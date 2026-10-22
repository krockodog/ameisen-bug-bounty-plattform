"""PASSIVES WLAN-Coverage-/Site-Survey + Optimierung (NUR lesend/lauschend).

Dieses Modul ist bewusst ANGRIFFSFREI: kein Deauth, kein Evil-Twin, kein
Captive-Portal, kein Handshake-Capture, kein Cracking. Es hört nur, was die
Umgebung ohnehin aussendet (Beacons), und leitet daraus Kanal-/Störungs- und
Abdeckungs-Analysen ab.

Leitplanken (wie der Rest von antbb):
  * Läuft scharf nur mit ANTBB_WIFI=1 UND vorhandenem WLAN-Tool/Interface.
    Fehlt beides → ehrlich-leer (NIE erfundene APs oder Signalwerte).
  * `iw dev <iface> scan` / `nmcli -f ALL dev wifi` brauchen KEINEN
    Monitor-Modus; airodump-ng-CSV (listen-only) ist optionaler Zusatz.
  * Jede Analyse ist regelbasiert, deterministisch und nachvollziehbar –
    es werden ausschließlich gemessene Werte verwendet, nichts geschätzt.

Die reine Parse-/Analyse-/Empfehlungslogik hat KEINE Tool-Abhängigkeit und ist
damit ohne WLAN-Hardware testbar (siehe smoke_test_wlan.py).
"""
from __future__ import annotations

import csv
import io
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------
#: Signal-Schwellen (dBm) für die Abdeckungs-Bewertung (gemessen, nicht geschätzt).
RSSI_GOOD = -60      # >= gut
RSSI_OK = -70        # >= brauchbar
RSSI_WEAK = -80      # >= schwach
#: Alles darunter gilt als Funkloch (dead zone).
RSSI_DEADZONE = RSSI_WEAK

#: Nicht-überlappende 2,4-GHz-Kanäle (klassische 1/6/11-Regel, 20 MHz).
NON_OVERLAP_24 = (1, 6, 11)
#: Zwei 2,4-GHz-Kanäle überlappen, wenn ihr Mittenabstand < 5 ist (20 MHz Breite).
OVERLAP_DISTANCE_24 = 5


@dataclass
class AccessPoint:
    """Ein beobachteter Access Point (aus Beacon/Scan, rein passiv)."""
    bssid: str = ""
    ssid: str = ""
    channel: Optional[int] = None
    band: str = ""          # "2.4" | "5" | "6" | ""
    freq_mhz: Optional[int] = None
    rssi: Optional[int] = None    # dBm
    encryption: str = ""    # WPA3 | WPA2 | WPA | WEP | OPEN | ""
    is_own: bool = False    # vom Nutzer als eigene Fritzbox getaggt
    connected: bool = False # aktuell assoziiert (nmcli IN-USE)

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid, "ssid": self.ssid, "channel": self.channel,
            "band": self.band, "freq_mhz": self.freq_mhz, "rssi": self.rssi,
            "encryption": self.encryption, "is_own": bool(self.is_own),
            "connected": bool(self.connected),
        }


# ---------------------------------------------------------------------------
# Frequenz-/Kanal-/Band-Helfer (rein numerisch, deterministisch)
# ---------------------------------------------------------------------------
def band_for_freq(freq_mhz: Optional[int]) -> str:
    if not freq_mhz:
        return ""
    if 2400 <= freq_mhz <= 2500:
        return "2.4"
    if 4900 <= freq_mhz <= 5895:
        return "5"
    if 5925 <= freq_mhz <= 7125:
        return "6"
    return ""


def channel_for_freq(freq_mhz: Optional[int]) -> Optional[int]:
    if not freq_mhz:
        return None
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if 5000 <= freq_mhz <= 5895:
        return (freq_mhz - 5000) // 5
    if 5925 <= freq_mhz <= 7125:          # 6 GHz (6E)
        return (freq_mhz - 5950) // 5
    return None


def band_for_channel(channel: Optional[int], freq_mhz: Optional[int] = None) -> str:
    b = band_for_freq(freq_mhz)
    if b:
        return b
    if channel is None:
        return ""
    if 1 <= channel <= 14:
        return "2.4"
    if 32 <= channel <= 177:
        return "5"
    return ""


def _norm_enc(raw: str) -> str:
    s = (raw or "").upper()
    if not s or s in ("--", "NONE", "OPEN", "ESS"):
        return "OPEN"
    if "WPA3" in s or "SAE" in s:
        return "WPA3"
    if "RSN" in s or "WPA2" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    if "PSK" in s or "EAP" in s:
        return "WPA2"
    return s


# ---------------------------------------------------------------------------
# Parser: `iw dev <iface> scan`
# ---------------------------------------------------------------------------
def parse_iw_scan(text: str) -> list[AccessPoint]:
    """Parst die Ausgabe von `iw dev <iface> scan` in AccessPoint-Records.

    Robust gegen fehlende Felder: nur tatsächlich vorhandene Werte werden
    gesetzt (honest-empty, keine Defaults erfunden).
    """
    aps: list[AccessPoint] = []
    cur: Optional[AccessPoint] = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        m = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", line)
        if m:
            if cur is not None:
                aps.append(cur)
            cur = AccessPoint(bssid=m.group(1).lower())
            continue
        if cur is None:
            continue
        m = re.match(r"^freq:\s*([0-9]+)", line)
        if m:
            cur.freq_mhz = int(float(m.group(1)))
            continue
        m = re.match(r"^signal:\s*(-?[0-9.]+)\s*dBm", line)
        if m:
            cur.rssi = int(round(float(m.group(1))))
            continue
        m = re.match(r"^SSID:\s*(.*)$", line)
        if m:
            cur.ssid = m.group(1).strip()
            continue
        m = re.match(r"^DS Parameter set:\s*channel\s*([0-9]+)", line)
        if m:
            cur.channel = int(m.group(1))
            continue
        m = re.match(r"^\*?\s*primary channel:\s*([0-9]+)", line)
        if m and cur.channel is None:
            cur.channel = int(m.group(1))
            continue
        if line.startswith("RSN:"):
            cur.encryption = "WPA2"
        if "Authentication suites:" in line and "SAE" in line:
            cur.encryption = "WPA3"
        if line.startswith("WPA:") and cur.encryption not in ("WPA2", "WPA3"):
            cur.encryption = "WPA"
        if "WEP" in line and not cur.encryption:
            cur.encryption = "WEP"
    if cur is not None:
        aps.append(cur)
    # Ableitungen nachziehen (nur aus Gemessenem).
    for ap in aps:
        if ap.channel is None:
            ap.channel = channel_for_freq(ap.freq_mhz)
        ap.band = band_for_channel(ap.channel, ap.freq_mhz)
        ap.encryption = _norm_enc(ap.encryption)
    return aps


# ---------------------------------------------------------------------------
# Parser: `nmcli -f ALL dev wifi` bzw. terse Variante
# ---------------------------------------------------------------------------
def parse_nmcli(text: str) -> list[AccessPoint]:
    """Parst nmcli-WiFi-Listen (terse `-t`).

    Unterstützte Formate:
      * IN-USE:BSSID:SSID:CHAN:FREQ:SIGNAL:SECURITY  (IN-USE=`*` oder leer)
      * BSSID:SSID:CHAN:FREQ:SIGNAL:SECURITY         (älter / Tests)

    SIGNAL ist 0..100 % → wird in dBm genähert (nmcli liefert kein dBm;
    die Näherung ist klar dokumentiert).
    """
    aps: list[AccessPoint] = []
    mac_re = re.compile(r"^[0-9a-fA-F:]{17}$")
    for raw in (text or "").splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        # terse (Backslash-escaped Doppelpunkte in BSSID)
        has_esc = "\\:" in line
        looks_mac = bool(re.match(r"^[0-9A-Fa-f]{2}\\:", line))
        if not (has_esc or looks_mac or line.startswith("*") or line.startswith(":")):
            continue
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        connected = False
        # nmcli padt leeres IN-USE mit Leerzeichen (" :BSSID:..."), daher strip()
        in_use = (parts[0] if parts else "").strip()
        if (len(parts) >= 7 and in_use in ("*", "")
                and mac_re.match(parts[1] or "")):
            connected = in_use == "*"
            bssid, ssid, chan, freq, signal, sec = parts[1:7]
        elif len(parts) >= 6 and mac_re.match((parts[0] or "").strip()):
            bssid, ssid, chan, freq, signal, sec = parts[:6]
            bssid = bssid.strip()
        else:
            continue
        ap = AccessPoint(bssid=bssid.lower(), ssid=ssid, connected=connected)
        ap.channel = int(chan) if chan.isdigit() else None
        fm = re.sub(r"[^0-9]", "", freq)
        ap.freq_mhz = int(fm) if fm else None
        if signal.strip().lstrip("-").isdigit():
            ap.rssi = _pct_to_dbm(int(signal))
        ap.encryption = _norm_enc(sec)
        ap.band = band_for_channel(ap.channel, ap.freq_mhz)
        aps.append(ap)
    return aps


def _pct_to_dbm(pct: int) -> int:
    """nmcli-SIGNAL (0..100 %) grob in dBm (−100..−50). Dokumentierte Näherung."""
    pct = max(0, min(100, pct))
    return int(round(-100 + (pct / 2.0)))


# ---------------------------------------------------------------------------
# Parser: airodump-ng CSV (listen-only); optionaler Zusatz
# ---------------------------------------------------------------------------
def parse_airodump_csv(text: str) -> list[AccessPoint]:
    """Parst den AP-Block einer airodump-ng-CSV (nur APs, keine Clients)."""
    aps: list[AccessPoint] = []
    block = (text or "").split("\r\nStation MAC")[0].split("\nStation MAC")[0]
    reader = csv.reader(io.StringIO(block))
    header_seen = False
    for row in reader:
        if not row:
            continue
        cell0 = row[0].strip()
        if cell0 == "BSSID":
            header_seen = True
            continue
        if not header_seen:
            continue
        if len(row) < 14:
            continue
        bssid = cell0
        if not re.match(r"^[0-9a-fA-F:]{17}$", bssid):
            continue
        try:
            channel = int(row[3].strip()) if row[3].strip() else None
        except ValueError:
            channel = None
        try:
            rssi = int(row[8].strip()) if row[8].strip() else None
        except ValueError:
            rssi = None
        enc = " ".join(x.strip() for x in row[5:8])
        ssid = row[13].strip() if len(row) > 13 else ""
        ap = AccessPoint(bssid=bssid.lower(), ssid=ssid, channel=channel,
                         rssi=rssi, encryption=_norm_enc(enc))
        ap.band = band_for_channel(ap.channel)
        aps.append(ap)
    return aps


# ---------------------------------------------------------------------------
# Kanal-/Störungs-Analyse
# ---------------------------------------------------------------------------
def _overlap_24(c1: int, c2: int) -> bool:
    return abs(c1 - c2) < OVERLAP_DISTANCE_24


def analyze_channels(aps: list[AccessPoint],
                     own_bssids: Optional[list[str]] = None) -> dict:
    """Kanal-Belegung + Überlappungs-/Störungs-Analyse.

    Markiert, wenn zwei EIGENE APs (per BSSID getaggt) auf gleichem/benachbartem
    Kanal sitzen (Selbst-Störung). Zusätzlich Kanal-Belegungszähler je Band.
    """
    own = {b.lower() for b in (own_bssids or [])}
    for ap in aps:
        if ap.bssid.lower() in own:
            ap.is_own = True

    by_band: dict[str, dict[int, int]] = {"2.4": {}, "5": {}, "6": {}}
    for ap in aps:
        if ap.band in by_band and ap.channel:
            by_band[ap.band][ap.channel] = by_band[ap.band].get(ap.channel, 0) + 1

    # Selbst-Störung der eigenen APs (nur 2,4 GHz hat das klassische Problem,
    # 5/6 GHz: nur Co-Channel als Hinweis).
    own_aps = [ap for ap in aps if ap.is_own and ap.channel]
    conflicts: list[dict] = []
    for i in range(len(own_aps)):
        for j in range(i + 1, len(own_aps)):
            a, b = own_aps[i], own_aps[j]
            if a.band != b.band:
                continue
            same = a.channel == b.channel
            adjacent = False
            if a.band == "2.4":
                adjacent = (not same) and _overlap_24(a.channel, b.channel)
            if same or adjacent:
                conflicts.append({
                    "band": a.band,
                    "ap_a": {"bssid": a.bssid, "ssid": a.ssid, "channel": a.channel},
                    "ap_b": {"bssid": b.bssid, "ssid": b.ssid, "channel": b.channel},
                    "kind": "co-channel" if same else "adjacent-overlap",
                    "severity": "high" if same else "medium",
                    "note": (f"Eigene APs auf {'gleichem' if same else 'überlappendem'} "
                             f"Kanal ({a.channel}/{b.channel}, {a.band} GHz) – "
                             f"gegenseitige Störung."),
                })

    # Überlappungs-Matrix der 2,4-GHz-Kanäle (fremd + eigen) für die Anzeige.
    occupied_24 = sorted(by_band["2.4"].keys())
    overlaps_24: list[dict] = []
    for idx in range(len(occupied_24)):
        for k in range(idx + 1, len(occupied_24)):
            c1, c2 = occupied_24[idx], occupied_24[k]
            if _overlap_24(c1, c2):
                overlaps_24.append({"ch_a": c1, "ch_b": c2,
                                    "distance": abs(c1 - c2)})

    return {
        "ap_count": len(aps),
        "own_ap_count": len(own_aps),
        "channel_usage": by_band,
        "non_overlap_24": list(NON_OVERLAP_24),
        "overlaps_24": overlaps_24,
        "self_interference": conflicts,
        "self_interference_count": len(conflicts),
    }


# ---------------------------------------------------------------------------
# Abdeckungs-/Coverage-Analyse (aus gemessenen Mess-Punkten)
# ---------------------------------------------------------------------------
def coverage_map(points: list[dict],
                 own_bssids: Optional[list[str]] = None,
                 threshold: int = RSSI_DEADZONE) -> dict:
    """Baut aus Mess-Punkten eine Abdeckungs-Karte + Funkloch-Erkennung.

    Jeder Punkt: {"label": str, "samples": {bssid: rssi_dbm, ...}}.
    Für jeden Punkt zählt das STÄRKSTE eigene (falls getaggt, sonst beste)
    Signal. Punkte unter `threshold` sind Funklöcher (dead zones).
    """
    own = {b.lower() for b in (own_bssids or [])}
    out_points: list[dict] = []
    dead_zones: list[dict] = []
    for p in points:
        label = str(p.get("label", "")).strip() or "(unbenannt)"
        samples = {str(k).lower(): int(v) for k, v in (p.get("samples") or {}).items()
                   if _is_int(v)}
        if not samples:
            out_points.append({"label": label, "best_rssi": None,
                               "best_bssid": "", "quality": "unbekannt",
                               "sample_count": 0, "is_dead_zone": False})
            continue
        own_samples = {b: r for b, r in samples.items() if b in own} if own else {}
        pool = own_samples or samples
        best_bssid = max(pool, key=lambda b: pool[b])
        best_rssi = pool[best_bssid]
        q = quality_for_rssi(best_rssi)
        is_dead = best_rssi < threshold
        rec = {"label": label, "best_rssi": best_rssi, "best_bssid": best_bssid,
               "quality": q, "sample_count": len(samples),
               "is_dead_zone": is_dead, "samples": samples}
        out_points.append(rec)
        if is_dead:
            dead_zones.append({"label": label, "best_rssi": best_rssi,
                               "best_bssid": best_bssid})
    measured = [p for p in out_points if p["best_rssi"] is not None]
    avg = (round(sum(p["best_rssi"] for p in measured) / len(measured), 1)
           if measured else None)
    return {
        "points": out_points,
        "point_count": len(out_points),
        "measured_count": len(measured),
        "dead_zones": dead_zones,
        "dead_zone_count": len(dead_zones),
        "threshold_dbm": threshold,
        "avg_best_rssi": avg,
    }


def quality_for_rssi(rssi: Optional[int]) -> str:
    if rssi is None:
        return "unbekannt"
    if rssi >= RSSI_GOOD:
        return "gut"
    if rssi >= RSSI_OK:
        return "brauchbar"
    if rssi >= RSSI_WEAK:
        return "schwach"
    return "funkloch"


def _is_int(v) -> bool:
    try:
        int(v)
        return True
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Optimierungs-Empfehlungen (regelbasiert, nur aus Messwerten)
# ---------------------------------------------------------------------------
def recommend(aps: list[AccessPoint],
              channel_analysis: Optional[dict] = None,
              coverage: Optional[dict] = None,
              own_bssids: Optional[list[str]] = None) -> dict:
    """Leitet nachvollziehbare Optimierungs-Empfehlungen ab.

    Alles regelbasiert und aus den tatsächlich gemessenen Daten; es werden
    KEINE Zahlen erfunden. Fehlen Daten, bleibt das Feld ehrlich leer/none.
    """
    ca = channel_analysis or analyze_channels(aps, own_bssids)
    recs: list[str] = []

    # Bester 2,4-GHz-Kanal: unter 1/6/11 den mit der geringsten beobachteten
    # Belegung (gewichtet nach überlappenden Nachbarn).
    best_24 = _best_channel_24(aps)
    if best_24:
        recs.append(f"2,4 GHz: Kanal {best_24['channel']} nutzen "
                    f"(geringste gemessene Überlappungs-Last {best_24['load']}; "
                    f"nur 1/6/11 sind überlappungsfrei).")

    # Selbst-Störung auflösen.
    for c in ca.get("self_interference", []):
        recs.append(f"Selbst-Störung ({c['kind']}, {c['band']} GHz): "
                    f"'{c['ap_a']['ssid'] or c['ap_a']['bssid']}' und "
                    f"'{c['ap_b']['ssid'] or c['ap_b']['bssid']}' auf getrennte, "
                    f"überlappungsfreie Kanäle setzen (2,4 GHz: 1/6/11).")

    # Band-Steering, falls dieselbe SSID auf 2,4 und 5 GHz sichtbar.
    steer = _band_steering_hint(aps, own_bssids)
    if steer:
        recs.append(steer)

    # Abdeckung / Repeater-Platzierung aus Funklöchern.
    placement: list[str] = []
    if coverage:
        for dz in coverage.get("dead_zones", []):
            placement.append(
                f"Funkloch bei '{dz['label']}' (bestes Signal {dz['best_rssi']} dBm "
                f"< {coverage.get('threshold_dbm')} dBm): Repeater/Mesh-AP auf halber "
                f"Strecke zwischen nächstem starken AP und '{dz['label']}' platzieren.")
        if coverage.get("measured_count") and not coverage.get("dead_zones"):
            placement.append("Keine Funklöcher in den Messpunkten – Abdeckung "
                             "ausreichend; kein zusätzlicher Repeater nötig.")

    # TX-Power-Hinweis (nur qualitativ, keine erfundenen dBm).
    tx_hint = None
    if ca.get("self_interference"):
        tx_hint = ("Bei dicht stehenden eigenen APs Sendeleistung moderat "
                   "senken, damit sich die Zellen weniger überlappen "
                   "(sauberes Roaming statt Selbst-Störung).")

    return {
        "best_channel_24": best_24,
        "channel_recommendations": recs,
        "placement": placement,
        "tx_power_hint": tx_hint,
        "band_steering_hint": steer,
        "note": ("Regelbasiert aus gemessenen Beacons/Signalpunkten abgeleitet. "
                 "Nur beobachtete Werte, keine Schätzungen."),
    }


def _best_channel_24(aps: list[AccessPoint]) -> Optional[dict]:
    aps24 = [ap for ap in aps if ap.band == "2.4" and ap.channel]
    if not aps24:
        return None
    loads = {}
    for cand in NON_OVERLAP_24:
        # Last = Anzahl APs, deren Kanal den Kandidaten überlappt.
        load = sum(1 for ap in aps24 if _overlap_24(ap.channel, cand))
        loads[cand] = load
    best = min(loads, key=lambda c: loads[c])
    return {"channel": best, "load": loads[best], "loads": loads}


def _band_steering_hint(aps: list[AccessPoint],
                        own_bssids: Optional[list[str]] = None) -> Optional[str]:
    own = {b.lower() for b in (own_bssids or [])}
    pool = [ap for ap in aps if (not own or ap.bssid.lower() in own)]
    by_ssid: dict[str, set] = {}
    for ap in pool:
        if ap.ssid and ap.band:
            by_ssid.setdefault(ap.ssid, set()).add(ap.band)
    for ssid, bands in by_ssid.items():
        if "2.4" in bands and "5" in bands:
            return (f"SSID '{ssid}' sendet auf 2,4 und 5 GHz: Band-Steering "
                    f"aktivieren, damit fähige Clients ins weniger überfüllte "
                    f"5-GHz-Band wechseln.")
    return None


# ---------------------------------------------------------------------------
# Live-Scan (scharf nur mit Tool + Interface; sonst ehrlich-leer)
# ---------------------------------------------------------------------------
def tool_availability() -> dict:
    return {t: bool(shutil.which(t))
            for t in ("iw", "nmcli", "iwlist", "airodump-ng")}


def wifi_enabled() -> bool:
    return os.environ.get("ANTBB_WIFI", "").strip() in ("1", "true", "yes")


def detect_iface() -> Optional[str]:
    """Erstes WLAN-Interface via `iw dev` (sonst None)."""
    if not shutil.which("iw"):
        return None
    try:
        proc = subprocess.run(["iw", "dev"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10, check=False)
        m = re.search(r"Interface\s+(\S+)", proc.stdout.decode("utf-8", "replace"))
        return m.group(1) if m else None
    except Exception:
        return None



# Bekannte lab-host-/Labor-Adapter (Metadaten für die GUI). Nur Anzeige;
# Discovery läuft weiterhin live über iw/nmcli/sysfs.
KNOWN_ADAPTERS = {
    "wlan0": {
        "chipset": "Realtek RTL8192CU",
        "driver": "rtl8192cu",
        "bands": ["2.4"],
        "monitor": False,
        "injection": False,
        "preferred": False,
        "label": "wlan0 · Realtek RTL8192CU (2.4 GHz)",
    },
    "wlan1": {
        "chipset": "Ralink RT3573 (NetGear WNDA4100)",
        "driver": "rt2800usb",
        "bands": ["2.4", "5"],
        "monitor": True,
        "injection": True,
        "preferred": True,
        "label": "wlan1 · NetGear WNDA4100 / Ralink RT3573 (dual-band 3×3) ★",
    },
}


def list_adapters() -> dict:
    """Listet vorhandene WLAN-Adapter inkl. bekannter Hardware-Metadaten.

    Discovery (best-effort, honest-empty):
      1. `iw dev` → Interface-Namen
      2. sysfs `/sys/class/net/*/phy80211` oder `*/wireless`
      3. `nmcli -t -f DEVICE,TYPE device` (wifi)

    Gibt {adapters:[...], tools, reason} zurück. Keine erfundenen Adapter.
    """
    found: list[str] = []
    seen = set()

    def _add(name: str):
        name = (name or "").strip()
        if not name or name in seen:
            return
        seen.add(name)
        found.append(name)

    if shutil.which("iw"):
        try:
            proc = subprocess.run(["iw", "dev"], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=10, check=False)
            for m in re.finditer(r"Interface\s+(\S+)",
                                 proc.stdout.decode("utf-8", "replace")):
                _add(m.group(1))
        except Exception:
            pass

    try:
        for name in sorted(os.listdir("/sys/class/net")):
            base = f"/sys/class/net/{name}"
            if os.path.isdir(f"{base}/phy80211") or os.path.isdir(f"{base}/wireless"):
                _add(name)
    except Exception:
        pass

    if shutil.which("nmcli"):
        try:
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False)
            for line in proc.stdout.decode("utf-8", "replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].strip().lower() == "wifi":
                    _add(parts[0].strip())
        except Exception:
            pass

    adapters = []
    for name in found:
        meta = dict(KNOWN_ADAPTERS.get(name, {}))
        adapters.append({
            "iface": name,
            "present": True,
            "label": meta.get("label") or name,
            "chipset": meta.get("chipset") or "",
            "driver": meta.get("driver") or "",
            "bands": meta.get("bands") or [],
            "monitor": bool(meta.get("monitor", False)),
            "injection": bool(meta.get("injection", False)),
            "preferred": bool(meta.get("preferred", False)),
        })
    # Preferred first, then name
    adapters.sort(key=lambda a: (not a["preferred"], a["iface"]))

    reason = ""
    if not adapters:
        reason = ("Keine WLAN-Adapter gefunden (iw/nmcli/sysfs). "
                  "honest-empty – nichts erfunden.")
    return {
        "adapters": adapters,
        "tools": tool_availability(),
        "enabled": wifi_enabled(),
        "reason": reason,
        "default": (adapters[0]["iface"] if adapters else ""),
    }



def _have_root() -> bool:
    """True, wenn effektiv root (CAP_NET_ADMIN). `iw scan` braucht das;
    nmcli nicht (geht über den NetworkManager-D-Bus)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _scan_iw(iface: str) -> list[AccessPoint]:
    proc = subprocess.run(["iw", "dev", iface, "scan"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, check=False)
    return parse_iw_scan(proc.stdout.decode("utf-8", "replace"))


def _scan_nmcli(rescan: bool = True) -> list[AccessPoint]:
    """nmcli-WiFi-Scan über ALLE verwalteten Adapter (kein root nötig).

    Optionaler, best-effort Rescan für frische Daten (Fehler werden ignoriert,
    z. B. Rate-Limit); danach die terse Liste parsen.
    """
    if rescan:
        try:
            subprocess.run(["nmcli", "dev", "wifi", "rescan"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=20, check=False)
            time.sleep(3)
        except Exception:
            pass
    proc = subprocess.run(
        ["nmcli", "-t", "-f", "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    return parse_nmcli(proc.stdout.decode("utf-8", "replace"))


def scan_environment(iface: Optional[str] = None,
                     log=None, prefer: Optional[str] = None,
                     force: bool = False) -> dict:
    """Führt einen passiven Umgebungs-Scan durch.

    Tool-Wahl (wichtig, damit nicht fälschlich 0 Netze erscheinen):
      * nmcli ist der robuste Standard – es läuft OHNE root über den
        NetworkManager und erfasst alle verwalteten Adapter. `iw dev scan`
        braucht dagegen root (CAP_NET_ADMIN) und liefert ohne root still 0 APs.
      * iw wird bevorzugt nur dann genutzt, wenn wir root sind (reichere Daten:
        dBm, Verschlüsselungs-Detail). Liefert iw dann 0 APs, fällt die Routine
        trotzdem auf nmcli zurück, statt fälschlich "0 Netze" zu melden.
      * `prefer` ("nmcli"/"iw") erzwingt eine Reihenfolge (für Tests/GUI).

    Gibt immer ein strukturiertes Ergebnis zurück. Ohne Freischaltung/Tool:
    ehrlich leer (aps=[], reason gesetzt) – NIE erfundene Netze.
    """
    def _log(msg):
        if log:
            log(msg)

    result = {"enabled": wifi_enabled(), "tool": None, "iface": iface or "",
              "aps": [], "reason": "", "tools": tool_availability(),
              "is_root": _have_root()}
    # `force` = der Nutzer hat einen Scan explizit ausgelöst (CLI `wlan-survey
    # scan` / GUI-Button) → das IST die Opt-in-Freischaltung. Der ANTBB_WIFI-Gate
    # schützt nur implizite/automatische Pfade.
    if not force and not wifi_enabled():
        result["reason"] = "WLAN-Survey nicht freigeschaltet (ANTBB_WIFI!=1) – ehrlich leer."
        _log("[wlan] " + result["reason"])
        return result
    result["enabled"] = True

    tools = result["tools"]
    # Reihenfolge bestimmen: nmcli-first (robust, kein root), iw nur mit root.
    use_iw_first = tools.get("iw") and result["is_root"]
    if prefer == "iw":
        use_iw_first = bool(tools.get("iw"))
    elif prefer == "nmcli":
        use_iw_first = False

    tried = []
    if use_iw_first:
        iw_iface = iface or detect_iface()
        if iw_iface:
            try:
                aps = _scan_iw(iw_iface)
                tried.append(f"iw({iw_iface}):{len(aps)}")
                if aps:
                    result.update(tool="iw", iface=iw_iface,
                                  aps=[a.to_dict() for a in aps])
                    _log(f"[wlan] iw-Scan ({iw_iface}): {len(aps)} AP(s) sichtbar.")
                    return result
                _log(f"[wlan] iw-Scan ({iw_iface}) lieferte 0 APs – Fallback nmcli.")
            except Exception as exc:
                tried.append(f"iw-fehler:{exc}")
                _log(f"[wlan] iw-Scan fehlgeschlagen ({exc}) – Fallback nmcli.")

    if tools.get("nmcli"):
        try:
            aps = _scan_nmcli(rescan=True)
            tried.append(f"nmcli:{len(aps)}")
            if aps:
                result.update(tool="nmcli", aps=[a.to_dict() for a in aps])
                _log(f"[wlan] nmcli-Scan: {len(aps)} AP(s) sichtbar.")
                return result
            _log("[wlan] nmcli-Scan lieferte 0 APs.")
        except Exception as exc:
            tried.append(f"nmcli-fehler:{exc}")
            _log(f"[wlan] nmcli-Scan fehlgeschlagen: {exc}")

    # Letzter Versuch: iw auch ohne root (liefert oft nur eigene Assoziation,
    # aber besser als nichts), falls nmcli nichts brachte.
    if not result["aps"] and tools.get("iw") and not use_iw_first:
        iw_iface = iface or detect_iface()
        if iw_iface:
            try:
                aps = _scan_iw(iw_iface)
                tried.append(f"iw-fallback({iw_iface}):{len(aps)}")
                if aps:
                    result.update(tool="iw", iface=iw_iface,
                                  aps=[a.to_dict() for a in aps])
                    _log(f"[wlan] iw-Scan-Fallback ({iw_iface}): {len(aps)} AP(s).")
                    return result
            except Exception as exc:
                tried.append(f"iw-fallback-fehler:{exc}")

    if not tools.get("iw") and not tools.get("nmcli"):
        result["reason"] = "Kein WLAN-Tool (iw/nmcli) vorhanden – ehrlich leer."
    else:
        result["reason"] = ("Scan lieferte keine APs (" + ", ".join(tried) + "). "
                            "Ohne root nutzt antbb nmcli; prüfe, ob der "
                            "NetworkManager den Adapter verwaltet und WLAN an ist.")
    _log("[wlan] " + result["reason"])
    return result


def full_survey(aps_dicts: list[dict],
                points: Optional[list[dict]] = None,
                own_bssids: Optional[list[str]] = None,
                threshold: int = RSSI_DEADZONE) -> dict:
    """Bündelt Kanal-Analyse + Coverage + Empfehlungen (reine Daten rein/raus)."""
    aps = [AccessPoint(**{k: d.get(k) for k in
            ("bssid", "ssid", "channel", "band", "freq_mhz", "rssi",
             "encryption", "is_own", "connected")}) for d in aps_dicts]
    # Band nachziehen, falls nicht gesetzt.
    for ap in aps:
        if not ap.band:
            ap.band = band_for_channel(ap.channel, ap.freq_mhz)
        ap.is_own = bool(ap.is_own)
    ca = analyze_channels(aps, own_bssids)
    cov = coverage_map(points or [], own_bssids, threshold)
    rec = recommend(aps, ca, cov, own_bssids)
    return {
        "aps": [a.to_dict() for a in aps],
        "channel_analysis": ca,
        "coverage": cov,
        "recommendations": rec,
    }
