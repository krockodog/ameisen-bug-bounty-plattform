"""Airgorah-inspirierte WLAN-Audit-Schicht (web-nativ, oversight-gated).

Orientiert sich am Feature-/Workflow-Umfang von Airgorah
(https://github.com/martin-olivier/airgorah, MIT License © Martin Olivier):
  * Interface / Monitor-Mode-Status (iw / airmon-ng)
  * AP-Liste mit Clients (airodump-ng CSV, wenn verfügbar)
  * Handshake-/PMKID-Capture, gezielter Deauth, Offline-Crack, Evil-Twin-Demo

Wir betten die GTK/Rust-App NICHT ein und kopieren keinen Airgorah-Code.
Alle scharfen Aktionen laufen über `wlan_offensive.WifiOffensive` (Engagement-
Gate + Oversight + ANTBB_WIFI=1, default-deny, honest-empty, keine autonomen
Ketten). Fehlt Root/Monitor-Mode/Tool → klarer Status, kein stilles Scheitern.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

# Katalog der DEFENSIVEN Checks für den Ein-Klick-Voll-Scan (Königin).
# Offensive Aktionen sind bewusst NICHT hier – die bleiben operator-getriggert.
FULL_SCAN_CHECKS: list[dict] = [
    {"id": "scan", "label": "Umgebungs-Scan (APs/Beacons)", "defensive": True,
     "playbook": "wlan-scan"},
    {"id": "konfig", "label": "Verschlüsselungs-/Konfig-Check (WEP/offen/WPS/TKIP)",
     "defensive": True, "playbook": "wlan-konfig-check"},
    {"id": "optim", "label": "Kanal-/Band-Optimierung", "defensive": True,
     "playbook": "wlan-optimierung"},
    {"id": "coverage", "label": "Coverage / Selbst-Störung / Funklöcher",
     "defensive": True, "playbook": "wlan-coverage-survey"},
]

FULL_SCAN_CHECK_IDS = [c["id"] for c in FULL_SCAN_CHECKS]

# Airgorah-Workflow-Aktionen (Offensiv) – nur über Gate.
AIRGORAH_ACTIONS: list[dict] = [
    {"id": "monitor-status", "label": "Monitor-Mode-Status", "offensive": False,
     "tools": ["iw", "airmon-ng"]},
    {"id": "ap-clients", "label": "AP + Clients (airodump)", "offensive": False,
     "tools": ["airodump-ng"]},
    {"id": "handshake-capture", "label": "Handshake-/PMKID-Capture", "offensive": True,
     "tools": ["hcxdumptool", "airodump-ng"]},
    {"id": "targeted-deauth", "label": "Gezielter Deauth", "offensive": True,
     "tools": ["aireplay-ng", "mdk4"]},
    {"id": "offline-crack", "label": "Offline-Crack (WPA)", "offensive": True,
     "tools": ["hashcat", "aircrack-ng"]},
    {"id": "evil-twin-demo", "label": "Evil-Twin / Fake-AP Demo", "offensive": True,
     "tools": ["wifiphisher", "eaphammer", "hostapd"]},
]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
        return (p.returncode,
                (p.stdout or b"").decode("utf-8", "replace"),
                (p.stderr or b"").decode("utf-8", "replace"))
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def _euid() -> int:
    try:
        return os.geteuid()
    except Exception:
        return -1


def can_sudo_nopasswd() -> bool:
    """Prüft, ob `sudo -n true` ohne Passwort gelingt (ohne etwas auszuführen)."""
    if not _which("sudo"):
        return False
    rc, _, _ = _run(["sudo", "-n", "true"], timeout=3)
    return rc == 0


def iface_monitor_mode(iface: str) -> dict:
    """Prüft, ob `iface` im Monitor-Mode ist (`iw dev <iface> info`).

    Gibt ehrlich zurück, wenn Tool/Interface fehlen oder Rechte fehlen.
    Startet KEINEN Monitor-Mode und ruft airmon-ng start NICHT auf.
    """
    out = {"iface": iface or "", "monitor": False, "managed": False,
           "exists": False, "tool": None, "needs_root": False,
           "reason": "", "raw_type": ""}
    if not iface:
        out["reason"] = "Kein Interface angegeben."
        return out
    iw = _which("iw")
    if not iw:
        out["reason"] = "Tool 'iw' fehlt – Monitor-Status nicht prüfbar (honest-empty)."
        return out
    out["tool"] = "iw"
    rc, stdout, stderr = _run([iw, "dev", iface, "info"], timeout=5)
    if rc != 0:
        low = (stderr + stdout).lower()
        if "operation not permitted" in low or "permission" in low:
            out["needs_root"] = True
            out["reason"] = (f"Rechte fehlen für 'iw dev {iface} info' "
                             f"(Root/NOPASSWD-sudo nötig).")
        elif "no such device" in low or "cannot find" in low:
            out["reason"] = f"Interface '{iface}' nicht gefunden."
        else:
            out["reason"] = f"iw-Info fehlgeschlagen (rc={rc}): {(stderr or stdout)[:200]}"
        return out
    out["exists"] = True
    # type monitor / type managed
    for line in stdout.splitlines():
        s = line.strip().lower()
        if s.startswith("type "):
            t = s.split(None, 1)[1].strip()
            out["raw_type"] = t
            out["monitor"] = t == "monitor"
            out["managed"] = t == "managed"
            break
    if not out["raw_type"]:
        out["reason"] = "iw-Ausgabe ohne 'type …' – Status unklar."
    return out


def airgorah_status(preferred_iface: str = "") -> dict:
    """Gesamtstatus für die Airgorah-UI: Tools, Rechte, Monitor, Adapter-Hinweis."""
    from . import wlan_survey as ws
    from . import wlan_offensive as wo

    adapters = ws.list_adapters()
    ifaces = [a.get("iface") for a in adapters.get("adapters", []) if a.get("iface")]
    preferred = preferred_iface
    if not preferred:
        for a in adapters.get("adapters", []):
            if a.get("preferred"):
                preferred = a["iface"]
                break
        if not preferred and ifaces:
            preferred = ifaces[0]

    euid = _euid()
    is_root = euid == 0
    nopass = can_sudo_nopasswd() if not is_root else True

    mon = iface_monitor_mode(preferred) if preferred else {
        "iface": "", "monitor": False, "reason": "Kein WLAN-Adapter erkannt."}

    tool_map = {
        "iw": bool(_which("iw")),
        "airmon-ng": bool(_which("airmon-ng")),
        "airodump-ng": bool(_which("airodump-ng")),
        "aireplay-ng": bool(_which("aireplay-ng")),
        "aircrack-ng": bool(_which("aircrack-ng")),
        "hcxdumptool": bool(_which("hcxdumptool")),
        "hashcat": bool(_which("hashcat")),
        "mdk4": bool(_which("mdk4")),
        "nmcli": bool(_which("nmcli")),
        "hostapd": bool(_which("hostapd")),
        "wifiphisher": bool(_which("wifiphisher")),
        "eaphammer": bool(_which("eaphammer")),
    }

    actions = []
    for a in AIRGORAH_ACTIONS:
        have = [t for t in a["tools"] if tool_map.get(t)]
        actions.append({
            **a,
            "available_tools": have,
            "ready": bool(have) if not a["offensive"] else (
                bool(have) and wo.wifi_offensive_enabled()),
        })

    caveats = []
    if not any(tool_map[t] for t in ("nmcli", "iw", "airodump-ng")):
        caveats.append("Keine Scan-Tools (nmcli/iw/airodump-ng) – Scan bleibt ehrlich leer.")
    if not is_root and not nopass:
        caveats.append(
            "Kein Root und kein NOPASSWD-sudo: Monitor-Mode / Deauth / Capture "
            "können nicht scharf starten – Status wird gemeldet, nichts still "
            "fehlgeschlagen. Entscheidung: root oder NOPASSWD-sudo für USER.")
    if preferred and not mon.get("monitor") and mon.get("exists"):
        caveats.append(
            f"'{preferred}' ist nicht im Monitor-Mode ({mon.get('raw_type') or 'managed'}). "
            f"Offensiv-Capture/Deauth brauchen Monitor+Injection (typisch wlan1/NetGear).")
    if not wo.wifi_offensive_enabled():
        caveats.append("ANTBB_WIFI≠1 – Offensiv-Aktionen bleiben gesperrt (default-deny).")

    return {
        "airgorah_ref": {
            "repo": "https://github.com/martin-olivier/airgorah",
            "license": "MIT",
            "note": ("Feature-/Workflow-Orientierung; kein GTK-Embed, kein Code-Copy. "
                     "Offensiv über antbb.wlan_offensive (Gate+Oversight)."),
        },
        "adapters": adapters,
        "preferred_iface": preferred or "",
        "monitor": mon,
        "privileges": {
            "euid": euid,
            "is_root": is_root,
            "sudo_nopasswd": nopass,
            "can_elevate": bool(is_root or nopass),
        },
        "tools": tool_map,
        "actions": actions,
        "full_scan_checks": FULL_SCAN_CHECKS,
        "offensive_enabled": wo.wifi_offensive_enabled(),
        "caveats": caveats,
    }


def list_clients_honest_empty(iface: str = "", bssid: str = "") -> dict:
    """Client-Liste zu einem AP.

    Ohne airodump-ng / Monitor-Mode / Root: ehrlich leer mit klarem Grund.
    Startet KEINEN Capture und KEINEN Deauth.
    """
    out = {"iface": iface or "", "bssid": (bssid or "").lower(),
           "clients": [], "tool": None, "honest_empty": True, "reason": ""}
    tool = _which("airodump-ng")
    if not tool:
        out["reason"] = ("airodump-ng fehlt – Client-Liste nicht verfügbar "
                         "(honest-empty). Auf Kali: apt install aircrack-ng.")
        return out
    out["tool"] = "airodump-ng"
    if not iface:
        out["reason"] = "Kein Interface – Client-Scan nicht gestartet."
        return out
    mon = iface_monitor_mode(iface)
    if not mon.get("monitor"):
        out["reason"] = (
            f"Interface '{iface}' nicht im Monitor-Mode "
            f"({mon.get('reason') or mon.get('raw_type') or 'managed'}). "
            f"Client-Enumeration braucht Monitor-Mode (Root/airmon-ng). "
            f"Nichts gestartet.")
        out["monitor"] = mon
        return out
    # Bewusst KEIN airodump-Lauf hier: wäre aktiv/lauschend-lang und braucht
    # Operator-Trigger. UI zeigt den Status; scharfer Lauf über Offensiv-Gate.
    out["reason"] = (
        "Monitor-Mode OK, airodump-ng vorhanden – Client-Capture startet nur "
        "operator-getrieben über Offensiv/Airgorah (Handshake-Capture), "
        "nicht automatisch.")
    out["monitor"] = mon
    out["honest_empty"] = True
    return out


def run_full_scan(*, iface: Optional[str] = None, checks: Optional[list] = None,
                  oversight_ack: bool = False, target_id: Optional[int] = None,
                  store=None, logger=None, emit=None) -> dict:
    """Königin-gesteuerter DEFENSIVER WLAN-Voll-Scan (Ein-Klick).

    - Läuft NUR defensive Checks (scan/konfig/optim/coverage).
    - Braucht oversight_ack=True (Human-Oversight-Häkchen), sonst blockiert.
    - Startet KEINE Offensiv-Aktion (kein Deauth/Capture/Crack/Evil-Twin).
    - honest-empty wenn Tools/Adapter fehlen; nichts erfunden.
    """
    from . import wlan_survey as ws

    def _log(msg: str) -> None:
        if logger:
            try:
                logger.info(msg)
            except Exception:
                pass
        if emit:
            try:
                emit({"ts": __import__("time").time(), "msg": msg})
            except Exception:
                pass

    wanted = list(checks) if checks else list(FULL_SCAN_CHECK_IDS)
    wanted = [c for c in wanted if c in FULL_SCAN_CHECK_IDS]
    result = {
        "ok": False,
        "queen": True,
        "oversight_ack": bool(oversight_ack),
        "iface": iface or "",
        "checks_requested": wanted,
        "checks_run": [],
        "checks_skipped": [],
        "blocked": False,
        "reason": "",
        "scan": None,
        "survey": None,
        "konfig": [],
        "phase_log": [],
        "findings_count": 0,
    }

    if not oversight_ack:
        result["blocked"] = True
        result["reason"] = ("BLOCKIERT: Human-Oversight-Häkchen fehlt – "
                            "Königin dispatcht keinen WLAN-Voll-Scan.")
        _log(f"👑 WLAN-Voll-Scan: {result['reason']}")
        return result

    _log("👑 Königin: WLAN-Voll-Scan gestartet (nur defensiv, oversight bestätigt).")
    result["phase_log"].append("queen:start")

    # 1) Scan
    scan_res = {"aps": [], "tool": None, "reason": "", "iface": iface or ""}
    if "scan" in wanted:
        _log("👑 Phase 'wlan-scan': dispatche Umgebungs-Scan.")
        scan_res = ws.scan_environment(iface=iface, log=_log, force=True)
        result["checks_run"].append("scan")
        result["phase_log"].append(f"scan:aps={len(scan_res.get('aps') or [])}")
    else:
        result["checks_skipped"].append("scan")

    aps = scan_res.get("aps") or []
    result["scan"] = scan_res

    # 2) Konfig-Check (regelbasiert aus Scan)
    konfig = []
    if "konfig" in wanted:
        _log("👑 Phase 'wlan-konfig-check': Verschlüsselungs-Audit.")
        for a in aps:
            enc = (a.get("encryption") or "").upper()
            weak = (not enc) or enc in ("OPEN", "NONE", "--") or "WEP" in enc or "TKIP" in enc
            wps = "WPS" in enc
            if weak or wps:
                konfig.append({
                    "bssid": a.get("bssid", ""), "ssid": a.get("ssid", ""),
                    "encryption": enc or "OPEN",
                    "issue": ("offen/WEP/TKIP" if weak else "") + ("+WPS" if wps else ""),
                    "severity": "medium" if weak else "low",
                })
        result["checks_run"].append("konfig")
        result["phase_log"].append(f"konfig:issues={len(konfig)}")
    else:
        result["checks_skipped"].append("konfig")
    result["konfig"] = konfig

    # 3+4) Survey = Optim + Coverage (Kanal, Selbst-Störung, Empfehlungen)
    survey = None
    if "optim" in wanted or "coverage" in wanted:
        _log("👑 Phase 'wlan-optim/coverage': Survey + Empfehlungen.")
        points, store_own = [], []
        if store is not None and target_id is not None:
            try:
                rows = store.list_wlan_samples(target_id)
                pts: dict = {}
                own: set = set()
                for r in rows:
                    pts.setdefault(r["point_label"], {})[r["bssid"]] = r["rssi"]
                    if r["is_own"]:
                        own.add(r["bssid"])
                points = [{"label": k, "samples": v} for k, v in pts.items()]
                store_own = sorted(own)
            except Exception:
                pass
        survey = ws.full_survey(aps, points=points, own_bssids=store_own)
        survey["own_bssids"] = store_own
        survey["scan"] = scan_res
        survey["tools"] = ws.tool_availability()
        survey["enabled"] = ws.wifi_enabled()
        if "optim" in wanted:
            result["checks_run"].append("optim")
        else:
            result["checks_skipped"].append("optim")
        if "coverage" in wanted:
            result["checks_run"].append("coverage")
        else:
            result["checks_skipped"].append("coverage")
        ca = survey.get("channel_analysis") or {}
        result["phase_log"].append(
            f"survey:self_interference={len(ca.get('self_interference') or [])}")
    else:
        result["checks_skipped"].extend(
            [c for c in ("optim", "coverage") if c in FULL_SCAN_CHECK_IDS])
    result["survey"] = survey

    result["findings_count"] = len(konfig) + len(
        (survey or {}).get("channel_analysis", {}).get("self_interference") or [])
    result["ok"] = True
    result["reason"] = (f"Königin hat {len(result['checks_run'])} Check(s) dispatcht; "
                        f"{result['findings_count']} Hinweis(e).")
    _log(f"👑 WLAN-Voll-Scan fertig: {result['reason']}")
    result["phase_log"].append("queen:done")
    return result
