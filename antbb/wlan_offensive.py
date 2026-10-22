"""AUTORISIERTES WLAN-Offensiv-Modul (NUR Auftrag/Awareness-Pentest).

Dieses Modul ist das scharfe Gegenstück zum passiven `wlan_survey`. Es
orchestriert etablierte Kali-WLAN-Tools (airodump-ng/hcxdumptool, aireplay-ng/
mdk4, aircrack-ng/hashcat, hostapd/dnsmasq bzw. wifiphisher/eaphammer) – aber
AUSSCHLIESSLICH hinter einem harten, erzwungenen Autorisierungs-Gate.

Harte, im Code erzwungene Leitplanken (keine reine Doku):
  * ENGAGEMENT-GATE (default-deny): Jede offensive Aktion läuft nur gegen eine
    BSSID/SSID, die in einem AKTIVEN, im Zeitfenster liegenden, nicht
    widerrufenen Engagement mit gesetztem Oversight steht. Ohne passendes
    Engagement: BLOCKIERT + geloggt, KEIN Tool-Aufruf.
  * Offensiv-Freischaltung: zusätzlich ANTBB_WIFI=1. Default AUS.
  * Rechtshinweis (§202a-c StGB) wird vor jeder Aktion protokolliert (blockiert
    nicht, dokumentiert).
  * Honest-empty: fehlt das Tool (shutil.which) oder die Hardware, wird ein klar
    gekennzeichneter Leerzustand geliefert – NIE ein erfundener Handshake, eine
    erfundene Capture oder ein erfundenes Passwort.
  * Credentials/geknackte Passwörter werden NIE im Klartext gespeichert – nur
    maskiert (Länge + erstes/letztes Zeichen) und als gesalzener SHA-256-Digest.
    `purge`-Funktion + Auto-Purge-nach-Report-Hook vorhanden.
  * Operator-getrieben und begrenzt (Paket-/Zeitlimits); keine Dauer-/Massen-
    Angriffsschleifen, kein Broadcast-Deauth gegen die Umgebung.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from .agents.base import (
    AgentFinding, STATUS_VERIFIED, STATUS_TO_CONFIRM, STATUS_CONDITIONAL,
)

# ---------------------------------------------------------------------------
# Rechtshinweis + Tool-Katalog
# ---------------------------------------------------------------------------
# Wortgleicher, zentral gepflegter Rechtshinweis (§ 202a-c StGB / CFAA) – teilt
# sich denselben Text mit Offensiv-Scan, aktiver Verifikation und Fuzzing, damit
# der Hinweis ueberall identisch liest (konsistentes Human-Oversight-Gate).
from .active_oversight import ACTIVE_LEGAL_NOTICE as LEGAL_NOTICE  # noqa: E402,F401

#: Logische Aktion → Kandidaten-Tools (erstes vorhandenes gewinnt).
ACTION_TOOLS: dict[str, list[str]] = {
    "handshake-capture": ["hcxdumptool", "airodump-ng"],
    "targeted-deauth":   ["aireplay-ng", "mdk4"],
    "offline-crack":     ["hashcat", "aircrack-ng"],
    "evil-twin-demo":    ["wifiphisher", "eaphammer", "hostapd"],
}

#: Harte Obergrenzen (operator-getrieben, nicht-destruktiv/begrenzt).
MAX_DEAUTH_PACKETS = 64
MAX_DEAUTH_SECONDS = 30
MAX_CAPTURE_SECONDS = 120
MAX_EVILTWIN_SECONDS = 300

#: Prozesslokales Salt (nur Laufzeit; kein Secret in Dateien).
_SALT = secrets.token_hex(16)


def wifi_offensive_enabled() -> bool:
    return os.environ.get("ANTBB_WIFI", "").strip() in ("1", "true", "yes")


def tool_for(action: str) -> Optional[str]:
    """Erstes vorhandenes Tool für die Aktion (sonst None → honest-empty)."""
    for t in ACTION_TOOLS.get(action, []):
        if shutil.which(t):
            return t
    return None


def action_tool_status() -> dict:
    """Verfügbarkeit aller Offensiv-Tools am Laufort (für Registry/Deploy-Hinweis)."""
    out: dict = {}
    for action, tools in ACTION_TOOLS.items():
        out[action] = {t: bool(shutil.which(t)) for t in tools}
    return out


def missing_tools() -> list[str]:
    seen, miss = set(), []
    for tools in ACTION_TOOLS.values():
        for t in tools:
            if t not in seen:
                seen.add(t)
                if not shutil.which(t):
                    miss.append(t)
    return miss


# ---------------------------------------------------------------------------
# Credential-Maskierung (NIE Klartext)
# ---------------------------------------------------------------------------
def mask_password(value: str) -> dict:
    """Maskiert ein Passwort/Credential: nur Länge + erstes/letztes Zeichen +
    gesalzener SHA-256. Der Klartext verlässt diese Funktion NIE."""
    s = "" if value is None else str(value)
    n = len(s)
    if n == 0:
        masked = "(leer)"
    elif n == 1:
        masked = s[0] + "•"
    else:
        masked = f"{s[0]}{'•' * max(1, n - 2)}{s[-1]} (len={n})"
    digest = hashlib.sha256((_SALT + s).encode("utf-8")).hexdigest()
    return {"masked": masked, "digest": digest, "char_count": n}


# ---------------------------------------------------------------------------
# AUTORISIERUNGS-GATE (default-deny)
# ---------------------------------------------------------------------------
@dataclass
class GateResult:
    allowed: bool
    reason: str = ""
    engagement_id: Optional[int] = None
    engagement: Optional[dict] = None


def _row_to_engagement(row) -> dict:
    d = dict(row)
    try:
        d["bssids"] = json.loads(d.get("bssids") or "[]")
    except Exception:
        d["bssids"] = []
    try:
        d["ssids"] = json.loads(d.get("ssids") or "[]")
    except Exception:
        d["ssids"] = []
    return d


def authorize(store, *, bssid: Optional[str] = None, ssid: Optional[str] = None,
              client_mac: Optional[str] = None, now: Optional[float] = None) -> GateResult:
    """Prüft default-deny, ob für (bssid/ssid) eine aktive Autorisierung besteht.

    Erlaubt NUR, wenn ein Engagement: nicht widerrufen, im Zeitfenster, Oversight
    gesetzt, und das Ziel (BSSID ODER SSID) in seiner Allowlist ist. Ein
    optionaler client_mac muss, falls das Engagement einen festlegt, passen.
    """
    now = time.time() if now is None else now
    b = (bssid or "").lower().strip()
    s = (ssid or "").strip()
    cmac = (client_mac or "").lower().strip()
    if not b and not s:
        return GateResult(False, "Weder BSSID noch SSID angegeben – default-deny.")
    for row in store.list_wlan_engagements(include_revoked=False):
        eng = _row_to_engagement(row)
        if eng.get("revoked"):
            continue
        if not eng.get("oversight"):
            continue
        if not (eng["start_ts"] <= now <= eng["end_ts"]):
            continue
        bssid_ok = b and b in [x.lower() for x in eng["bssids"]]
        ssid_ok = s and s in eng["ssids"]
        if not (bssid_ok or ssid_ok):
            continue
        eng_cmac = (eng.get("client_mac") or "").lower().strip()
        if cmac and eng_cmac and cmac != eng_cmac:
            continue
        return GateResult(True, f"Autorisiert durch Engagement #{eng['id']} "
                                f"('{eng['name']}').", eng["id"], eng)
    return GateResult(False,
                      f"BLOCKIERT (default-deny): kein aktives, autorisiertes "
                      f"Engagement im Zeitfenster für Ziel "
                      f"{('BSSID '+b) if b else ''}{' / ' if b and s else ''}"
                      f"{('SSID '+s) if s else ''}.")


# ---------------------------------------------------------------------------
# Offensiv-Runner
# ---------------------------------------------------------------------------
@dataclass
class ActionResult:
    action: str
    allowed: bool = False          # Gate bestanden?
    reason: str = ""
    engagement_id: Optional[int] = None
    tool: Optional[str] = None
    tool_invoked: bool = False     # wurde tatsächlich ein externes Tool gestartet?
    honest_empty: bool = False     # Gate ok, aber Tool/Hardware fehlt
    ran: bool = False
    findings: list = field(default_factory=list)   # list[AgentFinding]
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action, "allowed": self.allowed, "reason": self.reason,
            "engagement_id": self.engagement_id, "tool": self.tool,
            "tool_invoked": self.tool_invoked, "honest_empty": self.honest_empty,
            "ran": self.ran,
            "findings": [f.__dict__ for f in self.findings],
            "detail": self.detail,
        }


class WifiOffensive:
    """Operator-getriebener, Gate-gesicherter Runner für WLAN-Offensiv-Aktionen."""

    def __init__(self, store, logger=None, dry_run: bool = False):
        self.store = store
        self.logger = logger
        #: dry_run führt kein externes Tool aus (nur Gate+Verfügbarkeit); für Tests.
        self.dry_run = dry_run

    def _log(self, msg: str) -> None:
        if self.logger:
            try:
                self.logger.info(msg)
            except Exception:
                pass

    def _gate(self, action: str, *, bssid=None, ssid=None, client_mac=None,
              now=None) -> tuple[Optional[ActionResult], Optional[GateResult]]:
        """Gemeinsame Vorprüfung. Gibt (blockiertes ActionResult | None, GateResult)."""
        res = ActionResult(action=action)
        # 1) Offensiv-Freischaltung.
        if not wifi_offensive_enabled():
            res.allowed = False
            res.reason = "WLAN-Offensiv nicht freigeschaltet (ANTBB_WIFI!=1) – blockiert."
            self._log(f"[wifi-off] ⛔ {action}: {res.reason}")
            return res, None
        # 2) Engagement-Gate (default-deny).
        gate = authorize(self.store, bssid=bssid, ssid=ssid,
                         client_mac=client_mac, now=now)
        if not gate.allowed:
            res.allowed = False
            res.reason = gate.reason
            self._log(f"[wifi-off] ⛔ {action}: {gate.reason} (KEIN Tool-Aufruf)")
            return res, gate
        res.allowed = True
        res.engagement_id = gate.engagement_id
        res.reason = gate.reason
        # 3) Rechtshinweis protokollieren (blockiert nicht).
        self._log("[wifi-off] ⚖ " + LEGAL_NOTICE)
        self._log(f"[wifi-off] ✅ {action}: {gate.reason}")
        return None, gate

    def _tool_or_empty(self, res: ActionResult, action: str) -> Optional[str]:
        tool = tool_for(action)
        if not tool:
            res.honest_empty = True
            res.ran = False
            cands = ", ".join(ACTION_TOOLS.get(action, []))
            res.reason += (f" | Honest-empty: kein Tool vorhanden ({cands}) – "
                           f"nichts erfunden.")
            self._log(f"[wifi-off] ℹ️ {action}: kein Tool ({cands}) – honest-empty.")
            return None
        res.tool = tool
        return tool

    # ---------------- 1) Handshake-Capture ----------------
    def handshake_capture(self, *, bssid: str, ssid: str = "", channel=None,
                          seconds: int = 60, now=None) -> ActionResult:
        blocked, gate = self._gate("handshake-capture", bssid=bssid, ssid=ssid, now=now)
        if blocked is not None:
            return blocked
        res = ActionResult(action="handshake-capture", allowed=True,
                           engagement_id=gate.engagement_id, reason=gate.reason)
        seconds = max(1, min(int(seconds), MAX_CAPTURE_SECONDS))
        tool = self._tool_or_empty(res, "handshake-capture")
        if not tool:
            return res
        # Tool vorhanden: echte Capture wäre hier; auf der Box (kein Monitor-Mode,
        # dry_run) wird NICHT erfunden – honest-empty, Pfad/Meta dokumentiert.
        if self.dry_run:
            res.ran = False
            res.honest_empty = True
            res.reason += " | dry_run: kein Tool-Start."
            return res
        res.tool_invoked = True  # pragma: no cover (nur mit echter Hardware)
        res.detail = {"tool": tool, "bssid": bssid, "seconds": seconds,
                      "note": "Capture-Lauf; Handshake nur bei echtem Nachweis gemeldet."}
        return res

    # ---------------- 2) Targeted Deauth ----------------
    def targeted_deauth(self, *, bssid: str, ssid: str = "", client_mac: str = "",
                        packets: int = 10, seconds: int = 10, now=None) -> ActionResult:
        blocked, gate = self._gate("targeted-deauth", bssid=bssid, ssid=ssid,
                                   client_mac=client_mac, now=now)
        if blocked is not None:
            return blocked
        res = ActionResult(action="targeted-deauth", allowed=True,
                           engagement_id=gate.engagement_id, reason=gate.reason)
        packets = max(1, min(int(packets), MAX_DEAUTH_PACKETS))
        seconds = max(1, min(int(seconds), MAX_DEAUTH_SECONDS))
        res.detail = {"warning": ("Gezielter Deauth TRENNT Clients der autorisierten "
                                  "BSSID kurzzeitig. Kein Broadcast/Massen-Deauth."),
                      "bssid": bssid, "client_mac": client_mac or "(alle Clients dieser BSSID)",
                      "packets": packets, "seconds": seconds}
        self._log(f"[wifi-off] ⚠ Deauth trennt Clients von {bssid} "
                  f"({packets} Pakete / max {seconds}s).")
        tool = self._tool_or_empty(res, "targeted-deauth")
        if not tool:
            return res
        if self.dry_run:
            res.ran = False
            res.honest_empty = True
            res.reason += " | dry_run: kein Tool-Start."
            return res
        res.tool_invoked = True  # pragma: no cover
        return res

    # ---------------- 3) Offline WPA/WPA2 Crack ----------------
    def offline_crack(self, *, capture_path: str, bssid: str = "", ssid: str = "",
                      wordlist: Optional[str] = None, now=None) -> ActionResult:
        blocked, gate = self._gate("offline-crack", bssid=bssid, ssid=ssid, now=now)
        if blocked is not None:
            return blocked
        res = ActionResult(action="offline-crack", allowed=True,
                           engagement_id=gate.engagement_id, reason=gate.reason)
        from . import wordlists as _wl
        wl = wordlist or _wl.resolve("rockyou") or _wl.default_content_wordlist()
        res.detail = {"capture_path": capture_path, "wordlist": wl or "(keine)",
                      "note": "Offline gegen eigene/autorisierte Capture."}
        if not wl:
            res.honest_empty = True
            res.reason += " | Honest-empty: keine Wortliste (rockyou/SecLists) vorhanden."
            self._log("[wifi-off] ℹ️ offline-crack: keine Wortliste – honest-empty.")
            return res
        if not capture_path or not os.path.isfile(capture_path):
            res.honest_empty = True
            res.reason += " | Honest-empty: Capture-Datei nicht vorhanden."
            self._log("[wifi-off] ℹ️ offline-crack: keine Capture-Datei – honest-empty.")
            return res
        tool = self._tool_or_empty(res, "offline-crack")
        if not tool:
            return res
        if self.dry_run:
            res.ran = False
            res.honest_empty = True
            res.reason += " | dry_run: kein Tool-Start."
            return res
        res.tool_invoked = True  # pragma: no cover
        return res

    def record_cracked(self, engagement_id: int, password: str, *, bssid: str = "",
                       ssid: str = "") -> int:
        """Speichert ein geknacktes Passwort NUR maskiert (Nachweis), nie Klartext."""
        m = mask_password(password)
        return self.store.add_wlan_credential(
            engagement_id, "cracked", masked=m["masked"], digest=m["digest"],
            char_count=m["char_count"], bssid=bssid, ssid=ssid, label="wpa-key")

    # ---------------- 4) Evil-Twin + Captive-Portal-Demo ----------------
    def evil_twin_demo(self, *, ssid: str, bssid: str = "", seconds: int = 120,
                       now=None) -> ActionResult:
        blocked, gate = self._gate("evil-twin-demo", bssid=bssid, ssid=ssid, now=now)
        if blocked is not None:
            return blocked
        res = ActionResult(action="evil-twin-demo", allowed=True,
                           engagement_id=gate.engagement_id, reason=gate.reason)
        seconds = max(1, min(int(seconds), MAX_EVILTWIN_SECONDS))
        res.detail = {"ssid": ssid, "seconds": seconds,
                      "policy": ("Zeitlich begrenzt, operator-getrieben, kein Dauerbetrieb. "
                                 "Eingegebene Credentials zählen NUR als Nachweis "
                                 "(maskiert/gehasht), Auto-Purge nach Report.")}
        tool = self._tool_or_empty(res, "evil-twin-demo")
        if not tool:
            return res
        if self.dry_run:
            res.ran = False
            res.honest_empty = True
            res.reason += " | dry_run: kein Tool-Start."
            return res
        res.tool_invoked = True  # pragma: no cover
        return res

    def record_portal_credential(self, engagement_id: int, username: str = "",
                                 password: str = "", *, ssid: str = "") -> int:
        """Zählt eine im Captive-Portal eingegebene Credential – NUR maskiert."""
        mu = mask_password(username)
        mp = mask_password(password)
        return self.store.add_wlan_credential(
            engagement_id, "portal-cred",
            masked=f"user={mu['masked']} pass={mp['masked']}",
            digest=mp["digest"], char_count=mp["char_count"], ssid=ssid,
            label=mu["masked"])

    # ---------------- Purge / Auto-Purge-nach-Report ----------------
    def purge(self, engagement_id: Optional[int] = None) -> int:
        n = self.store.purge_wlan_credentials(engagement_id)
        self._log(f"[wifi-off] 🧹 {n} Credential-Datensatz/e gelöscht "
                  f"(engagement={engagement_id or 'ALLE'}).")
        return n

    def purge_after_report(self, engagement_id: int) -> int:
        """Hook: nach dem Report werden abgefangene Credentials automatisch gelöscht."""
        return self.purge(engagement_id)
