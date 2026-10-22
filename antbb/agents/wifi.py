"""WiFi-Hunter: WLAN-Sicherheitscheck + Optimierung (NUR lokal/autorisiert).

Harte Leitplanken:
  * Läuft NUR, wenn ein WLAN-Adapter + passende Tools vorhanden sind UND der
    Check ausdrücklich freigeschaltet ist (env ANTBB_WIFI=1). Ohne Hardware/
    Autorisierung: ehrlich-leer (keine erfundenen Netze).
  * Rein lesender Netz-Scan (nmcli/iw/iwlist). Verschlüsselungs-/Konfig-Check,
    Kanal-/Signal-Optimierungsempfehlung.
  * Handshake-Capture/Cracking ist NUR als dokumentierte, oversight-pflichtige,
    NICHT automatisch laufende Option vorhanden (ehrlich gekennzeichnet).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

from .base import (AntAgent, AgentFinding, Task, Playbook,
                   STATUS_PASSIVE, STATUS_TO_CONFIRM)


class WifiHunterAnt(AntAgent):
    name = "wifi"
    role = "WiFi-Hunter: WLAN-Verschlüsselung/Konfig-Check + Kanal-Optimierung (nur autorisiert)"
    specialty = "wifi-hunter"
    phases = ("recon",)
    playbooks = (
        Playbook("wlan-scan", "defensive", False,
                 ["nmcli", "iw", "iwlist"],
                 "Lokale WLAN-Netze scannen + Verschlüsselung (WPA2/WPA3/WEP/offen) bestimmen."),
        Playbook("wlan-konfig-check", "defensive", False,
                 ["encryption-audit"],
                 "Schwache WLAN-Konfiguration erkennen (WEP/offen/WPS/TKIP)."),
        Playbook("wlan-optimierung", "defensive", False,
                 ["channel-advice", "signal-advice"],
                 "Kanal-/Signal-Optimierungsempfehlung ableiten."),
        Playbook("wlan-coverage-survey", "defensive", False,
                 ["iw-scan", "channel-overlap", "coverage-heatmap"],
                 "PASSIVE Abdeckung/Kanal-Überlappung/Selbst-Störung + Optimierung "
                 "(nur lauschend; kein Deauth/Evil-Twin/Crack)."),
        # --- AUTORISIERTE Offensiv-Playbooks (Engagement-Gate + Oversight + ANTBB_WIFI=1).
        # Jede Aktion läuft NUR über das harte Autorisierungs-Gate (default-deny),
        # operator-getrieben, honest-empty wenn Tool/Hardware fehlt. Siehe
        # antbb.wlan_offensive. KEIN automatischer Lauf im Schwarm.
        Playbook("wlan-handshake-capture", "offensive", True,
                 ["hcxdumptool", "airodump-ng"],
                 "WPA-Handshake/PMKID gegen AUTORISIERTE BSSID erfassen (Gate-pflichtig, "
                 "operator-getrieben). Speichert Capture-Pfad+Metadaten, keine Zugangsdaten im Klartext."),
        Playbook("wlan-targeted-deauth", "offensive", True,
                 ["aireplay-ng", "mdk4"],
                 "GEZIELTER Deauth NUR gegen autorisierte BSSID (optional Client-MAC), "
                 "paket-/zeitbegrenzt. Kein Broadcast/Massen-Deauth. Trennt Clients."),
        Playbook("wlan-offline-crack", "offensive", True,
                 ["aircrack-ng", "hashcat"],
                 "OFFLINE WPA/WPA2-Crack gegen eigene/autorisierte Capture mit Wortliste "
                 "(rockyou/SecLists). Ergebnis maskiert, nie Klartext."),
        Playbook("wlan-evil-twin-demo", "offensive", True,
                 ["wifiphisher", "eaphammer", "hostapd"],
                 "Evil-Twin + Captive-Portal-DEMO für autorisierte Awareness-Tests. "
                 "Credentials nur als Nachweis (maskiert/gehasht), Auto-Purge nach Report."),
    )

    # ------------------------------------------------------------------
    # AUTORISIERTE Offensiv-Aktionen (operator-getrieben, NICHT im Schwarm-Lauf).
    # Jede Aktion prüft Gate + Oversight über antbb.wlan_offensive, bevor
    # irgendetwas passiert; Funde tragen Proof-Gate-Labels.
    # ------------------------------------------------------------------
    def run_offensive(self, store, action: str, **kwargs) -> list[AgentFinding]:
        """Führt EINE autorisierte Offensiv-Aktion aus und liefert Findings.

        Blockiert (ohne Tool-Aufruf), wenn das Engagement-Gate verweigert. Bei
        fehlendem Tool/Hardware: honest-empty (keine Findings erfunden).
        """
        from .. import wlan_offensive as wo
        off = wo.WifiOffensive(store, logger=getattr(self.ctx, "logger", None),
                               dry_run=bool(kwargs.pop("dry_run", False)))
        runner = {
            "handshake-capture": off.handshake_capture,
            "targeted-deauth": off.targeted_deauth,
            "offline-crack": off.offline_crack,
            "evil-twin-demo": off.evil_twin_demo,
        }.get(action)
        if runner is None:
            self.ctx.log(f"[wifi] ⛔ unbekannte Offensiv-Aktion '{action}'.")
            return []
        res = runner(**kwargs)
        return self._findings_from_result(res)

    def _findings_from_result(self, res) -> list[AgentFinding]:
        from ..agents.base import STATUS_VERIFIED, STATUS_TO_CONFIRM, STATUS_CONDITIONAL
        if not res.allowed:
            # Gate-Block: bewusst KEIN Finding (nichts nachgewiesen) – nur geloggt.
            return []
        if res.honest_empty or not res.ran:
            # Autorisiert, aber Tool/Hardware fehlt → ehrlich leer, kein Fund.
            return []
        # Nur ein real durchgeführter, aktiv nachgewiesener Lauf wird gemeldet.
        sev = {"handshake-capture": "medium", "targeted-deauth": "low",
               "offline-crack": "high", "evil-twin-demo": "high"}.get(res.action, "info")
        return [AgentFinding(
            agent=self.name, title=f"WLAN-Offensiv: {res.action} (autorisiert)",
            category="wlan-offensive", severity=sev,
            asset=res.detail.get("bssid") or res.detail.get("ssid", ""),
            description=res.reason,
            evidence={"source": res.action, "engagement_id": res.engagement_id,
                      "tool": res.tool, "detail": res.detail,
                      "response_excerpt": "aktiv durchgeführt (autorisiert)"},
            status=STATUS_VERIFIED,
            dedup_key=f"wlan-offensive:{res.action}:{res.engagement_id}",
        )]

    async def work(self, task: Task) -> list[AgentFinding]:
        out: list[AgentFinding] = []
        if os.environ.get("ANTBB_WIFI", "").strip() not in ("1", "true", "yes"):
            self.ctx.log("[wifi] WLAN-Audit nicht freigeschaltet (ANTBB_WIFI!=1) – ehrlich leer.")
            return out
        tool = None
        for t in ("nmcli", "iw", "iwlist"):
            if shutil.which(t):
                tool = t
                break
        if not tool:
            self.ctx.log("[wifi] Kein WLAN-Tool (nmcli/iw/iwlist) vorhanden – ehrlich leer.")
            return out
        try:
            import asyncio
            nets = await asyncio.to_thread(self._scan, tool)
        except Exception as exc:
            self.ctx.log(f"[wifi] Scan fehlgeschlagen: {exc}")
            return out
        if not nets:
            self.ctx.log("[wifi] Keine WLAN-Netze sichtbar (ehrlich leer).")
            return out
        for n in nets:
            enc = (n.get("security") or "").upper()
            weak = (not enc) or "WEP" in enc or enc in ("", "--", "NONE", "OPEN")
            sev = "medium" if weak else "info"
            out.append(AgentFinding(
                agent=self.name,
                title=f"WLAN: {n.get('ssid','(versteckt)')} [{enc or 'OFFEN'}]",
                category="misconfig" if weak else "fingerprint",
                severity=sev, asset=n.get("ssid", ""),
                description=(f"WLAN '{n.get('ssid','')}' – Verschlüsselung: {enc or 'OFFEN/unverschlüsselt'}"
                            + (" (schwach/unsicher!)" if weak else " (ok).")
                            + (f" Kanal {n.get('channel')}," if n.get('channel') else "")
                            + (f" Signal {n.get('signal')}." if n.get('signal') else "")),
                evidence={"ssid": n.get("ssid", ""), "security": enc,
                          "channel": n.get("channel", ""), "signal": n.get("signal", ""),
                          "tool": tool, "source": "wlan-scan"},
                status=STATUS_PASSIVE if not weak else STATUS_TO_CONFIRM,
                dedup_key=f"wifi:{n.get('ssid','')}:{n.get('channel','')}",
            ))
        self.ctx.log(f"[wifi] {len(nets)} WLAN-Netz(e) analysiert.")
        out.extend(self._coverage_findings(task))
        return out

    def _scan(self, tool: str) -> list[dict]:
        nets: list[dict] = []
        if tool == "nmcli":
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            for line in (proc.stdout or b"").decode("utf-8", "replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    nets.append({"ssid": parts[0], "channel": parts[1],
                                 "signal": parts[2], "security": parts[3]})
        return nets

    def _coverage_findings(self, task: Task) -> list[AgentFinding]:
        """PASSIVE Kanal-/Selbst-Störungs-Analyse (nur lauschend, honest-empty)."""
        out: list[AgentFinding] = []
        try:
            from .. import wlan_survey as ws
        except Exception:
            return out
        res = ws.scan_environment(log=self.ctx.log)
        aps = res.get("aps", [])
        if not aps:
            return out
        own = [str(m) for m in self.my_mems() if ws.re.match(r"^[0-9a-fA-F:]{17}$", str(m).strip())]
        ca = ws.analyze_channels(
            [ws.AccessPoint(**{k: a.get(k) for k in
              ("bssid","ssid","channel","band","freq_mhz","rssi","encryption","is_own")})
             for a in aps], own_bssids=own)
        for c in ca.get("self_interference", []):
            out.append(AgentFinding(
                agent=self.name,
                title=f"WLAN-Selbst-Störung ({c['kind']}, {c['band']} GHz)",
                category="misconfig", severity=c["severity"],
                asset=c["ap_a"].get("ssid") or c["ap_a"].get("bssid", ""),
                description=c["note"],
                evidence={"source": "wlan-coverage-survey", "kind": c["kind"],
                          "ap_a": c["ap_a"], "ap_b": c["ap_b"], "band": c["band"]},
                status=STATUS_PASSIVE,
                dedup_key=f"wifi-selfint:{c['ap_a'].get('bssid')}:{c['ap_b'].get('bssid')}",
            ))
        return out
