"""Blue-Soldat: Abwehr/Defense (Detection/Monitoring-Regeln, Blue-Playbooks).

Liefert konkrete, einsatzfertige Detection-Regeln (z.B. Sigma-artige
Beschreibungen) und Monitoring-Empfehlungen als Report. Schreibt nichts in
fremde Systeme; optional werden Events an Splunk (HEC) gespiegelt, wenn ein
Ziel konfiguriert ist (sonst sauber übersprungen).
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import splunk as _splunk

#: Kuratiertes, generisches Detection-Set (keine Secrets/PII, allgemeingültig).
DETECTION_RULES = [
    {"id": "auth-bruteforce", "title": "SSH/Login-Brute-Force",
     "logic": "Mehr als N fehlgeschlagene Auth-Versuche je Quelle in kurzer Zeit.",
     "sources": ["auth.log", "wazuh/ossec", "windows-security-4625"],
     "severity": "medium"},
    {"id": "new-listening-port", "title": "Neuer Listening-Port",
     "logic": "Prozess öffnet einen zuvor nicht beobachteten Netzwerk-Port.",
     "sources": ["ss/netstat-baseline", "auditd"], "severity": "medium"},
    {"id": "suspicious-outbound", "title": "Auffälliger ausgehender Verkehr",
     "logic": "Verbindung zu bekannten C2/Tor-Exit/ungewöhnlichem Ziel.",
     "sources": ["firewall-log", "zeek/suricata"], "severity": "high"},
    {"id": "priv-esc-sudo", "title": "Unerwartete sudo/Privileg-Eskalation",
     "logic": "sudo durch Konto ohne übliche Admin-Rolle.",
     "sources": ["auth.log", "auditd-execve"], "severity": "high"},
    {"id": "persistence-cron", "title": "Neue Persistenz (cron/systemd-timer)",
     "logic": "Neuer cron-Job/Timer/Autostart außerhalb Change-Window.",
     "sources": ["auditd-file", "systemd"], "severity": "medium"},
]


class DefenseAnt(BlueAgent):
    name = "blue-defense"
    specialty = "blue-defense-sentinel"
    role = ("Abwehr/Monitoring: Detection-Regeln (Sigma-artig) und Blue-"
            "Playbooks bereitstellen; optional Events an Splunk spiegeln.")
    blue_phases = ("defend",)
    playbooks = (
        Playbook("detection-ruleset", "defensive", False,
                 ["sigma-like-rules", "monitoring-recommendations"],
                 "Kuratiertes Detection-Regelset (Brute-Force, neue Ports, "
                 "C2-Outbound, Priv-Esc, Persistenz) als Report."),
        Playbook("splunk-forward", "defensive", False,
                 ["hec-event-forward"],
                 "Findings/Events optional an ein konfiguriertes Splunk-HEC-Ziel "
                 "spiegeln (ohne Config sauber übersprungen)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log(f"[blue-defense] 🛰 {len(DETECTION_RULES)} Detection-Regel(n) bereitgestellt.")
        for r in DETECTION_RULES:
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Detection: {r['title']}",
                category="blue-detection-rule", severity="info",
                asset="monitoring",
                description=f"{r['logic']} · Quellen: {', '.join(r['sources'])}",
                evidence={"rule_id": r["id"], "logic": r["logic"],
                          "sources": r["sources"], "detect_severity": r["severity"]},
                status="REFERENZ",
                dedup_key=f"blue-detection:{r['id']}",
            ))

        # Optionales Splunk-Spiegeln (ohne Config = übersprungen).
        st = _splunk.status()
        if st["configured"]:
            events = [_splunk.finding_to_event(
                {"agent": self.name, "title": f.title, "category": f.category,
                 "severity": f.severity, "status": f.status, "asset": f.asset})
                for f in findings]
            res = _splunk.send_events(events)
            self.ctx.log(f"[blue-defense] Splunk-HEC: {res}")
            findings.append(AgentFinding(
                agent=self.name, title="Splunk-HEC-Weiterleitung",
                category="blue-splunk-forward", severity="info", asset="monitoring",
                description=f"Events an Splunk gespiegelt: ok={res.get('ok')}, sent={res.get('sent')}.",
                evidence={"splunk": {k: v for k, v in res.items()}},
                status="REFERENZ", dedup_key="blue-splunk-forward"))
        else:
            self.ctx.log("[blue-defense] Splunk-HEC nicht konfiguriert (ENV) – "
                         "Weiterleitung sauber übersprungen.")
        return findings
