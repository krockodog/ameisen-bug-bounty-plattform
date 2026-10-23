"""Blue-Soldat: Incident-Response-Basics (Playbooks + Checklisten)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task

IR_PLAYBOOKS = [
    {"id": "ir-triage", "title": "Triage & Severity",
     "steps": ["Signal klassifizieren", "Business-Impact schätzen",
               "Severity (SEV1–4) setzen", "On-Call informieren"],
     "severity": "info"},
    {"id": "ir-contain", "title": "Containment",
     "steps": ["Betroffene Assets isolieren", "Credentials rotieren (geplant)",
               "Honeypot-Umleitung prüfen", "Firewall-Regel temporär setzen"],
     "severity": "medium"},
    {"id": "ir-eradicate", "title": "Eradication",
     "steps": ["Root-Cause eingrenzen", "Malware/Backdoor entfernen (geplant)",
               "Patches einspielen", "Persistenz prüfen"],
     "severity": "medium"},
    {"id": "ir-recover", "title": "Recovery & Lessons",
     "steps": ["Services kontrolliert wiederherstellen",
               "Monitoring schärfen", "Post-Incident-Report",
               "Playbook-Lücken schließen"],
     "severity": "info"},
    {"id": "ir-comms", "title": "Kommunikation",
     "steps": ["Stakeholder-Liste", "Status-Update-Takt",
               "Externe Meldepflichten prüfen", "Keine Secrets in Comms"],
     "severity": "info"},
]


class IncidentAnt(BlueAgent):
    name = "blue-incident"
    specialty = "blue-incident-responder"
    role = ("Incident-Response-Basics: Triage, Containment, Eradication, "
            "Recovery und Kommunikation als ausführbare Playbooks.")
    blue_phases = ("defend", "remediate", "verify")
    playbooks = (
        Playbook("ir-triage", "defensive", False,
                 ["severity-matrix", "on-call"],
                 "Incident triageen und Severity setzen.",
                 tasks=IR_PLAYBOOKS[0]["steps"]),
        Playbook("ir-containment", "defensive", True,
                 ["isolate-asset", "temp-firewall"],
                 "Containment-Schritte – aktive Isolation nur mit Oversight.",
                 tasks=IR_PLAYBOOKS[1]["steps"]),
        Playbook("ir-eradication-recovery", "defensive", True,
                 ["eradicate", "recover", "lessons-learned"],
                 "Eradication + Recovery + Lessons-Learned.",
                 tasks=IR_PLAYBOOKS[2]["steps"] + IR_PLAYBOOKS[3]["steps"]),
        Playbook("ir-comms", "defensive", False,
                 ["stakeholder-comms"],
                 "Kommunikations-Checkliste ohne Secrets.",
                 tasks=IR_PLAYBOOKS[4]["steps"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log(f"[blue-incident] 🚨 {len(IR_PLAYBOOKS)} IR-Playbooks bereit.")
        for pb in IR_PLAYBOOKS:
            findings.append(AgentFinding(
                agent=self.name, title=f"IR: {pb['title']}",
                category="blue-incident-playbook", severity=pb["severity"],
                asset="monitoring",
                description=" → ".join(pb["steps"]),
                evidence={"playbook_id": pb["id"], "steps": pb["steps"],
                          "oversight_for_active": pb["id"] in ("ir-contain", "ir-eradicate")},
                status="REFERENZ",
                dedup_key=f"blue-incident:{pb['id']}",
            ))
        return findings
