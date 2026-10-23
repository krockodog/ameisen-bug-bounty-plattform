"""Blue-Soldat: Finding→Ticket→Close: offene Blue-/Härtungsfunde als Tickets strukturieren und Close-Kriterien definieren.

Rein lesend / non-destruktiv. Aktive Änderungen nur oversight-gated (Scaffold).
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task


class VulnTicketAnt(BlueAgent):
    name = "blue-vulnticket"
    specialty = "blue-vuln-ticket-closer"
    role = ("Finding→Ticket→Close: offene Blue-/Härtungsfunde als Tickets strukturieren und Close-Kriterien definieren.")
    blue_phases = ("remediate", "verify",)
    playbooks = (
        Playbook("ticket-backlog", "defensive", False,
                 ['open-findings-to-tickets'],
                 "Offene remedierbare Findings als Ticket-Backlog strukturieren (kein externes Ticket-System nötig)."),
        Playbook("ticket-close-criteria", "defensive", False,
                 ['evidence-before-after', 'proof-gate'],
                 "Close nur mit Vorher/Nachher-Evidence und Proof-Gate-Kriterien."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:

        findings: list[AgentFinding] = []
        self.ctx.log("[blue-vulnticket] 🎫 Ticket-Backlog aus bekannten Gaps.")
        # Rein struktureller Report — keine erfundenen CVEs.
        backlog = [
            {"id": "T-HARDEN-SSH", "title": "SSH-Härtung prüfen/schließen",
             "close": "PermitRootLogin/PasswordAuth belegt hart"},
            {"id": "T-FW-DEFAULT", "title": "Firewall Default-Drop verifizieren",
             "close": "Policy/Snapshot nach Fix gespeichert"},
            {"id": "T-PATCH-SEC", "title": "Security-Patches im Fenster",
             "close": "Update-Log + Reboot-Status"},
        ]
        for t in backlog:
            findings.append(AgentFinding(
                agent=self.name, title=f"Ticket {t['id']}: {t['title']}",
                category="blue-vuln-ticket", severity="info", asset="process",
                description=f"Close-Kriterium: {t['close']}",
                evidence=t, status="REFERENZ",
                dedup_key=f"blue-ticket:{t['id']}",
            ))
        findings.append(AgentFinding(
            agent=self.name, title="Close-Policy (Proof-Gate)",
            category="blue-vuln-close", severity="info", asset="process",
            description="Geschlossen erst mit Vorher/Nachher-Evidence; sonst offen lassen.",
            evidence={"requires": ["before", "after", "proof_gate"]},
            status="REFERENZ", dedup_key="blue-ticket:close-policy",
        ))
        return findings

