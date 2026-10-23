"""Blue-Soldat: Credential-Hygiene (Dateirechte, Keys/.env – Secrets maskiert)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import credhygiene as _ch


class CredHygieneAnt(BlueAgent):
    name = "blue-credhygiene"
    specialty = "blue-credential-hygienist"
    role = ("Credential-Hygiene: Rechte von Keys/.env prüfen. Werte nie "
            "ausgeben – nur Pfade und Modi.")
    blue_phases = ("assess", "harden")
    playbooks = (
        Playbook("cred-key-permissions", "defensive", False,
                 ["ssh-key-mode", "env-file-mode"],
                 "Private Keys und .env auf zu offene Rechte prüfen.",
                 tasks=["Standard-Pfade scannen", "mode/world-readable prüfen",
                        "Findings ohne Klartext-Secrets", "chmod-Empfehlung"]),
        Playbook("cred-hygiene-report", "defensive", False,
                 ["hygiene-summary"],
                 "Zusammenfassung Credential-Hygiene.",
                 tasks=["Treffer zählen", "High-Findings priorisieren",
                        "Remediation-Hinweise bündeln"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-credhygiene] 🔑 Credential-Hygiene-Scan.")
        results = _ch.scan_key_permissions()
        n_fail = sum(1 for r in results if r.status == "fail")
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Credential-Hygiene: {n_fail} Abweichung(en)",
            category="blue-credhygiene-summary", severity="info",
            asset="localhost",
            description="Read-only Rechte-Scan; Secrets immer maskiert/nicht gelesen.",
            evidence={"fail_count": n_fail, "total": len(results),
                      "capabilities": _ch.capability_summary()},
            status="BESTÄTIGT(PASSIV)",
            dedup_key="blue-credhygiene-summary",
        ))
        for r in results:
            if r.status == "info" and r.check_id == "cred-none":
                findings.append(AgentFinding(
                    agent=self.name, title=r.title,
                    category="blue-credhygiene-empty", severity="info",
                    asset="localhost", description=r.detail,
                    evidence=r.to_dict(), status="REFERENZ",
                    dedup_key=f"blue-credhygiene:{r.check_id}",
                ))
                continue
            if r.status not in ("fail", "pass"):
                continue
            findings.append(AgentFinding(
                agent=self.name, title=r.title,
                category=f"blue-credhygiene-{r.status}",
                severity=r.severity if r.status == "fail" else "info",
                asset="localhost",
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence=r.to_dict(),
                status="ZU BESTÄTIGEN" if r.status == "fail" else "BESTÄTIGT(PASSIV)",
                dedup_key=f"blue-credhygiene:{r.check_id}",
            ))
        return findings
