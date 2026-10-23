"""Blue-Soldat: Supply-Chain / Dependency-Audit (OSV)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import supplychain as _sc


class SupplyChainAnt(BlueAgent):
    name = "blue-supplychain"
    specialty = "blue-supplychain-auditor"
    role = ("Supply-Chain: Manifeste lesen und Abhängigkeiten gegen OSV "
            "abgleichen. Nichts erfinden.")
    blue_phases = ("assess", "verify")
    playbooks = (
        Playbook("sc-manifest-inventory", "defensive", False,
                 ["requirements.txt", "package-lock.json", "pyproject.toml"],
                 "Dependency-Manifeste inventarisieren.",
                 tasks=["Manifeste finden", "Pakete+Versionen parsen",
                        "Inventar-Finding erzeugen"]),
        Playbook("sc-osv-audit", "defensive", False,
                 ["osv-querybatch"],
                 "Gepinnte Pakete gegen OSV abgleichen.",
                 tasks=["Pakete mit Version wählen", "OSV abfragen",
                        "CVE-IDs nur aus OSV", "Offline sauber skippen"]),
        Playbook("sc-remediation-hints", "defensive", False,
                 ["bump-version-hints"],
                 "Update-/Pin-Hinweise je Treffer.",
                 tasks=["fixed-Version aus OSV", "Priorität nach Severity",
                        "Kein automatisches Upgrade"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        online = bool((task.params or {}).get("online", True))
        self.ctx.log(f"[blue-supplychain] 📦 Dependency-Audit (online={online}).")
        for r in _sc.audit(online=online):
            sev = r.severity if r.status == "fail" else "info"
            status = ("REFERENZ" if r.status == "fail"
                      else ("BESTÄTIGT(PASSIV)" if r.status == "pass" else "REFERENZ"))
            findings.append(AgentFinding(
                agent=self.name, title=r.title,
                category=f"blue-supplychain-{r.status}", severity=sev,
                asset="localhost",
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence=r.to_dict(), status=status,
                dedup_key=f"blue-supplychain:{r.check_id}",
            ))
        return findings
