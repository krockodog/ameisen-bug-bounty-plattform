"""Blue-Soldat: Network-Defense (lokale Listener + Firewall)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import netdef as _nd


class NetDefAnt(BlueAgent):
    name = "blue-netdef"
    specialty = "blue-network-defender"
    role = ("Network-Defense: lokale Listening-Ports und Firewall-Status "
            "rein lesend prüfen. Kein Scan fremder Ziele.")
    blue_phases = ("assess", "harden", "defend")
    playbooks = (
        Playbook("net-listen-audit", "defensive", False,
                 ["ss-netstat", "risky-port-catalog"],
                 "Lokale Listener erfassen und Risiko-Ports markieren.",
                 tasks=["ss/netstat lesen", "Ports extrahieren",
                        "Gegen Risiko-Katalog matchen", "Empfehlungen geben"]),
        Playbook("net-firewall-status", "defensive", False,
                 ["ufw", "firewalld", "nftables", "iptables"],
                 "Firewall-Tool und Aktiv-Status prüfen.",
                 tasks=["Tool erkennen", "Aktiv-Status lesen",
                        "Default-Deny empfehlen wenn inaktiv"]),
        Playbook("net-exposure-report", "defensive", False,
                 ["exposure-summary"],
                 "Exposure-Report aus Listener+Firewall bündeln.",
                 tasks=["Findings aggregieren", "Priorität setzen",
                        "Härtungsmaßnahmen vorschlagen"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-netdef] 🌐 Network-Defense-Audit.")
        for r in _nd.run_audit():
            sev = r.severity if r.status == "fail" else "info"
            status = ("ZU BESTÄTIGEN" if r.status == "fail"
                      else ("BESTÄTIGT(PASSIV)" if r.status == "pass" else "REFERENZ"))
            findings.append(AgentFinding(
                agent=self.name, title=r.title,
                category=f"blue-netdef-{r.status}", severity=sev,
                asset="localhost",
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence=r.to_dict(), status=status,
                dedup_key=f"blue-netdef:{r.check_id}",
            ))
        return findings
