"""Blue-Soldat: Hardening-Audit (CIS-artig, read-only).

Prüft lokale System-/Dienst-Konfiguration rein lesend und liefert je Check
einen konkreten Fix-VORSCHLAG. Anwenden eines Fixes ist non-default und nur
mit Oversight-Freigabe (ctx.active) erlaubt – dieser Soldat führt KEINE
verändernden Kommandos aus (Scaffold: Fix-Apply ist dokumentiert/gated).
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import hardening as _hd


class HardeningAnt(BlueAgent):
    name = "blue-hardening"
    specialty = "blue-hardening-engineer"
    role = ("System-/Dienst-Härtung (CIS-artig, read-only): sichere Configs "
            "prüfen und konkrete Fix-Empfehlungen geben. Fix-Apply nur gated.")
    blue_phases = ("assess", "harden")
    playbooks = (
        Playbook("hardening-audit", "defensive", False,
                 ["ssh-config-review", "firewall-status", "world-writable-scan",
                  "sysctl-hardening"],
                 "Read-only CIS-artige Prüfung (SSH, Firewall, Dateirechte, "
                 "Kernel-sysctl) mit Fix-Empfehlung je Befund."),
        Playbook("hardening-apply", "defensive", True,
                 ["apply-recommended-fix"],
                 "Anwenden einer empfohlenen Härtung – NUR mit Oversight-"
                 "Freigabe (default-deny, Scaffold/dokumentiert)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-hardening] 🛡 Read-only Hardening-Audit (CIS-artig).")
        results = _hd.run_audit()
        n_fail = sum(1 for r in results if r.status == "fail")
        self.ctx.log(f"[blue-hardening] {len(results)} Check(s), {n_fail} Abweichung(en).")

        _sev = {"high": "high", "medium": "medium", "low": "low"}
        for r in results:
            if r.status == "pass":
                sev, status, cat = "info", "BESTÄTIGT(PASSIV)", "blue-hardening-pass"
            elif r.status == "fail":
                sev = _sev.get(r.severity, "low")
                status, cat = "BESTÄTIGT(PASSIV)", "blue-hardening-gap"
            else:
                sev, status, cat = "info", "REFERENZ", "blue-hardening-na"
            ev = {"check_id": r.check_id, "check_status": r.status,
                  "recommendation": r.recommendation,
                  "fix_command": r.fix_command}
            ev.update(r.evidence or {})
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[{r.status.upper()}] {r.title}",
                category=cat, severity=sev, asset="localhost",
                description=(r.detail + (f" · Empfehlung: {r.recommendation}"
                                          if r.recommendation else "")),
                evidence=ev, status=status,
                dedup_key=f"blue-hardening:{r.check_id}",
            ))

        if self.active_allowed():
            self.ctx.log("[blue-hardening] ⚠️ Fix-Apply freigegeben (Oversight) – "
                         "im Scaffold werden Fixes dokumentiert, NICHT automatisch "
                         "ausgeführt (bewusst konservativ).")
        return findings
