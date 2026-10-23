"""Basis für Blue-Audit-Soldaten (read-only Posture-Checks mit Fix-Vorschlag).

Alle Audit-Soldaten teilen ein Muster: `collect()` liefert `CheckResult`s
(pass | fail | info); `AuditAnt.to_findings()` macht daraus Findings:
  * pass  → info/BESTÄTIGT(PASSIV)   Kategorie blue-audit-pass
  * fail  → Severity des Checks      Kategorie blue-audit-gap  (remedierbar)
  * info  → REFERENZ                 Kategorie blue-audit-na   (ehrlich "nicht prüfbar")
Fixes werden nur VORGESCHLAGEN (fix_command), nie ausgeführt.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import hardening as _hd

CheckResult = _hd.CheckResult

_SEV = {"high": "high", "medium": "medium", "low": "low", "critical": "critical"}


class AuditAnt(BlueAgent):
    """Soldat mit `audit_id` (Modulname) und `collect()` (modulweite Funktion)."""

    audit_id: str = ""
    asset: str = "localhost"

    def collect(self, task: Task) -> list[CheckResult]:  # pragma: no cover
        raise NotImplementedError

    def to_findings(self, results: list[CheckResult]) -> list[AgentFinding]:
        out: list[AgentFinding] = []
        for r in results:
            if r.status == "pass":
                sev, status, cat = "info", "BESTÄTIGT(PASSIV)", "blue-audit-pass"
            elif r.status == "fail":
                sev, status, cat = _SEV.get(r.severity, "low"), "BESTÄTIGT(PASSIV)", "blue-audit-gap"
            else:
                sev, status, cat = "info", "REFERENZ", "blue-audit-na"
            ev = {"audit": self.audit_id, "check_id": r.check_id,
                  "check_status": r.status, "recommendation": r.recommendation,
                  "fix_command": r.fix_command}
            ev.update(r.evidence or {})
            out.append(AgentFinding(
                agent=self.name,
                title=f"[{r.status.upper()}] {r.title}",
                category=cat, severity=sev, asset=self.asset,
                description=(r.detail + (f" · Empfehlung: {r.recommendation}"
                                          if r.recommendation else "")),
                evidence=ev, status=status,
                dedup_key=f"blue-{self.audit_id}:{r.check_id}"))
        return out

    async def work(self, task: Task) -> list[AgentFinding]:
        self.ctx.log(f"[{self.name}] 🛡 Read-only Audit '{self.audit_id}'.")
        results = self.collect(task)
        nf = sum(1 for r in results if r.status == "fail")
        self.ctx.log(f"[{self.name}] {len(results)} Check(s), {nf} Abweichung(en).")
        if self.active_allowed():
            self.ctx.log(f"[{self.name}] ⚠️ Fix-Apply freigegeben (Oversight) – im "
                         "Scaffold werden Fixes dokumentiert, NICHT automatisch ausgeführt.")
        return self.to_findings(results)


__all__ = ["AuditAnt", "CheckResult", "Playbook", "Task"]
