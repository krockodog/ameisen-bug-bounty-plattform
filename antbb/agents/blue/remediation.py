"""Blue-Soldat: Schadensbeseitigung/Remediation (Finding → Fix → Re-Check).

Nimmt vorhandene Findings (aus task.context_findings bzw. task.params['findings'])
und erzeugt je Finding einen konkreten Behebungsschritt sowie einen rein
lesenden RE-CHECK, der belegt, ob die Lücke „nachweislich geschlossen" ist.
Non-destruktiv: es wird nichts automatisch verändert.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import remediation as _rem


class RemediationAnt(BlueAgent):
    name = "blue-remediation"
    specialty = "blue-remediation-medic"
    role = ("Schadensbeseitigung: Finding→Fix-Pipeline mit non-destruktivem "
            "Re-Check, der belegt, dass die Lücke geschlossen ist.")
    blue_phases = ("remediate", "verify")
    playbooks = (
        Playbook("remediation-plan", "defensive", False,
                 ["derive-fix-step", "fix-command-suggestion"],
                 "Je Finding einen konkreten, überprüfbaren Behebungsschritt "
                 "ableiten (Fix-Vorschlag, nie automatisch angewendet)."),
        Playbook("remediation-verify", "defensive", False,
                 ["read-only-recheck", "before-after-evidence"],
                 "Rein lesender Re-Check: belegt, ob die Lücke nach dem Fix "
                 "tatsächlich geschlossen ist (Vorher/Nachher-Evidence)."),
    )

    def _candidate_findings(self, task: Task) -> list[dict]:
        out: list[dict] = []
        params = task.params or {}
        for f in (params.get("findings") or []):
            if isinstance(f, dict):
                out.append(f)
        # Zusätzlich aus Kontext-Findings dieses Laufs (von der Blue Queen gefüllt).
        for f in task.context_findings or []:
            out.append({"category": f.category, "title": f.title,
                        "dedup_key": f.key(), "evidence": f.evidence,
                        "severity": f.severity})
        # Nur remedierbare Kategorien.
        remediable = {"blue-hardening-gap", "blue-outdated-software"}
        return [f for f in out if f.get("category") in remediable]

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        cands = self._candidate_findings(task)
        if not cands:
            self.ctx.log("[blue-remediation] Keine remedierbaren Findings übergeben "
                         "– übersprungen (honest-empty).")
            return findings
        self.ctx.log(f"[blue-remediation] 🩺 {len(cands)} Finding(s) → Fix-Pipeline.")
        closed_n = 0
        for f in cands:
            step = _rem.verify_closed(f)
            if step.closed is True:
                closed_n += 1
                status, cat, sev = "BESTÄTIGT(PASSIV)", "blue-remediation-verified", "info"
                verdict = "NACHWEISLICH GESCHLOSSEN"
            elif step.closed is False:
                status, cat, sev = "ZU BESTÄTIGEN", "blue-remediation-open", "medium"
                verdict = "NOCH OFFEN"
            else:
                status, cat, sev = "REFERENZ", "blue-remediation-open", "info"
                verdict = "NICHT AUTOMATISCH PRÜFBAR"
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[{verdict}] {step.title}",
                category=cat, severity=sev, asset="localhost",
                description=(f"Fix: {step.fix_action}"
                             + (f" · Befehl-Vorschlag: {step.fix_command}" if step.fix_command else "")
                             + f" · Re-Check: {step.verify_method}"),
                evidence={"fix_action": step.fix_action,
                          "fix_command": step.fix_command,
                          "verify_method": step.verify_method,
                          "closed": step.closed,
                          "recheck": step.evidence,
                          "source_finding": step.finding_key},
                status=status,
                dedup_key=f"blue-remediation:{step.finding_key}",
            ))
        self.ctx.log(f"[blue-remediation] ✅ {closed_n}/{len(cands)} nachweislich geschlossen.")
        return findings
