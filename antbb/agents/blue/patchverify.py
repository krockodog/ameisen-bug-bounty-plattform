"""Blue-Soldat: Patch-/Config-Verify nach Remediation."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import hardening as _hd
from ... import remediation as _rem


class PatchVerifyAnt(BlueAgent):
    name = "blue-patchverify"
    specialty = "blue-patch-verifier"
    role = ("Patch-/Config-Verify: nach Remediation rein lesend prüfen, "
            "ob Härtung/Patch wirklich greift (Vorher/Nachher).")
    blue_phases = ("verify", "remediate")
    playbooks = (
        Playbook("patch-recheck", "defensive", False,
                 ["hardening-reaudit", "before-after"],
                 "Hardening-Checks erneut ausführen und Diff bewerten.",
                 tasks=["Audit erneut laufen", "Status je Check erfassen",
                        "Abweichungen melden", "Passes als geschlossen markieren"]),
        Playbook("patch-verify-finding", "defensive", False,
                 ["verify-closed"],
                 "Einzelne Findings auf 'nachweislich geschlossen' prüfen.",
                 tasks=["Finding-Key lesen", "verify_closed aufrufen",
                        "Evidence Vorher/Nachher speichern"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-patchverify] ✅ Re-Audit nach Remediation.")
        results = _hd.run_audit()
        n_fail = sum(1 for r in results if r.status == "fail")
        n_pass = sum(1 for r in results if r.status == "pass")
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Patch-Verify: {n_pass} pass / {n_fail} fail",
            category="blue-patchverify-summary", severity="info",
            asset="localhost",
            description="Read-only Re-Audit der CIS-artigen Hardening-Checks.",
            evidence={"pass": n_pass, "fail": n_fail, "total": len(results)},
            status="BESTÄTIGT(PASSIV)",
            dedup_key="blue-patchverify-summary",
        ))
        for r in results:
            if r.status == "pass":
                continue
            sev = {"high": "high", "medium": "medium", "low": "low"}.get(r.severity, "low")
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[OPEN] {r.title}",
                category="blue-patchverify-open", severity=sev,
                asset="localhost",
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence={"check_id": r.check_id, "status": r.status,
                          "recommendation": r.recommendation},
                status="ZU BESTÄTIGEN" if r.status == "fail" else "REFERENZ",
                dedup_key=f"blue-patchverify:{r.check_id}",
            ))

        # Optional: konkrete Findings verifizieren
        for f in (task.params or {}).get("findings") or []:
            if not isinstance(f, dict):
                continue
            step = _rem.verify_closed(f)
            verdict = ("NACHWEISLICH GESCHLOSSEN" if step.closed is True
                       else ("NOCH OFFEN" if step.closed is False else "UNPRÜFBAR"))
            findings.append(AgentFinding(
                agent=self.name, title=f"[{verdict}] {step.title}",
                category=("blue-remediation-verified" if step.closed is True
                          else "blue-patchverify-open"),
                severity="info" if step.closed else "medium",
                asset="localhost",
                description=step.verify_method,
                evidence={"closed": step.closed, "recheck": step.evidence,
                          "fix_action": step.fix_action},
                status="BESTÄTIGT(PASSIV)" if step.closed else "ZU BESTÄTIGEN",
                dedup_key=f"blue-patchverify-finding:{step.finding_key}",
            ))
        return findings
