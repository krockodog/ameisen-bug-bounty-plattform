"""Blue-Soldat: Backup/Restore-Checks (non-destruktiv, kein Restore)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import backupcheck as _bc


class BackupAnt(BlueAgent):
    name = "blue-backup"
    specialty = "blue-backup-guardian"
    role = ("Backup/Restore-Checks: Existenz, Alter, Lesbarkeit prüfen. "
            "Kein Restore, nichts destruktiv.")
    blue_phases = ("assess", "verify")
    playbooks = (
        Playbook("backup-inventory", "defensive", False,
                 ["path-discovery", "mtime-age"],
                 "Backup-Locations finden und Alter bewerten.",
                 tasks=["Standard-Pfade prüfen", "mtime/Alter berechnen",
                        "Veraltete Backups melden", "Fehlende Locations melden"]),
        Playbook("backup-restore-drill-plan", "defensive", False,
                 ["restore-checklist"],
                 "Restore-Drill als Checkliste planen (nicht ausführen).",
                 tasks=["Ziel-System definieren", "Restore-Fenster wählen",
                        "Erfolgskriterien festlegen", "Rollback-Plan skizzieren"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-backup] 💾 Backup-Audit (read-only).")
        for r in _bc.run_audit():
            sev = r.severity if r.status == "fail" else "info"
            status = ("ZU BESTÄTIGEN" if r.status == "fail"
                      else ("BESTÄTIGT(PASSIV)" if r.status == "pass" else "REFERENZ"))
            findings.append(AgentFinding(
                agent=self.name, title=r.title,
                category=f"blue-backup-{r.status}", severity=sev,
                asset="localhost",
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence=r.to_dict(), status=status,
                dedup_key=f"blue-backup:{r.check_id}",
            ))
        # Restore-Drill nur als Plan
        findings.append(AgentFinding(
            agent=self.name, title="Restore-Drill-Plan (nicht ausgeführt)",
            category="blue-backup-drill", severity="info", asset="localhost",
            description=("Checkliste: Ziel wählen → Restore in Isolierung → "
                         "Integrität prüfen → Rollback dokumentieren. "
                         "Kein automatischer Restore."),
            evidence={"executed": False, "steps": [
                "Ziel-System/Snapshot wählen", "Isolierte Restore-Umgebung",
                "Integritätscheck", "Erfolg dokumentieren", "Rollback-Plan"]},
            status="REFERENZ", dedup_key="blue-backup-drill-plan",
        ))
        return findings
