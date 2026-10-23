"""Wiederholbare Jobs der Blue Queen (Scheduler-Grundgerüst).

Persistente Job-Definitionen in der DB (blue_jobs) + Verlauf (blue_job_runs).
Non-destruktiv standardmäßig. Aktive Fixes/Starts bleiben oversight-gated und
werden in Jobs NICHT automatisch freigegeben (apply_fixes=False).

Unterstützte Job-Arten (`kind`):
  * swscan     – Software-/Versions-Scan (read-only)
  * hardening  – Hardening-Audit (read-only)
  * remediate  – Remediation-Verify über vorhandene Findings
  * colony     – voller Blue-Queen-Lauf (alle Phasen, read-only)
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from .agents.blue import BLUE_PHASES
from .blue_queen import BlueQueen
from .store import Store

VALID_KINDS = frozenset({"swscan", "hardening", "remediate", "colony", "patching", "firewall", "identity", "tls", "logs", "backup", "watcher", "attacklog"})

_KIND_PHASES = {
    "swscan": ("assess",),
    "hardening": ("assess", "harden"),
    "remediate": ("remediate", "verify"),
    "colony": BLUE_PHASES,
}

#: Optionale Agenten-Filter je Job-Art (None = alle Soldaten der Phase).
_KIND_AGENTS = {
    "swscan": ("blue-swscan",),
    "hardening": ("blue-hardening",),
    "remediate": ("blue-remediation",),
    "colony": None,
}


class JobScheduler:
    """Einfacher, in-process Scheduler. Pollt `due_blue_jobs()` und führt sie aus.

    Idempotent / robust: ein fehlerhafter Job killt den Scheduler nicht; der
    Fehler wird als blue_job_run mit status='error' persistiert.
    """

    def __init__(self, store: Store, logger: Optional[logging.Logger] = None,
                 emit=None):
        self.store = store
        self.logger = logger or logging.getLogger("antbb.jobs")
        self.emit = emit

    def create(self, name: str, kind: str, interval_sec: int = 86400,
               target_id: Optional[int] = None, params: Optional[dict] = None,
               enabled: bool = True) -> int:
        kind = (kind or "").lower()
        if kind not in VALID_KINDS:
            raise ValueError(f"Unbekannte Job-Art '{kind}' "
                             f"(erlaubt: {sorted(VALID_KINDS)})")
        return self.store.add_blue_job(name, kind, interval_sec=interval_sec,
                                       target_id=target_id, params=params,
                                       enabled=enabled)

    def list(self, enabled_only: bool = False):
        return self.store.list_blue_jobs(enabled_only=enabled_only)

    def runs(self, job_id: Optional[int] = None, limit: int = 50):
        return self.store.list_blue_job_runs(job_id, limit=limit)

    def run_once(self, job_id: int) -> dict:
        """Führt EINEN Job sofort aus (unabhängig vom Intervall) und persistiert
        den Verlauf. Non-destruktiv (apply_fixes=False)."""
        row = self.store.get_blue_job(job_id)
        if not row:
            raise ValueError(f"Job {job_id} existiert nicht.")
        kind = row["kind"]
        phases = _KIND_PHASES.get(kind, BLUE_PHASES)
        try:
            params = json.loads(row["params_json"] or "{}")
        except Exception:
            params = {}
        started = time.time()
        try:
            use_llm = os.environ.get("ANTBB_NO_LLM", "").strip().lower() not in (
                "1", "true", "yes", "on",
            )
            queen = BlueQueen(self.store, logger=self.logger, emit=self.emit,
                              use_llm=use_llm)
            # Job-Art kann auf einzelne Soldaten eingrenzen.
            only = _KIND_AGENTS.get(kind)
            if only:
                params = {**params, "only_agents": list(only)}
            result = queen.run_colony_sync(
                target_id=row["target_id"], phases=phases,
                apply_fixes=False, params=params)
            closed = result.closed_count()
            summary = {"severity": result.by_severity(),
                       "status": result.by_status(),
                       "closed": closed,
                       "kind": kind}
            self.store.add_blue_job_run(
                job_id, run_id=result.run_id, status="done",
                finding_count=len(result.findings), closed_count=closed,
                summary=summary, started_at=started,
                finished_at=result.finished_at)
            self.store.mark_blue_job_ran(job_id)
            return {"ok": True, "run_id": result.run_id,
                    "finding_count": len(result.findings),
                    "closed_count": closed, "summary": summary}
        except Exception as exc:
            self.store.add_blue_job_run(
                job_id, status="error", error=f"{type(exc).__name__}: {exc}",
                started_at=started, finished_at=time.time())
            self.store.mark_blue_job_ran(job_id)
            self.logger.exception("Job %s fehlgeschlagen", job_id)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def tick(self) -> list[dict]:
        """Führt alle fälligen Jobs aus. Rückgabe: Liste der Run-Reports."""
        due = self.store.due_blue_jobs()
        out = []
        for j in due:
            self.logger.info("⏱ Job fällig: %s (id=%s, kind=%s)",
                             j["name"], j["id"], j["kind"])
            out.append({"job_id": j["id"], "name": j["name"],
                        **self.run_once(j["id"])})
        return out
