"""Replay-/Checkpoint-Engine: Läufe reproduzierbar, pausierbar, wiederholbar.

Persistiert die Schritte/den Zustand eines Scan-Laufs nach SQLite
(scan_runs + scan_steps). Damit lässt sich ein Lauf:
  * checkpointen (jeder Schritt wird deterministisch mit seq gespeichert),
  * pausieren/fortsetzen (Status running|paused|done|error),
  * deterministisch REPLAYEN – die aufgezeichneten Ergebnisse werden in
    seq-Reihenfolge erneut ausgegeben, OHNE Tools neu zu starten (für
    Reporting/Audit).

Es werden NUR Metadaten/Events/Finding-Zusammenfassungen gespeichert; keine
Secrets. Das Replay ruft KEINE externen Tools auf – es gibt nur Aufgezeichnetes
wieder.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable, Optional


class Recorder:
    """Zeichnet die Schritte eines Laufs in den Store (Checkpoints)."""

    def __init__(self, store, run_id: str, target_id: int, phases=None,
                 meta: Optional[dict] = None):
        self.store = store
        self.run_id = run_id
        self.target_id = target_id
        store.create_scan_run(run_id, target_id, phases=phases, meta=meta or {},
                              status="running")

    def event(self, msg: str, phase: str = "", agent: str = "") -> int:
        return self.store.add_scan_step(self.run_id, "event",
                                        {"msg": msg, "ts": time.time()},
                                        phase=phase, agent=agent)

    def finding(self, finding: dict, phase: str = "", agent: str = "") -> int:
        # Nur sichere, nicht-geheime Felder spiegeln.
        safe = {k: finding.get(k) for k in
                ("title", "category", "severity", "asset", "status", "agent")}
        return self.store.add_scan_step(self.run_id, "finding", safe,
                                        phase=phase, agent=agent or safe.get("agent", ""))

    def phase(self, name: str) -> int:
        return self.store.add_scan_step(self.run_id, "phase", {"phase": name}, phase=name)

    def pause(self) -> None:
        self.store.set_scan_run_status(self.run_id, "paused")

    def resume(self) -> None:
        self.store.set_scan_run_status(self.run_id, "running")

    def finish(self, status: str = "done") -> None:
        self.store.set_scan_run_status(self.run_id, status)


@dataclass
class ReplayResult:
    run_id: str
    target_id: int
    status: str
    step_count: int
    events: int
    findings: int
    phases: list


def list_checkpoints(store, target_id: Optional[int] = None) -> list[dict]:
    """Alle Läufe mit Schrittzahl + Status (für CLI/GUI)."""
    out = []
    for r in store.list_scan_runs(target_id):
        steps = store.list_scan_steps(r["run_id"])
        out.append({
            "run_id": r["run_id"],
            "target_id": r["target_id"],
            "status": r["status"],
            "steps": len(steps),
            "started_at": r["started_at"],
            "finished_at": r["finished_at"],
            "meta": _json(r["meta"]),
        })
    return out


def resume(store, run_id: str) -> dict:
    """Setzt einen pausierten Lauf auf 'running'. Ändert nur den Status."""
    row = store.get_scan_run(run_id)
    if not row:
        raise ValueError(f"Lauf '{run_id}' nicht gefunden.")
    if row["status"] not in ("paused", "running"):
        return {"run_id": run_id, "status": row["status"],
                "note": f"Lauf ist '{row['status']}' – nicht fortsetzbar."}
    store.set_scan_run_status(run_id, "running")
    steps = store.list_scan_steps(run_id)
    return {"run_id": run_id, "status": "running", "resumed_from_step": len(steps),
            "note": "Status auf 'running' gesetzt; neue Schritte werden angehängt."}


def replay(store, run_id: str, emit: Optional[Callable[[dict], None]] = None) -> ReplayResult:
    """Gibt die aufgezeichneten Schritte deterministisch erneut aus.

    Ruft KEINE Tools auf – reines Re-Emit für Reporting/Audit.
    """
    row = store.get_scan_run(run_id)
    if not row:
        raise ValueError(f"Lauf '{run_id}' nicht gefunden.")
    steps = store.list_scan_steps(run_id)
    events = findings = 0
    phases: list = []
    for st in steps:
        payload = _json(st["payload"])
        kind = st["kind"]
        if kind == "event":
            events += 1
            if emit:
                emit({"ts": payload.get("ts"), "msg": payload.get("msg", ""),
                      "replay": True, "seq": st["seq"]})
        elif kind == "finding":
            findings += 1
            if emit:
                emit({"replay": True, "seq": st["seq"], "finding": payload})
        elif kind == "phase":
            ph = payload.get("phase", "")
            if ph:
                phases.append(ph)
            if emit:
                emit({"replay": True, "seq": st["seq"], "phase": ph})
    return ReplayResult(run_id=run_id, target_id=row["target_id"],
                        status=row["status"], step_count=len(steps),
                        events=events, findings=findings, phases=phases)


def _json(val) -> dict:
    if isinstance(val, dict):
        return val
    try:
        d = json.loads(val or "{}")
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}
