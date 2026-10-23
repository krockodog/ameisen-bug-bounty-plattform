"""Backup/Restore-Checks – non-destruktiv.

Prüft Existenz, Alter und Lesbarkeit typischer Backup-Pfade. Führt KEIN
Restore aus und schreibt nichts. Ohne Treffer → ehrliches info-Finding.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("antbb.backupcheck")

DEFAULT_CANDIDATES = [
    Path("/var/backups"),
    Path.home() / "backups",
    Path.home() / "Backup",
    Path("/backup"),
    Path.cwd() / "backups",
    Path.cwd() / "backup",
]

MAX_AGE_DAYS_WARN = 7


@dataclass
class BackupCheck:
    check_id: str
    title: str
    status: str
    severity: str
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _newest_mtime(path: Path) -> Optional[float]:
    newest = None
    try:
        if path.is_file():
            return path.stat().st_mtime
        for root, dirs, files in os.walk(path):
            # limit depth
            rel = Path(root).relative_to(path)
            if len(rel.parts) > 2:
                dirs.clear()
                continue
            for f in files[:50]:
                try:
                    mt = (Path(root) / f).stat().st_mtime
                except OSError:
                    continue
                if newest is None or mt > newest:
                    newest = mt
            if newest and (time.time() - newest) < 3600:
                break
    except OSError:
        return None
    return newest


def run_audit(candidates: Optional[Iterable[Path]] = None,
              max_age_days: int = MAX_AGE_DAYS_WARN) -> list[BackupCheck]:
    cands = list(candidates) if candidates is not None else list(DEFAULT_CANDIDATES)
    checks: list[BackupCheck] = []
    found = []
    for p in cands:
        p = Path(p)
        if not p.exists():
            continue
        mt = _newest_mtime(p)
        age_days = ((time.time() - mt) / 86400.0) if mt else None
        found.append({"path": str(p), "mtime": mt, "age_days": age_days})
        stale = age_days is not None and age_days > max_age_days
        checks.append(BackupCheck(
            check_id=f"backup:{p.name}",
            title=(f"Backup veraltet: {p}" if stale
                   else f"Backup vorhanden: {p}"),
            status="fail" if stale else "pass",
            severity="medium" if stale else "info",
            detail=(f"Alter ≈ {age_days:.1f} Tage" if age_days is not None
                    else "mtime nicht ermittelbar"),
            recommendation=("Backup-Job prüfen / Restore-Test planen (non-destruktiv)."
                            if stale else "Periodischen Restore-Drill dokumentieren."),
            evidence={"path": str(p), "age_days": age_days,
                      "max_age_days": max_age_days},
        ))
    if not found:
        checks.append(BackupCheck(
            check_id="backup-none",
            title="Keine Backup-Pfade in Standard-Locations gefunden",
            status="fail", severity="medium",
            detail="Geprüfte Kandidaten ohne Treffer.",
            recommendation="Backup-Ziel definieren, Jobs einrichten, Restore-Drill planen.",
            evidence={"candidates": [str(c) for c in cands]},
        ))
    else:
        checks.insert(0, BackupCheck(
            check_id="backup-inventory",
            title=f"{len(found)} Backup-Location(s) gefunden",
            status="info", severity="info",
            detail="Read-only Existenz-/Altersprüfung (kein Restore ausgeführt).",
            evidence={"locations": found},
        ))
    return checks


def capability_summary() -> dict:
    return {"default_candidates": [str(p) for p in DEFAULT_CANDIDATES],
            "restore_executed": False, "status": "installed"}
