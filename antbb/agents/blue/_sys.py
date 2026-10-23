"""Gemeinsame, rein lesende System-Helfer der Blue-Audit-Soldaten.

Nichts hier verändert das System. Fehlende Dateien/Tools führen zu leeren
Ergebnissen (der Aufrufer meldet dann ehrlich `info` = nicht prüfbar).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

__all__ = ["read", "run", "have", "proc_names", "age_days", "mode_of"]


def read(path: str, limit: int = 400_000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str]:
    """Führt ein lesendes Kommando aus. Rückgabe (rc, stdout+stderr); rc=-1 bei Fehler."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return out.returncode, (out.stdout or "") + (out.stderr or "")
    except Exception:
        return -1, ""


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def proc_names() -> set[str]:
    """Namen laufender Prozesse (aus /proc/*/comm, rein lesend)."""
    names: set[str] = set()
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                n = read(f"/proc/{pid}/comm", 200).strip()
                if n:
                    names.add(n)
    except Exception:
        pass
    return names


def age_days(path: str) -> float | None:
    try:
        return (time.time() - os.stat(path).st_mtime) / 86400.0
    except Exception:
        return None


def mode_of(path: str) -> int | None:
    try:
        return os.stat(path).st_mode & 0o777
    except Exception:
        return None
