"""Credential-Hygiene-Checks – rein lesend, Secrets immer maskiert.

Prüft lokale Dateirechte für Schlüssel/Configs und typische Anti-Patterns
(world-readable private keys, .env mit zu offenen Rechten). Werte werden
NIEMALS ausgegeben – nur Pfade + Rechte.
"""
from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("antbb.credhygiene")

DEFAULT_SCAN_ROOTS = [
    Path.home() / ".ssh",
    Path("/etc/ssh"),
    Path.cwd(),
]


@dataclass
class CredCheck:
    check_id: str
    title: str
    status: str
    severity: str
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _mode_str(mode: int) -> str:
    return oct(stat.S_IMODE(mode))


def _is_world_readable(mode: int) -> bool:
    return bool(stat.S_IMODE(mode) & stat.S_IROTH)


def _is_group_readable(mode: int) -> bool:
    return bool(stat.S_IMODE(mode) & stat.S_IRGRP)


def scan_key_permissions(roots: Optional[Iterable[Path]] = None,
                         max_files: int = 80) -> list[CredCheck]:
    roots = list(roots) if roots is not None else list(DEFAULT_SCAN_ROOTS)
    checks: list[CredCheck] = []
    seen = 0
    key_patterns = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".pem", "private")
    env_names = (".env", ".env.local", ".env.production", "antbb.env")

    for root in roots:
        try:
            root = Path(root)
        except Exception:
            continue
        if not root.exists() or not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except PermissionError:
            checks.append(CredCheck(
                check_id=f"perm-denied:{root}",
                title=f"Kein Zugriff auf {root}",
                status="skip", severity="info",
                detail="Permission denied – übersprungen.",
                evidence={"path": str(root)},
            ))
            continue
        for p in entries:
            if seen >= max_files:
                break
            if not p.is_file():
                continue
            name = p.name
            low = name.lower()
            is_key = any(k in low for k in key_patterns) and not low.endswith(".pub")
            is_env = name in env_names or low.endswith(".env")
            if not (is_key or is_env):
                continue
            seen += 1
            try:
                st = p.stat()
            except OSError as exc:
                checks.append(CredCheck(
                    check_id=f"stat-fail:{p.name}",
                    title=f"stat fehlgeschlagen: {p.name}",
                    status="skip", severity="info",
                    detail=str(exc)[:120], evidence={"path": str(p)},
                ))
                continue
            mode = _mode_str(st.st_mode)
            world = _is_world_readable(st.st_mode)
            group = _is_group_readable(st.st_mode)
            # Private keys: sollten 600/400 sein
            bad = world or (is_key and group)
            checks.append(CredCheck(
                check_id=f"cred-perm:{p.name}",
                title=(f"Zu offene Rechte: {p.name} ({mode})" if bad
                       else f"Rechte ok: {p.name} ({mode})"),
                status="fail" if bad else "pass",
                severity="high" if (bad and is_key) else ("medium" if bad else "info"),
                detail=f"Pfad={p} mode={mode} world_readable={world}",
                recommendation=("chmod 600 (Keys) bzw. 640/600 (.env); "
                                "niemals world-readable." if bad else ""),
                evidence={"path": str(p), "mode": mode,
                          "world_readable": world, "kind": "key" if is_key else "env"},
            ))
    if not checks:
        checks.append(CredCheck(
            check_id="cred-none",
            title="Keine Key/.env-Dateien in Standard-Pfaden gefunden",
            status="info", severity="info",
            detail="Scan-Roots ohne Treffer (honest-empty für Findings).",
            evidence={"roots": [str(r) for r in roots]},
        ))
    return checks


def capability_summary() -> dict:
    return {"scan_roots_default": [str(p) for p in DEFAULT_SCAN_ROOTS],
            "status": "installed"}
