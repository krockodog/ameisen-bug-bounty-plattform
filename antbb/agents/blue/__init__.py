"""Verteidigungs-Kolonie (Blue Queen) – Blue-Team-Soldaten.

Getrenntes Roster von den offensiven Arbeiter-Ameisen. Dieselbe Soldaten-
Schnittstelle (AntAgent/AgentFinding/Playbook) + Registry/GUI-Karten.

Das Roster wird per AUTO-DISCOVERY aufgebaut: jedes Modul in diesem Paket, das
eine konkrete `BlueAgent`-Unterklasse mit eigenem `name` definiert, wird registriert
(Basis-/Hilfsmodule ausgenommen). Neue Soldaten brauchen also nur eine neue Datei +
SKILL.md – keine manuelle Registrierung, keine Merge-Konflikte.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import BlueAgent, BLUE_PHASES

_SKIP = {"base", "audit", "_sys"}

#: Bevorzugte Reihenfolge (Kette Assess → … → Verify); Unbekannte folgen alphabetisch.
_ORDER = [
    "blue-swscan", "blue-patchmgmt", "blue-hardening", "blue-fwaudit", "blue-netdef",
    "blue-idhygiene", "blue-credhygiene", "blue-tlsposture", "blue-webharden",
    "blue-supplychain", "blue-backup", "blue-backupverify",
    "blue-watcher", "blue-defense", "blue-logintegrity", "blue-logging",
    "blue-honeypot", "blue-attacklog", "blue-incident",
    "blue-remediation", "blue-patchverify", "blue-vulnticket", "blue-ticketclose",
]


def _discover() -> list[type]:
    found: dict[str, type] = {}
    for mod in pkgutil.iter_modules(__path__):
        if mod.name in _SKIP:
            continue
        try:
            m = importlib.import_module(f"{__name__}.{mod.name}")
        except Exception:  # defekte Einzel-Soldaten dürfen das Roster nicht kippen
            continue
        for _n, obj in inspect.getmembers(m, inspect.isclass):
            if (issubclass(obj, BlueAgent) and obj.__module__ == m.__name__
                    and obj.__name__ not in ("BlueAgent", "AuditAnt")
                    and not inspect.isabstract(obj)
                    and getattr(obj, "name", "ant") not in ("ant", "")):
                found[obj.name] = obj
    rank = {n: i for i, n in enumerate(_ORDER)}
    return [found[n] for n in sorted(found, key=lambda n: (rank.get(n, 999), n))]


#: Alle Blue-Team-Soldaten der Verteidigungs-Königin (Reihenfolge = Kette).
BLUE_AGENTS = _discover()

# Klassen auch unter ihrem Namen exportierbar machen (rückwärtskompatibel).
for _cls in BLUE_AGENTS:
    globals()[_cls.__name__] = _cls

__all__ = ["BlueAgent", "BLUE_PHASES", "BLUE_AGENTS"] + [c.__name__ for c in BLUE_AGENTS]
