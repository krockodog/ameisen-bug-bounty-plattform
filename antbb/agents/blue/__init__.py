"""Verteidigungs-Kolonie (Blue Queen) – Blue-Team-Soldaten.

Getrenntes Roster von den offensiven Arbeiter-Ameisen. Dieselbe Soldaten-
Schnittstelle (AntAgent/AgentFinding/Playbook) + Registry/GUI-Karten.
"""
from .base import BlueAgent, BLUE_PHASES
from .swscan import SoftwareScanAnt
from .hardening import HardeningAnt
from .remediation import RemediationAnt
from .defense import DefenseAnt
from .honeypot import HoneypotAnt

#: Alle Blue-Team-Soldaten der Verteidigungs-Königin.
BLUE_AGENTS = [
    SoftwareScanAnt, HardeningAnt, DefenseAnt, RemediationAnt, HoneypotAnt,
]

__all__ = [
    "BlueAgent", "BLUE_PHASES", "BLUE_AGENTS",
    "SoftwareScanAnt", "HardeningAnt", "RemediationAnt", "DefenseAnt",
    "HoneypotAnt",
]
