"""Soldaten der Blue Queen.

Diese Ausgabe registriert keine offensive Kolonie. Die gemeinsame Basisklasse
bleibt, damit Orchestrierung, Registry und Proof-Gate dieselbe Schnittstelle
nutzen. Die Arbeiterliste ist leer; die Verteidigungs-Soldaten liegen unter
``antbb.agents.blue``.
"""
from .base import AntAgent, Task, AgentFinding, AgentContext, Playbook

#: Keine offensiven Jäger in diesem Produkt.
WORKER_AGENTS: list = []

__all__ = [
    "AntAgent", "Task", "AgentFinding", "AgentContext", "Playbook",
    "WORKER_AGENTS",
]
