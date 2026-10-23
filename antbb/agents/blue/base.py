"""Basis für Blue-Team-Soldaten (Verteidigungs-Kolonie der Blue Queen).

Blue-Soldaten nutzen DASSELBE Interface wie die offensiven Ameisen
(`AntAgent`, `Task`, `AgentFinding`, `Playbook`) und dieselbe Registry/GUI-
Karten-Logik. Unterschiede:
  * `colony = "blue"` (für Registry/GUI-Trennung offensiv vs. defensiv).
  * `blue_phases` statt der offensiven Kill-Chain-Phasen:
    assess → watch → harden → defend → remediate → verify.
  * Default rein lesend/non-destruktiv. Aktive Fixes/Starts laufen NUR über
    das bestehende Oversight-Gate (ctx.active == Freigabe für aktive Aktion).
"""
from __future__ import annotations

from ..base import AntAgent, AgentContext, AgentFinding, Playbook, Task

#: Phasen der defensiven Kolonie (erweitert um Watch).
BLUE_PHASES = ("assess", "watch", "harden", "defend", "remediate", "verify")


class BlueAgent(AntAgent):
    """Abstrakte Basis-Ameise der Verteidigungs-Kolonie."""

    colony = "blue"
    #: Blue-Team-Phasen, für die dieser Soldat zuständig ist.
    blue_phases: tuple[str, ...] = ()
    #: Die offensive `phases`-Eigenschaft bleibt leer – Blue-Soldaten werden
    #: NIE von der offensiven Königin dispatcht (getrennte Roster).
    phases: tuple[str, ...] = ()

    @classmethod
    def describe(cls) -> dict:
        d = super().describe()
        d["colony"] = "blue"
        d["blue_phases"] = list(cls.blue_phases)
        return d

    def active_allowed(self) -> bool:
        """True, wenn aktive/verändernde Aktionen freigegeben sind (Oversight)."""
        return bool(getattr(self.ctx, "active", False))


__all__ = ["BlueAgent", "BLUE_PHASES", "AgentContext", "AgentFinding",
           "Playbook", "Task"]
