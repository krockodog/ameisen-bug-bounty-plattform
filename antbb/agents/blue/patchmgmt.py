"""Blue-Soldat: blue-patch-manager – Patch-Management (read-only).

Patch-Management (read-only): ausstehende Updates, Neustart-Bedarf, Kernel-Stand und automatische Sicherheits-Updates prüfen; Fix-Vorschläge je Abweichung.
Rein lesend/non-destruktiv; echte Checks aus `antbb.blue_checks` (Domäne 'patchmgmt').
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task


class PatchMgmtAnt(BlueAgent):
    name = 'blue-patchmgmt'
    specialty = 'blue-patch-manager'
    role = ('Patch-Management (read-only): ausstehende Updates, Neustart-Bedarf, Kernel-Stand und automatische Sicherheits-Updates prüfen; Fix-Vorschläge je Abweichung.')
    blue_phases = ("assess", "harden")
    domain = 'patchmgmt'
    playbooks = (
        Playbook('patch-pending-audit', "defensive", False,
                 ['apt-list-upgradable', 'dnf-check-update'],
                 'Ausstehende Paket-Updates (apt/dnf, lokaler Cache) erfassen und sicherheitsrelevante hervorheben.',
                 tasks=['Paketmanager erkennen (apt/dnf)', 'Ausstehende Updates zählen', 'Sicherheits-Updates getrennt zählen', 'Betroffene Pakete (Stichprobe) dokumentieren', 'Update-Befehl als Vorschlag ausgeben (nie ausführen)']),
        Playbook('patch-hygiene-audit', "defensive", False,
                 ['reboot-required', 'uname', 'unattended-upgrades'],
                 'Neustart-Bedarf, Kernel-Stand und automatische Sicherheits-Updates prüfen.',
                 tasks=['reboot-required-Flag lesen', 'Laufenden vs. neuesten installierten Kernel vergleichen', 'unattended-upgrades-Status prüfen', 'Neustart/Aktivierung als Empfehlung ausgeben']),
    )
    playbook_checks = {'patch-pending-audit': ['patch-pending-updates'], 'patch-hygiene-audit': ['patch-reboot-required', 'patch-auto-security', 'patch-kernel-current']}

    async def work(self, task: Task) -> list[AgentFinding]:
        return await self.run_domain(task)
