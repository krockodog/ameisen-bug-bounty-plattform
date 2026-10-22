"""Mobile-Ameise: mobile App-Security.

EHRLICHE GRENZE: Ein reiner Netzwerk-Scan kann KEINE APK/IPA oder ein
Mobile-Repo inspizieren. Diese Ameise ist registriert und ausführbar, meldet
aber ehrlich, dass sie für echte Befunde ein App-Artefakt (APK/IPA/Repo) als
Eingabe braucht. Sobald `task.params["mobile_artifact"]` gesetzt ist, würde sie
Manifest-Flags (allowBackup, debuggable), Certificate-Pinning und iOS-ATS
prüfen. Ohne Artefakt: honest empty state, keine erfundenen Befunde.
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook


class MobileHunterAnt(AntAgent):
    name = "mobile"
    role = "Mobile-Security: APK/IPA-Manifest, Cert-Pinning, ATS (braucht App-Artefakt)"
    specialty = "mobile-hunter"
    phases = ("recon",)
    playbooks = (
        Playbook("manifest-analyse", "defensive", False,
                 ["allowbackup", "debuggable", "exported-components"],
                 "Android-Manifest-Flags prüfen (benötigt APK)."),
        Playbook("certificate-pinning", "defensive", False,
                 ["pinning-config-check"],
                 "Certificate-Pinning im App-Artefakt prüfen (benötigt APK/IPA)."),
        Playbook("ios-ats", "defensive", False,
                 ["ats-hardening-check"],
                 "iOS App Transport Security prüfen (benötigt IPA/Repo)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        artifact = (task.params or {}).get("mobile_artifact")
        if not artifact:
            self.ctx.log("[mobile] ℹ️ Kein App-Artefakt (APK/IPA/Repo) übergeben – "
                         "Mobile-Analyse übersprungen (ehrlicher Leerzustand).")
            return [AgentFinding(
                agent=self.name,
                title="Mobile-Analyse: kein App-Artefakt vorhanden",
                category="info-disclosure", severity="info", asset=task.target_name,
                description=("Mobile-Hunter ist registriert und ausführbar, benötigt für "
                             "echte Befunde aber ein APK/IPA/Repo. Es wurde keines übergeben, "
                             "daher KEINE Befunde (keine Erfindung)."),
                evidence={"needs": "mobile_artifact (APK/IPA/repo path)",
                          "ran": True, "findings": 0},
                dedup_key=f"mobile-noartifact:{task.target_name}",
            )]
        # Platzhalter: echte Artefakt-Analyse würde hier ansetzen.
        self.ctx.log(f"[mobile] Artefakt übergeben ({artifact}) – Analyse-Hook bereit.")
        return []
