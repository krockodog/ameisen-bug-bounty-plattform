"""Blue-Soldat: Honeypot/Decoy (Playbook + Scaffold, Start nur gated).

Stellt einfache, sichere Honeypot-/Decoy-Rezepte bereit (Doku + Playbook). Ein
tatsächliches Starten eines Honeypots ist default-deny und nur mit Oversight-
Freigabe (ctx.active) erlaubt; im Scaffold wird NICHTS gestartet – es werden
ausschließlich sichere Konfigurationen beschrieben.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task

HONEYPOT_RECIPES = [
    {"id": "ssh-decoy", "title": "SSH-Decoy (low-interaction)",
     "desc": "Fake-SSH auf unüblichem Port, der nur Verbindungs-/Login-Versuche "
             "protokolliert (z.B. cowrie im low-interaction-Modus, isoliert).",
     "safety": "In isoliertem Netz/Container, keine echten Credentials, Logs lokal."},
    {"id": "http-canary", "title": "HTTP-Canary-Endpoint",
     "desc": "Unverlinkter Pfad/Token, dessen Abruf einen Alarm auslöst "
             "(Canarytoken-Prinzip).",
     "safety": "Kein echter Dienst dahinter; nur Zugriffs-Logging."},
    {"id": "decoy-file", "title": "Decoy-Dokument (Canary)",
     "desc": "Köder-Datei mit eingebettetem Canary, die beim Öffnen/Exfil meldet.",
     "safety": "Enthält keine echten Daten; rein als Tripwire."},
]


class HoneypotAnt(BlueAgent):
    name = "blue-honeypot"
    specialty = "blue-honeypot-keeper"
    role = ("Honeypots/Decoys: sichere, einfache Köder-Rezepte als Playbook. "
            "Start default-deny, nur mit Oversight (Scaffold: nichts gestartet).")
    blue_phases = ("defend",)
    playbooks = (
        Playbook("honeypot-recipes", "defensive", False,
                 ["ssh-decoy", "http-canary", "decoy-file"],
                 "Sichere Honeypot-/Decoy-Rezepte (Doku) bereitstellen."),
        Playbook("honeypot-deploy", "defensive", True,
                 ["start-decoy"],
                 "Einen Decoy tatsächlich starten – NUR mit Oversight "
                 "(default-deny, Scaffold/dokumentiert)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log(f"[blue-honeypot] 🍯 {len(HONEYPOT_RECIPES)} Decoy-Rezept(e) bereitgestellt.")
        for r in HONEYPOT_RECIPES:
            findings.append(AgentFinding(
                agent=self.name, title=f"Honeypot: {r['title']}",
                category="blue-honeypot-recipe", severity="info", asset="decoy",
                description=f"{r['desc']} · Sicherheit: {r['safety']}",
                evidence={"recipe_id": r["id"], "safety": r["safety"]},
                status="REFERENZ", dedup_key=f"blue-honeypot:{r['id']}"))
        if self.active_allowed():
            self.ctx.log("[blue-honeypot] ⚠️ Deploy freigegeben (Oversight) – im "
                         "Scaffold wird KEIN Honeypot automatisch gestartet "
                         "(bewusst konservativ, nur dokumentiert).")
        return findings
