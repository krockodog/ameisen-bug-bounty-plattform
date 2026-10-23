"""Blue-Soldat: Honeypot/Decoy + Umleitungs-API.

Stellt sichere Decoy-Rezepte bereit und plant/wendet (gated) Umleitungen an.
Start/Deploy default-deny; ohne Oversight nur Plan + Playbook-Schritte.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import honeypot as _hp


class HoneypotAnt(BlueAgent):
    name = "blue-honeypot"
    specialty = "blue-honeypot-keeper"
    role = ("Honeypots/Decoys: sichere Köder-Rezepte und Umleitungs-API. "
            "Deploy/Divert default-deny, nur mit Oversight.")
    blue_phases = ("defend", "watch")
    playbooks = (
        Playbook("honeypot-recipes", "defensive", False,
                 ["ssh-decoy", "http-canary", "decoy-file", "smtp-decoy"],
                 "Sichere Honeypot-/Decoy-Rezepte (Doku) bereitstellen.",
                 tasks=["Rezepte auflisten", "Safety-Hinweise prüfen",
                        "Passendes Rezept je Signal-Klasse wählen"]),
        Playbook("honeypot-divert-plan", "defensive", False,
                 ["divert-plan"],
                 "Umleitung in Decoy planen (Playbook-Schritte, nichts starten).",
                 tasks=["Signal klassifizieren", "Decoy wählen",
                        "Umleitungs-Schritte dokumentieren",
                        "Sofortschutz-Empfehlung anhängen"]),
        Playbook("honeypot-deploy", "defensive", True,
                 ["divert-apply", "start-decoy"],
                 "Umleitung/Deploy NUR mit Oversight (default-deny).",
                 tasks=["Oversight prüfen", "Divert-Entscheidung setzen",
                        "Netz-Backend nur wenn konfiguriert",
                        "Ergebnis im Attack-Log dokumentieren"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        recipes = _hp.list_recipes()
        self.ctx.log(f"[blue-honeypot] 🍯 {len(recipes)} Decoy-Rezept(e).")
        for r in recipes:
            findings.append(AgentFinding(
                agent=self.name, title=f"Honeypot: {r['title']}",
                category="blue-honeypot-recipe", severity="info", asset="decoy",
                description=f"{r['desc']} · Sicherheit: {r['safety']}",
                evidence={"recipe_id": r["id"], "safety": r["safety"],
                          "protocol": r.get("protocol"),
                          "divert_port": r.get("divert_port")},
                status="REFERENZ", dedup_key=f"blue-honeypot:{r['id']}"))

        # Optional: Plan aus params.signal
        signal = (task.params or {}).get("signal") or {}
        if signal:
            plan = _hp.divert_plan(signal, recipe_id=signal.get("recipe") or "http-canary")
            findings.append(AgentFinding(
                agent=self.name, title=f"Divert-Plan → {plan.recipe_id}",
                category="blue-honeypot-divert", severity="info", asset="decoy",
                description=plan.reason + " · " + " | ".join(plan.playbook_steps[:3]),
                evidence=plan.to_dict(), status="REFERENZ",
                dedup_key=f"blue-honeypot-divert:{plan.recipe_id}"))
            if self.active_allowed():
                applied = _hp.divert_apply(signal, recipe_id=plan.recipe_id, active=True)
                findings.append(AgentFinding(
                    agent=self.name, title=f"Divert-Apply: {applied.status}",
                    category="blue-honeypot-divert-apply",
                    severity="info", asset="decoy",
                    description=applied.reason,
                    evidence=applied.to_dict(),
                    status="BESTÄTIGT(PASSIV)" if applied.applied else "REFERENZ",
                    dedup_key=f"blue-honeypot-apply:{plan.recipe_id}"))
        elif self.active_allowed():
            self.ctx.log("[blue-honeypot] Oversight ok – kein Signal übergeben, "
                         "kein automatischer Deploy.")
        return findings
