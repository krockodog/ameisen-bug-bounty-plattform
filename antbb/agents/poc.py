"""PoC-Ameise: erzeugt ECHTE, reproduzierbare PoCs (nicht ausgeführt).

Für jedes AKTIV verifizierte Finding baut sie aus der bereits erfassten
Evidence (evidence.request + Response-Nachweis) eine copy-paste-fähige
Reproduktion: exakter curl-Befehl, nummerierte Repro-Schritte, beobachteter
Beweis und Erwartet-vs-Beobachtet. Der PoC wird NIE automatisch abgefeuert –
es ist reiner Text, den ein Mensch/Triager ausführt (demonstrate-and-stop).

Es werden keine PoCs für Findings ohne aktive Request/Response-Evidence
erfunden; solche Findings werden ehrlich übersprungen (Proof-Gate-Disziplin).
"""
from __future__ import annotations

import asyncio

from .base import AntAgent, AgentFinding, Task, Playbook
from .. import poc_builder

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Kategorien, für die ein echter, ausführbarer PoC sinnvoll ist (aktive Belege).
_POC_CATEGORIES = frozenset({
    "xss-verified", "sqli-verified", "open-redirect", "path-traversal",
    "exposed-artifact", "cors-misconfig", "missing-auth",
    "ssrf-verified", "ssrf-indicator", "subdomain-takeover",
})


class PocAnt(AntAgent):
    name = "poc"
    role = "Exploit-Developer: echte, reproduzierbare PoCs aus Evidence (nicht ausgeführt)"
    specialty = "exploit-developer"
    phases = ("analyze",)
    playbooks = (
        Playbook("poc-template-builder", "defensive", False,
                 ["curl-repro-from-evidence", "repro-steps", "expected-vs-actual",
                  "non-executing"],
                 "Echte, copy-paste-fähige PoCs (curl + Schritte + Beweis) nur aus "
                 "aktiver Evidence – nicht ausgeführt."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        await asyncio.sleep(0.0)
        out: list[AgentFinding] = []
        # PoCs nur für ernsthafte Findings, die aktive Evidence tragen.
        candidates = []
        for f in task.context_findings:
            if _SEV_RANK.get(f.severity, 0) < 2:
                continue
            # Nur aus aktiver Evidence (Request+Response) echte PoCs bauen.
            if not f.has_active_evidence():
                continue
            candidates.append(f)

        for f in candidates[:25]:
            built = poc_builder.build(
                category=f.category, asset=f.asset, title=f.title,
                evidence=f.evidence, severity=f.severity,
                description=f.description, status=f.status,
            )
            if not built.get("curl"):
                # Ohne reproduzierbaren Request keinen PoC erfinden.
                continue
            self.ctx.log(f"[poc] ✅ echter PoC generiert für '{f.title}'")
            out.append(AgentFinding(
                agent=self.name,
                title=f"PoC: {f.title}",
                category="poc",
                severity=f.severity,
                asset=f.asset,
                description=(f"Copy-paste-fähige Reproduktion für '{f.title}' "
                             "(nicht ausgeführt – demonstrate-and-stop)."),
                evidence={
                    "poc_markdown": built["markdown"],
                    "curl": built["curl"],
                    "repro_steps": built["steps"],
                    "observed_proof": built["proof"],
                    "expected": built["expected"],
                    "actual": built["actual"],
                    "executed": False,
                    "non_executing": True,
                    "for": f.key(),
                },
                dedup_key=f"poc:{f.key()}",
            ))
        return out
