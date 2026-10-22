"""Analyse-Ameise: korreliert ECHTE Findings, schlägt CVSS vor, priorisiert.

- CVSS-Vorschlag pro Finding (Basisscore + Vektor), abgeleitet aus der
  Finding-Kategorie (konservative, dokumentierte Heuristik).
- Korrelation mehrerer Findings zu höherwertigen Angriffsketten.
- Priorisierung nach Schweregrad.
Optionaler LLM-Schritt (Zusammenfassung) mit sauberem Fallback bleibt erhalten.
"""
from __future__ import annotations

import asyncio

from .base import AntAgent, AgentFinding, Task, Playbook
from .. import llm as _llm

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Kategorie → (CVSS-Basisscore, CVSS-3.1-Vektor, Schweregrad-Label).
# Konservative Vorschläge für die ECHTEN, defensiven Checks.
_CVSS_MAP = {
    "misconfig":        (3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "low"),
    "info-disclosure":  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "medium"),
    "xss-indicator":    (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "medium"),
    "sqli-indicator":   (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "high"),
    "tls":              (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "low"),
    "tls-cert":         (4.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "low"),
    "api-surface":      (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "medium"),
    "recon-ports":      (2.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "low"),
    "recon-dns":        (0.0, "", "info"),
    "recon-subdomain":  (0.0, "", "info"),
    "fingerprint":      (0.0, "", "info"),
    # ── Verifizierte (bestätigte) Befunde der aktiven Verifikations-Phase ──
    "xss-verified":     (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "high"),
    "sqli-verified":    (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    "open-redirect":    (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "medium"),
    "path-traversal":   (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    "exposed-artifact": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    "cors-misconfig":   (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "medium"),
    "missing-auth":     (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "high"),
}

#: Kategorien, die aus der AKTIVEN Verifikation stammen → Confidence "bestätigt".
_VERIFIED_CATEGORIES = {
    "xss-verified", "sqli-verified", "open-redirect", "path-traversal",
    "exposed-artifact", "cors-misconfig", "missing-auth",
}

# Korrelationsregeln auf den ECHTEN Kategorien.
_CHAINS = [
    ({"sqli-verified"},
     "SQL-Injection VERIFIZIERT – DB-Kompromittierung realistisch (bestätigt)", "critical"),
    ({"xss-verified"},
     "Reflected XSS VERIFIZIERT – Session-/Token-Diebstahl realistisch (bestätigt)", "high"),
    ({"path-traversal"},
     "Path Traversal/LFI VERIFIZIERT – Datei-Lesezugriff bestätigt", "high"),
    ({"missing-auth"},
     "Admin-Endpunkt ohne Auth VERIFIZIERT – unautorisierter Zugriff bestätigt", "high"),
    ({"sqli-indicator"},
     "SQLi-Indikator – DB-Kompromittierung prüfen", "high"),
    ({"xss-indicator", "misconfig"},
     "Reflektierte Eingabe ohne CSP → XSS/Session-Diebstahl plausibel", "high"),
    ({"info-disclosure", "misconfig"},
     "Info-Disclosure + fehlende Header → erhöhtes Aufklärungsrisiko", "medium"),
]


class AnalysisAnt(AntAgent):
    name = "analysis"
    role = "Red-Team-Analyse: Korrelation, Angriffsketten, CVSS-Vorschlag, Priorisierung"
    specialty = "redteam-operator"
    phases = ("analyze",)
    playbooks = (
        Playbook("cvss-vorschlag", "defensive", False,
                 ["cvss-heuristik", "confidence-label"],
                 "Konservativer CVSS-Basisscore/-Vektor pro Finding."),
        Playbook("angriffsketten-korrelation", "defensive", False,
                 ["chain-rules", "severity-rollup"],
                 "Einzel-Findings zu höherwertigen Ketten korrelieren."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        await asyncio.sleep(0)
        existing = task.context_findings
        meta: list[AgentFinding] = []

        # ---- CVSS-Vorschläge pro Finding ----
        suggestions = []
        for f in existing:
            score, vector, label = _CVSS_MAP.get(f.category, (0.0, "", "info"))
            confidence = "bestätigt" if f.category in _VERIFIED_CATEGORIES else (
                "indikator" if f.category.endswith("-indicator") else "beobachtet")
            suggestions.append({
                "finding": f.title, "asset": f.asset, "category": f.category,
                "cvss_score": score, "cvss_vector": vector, "cvss_severity": label,
                "confidence": confidence,
            })
        if suggestions:
            graded = [s for s in suggestions if s["cvss_score"] > 0]
            top = sorted(graded, key=lambda s: s["cvss_score"], reverse=True)[:5]
            self.ctx.log(f"[analysis] CVSS-Vorschläge für {len(suggestions)} Findings erstellt.")
            meta.append(AgentFinding(
                agent=self.name, title="CVSS-Vorschläge & Priorisierung",
                category="analysis-cvss", severity=(top[0]["cvss_severity"] if top else "info"),
                asset=task.target_name,
                description=("CVSS-Basisscores pro Finding (konservative Heuristik). "
                             f"Höchste: " + "; ".join(
                                 f"{t['finding']} = {t['cvss_score']}" for t in top) + "."),
                evidence={"suggestions": suggestions},
                dedup_key=f"analysis-cvss:{task.run_id if hasattr(task,'run_id') else task.target_id}",
            ))

        # ---- Korrelation ----
        cats = {f.category for f in existing}
        for needed, title, sev in _CHAINS:
            if needed.issubset(cats):
                assets = sorted({f.asset for f in existing if f.category in needed})
                self.ctx.log(f"[analysis] 🔗 Korrelation: {title}")
                meta.append(AgentFinding(
                    agent=self.name, title=title, category="correlation", severity=sev,
                    asset=", ".join(assets)[:200],
                    description=("Mehrere Einzel-Findings wurden zu einer höherwertigen "
                                 f"Angriffskette korreliert (Kategorien: {sorted(needed)})."),
                    evidence={"source_categories": sorted(needed), "assets": assets},
                    dedup_key=f"corr:{title}",
                ))

        verified = [f for f in existing if f.category in _VERIFIED_CATEGORIES]
        if verified:
            self.ctx.log(f"[analysis] ✅ {len(verified)} VERIFIZIERTE Finding(s) (Confidence "
                         f"'bestätigt') werden höher priorisiert als bloße Indikatoren.")

        high = sorted(existing, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        if high:
            self.ctx.log(f"[analysis] Priorisierung: Top '{high[0].title}' ({high[0].severity})")

        # ---- Optionaler LLM-Schritt ----
        llm_finding = await self._llm_summary(existing)
        if llm_finding:
            meta.append(llm_finding)
        return meta

    async def _llm_summary(self, findings: list[AgentFinding]):
        if not self.ctx.llm_ready or not findings:
            return None
        lines = [f"- [{f.severity}] {f.title} ({f.category}) @ {f.asset}" for f in findings[:40]]
        messages = [
            {"role": "system", "content":
                "Du bist ein Security-Analyst. Fasse die Findings eines lokalen, "
                "autorisierten Bug-Bounty-Scans knapp auf Deutsch zusammen und "
                "priorisiere die 3 wichtigsten. Max 120 Wörter."},
            {"role": "user", "content": "Findings:\n" + "\n".join(lines)},
        ]
        try:
            provider = None
            model = _llm.select_model("analysis")
            if self.ctx.route:
                dec = self.ctx.route("analysis", 0.8)
                provider, model = dec.provider, dec.model
                self.ctx.log(f"[analysis] 🧭 Router → {provider}/{model} ({dec.reason})")
            res = await asyncio.to_thread(self.ctx.llm.chat, messages, model, provider, 0.2, 400)
        except Exception as exc:
            self.ctx.log(f"[analysis] ⚠️ LLM-Aufruf fehlgeschlagen (Fallback): {exc}")
            return None
        if not res.ok:
            self.ctx.log(f"[analysis] ⚠️ LLM nicht nutzbar (Fallback): {res.error}")
            return None
        self.ctx.log(f"[analysis] 🧠 LLM-Priorisierung erstellt ({res.provider}/{res.model}).")
        return AgentFinding(
            agent=self.name, title="LLM-Analyse: Zusammenfassung & Priorisierung",
            category="llm-analysis", severity="info", asset="",
            description=res.content.strip(),
            evidence={"provider": res.provider, "model": res.model},
        )
