"""Reporting-Ameise: fasst Findings zu einem Report-Entwurf zusammen.

Optionaler LLM-Schritt: mit konfiguriertem Provider erzeugt diese Ameise
zusätzlich einen narrativen Report-Text-Entwurf. Ohne LLM läuft die
regelbasierte Aggregation unverändert als Fallback.
"""
from __future__ import annotations

import asyncio

from .base import AntAgent, AgentFinding, Task, Playbook
from .. import llm as _llm
from .. import proofgate as _pg
from .base import STATUS_VERIFIED

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ReportingAnt(AntAgent):
    name = "reporting"
    role = "Report-Engineer: aggregiert Findings + Proof-Gate-Validierung zum Report-Entwurf"
    specialty = "report-engineer"
    phases = ("report",)
    playbooks = (
        Playbook("report-aggregation", "defensive", False,
                 ["severity-rollup-from-list", "status-rollup", "top-finding"],
                 "Findings aggregieren; Zählungen aus der Liste (Single Source of Truth)."),
        Playbook("proof-gate-validierung", "defensive", False,
                 ["verified-evidence-check", "false-positive-exclude"],
                 "Prüft, dass kein VERIFIZIERT ohne aktive Evidence vorliegt."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        await asyncio.sleep(0.01)
        findings = task.context_findings
        if not findings:
            self.ctx.log("[reporting] Keine Findings – kein Entwurf.")
            return []
        # HARTER Proof-Gate erneut anwenden (idempotent) – Reporting darf nie
        # etwas als VERIFIZIERT ausweisen, das keine aktive Evidence trägt.
        validation = _pg.enforce(findings, self.ctx.logger)
        # Zählungen AUSSCHLIESSLICH aus der Finding-Liste (Single Source of Truth),
        # Catch-all-/False-Positives ausgeschlossen.
        counted = _pg.counted_findings(findings)
        by_sev = _pg.severity_counts(findings)
        by_status = _pg.status_counts(findings)
        fp = [f for f in findings if f.false_positive]
        top = max(counted, key=lambda f: _SEV_RANK.get(f.severity, 0)) if counted else findings[0]
        self.ctx.log(
            f"[reporting] Zusammenfassung: {len(counted)} gezählte Findings "
            f"(+{len(fp)} als False-Positive ausgeschlossen), Verteilung {by_sev}, "
            f"Status {by_status}"
        )
        out = [AgentFinding(
            agent=self.name,
            title="Report-Entwurf erstellt",
            category="report-summary",
            severity=top.severity,
            asset=task.target_name,
            description=(
                f"{len(counted)} gezählte Findings aggregiert "
                f"({len(fp)} Catch-all/False-Positive ausgeschlossen). "
                f"Schweregrad-Verteilung: {by_sev}. Status-Verteilung: {by_status}. "
                f"Schwerstes Finding: '{top.title}'."
            ),
            evidence={"distribution": by_sev, "status_distribution": by_status,
                      "false_positive_count": len(fp), "top_finding": top.key(),
                      "counted_total": len(counted)},
        )]
        # ---- Proof-Gate-Validierungs-Finding (sichtbar im Report) ----
        verified = [f for f in counted if f.status == STATUS_VERIFIED]
        bad = [f for f in verified if not f.has_active_evidence()]
        gate_ok = not bad and not validation["violations"]
        out.append(AgentFinding(
            agent=self.name,
            title=("Proof-Gate: bestanden" if gate_ok else
                   "Proof-Gate: VERLETZUNG – VERIFIZIERT ohne Evidence"),
            category="proofgate-validation",
            severity=("info" if gate_ok else "high"),
            asset=task.target_name,
            description=(
                f"{len(verified)} Finding(s) als VERIFIZIERT geführt, davon "
                f"{len(verified) - len(bad)} mit konkreter aktiver Evidence. "
                + ("Keine Verletzung: jedes VERIFIZIERT trägt Request+Response-Nachweis."
                   if gate_ok else
                   f"{len(bad)} Finding(s) OHNE Evidence – NICHT als bewiesen behandeln.")
                + f" Herabgestuft in diesem Lauf: {len(validation['downgraded'])}."
            ),
            evidence={"verified_count": len(verified),
                      "verified_with_evidence": len(verified) - len(bad),
                      "downgraded": validation["downgraded"],
                      "flagged_false_positive": validation["flagged_false_positive"],
                      "violations": validation["violations"], "gate_ok": gate_ok},
            dedup_key=f"proofgate:{task.target_name}",
        ))

        # ---- Optionaler LLM-Schritt: narrativer Report-Text ----
        llm_finding = await self._llm_report(task, findings, by_sev)
        if llm_finding:
            out.append(llm_finding)
        return out

    async def _llm_report(self, task, findings, by_sev):
        if not self.ctx.llm_ready:
            return None
        lines = [
            f"- [{f.severity}] {f.title} ({f.category}) @ {f.asset}: {f.description}"
            for f in findings[:30]
        ]
        messages = [
            {"role": "system", "content":
                "Du bist ein Security-Report-Autor. Schreibe auf Deutsch einen "
                "knappen, strukturierten Report-Entwurf (Executive Summary + "
                "Hauptrisiken + Empfehlungen) für einen lokalen, autorisierten "
                "Bug-Bounty-Scan. Max 200 Wörter. Kein Markdown-Codeblock."},
            {"role": "user", "content":
                f"Target: {task.target_name}\nVerteilung: {by_sev}\n"
                f"Findings:\n" + "\n".join(lines)},
        ]
        try:
            # Report-Narrativ ist ein komplexer Schritt → Router wählt Provider+Modell
            provider = None
            model = _llm.select_model("report")
            if self.ctx.route:
                dec = self.ctx.route("report", 0.8)
                provider, model = dec.provider, dec.model
                self.ctx.log(f"[reporting] 🧭 Router → {provider}/{model} ({dec.reason})")
            res = await asyncio.to_thread(
                self.ctx.llm.chat, messages, model, provider, 0.3, 600
            )
        except Exception as exc:
            self.ctx.log(f"[reporting] ⚠️ LLM-Aufruf fehlgeschlagen (Fallback): {exc}")
            return None
        if not res.ok:
            self.ctx.log(f"[reporting] ⚠️ LLM nicht nutzbar (Fallback): {res.error}")
            return None
        self.ctx.log(f"[reporting] 🧠 LLM-Report-Entwurf erstellt ({res.provider}/{res.model}).")
        return AgentFinding(
            agent=self.name, title="LLM-Report-Entwurf",
            category="llm-report", severity="info", asset=task.target_name,
            description=res.content.strip(),
            evidence={"provider": res.provider, "model": res.model},
        )
