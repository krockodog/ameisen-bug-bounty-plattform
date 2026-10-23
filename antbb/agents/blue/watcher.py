"""Blue-Soldat: Wächter – frühe Angriffserkennung aller Arten.

Pipeline: detect → honeypot-divert → Sofortschutz → Angreifer-Rückverfolgung
→ permanenter Attack-Log. Ohne echte Events: honest-empty.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import watcher as _w


class WatcherAnt(BlueAgent):
    name = "blue-watcher"
    specialty = "blue-watcher-sentinel"
    role = ("Wächter: Angriffe früh erkennen (web/auth/net/wlan/api), in "
            "Honeypot umleiten, Sofortschutz, Rückverfolgung, Attack-Log.")
    blue_phases = ("watch", "defend")
    playbooks = (
        Playbook("watcher-detect", "defensive", False,
                 ["signal-catalog", "event-match"],
                 "Signale in echten Events erkennen (SQL/XSS/Brute/Portscan/…).",
                 tasks=["Events entgegennehmen", "Signal-Katalog anwenden",
                        "Treffer mit Evidence erfassen",
                        "Ohne Events: honest-empty"]),
        Playbook("watcher-divert-protect", "defensive", False,
                 ["honeypot-divert", "immediate-protect"],
                 "Je Detection: Divert-Plan + Sofortschutz-Empfehlung.",
                 tasks=["Divert je Detection planen",
                        "Sofortschutz empfehlen (rate-limit/block)",
                        "Aktives Anwenden nur mit Oversight"]),
        Playbook("watcher-traceback", "defensive", False,
                 ["source-correlation", "fingerprint-session"],
                 "Angreifer-Rückverfolgung aus echten Sources/Sessions.",
                 tasks=["Sources korrelieren", "Fingerprints/Sessions sammeln",
                        "Keine erfundenen IPs/Identitäten",
                        "Attribution im Attack-Log ablegen"]),
        Playbook("watcher-full-run", "defensive", True,
                 ["run-watch"],
                 "Voller Wächter-Lauf inkl. optional aktivem Divert/Protect "
                 "(Oversight).",
                 tasks=["Oversight prüfen", "run_watch ausführen",
                        "Log-IDs zurückgeben", "Summary melden"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        params = task.params or {}
        events = list(params.get("events") or [])
        kinds = params.get("kinds")
        active = self.active_allowed()
        apply_protect = bool(params.get("apply_protect")) and active
        store = None
        # Store nur wenn die Königin einen angehängt hat (über params)
        store = params.get("_store")

        self.ctx.log(f"[blue-watcher] 👁 {len(events)} Event(s), "
                     f"active={active}, signals={len(_w.SIGNAL_CATALOG)}.")
        report = _w.run_watch(
            events, active=active, apply_protect=apply_protect,
            kinds=kinds, store=store, run_id=self.ctx.run_id,
            target_id=task.target_id or None)

        # Capability / Summary immer
        findings.append(AgentFinding(
            agent=self.name,
            title=(f"Wächter: {report.summary.get('detection_count', 0)} Detection(s) "
                   f"aus {report.summary.get('event_count', 0)} Event(s)"),
            category="blue-watcher-summary", severity="info", asset="monitoring",
            description=("Pipeline detect→divert→protect→traceback→log. "
                         + ("Honest-empty: keine Events." if report.summary.get("honest_empty")
                            else report.traceback.get("reason", ""))),
            evidence={"summary": report.summary,
                      "capabilities": _w.capability_summary(),
                      "traceback": report.traceback},
            status="REFERENZ",
            dedup_key="blue-watcher-summary",
        ))

        for d in report.detections:
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[{d.severity.upper()}] {d.title}",
                category="blue-watcher-detection", severity=d.severity,
                asset=d.source or "monitoring",
                description=f"Signal {d.signal_id} · Marker: {d.matched_marker}",
                evidence=d.to_dict(),
                status="BESTÄTIGT(PASSIV)",
                dedup_key=f"blue-watcher:{d.signal_id}:{d.source}:{d.ts}",
            ))

        for i, div in enumerate(report.diverts):
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Divert {div.get('status')}: → {div.get('recipe_id')}",
                category="blue-watcher-divert",
                severity="info", asset="decoy",
                description=div.get("reason") or "",
                evidence=div, status="REFERENZ",
                dedup_key=f"blue-watcher-divert:{i}:{div.get('recipe_id')}",
            ))

        attrs = (report.traceback or {}).get("attributions") or []
        if attrs:
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Rückverfolgung: {len(attrs)} Quelle(n)",
                category="blue-watcher-traceback", severity="info",
                asset="monitoring",
                description=(report.traceback or {}).get("reason") or "",
                evidence={"attributions": attrs},
                status="BESTÄTIGT(PASSIV)",
                dedup_key="blue-watcher-traceback",
            ))
        return findings
