"""Blue-Soldat: Permanenter Attack-Log (append-only).

Dokumentiert Angreifer-Aktionen UND Gegenmaßnahmen lückenlos.
Kein Truncate/Delete über die normale API.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ...attack_log import AttackLog, AttackEvent, EVENT_TYPES


class AttackLogAnt(BlueAgent):
    name = "blue-attacklog"
    specialty = "blue-attack-chronicler"
    role = ("Permanenter Attack-Log: Angreifer-Aktionen und Gegenmaßnahmen "
            "append-only dokumentieren (optional Splunk-Spiegel).")
    blue_phases = ("watch", "defend", "verify")
    playbooks = (
        Playbook("attacklog-append", "defensive", False,
                 ["append-event", "scrub-secrets"],
                 "Events append-only persistieren (Secrets gestrippt).",
                 tasks=["Event normalisieren", "Secrets redakten",
                        "In Store schreiben", "Optional Splunk spiegeln"]),
        Playbook("attacklog-review", "defensive", False,
                 ["list-events", "summary-by-type"],
                 "Log einsehen und nach Typ/Outcome zusammenfassen.",
                 tasks=["Events lesen (Limit)", "Nach Typ zählen",
                        "Nach Outcome zählen", "Keine Delete-API nutzen"]),
        Playbook("attacklog-integrity", "defensive", False,
                 ["append-only-check"],
                 "Append-only-Eigenschaft und Event-Typen prüfen.",
                 tasks=["EVENT_TYPES prüfen", "delete_api=False bestätigen",
                        "Summary erzeugen"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        params = task.params or {}
        store = params.get("_store")
        if store is None:
            self.ctx.log("[blue-attacklog] Kein Store im Kontext – "
                         "Integritäts-Report ohne Persistenz.")
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Attack-Log bereit ({len(EVENT_TYPES)} Event-Typen)",
                category="blue-attacklog-ready", severity="info",
                asset="monitoring",
                description="Append-only Facade; Persistenz braucht Store.",
                evidence={"event_types": sorted(EVENT_TYPES),
                          "delete_api": False, "append_only": True},
                status="REFERENZ", dedup_key="blue-attacklog-ready",
            ))
            return findings

        alog = AttackLog(store)
        # Optional: Events aus params anhängen
        for raw in (params.get("log_events") or []):
            if not isinstance(raw, dict):
                continue
            alog.append(AttackEvent(
                event_type=raw.get("event_type") or "info",
                source=raw.get("source") or "",
                action=raw.get("action") or "",
                countermeasure=raw.get("countermeasure") or "",
                outcome=raw.get("outcome") or "",
                evidence=raw.get("evidence") or {},
                run_id=self.ctx.run_id, target_id=task.target_id or None,
                severity=raw.get("severity") or "info",
            ))

        summ = alog.summary()
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Attack-Log: {summ.get('total', 0)} Einträge (append-only)",
            category="blue-attacklog-summary", severity="info",
            asset="monitoring",
            description=f"by_type={summ.get('by_type')} · delete_api={summ.get('delete_api')}",
            evidence=summ, status="BESTÄTIGT(PASSIV)",
            dedup_key="blue-attacklog-summary",
        ))
        # Sample recent
        for row in alog.list(limit=5):
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Log#{row.get('id')}: {row.get('event_type')} – {row.get('action', '')[:60]}",
                category="blue-attacklog-entry", severity=row.get("severity") or "info",
                asset=row.get("source") or "monitoring",
                description=(f"cm={row.get('countermeasure') or '—'} · "
                             f"outcome={row.get('outcome') or '—'}"),
                evidence={"id": row.get("id"), "event_type": row.get("event_type"),
                          "ts": row.get("ts")},
                status="REFERENZ",
                dedup_key=f"blue-attacklog-entry:{row.get('id')}",
            ))
        return findings
