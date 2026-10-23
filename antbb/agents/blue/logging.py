"""Blue-Soldat: Logging / Splunk-Free-Adapter vertiefen."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import splunk as _splunk


class LoggingAnt(BlueAgent):
    name = "blue-logging"
    specialty = "blue-logging-officer"
    role = ("Logging & SIEM-Adapter: Splunk-HEC (Free/Green) Status, "
            "Event-Mapping, sauberer Skip ohne Config.")
    blue_phases = ("defend", "verify")
    playbooks = (
        Playbook("logging-splunk-status", "defensive", False,
                 ["hec-status"],
                 "Splunk-HEC-Konfiguration (ENV) prüfen – keine Tokens loggen.",
                 tasks=["ENV-Status lesen", "configured ja/nein",
                        "Index/Sourcetype melden", "Token nie ausgeben"]),
        Playbook("logging-event-map", "defensive", False,
                 ["finding-to-event"],
                 "Finding→HEC-Event-Mapping dokumentieren/testen (lokal).",
                 tasks=["Beispiel-Finding mappen", "Felder prüfen",
                        "Ohne Config Skip bestätigen"]),
        Playbook("logging-forward-smoke", "defensive", False,
                 ["hec-send-smoke"],
                 "Smoke: send_events – ohne Config skipped=ok.",
                 tasks=["send_events aufrufen", "skipped/ok auswerten",
                        "Fehler ehrlich melden"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        st = _splunk.status()
        # Token nie in Evidence
        safe_st = {k: v for k, v in st.items() if "token" not in k.lower()}
        self.ctx.log(f"[blue-logging] 📡 Splunk configured={st.get('configured')}.")
        findings.append(AgentFinding(
            agent=self.name,
            title=("Splunk-HEC konfiguriert" if st.get("configured")
                   else "Splunk-HEC nicht konfiguriert (Skip)"),
            category="blue-logging-status", severity="info",
            asset="monitoring",
            description=("Setze ANTBB_SPLUNK_HEC_URL + ANTBB_SPLUNK_HEC_TOKEN "
                         "(ENV), nie im Repo." if not st.get("configured")
                         else f"Index={st.get('index') or '—'} · "
                              f"sourcetype={st.get('sourcetype')}"),
            evidence=safe_st, status="BESTÄTIGT(PASSIV)",
            dedup_key="blue-logging-status",
        ))
        sample = _splunk.finding_to_event({
            "agent": self.name, "title": "logging-smoke",
            "category": "blue-logging", "severity": "info",
            "status": "REFERENZ", "asset": "monitoring",
        })
        findings.append(AgentFinding(
            agent=self.name, title="Event-Mapping-Smoke",
            category="blue-logging-map", severity="info",
            asset="monitoring",
            description="finding_to_event liefert HEC-Payload-Struktur.",
            evidence={"sample_keys": sorted(sample.keys())},
            status="REFERENZ", dedup_key="blue-logging-map",
        ))
        res = _splunk.send_events([sample])
        safe_res = {k: v for k, v in res.items() if "token" not in k.lower()}
        findings.append(AgentFinding(
            agent=self.name,
            title=f"HEC-Forward: ok={res.get('ok')} skipped={res.get('skipped')}",
            category="blue-logging-forward", severity="info",
            asset="monitoring",
            description="Ohne Config = sauberer Skip (ok=True, skipped=True).",
            evidence=safe_res, status="BESTÄTIGT(PASSIV)",
            dedup_key="blue-logging-forward",
        ))
        return findings
