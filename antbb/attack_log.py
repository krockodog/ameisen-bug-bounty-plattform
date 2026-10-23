"""Permanenter Attack-Log der Blue Queen (append-only).

Lückenlose Dokumentation von Angreifer-Aktionen UND Gegenmaßnahmen:
  * Timestamp, Event-Typ, Source, Action, Outcome, Vorher/Nachher
  * Append-only: normale API bietet KEIN Truncate/Delete
  * Optional Spiegelung an Splunk HEC (ENV), sonst skipped

Nichts erfinden: leere Daten → leere Liste (honest-empty).
Secrets/PII werden vor Persistenz gestrippt.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from . import splunk as _splunk

log = logging.getLogger("antbb.attack_log")

#: Erlaubte Event-Typen (geschlossen, erweiterbar).
EVENT_TYPES = frozenset({
    "detection",          # Signal erkannt
    "divert",             # Umleitung in Honeypot
    "protect",            # Sofortschutz angewendet/vorgeschlagen
    "traceback",          # Attribution/Korrelation
    "countermeasure",     # Gegenmaßnahme (generisch)
    "honeypot_hit",       # Treffer im Decoy
    "info",               # Meta/Status
})

_SECRET_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "session", "private_key", "hec_token",
})


def _scrub(obj: Any) -> Any:
    """Entfernt Secret-ähnliche Keys rekursiv (nie Secrets im Log)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _SECRET_KEYS or any(
                    m in str(k).lower() for m in ("password", "token", "secret", "apikey")):
                out[k] = "[redacted]"
            else:
                out[k] = _scrub(v)
        return out
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    return obj


@dataclass
class AttackEvent:
    """Ein Eintrag im permanenten Attack-Log."""
    event_type: str
    source: str = ""                 # Quelle (z.B. Signal-ID, Asset, IP-Klasse)
    action: str = ""                 # Was der Angreifer tat / was erkannt wurde
    countermeasure: str = ""         # Gegenmaßnahme (oder Empfehlung)
    outcome: str = ""                # Ergebnis (detected/diverted/blocked/skipped/…)
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    run_id: str = ""
    target_id: Optional[int] = None
    severity: str = "info"
    ts: float = 0.0

    def normalize(self) -> "AttackEvent":
        if self.event_type not in EVENT_TYPES:
            self.event_type = "info"
        if not self.ts:
            self.ts = time.time()
        self.before = _scrub(self.before or {})
        self.after = _scrub(self.after or {})
        self.evidence = _scrub(self.evidence or {})
        return self

    def to_dict(self) -> dict:
        self.normalize()
        d = asdict(self)
        return d


class AttackLog:
    """Append-only Facade über den Store. Kein Truncate/Delete."""

    def __init__(self, store, logger: Optional[logging.Logger] = None,
                 mirror_splunk: bool = True):
        self.store = store
        self.logger = logger or log
        self.mirror_splunk = mirror_splunk

    def append(self, event: AttackEvent) -> int:
        """Persistiert EIN Event. Rückgabe: row-id. Niemals löschen."""
        event = event.normalize()
        eid = self.store.append_attack_event(event.to_dict())
        self.logger.info(
            "attack-log#%s %s src=%s action=%s cm=%s outcome=%s",
            eid, event.event_type, event.source[:40],
            (event.action or "")[:60],
            (event.countermeasure or "")[:60],
            event.outcome,
        )
        if self.mirror_splunk:
            try:
                st = _splunk.status()
                if st.get("configured"):
                    _splunk.send_events([{
                        "time": event.ts,
                        "colony": "blue",
                        "kind": "attack_log",
                        "event_type": event.event_type,
                        "source": event.source,
                        "action": event.action,
                        "countermeasure": event.countermeasure,
                        "outcome": event.outcome,
                        "severity": event.severity,
                        "run_id": event.run_id,
                    }])
            except Exception as exc:
                self.logger.debug("splunk-mirror skipped: %s", exc)
        return eid

    def append_many(self, events: list[AttackEvent]) -> list[int]:
        return [self.append(e) for e in events]

    def list(self, *, run_id: str = "", event_type: str = "",
             limit: int = 200, since: Optional[float] = None) -> list[dict]:
        """Liest Events (honest-empty wenn keine). Kein Truncate."""
        return self.store.list_attack_events(
            run_id=run_id or None, event_type=event_type or None,
            limit=limit, since=since)

    def count(self) -> int:
        return self.store.count_attack_events()

    def summary(self) -> dict:
        rows = self.list(limit=10_000)
        by_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in rows:
            by_type[r.get("event_type") or "info"] = by_type.get(r.get("event_type") or "info", 0) + 1
            by_outcome[r.get("outcome") or ""] = by_outcome.get(r.get("outcome") or "", 0) + 1
        return {
            "total": len(rows),
            "by_type": by_type,
            "by_outcome": by_outcome,
            "append_only": True,
            "delete_api": False,
        }


def record(store, *, event_type: str, source: str = "", action: str = "",
           countermeasure: str = "", outcome: str = "",
           before: Optional[dict] = None, after: Optional[dict] = None,
           evidence: Optional[dict] = None, run_id: str = "",
           target_id: Optional[int] = None, severity: str = "info") -> int:
    """Convenience: ein Event anlegen und persistieren."""
    return AttackLog(store).append(AttackEvent(
        event_type=event_type, source=source, action=action,
        countermeasure=countermeasure, outcome=outcome,
        before=before or {}, after=after or {},
        evidence=evidence or {}, run_id=run_id, target_id=target_id,
        severity=severity,
    ))
