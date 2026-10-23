"""Wächter-Kernmodul: frühe Angriffserkennung + Umleitung + Sofortschutz + Traceback.

Signalbasiert und ehrlich:
  * Keine Fake-IPs, Fake-Angriffe, Fake-Attribution.
  * Ohne echte Events/Signale → honest-empty (leere Liste).
  * Aktive Gegenmaßnahmen (divert apply, temporary block) nur oversight-gated.
  * Alles kann in den permanenten Attack-Log geschrieben werden.

Angriffsarten (Signal-Klassen):
  web | auth | net | wlan | api | generic
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

from . import honeypot as _hp

log = logging.getLogger("antbb.watcher")

#: Bekannte Signal-Muster je Angriffsart (generisch, keine Secrets).
#: Ein Signal gilt nur, wenn ein ECHTES Event diese Marker trifft.
SIGNAL_CATALOG: list[dict] = [
    {"id": "web-sqli", "kind": "web", "title": "SQL-Injection-Versuch",
     "markers": [r"(?i)union\s+select", r"(?i)or\s+1\s*=\s*1", r"(?i)'\s*or\s*'"],
     "fields": ("path", "query", "body", "raw"), "severity": "high",
     "recipe": "http-canary"},
    {"id": "web-xss", "kind": "web", "title": "XSS-Versuch",
     "markers": [r"(?i)<script", r"(?i)javascript:", r"(?i)onerror\s*="],
     "fields": ("path", "query", "body", "raw"), "severity": "medium",
     "recipe": "http-canary"},
    {"id": "web-path-traversal", "kind": "web", "title": "Path-Traversal-Versuch",
     "markers": [r"\.\./", r"(?i)%2e%2e%2f", r"(?i)/etc/passwd"],
     "fields": ("path", "query", "raw"), "severity": "high",
     "recipe": "http-canary"},
    {"id": "auth-bruteforce", "kind": "auth", "title": "Auth-Brute-Force",
     "markers": [r"(?i)failed\s+password", r"(?i)authentication\s+failure",
                 r"(?i)invalid\s+user"],
     "fields": ("message", "raw"), "severity": "medium",
     "recipe": "ssh-decoy"},
    {"id": "auth-spray", "kind": "auth", "title": "Credential-Spray",
     "markers": [r"(?i)password\s+spray", r"(?i)multiple\s+failed\s+logins"],
     "fields": ("message", "raw"), "severity": "high",
     "recipe": "ssh-decoy"},
    {"id": "net-portscan", "kind": "net", "title": "Portscan / Probe",
     "markers": [r"(?i)nmap", r"(?i)port\s*scan", r"(?i)syn\s*flood",
                 r"(?i)connection\s+attempt"],
     "fields": ("message", "raw"), "severity": "medium",
     "recipe": "ssh-decoy"},
    {"id": "api-abuse", "kind": "api", "title": "API-Missbrauch / Enum",
     "markers": [r"(?i)/api/v\d+/.*/\.\.", r"(?i)graphql.*introspection",
                 r"(?i)rate.?limit.?exceeded"],
     "fields": ("path", "query", "message", "raw"), "severity": "medium",
     "recipe": "http-canary"},
    {"id": "wlan-deauth", "kind": "wlan", "title": "WLAN-Deauth / Rogue",
     "markers": [r"(?i)deauth", r"(?i)rogue\s*ap", r"(?i)evil.?twin"],
     "fields": ("message", "raw"), "severity": "high",
     "recipe": "http-canary"},
    {"id": "generic-c2", "kind": "generic", "title": "Auffälliger Outbound / C2-Muster",
     "markers": [r"(?i)beaconing", r"(?i)c2\s*callback", r"(?i)tor\s*exit"],
     "fields": ("message", "raw"), "severity": "high",
     "recipe": "http-canary"},
]


@dataclass
class Detection:
    """Ein erkanntes Signal (aus echten Events)."""
    signal_id: str
    kind: str
    title: str
    severity: str
    source: str = ""
    matched_marker: str = ""
    event_excerpt: str = ""
    recipe_id: str = "http-canary"
    evidence: dict = field(default_factory=dict)
    ts: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d["ts"]:
            d["ts"] = time.time()
        return d


@dataclass
class ProtectResult:
    ok: bool
    applied: bool
    action: str = ""
    reason: str = ""
    status: str = "skipped"          # applied | planned | denied | skipped
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TracebackResult:
    ok: bool
    attributions: list[dict] = field(default_factory=list)
    reason: str = ""
    status: str = "empty"            # correlated | empty | partial

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WatchReport:
    """Gesamtbericht eines Wächter-Laufs."""
    detections: list[Detection] = field(default_factory=list)
    diverts: list[dict] = field(default_factory=list)
    protects: list[dict] = field(default_factory=list)
    traceback: dict = field(default_factory=dict)
    log_ids: list[int] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "detections": [d.to_dict() for d in self.detections],
            "diverts": list(self.diverts),
            "protects": list(self.protects),
            "traceback": dict(self.traceback),
            "log_ids": list(self.log_ids),
            "summary": dict(self.summary),
        }


def _event_blob(event: dict) -> str:
    """Flacht ein Event zu einem suchbaren Textblob."""
    parts = []
    for k in ("path", "query", "body", "message", "raw", "action", "title"):
        v = event.get(k)
        if v:
            parts.append(str(v))
    # Zusätzlich alle string-Werte flach anhängen (ohne Secrets).
    for k, v in event.items():
        if k in ("path", "query", "body", "message", "raw", "action", "title"):
            continue
        if isinstance(v, str) and v and k.lower() not in (
                "password", "token", "secret", "authorization", "cookie"):
            parts.append(v)
    return "\n".join(parts)


def detect_signals(events: Iterable[dict],
                   kinds: Optional[Iterable[str]] = None) -> list[Detection]:
    """Erkennt Angriffssignale in ECHTEN Events. Ohne Events → [].

    `events`: Iterable von dicts mit Feldern wie path/query/body/message/raw
              und optional source/asset/ts.
    `kinds`: optionaler Filter auf Signal-Klassen.
    """
    want = set(kinds) if kinds else None
    out: list[Detection] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        blob = _event_blob(ev)
        if not blob.strip():
            continue
        source = str(ev.get("source") or ev.get("asset") or ev.get("src") or "")
        for sig in SIGNAL_CATALOG:
            if want is not None and sig["kind"] not in want:
                continue
            for marker in sig["markers"]:
                try:
                    m = re.search(marker, blob)
                except re.error:
                    continue
                if not m:
                    continue
                excerpt = blob[max(0, m.start() - 40): m.end() + 40]
                out.append(Detection(
                    signal_id=sig["id"], kind=sig["kind"], title=sig["title"],
                    severity=sig["severity"], source=source,
                    matched_marker=marker, event_excerpt=excerpt[:240],
                    recipe_id=sig.get("recipe") or "http-canary",
                    evidence={
                        "event_keys": sorted(ev.keys()),
                        "kind": sig["kind"],
                        "marker": marker,
                    },
                    ts=float(ev.get("ts") or time.time()),
                ))
                break  # ein Treffer je Signal-ID pro Event reicht
    return out


def immediate_protect(detection: Detection, *, active: bool = False,
                      mode: str = "recommend") -> ProtectResult:
    """Sofortschutz für verwundbare Assets.

    Default: Empfehlung (rate-limit / temporary block) ohne Anwendung.
    Mit Oversight (`active=True`) und mode='apply': dokumentierte
    Schutzentscheidung (applied auf Steuerungsebene). Keine destruktiven
    System-Calls ohne explizites Backend.
    """
    action = "temporary-block-or-rate-limit"
    steps_evidence = {
        "recommended_actions": [
            "Rate-Limit für die Quell-Session setzen",
            "Temporären Block (Fail2ban/nft-set) für Quelle erwägen",
            "Betroffenes Asset in Isolation / Wartungsmodus",
            "Honeypot-Umleitung aktivieren (siehe divert)",
        ],
        "detection": detection.to_dict(),
        "non_destructive_default": True,
    }
    if not active or mode != "apply":
        return ProtectResult(
            ok=True, applied=False, action=action,
            reason=("Sofortschutz als Empfehlung (default). Aktives Anwenden "
                    "nur mit Oversight + mode='apply'."),
            status="planned" if not active else "planned",
            evidence=steps_evidence,
        )
    # Oversight + apply: Steuerungsentscheidung dokumentieren.
    steps_evidence["protect_decision"] = "mark_asset_protected"
    steps_evidence["protected_at"] = time.time()
    return ProtectResult(
        ok=True, applied=True, action=action,
        reason=("Sofortschutz-Entscheidung gesetzt (Asset markiert/rate-limit "
                "empfohlen). Kein unkontrollierter Firewall-Call."),
        status="applied", evidence=steps_evidence,
    )


def traceback_attacker(detections: list[Detection],
                       events: Optional[Iterable[dict]] = None) -> TracebackResult:
    """Angreifer-Rückverfolgung aus echten Events/Detectionen.

    Korreliert Source/Session/Fingerprint. Ohne Daten → honest-empty.
    Erfindet KEINE IPs/Identitäten.
    """
    if not detections and not events:
        return TracebackResult(
            ok=True, attributions=[], status="empty",
            reason="Keine Events/Detectionen – keine Attribution möglich.",
        )
    # Quellen aus Detectionen.
    by_source: dict[str, dict] = {}
    for d in detections:
        src = (d.source or "").strip()
        if not src:
            continue
        bucket = by_source.setdefault(src, {
            "source": src, "signal_ids": [], "kinds": [],
            "severities": [], "first_ts": d.ts, "last_ts": d.ts,
            "event_count": 0,
        })
        bucket["signal_ids"].append(d.signal_id)
        bucket["kinds"].append(d.kind)
        bucket["severities"].append(d.severity)
        bucket["first_ts"] = min(bucket["first_ts"] or d.ts, d.ts)
        bucket["last_ts"] = max(bucket["last_ts"] or d.ts, d.ts)
        bucket["event_count"] += 1

    # Zusätzliche Korrelation über Events (session/fingerprint falls vorhanden).
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        src = str(ev.get("source") or ev.get("asset") or ev.get("src") or "").strip()
        if not src:
            continue
        bucket = by_source.setdefault(src, {
            "source": src, "signal_ids": [], "kinds": [],
            "severities": [], "first_ts": float(ev.get("ts") or time.time()),
            "last_ts": float(ev.get("ts") or time.time()), "event_count": 0,
        })
        bucket["event_count"] += 1
        fp = ev.get("fingerprint") or ev.get("session") or ev.get("ja3")
        if fp:
            bucket.setdefault("fingerprints", [])
            if fp not in bucket["fingerprints"]:
                bucket["fingerprints"].append(str(fp)[:120])

    attrs = []
    for src, b in by_source.items():
        attrs.append({
            "source": src,
            "signal_ids": sorted(set(b["signal_ids"])),
            "kinds": sorted(set(b["kinds"])),
            "max_severity": _max_sev(b["severities"]),
            "first_ts": b["first_ts"],
            "last_ts": b["last_ts"],
            "event_count": b["event_count"],
            "fingerprints": b.get("fingerprints", []),
            # Keine erfundenen Geo/ASN – nur was da ist.
        })
    if not attrs:
        return TracebackResult(
            ok=True, attributions=[], status="empty",
            reason="Events ohne verwertbare Quelle – keine Attribution.",
        )
    return TracebackResult(
        ok=True, attributions=attrs, status="correlated",
        reason=f"{len(attrs)} Quelle(n) aus echten Events korreliert.",
    )


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_sev(sevs: list[str]) -> str:
    best = "info"
    for s in sevs:
        if _SEV_RANK.get(s, 0) > _SEV_RANK.get(best, 0):
            best = s
    return best


def run_watch(events: Optional[list[dict]] = None, *,
              active: bool = False,
              apply_protect: bool = False,
              apply_network: bool = False,
              kinds: Optional[Iterable[str]] = None,
              store=None, run_id: str = "",
              target_id: Optional[int] = None) -> WatchReport:
    """Voller Wächter-Lauf: detect → divert → protect → traceback → log.

    `events=None`/leer → honest-empty Report (keine Fake-Detections).
    Aktive divert/protect nur mit `active=True` (Oversight).
    """
    events = list(events or [])
    detections = detect_signals(events, kinds=kinds)
    report = WatchReport(detections=detections)

    # Divert je Detection (Plan immer; Apply nur gated).
    for d in detections:
        if active:
            dr = _hp.divert_apply(
                {"kind": d.kind, "source": d.source, "signal_id": d.signal_id},
                recipe_id=d.recipe_id, active=True, apply_network=apply_network)
        else:
            dr = _hp.divert_plan(
                {"kind": d.kind, "source": d.source, "signal_id": d.signal_id},
                recipe_id=d.recipe_id)
            dr.status = "planned"
        report.diverts.append(dr.to_dict())

        pr = immediate_protect(
            d, active=active,
            mode="apply" if (active and apply_protect) else "recommend")
        report.protects.append(pr.to_dict())

    tb = traceback_attacker(detections, events)
    report.traceback = tb.to_dict()

    # Permanenter Attack-Log (wenn Store vorhanden).
    if store is not None:
        from .attack_log import AttackLog, AttackEvent
        alog = AttackLog(store)
        for d in detections:
            report.log_ids.append(alog.append(AttackEvent(
                event_type="detection", source=d.source,
                action=f"{d.title} ({d.signal_id})",
                countermeasure="", outcome="detected",
                evidence=d.to_dict(), run_id=run_id, target_id=target_id,
                severity=d.severity, ts=d.ts,
            )))
        for i, div in enumerate(report.diverts):
            d = detections[i] if i < len(detections) else None
            report.log_ids.append(alog.append(AttackEvent(
                event_type="divert",
                source=(d.source if d else ""),
                action=f"honeypot-divert → {div.get('recipe_id')}",
                countermeasure="honeypot-divert",
                outcome=div.get("status") or "",
                before={"detection": d.to_dict() if d else {}},
                after=div.get("evidence") or {},
                evidence={"reason": div.get("reason"),
                          "playbook_steps": div.get("playbook_steps")},
                run_id=run_id, target_id=target_id,
                severity=(d.severity if d else "info"),
            )))
        for i, prot in enumerate(report.protects):
            d = detections[i] if i < len(detections) else None
            report.log_ids.append(alog.append(AttackEvent(
                event_type="protect",
                source=(d.source if d else ""),
                action=prot.get("action") or "immediate-protect",
                countermeasure=prot.get("action") or "immediate-protect",
                outcome=prot.get("status") or "",
                before={"detection": d.to_dict() if d else {}},
                after=prot.get("evidence") or {},
                evidence={"reason": prot.get("reason")},
                run_id=run_id, target_id=target_id,
                severity=(d.severity if d else "info"),
            )))
        report.log_ids.append(alog.append(AttackEvent(
            event_type="traceback",
            source="",
            action="attacker-traceback",
            countermeasure="correlation",
            outcome=tb.status,
            after={"attributions": tb.attributions},
            evidence={"reason": tb.reason},
            run_id=run_id, target_id=target_id, severity="info",
        )))

    report.summary = {
        "event_count": len(events),
        "detection_count": len(detections),
        "divert_count": len(report.diverts),
        "divert_applied": sum(1 for d in report.diverts if d.get("applied")),
        "protect_applied": sum(1 for p in report.protects if p.get("applied")),
        "traceback_sources": len(tb.attributions),
        "log_entries": len(report.log_ids),
        "active_oversight": bool(active),
        "honest_empty": (len(events) == 0),
        "status": "installed",
    }
    return report


def capability_summary() -> dict:
    return {
        "signals": len(SIGNAL_CATALOG),
        "signal_ids": [s["id"] for s in SIGNAL_CATALOG],
        "kinds": sorted({s["kind"] for s in SIGNAL_CATALOG}),
        "honeypot": _hp.capability_summary(),
        "default": "detect+plan (apply oversight-gated)",
        "status": "installed",
    }
