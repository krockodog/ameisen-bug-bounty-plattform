"""Optionaler Splunk-Adapter (free/green) via HTTP Event Collector (HEC).

Schickt Blue-Queen-Findings/Events an ein lokales Splunk Free bzw. ein
HEC-kompatibles Ziel. STRENG OPTIONAL:
  * Endpoint + Token kommen AUSSCHLIESSLICH aus ENV/Config, NIEMALS aus dem Code.
    - ANTBB_SPLUNK_HEC_URL   (z.B. https://localhost:8088/services/collector)
    - ANTBB_SPLUNK_HEC_TOKEN (HEC-Token)
    - ANTBB_SPLUNK_VERIFY    ("0" = TLS-Verify aus für lokale self-signed Instanzen)
    - ANTBB_SPLUNK_INDEX / ANTBB_SPLUNK_SOURCETYPE (optional)
  * Fehlt die Konfiguration → sauber ÜBERSPRUNGEN (skipped=True), kein Fehler,
    kein Abbruch eines Laufs.
  * Das Token wird nie geloggt/zurückgegeben.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class SplunkConfig:
    url: str = ""
    token: str = ""
    index: str = ""
    sourcetype: str = "antbb:bluequeen"
    verify_tls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


def config_from_env() -> SplunkConfig:
    verify = os.environ.get("ANTBB_SPLUNK_VERIFY", "1").strip().lower()
    return SplunkConfig(
        url=os.environ.get("ANTBB_SPLUNK_HEC_URL", "").strip(),
        token=os.environ.get("ANTBB_SPLUNK_HEC_TOKEN", "").strip(),
        index=os.environ.get("ANTBB_SPLUNK_INDEX", "").strip(),
        sourcetype=os.environ.get("ANTBB_SPLUNK_SOURCETYPE", "antbb:bluequeen").strip()
                   or "antbb:bluequeen",
        verify_tls=verify not in ("0", "false", "no", "off"),
    )


def status() -> dict:
    """Konfigurationsstatus OHNE Secret-Offenlegung (für GUI/Registry)."""
    cfg = config_from_env()
    return {
        "configured": cfg.configured,
        "url_set": bool(cfg.url),
        "token_set": bool(cfg.token),
        "index": cfg.index,
        "sourcetype": cfg.sourcetype,
        "verify_tls": cfg.verify_tls,
    }


def _event_payload(cfg: SplunkConfig, event: dict) -> dict:
    body: dict[str, Any] = {
        "time": event.get("time", time.time()),
        "sourcetype": cfg.sourcetype,
        "source": "antbb-blue-queen",
        "event": event,
    }
    if cfg.index:
        body["index"] = cfg.index
    return body


def send_events(events: list[dict], cfg: Optional[SplunkConfig] = None,
                timeout: float = 8.0) -> dict:
    """Sendet Events an HEC. Rückgabe-Report; niemals Exception nach außen.

    {"skipped": bool, "sent": int, "ok": bool, "error": str|None}
    """
    cfg = cfg or config_from_env()
    if not cfg.configured:
        return {"skipped": True, "sent": 0, "ok": True, "error": None,
                "reason": "Keine Splunk-HEC-Konfiguration (ENV) gesetzt – übersprungen."}
    if not events:
        return {"skipped": False, "sent": 0, "ok": True, "error": None}
    try:
        import httpx
    except Exception:
        return {"skipped": True, "sent": 0, "ok": False,
                "error": "httpx nicht verfügbar"}
    headers = {"Authorization": f"Splunk {cfg.token}"}
    # HEC akzeptiert mehrere Events als aneinandergehängte JSON-Objekte.
    import json
    payload = "\n".join(json.dumps(_event_payload(cfg, e)) for e in events)
    try:
        with httpx.Client(timeout=timeout, verify=cfg.verify_tls) as client:
            resp = client.post(cfg.url, headers=headers, content=payload)
            ok = resp.status_code == 200
            return {"skipped": False, "sent": len(events) if ok else 0,
                    "ok": ok, "error": None if ok else f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"skipped": False, "sent": 0, "ok": False,
                "error": f"{type(exc).__name__}: {exc}"}


def finding_to_event(finding: dict) -> dict:
    """Normalisiert ein Finding/Ergebnis zu einem Splunk-Event (ohne Secrets)."""
    return {
        "time": time.time(),
        "colony": "blue",
        "agent": finding.get("agent", ""),
        "title": finding.get("title", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", ""),
        "status": finding.get("status", ""),
        "asset": finding.get("asset", ""),
    }
