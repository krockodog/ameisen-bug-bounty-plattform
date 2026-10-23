"""Honeypot-/Decoy-Kernmodul (sichere Rezepte + Umleitungs-API).

Leitlinien:
  * Default-deny: aktive Umleitung/Start NUR mit Oversight (active=True).
  * Ohne Oversight: ehrlicher Scaffold + Playbook-Schritte, NICHTS gestartet.
  * Keine Fake-Hits, keine Fake-IPs. honest-empty wenn keine Events.
  * Non-destruktiv: Umleitung ist eine Steuerungsentscheidung + Log-Eintrag;
    echte Netzwerkumleitung (iptables/nft/proxy) ist optional und ebenfalls gated.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

log = logging.getLogger("antbb.honeypot")

#: Sichere, generische Decoy-Rezepte (keine Secrets/PII, allgemeingültig).
RECIPES = [
    {"id": "ssh-decoy", "title": "SSH-Decoy (low-interaction)",
     "desc": ("Fake-SSH auf unüblichem Port, der nur Verbindungs-/Login-Versuche "
              "protokolliert (z.B. cowrie low-interaction, isoliert)."),
     "safety": "Isoliertes Netz/Container, keine echten Credentials, Logs lokal.",
     "divert_port": 2222, "protocol": "tcp"},
    {"id": "http-canary", "title": "HTTP-Canary-Endpoint",
     "desc": ("Unverlinkter Pfad/Token, dessen Abruf einen Alarm auslöst "
              "(Canarytoken-Prinzip)."),
     "safety": "Kein echter Dienst dahinter; nur Zugriffs-Logging.",
     "divert_port": 8089, "protocol": "http"},
    {"id": "decoy-file", "title": "Decoy-Dokument (Canary)",
     "desc": "Köder-Datei mit eingebettetem Canary, die beim Öffnen/Exfil meldet.",
     "safety": "Enthält keine echten Daten; rein als Tripwire.",
     "divert_port": None, "protocol": "file"},
    {"id": "smtp-decoy", "title": "SMTP-Decoy (low-interaction)",
     "desc": "Fake-SMTP der EHLO/MAIL-Versuche protokolliert, keine Relays.",
     "safety": "Kein Relay, isoliert, nur Logging.",
     "divert_port": 2525, "protocol": "tcp"},
]


@dataclass
class DivertResult:
    """Ergebnis einer Umleitungs-Entscheidung."""
    ok: bool
    applied: bool                    # True nur wenn aktive Umleitung wirklich gesetzt
    recipe_id: str = ""
    reason: str = ""
    playbook_steps: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    status: str = "skipped"          # applied | planned | denied | skipped | failed

    def to_dict(self) -> dict:
        return asdict(self)


def list_recipes() -> list[dict]:
    """Alle sicheren Rezepte (ohne Secrets)."""
    return [dict(r) for r in RECIPES]


def get_recipe(recipe_id: str) -> Optional[dict]:
    for r in RECIPES:
        if r["id"] == recipe_id:
            return dict(r)
    return None


def divert_plan(signal: dict, recipe_id: str = "http-canary") -> DivertResult:
    """Plant eine Umleitung (immer erlaubt, rein dokumentierend).

    `signal` sollte mindestens `kind` und optional `source`/`asset` enthalten.
    Liefert Playbook-Schritte; startet NICHTS.
    """
    recipe = get_recipe(recipe_id) or get_recipe("http-canary")
    assert recipe is not None
    steps = [
        f"1. Signal klassifizieren: kind={signal.get('kind', '?')} "
        f"source={signal.get('source', '?')}",
        f"2. Decoy wählen: {recipe['id']} ({recipe['title']})",
        "3. Angreifer-Traffic auf Decoy umleiten (Proxy/Firewall-Regel) – "
        "NUR mit Oversight",
        "4. Echte Assets isolieren / rate-limiten (Sofortschutz)",
        "5. Alles im Attack-Log dokumentieren (Vorher/Nachher)",
        "6. Attribution/Rückverfolgung aus echten Events starten",
    ]
    return DivertResult(
        ok=True, applied=False, recipe_id=recipe["id"],
        reason="Plan erstellt (kein aktiver Eingriff).",
        playbook_steps=steps, status="planned",
        evidence={
            "signal_kind": signal.get("kind"),
            "signal_source": signal.get("source"),
            "recipe": {"id": recipe["id"], "title": recipe["title"],
                       "protocol": recipe.get("protocol"),
                       "divert_port": recipe.get("divert_port")},
            "safety": recipe.get("safety"),
            "ts": time.time(),
        },
    )


def divert_apply(signal: dict, recipe_id: str = "http-canary", *,
                 active: bool = False,
                 apply_network: bool = False) -> DivertResult:
    """Umleitung ausführen – default-deny ohne Oversight.

    Ohne `active=True`: denied, Playbook-Schritte zurück.
    Mit Oversight: dokumentierte Umleitungsentscheidung (applied=True auf
    Steuerungsebene). Echte Netz-Regeln nur wenn zusätzlich
    `apply_network=True` UND ein unterstützter Backend vorhanden – sonst
    ehrlich als 'planned/skipped' mit Begründung.
    """
    plan = divert_plan(signal, recipe_id)
    if not active:
        plan.status = "denied"
        plan.reason = ("BLOCKIERT (default-deny): Honeypot-Umleitung ohne "
                       "Oversight-Freigabe. Nichts umgeleitet.")
        plan.applied = False
        plan.ok = False
        return plan

    # Oversight vorhanden: Steuerungsentscheidung dokumentieren.
    # Echte Netzwerkumleitung ist bewusst konservativ – ohne Backend skipped.
    evidence = dict(plan.evidence)
    evidence["oversight"] = True
    evidence["apply_network_requested"] = bool(apply_network)

    if apply_network:
        # Kein unkontrollierter iptables/nft-Call. Ehrlicher Skip mit Hinweis.
        evidence["network_backend"] = "none"
        evidence["network_note"] = (
            "Kein automatischer Netz-Backend-Call (bewusst konservativ). "
            "Operator setzt Proxy/Firewall-Regel laut Playbook-Schritten.")
        return DivertResult(
            ok=True, applied=False, recipe_id=plan.recipe_id,
            reason=("Oversight ok – Steuerungsentscheidung dokumentiert; "
                    "Netz-Backend nicht konfiguriert (skipped)."),
            playbook_steps=plan.playbook_steps, status="skipped",
            evidence=evidence,
        )

    # Steuerungsentscheidung: Umleitung als „angewendet" auf Logik-Ebene
    # (Decoy als Ziel markiert). Kein Prozess gestartet.
    evidence["divert_decision"] = "mark_decoy_target"
    evidence["decoy_marked_at"] = time.time()
    return DivertResult(
        ok=True, applied=True, recipe_id=plan.recipe_id,
        reason=("Umleitungsentscheidung gesetzt (Decoy als Ziel markiert). "
                "Kein unkontrollierter Prozess gestartet."),
        playbook_steps=plan.playbook_steps, status="applied",
        evidence=evidence,
    )


def capability_summary(active: bool = False) -> dict:
    """installed/skipped/failed-Zusammenfassung für Capability-Report."""
    return {
        "recipes": len(RECIPES),
        "recipe_ids": [r["id"] for r in RECIPES],
        "divert_default": "deny",
        "active_oversight": bool(active),
        "network_backend": "none",
        "status": "installed",
    }
