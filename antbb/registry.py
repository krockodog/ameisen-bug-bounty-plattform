"""Capability-Registry der Königin (Single Source of Truth).

Beim Start liest die Königin JEDEN Soldaten (Agenten-Klasse) ein und baut die
Registry FRISCH aus den deklarativen `playbooks` jedes Soldaten auf — nie
hartkodiert, nie veraltet. Jeder Soldat hat einen klar benannten SKILL mit
seiner Playbook-Liste; jedes Playbook trägt eine Liste konkreter AUFGABEN/
CHECKS (task items) mit Default-Status, damit die GUI-Checklisten gefüllt sind.

Die Registry listet nur die Verteidigungs-Soldaten. NIEMALS Secrets.
"""
from __future__ import annotations

import time
from typing import Optional

from .agents.blue import BLUE_AGENTS, BLUE_PHASES

_SECRET_MARKERS = ("api_key", "apikey", "token", "secret", "password", "minimax")


def _scrub(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _SECRET_MARKERS)


import os as _os

_SKILLS_DIR = _os.path.join(_os.path.dirname(__file__), "agents", "skills")

def load_skill_md(soldier: str) -> str:
    """Lädt den Octogent-SKILL.md-Volltext eines Soldaten (oder '' wenn keiner)."""
    path = _os.path.join(_SKILLS_DIR, f"{soldier}.md")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""

# Phasen der Verteidigungs-Kolonie (öffentliche Capability-Liste).
OCTOGENT_PHASES = [
    {"phase": ph, "label": label, "mode": "defensive",
     "soldiers": [], "tools": [], "maps_to": ph, "note": note}
    for ph, label, note in (
        ("assess", "Assess", "Inventar und lesende Checks."),
        ("watch", "Watch", "Beobachten, Detection, Logs."),
        ("harden", "Harden", "Härtung prüfen, Fixes nur mit Oversight."),
        ("defend", "Defend", "Regeln, Decoys, Umleitung planen."),
        ("remediate", "Remediate", "Finding zu einem Fix-Plan."),
        ("verify", "Verify", "Vorher/Nachher belegen."),
    )
]

SCOPE_SUGGESTIONS = {
    "note": ("Vorschlag/Historie – NICHT automatisch erlaubt. Die echte Allowlist bleibt explizit + default-deny."),
    "targets": ["demo.example.com", "shop.example.com", "app.example.com"],
    "separate_engagement": ["engagement.example.com"],
}


# ---------------------------------------------------------------------------
# Zentrale Aufgaben-/Check-Liste je Playbook (konkrete Schritte, nicht nur Titel).
# Gefüllt für ALLE Soldaten. Default-Status pro Task: "offen".
# ---------------------------------------------------------------------------
TASK_CATALOG: dict[str, list[str]] = {
    # --- blue queen ---
    "sw-inventory": ["Paketmanager rein lesend abfragen (dpkg/rpm/pip)",
                     "Paketname+Version erfassen", "keine Secrets"],
    "sw-cve-match-osv": ["Inventar gegen OSV abgleichen", "CVE-IDs nur aus OSV übernehmen",
                         "nie erfundene Schwachstellen"],
    "hardening-audit": ["SSH-Config prüfen", "Firewall-Status prüfen",
                        "world-writable Dateien in /etc finden", "sysctl-Härtung prüfen"],
    "hardening-apply": ["Fix-Vorschlag NUR mit Oversight anwenden (default-deny)",
                        "nie automatisch ohne Freigabe"],
    "detection-ruleset": ["Detection-Regeln bereitstellen", "Quellen zuordnen"],
    "splunk-forward": ["Events an HEC spiegeln wenn konfiguriert",
                       "ohne Config sauber überspringen"],
    "remediation-plan": ["Finding→Fix-Schritt ableiten", "konkreten Behebungsschritt vorschlagen"],
    "remediation-verify": ["rein lesender Re-Check", "Vorher/Nachher-Evidence",
                           "nachweislich geschlossen belegen"],
    "honeypot-recipes": ["sichere Decoy-Rezepte dokumentieren"],
    "honeypot-deploy": ["Decoy NUR mit Oversight starten (default-deny, Scaffold)"],
    # --- blue extras (watcher / attacklog / web / net / supply / ir) ---
    "watcher-detect": ["Events entgegennehmen", "Signal-Katalog anwenden",
                       "Treffer mit Evidence erfassen", "Ohne Events: honest-empty"],
    "watcher-divert-protect": ["Divert je Detection planen",
                               "Sofortschutz empfehlen (rate-limit/block)",
                               "Aktives Anwenden nur mit Oversight"],
    "watcher-traceback": ["Sources korrelieren", "Fingerprints/Sessions sammeln",
                          "Keine erfundenen IPs/Identitäten",
                          "Attribution im Attack-Log ablegen"],
    "watcher-full-run": ["Oversight prüfen", "run_watch ausführen",
                         "Log-IDs zurückgeben", "Summary melden"],
    "attacklog-append": ["Event normalisieren", "Secrets redakten",
                         "In Store schreiben", "Optional Splunk spiegeln"],
    "attacklog-review": ["Events lesen (Limit)", "Nach Typ zählen",
                         "Nach Outcome zählen", "Keine Delete-API nutzen"],
    "attacklog-integrity": ["EVENT_TYPES prüfen", "delete_api=False bestätigen",
                            "Summary erzeugen"],
    "patch-recheck": ["Audit erneut laufen", "Status je Check erfassen",
                      "Abweichungen melden", "Passes als geschlossen markieren"],
    "patch-verify-finding": ["Finding-Key lesen", "verify_closed aufrufen",
                             "Evidence Vorher/Nachher speichern"],
    "ir-triage": ["Signal klassifizieren", "Business-Impact schätzen",
                  "Severity setzen", "On-Call informieren"],
    "ir-containment": ["Betroffene Assets isolieren", "Credentials rotieren (geplant)",
                       "Honeypot-Umleitung prüfen", "Firewall-Regel temporär"],
    "ir-eradication-recovery": ["Root-Cause eingrenzen", "Patches einspielen",
                                "Services wiederherstellen", "Lessons-Learned"],
    "ir-comms": ["Stakeholder-Liste", "Status-Update-Takt",
                 "Externe Meldepflichten", "Keine Secrets in Comms"],
    "backup-inventory": ["Standard-Pfade prüfen", "mtime/Alter berechnen",
                         "Veraltete Backups melden", "Fehlende Locations melden"],
    "backup-restore-drill-plan": ["Ziel-System definieren", "Restore-Fenster wählen",
                                  "Erfolgskriterien festlegen", "Kein Auto-Restore"],
    "net-listen-audit": ["ss/netstat lesen", "Ports extrahieren",
                         "Gegen Risiko-Katalog matchen", "Empfehlungen geben"],
    "net-firewall-status": ["Tool erkennen", "Aktiv-Status lesen",
                            "Default-Deny empfehlen wenn inaktiv"],
    "net-exposure-report": ["Findings aggregieren", "Priorität setzen",
                            "Härtungsmaßnahmen vorschlagen"],
    "web-security-headers": ["HTTP-Response holen", "Header-Katalog prüfen",
                             "Fehlende Header als Finding", "Empfehlungen geben"],
    "web-cookie-flags": ["Set-Cookie lesen", "Flags prüfen", "Lücken melden"],
    "web-tls-basics": ["TLS-Handshake", "Version lesen", "Schwache Protokolle melden"],
    "cred-key-permissions": ["Standard-Pfade scannen", "mode/world-readable prüfen",
                             "Findings ohne Klartext-Secrets", "chmod-Empfehlung"],
    "cred-hygiene-report": ["Treffer zählen", "High-Findings priorisieren",
                            "Remediation-Hinweise bündeln"],
    "sc-manifest-inventory": ["Manifeste finden", "Pakete+Versionen parsen",
                              "Inventar-Finding erzeugen"],
    "sc-osv-audit": ["Pakete mit Version wählen", "OSV abfragen",
                     "CVE-IDs nur aus OSV", "Offline sauber skippen"],
    "sc-remediation-hints": ["fixed-Version aus OSV", "Priorität nach Severity",
                             "Kein automatisches Upgrade"],
    "logging-splunk-status": ["ENV-Status lesen", "configured ja/nein",
                              "Index/Sourcetype melden", "Token nie ausgeben"],
    "logging-event-map": ["Beispiel-Finding mappen", "Felder prüfen",
                          "Ohne Config Skip bestätigen"],
    "logging-forward-smoke": ["send_events aufrufen", "skipped/ok auswerten",
                              "Fehler ehrlich melden"],
    "honeypot-divert-plan": ["Signal klassifizieren", "Decoy wählen",
                             "Umleitungs-Schritte dokumentieren",
                             "Sofortschutz-Empfehlung anhängen"],
    "patch-posture": ["ausstehende Updates lesen", "Paketlisten-Alter",
                      "Reboot-Pflicht", "Auto-Security-Updates"],
    "patch-policy-check": ["unattended-upgrades prüfen", "OS-Release erfassen"],
    "patch-apply": ["Oversight prüfen", "Updates nur mit Freigabe",
                    "Dokumentieren statt blind installieren"],
    "fw-ruleset-audit": ["ufw/nft/iptables Status", "aktive Regeln prüfen"],
    "fw-exposure-review": ["Wildcard-Listener", "Risiko-Ports", "IP-Forwarding"],
    "fw-rule-apply": ["Oversight prüfen", "Default-Deny vorschlagen",
                      "nur mit Freigabe anwenden"],

}


def _tasks_for(pb: dict) -> list[dict]:
    """Baut die Task-Items (mit Default-Status) für ein Playbook."""
    name = pb.get("name", "")
    items = list(pb.get("tasks") or []) or TASK_CATALOG.get(name)
    if not items:
        # Fallback: aus Tools/Beschreibung ableiten (ehrlich, generisch).
        items = [f"{t} ausführen" for t in pb.get("tools", [])] or [pb.get("description", name)]
    return [{"task": t, "status": "offen",
             "oversight": bool(pb.get("oversight_required"))} for t in items]


def build_registry(agents=None, include_blue: bool = True) -> dict:
    if agents is None:
        agents = list(BLUE_AGENTS) if include_blue else []
    soldiers = []
    pb_count = 0
    tool_count = 0
    task_count = 0
    for cls in agents:
        desc = cls.describe()
        clean_pbs = []
        for pb in desc.get("playbooks", []):
            if _scrub(pb.get("name", "")) or _scrub(pb.get("description", "")):
                continue
            pb["tools"] = [t for t in pb.get("tools", []) if not _scrub(t)]
            pb["task_items"] = _tasks_for(pb)
            clean_pbs.append(pb)
            pb_count += 1
            tool_count += len(pb["tools"])
            task_count += len(pb["task_items"])
        desc["playbooks"] = clean_pbs
        # Klar benannter Skill je Soldat (mit seiner Playbook-Liste).
        skill_md = load_skill_md(cls.name)
        desc["skill"] = {
            "name": desc.get("specialty") or desc.get("name"),
            "skill_md": skill_md,
            "has_skill_md": bool(skill_md),
            "summary": desc.get("role", ""),
            "playbooks": [p["name"] for p in clean_pbs],
            "playbook_count": len(clean_pbs),
            "task_count": sum(len(p["task_items"]) for p in clean_pbs),
        }
        try:
            from . import prompts as _prompts
            desc["prompt"] = _prompts.for_soldier(cls.name)
        except Exception:
            desc["prompt"] = {}
        soldiers.append(desc)
    soldiers.sort(key=lambda d: d.get("specialty", d.get("name", "")))

    # Nutzbare externe Tools + Wortlisten am Laufort (keine Secrets).
    try:
        from .tools import kali as _kali
        kali_tools = _kali.tool_status()
    except Exception:
        kali_tools = {}
    try:
        from . import wordlists as _wl
        wl_status = _wl.status()
    except Exception:
        wl_status = {}

    try:
        from . import sdk as _sdk
        plugins_block = _sdk.registry_block()
    except Exception:
        plugins_block = {"plugin_count": 0, "plugins": [], "errors": []}

    return {
        "built_at": time.time(),
        "soldier_count": len(soldiers),
        "playbook_count": pb_count,
        "tool_count": tool_count,
        "task_count": task_count,
        "soldiers": soldiers,
        "kali_tools": kali_tools,
        "wordlists": wl_status,
        "plugins": plugins_block,
        "octogent_phases": OCTOGENT_PHASES,
        "blue_phases": list(BLUE_PHASES),
        "blue_soldier_count": sum(1 for s in soldiers if s.get("colony") == "blue"),
        "scope_suggestions": SCOPE_SUGGESTIONS,
        "prompt_categories": list(__import__("antbb.prompts", fromlist=["PROMPT_TEMPLATES"]).PROMPT_TEMPLATES),
    }


def persist_registry(store, registry: Optional[dict] = None) -> dict:
    registry = registry or build_registry()
    store.replace_capabilities(registry)
    return registry


def get_registry(store) -> dict:
    return store.get_capabilities()
