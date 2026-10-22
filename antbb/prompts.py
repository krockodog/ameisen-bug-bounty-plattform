"""AI-Prompt-Bibliothek (aus den Octogent AI-Prompt-Templates abgeleitet).

Stellt wiederverwendbare Prompt-Vorlagen je Phase bereit (Recon, Vuln-Analyse,
Exploit-Entscheidung, Reporting, MITRE-Mapping), die der jeweilige Soldat bzw.
der LLM-Connector (antbb/llm.py, antbb/router.py) nutzen kann. Reiner Text,
keine Secrets. Quelle: Octogent 'AI Prompt Templates' (reference/ai_prompt_templates.md).
"""
from __future__ import annotations

import os

_SKILLS_DIR = os.path.join(os.path.dirname(__file__), "agents", "skills")
_REF = os.path.join(_SKILLS_DIR, "reference", "ai_prompt_templates.md")

PROMPT_TEMPLATES: dict[str, str] = {
    "recon": (
        "Analysiere die folgenden Recon-Daten und bestimme die Angriffsfläche. "
        "Bewerte je Fund die Kritikalität (Kritisch/Hoch/Mittel/Niedrig) und "
        "schlage nächste Recon-Schritte vor.\n\n[RECON DATA]\n{recon_output}\n\n"
        "Format: 1) Zusammenfassung (3 Punkte) 2) Angriffsflächen-Tabelle "
        "(Service|Port|Version|Risiko|Nächster Schritt) 3) Priorisierte Ziele."
    ),
    "vuln": (
        "Bewerte und priorisiere die folgenden Schwachstellen-Scan-Ergebnisse "
        "zusammen mit der Asset-Kritikalität. Gib eine priorisierte Liste mit "
        "CVSS + Business-Impact aus. Keine erfundenen Befunde; nur Belegtes.\n\n"
        "[SCAN OUTPUT]\n{scan_output}"
    ),
    "exploit": (
        "Auf Basis des Service-Fingerprints: welche nicht-destruktive, "
        "autorisierte Verifikation ist angemessen? Dokumentiere ausdrücklich, "
        "ob ein Ergebnis Proof-of-Concept oder voller Kompromiss wäre. KEINE "
        "destruktiven Schritte, keine Persistenz/Lateral Movement automatisch.\n\n"
        "[FINGERPRINT]\n{fingerprint}"
    ),
    "report": (
        "Erzeuge aus den verifizierten Befunden einen strukturierten Bericht: "
        "Executive Summary, technische Findings (Schwachstelle, Evidence, "
        "Remediation), Angriffspfad-Narrativ, MITRE-ATT&CK-Mapping, "
        "Remediation-Roadmap. Nur VERIFIZIERT ist bewiesen.\n\n[FINDINGS]\n{findings}"
    ),
    "mitre": (
        "Ordne die folgenden Aktivitäten/Befunde den passenden MITRE-ATT&CK-"
        "Taktiken und -Techniken zu (ID + Name). Keine Spekulation ohne Beleg.\n\n"
        "[ACTIVITIES]\n{activities}"
    ),
}

#: Welcher Soldat nutzt welche Prompt-Kategorie primär.
SOLDIER_PROMPT = {
    "recon": "recon", "osint": "recon", "infra": "recon", "scanning": "vuln",
    "api": "vuln", "fuzz": "vuln", "llmsec": "vuln", "cloud": "vuln",
    "auth": "vuln", "verify": "exploit", "poc": "exploit", "analysis": "mitre",
    "threatintel": "mitre", "reporting": "report", "mobile": "vuln",
}


def get(category: str) -> str:
    return PROMPT_TEMPLATES.get(category, "")


def render(category: str, **kw) -> str:
    tpl = get(category)
    try:
        return tpl.format(**kw)
    except Exception:
        return tpl


def for_soldier(name: str) -> dict:
    cat = SOLDIER_PROMPT.get(name, "vuln")
    return {"category": cat, "template": get(cat)}


def reference_text() -> str:
    try:
        with open(_REF, encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""
