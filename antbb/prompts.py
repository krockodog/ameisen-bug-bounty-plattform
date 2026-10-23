"""Prompt-Vorlagen der Blauen Königin.

Die Königin nutzt sie nur, wenn zur Laufzeit ein Provider konfiguriert ist.
Reiner Text, keine Secrets, keine Schlüssel. Ohne Provider bleiben die
Checks deterministisch.
"""
from __future__ import annotations

PROMPT_TEMPLATES: dict[str, str] = {
    "assess": (
        "Fasse die folgenden lesenden Prüfungen zusammen. Erfinde keine Befunde. "
        "Nenne nur, was in den Daten steht, und ordne die Lücken nach Schwere.\n\n"
        "[CHECKS]\n{checks}"
    ),
    "harden": (
        "Formuliere aus den Härtungs-Lücken konkrete, nachvollziehbare Schritte. "
        "Aktive Änderungen nur als Vorschlag markieren, nicht als bereits ausgeführt.\n\n"
        "[GAPS]\n{gaps}"
    ),
    "defend": (
        "Ordne Beobachtungen Detection-Regeln und geplanten Gegenmaßnahmen zu. "
        "Keine erfundenen Quellen. Umleitungen bleiben ein Plan, bis Oversight sie freigibt.\n\n"
        "[EVENTS]\n{events}"
    ),
    "remediate": (
        "Übersetze jeden Befund in einen Fix-Schritt und sage, woran man danach "
        "erkennt, dass die Lücke zu ist.\n\n[FINDINGS]\n{findings}"
    ),
    "verify": (
        "Vergleiche Vorher und Nachher. „Nachweislich geschlossen“ nur, wenn der "
        "Re-Check den früheren Fehlschlag nicht mehr zeigt.\n\n[EVIDENCE]\n{evidence}"
    ),
    "report": (
        "Schreibe einen kurzen Lagebericht: offene Lücken, geschlossene Punkte, "
        "nächster sinnvoller Schritt. Nur belegte Aussagen.\n\n[FINDINGS]\n{findings}"
    ),
}

#: Welcher Blue-Soldat welche Vorlage primär nutzt. Unbekannte Namen fallen auf assess.
SOLDIER_PROMPT = {
    "blue-swscan": "assess",
    "blue-patchmgmt": "assess",
    "blue-supplychain": "assess",
    "blue-hardening": "harden",
    "blue-fwaudit": "harden",
    "blue-webharden": "harden",
    "blue-tlsposture": "harden",
    "blue-idhygiene": "harden",
    "blue-credhygiene": "harden",
    "blue-watcher": "defend",
    "blue-defense": "defend",
    "blue-honeypot": "defend",
    "blue-logging": "defend",
    "blue-logintegrity": "defend",
    "blue-attacklog": "defend",
    "blue-incident": "defend",
    "blue-netdef": "defend",
    "blue-remediation": "remediate",
    "blue-vulnticket": "remediate",
    "blue-backup": "assess",
    "blue-patchverify": "verify",
    "blue-backupverify": "verify",
    "blue-ticketclose": "verify",
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
    cat = SOLDIER_PROMPT.get(name, "assess")
    return {"category": cat, "template": get(cat)}


def reference_text() -> str:
    return ""
