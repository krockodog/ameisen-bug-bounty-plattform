"""Pflichthinweis / Disclaimer (Regel Null – Scope-Gate)."""

DISCLAIMER_TEXT = (
    "⚠️  RECHTLICHER PFLICHTHINWEIS\n"
    "──────────────────────────────────────────────────────────────\n"
    "Prüfen oder verändern von Systemen OHNE schriftliche oder öffentliche\n"
    "Autorisierung ist strafbar (§ 202a-c StGB in Deutschland, Computer Fraud\n"
    "and Abuse Act / CFAA in den USA).\n"
    "\n"
    "Blue Queen arbeitet standardmäßig lesend am eigenen System oder an Assets,\n"
    "die in der Allowlist stehen (default-deny). Aktive Härtung, Fixes und\n"
    "Honeypot-Starts nur mit Human-Oversight. Kein Brute-Force, keine Last.\n"
    "──────────────────────────────────────────────────────────────"
)

SCOPE_GATE_PROMPT = "Scope-Freigabe vorhanden? [j/N]"


def disclaimer_text() -> str:
    """Gibt den vollständigen Disclaimer-Text zurück."""
    return DISCLAIMER_TEXT


def new_target_notice(target: str) -> str:
    """Pflicht-Hinweis, der bei jedem neuen Ziel ausgegeben wird."""
    return (
        f"⚠️  NEUES ZIEL: {target}\n"
        "Prüfen oder verändern OHNE schriftliche oder öffentliche\n"
        "Autorisierung ist strafbar (§ 202a-c StGB in DE,\n"
        "Computer Fraud and Abuse Act in US).\n"
        f"{SCOPE_GATE_PROMPT}"
    )
