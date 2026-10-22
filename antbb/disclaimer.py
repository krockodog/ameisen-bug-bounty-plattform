"""Pflichthinweis / Disclaimer (Regel Null – Scope-Gate)."""

DISCLAIMER_TEXT = (
    "⚠️  RECHTLICHER PFLICHTHINWEIS\n"
    "──────────────────────────────────────────────────────────────\n"
    "Pentests und Bug-Bounty-Aktivitäten OHNE schriftliche oder\n"
    "öffentliche Ausschreibung/Autorisierung sind STRAFBAR\n"
    "(§ 202a-c StGB in Deutschland, Computer Fraud and Abuse Act in den USA).\n"
    "\n"
    "Dieses Framework führt rein DEFENSIVE, nicht-destruktive Checks aus\n"
    "(DNS, HTTP-Header, TLS, Sichtbarkeit exponierter Pfade). Es werden\n"
    "KEINE destruktiven Angriffe, kein Brute-Force und keine Last-Erzeugung\n"
    "durchgeführt. Optionale aktive Verifikation (XSS-/SQLi-/Redirect-Nachweis)\n"
    "läuft nur bei ausdrücklicher zusätzlicher Freigabe (--active).\n"
    "Optionales offensives Fuzzing (GET Content-Discovery mit Catch-all-Baseline)\n"
    "läuft nur bei ausdrücklicher zusätzlicher Freigabe (--fuzz).\n"
    "Jede Aktion erfordert einen nachweislich autorisierten Scope\n"
    "(Allowlist, default-deny) und eine manuelle Freigabe (Human-Oversight-Häkchen).\n"
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
        "Pentest und Bug-Bounty OHNE schriftliche oder öffentliche\n"
        "Ausschreibung/Autorisierung sind STRAFBAR (§ 202a-c StGB in DE,\n"
        "Computer Fraud and Abuse Act in US).\n"
        f"{SCOPE_GATE_PROMPT}"
    )
