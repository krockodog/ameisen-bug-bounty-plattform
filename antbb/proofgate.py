"""Harter Proof-Gate + Zähl-Logik (Single Source of Truth).

Regeln:
  * Ein Finding darf NUR dann `VERIFIZIERT` sein, wenn es konkrete AKTIVE
    Evidence trägt (Request + Response-Nachweis aus DIESEM Lauf). Fehlt der
    Nachweis, wird es automatisch auf `ZU BESTÄTIGEN` herabgestuft (nie still
    behaupten). Der Vorgang wird protokolliert.
  * Catch-all-/Baseline-Treffer werden als potenzielle False-Positives markiert
    und aus den Zählungen ausgeschlossen.
  * Severity-Zählungen werden IMMER aus der Finding-Liste berechnet, damit
    Tallies nicht widersprechen können.
"""
from __future__ import annotations

from typing import Iterable

from .agents.base import (
    AgentFinding, STATUS_VERIFIED, STATUS_PASSIVE, STATUS_TO_CONFIRM,
    STATUS_CONDITIONAL, STATUS_REFERENCE, ALL_STATUSES,
)

# Default-Beweis-Stufe pro Finding-Kategorie (greift nur, wenn ein Agent kein
# explizites status-Label gesetzt hat). Single Source of Truth für die Labels.
DEFAULT_STATUS_BY_CATEGORY = {
    # AKTIV verifiziert (tragen Request+Response-Evidence):
    "xss-verified": STATUS_VERIFIED,
    "sqli-verified": STATUS_VERIFIED,
    "open-redirect": STATUS_VERIFIED,
    "path-traversal": STATUS_VERIFIED,
    "exposed-artifact": STATUS_VERIFIED,
    "cors-misconfig": STATUS_VERIFIED,
    "missing-auth": STATUS_VERIFIED,
    "ssrf-verified": STATUS_VERIFIED,
    "subdomain-takeover": STATUS_VERIFIED,
    # Passiv/direkt beobachtet:
    "recon-dns": STATUS_PASSIVE,
    "recon-subdomain": STATUS_PASSIVE,
    "recon-ports": STATUS_PASSIVE,
    "fingerprint": STATUS_PASSIVE,
    "misconfig": STATUS_PASSIVE,
    "info-disclosure": STATUS_PASSIVE,
    "tls": STATUS_PASSIVE,
    "tls-cert": STATUS_PASSIVE,
    "api-surface": STATUS_PASSIVE,
    "cookie-flags": STATUS_PASSIVE,
    "csp-analysis": STATUS_PASSIVE,
    "permissions-policy": STATUS_PASSIVE,
    "security-txt": STATUS_PASSIVE,
    "cors-passive": STATUS_PASSIVE,
    "storage-exposure": STATUS_PASSIVE,
    "dns-email-auth": STATUS_PASSIVE,
    "dns-caa": STATUS_PASSIVE,
    # Abgeleitet / Indikator / versionsbasiert -> noch zu bestätigen:
    "xss-indicator": STATUS_TO_CONFIRM,
    "sqli-indicator": STATUS_TO_CONFIRM,
    "ssrf-indicator": STATUS_TO_CONFIRM,
    "fuzz-discovery": STATUS_TO_CONFIRM,
    "fuzz-param-reflection": STATUS_TO_CONFIRM,
    "version-disclosure": STATUS_TO_CONFIRM,
    "llm-prompt-injection-indicator": STATUS_TO_CONFIRM,
    # Fremd-CVE / Muster:
    "threat-intel-cve": STATUS_REFERENCE,
    "cve-reference": STATUS_REFERENCE,
}

#: Meta-/Hilfs-Kategorien ohne Vulnerability-Charakter -> kein Status-Label.
_META_CATEGORIES = frozenset({
    "report-summary", "llm-report", "analysis-cvss", "correlation",
    "llm-analysis", "poc", "proofgate-validation",
})


def default_status_for(category: str) -> str:
    if category in _META_CATEGORIES:
        return ""
    return DEFAULT_STATUS_BY_CATEGORY.get(category, STATUS_TO_CONFIRM)

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _is_catchall_artifact(f: AgentFinding) -> bool:
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    if f.false_positive:
        return True
    return bool(ev.get("catch_all_suspect") or ev.get("baseline_artifact"))


def enforce(findings: Iterable[AgentFinding], logger=None) -> dict:
    """Erzwingt den Proof-Gate IN-PLACE und liefert einen Validierungs-Report.

    Rückgabe:
      {
        "downgraded": [titel, ...],   # VERIFIZIERT ohne Evidence -> ZU BESTÄTIGEN
        "flagged_false_positive": [...],
        "violations": [...],          # (sollte nach enforce leer sein)
        "ok": bool,
      }
    """
    downgraded: list[str] = []
    flagged: list[str] = []
    violations: list[str] = []

    for f in findings:
        # Fehlendes Label aus der Kategorie ableiten (Single Source of Truth).
        if not f.status:
            f.status = default_status_for(f.category)
        # Status normalisieren: unbekannte Labels defensiv behandeln.
        if f.status and f.status not in ALL_STATUSES:
            # unbekanntes Label -> konservativ "zu bestätigen"
            f.status = STATUS_TO_CONFIRM

        # Catch-all-/Baseline-Artefakt?
        if _is_catchall_artifact(f):
            f.false_positive = True
            flagged.append(f.title)

        # HARTE Regel: VERIFIZIERT nur mit aktiver Evidence.
        if f.status == STATUS_VERIFIED and not f.has_active_evidence():
            if logger:
                logger.warning(
                    "[proofgate] ⚠️ '%s' war VERIFIZIERT ohne aktive Evidence "
                    "→ herabgestuft auf ZU BESTÄTIGEN.", f.title)
            f.status = STATUS_TO_CONFIRM
            if isinstance(f.evidence, dict):
                f.evidence["proofgate_downgraded"] = True
                f.evidence["proofgate_reason"] = (
                    "Keine aktive Evidence (Request+Response) in diesem Lauf erfasst."
                )
            downgraded.append(f.title)

    # Nach dem Erzwingen darf es keine Verletzung mehr geben.
    for f in findings:
        if f.status == STATUS_VERIFIED and not f.has_active_evidence():
            violations.append(f.title)

    return {
        "downgraded": downgraded,
        "flagged_false_positive": flagged,
        "violations": violations,
        "ok": not violations,
    }


def counted_findings(findings: Iterable[AgentFinding]) -> list[AgentFinding]:
    """Findings, die in die Zählung eingehen.

    Ausgeschlossen werden (a) Catch-all-/Baseline-False-Positives und (b) Meta-/
    Aggregat-Findings (Report-Zusammenfassung, CVSS-Vorschlag, Korrelation, PoC,
    Proof-Gate-Validierung) – sie sind keine eigenständigen Schwachstellen und
    würden die Severity-Zählung sonst aufblähen bzw. doppelt zählen. So stimmen
    alle Zähl-Oberflächen überein (Single Source of Truth)."""
    return [f for f in findings
            if not f.false_positive and f.category not in _META_CATEGORIES]


def severity_counts(findings: Iterable[AgentFinding]) -> dict:
    """Severity-Verteilung aus der Finding-Liste (ohne False-Positives)."""
    out = {k: 0 for k in _SEV_ORDER}
    for f in counted_findings(findings):
        out[f.severity] = out.get(f.severity, 0) + 1
    return {k: v for k, v in out.items() if v or k in _SEV_ORDER}


def status_counts(findings: Iterable[AgentFinding]) -> dict:
    """Verteilung nach Beweis-Stufe (ohne False-Positives)."""
    out: dict[str, int] = {}
    for f in counted_findings(findings):
        label = f.status or "OHNE-STATUS"
        out[label] = out.get(label, 0) + 1
    return out
