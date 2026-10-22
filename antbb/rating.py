"""Neutrales Sicherheits-Rating + Risiko-Heatmap (deterministisch, nachvollziehbar).

Leitet aus der proofgate-bereinigten Findingliste einen neutralen Gesamt-Score
(0–100 + Schulnote A–F) samt Teilscores ab. Dieselbe Gewichtung wird für die
Risiko-Heatmap genutzt, damit beide konsistent sind.

Formel (dokumentiert, deterministisch):
  Risikobeitrag eines Findings = SEV_WEIGHT[severity] * STATUS_MULT[status]
    * VERIFIZIERT/BESTÄTIGT zählen voll bzw. fast voll, Verdachtsstufen
      reduziert, REFERENZ am geringsten.
    * Catch-all/false_positive zählen NICHT (werden vorher ausgefiltert).
  Gesamt-Risikopunkte R = Σ Risikobeiträge (nur gezählte Findings).
  Score = round(max(0, 100 - R)), Note über feste Schwellen.
Keine Severity-Inflation: die Gewichte sind fix; nichts wird „hochgestuft".

Zusätzlich eine kurze, klar gekennzeichnete KI-Einschätzung (LLM, falls
verfügbar; sonst deterministische, regelbasierte Zusammenfassung) – sauber
getrennt von den verifizierten Einzelbefunden.
"""
from __future__ import annotations

from typing import Optional

from . import proofgate as _pg
from .agents.base import (
    AgentFinding, STATUS_VERIFIED, STATUS_PASSIVE, STATUS_TO_CONFIRM,
    STATUS_CONDITIONAL, STATUS_REFERENCE,
)

# --- Gewichte (Single Source of Truth für Rating UND Heatmap) ---
SEV_WEIGHT = {"critical": 40.0, "high": 20.0, "medium": 8.0, "low": 3.0, "info": 0.5}
STATUS_MULT = {
    STATUS_VERIFIED: 1.0,
    STATUS_PASSIVE: 0.9,
    STATUS_TO_CONFIRM: 0.5,
    STATUS_CONDITIONAL: 0.4,
    STATUS_REFERENCE: 0.25,
    "": 0.5,
}

SEVERITIES = ("info", "low", "medium", "high", "critical")

# --- Dimensionen (Teilscores + Heatmap-Achse 1) ---
DIMENSIONS = ("TLS/Transport", "Header/Config", "Auth", "Exposition",
              "Secrets", "Web-Vuln", "Netz")

_CATEGORY_DIMENSION = {
    # TLS/Transport
    "tls": "TLS/Transport", "tls-cert": "TLS/Transport", "tls-scan": "TLS/Transport",
    # Header/Config
    "misconfig": "Header/Config", "csp-analysis": "Header/Config",
    "permissions-policy": "Header/Config", "cookie-flags": "Header/Config",
    "security-txt": "Header/Config", "dns-email-auth": "Header/Config",
    "dns-caa": "Header/Config", "fingerprint": "Header/Config",
    "whatweb-fingerprint": "Header/Config", "wafw00f": "Header/Config",
    "version-disclosure": "Header/Config",
    # Auth
    "missing-auth": "Auth", "cors-misconfig": "Auth", "cors-passive": "Auth",
    "llm-prompt-injection-indicator": "Auth",
    # Exposition
    "exposed-artifact": "Exposition", "info-disclosure": "Exposition",
    "api-surface": "Exposition", "storage-exposure": "Exposition",
    "content-discovery": "Exposition", "fuzz-discovery": "Exposition",
    "fuzz-param-reflection": "Exposition",
    # Secrets
    "secret-exposure": "Secrets",
    # Web-Vuln
    "xss-verified": "Web-Vuln", "xss-indicator": "Web-Vuln",
    "sqli-verified": "Web-Vuln", "sqli-indicator": "Web-Vuln",
    "open-redirect": "Web-Vuln", "path-traversal": "Web-Vuln",
    "nuclei-finding": "Web-Vuln", "nikto-finding": "Web-Vuln",
    # Netz
    "recon-ports": "Netz", "nmap-service": "Netz", "recon-dns": "Netz",
    "recon-subdomain": "Netz", "msf-aux-finding": "Netz",
    "threat-intel-cve": "Netz", "cve-reference": "Netz",
}


def dimension_for(category: str) -> str:
    return _CATEGORY_DIMENSION.get(category, "Header/Config")


def grade_for(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    if score >= 50: return "E"
    return "F"


def risk_contribution(f: AgentFinding) -> float:
    sev = SEV_WEIGHT.get(f.severity, 0.5)
    mult = STATUS_MULT.get(f.status, 0.5)
    return sev * mult


def _as_findings(rows) -> list[AgentFinding]:
    """Store-Rows → AgentFinding (für proofgate-Konsistenz)."""
    from .findingreport import parse_evidence, _g
    out = []
    for r in rows:
        out.append(AgentFinding(
            agent=_g(r, "agent", ""), title=_g(r, "title", ""),
            category=_g(r, "category", ""), severity=_g(r, "severity", "info"),
            asset=_g(r, "asset", ""), description=_g(r, "description", ""),
            evidence=parse_evidence(r), status=_g(r, "status", ""),
            false_positive=bool(_g(r, "false_positive", 0)),
        ))
    return out


def compute_rating(findings: list[AgentFinding]) -> dict:
    """Berechnet Gesamt- und Teilscores aus einer Findingliste (proofgate-bereinigt)."""
    _pg.enforce(findings, None)
    counted = _pg.counted_findings(findings)

    total_risk = sum(risk_contribution(f) for f in counted)
    score = round(max(0.0, 100.0 - total_risk), 1)

    # Teilscores je Dimension.
    sub: dict[str, dict] = {}
    for dim in DIMENSIONS:
        subset = [f for f in counted if dimension_for(f.category) == dim]
        rsk = sum(risk_contribution(f) for f in subset)
        s = round(max(0.0, 100.0 - rsk), 1)
        sub[dim] = {"score": s, "grade": grade_for(s), "count": len(subset),
                    "risk_points": round(rsk, 2)}

    by_sev = _pg.severity_counts(findings)
    by_status = _pg.status_counts(findings)
    verified = [f for f in counted if f.status == STATUS_VERIFIED]

    return {
        "score": score,
        "grade": grade_for(score),
        "risk_points": round(total_risk, 2),
        "counted_findings": len(counted),
        "verified_count": len(verified),
        "severity_counts": by_sev,
        "status_counts": by_status,
        "subscores": sub,
        "weights": {"severity": SEV_WEIGHT, "status": STATUS_MULT},
        "formula": ("score = max(0, 100 - Σ(SEV_WEIGHT[sev]*STATUS_MULT[status])); "
                    "nur gezählte Findings (ohne Catch-all/False-Positive)."),
    }


# ---------------------------------------------------------------------------
# KI-Einschätzung (klar gekennzeichnet; LLM optional, sonst regelbasiert).
# ---------------------------------------------------------------------------
def _rule_based_summary(rating: dict) -> str:
    score = rating["score"]
    grade = rating["grade"]
    bysev = rating["severity_counts"]
    crit = bysev.get("critical", 0) + bysev.get("high", 0)
    vcount = rating["verified_count"]
    weak_dims = sorted(
        rating["subscores"].items(), key=lambda kv: kv[1]["score"])[:2]
    weak = ", ".join(f"{d} ({v['grade']})" for d, v in weak_dims if v["count"])
    tone = ("solide" if score >= 80 else "mittelmäßig" if score >= 60
            else "schwach" if score >= 40 else "kritisch")
    parts = [
        f"Gesamtbewertung {grade} ({score}/100) – die Sicherheitslage wirkt {tone}.",
        (f"{crit} Befund(e) hoher/kritischer Schwere" if crit else
         "keine Befunde hoher/kritischer Schwere"),
        f"davon {vcount} aktiv verifiziert.",
    ]
    if weak:
        parts.append(f"Schwächste Bereiche: {weak}.")
    parts.append("Dies ist eine neutrale, aus den Befunden abgeleitete Einschätzung, "
                 "keine Garantie; nur VERIFIZIERT ist aktiv belegt.")
    return " ".join(parts)


def ai_assessment(rating: dict, llm=None) -> dict:
    """Kurze neutrale Einschätzung. Nutzt LLM wenn verfügbar, sonst Regelbasis."""
    if llm is not None and getattr(llm, "configured", False):
        try:
            prompt = (
                "Du bist ein neutraler Security-Gutachter. Bewerte in 2-3 Sätzen "
                "sachlich, wie sicher die Website basierend auf diesen aggregierten "
                "Kennzahlen wirkt. Keine Übertreibung, keine erfundenen Befunde. "
                f"Score={rating['score']}/100 Note={rating['grade']}, "
                f"Severity={rating['severity_counts']}, Status={rating['status_counts']}, "
                f"Teilscores={{d: v['grade'] for d, v in rating['subscores'].items()}}."
            )
            r = llm.chat([
                {"role": "system", "content": "Antworte knapp, neutral, auf Deutsch."},
                {"role": "user", "content": prompt},
            ], max_tokens=220)
            if getattr(r, "ok", False) and r.content.strip():
                return {"text": r.content.strip(), "source": f"KI ({r.provider}/{r.model})",
                        "disclaimer": "KI-Einschätzung, keine Garantie."}
        except Exception:
            pass
    return {"text": _rule_based_summary(rating), "source": "regelbasiert",
            "disclaimer": "KI-Einschätzung, keine Garantie."}


def rating_for_target(store, target_id: int, llm=None, with_ai: bool = True) -> dict:
    rows = store.list_findings(target_id)
    findings = _as_findings(rows)
    rating = compute_rating(findings)
    if with_ai:
        rating["assessment"] = ai_assessment(rating, llm=llm)
    rating["heatmap"] = build_heatmap(findings)
    return rating


# ===========================================================================
# Risiko-Heatmap (Achse1 = Dimension, Achse2 = Severity; Intensität = Risiko).
# ===========================================================================
def build_heatmap(findings: list[AgentFinding]) -> dict:
    """Baut die Risiko-Matrix Dimension × Severity aus echten Findings.

    Zelle = {count, risk}. Intensität 0..1 = risk / max_cell_risk (konsistent
    zur rating.py-Gewichtung). Zusätzlich eine Dimension × Status-Matrix.
    """
    _pg.enforce(findings, None)
    counted = _pg.counted_findings(findings)

    # Dimension × Severity
    sev_matrix = {d: {s: {"count": 0, "risk": 0.0} for s in SEVERITIES}
                  for d in DIMENSIONS}
    # Dimension × Status
    statuses = (STATUS_VERIFIED, STATUS_PASSIVE, STATUS_TO_CONFIRM,
                STATUS_CONDITIONAL, STATUS_REFERENCE)
    status_matrix = {d: {st: {"count": 0, "risk": 0.0} for st in statuses}
                     for d in DIMENSIONS}

    max_risk = 0.0
    for f in counted:
        dim = dimension_for(f.category)
        rc = risk_contribution(f)
        sev = f.severity if f.severity in SEVERITIES else "info"
        cell = sev_matrix[dim][sev]
        cell["count"] += 1
        cell["risk"] = round(cell["risk"] + rc, 2)
        max_risk = max(max_risk, cell["risk"])
        st = f.status if f.status in statuses else STATUS_TO_CONFIRM
        scell = status_matrix[dim][st]
        scell["count"] += 1
        scell["risk"] = round(scell["risk"] + rc, 2)

    def _intensity(cells):
        for row in cells.values():
            for c in row.values():
                c["intensity"] = round(c["risk"] / max_risk, 3) if max_risk > 0 else 0.0

    _intensity(sev_matrix)
    _intensity(status_matrix)

    # Zeilen-/Spaltensummen (für Anzeige).
    row_totals = {d: round(sum(sev_matrix[d][s]["risk"] for s in SEVERITIES), 2)
                  for d in DIMENSIONS}
    col_totals = {s: round(sum(sev_matrix[d][s]["risk"] for d in DIMENSIONS), 2)
                  for s in SEVERITIES}

    return {
        "dimensions": list(DIMENSIONS),
        "severities": list(SEVERITIES),
        "statuses": list(statuses),
        "severity_matrix": sev_matrix,
        "status_matrix": status_matrix,
        "max_cell_risk": round(max_risk, 2),
        "row_totals": row_totals,
        "col_totals": col_totals,
        "total_cells": len(counted),
        "note": "Intensität = Zellen-Risiko / max. Zellen-Risiko (rating.py-Gewichtung).",
    }


def heatmap_for_target(store, target_id: int) -> dict:
    return build_heatmap(_as_findings(store.list_findings(target_id)))


def heatmap_markdown(heatmap: dict) -> str:
    """Kompakte Text-/ASCII-Tabelle Dimension × Severity (Zahlen) für MD/PDF."""
    dims = heatmap.get("dimensions", [])
    sevs = heatmap.get("severities", [])
    sm = heatmap.get("severity_matrix", {})
    if not dims or heatmap.get("total_cells", 0) == 0:
        return "_Keine zählbaren Befunde – keine Heatmap (ehrlicher Leerzustand)._"
    hdr = ["Dimension \\ Severity"] + [s.capitalize() for s in sevs] + ["Σ Risiko"]
    L = ["| " + " | ".join(hdr) + " |",
         "|" + "|".join(["---"] * len(hdr)) + "|"]
    for d in dims:
        row = [d]
        for s in sevs:
            cell = sm.get(d, {}).get(s, {})
            cnt = cell.get("count", 0)
            row.append(str(cnt) if cnt else "·")
        row.append(str(heatmap.get("row_totals", {}).get(d, 0)))
        L.append("| " + " | ".join(row) + " |")
    L.append("")
    L.append(f"_Max. Zellen-Risiko: {heatmap.get('max_cell_risk', 0)} · "
             f"Zahl = Anzahl Befunde, Σ = Risikobeitrag (rating.py-Gewichtung)._")
    return "\n".join(L)
