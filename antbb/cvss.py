"""CVSS v3.1 Base-Score-Rechner (rein lokal, keine Netzwerkzugriffe).

Implementiert die offizielle CVSS-v3.1-Base-Score-Formel (FIRST.org,
Specification Document v3.1). Nur Base-Metriken (AV/AC/PR/UI/S/C/I/A);
Temporal/Environmental sind bewusst nicht enthalten.

Verwendung:
    >>> from antbb import cvss
    >>> r = cvss.score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    >>> r["base_score"], r["severity"]
    (9.8, 'Critical')

Keine Secrets, keine externen Aufrufe – reine Arithmetik.
"""
from __future__ import annotations

import math
from typing import Any, Optional

# ---- Metrik-Gewichte nach CVSS 3.1 Spezifikation --------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
# PR haengt vom Scope ab (U = unchanged, C = changed)
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

#: Pflicht-Metriken der Base-Gruppe (Reihenfolge = kanonischer Vektor).
METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
VALID = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"},
    "UI": set(_UI), "S": {"U", "C"},
    "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}


class CVSSError(ValueError):
    """Ungueltiger CVSS-Vektor oder fehlende/ungueltige Metrik."""


def _roundup(value: float) -> float:
    """Offizielles CVSS-3.1-Roundup (auf 1 Nachkommastelle, immer aufrunden)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_for(score: float) -> str:
    """Qualitatives Severity-Rating nach CVSS 3.1."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def compute_base_score(metrics: dict[str, str]) -> float:
    """Berechnet den Base-Score aus einem Metrik-Dict (Werte-Kuerzel)."""
    m = {k: str(v).upper() for k, v in metrics.items()}
    for key in METRIC_ORDER:
        if key not in m:
            raise CVSSError(f"Metrik {key} fehlt.")
        if m[key] not in VALID[key]:
            raise CVSSError(f"Metrik {key}:{m[key]} ist ungueltig "
                            f"(erlaubt: {sorted(VALID[key])}).")
    scope = m["S"]
    iss = 1.0 - ((1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _PR[scope][m["PR"]] * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    return _roundup(base)


def canonical_vector(metrics: dict[str, str]) -> str:
    """Baut den kanonischen CVSS:3.1-Vektorstring aus einem Metrik-Dict."""
    parts = ["CVSS:3.1"]
    for key in METRIC_ORDER:
        parts.append(f"{key}:{str(metrics[key]).upper()}")
    return "/".join(parts)


def parse_vector(vector: str) -> dict[str, str]:
    """Zerlegt einen CVSS-Vektor in ein Metrik-Dict (nur Base-Metriken)."""
    if not vector or not isinstance(vector, str):
        raise CVSSError("Leerer CVSS-Vektor.")
    tokens = [t for t in vector.strip().split("/") if t]
    if tokens and tokens[0].upper().startswith("CVSS:"):
        ver = tokens[0].split(":", 1)[1]
        if ver not in ("3.1", "3.0"):
            raise CVSSError(f"Nicht unterstuetzte CVSS-Version: {ver} (erwartet 3.1).")
        tokens = tokens[1:]
    out: dict[str, str] = {}
    for tok in tokens:
        if ":" not in tok:
            raise CVSSError(f"Ungueltiges Token '{tok}'.")
        k, v = tok.split(":", 1)
        k = k.strip().upper()
        if k in METRIC_ORDER:
            out[k] = v.strip().upper()
    missing = [k for k in METRIC_ORDER if k not in out]
    if missing:
        raise CVSSError(f"Vektor unvollstaendig, fehlt: {', '.join(missing)}.")
    return out


def score_from_vector(vector: str) -> dict[str, Any]:
    """Komfort: Vektor → {base_score, severity, vector, metrics}."""
    metrics = parse_vector(vector)
    score = compute_base_score(metrics)
    return {
        "base_score": score,
        "severity": severity_for(score),
        "vector": canonical_vector(metrics),
        "metrics": metrics,
    }


def score_from_metrics(metrics: dict[str, str]) -> dict[str, Any]:
    """Komfort: Metrik-Dict → {base_score, severity, vector, metrics}."""
    score = compute_base_score(metrics)
    return {
        "base_score": score,
        "severity": severity_for(score),
        "vector": canonical_vector(metrics),
        "metrics": {k: str(v).upper() for k, v in metrics.items()},
    }
