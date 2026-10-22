"""Unit-Tests fuer den CVSS-v3.1-Rechner (antbb/cvss.py).

Referenz-Vektoren aus der offiziellen CVSS-3.1-Spezifikation / Beispielen.
Lauf: python tests/test_cvss.py  (oder via pytest)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antbb import cvss

# (Vektor, erwarteter Base-Score, erwartete Severity)
REFERENCE = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.5, "High"),
    ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.6, "Medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
]


def test_reference_vectors():
    for vector, exp_score, exp_sev in REFERENCE:
        r = cvss.score_from_vector(vector)
        assert r["base_score"] == exp_score, (
            f"{vector}: {r['base_score']} != {exp_score}")
        assert r["severity"] == exp_sev, (
            f"{vector}: {r['severity']} != {exp_sev}")


def test_from_metrics_roundtrip():
    m = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
         "S": "U", "C": "H", "I": "H", "A": "H"}
    r = cvss.score_from_metrics(m)
    assert r["base_score"] == 9.8
    assert r["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_invalid_vector_raises():
    for bad in ["", "garbage", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:L"]:
        try:
            cvss.score_from_vector(bad)
            raise AssertionError(f"Erwartete CVSSError fuer {bad!r}")
        except cvss.CVSSError:
            pass


if __name__ == "__main__":
    test_reference_vectors()
    test_from_metrics_roundtrip()
    test_invalid_vector_raises()
    print("[test_cvss] OK — alle Referenz-Vektoren + Validierung bestanden.")
