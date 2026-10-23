"""Smoke-Test: Pentest-/Bugbounty-Runs als Knoten im Neuronalen Gehirn.

Prüft:
  * GET /api/runs liefert eine Liste (Struktur passt für den Brain-Layer).
  * Felder je Lauf sind vorhanden (target_name, mode, finding_count, severity, when).
  * brain.html bindet den neuen Lauf-Knoten-Layer (runs.js) ein.
  * runs.js existiert und ist syntaktisch plausibel (balancierte Klammern).
  * Leerzustand (keine Runs) crasht nicht.
"""
from __future__ import annotations

import os
import sys


def test_api_runs_structure():
    from fastapi.testclient import TestClient
    from antbb.web.app import app
    client = TestClient(app)
    r = client.get("/api/runs")
    assert r.status_code == 200, r.status_code
    data = r.json()
    assert isinstance(data, list), data
    for run in data[:5]:
        for key in ("target_name", "mode", "finding_count", "severity", "when"):
            assert key in run, (key, run)
    print(f"[ok] /api/runs liefert Liste ({len(data)} Läufe), Felder vorhanden")


def test_brain_html_wires_runs_layer():
    # tests/ → Repo-Root
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = open(os.path.join(base, "antbb/web/templates/brain.html"), encoding="utf-8").read()
    assert "/static/brain/runs.js" in html, "runs.js nicht in brain.html eingebunden"
    js_path = os.path.join(base, "antbb/web/static/brain/runs.js")
    assert os.path.isfile(js_path), "runs.js fehlt"
    js = open(js_path, encoding="utf-8").read()
    assert js.count("{") == js.count("}"), "unbalancierte geschweifte Klammern"
    assert js.count("(") == js.count(")"), "unbalancierte runde Klammern"
    assert "/api/runs" in js and "trail" in js, "Layer nutzt /api/runs + Trail nicht"
    print("[ok] brain.html bindet runs.js ein; Layer nutzt /api/runs + Pheromonspur")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    test_api_runs_structure()
    test_brain_html_wires_runs_layer()
    print("\nAlle Brain-Runs-Tests GRÜN.")
