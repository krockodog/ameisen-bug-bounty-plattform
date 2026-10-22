"""Integrations-Smoke-Test der neuen Web-Features ueber den FastAPI-TestClient.

Prueft (Auth standardmaessig AUS):
  * WebSocket /ws/feed liefert sofort den Backlog/Startzustand (echter Push).
  * /api/cvss rechnet korrekt (Referenz 9.8).
  * /api/assets + default-deny (Check ohne Ownership-Bestaetigung -> 403).
  * /api/runs + /api/exports antworten.
  * HTML-Seiten /, /assets, /history liefern 200.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANTBB_NO_LLM"] = "1"
os.environ.pop("ANTBB_AUTH", None)  # Auth AUS fuer diesen Test
os.environ["ANTBB_DB"] = "/tmp/antbb_test_web.db"
if os.path.exists("/tmp/antbb_test_web.db"):
    os.remove("/tmp/antbb_test_web.db")

from fastapi.testclient import TestClient
from antbb.web.app import app


def run():
    with TestClient(app) as client:
        # --- HTML-Seiten ---
        for path in ["/", "/assets", "/history", "/brain"]:
            r = client.get(path)
            assert r.status_code == 200, f"{path} -> {r.status_code}"

        # --- CVSS ---
        r = client.get("/api/cvss?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.status_code == 200
        assert r.json()["base_score"] == 9.8
        assert r.json()["severity"] == "Critical"
        r = client.get("/api/cvss?AV=N&AC=L&PR=N&UI=R&S=C&C=L&I=L&A=N")
        assert r.json()["base_score"] == 6.1
        # ungueltig -> 400
        assert client.get("/api/cvss?vector=bad").status_code == 400

        # --- Assets default-deny ---
        r = client.post("/api/assets", json={"host": "deny.example", "confirm_owner": False})
        aid = r.json()["id"]
        r = client.post(f"/api/assets/{aid}/check", json={"kind": "tls"})
        assert r.status_code == 403, f"default-deny erwartet 403, war {r.status_code}"

        # --- Runs / Exports ---
        assert client.get("/api/runs").status_code == 200
        assert client.get("/api/exports").status_code == 200

        # --- WebSocket-Feed: Backlog/Startzustand ---
        with client.websocket_connect("/ws/feed") as ws:
            data = ws.receive_json()
            assert data.get("backlog") is True
            assert "scan" in data and "events" in data

    print("[test_web_features] OK — WS-Feed, CVSS, Assets-default-deny, Runs/Exports, Seiten.")


if __name__ == "__main__":
    run()
