"""Smoke-Test: Zeitraffer-Player für echte Läufe im Neuronalen Gehirn."""
from __future__ import annotations

import os
import sys
import time


def test_timeline_404():
    from fastapi.testclient import TestClient
    from antbb.web.app import app
    c = TestClient(app)
    r = c.get("/api/runs/999999/timeline")
    assert r.status_code == 404, r.status_code
    print("[ok] unbekannter Lauf → 404")


def test_timeline_with_synthetic_run():
    """Legt einen echten Run + Findings an und prüft die Timeline-Struktur."""
    from fastapi.testclient import TestClient
    from antbb.web.app import app, svc
    store = svc.store
    # Target anlegen
    tid = store.add_target("tl-test-target", "Zeitraffer-Smoke")
    rid = "tl-smoke-" + str(int(time.time()))
    t0 = time.time() - 30
    t1 = time.time()
    hid = store.add_run_history(
        run_id=rid, target_id=tid, target_name="tl-test-target",
        mode="defensive", status="done", finding_count=2,
        severity={"medium": 1, "low": 1},
        started_at=t0, finished_at=t1, duration=t1 - t0,
    )
    store.create_scan_run(rid, tid, phases=["recon", "analyze"], status="done")
    store.add_scan_step(rid, kind="phase", phase="recon", agent="recon",
                        payload={"message": "Recon gestartet"})
    store.add_scan_step(rid, kind="finding", phase="analyze", agent="scanning",
                        payload={"title": "Offenes Admin-Panel", "severity": "medium"})
    store.add_finding(tid, rid, "scanning", "Offenes Admin-Panel", "web",
                      "medium", asset="https://example.test/admin",
                      description="Smoke", evidence={})
    store.add_finding(tid, rid, "wifi", "Offenes Gast-WLAN", "wlan",
                      "low", asset="aa:bb:cc:dd:ee:ff",
                      description="Smoke-WLAN", evidence={})

    c = TestClient(app)
    r = c.get(f"/api/runs/{hid}/timeline")
    assert r.status_code == 200, r.status_code
    data = r.json()
    assert data.get("ok") is True, data
    run = data["run"]
    assert run["target_name"] == "tl-test-target"
    assert run["type"] in ("pentest", "bugbounty", "wlan"), run["type"]
    # wifi-Finding → Typ wlan
    assert run["type"] == "wlan", run
    events = data["events"]
    assert len(events) >= 3, events  # start + steps/findings + end
    kinds = {e["kind"] for e in events}
    assert "start" in kinds and "end" in kinds, kinds
    # chronologisch
    ts = [e["t"] for e in events]
    assert ts == sorted(ts), ts
    print(f"[ok] Timeline: type={run['type']}, {len(events)} Events, chronologisch")

    # Auch per run_id-String erreichbar
    r2 = c.get(f"/api/runs/{rid}/timeline")
    assert r2.status_code == 200 and r2.json().get("ok")
    print("[ok] Timeline auch per run_id-String")


def test_player_wired():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(base, "antbb/web/static/brain/runs.js"), encoding="utf-8").read()
    assert "brain-tl-bar" in js and "/timeline" in js
    assert "Zeitraffer" in js and "player.speed" in js
    assert js.count("{") == js.count("}")
    print("[ok] runs.js enthält Zeitraffer-Player (Play/Speed/Timeline)")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    test_timeline_404()
    test_timeline_with_synthetic_run()
    test_player_wired()
    print("\nAlle Zeitraffer-Tests GRÜN.")
