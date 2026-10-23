"""Smoke-Test für die WLAN-Coverage-Heatmap (verortete passive RSSI-Messung).

Komplett lokal, ohne WLAN-Hardware: prüft Store-Tabelle wlan_heatmap_samples,
Service-Aggregation/Qualität, Grundriss-Persistenz und die Web-Routen
(POST sample, GET heatmap-Struktur, honest-empty ohne Samples, Grundriss).
"""
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_heatmap_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
os.environ.pop("ANTBB_WIFI", None)
if os.path.exists("/tmp/antbb_heatmap_smoke.db"):
    os.remove("/tmp/antbb_heatmap_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from antbb.service import AntBBService

banner("TEST A: Service-Aggregation + Qualität (honest-empty zuerst)")
svc = AntBBService()
tid = svc.add_target("heatmap-smoke", "Heatmap-Test")
empty = svc.wlan_heatmap_data(target_id=tid)
check("leer → valide Struktur, keine erfundenen Punkte",
      empty["point_count"] == 0 and empty["sample_count"] == 0 and empty["aps"] == [])
check("Qualitäts-Regeln", svc._rssi_quality(-50) == "gut" and svc._rssi_quality(-60) == "ok"
      and svc._rssi_quality(-72) == "schwach" and svc._rssi_quality(-85) == "funkloch"
      and svc._rssi_quality(None) == "none")

banner("TEST B: Sample aufnehmen + aggregieren")
own = ["aa:bb:cc:00:00:01"]
n1 = svc.wlan_heatmap_add_sample(0.2, 0.3, {"aa:bb:cc:00:00:01": -48, "de:ad:be:ef:00:99": -82},
    ort="Wohnzimmer", target_id=tid, own_bssids=own,
    ap_meta={"aa:bb:cc:00:00:01": {"ssid": "FritzBox-A", "channel": 1, "band": "2.4"}})
check("2 Messwerte gespeichert", n1 == 2)
n2 = svc.wlan_heatmap_add_sample(0.8, 0.7, {"aa:bb:cc:00:00:01": -86},
    ort="Keller", target_id=tid, own_bssids=own)
check("1 Messwert gespeichert", n2 == 1)
d = svc.wlan_heatmap_data(target_id=tid)
check("2 Punkte / 3 Samples", d["point_count"] == 2 and d["sample_count"] == 3)
wz = next(p for p in d["points"] if p["ort"] == "Wohnzimmer")
check("Wohnzimmer bestes Signal -48 = gut", wz["best_rssi"] == -48 and wz["quality"] == "gut")
kel = next(p for p in d["points"] if p["ort"] == "Keller")
check("Keller -86 = funkloch", kel["best_rssi"] == -86 and kel["quality"] == "funkloch")
check("AP-Liste mit SSID + eigen-Tag", any(a["ssid"] == "FritzBox-A" and a["is_own"] for a in d["aps"]))
check("x/y normalisiert erhalten", abs(wz["x"] - 0.2) < 1e-6 and abs(wz["y"] - 0.3) < 1e-6)

banner("TEST C: ungültige Koordinaten/Leersamples werden sauber abgelehnt")
try:
    svc.wlan_heatmap_add_sample("nan", 0.5, {"x": -50}, target_id=tid); bad = False
except ValueError:
    bad = True
check("x='nan' → ValueError", bad)

banner("TEST D: Grundriss-Persistenz (data-URL)")
DATA_URL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
svc.wlan_heatmap_set_floorplan(DATA_URL, filename="plan.png", target_id=tid)
fp = svc.wlan_heatmap_floorplan(target_id=tid)
check("Grundriss gespeichert+gelesen", fp and fp["data_url"] == DATA_URL)
check("has_floorplan flag", svc.wlan_heatmap_data(target_id=tid)["has_floorplan"] is True)
try:
    svc.wlan_heatmap_set_floorplan("not-a-data-url", target_id=tid); bad2 = False
except ValueError:
    bad2 = True
check("ungültige data_url → ValueError", bad2)
svc.wlan_heatmap_delete_floorplan(target_id=tid)
check("Grundriss gelöscht", svc.wlan_heatmap_floorplan(target_id=tid) is None)

banner("TEST E: Sample löschen + clear")
sid = d["samples"][0]["id"]
svc.wlan_heatmap_delete_sample(sid)
check("Einzel-Sample gelöscht", svc.wlan_heatmap_data(target_id=tid)["sample_count"] == 2)
svc.wlan_heatmap_clear(target_id=tid)
check("clear leert alles", svc.wlan_heatmap_data(target_id=tid)["sample_count"] == 0)
svc.close()

banner("TEST F: Web-Routen (FastAPI TestClient)")
from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)
t = client.post("/api/targets", json={"name": "heatweb", "description": "x"}).json()
r0 = client.get(f"/api/wlan/heatmap?target_id={t['id']}")
check("GET /api/wlan/heatmap 200 + honest-empty",
      r0.status_code == 200 and r0.json()["point_count"] == 0)
rp = client.post("/api/wlan/heatmap/sample", json={
    "x": 0.4, "y": 0.5, "ort": "Flur", "target_id": t["id"],
    "samples": {"aa:bb:cc:00:00:01": -70},
    "ap_meta": {"aa:bb:cc:00:00:01": {"ssid": "FritzBox-A", "channel": 1, "band": "2.4"}}})
check("POST sample 200", rp.status_code == 200 and rp.json()["sample_count"] == 1)
rb = client.post("/api/wlan/heatmap/sample", json={"x": 0.5, "y": 0.5, "samples": {}})
check("leere samples → 400", rb.status_code == 400)
rg = client.get(f"/api/wlan/heatmap?target_id={t['id']}")
check("GET liefert Flur-Punkt (ok-Qualität)", rg.status_code == 200
      and rg.json()["point_count"] == 1
      and rg.json()["points"][0]["quality"] == "schwach")
rfp = client.post("/api/wlan/heatmap/floorplan",
                  json={"data_url": DATA_URL, "target_id": t["id"]})
check("POST floorplan 200", rfp.status_code == 200)
rfg = client.get(f"/api/wlan/heatmap/floorplan?target_id={t['id']}")
check("GET floorplan liefert data_url", rfg.json()["floorplan"]["data_url"] == DATA_URL)
rd = client.delete(f"/api/wlan/heatmap?target_id={t['id']}")
check("DELETE heatmap 200", rd.status_code == 200)

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
