"""Smoke-Test für das PASSIVE WLAN-Coverage/Site-Survey-Modul (antbb.wlan_survey).

Läuft komplett lokal ohne WLAN-Hardware: nutzt eine iw-scan-Fixture, prüft
Parser, Kanal-Überlappung/Selbst-Störung, Coverage/Funkloch-Erkennung,
Empfehlungs-Engine, SQLite-Persistenz und die honest-empty-Pfade.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_wlan_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
os.environ.pop("ANTBB_WIFI", None)   # bewusst NICHT freigeschaltet → honest-empty
if os.path.exists("/tmp/antbb_wlan_smoke.db"):
    os.remove("/tmp/antbb_wlan_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from antbb import wlan_survey as ws

# ----------------------------------------------------------------- Fixture
# Drei eigene Fritzboxen: A+B kollidieren auf 2,4-GHz-Kanal 1 (Co-Channel),
# C auf 5 GHz. Plus ein Fremd-AP auf Kanal 6.
IW_SCAN_FIXTURE = """\
BSS aa:bb:cc:00:00:01(on wlan0)
	freq: 2412
	signal: -45.00 dBm
	SSID: FritzBox-A
	DS Parameter set: channel 1
	RSN:	 * Version: 1
BSS aa:bb:cc:00:00:02(on wlan0)
	freq: 2412
	signal: -58.00 dBm
	SSID: FritzBox-B
	DS Parameter set: channel 1
	RSN:	 * Version: 1
		 * Authentication suites: SAE
BSS aa:bb:cc:00:00:03(on wlan0)
	freq: 5180
	signal: -62.00 dBm
	SSID: FritzBox-C
	DS Parameter set: channel 36
	RSN:	 * Version: 1
BSS de:ad:be:ef:00:99(on wlan0)
	freq: 2437
	signal: -80.00 dBm
	SSID: Nachbar-WLAN
	DS Parameter set: channel 6
	WPA:	 * Version: 1
"""

OWN = ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"]

banner("TEST A: iw-scan Parser")
aps = ws.parse_iw_scan(IW_SCAN_FIXTURE)
check("4 APs geparst", len(aps) == 4)
a1 = next(a for a in aps if a.bssid == "aa:bb:cc:00:00:01")
check("AP1 SSID/Kanal/RSSI korrekt", a1.ssid == "FritzBox-A" and a1.channel == 1 and a1.rssi == -45)
check("AP1 Band 2.4", a1.band == "2.4")
a2 = next(a for a in aps if a.bssid == "aa:bb:cc:00:00:02")
check("AP2 WPA3 erkannt (SAE)", a2.encryption == "WPA3")
a3 = next(a for a in aps if a.bssid == "aa:bb:cc:00:00:03")
check("AP3 Band 5 / Kanal 36", a3.band == "5" and a3.channel == 36)
check("Fremd-AP WPA", next(a for a in aps if a.bssid=="de:ad:be:ef:00:99").encryption == "WPA")

banner("TEST B: Kanal-/Störungs-Analyse (1/6/11, Selbst-Störung)")
ca = ws.analyze_channels(aps, own_bssids=OWN)
check("ap_count 4 / own 3", ca["ap_count"] == 4 and ca["own_ap_count"] == 3)
check("2.4-GHz Kanal 1 doppelt belegt", ca["channel_usage"]["2.4"].get(1) == 2)
check("Selbst-Störung erkannt (A+B co-channel)",
      ca["self_interference_count"] == 1 and ca["self_interference"][0]["kind"] == "co-channel")
check("Co-Channel severity high", ca["self_interference"][0]["severity"] == "high")
check("1 und 6 sind NICHT überlappend (1/6/11-Regel korrekt)",
      not any({o["ch_a"], o["ch_b"]} == {1, 6} for o in ca["overlaps_24"]))
check("_overlap_24: 1↔3 überlappt, 1↔6 nicht",
      ws._overlap_24(1, 3) and not ws._overlap_24(1, 6))

banner("TEST C: Coverage / Funkloch-Erkennung")
points = [
    {"label": "Wohnzimmer", "samples": {"aa:bb:cc:00:00:01": -48, "de:ad:be:ef:00:99": -85}},
    {"label": "Keller",     "samples": {"aa:bb:cc:00:00:01": -86, "aa:bb:cc:00:00:03": -88}},
    {"label": "Büro",       "samples": {"aa:bb:cc:00:00:03": -65}},
]
cov = ws.coverage_map(points, own_bssids=OWN)
check("3 Punkte / 3 gemessen", cov["point_count"] == 3 and cov["measured_count"] == 3)
check("Keller ist Funkloch", any(d["label"] == "Keller" for d in cov["dead_zones"]))
check("1 Funkloch gesamt", cov["dead_zone_count"] == 1)
wz = next(p for p in cov["points"] if p["label"] == "Wohnzimmer")
check("Wohnzimmer bestes eigenes Signal -48 (gut)", wz["best_rssi"] == -48 and wz["quality"] == "gut")

banner("TEST D: Empfehlungs-Engine (regelbasiert)")
rec = ws.recommend(aps, ca, cov, own_bssids=OWN)
check("bester 2,4-GHz-Kanal aus {1,6,11}", rec["best_channel_24"]["channel"] in (1,6,11))
check("Empfehlungen nicht leer", len(rec["channel_recommendations"]) >= 1)
check("Selbst-Störungs-Empfehlung vorhanden",
      any("Selbst-Störung" in r for r in rec["channel_recommendations"]))
check("Placement nennt Funkloch 'Keller'", any("Keller" in p for p in rec["placement"]))

banner("TEST E: full_survey Bündelung + honest-empty")
full = ws.full_survey([a.to_dict() for a in aps], points=points, own_bssids=OWN)
check("full_survey Struktur komplett",
      all(k in full for k in ("aps","channel_analysis","coverage","recommendations")))
empty = ws.full_survey([], points=[], own_bssids=[])
check("leer → keine erfundenen Daten", empty["channel_analysis"]["ap_count"] == 0
      and empty["coverage"]["dead_zone_count"] == 0
      and empty["recommendations"]["best_channel_24"] is None)

banner("TEST F: scan_environment degradiert ehrlich (ANTBB_WIFI nicht gesetzt)")
sc = ws.scan_environment()
check("nicht freigeschaltet → aps leer + Grund", sc["aps"] == [] and "ANTBB_WIFI" in sc["reason"])
check("tool_availability liefert dict", isinstance(ws.tool_availability(), dict))

banner("TEST G: SQLite-Persistenz über Service-Fassade")
from antbb.service import AntBBService
svc = AntBBService()
tid = svc.add_target("wlan-smoke", "WLAN-Survey-Test")
n = svc.wlan_add_point("Wohnzimmer", {"aa:bb:cc:00:00:01": -48}, target_id=tid, own_bssids=OWN)
svc.wlan_add_point("Keller", {"aa:bb:cc:00:00:01": -86, "aa:bb:cc:00:00:03": -88},
                   target_id=tid, own_bssids=OWN)
check("Samples gespeichert", n == 1)
rows = svc.store.list_wlan_samples(tid)
check("3 Samples in SQLite", len(rows) == 3)
survey = svc.wlan_survey(target_id=tid, aps=[a.to_dict() for a in aps], own_bssids=OWN)
check("Survey aus Store-Punkten: Keller-Funkloch", survey["coverage"]["dead_zone_count"] == 1)
check("own_bssids aus Store rekonstruiert", set(OWN).issubset(set(survey["own_bssids"])))
svc.wlan_delete_point("Keller", target_id=tid)
check("delete_point wirkt", len(svc.store.list_wlan_samples(tid)) == 1)

banner("TEST H: Web-Routen (FastAPI TestClient)")
from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)
r = client.get("/api/wlan/scan")
check("/api/wlan/scan 200 + honest-empty", r.status_code == 200 and r.json()["aps"] == [])
t = client.post("/api/targets", json={"name":"wlanweb","description":"x"}).json()
rp = client.post("/api/wlan/point", json={"label":"Flur","samples":{"aa:bb:cc:00:00:01":-90},
                                          "own_bssids":OWN,"target_id":t["id"]})
check("POST /api/wlan/point 200", rp.status_code == 200 and rp.json()["sample_count"] == 1)
rs = client.get(f"/api/wlan/survey?target_id={t['id']}")
check("/api/wlan/survey 200 + Flur-Funkloch", rs.status_code == 200
      and rs.json()["coverage"]["dead_zone_count"] == 1)
check("DELETE /api/wlan/point 200",
      client.delete(f"/api/wlan/point?label=Flur&target_id={t['id']}").status_code == 200)
svc.close()

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
