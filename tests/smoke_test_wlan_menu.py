"""Smoke-Test für den eigenständigen WLAN-Menüpunkt in der Web-GUI.

Prüft, dass:
  * /wlan 200 rendert mit drei klaren Tabs: Scope | Coverage | Offensiv/Airgorah
  * WLAN-Nav-Link, Rechtshinweis §202a-c, Scripts eingebunden
  * Scan-first-UI + Königin-Voll-Scan Marker (Alle auswählen / Oversight / Button)
  * /api/wlan/adapters + full-scan checks honest-empty
  * Offensiv-Gate: ohne Engagement default-deny
  * Airgorah-Status-API antwortet
Läuft lokal ohne WLAN-Tools (honest-empty).
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_wlanmenu_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
os.environ["ANTBB_WIFI"] = "1"
if os.path.exists("/tmp/antbb_wlanmenu_smoke.db"):
    os.remove("/tmp/antbb_wlanmenu_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)

banner("TEST A: /wlan-Seite – drei klare Tabs")
r = client.get("/wlan")
check("/wlan 200", r.status_code == 200)
html = r.text
check("Nav-Link /wlan", 'href="/wlan"' in html)
check("Tab WLAN-Scope", 'data-tab="scope"' in html)
check("Tab Coverage & Scan", 'data-tab="coverage"' in html)
check("Tab Offensiv/Airgorah", 'data-tab="offensive"' in html)
check("Scope-Mount #wlan-scope-view", 'id="wlan-scope-view"' in html)
check("Coverage-Mount #wlan-view", 'id="wlan-view"' in html)
check("Offensiv-Mount #wlan-offensive-view", 'id="wlan-offensive-view"' in html)
check("Königin-Box vorhanden", 'id="wlan-queen-box"' in html or "wlan-queen-box" in html)
check("Voll-Scan-Button", 'id="wlan-full-scan-btn"' in html)
check("Alle auswählen", 'id="wlan-sel-all"' in html)
check("Alle abwählen", 'id="wlan-sel-none"' in html)
check("Oversight für Voll-Scan", 'id="wlan-full-oversight"' in html)
check("Offensiv blocked-border", "wlan-offensive-panel" in html and "blocked-border" in html)
check("Rechtshinweis §202a-c", "202a-c" in html or "202a" in html)
check("wlan_scope.js", "/static/wlan_scope.js" in html)
check("wlan.js", "/static/wlan.js" in html)
check("wlan_offensive.js", "/static/wlan_offensive.js" in html)
check("Airgorah-Erwähnung", "Airgorah" in html or "airgorah" in html)

banner("TEST B: Nav auf Startseite")
check("Startseite / enthält WLAN-Nav", 'href="/wlan"' in client.get("/").text)

banner("TEST C: target_id optional")
check("/wlan?target_id=999999 → 200", client.get("/wlan?target_id=999999").status_code == 200)

banner("TEST D: Passive APIs honest-empty")
sj = client.get("/api/wlan/survey").json()
check("survey dict", isinstance(sj, dict))
check("survey keine erfundenen APs", sj.get("aps", []) == [])
aj = client.get("/api/wlan/adapters").json()
check("adapters dict", isinstance(aj, dict) and "adapters" in aj)
check("adapters ehrlich leer", aj.get("adapters") == [])

banner("TEST D2: Königin full-scan checks + Gate ohne Oversight")
fc = client.get("/api/wlan/full-scan/checks").json()
check("full-scan checks list", isinstance(fc.get("checks"), list) and len(fc["checks"]) >= 4)
ids = [c["id"] for c in fc["checks"]]
check("checks enthalten scan/konfig/optim/coverage",
      set(["scan","konfig","optim","coverage"]).issubset(set(ids)))
blocked = client.post("/api/wlan/full-scan", json={"oversight_ack": False}).json()
check("Voll-Scan ohne Oversight blockiert", blocked.get("blocked") is True)
check("kein checks_run ohne Oversight", blocked.get("checks_run") == [] or not blocked.get("ok"))

banner("TEST D3: Scan-first + Queen Marker in JS")
wj = client.get("/static/wlan.js").text
check("wlan.js Adapter-Dropdown", "wlan-iface" in wj)
check("wlan.js Scannen-Button", "wlan-scan-btn" in wj)
check("wlan.js selectAp", "selectAp" in wj and "wlan-ap-row" in wj)
check("wlan.js Queen full-scan", "wlan-full-scan-btn" in wj and "loadFullChecks" in wj)
check("wlan.js Alle auswählen", "wlan-sel-all" in wj)
ws = client.get("/static/wlan_scope.js").text
check("wlan_scope.js Engagement-UI", "sc-create" in ws and "sc-from-sel" in ws)
wo = client.get("/static/wlan_offensive.js").text
check("offensive.js Airgorah-Marker", "Airgorah" in wo or "airgorah" in wo)
check("offensive.js Selection-Event", "antbb:wlan-selected" in wo)
check("offensive.js dry_run", "dry_run" in wo)
css = client.get("/static/style.css").text
check("CSS queen-box", "wlan-queen-box" in css)

banner("TEST E: Offensiv-Gate default-deny")
stj = client.get("/api/wlan/offensive/status").json()
check("status Rechtshinweis", "202a" in stj.get("legal_notice", ""))
for action in ("handshake-capture", "targeted-deauth", "offline-crack", "evil-twin-demo"):
    ra = client.post("/api/wlan/offensive/" + action,
                     json={"bssid": "aa:bb:cc:11:22:33", "ssid": "X", "dry_run": True}).json()
    check(f"{action}: allowed=False", ra.get("allowed") is False)
    check(f"{action}: kein Tool", ra.get("tool_invoked") is False and ra.get("ran") is False)

banner("TEST F: Airgorah-Status-API")
ag = client.get("/api/wlan/airgorah/status").json()
check("airgorah status dict", isinstance(ag, dict))
check("airgorah_ref MIT", (ag.get("airgorah_ref") or {}).get("license") == "MIT")
check("full_scan_checks im Status", len(ag.get("full_scan_checks") or []) >= 4)
check("privileges vorhanden", "privileges" in ag)
check("monitor-Status vorhanden", "monitor" in ag)
cl = client.get("/api/wlan/clients").json()
check("clients honest-empty", cl.get("honest_empty") is True and cl.get("clients") == [])

banner("TEST G: nmcli IN-USE Parser")
from antbb.wlan_survey import parse_nmcli
sample = "*:" + r"AA\:BB\:CC\:00\:00\:01" + ":MeinWLAN:6:2437:88:WPA2\n" + \
         ":" + r"DE\:AD\:BE\:EF\:00\:99" + ":Nachbar:1:2412:40:WPA3"
aps = parse_nmcli(sample)
check("2 APs", len(aps) == 2)
check("connected=True", aps[0].connected is True and aps[0].ssid == "MeinWLAN")

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
