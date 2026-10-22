"""Smoke-Test für das AUTORISIERTE WLAN-Offensiv-Modul (antbb.wlan_offensive).

Prüft NUR die Gates (kein echter Tool-Lauf nötig; WLAN-Tools fehlen auf der Box
→ honest-empty). Zentrale Zusicherungen:
  * Ohne Engagement ist JEDE offensive Aktion blockiert (default-deny), KEIN
    Tool wird aufgerufen.
  * Mit aktivem, im-Zeitfenster-liegendem, oversight-bestätigtem Engagement
    passiert das Gate – aber die Tools sind honest-empty (box ohne WLAN-Tools).
  * Out-of-window / abgelaufenes / widerrufenes / oversight-loses Engagement
    bleibt blockiert.
  * Credentials werden MASKIERT (nie Klartext) gespeichert; Purge wirkt.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, time, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_wlanoff_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
if os.path.exists("/tmp/antbb_wlanoff_smoke.db"):
    os.remove("/tmp/antbb_wlanoff_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from antbb import wlan_offensive as wo
from antbb.service import AntBBService

BSSID = "aa:bb:cc:11:22:33"
SSID = "ACME-Corp"
NOW = time.time()

# ------------------------------------------------------------------ TEST A
banner("TEST A: default-deny OHNE Engagement (ANTBB_WIFI=1), kein Tool-Aufruf")
os.environ["ANTBB_WIFI"] = "1"   # Freischaltung an, aber KEIN Engagement vorhanden
svc = AntBBService()
for action in ("handshake-capture", "targeted-deauth", "offline-crack", "evil-twin-demo"):
    r = svc.wlan_offensive_run(action, bssid=BSSID, ssid=SSID, capture_path="/nope",
                               dry_run=True)
    check(f"{action}: blockiert (allowed=False)", r["allowed"] is False)
    check(f"{action}: kein Tool invoked", r["tool_invoked"] is False and r["ran"] is False)

g = svc.wlan_authorize_check(bssid=BSSID, ssid=SSID)
check("authorize_check default-deny", g["allowed"] is False and g["engagement_id"] is None)

# ------------------------------------------------------------------ TEST B
banner("TEST B: ANTBB_WIFI nicht gesetzt → blockiert trotz (später) Engagement")
os.environ.pop("ANTBB_WIFI", None)
r = svc.wlan_offensive_run("handshake-capture", bssid=BSSID, ssid=SSID, dry_run=True)
check("ohne ANTBB_WIFI blockiert", r["allowed"] is False and "ANTBB_WIFI" in r["reason"])
os.environ["ANTBB_WIFI"] = "1"

# ------------------------------------------------------------------ TEST C
banner("TEST C: aktives, autorisiertes Engagement → Gate passiert, Tools honest-empty")
eid = svc.wlan_engagement_create("ACME-Awareness", bssids=[BSSID], ssids=[SSID],
                                 start_ts=NOW-60, end_ts=NOW+3600, oversight=True,
                                 location="HQ")
check("Engagement angelegt", isinstance(eid, int) and eid > 0)
g2 = svc.wlan_authorize_check(bssid=BSSID)
check("authorize_check jetzt erlaubt", g2["allowed"] is True and g2["engagement_id"] == eid)

r = svc.wlan_offensive_run("handshake-capture", bssid=BSSID, ssid=SSID, dry_run=True)
check("capture: Gate bestanden (allowed)", r["allowed"] is True)
check("capture: honest-empty (box ohne Tool), nichts erfunden",
      (r["honest_empty"] is True or r["tool"] is None) and r["tool_invoked"] is False)

rd = svc.wlan_offensive_run("targeted-deauth", bssid=BSSID, packets=9999, seconds=9999,
                            dry_run=True)
check("deauth: Gate bestanden + Warnung + Paketlimit gedeckelt",
      rd["allowed"] and rd["detail"].get("warning") and rd["detail"]["packets"] <= wo.MAX_DEAUTH_PACKETS)

# Ziel NICHT in der Allowlist → blockiert, obwohl Engagement aktiv ist
rx = svc.wlan_offensive_run("handshake-capture", bssid="de:ad:de:ad:de:ad", dry_run=True)
check("fremde BSSID trotz aktivem Engagement blockiert", rx["allowed"] is False)

# ------------------------------------------------------------------ TEST D
banner("TEST D: out-of-window / abgelaufen / widerrufen / oversight-los = blockiert")
# abgelaufenes Engagement
e_exp = svc.wlan_engagement_create("Abgelaufen", bssids=["11:11:11:11:11:11"],
                                   start_ts=NOW-7200, end_ts=NOW-3600, oversight=True)
check("abgelaufen blockiert",
      svc.wlan_authorize_check(bssid="11:11:11:11:11:11")["allowed"] is False)
# zukünftiges Fenster
e_fut = svc.wlan_engagement_create("Zukunft", bssids=["22:22:22:22:22:22"],
                                   start_ts=NOW+3600, end_ts=NOW+7200, oversight=True)
check("out-of-window (Zukunft) blockiert",
      svc.wlan_authorize_check(bssid="22:22:22:22:22:22")["allowed"] is False)
# oversight fehlt
e_noov = svc.wlan_engagement_create("OhneOversight", bssids=["33:33:33:33:33:33"],
                                    start_ts=NOW-60, end_ts=NOW+3600, oversight=False)
check("ohne Oversight blockiert",
      svc.wlan_authorize_check(bssid="33:33:33:33:33:33")["allowed"] is False)
# widerrufen
svc.wlan_engagement_revoke(eid)
check("widerrufenes Engagement blockiert",
      svc.wlan_authorize_check(bssid=BSSID)["allowed"] is False)
r_after = svc.wlan_offensive_run("handshake-capture", bssid=BSSID, dry_run=True)
check("Aktion nach Widerruf blockiert", r_after["allowed"] is False)

# ------------------------------------------------------------------ TEST E
banner("TEST E: Credentials werden MASKIERT gespeichert (nie Klartext) + Purge")
off = wo.WifiOffensive(svc.store, dry_run=True)
PLAIN = "SuperGeheim123!"
cid = off.record_cracked(e_noov, PLAIN, bssid=BSSID, ssid=SSID)
pid = off.record_portal_credential(e_noov, username="alice", password="hunter2hunter",
                                   ssid=SSID)
creds = svc.wlan_credentials_list(e_noov)
check("2 Credentials gespeichert", len(creds) == 2)
blob = (creds[0]["masked"] + creds[0]["digest"] + (creds[1]["masked"] or "")
        + creds[1]["digest"])
check("Klartext-Passwort NICHT gespeichert", PLAIN not in blob and "hunter2hunter" not in blob)
check("Maskierung zeigt Länge/erstes/letztes Zeichen", "len=" in creds[0]["masked"])
check("Digest ist 64-Hex (gesalzener sha256)", all(len(c["digest"]) == 64 for c in creds))
m = wo.mask_password(PLAIN)
check("mask_password: kein Klartext, char_count korrekt",
      PLAIN not in m["masked"] and m["char_count"] == len(PLAIN))

# Purge wirkt + Auto-Purge-nach-Report
n = off.purge_after_report(e_noov)
check("purge_after_report löscht", n == 2 and svc.wlan_credentials_list(e_noov) == [])

# ------------------------------------------------------------------ TEST F
banner("TEST F: Playbook-Registrierung + Tool-Status (fehlende Tools für Deploy)")
reg = svc.capabilities(rebuild=True)
wifi = next(s for s in reg["soldiers"] if s["name"] == "wifi")
pbnames = {pb["name"] for pb in wifi["playbooks"]}
check("alle 4 Offensiv-Playbooks registriert",
      {"wlan-handshake-capture", "wlan-targeted-deauth", "wlan-offline-crack",
       "wlan-evil-twin-demo"}.issubset(pbnames))
check("Offensiv-Playbooks oversight-pflichtig",
      all(pb["oversight_required"] for pb in wifi["playbooks"]
          if pb["name"].startswith("wlan-") and pb["mode"] == "offensive"))
st = svc.wlan_offensive_tool_status()
check("tool_status liefert missing-Liste", isinstance(st["missing"], list))
print("   Fehlende WLAN-Offensiv-Tools (Deploy):", ", ".join(st["missing"]) or "(keine)")

svc.close()

# ------------------------------------------------------------------ TEST G
banner("TEST G: Web-Routen (FastAPI TestClient) – Gate über HTTP")
from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)
# ohne passendes aktives Engagement blockiert eine neue (fremde) BSSID
rb = client.post("/api/wlan/offensive/handshake-capture",
                 json={"bssid": "99:99:99:99:99:99", "dry_run": True}).json()
check("HTTP: fremde BSSID blockiert", rb["allowed"] is False)
ce = client.post("/api/wlan/engagements",
                 json={"name": "web-eng", "bssids": ["ab:cd:ef:01:02:03"],
                       "oversight": True, "duration_hours": 2}).json()
check("HTTP: Engagement anlegen 200", ce["ok"] and ce["id"])
ra = client.post("/api/wlan/offensive/handshake-capture",
                 json={"bssid": "ab:cd:ef:01:02:03", "dry_run": True}).json()
check("HTTP: autorisierte BSSID passiert Gate", ra["allowed"] is True)
check("HTTP: honest-empty (kein Tool)", ra["honest_empty"] is True or ra["tool"] is None)
stj = client.get("/api/wlan/offensive/status").json()
check("HTTP: status enthält Rechtshinweis (§202a-c)", "202a" in stj.get("legal_notice", ""))

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
