"""Smoke-Test: konsistentes Human-Oversight-Gate fuer ALLE aktiven/offensiven Ausloeser.

Beweist serverseitig (nicht nur UI): ohne ausdrueckliche Human-Oversight-Freigabe
wird jede aktive/offensive Aktion VERWEIGERT (nichts aufgerufen); mit Freigabe
laeuft sie (bei sonst gueltigem Scope). Defensive/lesende Pfade bleiben un-gated.

Deckt ab: Offensiv-Scan, aktive Verifikation, offensives Fuzzing (Service +
Web HTML + Web JSON) sowie das WLAN-Offensiv-Modul (Engagement-Gate).
NUR lokal. ANTBB_NO_LLM=1.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stdout)

DB = "/tmp/antbb_active_oversight_smoke.db"
os.environ["ANTBB_DB"] = DB
os.environ["ANTBB_NO_LLM"] = "1"
os.environ.pop("ANTBB_WIFI", None)
if os.path.exists(DB):
    os.remove(DB)

from antbb.service import AntBBService
from antbb.oversight import OversightError
from antbb.active_oversight import (
    ACTIVE_LEGAL_NOTICE, ACTIVE_OVERSIGHT_PROMPT, active_trigger_requested,
)

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  OK   {name}")
    else:    FAIL += 1; print(f"  FAIL {name}")

def banner(t): print("\n" + "="*68 + f"\n{t}\n" + "="*68)

svc = AntBBService()
tid = svc.add_target("ao-test", "lokales Oversight-Gate", )
svc.add_scope(tid, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid, "url", "http://127.0.0.1:9", allowed=True)
svc.set_oversight(tid, True, confirmed_by="ao-smoke")  # Target-Oversight gesetzt
svc.set_mode_policy(tid, "auto")

banner("TEST 0: zentrale Konsistenz (ein Text ueberall)")
check("Rechtshinweis enthaelt §202a-c", "202a-c" in ACTIVE_LEGAL_NOTICE)
check("Rechtshinweis enthaelt CFAA", "Computer Fraud" in ACTIVE_LEGAL_NOTICE)
check("Prompt nennt Human Oversight", "Human Oversight" in ACTIVE_OVERSIGHT_PROMPT)
check("Trigger-Erkennung: active", active_trigger_requested(active=True))
check("Trigger-Erkennung: fuzz", active_trigger_requested(fuzz=True))
check("Trigger-Erkennung: offensive", active_trigger_requested(offensive=True))
check("Trigger-Erkennung: defensiv=NEIN", not active_trigger_requested())

banner("TEST 1: Service — aktive/offensive Laeufe OHNE Freigabe (oversight_ack=False) VERWEIGERT")
for label, kw in [("active", dict(active=True)), ("fuzz", dict(fuzz=True)),
                  ("offensive", dict(offensive=True))]:
    try:
        svc.run_scan(tid, phases=("scan",), oversight_ack=False, use_llm=False, **kw)
        check(f"{label}: verweigert (default-deny)", False)
    except OversightError as e:
        check(f"{label}: verweigert (default-deny)", "default-deny" in str(e))

banner("TEST 2: Service — MIT Freigabe (oversight_ack=True) laeuft")
got = []
def cap(ev): got.append(ev.get("msg",""))
res = svc.run_scan(tid, phases=("scan",), active=True, oversight_ack=True,
                   emit=cap, use_llm=False)
check("active-Lauf mit Freigabe lief (run_id vorhanden)", bool(res.run_id))
check("Rechtshinweis wurde protokolliert (recorded)", any("202a-c" in m for m in got))
check("Freigabe wurde protokolliert", any("Human-Oversight-Freigabe bestaetigt" in m for m in got))

banner("TEST 3: Service — DEFENSIVER Lauf bleibt UN-gated (ack=False ignoriert)")
res_def = svc.run_scan(tid, phases=("recon",), oversight_ack=False, use_llm=False)
check("defensiver Lauf trotz ack=False gelaufen", bool(res_def.run_id))

banner("TEST 4: Service — programmatisch (ack=None) bleibt rueckwaertskompatibel")
res_compat = svc.run_scan(tid, phases=("scan",), fuzz=True, use_llm=False)  # kein ack
check("ack=None: aktiver Lauf lief (kompatibel)", bool(res_compat.run_id))

banner("TEST 5: Web — HTML- und JSON-Scan-Routen serverseitig")
try:
    from starlette.testclient import TestClient
except Exception:
    from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)

# HTML: offensive ohne Oversight-Haekchen -> 403 (verweigert, nichts gestartet)
resp = client.post(f"/target/{tid}/scan",
                   data={"offensive": "on", "oversight_active": "off"},
                   follow_redirects=False)
check("HTML offensive ohne Haekchen -> 403", resp.status_code == 403)
check("HTML 403 nennt default-deny", "default-deny" in resp.text or "BLOCKIERT" in resp.text)

# HTML: offensive MIT Oversight-Haekchen -> 303 Redirect (Start)
import antbb.web.app as webapp
import threading, time as _time

def _wait_scan_idle(timeout: float = 30.0) -> None:
    """Test-Isolation: WARTE, bis der im Hintergrund gestartete antbb-Scan-
    Thread wirklich fertig ist, bevor die naechste Scan-Route getriggert wird.

    Grund: Die Web-Routen starten den Scan in einem Daemon-Thread, der sich
    denselben (prozessweiten) SQLite-Store teilt. Ein frueheres, hartes
    Zuruecksetzen von SCAN_STATE auf "idle" liess einen noch LAUFENDEN
    Hintergrund-Scan parallel zum naechsten Request auf dieselbe Verbindung
    zugreifen -> sporadisch sqlite3.InterfaceError / 29-von-30. Wir joinen den
    Thread und setzen ERST DANN idle. Reiner Test-Fix; das Produktionsverhalten
    (Default-Deny-Gate, Routen, Service) bleibt unveraendert.
    """
    for th in threading.enumerate():
        if th.name == "antbb-scan" and th.is_alive():
            th.join(timeout)
    deadline = _time.time() + timeout
    while webapp.SCAN_STATE.get("status") == "running" and _time.time() < deadline:
        _time.sleep(0.05)
    with webapp._SCAN_LOCK:
        webapp.SCAN_STATE["status"] = "idle"

_wait_scan_idle()
resp2 = client.post(f"/target/{tid}/scan",
                    data={"offensive": "on", "oversight_active": "on"},
                    follow_redirects=False)
check("HTML offensive mit Haekchen -> 303", resp2.status_code == 303)

# HTML: rein defensiv ohne Haekchen -> 303 (un-gated)
_wait_scan_idle()
resp3 = client.post(f"/target/{tid}/scan", data={}, follow_redirects=False)
check("HTML defensiv ohne Haekchen -> 303 (un-gated)", resp3.status_code == 303)

# JSON: active ohne ack -> 403
_wait_scan_idle()
resp4 = client.post(f"/api/targets/{tid}/scan",
                    json={"active": True, "oversight_active": False})
check("JSON active ohne ack -> 403", resp4.status_code == 403)
# JSON: active mit ack -> 200 running
_wait_scan_idle()
resp5 = client.post(f"/api/targets/{tid}/scan",
                    json={"active": True, "oversight_active": True})
check("JSON active mit ack -> 200/running", resp5.status_code == 200 and
      resp5.json().get("status") == "running")
# Hintergrund-Scan sauber beenden, bevor der Prozess/die naechste Route folgt.
_wait_scan_idle()

# WLAN-Status liefert konsistenten Prompt + Rechtshinweis
st = client.get("/api/wlan/offensive/status").json()
check("WLAN-Status: §202a-c im Rechtshinweis", "202a" in st.get("legal_notice",""))
check("WLAN-Status: konsistenter Oversight-Prompt", st.get("oversight_prompt") == ACTIVE_OVERSIGHT_PROMPT)

banner(f"ERGEBNIS: {PASS} OK / {FAIL} FAIL")
sys.exit(0 if FAIL == 0 else 1)
