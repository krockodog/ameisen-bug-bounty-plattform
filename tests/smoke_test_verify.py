"""Smoke-Test für die TIEFE, kontrollierte AKTIVE Verifikations-Ebene.

NUR lokal (127.0.0.1, bewusst verwundbarer Mini-Server). Weist nach:
  1. Aktive Checks ERKENNEN die eingebauten Schwachstellen + liefern Evidence.
  2. OHNE active-Schalter laufen die aktiven Checks NICHT.
  3. Scope-Block (default-deny) greift weiter (out-of-scope → kein Request).
  4. Oversight-Gate greift weiter (ohne Häkchen → OversightError).
Temporäre DB, NICHT die Live-DB. Nichts Fremdes im Internet.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asyncio, logging, os, sys, threading, time
logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

os.environ["ANTBB_DB"] = "/tmp/antbb_verify_smoke.db"
if os.path.exists("/tmp/antbb_verify_smoke.db"):
    os.remove("/tmp/antbb_verify_smoke.db")

PORT = 8911
from http.server import ThreadingHTTPServer
import tools_vuln_testserver as vuln
srv = ThreadingHTTPServer(("127.0.0.1", PORT), vuln.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.3)

from antbb.service import AntBBService
from antbb.oversight import OversightError
from antbb import netutil, scope as scope_mod, config as config_mod

svc = AntBBService()
def banner(t): print("\n" + "="*72 + f"\n{t}\n" + "="*72)

BASE = f"http://127.0.0.1:{PORT}"
tid = svc.add_target("verifytest", "lokaler verwundbarer Testserver")
svc.add_scope(tid, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid, "url", BASE, allowed=True)

# ---------------------------------------------------------------- TEST 1
banner("TEST 1: Oversight-Gate — aktiver Scan OHNE Häkchen MUSS blockieren")
try:
    svc.run_scan(tid, active=True)
    print("FEHLER: lief trotz fehlendem Häkchen!")
except OversightError as e:
    print("OK — blockiert:", str(e).splitlines()[0])

# ---------------------------------------------------------------- TEST 2
banner("TEST 2: Häkchen + Lauf OHNE active-Schalter → KEINE aktiven Checks")
svc.set_oversight(tid, True, confirmed_by="verify-smoke")
res_passive = svc.run_scan(tid, active=False)
verified_cats = {"xss-verified","sqli-verified","open-redirect","path-traversal",
                 "exposed-artifact","cors-misconfig","missing-auth"}
vf = [f for f in res_passive.findings if f.category in verified_cats or f.agent == "verify"]
print(f">>> passiver Lauf: {len(res_passive.findings)} Findings, davon Verify-Agent: {len(vf)}")
print(">>> ERWARTET 0 Verify-Findings ohne Schalter →", "OK" if len(vf)==0 else "FEHLER")

# ---------------------------------------------------------------- TEST 3
banner("TEST 3: Häkchen + active=True → aktive Verifikation MUSS Schwachstellen bestätigen")
res = svc.run_scan(tid, active=True)
print(f"\n>>> run_id={res.run_id} dauer={res.duration:.2f}s verteilung={res.by_severity()}")
vfind = [f for f in res.findings if f.agent == "verify"]
print(f">>> VERIFIZIERTE/AKTIVE FINDINGS ({len(vfind)}):")
for f in vfind:
    conf = f.evidence.get("confidence", "?")
    print(f"   [{f.severity:8}] {f.title}  @ {f.asset}  <confidence={conf}>")
    req = f.evidence.get("request") or f.evidence.get("request_true") or {}
    exc = f.evidence.get("response_excerpt") or f.evidence.get("location") or \
          f.evidence.get("access_control_allow_origin") or ""
    print(f"              EVIDENCE req={req}")
    if exc:
        print(f"              EVIDENCE resp≈ {str(exc)[:120]}")
cats = {f.category for f in vfind}
print("\n>>> bestätigte Kategorien:", sorted(cats))

# ---------------------------------------------------------------- TEST 4
banner("TEST 4: Scope-Block — out-of-scope Request MUSS unterbleiben (default-deny)")
cfg = config_mod.scan_config()
def scope_check(asset): return bool(scope_mod.check_asset(svc.store, tid, asset))
net = netutil.NetClient(scope_check, cfg, logging.getLogger("net"))
async def oos():
    r1 = await net.http_get("http://example.com/", params={"q":"x"})
    r2 = await net.http_get(f"{BASE}/", params={"q":"x"})   # Kontrolle in-scope
    return r1, r2
r1, r2 = asyncio.run(oos())
print(f"out-of-scope http example.com → {r1} (None=kein Request)")
print(f"in-scope 127.0.0.1 → HTTP {getattr(r2,'status_code',None)} (Kontrolle: erlaubt)")
print("net.blocked:", [(b['op'], b['asset']) for b in net.blocked])

# ---------------------------------------------------------------- TEST 5
banner("TEST 5: Config-Default — active_verification MUSS standardmäßig AUS sein")
print(">>> scan_config().active_verification =", cfg.active_verification,
      "→", "OK (AUS)" if cfg.active_verification is False else "FEHLER")

# ---------------------------------------------------------------- TEST 6
banner("TEST 6: Catch-all-Host — aktive Checks melden KEINE Geister-Funde")
PORT_C = 8914
srv_c = ThreadingHTTPServer(("127.0.0.1", PORT_C), vuln.CatchAllH)
threading.Thread(target=srv_c.serve_forever, daemon=True).start()
time.sleep(0.3)
BASE_C = f"http://127.0.0.1:{PORT_C}"
tid_c = svc.add_target("verifycatchall", "jitternder Catch-all (Verify)")
svc.add_scope(tid_c, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid_c, "url", BASE_C, allowed=True)
svc.set_oversight(tid_c, True, confirmed_by="verify-smoke")
res_c = svc.run_scan(tid_c, active=True)
vf_c = [f for f in res_c.findings if f.agent == "verify"]
print(f">>> Verify-Findings auf jitterndem Catch-all: {len(vf_c)}")
for f in vf_c:
    print(f"   [{f.severity}] {f.title} @ {f.asset}")
ok6 = len(vf_c) == 0
print(">>> ERWARTET 0 Verify-Geister auf Catch-all →", "OK" if ok6 else "FEHLER")
srv_c.shutdown()

svc.close(); srv.shutdown()
print("\n[smoke_test_verify] fertig.")
