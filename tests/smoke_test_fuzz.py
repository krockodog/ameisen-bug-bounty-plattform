"""Smoke-Test für kontrolliertes OFFENSIVES Fuzzing (Baseline gegen Catch-all).

NUR lokal (127.0.0.1). Kein externes Target. ANTBB_NO_LLM=1 für Tempo.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asyncio, logging, os, sys, threading, time
logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

os.environ["ANTBB_DB"] = "/tmp/antbb_fuzz_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
os.environ["ANTBB_SCAN_DELAY"] = "0.05"
os.environ["ANTBB_SCAN_MAX_RPS"] = "20"
os.environ.pop("ANTBB_FUZZ", None)
os.environ.pop("ANTBB_ACTIVE_VERIFICATION", None)
if os.path.exists("/tmp/antbb_fuzz_smoke.db"):
    os.remove("/tmp/antbb_fuzz_smoke.db")

PORT_VULN = 8912
PORT_CATCH = 8913
from http.server import ThreadingHTTPServer
import tools_vuln_testserver as vuln

srv_v = ThreadingHTTPServer(("127.0.0.1", PORT_VULN), vuln.H)
srv_c = ThreadingHTTPServer(("127.0.0.1", PORT_CATCH), vuln.CatchAllH)
threading.Thread(target=srv_v.serve_forever, daemon=True).start()
threading.Thread(target=srv_c.serve_forever, daemon=True).start()
time.sleep(0.2)

from antbb.service import AntBBService
from antbb.oversight import OversightError
from antbb import netutil, scope as scope_mod, config as config_mod

svc = AntBBService()
def banner(t): print("\n" + "="*72 + f"\n{t}\n" + "="*72)

BASE_V = f"http://127.0.0.1:{PORT_VULN}"
BASE_C = f"http://127.0.0.1:{PORT_CATCH}"

banner("TEST 0: Config-Default — fuzz_enabled MUSS AUS sein")
cfg = config_mod.scan_config()
print(">>> fuzz_enabled =", cfg.fuzz_enabled, "→", "OK" if cfg.fuzz_enabled is False else "FEHLER")
print(">>> wordlist =", len(cfg.fuzz_wordlist))
ok0 = cfg.fuzz_enabled is False and 30 <= len(cfg.fuzz_wordlist) <= 80

tid = svc.add_target("fuzztest", "lokaler verwundbarer Testserver (Fuzz)")
svc.add_scope(tid, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid, "url", BASE_V, allowed=True)

banner("TEST 1: Oversight-Gate")
try:
    svc.run_scan(tid, fuzz=True, phases=("scan",), use_llm=False)
    print("FEHLER"); ok_gate = False
except OversightError as e:
    print("OK —", str(e).splitlines()[0]); ok_gate = True

banner("TEST 2: OHNE fuzz → 0 Fuzz-Findings")
svc.set_oversight(tid, True, confirmed_by="fuzz-smoke")
res_off = svc.run_scan(tid, fuzz=False, phases=("scan",), use_llm=False)
ff_off = [f for f in res_off.findings if f.agent == "fuzz"]
print(f">>> Fuzz-Findings ohne Schalter: {len(ff_off)} →", "OK" if len(ff_off)==0 else "FEHLER")
ok_off = len(ff_off) == 0

banner("TEST 3: fuzz=True → echte abweichende Pfade")
res = svc.run_scan(tid, fuzz=True, phases=("scan",), use_llm=False)
ff = [f for f in res.findings if f.agent == "fuzz"]
print(f">>> FUZZ-FINDINGS ({len(ff)}):")
for f in ff:
    print(f"   [{f.severity:8}] {f.title}  @ {f.asset}")
disco = [f for f in ff if f.category == "fuzz-discovery"]
paths_hit = set()
for f in disco:
    asset = f.asset
    # normalize path
    if BASE_V in asset:
        paths_hit.add(asset.split(BASE_V, 1)[-1] or "/")
    else:
        paths_hit.add(asset)
expect_any = {"/admin", "/admin/", "/login", "/login/", "/backup", "/backup/",
              "/.git/HEAD", "/.git/config", "/.env", "/api", "/api/v1"}
found_expected = paths_hit & expect_any
print(f">>> Pfade: {sorted(paths_hit)}")
print(f">>> erwartete Treffer: {sorted(found_expected)}")
ok_vuln = len(found_expected) >= 3
print(">>> ≥3 echte Treffer →", "OK" if ok_vuln else "FEHLER")

banner("TEST 4: Catch-all — 0 fuzz-discovery Fehlalarme")
tid2 = svc.add_target("catchall", "Catch-all-Simulator")
svc.add_scope(tid2, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid2, "url", BASE_C, allowed=True)
svc.set_oversight(tid2, True, confirmed_by="fuzz-smoke")
res_c = svc.run_scan(tid2, fuzz=True, phases=("scan",), use_llm=False)
ff_c = [f for f in res_c.findings if f.agent == "fuzz" and f.category == "fuzz-discovery"]
print(f">>> fuzz-discovery auf Catch-all: {len(ff_c)} →", "OK" if len(ff_c)==0 else "FEHLER")
ok_catch = len(ff_c) == 0

banner("TEST 5: Scope default-deny")
def scope_check(asset): return bool(scope_mod.check_asset(svc.store, tid, asset))
net = netutil.NetClient(scope_check, cfg, logging.getLogger("net"))
async def oos():
    r1 = await net.http_get("http://example.com/admin")
    r2 = await net.http_get(f"{BASE_V}/admin")
    return r1, r2
r1, r2 = asyncio.run(oos())
ok_scope = (r1 is None) and (r2 is not None) and len(net.blocked) >= 1
print(f">>> oos={r1} in={getattr(r2,'status_code',None)} blocked={len(net.blocked)} →",
      "OK" if ok_scope else "FEHLER")

banner("TEST 6: mode_policy defensive sperrt Offensiv")
svc.set_mode_policy(tid, "defensive")
st = svc.mode_status(tid)
print(">>> status:", st)
# With defensive, run_scan should force fuzz off
res_d = svc.run_scan(tid, fuzz=True, phases=("scan",), use_llm=False)
ff_d = [f for f in res_d.findings if f.agent == "fuzz" and f.category == "fuzz-discovery"]
ok_pol = (st["effective_mode"] == "defensive" and len(ff_d) == 0)
print(">>> defensive sperrt Fuzz →", "OK" if ok_pol else "FEHLER", f"(fuzz-disco={len(ff_d)})")
svc.set_mode_policy(tid, "auto")  # restore

svc.close(); srv_v.shutdown(); srv_c.shutdown()
print("\n" + "="*72)
alls = [ok0, ok_gate, ok_off, ok_vuln, ok_catch, ok_scope, ok_pol]
print("ZUSAMMENFASSUNG:",
      f"cfg={ok0} gate={ok_gate} off={ok_off} vuln={ok_vuln} "
      f"catch={ok_catch} scope={ok_scope} policy={ok_pol}")
print("GESAMT:", "ALLE GRÜN" if all(alls) else "FEHLER")
print("="*72)
sys.exit(0 if all(alls) else 1)
