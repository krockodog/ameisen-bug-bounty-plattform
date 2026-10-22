"""Smoke-Test für die echten, defensiven Scan-Module (Recon/Scan/Analyse).

Testziele: NUR lokaler http.server (127.0.0.1:8899) und httpbin.org.
Weist nach: echte Findings, Scope-Block (default-deny), Oversight-Gate.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asyncio, logging, os, sys
logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

os.environ["ANTBB_DB"] = "/tmp/antbb_smoke.db"
if os.path.exists("/tmp/antbb_smoke.db"):
    os.remove("/tmp/antbb_smoke.db")

from antbb.service import AntBBService
from antbb.oversight import OversightError
from antbb import netutil, scope as scope_mod, config as config_mod

svc = AntBBService()

def banner(t): print("\n" + "="*70 + f"\n{t}\n" + "="*70)

# ---------------------------------------------------------------- Target lokal
banner("SETUP: lokales Testziel 127.0.0.1:8899 (autorisiert)")
tid = svc.add_target("localtest", "lokaler http.server Smoke-Test")
svc.add_scope(tid, "ip", "127.0.0.1", allowed=True)
svc.add_scope(tid, "url", "http://127.0.0.1:8899", allowed=True)
print("Scopes:", [(s["kind"], s["value"], s["allowed"]) for s in svc.list_scopes(tid)])

# ---------------------------------------------------------------- Oversight-Gate OHNE Häkchen
banner("TEST 1: Oversight-Gate — Scan OHNE Häkchen MUSS blockieren")
try:
    svc.run_scan(tid)
    print("FEHLER: Scan lief trotz fehlendem Häkchen!")
except OversightError as e:
    print("OK — blockiert mit OversightError:")
    print("   " + str(e).splitlines()[0])

# ---------------------------------------------------------------- Häkchen + Scan
banner("TEST 2: Häkchen setzen + voller Schwarm-Lauf (echte Findings)")
svc.set_oversight(tid, True, confirmed_by="smoke-test")
res = svc.run_scan(tid)
print(f"\n>>> run_id={res.run_id} dauer={res.duration:.2f}s verteilung={res.by_severity()}")
print(">>> ECHTE FINDINGS:")
for f in res.findings:
    print(f"   [{f.severity:8}] {f.title}  @ {f.asset}  <{f.agent}>")

# ---------------------------------------------------------------- Scope-Block (net-Ebene)
banner("TEST 3: Scope-Block — out-of-scope Request MUSS unterbleiben (default-deny)")
cfg = config_mod.scan_config()
def scope_check(asset):
    return bool(scope_mod.check_asset(svc.store, tid, asset))
net = netutil.NetClient(scope_check, cfg, logging.getLogger("net"))
async def oos():
    r1 = await net.http_get("http://example.com/")        # out-of-scope
    r2 = await net.resolve("evil.example.net", "A")        # out-of-scope
    r3 = await net.http_get("http://127.0.0.1:8899/")      # in-scope (Kontrollprobe)
    return r1, r2, r3
r1, r2, r3 = asyncio.run(oos())
print(f"out-of-scope http example.com → {r1} (None = kein Request)")
print(f"out-of-scope dns evil.example.net → {r2} (leer = kein Request)")
print(f"in-scope http 127.0.0.1:8899 → HTTP {getattr(r3,'status_code',None)} (Kontrolle: erlaubt)")
print("net.blocked (protokollierte Blocks):")
for b in net.blocked:
    print("   ", b["op"], b["asset"])
print(f"net.request_count (nur in-scope ausgeführt): {net.request_count}")

svc.close()
print("\n[smoke_test] fertig.")
