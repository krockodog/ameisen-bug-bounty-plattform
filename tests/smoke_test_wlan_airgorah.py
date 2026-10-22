"""Smoke: Airgorah-Schicht + Königin-Voll-Scan (defensiv, oversight-gated)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_wlan_airgorah_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
os.environ["ANTBB_WIFI"] = "1"
if os.path.exists("/tmp/antbb_wlan_airgorah_smoke.db"):
    os.remove("/tmp/antbb_wlan_airgorah_smoke.db")

OK=[]
def check(n,c):
    OK.append(bool(c)); print(("OK  " if c else "FAIL")+" · "+n)

from antbb import wlan_airgorah as wa
from antbb.service import AntBBService as Service

check("FULL_SCAN_CHECKS >=4", len(wa.FULL_SCAN_CHECKS) >= 4)
check("AIRGORAH_ACTIONS enthält handshake+deauth",
      {"handshake-capture","targeted-deauth"}.issubset({a["id"] for a in wa.AIRGORAH_ACTIONS}))

st = wa.airgorah_status()
check("status hat tools", isinstance(st.get("tools"), dict))
check("status hat caveats list", isinstance(st.get("caveats"), list))
check("MIT ref", st["airgorah_ref"]["license"] == "MIT")

# ohne Oversight blockiert
blocked = wa.run_full_scan(oversight_ack=False)
check("ohne oversight blocked", blocked["blocked"] is True and not blocked["ok"])

# mit Oversight: läuft (honest-empty auf Box ohne WLAN)
ok = wa.run_full_scan(oversight_ack=True, checks=["scan","konfig","optim","coverage"])
check("mit oversight ok", ok["ok"] is True and ok["blocked"] is False)
check("checks_run enthält scan", "scan" in ok["checks_run"])
check("queen flag", ok.get("queen") is True)
check("keine erfundenen APs", (ok.get("scan") or {}).get("aps", []) == [])

# Service-Pfad
svc = Service(db_path=os.environ["ANTBB_DB"])
r = svc.wlan_full_scan(oversight_ack=True, checks=["scan"])
check("service full_scan ok", r.get("ok") is True)
r2 = svc.wlan_full_scan(oversight_ack=False)
check("service ohne ack blocked", r2.get("blocked") is True)

# Offensiv bleibt gated
from antbb import wlan_offensive as wo
off = wo.WifiOffensive(svc.store, dry_run=True)
res = off.targeted_deauth(bssid="aa:bb:cc:11:22:33", ssid="Nope")
check("deauth ohne Engagement blocked", res.allowed is False and res.tool_invoked is False)

# clients honest-empty
cl = wa.list_clients_honest_empty()
check("clients honest_empty", cl["honest_empty"] is True)

print(f"\nERGEBNIS: {sum(OK)}/{len(OK)} OK")
sys.exit(0 if all(OK) else 1)
