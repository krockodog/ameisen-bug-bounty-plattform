"""Smoke-Test für die ARES "acceptable half" (defensiv/Infra):
Scope-Firewall (DRY-RUN), Branded Report, Module-SDK, Replay/Checkpoint,
DAG-Angriffspfad-Visualisierung. Rein lokal, keine Tools, kein Netz, kein Deploy.
Nichts Offensives.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_ares_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
if os.path.exists("/tmp/antbb_ares_smoke.db"):
    os.remove("/tmp/antbb_ares_smoke.db")

OK=[]
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL")+" · "+name)
def banner(t): print("\n"+"="*68+"\n"+t+"\n"+"="*68)

from antbb.service import AntBBService
svc = AntBBService()
tid = svc.add_target("ares-test", "ARES acceptable-half Smoke")
svc.add_scope(tid, "domain", "example.com", True)
svc.add_scope(tid, "ip", "127.0.0.1", True)
svc.add_scope(tid, "domain", "evil.test", False)  # out-of-scope
# Echte Findings für Report/Attackpath.
svc.store.add_finding(tid, "run-sample", "scanning", "Reflected XSS in q", "xss-verified",
    "high", asset="http://example.com/search",
    evidence={"request":{"url":"http://example.com/search","param":"q","value":"<x>"},
              "response_excerpt":"<x>"}, status="VERIFIZIERT", dedup_key="x1")
svc.store.add_finding(tid, "run-sample", "osint", "Exposed .env", "exposed-artifact",
    "high", asset="http://example.com/.env", status="BESTÄTIGT(PASSIV)", dedup_key="x2")
svc.store.add_finding(tid, "run-sample", "auth", "Admin ohne Auth", "missing-auth",
    "medium", asset="http://example.com/admin", status="ZU BESTÄTIGEN", dedup_key="x3")

# ---------------------------------------------------------------- 1) Firewall
banner("TEST 1: Scope-Firewall / Egress-Filter (DRY-RUN, kein echtes iptables)")
import antbb.egress_firewall as fw
_real_run = __import__("subprocess").run
import subprocess as _sp
_called = {"n":0}
def _trap(*a, **k):
    _called["n"] += 1
    raise AssertionError("subprocess.run DARF im DRY-RUN NICHT aufgerufen werden!")
_sp.run = _trap
try:
    plan = svc.egress_firewall_plan(tid)
    check("DRY-RUN erzeugt iptables-Regeln", len(plan["iptables_rules"]) > 5)
    check("DRY-RUN erzeugt nft-Regelsatz", "policy drop" in plan["nft_ruleset"])
    check("DRY-RUN dry_run=True, applied=False", plan["dry_run"] and not plan["applied"])
    check("default-deny DROP enthalten", any("DROP" in r for r in plan["iptables_rules"]))
    check("Log-Regel enthalten", any("LOG" in r for r in plan["iptables_rules"]))
    # apply ohne Gates → honest no-op, KEIN subprocess
    ap = svc.egress_firewall_apply(tid, confirm=True)
    check("apply ohne root/Binary → applied=False (honest no-op)", ap["applied"] is False)
    check("apply nennt offene Gates", "Gates" in ap["apply_report"] or "nicht root" in ap["apply_report"])
finally:
    _sp.run = _real_run
check("subprocess.run wurde NIE aufgerufen (Firewall nie angefasst)", _called["n"] == 0)

# ---------------------------------------------------------------- 2) Branded report
banner("TEST 2: Branded Report-Pipeline (HTML immer, PDF honest-empty ohne Engine)")
res = svc.branded_report_export(tid, brand={"company_name":"ACME Pentest",
    "primary_color":"#123456","report_title":"Pentest-Report"})
check("HTML-Datei erzeugt", os.path.isfile(res["html_path"]))
htmldoc = open(res["html_path"],encoding="utf-8").read()
check("Branding (Firmenname) im HTML", "ACME Pentest" in htmldoc)
check("echte Findings im HTML (XSS)", "Reflected XSS" in htmldoc)
check("Executive Summary vorhanden", "Executive Summary" in htmldoc)
check("keine Secrets/MiniMax im HTML", "minimax" not in htmldoc.lower() and "MINIMAX_API_KEY" not in htmldoc)
eng = svc.pdf_engine()
if eng:
    check("PDF erzeugt (Engine vorhanden)", res.get("pdf_path"))
else:
    check("PDF honest-empty ohne Engine (pdf_path None)", res.get("pdf_path") is None and "Honest-empty" in res["pdf_note"])

# ---------------------------------------------------------------- 3) Module SDK
banner("TEST 3: Module-SDK (lokale Plugins, Beispiel lädt + validiert)")
blk = svc.plugins_list()
check("mind. 1 Plugin entdeckt", blk["plugin_count"] >= 1)
check("Beispiel-Plugin geladen", any(m["name"]=="example-header-check" for m in blk["plugins"]))
check("keine Ladefehler im Beispiel-Ordner", len(blk["errors"]) == 0)
run = svc.plugins_run("example-header-check", tid)
check("Plugin laeuft isoliert (ok)", run["ok"])
# Validierung: ein kaputtes Plugin wird abgelehnt, nicht geladen
import antbb.sdk as sdk, tempfile
tmpd = tempfile.mkdtemp()
open(os.path.join(tmpd,"bad.py"),"w").write(
    "from antbb.sdk import CheckPlugin\nclass Bad(CheckPlugin):\n    name=''\n")
rep = sdk.discover_plugins(tmpd)
check("ungültiges Plugin wird abgelehnt (Validierung)", len(rep.plugins)==0 and len(rep.errors)>=1)
# Registry enthält Plugins
reg = svc.capabilities(rebuild=True)
check("Registry enthält plugins-Block", "plugins" in reg and reg["plugins"]["plugin_count"]>=1)

# ---------------------------------------------------------------- 4) Replay/Checkpoint
banner("TEST 4: Replay-/Checkpoint-Engine (checkpoint, pause, resume, replay)")
rec = svc.checkpoint_recorder("ck-run-1", tid, phases=["recon","scan"], meta={"active":False})
rec.phase("recon"); rec.event("recon startet", phase="recon", agent="recon")
rec.finding({"title":"Reflected XSS","category":"xss-verified","severity":"high",
             "asset":"http://example.com/search","status":"VERIFIZIERT","agent":"scanning"},
            phase="scan", agent="scanning")
rec.pause()
cps = svc.checkpoints_list(tid)
check("Checkpoint gelistet", any(c["run_id"]=="ck-run-1" for c in cps))
check("Status paused nach pause()", any(c["run_id"]=="ck-run-1" and c["status"]=="paused" for c in cps))
rr = svc.checkpoint_resume("ck-run-1")
check("resume setzt status=running", rr["status"]=="running")
emitted=[]
rp = svc.checkpoint_replay("ck-run-1", emit=lambda ev: emitted.append(ev))
check("replay re-emittiert Schritte deterministisch", rp["step_count"]>=3 and rp["findings"]==1)
check("replay emit-Events tragen replay=True", all(e.get("replay") for e in emitted))
# Determinismus: zweiter Replay identisch
emitted2=[]
svc.checkpoint_replay("ck-run-1", emit=lambda ev: emitted2.append(ev))
check("replay deterministisch (gleiche Schrittzahl)", len(emitted)==len(emitted2))

# ---------------------------------------------------------------- 5) DAG attackpath
banner("TEST 5: DAG-Angriffspfad-Visualisierung (nur Darstellung, kein Executor)")
import antbb.attackpath as apmod
g = svc.attack_graph(tid)
check("Graph hat Knoten + Kanten", len(g["nodes"])>=4 and len(g["edges"])>=3)
check("internet-Wurzelknoten vorhanden", any(n["id"]=="internet" for n in g["nodes"]))
check("ALLE Kanten hypothetisch markiert", all(e["hypothetical"] for e in g["edges"]))
check("jede Kante hat Remediation", all(e.get("remediation") for e in g["edges"]))
check("Pfadliste vorhanden", len(g["paths"])>=1)
check("Note betont: kein Pfad-Ausführen", "exploit" in g["note"].lower() or "führt keinen" in g["note"].lower())
md = svc.attack_paths_markdown(tid)
check("Markdown-Pfadliste nicht leer", len(md)>40 and "hypothetisch" in md.lower())
# Leerzustand ehrlich
tid2 = svc.add_target("leer","ohne findings")
g2 = svc.attack_graph(tid2)
check("leeres Target → empty=True", g2["empty"] is True)

svc.close()

# ---------------------------------------------------------------- Web routes
banner("TEST 6: Web-Routen (FastAPI TestClient)")
from fastapi.testclient import TestClient
from antbb.web.app import app
c = TestClient(app)
r = c.get(f"/api/targets/{tid}/firewall"); check("/firewall 200 + plan", r.status_code==200 and "plan" in r.json())
r = c.get(f"/api/targets/{tid}/attackpath"); check("/attackpath 200", r.status_code==200 and "nodes" in r.json())
r = c.get(f"/target/{tid}/branded-report?company=WebCo"); check("/branded-report HTML 200", r.status_code==200 and "WebCo" in r.text)
r = c.get("/api/plugins"); check("/api/plugins 200", r.status_code==200 and r.json()["plugin_count"]>=1)
r = c.get(f"/api/targets/{tid}/checkpoints"); check("/checkpoints 200", r.status_code==200)
r = c.get(f"/target/{tid}/attackpath"); check("/target attackpath page 200 + JS", r.status_code==200 and "attackpath.js" in r.text)

print("\n"+"="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
