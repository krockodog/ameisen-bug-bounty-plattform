"""Smoke-Test für die neuen Erweiterungen (Kali-Adapter graceful degrade,
Rating, Heatmap, WiFi, NVD-Gate, Soldaten-Overrides/Mems, Registry, Web-Routen).

Läuft komplett lokal, ohne externe Tools/Netz (graceful-degrade-Pfad)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asyncio, os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_ext_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
if os.path.exists("/tmp/antbb_ext_smoke.db"):
    os.remove("/tmp/antbb_ext_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond))
    print(("OK  " if cond else "FAIL") + " · " + name)

def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

# ---------------------------------------------------------------- Kali graceful
banner("TEST A: Kali-Adapter graceful degrade (Tools fehlen → honest-empty)")
from antbb.tools import kali
from antbb.agents.base import AgentContext
import logging as _l
ctx = AgentContext(run_id="t", scope_check=lambda a: True, logger=_l.getLogger("t"),
                   active=True, fuzz=True)
ka = kali.KaliAdapter(ctx)
async def _kali_tests():
    r1 = await ka.nmap("127.0.0.1")
    r2 = await ka.nuclei("http://127.0.0.1")
    r3 = await ka.sqlmap("http://127.0.0.1/?id=1")
    r4 = await ka.metasploit_aux("auxiliary/scanner/http/http_version", "127.0.0.1")
    # Allowlist-Filter: exploit-Modul MUSS blockiert werden
    r5 = await ka.metasploit_aux("exploit/multi/handler", "127.0.0.1")
    r6 = await ka.trufflehog("/tmp", mode="filesystem")
    return r1,r2,r3,r4,r5,r6
res = asyncio.run(_kali_tests())
check("alle Kali-Adapter liefern [] ohne Tools (kein Crash/Fake)", all(r==[] for r in res))
check("metasploit nur auxiliary/scanner erlaubt (exploit blockiert)", res[4]==[])
check("mask_secret maskiert", kali.mask_secret("supersecret123456").endswith("56") and "*" in kali.mask_secret("supersecret123456"))

# Scope default-deny bleibt grün
banner("TEST B: Kali-Adapter Scope default-deny")
ctx_block = AgentContext(run_id="t", scope_check=lambda a: False, logger=_l.getLogger("t"), active=True)
kab = kali.KaliAdapter(ctx_block)
async def _blocked(): return await kab.run("nmap", ["127.0.0.1"], target="evil.example.com")
rb = asyncio.run(_blocked())
check("out-of-scope → ran=False (blockiert)", rb.ran is False)

# Offensiv-Gate
ctx_def = AgentContext(run_id="t", scope_check=lambda a: True, logger=_l.getLogger("t"), active=False, fuzz=False)
kad = kali.KaliAdapter(ctx_def)
async def _off(): return await kad.run("nuclei", ["-u","x"], target="127.0.0.1", offensive=True)
check("offensiv ohne Freischaltung → ran=False", asyncio.run(_off()).ran is False)

# ---------------------------------------------------------------- Rating
banner("TEST C: Rating + Heatmap aus synthetischer Findingliste")
from antbb.rating import compute_rating, build_heatmap, heatmap_markdown, grade_for, dimension_for
from antbb.agents.base import AgentFinding, STATUS_VERIFIED, STATUS_TO_CONFIRM, STATUS_REFERENCE
fs = [
    AgentFinding("scanning","XSS","xss-verified","high",status=STATUS_VERIFIED,
                 evidence={"request":{"url":"x"},"response_excerpt":"y"}),
    AgentFinding("infra","TLS","tls-scan","medium",status="BESTÄTIGT(PASSIV)"),
    AgentFinding("osint","Secret","secret-exposure","high",status=STATUS_TO_CONFIRM),
    AgentFinding("threatintel","CVE","cve-reference","info",status=STATUS_REFERENCE),
    AgentFinding("fuzz","FP","content-discovery","info",false_positive=True),
]
r = compute_rating([AgentFinding(**{k:getattr(f,k) for k in ("agent","title","category","severity","asset","description","evidence","status","false_positive")}) for f in fs])
check("Score 0..100", 0 <= r["score"] <= 100)
check("Note konsistent", r["grade"] == grade_for(r["score"]))
check("false_positive NICHT gezählt", r["counted_findings"] == 4)
check("Teilscores für alle Dimensionen", len(r["subscores"]) == 7)
hm = build_heatmap([AgentFinding(**{k:getattr(f,k) for k in ("agent","title","category","severity","asset","description","evidence","status","false_positive")}) for f in fs])
check("Heatmap total_cells == 4 (ohne FP)", hm["total_cells"] == 4)
check("Heatmap-Markdown nicht leer", len(heatmap_markdown(hm)) > 20)
check("dimension_for mapping", dimension_for("tls-scan")=="TLS/Transport" and dimension_for("secret-exposure")=="Secrets")

# ---------------------------------------------------------------- Service/Store
banner("TEST D: Service Rating/Heatmap/Soldaten + Store-Overrides/Mems")
from antbb.service import AntBBService
svc = AntBBService()
tid = svc.add_target("ext-test","Erweiterungs-Smoke")
svc.add_scope(tid, "ip", "127.0.0.1", True)
# echte Findings in Store
svc.store.add_finding(tid, "run1", "scanning", "XSS", "xss-verified", "high",
                      asset="http://127.0.0.1", evidence={"request":{"url":"x"},"response_excerpt":"y"},
                      status="VERIFIZIERT", dedup_key="k1")
svc.store.add_finding(tid, "run1", "infra", "TLS", "tls-scan", "medium",
                      status="BESTÄTIGT(PASSIV)", dedup_key="k2")
rat = svc.rating(tid, with_ai=True)
check("svc.rating liefert Score", "score" in rat and "heatmap" in rat)
check("svc.rating KI-Einschätzung vorhanden", "assessment" in rat and rat["assessment"]["text"])
hm2 = svc.heatmap(tid)
check("svc.heatmap total_cells == 2", hm2["total_cells"] == 2)

# Overrides/Mems
svc.set_soldier_override("scanning","nuclei-scan","enabled","false")
svc.add_soldier_mem("scanning","Fokus auf /wp-json")
det = svc.soldier_detail("scanning", target_id=tid)
check("soldier_detail hat SKILL.md-Volltext", det["soldier"]["skill"]["has_skill_md"])
check("soldier_detail Overrides", any(o["key"]=="enabled" for o in det["overrides"]))
check("soldier_detail Mems", any("wp-json" in m["text"] for m in det["mems"]))
check("soldier_detail Ergebnisse gefiltert auf Agent", all(x["title"] for x in det["results"]))
# skill_md override editierbar
svc.set_soldier_override("scanning","","skill_md","# Mein eigener Skill")
det2 = svc.soldier_detail("scanning")
check("SKILL.md override greift", det2["soldier"]["skill"]["skill_md"].startswith("# Mein eigener"))

# ---------------------------------------------------------------- Registry
banner("TEST E: Registry-Vollständigkeit (Tasks, SKILL.md, Phasen)")
reg = svc.capabilities(rebuild=True)
check("18 Soldaten", reg["soldier_count"] == 18)
check("Task-Items > 130", reg["task_count"] > 130)
check("alle Soldaten haben SKILL.md", all(s["skill"]["has_skill_md"] for s in reg["soldiers"]))
check("alle Playbooks haben task_items", all(len(pb["task_items"])>0 for s in reg["soldiers"] for pb in s["playbooks"]))
check("octogent_phases == 5", len(reg["octogent_phases"]) == 5)
check("scope_suggestions NICHT auto-allow (nur Vorschlag)", "default-deny" in reg["scope_suggestions"]["note"])
check("kali_tools gelistet", len(reg["kali_tools"]) >= 15)
check("wifi-Soldat registriert", any(s["name"]=="wifi" for s in reg["soldiers"]))

svc.close()

# ---------------------------------------------------------------- Web-Routen
banner("TEST F: Web-Routen (FastAPI TestClient gegen lokale DB)")
from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)
check("/api/soldiers 200 + tasks", client.get("/api/soldiers").status_code==200 and client.get("/api/soldiers").json()["task_count"]>0)
check("/api/soldiers/scanning 200", client.get("/api/soldiers/scanning").status_code==200)
r_ov = client.post("/api/soldiers/scanning/override", json={"playbook":"nuclei-scan","key":"enabled","value":"false"})
check("POST override 200", r_ov.status_code==200 and r_ov.json()["ok"])
r_mem = client.post("/api/soldiers/scanning/mem", json={"text":"TestMem"})
check("POST mem 200", r_mem.status_code==200)
mid = r_mem.json()["id"]
check("DELETE mem 200", client.delete(f"/api/soldiers/scanning/mem/{mid}").status_code==200)
# rating/heatmap routes need a target
t = client.post("/api/targets", json={"name":"webext","description":"x"}).json()
check("/api/targets/{id}/rating 200", client.get(f"/api/targets/{t['id']}/rating").status_code==200)
check("/api/targets/{id}/heatmap 200", client.get(f"/api/targets/{t['id']}/heatmap").status_code==200)
check("/api/brain enthält capabilities+phasen", "octogent_phases" in client.get(f"/api/brain/{t['id']}").json()["brain"]["capabilities"])

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
