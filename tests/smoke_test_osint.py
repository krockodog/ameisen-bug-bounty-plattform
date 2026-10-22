"""Smoke-Test: OSINT Username-Enumeration (sherlock primaer, maigret Fallback).

Rein lokal, ohne Netz/externe Tools (honest-empty-Pfad):
 - Kali-Adapter-Funktionen vorhanden (sherlock/maigret/username_enum)
 - TOOL_SPECS-Eintraege + Registry-Task-Katalog
 - Playbook 'username-enumeration' am osint-Soldaten registriert
 - honest-empty wenn Tool fehlt (KEINE erfundenen Treffer)
 - Parser arbeitet korrekt auf eingebettetem sherlock-Beispiel-Output
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asyncio, os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_osint_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
if os.path.exists("/tmp/antbb_osint_smoke.db"):
    os.remove("/tmp/antbb_osint_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from antbb.tools import kali
from antbb.agents.base import AgentContext, STATUS_REFERENCE
import logging as _l

# ------------------------------------------------------------- A: Adapter + specs
banner("TEST A: Adapter-Schicht + TOOL_SPECS")
check("sherlock in TOOL_SPECS (nicht offensiv)",
      "sherlock" in kali.TOOL_SPECS and kali.TOOL_SPECS["sherlock"]["offensive"] is False)
check("maigret in TOOL_SPECS (nicht offensiv)",
      "maigret" in kali.TOOL_SPECS and kali.TOOL_SPECS["maigret"]["offensive"] is False)
ctx = AgentContext(run_id="t", scope_check=lambda a: True, logger=_l.getLogger("t"))
ka = kali.KaliAdapter(ctx)
check("KaliAdapter.sherlock vorhanden", hasattr(ka, "sherlock"))
check("KaliAdapter.maigret vorhanden", hasattr(ka, "maigret"))
check("KaliAdapter.username_enum vorhanden", hasattr(ka, "username_enum"))

# ------------------------------------------------------------- B: honest-empty
banner("TEST B: honest-empty ohne installiertes Tool (kein Fake)")
async def _enum():
    return (await ka.sherlock("octocat"), await ka.maigret("octocat"),
            await ka.username_enum("octocat"))
r_sh, r_mg, r_ue = asyncio.run(_enum())
tool_present = bool(kali.which("sherlock") or kali.which("maigret"))
if not tool_present:
    check("sherlock honest-empty (keine Tools)", r_sh == [])
    check("maigret honest-empty (keine Tools)", r_mg == [])
    check("username_enum honest-empty (keine Tools)", r_ue == [])
else:
    check("Tool installiert -> Ergebnis ist Liste (kein Crash)",
          isinstance(r_sh, list) and isinstance(r_ue, list))

# invalid username wird abgelehnt
async def _bad(): return await ka.sherlock("bad name/../x")
check("ungueltiger Username -> [] (kein Lauf)", asyncio.run(_bad()) == [])

# ------------------------------------------------------------- C: Parser
banner("TEST C: Parser auf eingebettetem sherlock/maigret-Beispiel")
SAMPLE = """[*] Checking username octocat on:
[+] GitHub: https://github.com/octocat
[+] Instagram: https://instagram.com/octocat
[-] Twitter: Not Found!
[+] Reddit: https://www.reddit.com/user/octocat
[+] GitHub: https://github.com/octocat
"""
recs = kali._parse_username_enum(SAMPLE)
check("Parser findet 3 eindeutige Treffer (dedupe)", len(recs) == 3)
check("Parser ignoriert 'Not Found' Zeilen", all(r["claimed_present"] for r in recs))
check("Parser extrahiert site+url", recs[0]["site"] == "GitHub"
      and recs[0]["url"] == "https://github.com/octocat")
fnds = kali._records_to_findings(recs, "octocat", tool="sherlock",
                                 agent="osint", command="sherlock octocat")
check("records_to_findings -> 1 Finding", len(fnds) == 1)
check("Finding Status REFERENZ (informational)", fnds[0].status == STATUS_REFERENCE)
check("Finding severity info", fnds[0].severity == "info")
check("Evidence enthaelt strukturierte sites", len(fnds[0].evidence["sites"]) == 3)
check("leere Records -> keine Findings (kein Fake)",
      kali._records_to_findings([], "x", tool="sherlock", agent="osint", command="") == [])

# ------------------------------------------------------------- D: Playbook/Registry
banner("TEST D: Playbook registriert + Registry-Task-Katalog + Neural Brain")
from antbb.agents.osint import OsintHunterAnt
pb_names = [pb.name for pb in OsintHunterAnt.playbooks]
check("Playbook 'username-enumeration' am osint-Soldaten", "username-enumeration" in pb_names)
pb = next(p for p in OsintHunterAnt.playbooks if p.name == "username-enumeration")
check("Playbook defensiv, kein Oversight", pb.mode == "defensive" and pb.oversight_required is False)
check("Playbook listet sherlock+maigret", "sherlock" in pb.tools and "maigret" in pb.tools)
from antbb import registry
check("TASK_CATALOG hat username-enumeration", "username-enumeration" in registry.TASK_CATALOG)
reg = registry.build_registry()
osint_sol = next(s for s in reg["soldiers"] if s["name"] == "osint")
reg_pbs = [p["name"] for p in osint_sol["playbooks"]]
check("Registry/Neural Brain fuehrt username-enumeration", "username-enumeration" in reg_pbs)
ue = next(p for p in osint_sol["playbooks"] if p["name"] == "username-enumeration")
check("Neural Brain: Playbook hat task_items", len(ue["task_items"]) > 0)
check("Registry kennt sherlock+maigret als Tools",
      "sherlock" in reg["kali_tools"] and "maigret" in reg["kali_tools"])

# ------------------------------------------------------------- E: Service + CLI path
banner("TEST E: Service osint_username (honest-empty-Pfad)")
from antbb.service import AntBBService
svc = AntBBService()
out = svc.osint_username("octocat")
check("service.osint_username liefert dict", isinstance(out, dict) and "results" in out)
if not tool_present:
    check("service honest-empty (available=False, results=[])",
          out["available"] is False and out["results"] == [])
else:
    check("service: results ist Liste", isinstance(out["results"], list))
svc.close()

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
