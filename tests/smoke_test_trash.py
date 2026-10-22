"""Smoke-Test: Papierkorb / Soft-Delete für Targets im Scope-Manager.

Beweist:
  * archive() blendet ein Target aus der Default-Liste aus, aber Zeile,
    Findings, Scopes und Reports bleiben in der DB erhalten,
  * das Königin-Wissen (Capability-Registry/Neural-Brain) bleibt nach dem
    Archivieren unverändert,
  * archivierte Targets werden von aktiven Scans ausgeschlossen (run_scan wirft),
  * restore() holt das Target zurück in die aktive Liste,
  * die Web-Routen (POST archive/restore, GET /trash) arbeiten mit 303/200,
  * die harte Löschung (delete_target/Purge) das aggregierte Königin-Wissen
    NICHT reduziert (Registry bleibt vollständig).
Läuft lokal ohne LLM.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, json, logging, copy
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_trash_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
if os.path.exists("/tmp/antbb_trash_smoke.db"):
    os.remove("/tmp/antbb_trash_smoke.db")

OK = []
def check(name, cond):
    OK.append(bool(cond)); print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from antbb.service import AntBBService
svc = AntBBService()

banner("SETUP: Target mit Scope + Finding + Report anlegen")
tid = svc.add_target("trash-lab", "Papierkorb-Test")
svc.add_scope(tid, "ip", "127.0.0.1", allowed=True)
svc.store.add_finding(tid, run_id="r1", agent="recon", title="Testbefund",
                      category="misc", severity="low", asset="127.0.0.1",
                      description="x", evidence="{}", dedup_key="dk1")
fcount_before = len(svc.list_findings(tid))
scount_before = len(svc.list_scopes(tid))
check("Finding angelegt", fcount_before == 1)
check("Scope angelegt", scount_before == 1)

# Königin-Wissen VOR dem Archivieren einfrieren
cap_before = svc.capabilities(rebuild=True)
reg_sig_before = (cap_before["soldier_count"], cap_before["playbook_count"],
                  cap_before["tool_count"], cap_before["task_count"])

banner("TEST A: archive() blendet aus Default-Liste aus, Daten bleiben")
svc.archive_target(tid)
active_names = [t["name"] for t in svc.list_targets()]
check("Target NICHT mehr in Default-Liste", "trash-lab" not in active_names)
check("Target im Papierkorb (list_archived)", "trash-lab" in [t["name"] for t in svc.list_archived_targets()])
check("is_archived True", svc.is_archived(tid) is True)
# Daten unangetastet
check("Finding-Zeile bleibt erhalten", len(svc.list_findings(tid)) == fcount_before)
check("Scope-Zeile bleibt erhalten", len(svc.list_scopes(tid)) == scount_before)
check("Target-Zeile per get_target weiter erreichbar", svc.get_target(tid) is not None)

banner("TEST B: Königin-Wissen unverändert nach Archivieren")
cap_after = svc.capabilities(rebuild=True)
reg_sig_after = (cap_after["soldier_count"], cap_after["playbook_count"],
                 cap_after["tool_count"], cap_after["task_count"])
check("Registry-Signatur (soldiers/playbooks/tools/tasks) unverändert",
      reg_sig_before == reg_sig_after)

banner("TEST C: archivierte Targets von aktiven Scans ausgeschlossen")
threw = False
try:
    svc.run_scan(tid, active=False, fuzz=False)
except ValueError as e:
    threw = "archiviert" in str(e).lower()
check("run_scan auf archiviertem Target wirft/ blockt", threw)

banner("TEST D: restore() holt Target zurück")
svc.restore_target(tid)
check("Target wieder in Default-Liste", "trash-lab" in [t["name"] for t in svc.list_targets()])
check("is_archived False nach restore", svc.is_archived(tid) is False)
check("Papierkorb wieder leer", svc.list_archived_targets() == [])

banner("TEST E: Web-Routen (POST archive/restore 303, GET /trash 200)")
from fastapi.testclient import TestClient
from antbb.web.app import app
client = TestClient(app)
r = client.post(f"/target/{tid}/archive", follow_redirects=False)
check("POST archive -> 303", r.status_code == 303)
check("/ enthält trash-lab NICHT mehr", "trash-lab" not in client.get("/").text)
tr = client.get("/trash")
check("GET /trash -> 200", tr.status_code == 200)
check("/trash listet trash-lab", "trash-lab" in tr.text)
check("/trash erklärt: Königin behält Wissen", "Königin" in tr.text)
check("/ zeigt Papierkorb-Link", 'href="/trash"' in client.get("/").text)
r2 = client.post(f"/target/{tid}/restore", follow_redirects=False)
check("POST restore -> 303", r2.status_code == 303)
check("nach restore wieder in /", "trash-lab" in client.get("/").text)
check("Archivieren-Button in / sichtbar", "/archive" in client.get("/").text)

banner("TEST F: harte Löschung (Purge) reduziert Königin-Wissen NICHT")
cap_pre_purge = svc.capabilities(rebuild=True)
sig_pre = (cap_pre_purge["soldier_count"], cap_pre_purge["playbook_count"],
           cap_pre_purge["tool_count"], cap_pre_purge["task_count"])
svc.delete_target(tid)  # Purge (nicht in GUI; nur Store/CLI-fähig)
check("Target nach Purge weg", svc.get_target(tid) is None)
cap_post_purge = svc.capabilities(rebuild=True)
sig_post = (cap_post_purge["soldier_count"], cap_post_purge["playbook_count"],
            cap_post_purge["tool_count"], cap_post_purge["task_count"])
check("Registry-Signatur nach Purge unverändert (Wissen erhalten)",
      sig_pre == sig_post)

print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
