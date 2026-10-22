"""Smoke-Test: Neuronales Gehirn — Node-/Log-API, HUMAN-ONLY Löschen/Reset,
Auto-Backup, Secret-/Env-Schutz, Brain-Seite lädt (Partikelfeld bootstrappt).

Läuft komplett lokal gegen eine temporäre DB. Kein Kali, kein Live-Scan.
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, sys, logging
logging.basicConfig(level=logging.WARNING)
os.environ["ANTBB_DB"] = "/tmp/antbb_brain_smoke.db"
os.environ["ANTBB_NO_LLM"] = "1"
for p in ("/tmp/antbb_brain_smoke.db",):
    if os.path.exists(p):
        os.remove(p)

OK = []
def check(name, cond):
    OK.append(bool(cond))
    print(("OK  " if cond else "FAIL") + " · " + name)
def banner(t): print("\n" + "="*68 + "\n" + t + "\n" + "="*68)

from fastapi.testclient import TestClient
from antbb.web.app import app, svc
from antbb import brain_ops
client = TestClient(app)

DATA_DIR = os.path.dirname(svc.store.db_path)
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

def backups():
    return os.listdir(BACKUP_DIR) if os.path.isdir(BACKUP_DIR) else []

# --------------------------------------------------------------- Seed echte Daten
banner("SETUP: echte Zeilen in den Store schreiben")
tid = svc.add_target("brainsmoke", "lokal")
svc.add_scope(tid, "url", "http://127.0.0.1:8899", allowed=True)
f1 = svc.store.add_finding(tid, "run-A", "scanning", "Reflected XSS", "xss",
                           "high", asset="http://x/?q=1", status="VERIFIZIERT")
f2 = svc.store.add_finding(tid, "run-A", "api", "IDOR", "bola", "medium",
                           asset="http://x/api/1", status="zu bestätigen")
svc.store.create_scan_run("run-A", tid, phases=["recon"], status="running")  # hängend/laufend
svc.store.add_scan_step("run-A", "event", {"msg": "[scanning] startet Phase recon"},
                        phase="recon", agent="scanning")
svc.store.add_scan_step("run-A", "finding", {"msg": "xss gefunden"}, phase="scan",
                        agent="scanning")
svc.store.create_scan_run("run-DONE", tid, phases=["recon"], status="done")  # fertig
svc.store.add_scan_step("run-DONE", "status", {"msg": "fertig"}, agent="reporting")

# --------------------------------------------------------------- Nodes-API
banner("TEST A: /api/brain/nodes liefert ECHTE Zeilen")
n = client.get("/api/brain/nodes")
check("/api/brain/nodes 200", n.status_code == 200)
nb = n.json()
check("counts spiegeln echte Daten", nb["counts"]["targets"] >= 1 and
      nb["counts"]["findings"] >= 2 and nb["counts"]["runs"] >= 2)
check("hängender Lauf erkannt (stuck_runs enthält run-A)", "run-A" in nb["stuck_runs"])
types = set(x["type"] for x in nb["nodes"])
check("Node-Typen: target/run/finding/soldier vorhanden",
      {"target", "run", "finding", "soldier"} <= types)
run_node = next(x for x in nb["nodes"] if x["id"] == "run:run-A")
check("laufender Node hat Status 'läuft' + running=True",
      run_node["status"] == "läuft" and run_node["running"] is True)

banner("TEST B: Node-Detail + Logs")
d = client.get("/api/brain/node/run/run-A").json()
check("Run-Detail enthält Logs", d["ok"] and d["log_count"] == 2 and len(d["logs"]) == 2)
dt = client.get(f"/api/brain/node/target/{tid}").json()
check("Target-Detail listet Funde", dt["finding_count"] == 2)
lg = client.get("/api/brain/logs").json()
check("/api/brain/logs liefert alle Logs, neueste zuerst",
      lg["total"] == 3 and len(lg["logs"]) == 3)
lgf = client.get("/api/brain/logs?run_id=run-A").json()
check("Log-Filter nach run_id", lgf["total"] == 2)

# --------------------------------------------------------------- HUMAN-ONLY Gate
banner("TEST C: Löschen/Reset OHNE Human-Confirm wird abgelehnt (403) + geloggt")
before = svc.store.count_findings(tid)
r = client.delete(f"/api/brain/finding/{f2}")
check("DELETE finding ohne Confirm -> 403", r.status_code == 403)
check("Fund NICHT gelöscht", svc.store.count_findings(tid) == before)
check("reset ohne Confirm -> 403",
      client.post("/api/brain/run/run-A/reset").status_code == 403)
check("delete all ohne Confirm -> 403",
      client.delete("/api/brain/all").status_code == 403)
check("agent reset ohne Confirm -> 403",
      client.post("/api/brain/agent/scanning/reset").status_code == 403)
audit = os.path.join(DATA_DIR, "brain_audit.log")
check("Ablehnung protokolliert (brain_audit.log enthält REJECT)",
      os.path.exists(audit) and "REJECT" in open(audit, encoding="utf-8").read())

banner("TEST D: brain_ops direkt ohne Flag wirft HumanConfirmError (Kapselung)")
try:
    brain_ops.delete_finding(svc.store, f2, human_confirm=None)
    raised = False
except brain_ops.HumanConfirmError:
    raised = True
check("brain_ops.delete_finding(human_confirm=None) -> HumanConfirmError", raised)

banner("TEST E: Weder Service-Agenten-Fassade noch Queen kennen Delete/Reset")
import antbb.service as service_mod, antbb.queen as queen_mod
svc_src = open(service_mod.__file__, encoding="utf-8").read()
queen_src = open(queen_mod.__file__, encoding="utf-8").read()
check("service.py importiert brain_ops NICHT", "brain_ops" not in svc_src)
check("queen.py importiert brain_ops NICHT", "brain_ops" not in queen_src)
check("AntBBService hat keine brain-delete/-reset-Methode",
      not any(hasattr(svc, m) for m in
              ("delete_finding", "purge_logs", "reset_run", "delete_all")))

# --------------------------------------------------------------- Löschen MIT Confirm
banner("TEST F: Löschen MIT Human-Confirm wirkt gezielt + Auto-Backup")
nb_before = len(backups())
r = client.request("DELETE", f"/api/brain/finding/{f1}?human_confirm=true")
check("DELETE finding mit Confirm -> 200", r.status_code == 200 and r.json()["ok"])
check("nur das eine Finding weg (anderes bleibt)",
      svc.store.get_finding(f1) is None and svc.store.get_finding(f2) is not None)
check("Backup wurde angelegt", len(backups()) > nb_before)
check("Backup-Datei referenziert in Antwort", "bak-" in r.json()["backup"])

banner("TEST G: Reset eines hängenden Laufs (fertige Daten unberührt)")
r = client.post("/api/brain/run/run-A/reset?human_confirm=true").json()
check("reset ok, Status 'reset', Teil-Artefakte verworfen",
      r["ok"] and r["previous_status"] == "running" and r["steps_discarded"] == 2)
check("Lauf-Status nun 'reset'", svc.store.get_scan_run("run-A")["status"] == "reset")
check("fertiger Lauf run-DONE unverändert",
      svc.store.get_scan_run("run-DONE")["status"] == "done")
check("verbleibender Fund NICHT angetastet", svc.store.get_finding(f2) is not None)
# Reset eines fertigen Laufs wird höflich abgelehnt (kein Schaden)
r2 = client.post("/api/brain/run/run-DONE/reset?human_confirm=true").json()
check("reset eines fertigen Laufs -> ok=False (run_already_final)",
      r2["ok"] is False and r2["reason"] == "run_already_final")

banner("TEST H: Agent-Reset (nur In-Memory-Anzeige) human-only")
ra = client.post("/api/brain/agent/scanning/reset", headers={"x-human-confirm": "1"})
check("agent reset mit Confirm -> 200", ra.status_code == 200 and ra.json()["ok"])

banner("TEST I: Secrets/Env werden NIE angefasst; Backup enthält keine .env")
# brain_ops sichert ausschließlich die DB-Datei.
bak_files = backups()
check("Backups sind ausschließlich DB-Kopien (.bak-)",
      all(".bak-" in b for b in bak_files))
check("kein antbb.env im Daten-/Backup-Verzeichnis angelegt",
      not os.path.exists(os.path.join(BACKUP_DIR, "antbb.env")))

banner("TEST J: HARD delete target (Purge) unterscheidet sich vom Papierkorb")
tid2 = svc.add_target("purgeme", "x")
svc.store.add_finding(tid2, "run-Z", "scanning", "X", "x", "low")
pre_archived = len(svc.list_archived_targets())
rp = client.request("DELETE", f"/api/brain/target/{tid2}?human_confirm=true").json()
check("Target hart gelöscht (nicht im Papierkorb)",
      rp["ok"] and svc.get_target(tid2) is None and
      len(svc.list_archived_targets()) == pre_archived)

banner("TEST K: Brain-Seite lädt (Partikelfeld bootstrappt) + Panel-Assets 200")
pg = client.get("/brain")
html = pg.text
check("/brain 200", pg.status_code == 200)
check("brain-canvas + importmap + mount vorhanden",
      "brain-canvas" in html and "importmap" in html and "mount.js" in html)
check("Node-Panel + Löschen/Reset-Controls im Markup",
      "brain-panel" in html and "bp-del-all" in html and "nodes-panel.js" in html)
check("/static/brain/nodes-panel.js 200",
      client.get("/static/brain/nodes-panel.js").status_code == 200)
check("/static/brain/mount.js 200 (Engine unberührt)",
      client.get("/static/brain/mount.js").status_code == 200)
check("alte /api/brain/{target_id}-Route funktioniert weiter",
      client.get(f"/api/brain/{tid}").status_code == 200)

svc.close()
print("\n" + "="*68)
print(f"ERGEBNIS: {sum(OK)}/{len(OK)} Checks OK")
print("="*68)
sys.exit(0 if all(OK) else 1)
