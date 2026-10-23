"""Neuronales Gehirn der Königin — Node-/Log-Lesezugriff + HUMAN-ONLY
Lösch-/Reset-Operationen.

Blue Queen (colony=blue) hat eine eigene Ansicht unter /blue und erscheint
nicht im Brain-Graph.

================================ WICHTIG =================================
Die LÖSCH- und RESET-Funktionen in diesem Modul sind AUSSCHLIESSLICH für
einen Menschen über die Neuronales-Gehirn-GUI gedacht ("human-only").

  * Jede Lösch-/Reset-Operation verlangt ein ausdrückliches menschliches
    Bestätigungs-Flag (``human_confirm is True``). Dieses Flag setzt NUR der
    interaktive Web-UI-Handler nach einem Confirm-Dialog der Nutzerin.
  * Weder Soldaten noch die Königin (queen.py) noch die Agenten-Fassade in
    service.py dürfen diese Funktionen erreichen — sie importieren dieses
    Modul nicht und haben auf Logs/Läufe/Funde/Ziele nur LESENDEN Zugriff.
  * Ein Aufruf ohne gesetztes Bestätigungs-Flag wird HART abgelehnt
    (HumanConfirmError) und zusätzlich in data/brain_audit.log protokolliert.
  * Vor jeder harten Löschung ODER jedem Reset wird automatisch eine
    Zeitstempel-Sicherung von data/antbb.db nach data/backups/ angelegt,
    damit ein versehentlicher Purge wiederherstellbar ist.
  * antbb.env / Secrets werden NIE angefasst oder gesichert.
=========================================================================
"""
from __future__ import annotations

import datetime as _dt
import os
import shutil
import time
from typing import Callable, Optional

from .store import Store

# Wortlaut, den die GUI im Confirm-Dialog zeigt und bestätigt.
HUMAN_CONFIRM_PROMPT = (
    "Human-Only Löschen/Zurücksetzen: Ich bestätige als verantwortlicher Mensch "
    "diese endgültige Aktion im Neuronalen Gehirn. (Automatisches DB-Backup wird "
    "angelegt. Agenten/Königin dürfen dies NICHT auslösen.)"
)


class HumanConfirmError(PermissionError):
    """Wird geworfen, wenn eine Lösch-/Reset-Operation ohne ausdrückliches
    menschliches Bestätigungs-Flag versucht wird (default-deny)."""


def _is_blue_agent(name: Optional[str]) -> bool:
    """Blue-Queen-Soldaten (colony=blue) – gehören NICHT ins Neuronale Gehirn."""
    n = (name or "").strip().lower()
    return n.startswith("blue-") or n.startswith("blue_")


def _is_blue_run_id(run_id: Optional[str]) -> bool:
    """Blue-Queen-Läufe (run_id blue-…) – eigene Ansicht /blue, nicht /brain."""
    r = (run_id or "").strip().lower()
    return r.startswith("blue-") or r.startswith("blue_")



def _audit_path(store: Store) -> str:
    return os.path.join(os.path.dirname(store.db_path), "brain_audit.log")


def _audit(store: Store, line: str) -> None:
    """Hängt eine Audit-Zeile an (NIE Secrets). Best-effort."""
    try:
        ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(_audit_path(store), "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {line}\n")
    except Exception:
        pass


def _require_human(store: Store, human_confirm, action: str) -> None:
    """HARTES, serverseitiges Default-Deny-Gate: human_confirm MUSS True sein.

    Dieser Guard lehnt JEDE Lösch-/Reset-Anfrage ohne menschliches
    Bestätigungs-Flag ab und protokolliert die Ablehnung. Er ist die einzige
    Pforte zu allen destruktiven Primitiven unten."""
    if human_confirm is not True:
        _audit(store, f"REJECT (kein Human-Confirm) · aktion={action} · "
                      f"flag={human_confirm!r}")
        raise HumanConfirmError(
            "BLOCKIERT (human-only): Diese Lösch-/Reset-Aktion darf NUR ein "
            "Mensch aus der Neuronales-Gehirn-GUI mit Bestätigung auslösen. "
            "Agenten und die Königin haben nur Lesezugriff.\n"
            f'  Bitte bestätigen: "{HUMAN_CONFIRM_PROMPT}"')


def backup_db(store: Store) -> str:
    """Zeitstempel-Sicherung von antbb.db nach data/backups/. Gibt den Pfad
    zurück. antbb.env / Secrets werden NIE kopiert."""
    db = store.db_path
    bdir = os.path.join(os.path.dirname(db), "backups")
    os.makedirs(bdir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(bdir, f"{os.path.basename(db)}.bak-{stamp}")
    # Konsistente Online-Sicherung über die SQLite-Backup-API (offene Conn).
    try:
        import sqlite3
        with sqlite3.connect(dest) as bck:
            store._conn.backup(bck)  # type: ignore[attr-defined]
    except Exception:
        # Fallback: Dateikopie (DB ist klein, WAL hier nicht aktiv).
        shutil.copy2(db, dest)
    return dest


def _fmt(ts: Optional[float]) -> str:
    """Epoch -> lesbarer Zeitstempel in Box-lokaler Zeit (Europe/Berlin)."""
    if not ts:
        return ""
    try:
        return _dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ===================================================================
# LESEN (für alle erlaubt — Agenten/Queen/UI): Nodes, Node-Detail, Logs
# ===================================================================
_RUNNING = ("running", "paused", "queued", "stuck")


def _run_node_status(status: str) -> str:
    if status in ("running", "queued"):
        return "läuft"
    if status in ("paused", "stuck"):
        return "hängt"
    if status == "reset":
        return "zurückgesetzt"
    return status or "unbekannt"


def nodes_graph(store: Store, log_cap: int = 50) -> dict:
    """Vollständiger Node-Graph: Targets, Runs, Findings, Soldaten, Log-Gruppen.

    Reiner Lesezugriff aus dem echten Store (keine erfundenen Daten)."""
    from . import registry as registry_mod
    nodes: list[dict] = []
    edges: list[dict] = []

    targets = store.list_targets(include_archived=True)
    for t in targets:
        tid = int(t["id"])
        nid = f"target:{tid}"
        fcount = store.count_findings(tid)
        runs = store.list_scan_runs(tid)
        nodes.append({
            "id": nid, "type": "target", "label": t["name"],
            "status": "archiviert" if t["archived_at"] else "aktiv",
            "severity": None,
            "counts": {"findings": fcount, "runs": len(runs),
                       "scopes": store.count_scopes(tid)},
            "created_at": t["created_at"], "created_fmt": _fmt(t["created_at"]),
        })

    # Runs (je Target) + Log-Gruppen-Node je Run — Blue-Queen-Läufe auslassen
    for r in store.list_scan_runs():
        rid = str(r["run_id"])
        if _is_blue_run_id(rid):
            continue
        nid = f"run:{rid}"
        tnid = f"target:{int(r['target_id'])}"
        steps = store.count_run_steps(rid)
        nodes.append({
            "id": nid, "type": "run", "label": rid[:18],
            "status": _run_node_status(r["status"]),
            "raw_status": r["status"], "severity": None,
            "running": r["status"] in _RUNNING,
            "counts": {"logs": steps},
            "started_at": r["started_at"], "started_fmt": _fmt(r["started_at"]),
            "finished_at": r["finished_at"], "finished_fmt": _fmt(r["finished_at"]),
        })
        edges.append({"from": tnid, "to": nid, "kind": "target-run"})

    # Findings (gekappt pro Aufruf für vernünftige Payload)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    soldier_seen: set[str] = set()
    # Brain = offensive Kolonie. Blue Queen bleibt unter /blue.
    all_findings = [f for f in store.list_findings()
                    if not _is_blue_agent(f["agent"])
                    and not _is_blue_run_id(f["run_id"] if "run_id" in f.keys() else None)]
    for f in all_findings[:400]:
        fid = int(f["id"])
        nid = f"finding:{fid}"
        tnid = f"target:{int(f['target_id'])}"
        agent = f["agent"] or "unbekannt"
        nodes.append({
            "id": nid, "type": "finding", "label": (f["title"] or "")[:40],
            "status": f["status"] or "", "severity": f["severity"],
            "agent": agent, "counts": {},
            "created_at": f["created_at"], "created_fmt": _fmt(f["created_at"]),
        })
        edges.append({"from": tnid, "to": nid, "kind": "target-finding"})
        snid = f"soldier:{agent}"
        edges.append({"from": snid, "to": nid, "kind": "soldier-finding"})
        soldier_seen.add(agent)

    # Soldaten/Capabilities — Blue Queen (colony=blue) hat eigene Ansicht /blue.
    try:
        reg = registry_mod.build_registry(include_blue=False)
        for s in reg.get("soldiers", []):
            name = s.get("name", "")
            if _is_blue_agent(name) or s.get("colony") == "blue":
                continue
            snid = f"soldier:{name}"
            fcount = sum(1 for f in all_findings if (f["agent"] or "") == name)
            nodes.append({
                "id": snid, "type": "soldier", "label": name,
                "status": "aktiv", "severity": None,
                "counts": {"findings": fcount,
                           "playbooks": len(s.get("skill", {}).get("playbooks", []))},
            })
            soldier_seen.discard(name)
    except Exception:
        pass
    # Soldaten, die Funde haben, aber nicht in der Registry stehen
    for name in sorted(soldier_seen):
        if _is_blue_agent(name):
            continue
        nodes.append({"id": f"soldier:{name}", "type": "soldier", "label": name,
                      "status": "aktiv", "severity": None, "counts": {}})

    stuck = [str(r["run_id"]) for r in store.list_stuck_runs()
             if not _is_blue_run_id(str(r["run_id"]))]
    counts = {
        "targets": len(targets),
        "runs": len(store.list_scan_runs()),
        "findings": store.count_findings(),
        "logs": store.count_logs(),
        "stuck_runs": len(stuck),
    }
    return {"nodes": nodes, "edges": edges, "counts": counts,
            "stuck_runs": stuck, "generated_fmt": _fmt(time.time())}


def node_detail(store: Store, ntype: str, nid: str) -> dict:
    """Detail für einen Node inkl. zugehöriger Logs/Evidence. Reiner Lesezugriff."""
    import json as _json
    if ntype == "target":
        t = store.get_target(int(nid))
        if not t:
            return {"ok": False, "reason": "not_found"}
        findings = [dict(f) for f in store.list_findings(int(nid))]
        runs = [dict(r) for r in store.list_scan_runs(int(nid))]
        return {"ok": True, "type": "target", "target": dict(t),
                "finding_count": len(findings),
                "findings": [{"id": f["id"], "title": f["title"],
                              "severity": f["severity"], "status": f["status"],
                              "agent": f["agent"], "asset": f["asset"]}
                             for f in findings[:100]],
                "runs": [{"run_id": r["run_id"], "status": r["status"],
                          "started_fmt": _fmt(r["started_at"])} for r in runs]}
    if ntype == "run":
        r = store.get_scan_run(nid)
        if not r:
            return {"ok": False, "reason": "not_found"}
        logs = store.list_logs(run_id=nid, limit=500)
        return {"ok": True, "type": "run", "run": dict(r),
                "running": r["status"] in _RUNNING,
                "status_label": _run_node_status(r["status"]),
                "log_count": store.count_logs(run_id=nid),
                "logs": [_log_row(l) for l in logs]}
    if ntype == "finding":
        f = store.get_finding(int(nid))
        if not f:
            return {"ok": False, "reason": "not_found"}
        d = dict(f)
        try:
            d["evidence"] = _json.loads(d.get("evidence") or "{}")
        except Exception:
            pass
        logs = store.list_logs(run_id=f["run_id"], limit=200)
        d["created_fmt"] = _fmt(f["created_at"])
        return {"ok": True, "type": "finding", "finding": d,
                "logs": [_log_row(l) for l in logs]}
    if ntype == "soldier":
        if _is_blue_agent(nid):
            return {"ok": False, "reason": "blue_queen_separate",
                    "hint": "Blue Queen hat eigene Ansicht unter /blue"}
        findings = [f for f in store.list_findings()
                    if (f["agent"] or "") == nid and not _is_blue_run_id(
                        f["run_id"] if "run_id" in f.keys() else None)]
        # Playbooks + SKILL.md aus der Capability-Registry.
        role = specialty = ""
        colony = None
        playbooks: list = []
        skill: dict = {}
        try:
            from . import registry as _reg
            sol = next((s for s in _reg.build_registry(include_blue=False)["soldiers"]
                        if s.get("name") == nid), None)
            if sol:
                role = sol.get("role") or ""
                specialty = sol.get("specialty") or ""
                colony = sol.get("colony")
                playbooks = list(sol.get("playbooks") or [])
                skill = dict(sol.get("skill") or {})
        except Exception:
            pass
        return {"ok": True, "type": "soldier", "name": nid,
                "role": role, "specialty": specialty, "colony": colony,
                "playbooks": playbooks, "skill": skill,
                "playbook_count": len(playbooks),
                "finding_count": len(findings),
                "findings": [{"id": f["id"], "title": f["title"],
                              "severity": f["severity"], "status": f["status"],
                              "target_id": f["target_id"]} for f in findings[:100]]}
    return {"ok": False, "reason": "unknown_type"}


def _log_row(l) -> dict:
    import json as _json
    try:
        payload = _json.loads(l["payload"] or "{}")
    except Exception:
        payload = {}
    return {"id": l["id"], "run_id": l["run_id"], "seq": l["seq"],
            "phase": l["phase"], "agent": l["agent"], "kind": l["kind"],
            "target_id": l["target_id"] if "target_id" in l.keys() else None,
            "msg": payload.get("msg", ""), "payload": payload,
            "created_at": l["created_at"], "created_fmt": _fmt(l["created_at"])}


def logs_page(store: Store, target_id: Optional[int] = None,
              run_id: Optional[str] = None, limit: int = 200,
              offset: int = 0) -> dict:
    """Vollständige Logs (scan_steps), neueste zuerst, filter-/paginierbar."""
    limit = max(1, min(int(limit), 1000))
    rows = store.list_logs(target_id=target_id, run_id=run_id,
                           limit=limit, offset=int(offset))
    total = store.count_logs(target_id=target_id, run_id=run_id)
    return {"logs": [_log_row(l) for l in rows], "total": total,
            "limit": limit, "offset": int(offset),
            "target_id": target_id, "run_id": run_id}


# ===================================================================
# HUMAN-ONLY: Löschen / Reset  (jede Funktion verlangt human_confirm=True)
# ===================================================================
def delete_logs(store: Store, *, human_confirm, target_id: Optional[int] = None,
                run_id: Optional[str] = None, all_logs: bool = False,
                actor: str = "web-ui") -> dict:
    """Löscht Log-Zeilen (scan_steps). Human-only (siehe Modul-Kopf)."""
    _require_human(store, human_confirm, "delete_logs")
    backup = backup_db(store)
    n = store.purge_logs(target_id=target_id, run_id=run_id, all_logs=all_logs)
    _audit(store, f"DELETE logs · actor={actor} · target={target_id} · "
                  f"run={run_id} · all={all_logs} · deleted={n} · backup={os.path.basename(backup)}")
    return {"ok": True, "deleted": {"logs": n}, "backup": backup}


def delete_run(store: Store, run_id: str, *, human_confirm,
               actor: str = "web-ui") -> dict:
    """Löscht EINEN Lauf samt Log-Zeilen (CASCADE). Human-only."""
    _require_human(store, human_confirm, "delete_run")
    backup = backup_db(store)
    steps = store.count_run_steps(run_id)
    existed = store.get_scan_run(run_id) is not None
    store.delete_scan_run(run_id)
    _audit(store, f"DELETE run · actor={actor} · run={run_id} · "
                  f"steps={steps} · existed={existed} · backup={os.path.basename(backup)}")
    return {"ok": existed, "deleted": {"runs": 1 if existed else 0,
            "logs": steps}, "backup": backup}


def delete_finding(store: Store, finding_id: int, *, human_confirm,
                   actor: str = "web-ui") -> dict:
    """Löscht EIN Finding. Human-only."""
    _require_human(store, human_confirm, "delete_finding")
    backup = backup_db(store)
    n = store.delete_finding(finding_id)
    _audit(store, f"DELETE finding · actor={actor} · id={finding_id} · "
                  f"deleted={n} · backup={os.path.basename(backup)}")
    return {"ok": bool(n), "deleted": {"findings": n}, "backup": backup}


def delete_target(store: Store, target_id: int, *, human_confirm,
                  actor: str = "web-ui") -> dict:
    """HARTE Löschung (Purge) EINES Targets samt CASCADE (Scopes/Findings/
    Reports/Scan-Historie/Oversight). Unterscheidet sich ausdrücklich vom
    Soft-Delete/Papierkorb (archive_target). Königin-Wissen (Registry/Mems/
    Overrides) bleibt erhalten. Human-only."""
    _require_human(store, human_confirm, "delete_target")
    backup = backup_db(store)
    t = store.get_target(int(target_id))
    label = t["name"] if t else ""
    fcount = store.count_findings(int(target_id)) if t else 0
    store.delete_target(int(target_id))
    _audit(store, f"DELETE target (HARD purge) · actor={actor} · id={target_id} · "
                  f"name={label} · findings={fcount} · backup={os.path.basename(backup)}")
    return {"ok": bool(t), "deleted": {"targets": 1 if t else 0,
            "findings": fcount, "name": label}, "backup": backup}


def delete_all(store: Store, *, human_confirm, actor: str = "web-ui") -> dict:
    """Wischt ALLE operativen Daten. Königin-Wissen bleibt erhalten. Human-only."""
    _require_human(store, human_confirm, "delete_all")
    backup = backup_db(store)
    counts = store.wipe_operational()
    _audit(store, f"DELETE ALL (operational wipe) · actor={actor} · "
                  f"counts={counts} · backup={os.path.basename(backup)}")
    return {"ok": True, "deleted": counts, "backup": backup,
            "preserved": ["capabilities", "soldier_mems", "soldier_overrides",
                          "settings"]}


def reset_run(store: Store, run_id: str, *, human_confirm,
              actor: str = "web-ui") -> dict:
    """Setzt einen laufenden/hängenden Lauf zurück (Status 'reset', unfertige
    scan_steps verworfen). Fertige Läufe/Funde/Königin-Wissen bleiben
    unangetastet. Human-only."""
    _require_human(store, human_confirm, "reset_run")
    backup = backup_db(store)
    res = store.reset_scan_run(run_id)
    res["backup"] = backup
    _audit(store, f"RESET run · actor={actor} · run={run_id} · "
                  f"result={res.get('ok')}/{res.get('reason','')} · "
                  f"steps_discarded={res.get('steps_discarded')} · "
                  f"backup={os.path.basename(backup)}")
    return res
