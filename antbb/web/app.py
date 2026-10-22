"""FastAPI-Webserver: grafische Oberfläche + on-device Königin-Steuerung.

Die GUI ruft AUSSCHLIESSLICH die fest definierten antbb-Operationen über
AntBBService auf (Scope/Oversight/Scan/Report/Mode). Kein os.system, kein
subprocess mit nutzergesteuerten Strings, kein eval. Scans laufen asynchron
in einem Hintergrund-Thread; der Live-Feed wird per Polling abgeholt.
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..disclaimer import DISCLAIMER_TEXT, new_target_notice
from ..oversight import OVERSIGHT_PROMPT, OversightError
from ..active_oversight import (
    ACTIVE_LEGAL_NOTICE, ACTIVE_OVERSIGHT_PROMPT, active_trigger_requested,
    enforce_active_oversight,
)
from ..reports import CHAIN_STEPS, ReportDraft, empty_chain
from ..service import AntBBService
from ..oauth import OAuthError, TokenStore, provider_from_config
from .. import telemetry

BASE = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))

app = FastAPI(title="antbb – Ameisen-Schwarm Bug-Bounty (lokal)")
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

svc = AntBBService()

# ---- Optionale, anonyme Telemetrie (standardmäßig AUS; siehe antbb/telemetry.py) ----
@app.on_event("startup")
def _telemetry_startup() -> None:
    # Klarer Konsolen-Hinweis zum Status (an/aus) – nichts versteckt.
    print("[antbb] " + telemetry.status_line())
    # Heartbeat-Task startet NUR, wenn ANTBB_TELEMETRY_URL gesetzt und nicht abgeschaltet.
    telemetry.start_heartbeat()

# ---- On-device Scan-Zustand (kein Fernzugriff; nur lokaler Prozess) ----
LIVE_FEED: list[dict] = []
SCAN_STATE: dict[str, Any] = {
    "status": "idle",          # idle | running | done | error
    "target_id": None,
    "run_id": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "severity": {},
    "finding_count": 0,
}
_SCAN_LOCK = threading.Lock()

# ---- Pro-Agent-Zustand für das Node-Visualisierungslayer ----
# Reihenfolge entspricht der Schwarm-Topologie; Bereich "web" (erweiterbar).
AGENT_NAMES = ["recon", "mobile", "scanning", "api", "infra", "osint",
               "cloud", "auth", "llmsec", "fuzz", "verify",
               "analysis", "threatintel", "poc", "reporting"]
PHASE_AGENTS = {
    "recon": ["recon", "mobile"],
    "scan": ["scanning", "api", "infra", "osint", "cloud", "auth", "llmsec", "fuzz"],
    "verify": ["verify"],
    "analyze": ["analysis", "threatintel", "poc"],
    "report": ["reporting"],
}
AGENT_STATE: dict[str, dict] = {}
QUEEN_STATE: dict[str, Any] = {"active": False, "command_phase": None,
                               "command_agents": [], "last_msg": ""}
_AGENT_RE = re.compile(r"^\[(\w+)\]\s*(.*)$")
_PHASE_RE = re.compile(r"Phase '(\w+)'")


def _reset_agents() -> None:
    for n in AGENT_NAMES:
        AGENT_STATE[n] = {"state": "idle", "task": "wartet auf Befehl",
                          "scope": "", "findings": 0}
    QUEEN_STATE.update({"active": False, "command_phase": None,
                        "command_agents": [], "last_msg": ""})


def _finish_agents(final: str = "done") -> None:
    for n in AGENT_NAMES:
        st = AGENT_STATE.get(n)
        if st and st["state"] == "running":
            st["state"] = final
            st["task"] = "fertig" if final == "done" else st["task"]
    QUEEN_STATE["active"] = False
    QUEEN_STATE["command_phase"] = None
    QUEEN_STATE["command_agents"] = []


def _update_agents(ev: dict) -> None:
    msg = ev.get("msg", "") or ""
    if msg.lstrip().startswith("👑"):  # 👑
        QUEEN_STATE["active"] = True
        QUEEN_STATE["last_msg"] = msg
        pm = _PHASE_RE.search(msg)
        if pm and "dispatche" in msg:
            ph = pm.group(1)
            QUEEN_STATE["command_phase"] = ph
            QUEEN_STATE["command_agents"] = PHASE_AGENTS.get(ph, [])
        return
    m = _AGENT_RE.match(msg)
    if not m:
        return
    name, rest = m.group(1), m.group(2)
    if name not in AGENT_STATE:
        return
    st = AGENT_STATE[name]
    if "startet Phase" in rest:
        st["state"] = "running"
        pm = _PHASE_RE.search(rest)
        st["task"] = f"Phase '{pm.group(1)}'" if pm else "arbeitet"
    elif "fertig" in rest or rest.startswith("✅"):
        st["state"] = "done"
        st["task"] = "fertig"
        fm = re.search(r"\((\d+)\s+Findings", rest)
        if fm:
            st["findings"] = int(fm.group(1))
    elif "out-of-scope" in rest or "⛔" in rest:
        st["state"] = "blocked"
        st["task"] = "out-of-scope geblockt"
        om = re.search(r"out-of-scope\):\s*(\S+)", rest)
        if om:
            st["scope"] = om.group(1)
    elif "Fehler" in rest or rest.startswith("❌"):
        st["state"] = "blocked"
        st["task"] = "Fehler"


def _agents_payload() -> dict:
    return {"agents": AGENT_STATE, "queen": dict(QUEEN_STATE)}


_reset_agents()

_OAUTH_PROVIDERS: dict = {}


def _oauth_provider(name: str):
    inst = _OAUTH_PROVIDERS.get(name)
    if inst is None:
        inst = provider_from_config(name)
        _OAUTH_PROVIDERS[name] = inst
    return inst


def _rowdict(row):
    return {k: row[k] for k in row.keys()} if row else None


def _start_scan_async(target_id: int, active: bool, fuzz: bool,
                      phases: Optional[tuple] = None,
                      offensive: Optional[bool] = None,
                      oversight_ack: Optional[bool] = None) -> dict:
    """Startet einen Scan in einem Daemon-Thread. Nur interne Service-Calls."""
    with _SCAN_LOCK:
        if SCAN_STATE["status"] == "running":
            raise HTTPException(409, "Ein Scan läuft bereits.")
        LIVE_FEED.clear()
        _reset_agents()
        SCAN_STATE.update({
            "status": "running", "target_id": target_id, "run_id": None,
            "started_at": time.time(), "finished_at": None, "error": None,
            "severity": {}, "finding_count": 0,
        })

    def _emit(ev: dict) -> None:
        LIVE_FEED.append(ev)
        _update_agents(ev)

    def _worker() -> None:
        try:
            kw = {"emit": _emit, "active": active, "fuzz": fuzz,
                  "offensive": offensive, "oversight_ack": oversight_ack}
            if phases:
                kw["phases"] = phases
            result = svc.run_scan(target_id, **kw)
            with _SCAN_LOCK:
                SCAN_STATE.update({
                    "status": "done",
                    "run_id": result.run_id,
                    "finished_at": time.time(),
                    "severity": result.by_severity(),
                    "finding_count": len(result.findings),
                })
            _finish_agents("done")
        except OversightError as exc:
            with _SCAN_LOCK:
                SCAN_STATE.update({
                    "status": "error", "error": str(exc),
                    "finished_at": time.time(),
                })
            LIVE_FEED.append({"ts": time.time(), "msg": f"⛔ {exc}"})
            _finish_agents("blocked")
        except Exception as exc:
            with _SCAN_LOCK:
                SCAN_STATE.update({
                    "status": "error", "error": str(exc),
                    "finished_at": time.time(),
                })
            LIVE_FEED.append({"ts": time.time(), "msg": f"❌ Scan-Fehler: {exc}"})
            _finish_agents("blocked")

    threading.Thread(target=_worker, daemon=True, name="antbb-scan").start()
    return {"ok": True, "status": "running", "target_id": target_id}


# ---------------- HTML-Seiten ----------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    targets = []
    for t in svc.list_targets():
        d = _rowdict(t)
        d["confirmed"] = svc.is_confirmed(t["id"])
        d["scope_count"] = len(svc.list_scopes(t["id"]))
        d["mode"] = svc.mode_status(t["id"])
        targets.append(d)
    remote_status = svc.remote_status()
    return templates.TemplateResponse(request, "index.html", {
        "targets": targets, "disclaimer": DISCLAIMER_TEXT,
        "archived_count": len(svc.list_archived_targets()),
        "remote": remote_status,
        "remote_steps": svc.remote_setup_steps(remote_status["mode"]),
    })


@app.get("/target/{target_id}", response_class=HTMLResponse)
def target_page(request: Request, target_id: int):
    t = svc.get_target(target_id)
    if not t:
        raise HTTPException(404, "Target nicht gefunden")
    o = svc.get_oversight(target_id)
    scopes = [_rowdict(s) for s in svc.list_scopes(target_id)]
    findings = [_rowdict(f) for f in svc.list_findings(target_id)]
    # Severity-Sortierung für die Anzeige
    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda f: _rank.get(f.get("severity", "info"), 0), reverse=True)
    reports = []
    for r in svc.list_reports(target_id):
        d = _rowdict(r)
        d["addenda"] = [_rowdict(a) for a in svc.list_report_addenda(r["id"])]
        d["revisions"] = [
            {"id": rev["id"], "revision": rev["revision"],
             "instruction": rev["instruction"]}
            for rev in svc.list_report_revisions(r["id"])]
        reports.append(d)
    mode = svc.mode_status(target_id)
    return templates.TemplateResponse(request, "target.html", {
        "target": _rowdict(t),
        "oversight": _rowdict(o),
        "confirmed": bool(o and o["confirmed"]),
        "scopes": scopes,
        "findings": findings,
        "reports": reports,
        "chain_steps": CHAIN_STEPS,
        "oversight_prompt": OVERSIGHT_PROMPT,
        "active_oversight_prompt": ACTIVE_OVERSIGHT_PROMPT,
        "active_legal_notice": ACTIVE_LEGAL_NOTICE,
        "notice": new_target_notice(t["name"]),
        "mode": mode,
        "disclaimer": DISCLAIMER_TEXT,
        "scan_state": dict(SCAN_STATE),
    })


@app.get("/wlan", response_class=HTMLResponse)
def wlan_page(request: Request, target_id: Optional[int] = None):
    """Eigenständige WLAN-Seite: bündelt passive Coverage/Survey, Kanal-Optimierung
    und das autorisierte Offensiv-Modul als first-class Menüpunkt. Kein Target nötig;
    target_id ist optional und wird nur an die passiven Survey-Panels durchgereicht."""
    if target_id is not None and not svc.get_target(target_id):
        target_id = None
    notice = ("Drei klare Bereiche: WLAN-Scope (Allowlist) · Coverage & Scan (passiv + "
              "Königin-Voll-Scan) · Offensiv/Airgorah (Gate-pflichtig).\n"
              "Ein-Klick „Voller WLAN-Scan“: Königin dispatcht alle defensiven Checks – "
              "kein Haken-Klicken. Offensiv bleibt default-deny (Engagement + Oversight + "
              "ANTBB_WIFI=1). § 202a-c StGB / CFAA beachten.")
    return templates.TemplateResponse(request, "wlan.html", {
        "target_id": target_id,
        "notice": notice,
        "disclaimer": DISCLAIMER_TEXT,
    })


@app.get("/brain", response_class=HTMLResponse)
def brain_page(request: Request):
    """Neuronales Gehirn der Koenigin: rein clientseitiges GPU-Partikelfeld
    (Three.js r158, vendored). Keine Serverlogik, keine Secrets, keine externen
    Datenabrufe, keine Telemetrie."""
    return templates.TemplateResponse(request, "brain.html", {
        "disclaimer": DISCLAIMER_TEXT,
    })


# ---------------- Form-Handler (HTML) – rufen nur Service-Funktionen ----------------
@app.post("/target/add")
def html_add_target(name: str = Form(...), description: str = Form(""),
                    mode_policy: str = Form("auto")):
    tid = svc.add_target(name, description)
    if mode_policy in ("defensive", "auto", "offensive"):
        svc.set_mode_policy(tid, mode_policy)
    return RedirectResponse(f"/target/{tid}", status_code=303)


@app.post("/remote/set")
def html_set_remote(mode: str = Form("off")):
    """Speichert NUR die Fernzugriff-Präferenz (off|tailscale|cloudflare).
    Startet NICHTS, exponiert NICHTS, schreibt KEIN Token. Danach 303-Redirect
    zurück auf die Startseite (gleiches duplikat-sicheres Muster wie add-target)."""
    svc.set_remote_mode(mode)
    return RedirectResponse("/", status_code=303)


@app.get("/api/remote")
def api_remote_status():
    """Ehrlicher, rein lesender Fernzugriff-Status (JSON). Kein Secret."""
    return JSONResponse(svc.remote_status())


@app.post("/api/remote")
def api_set_remote(payload: dict):
    """Setzt NUR die Präferenz (off|tailscale|cloudflare). Exponiert nichts."""
    mode = svc.set_remote_mode((payload or {}).get("mode", "off"))
    return JSONResponse({"mode": mode, "status": svc.remote_status()})


@app.get("/api/remote/tunnel")
def api_remote_tunnel_status():
    """Laufzeit-Status des von antbb verwalteten Cloudflare-Tunnels (JSON, kein Secret)."""
    from .. import remote_access as _ra
    return JSONResponse(_ra.cloudflare_tunnel_runtime())


@app.post("/api/remote/tunnel/start")
async def api_remote_tunnel_start(request: Request):
    """Startet den Cloudflare-Tunnel – NUR mit menschlichem Oversight.

    Der Klick in der GUI ist die Oversight-Bestätigung: das Frontend sendet
    {"confirm": true}. Ohne confirm wird NICHTS gestartet/exponiert. Ein
    benannter Tunnel (named=true) liest sein Token nur zur Laufzeit aus
    CLOUDFLARE_TUNNEL_TOKEN (nie gespeichert/geloggt)."""
    from .. import remote_access as _ra
    try:
        p = await request.json()
        if not isinstance(p, dict):
            p = {}
    except Exception:
        p = {}
    confirm = bool(p.get("confirm"))
    if not confirm:
        return JSONResponse(
            {"ok": False, "running": False, "url": "",
             "reason": "Oversight-Bestätigung fehlt (confirm=true erforderlich)."},
            status_code=403)
    res = _ra.start_cloudflare_tunnel(oversight=True, named=bool(p.get("named")))
    # Modus auf cloudflare setzen, damit die Startseite den aktiven Transport zeigt.
    try:
        if res.get("ok"):
            svc.set_remote_mode("cloudflare")
    except Exception:
        pass
    res["status"] = svc.remote_status()
    return JSONResponse(res)


@app.post("/api/remote/tunnel/stop")
def api_remote_tunnel_stop():
    """Stoppt den von antbb verwalteten Cloudflare-Tunnel."""
    from .. import remote_access as _ra
    res = _ra.stop_cloudflare_tunnel()
    res["status"] = svc.remote_status()
    return JSONResponse(res)


@app.post("/target/{target_id}/archive")
def html_archive_target(target_id: int):
    """Soft-Delete: Target in den Papierkorb verschieben. Daten + Königin-Wissen
    bleiben vollständig erhalten; nur die aktive Liste blendet es aus."""
    if svc.get_target(target_id):
        svc.archive_target(target_id)
    return RedirectResponse("/", status_code=303)


@app.post("/target/{target_id}/restore")
def html_restore_target(target_id: int):
    """Wiederherstellen aus dem Papierkorb."""
    if svc.get_target(target_id):
        svc.restore_target(target_id)
    return RedirectResponse("/trash", status_code=303)


@app.get("/trash", response_class=HTMLResponse)
def trash_page(request: Request):
    """Papierkorb: archivierte Targets mit Wiederherstellen-Aktion. Es werden
    keine Daten gelöscht – die Königin behält ihr gesamtes Wissen."""
    targets = []
    for t in svc.list_archived_targets():
        d = _rowdict(t)
        d["scope_count"] = len(svc.list_scopes(t["id"]))
        d["finding_count"] = len(svc.list_findings(t["id"]))
        d["report_count"] = len(svc.list_reports(t["id"]))
        try:
            import datetime as _dt
            d["archived_fmt"] = _dt.datetime.fromtimestamp(
                t["archived_at"]).strftime("%Y-%m-%d %H:%M") if t["archived_at"] else ""
        except Exception:
            d["archived_fmt"] = ""
        targets.append(d)
    return templates.TemplateResponse(request, "trash.html", {
        "targets": targets, "disclaimer": DISCLAIMER_TEXT,
    })


@app.post("/target/{target_id}/scope/add")
def html_add_scope(target_id: int, kind: str = Form(...), value: str = Form(...),
                   allowed: str = Form("on")):
    svc.add_scope(target_id, kind, value, allowed=(allowed == "on"))
    return RedirectResponse(f"/target/{target_id}", status_code=303)


@app.post("/target/{target_id}/scope/{scope_id}/delete")
def html_delete_scope(target_id: int, scope_id: int):
    svc.delete_scope(scope_id)
    return RedirectResponse(f"/target/{target_id}", status_code=303)


@app.post("/target/{target_id}/oversight")
def html_oversight(target_id: int, confirm: str = Form("off"), by: str = Form("web-user")):
    svc.set_oversight(target_id, confirm == "on", confirmed_by=by)
    return RedirectResponse(f"/target/{target_id}", status_code=303)


@app.post("/target/{target_id}/mode")
def html_set_mode(target_id: int, mode_policy: str = Form("auto")):
    svc.set_mode_policy(target_id, mode_policy)
    return RedirectResponse(f"/target/{target_id}", status_code=303)


@app.post("/target/{target_id}/scan")
def html_scan(target_id: int, active: str = Form("off"), fuzz: str = Form("off"),
              offensive: str = Form("off"), oversight_active: str = Form("off")):
    """Startet Scan asynchron – Nutzer bleibt in der GUI (Live-Feed).

    Das Offensiv-Häkchen (`offensive`) ENGAGIERT den Offensiv-Modus: bei
    autorisiertem Scope+Oversight laufen die aktiven Angriffs-Playbooks +
    Fuzzing (kein defensiver Read-only-Fallback). `active`/`fuzz` bleiben als
    Feinsteuerung erhalten. `oversight_active` ist das konsistente Human-Oversight-
    Häkchen: ohne es wird jede aktive/offensive Aktion serverseitig verweigert.
    """
    a, f, o = (active == "on"), (fuzz == "on"), (offensive == "on")
    ack = oversight_active == "on"
    try:
        # Vorab-Gate: ohne Target-Oversight sofort Fehlerseite
        if not svc.is_confirmed(target_id):
            from ..oversight import require_oversight
            require_oversight(svc.store, target_id)
        off = True if o else None
        # Konsistentes, serverseitiges Default-Deny: aktiver/offensiver Lauf ohne
        # ausdrückliche Human-Oversight-Freigabe wird verweigert (nichts gestartet).
        # Synchron VOR dem Thread-Start, damit die Route selbst 403 liefert.
        will_engage = (active_trigger_requested(active=a, fuzz=f, offensive=off)
                       and svc.mode_status(target_id)["offensive_allowed"])
        ack_val = ack if will_engage else None
        if will_engage:
            enforce_active_oversight(ack_val, action="offensiver/aktiver Schwarm-Lauf")
        _start_scan_async(target_id, active=a, fuzz=f, offensive=off,
                          oversight_ack=ack_val)
    except OversightError as exc:
        return templates_error(target_id, str(exc))
    except HTTPException as exc:
        return templates_error(target_id, exc.detail)
    return RedirectResponse(f"/target/{target_id}#live", status_code=303)


def templates_error(target_id, msg):
    return HTMLResponse(
        f"<h2>⛔ Blockiert</h2><pre>{msg}</pre>"
        f'<a href="/target/{target_id}">Zurück</a>', status_code=403,
    )


@app.post("/target/{target_id}/report/add")
async def html_add_report(request: Request, target_id: int):
    form = await request.form()
    chain = empty_chain()
    for key, _ in CHAIN_STEPS:
        chain[key] = form.get(f"chain_{key}", "")
    cvss = form.get("cvss")
    draft = ReportDraft(
        target_id=target_id, title=form.get("title", "Unbenannter Report"),
        chain=chain, cvss_score=float(cvss) if cvss else None,
        cvss_vector=form.get("vector", ""),
    )
    svc.create_report(draft)
    return RedirectResponse(f"/target/{target_id}", status_code=303)


# ---------------- Report-Builder: Prefill / Professional / Nachtrag / Neu-Anweisung ----------------
@app.get("/target/{target_id}/report/prefill")
def html_report_prefill(target_id: int, finding_id: int):
    """Liefert Prefill (Titel/CVSS + 8-Schritt-Kette) aus einem echten Finding."""
    try:
        return JSONResponse(svc.report_prefill(target_id, finding_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/target/{target_id}/report/professional", response_class=PlainTextResponse)
def html_report_professional(target_id: int, finding_id: Optional[int] = None,
                             instruction: str = ""):
    """Voller strukturierter Profi-Bericht (Code + Remediation je Finding)."""
    ids = [finding_id] if finding_id else None
    return svc.professional_report(target_id, finding_ids=ids, instruction=instruction)


@app.post("/report/{report_id}/addendum")
def html_add_addendum(report_id: int, text: str = Form(...),
                      author: str = Form("web-user")):
    try:
        svc.add_report_addendum(report_id, text, author=author)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    row = svc.get_report(report_id)
    tid = row["target_id"] if row else 0
    return RedirectResponse(f"/target/{tid}", status_code=303)


@app.post("/report/{report_id}/reinstruct")
def html_reinstruct(report_id: int, reanweisung: str = Form(...),
                    author: str = Form("web-user")):
    try:
        svc.reinstruct_report(report_id, reanweisung, author=author)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    row = svc.get_report(report_id)
    tid = row["target_id"] if row else 0
    return RedirectResponse(f"/target/{tid}", status_code=303)


@app.get("/report/{report_id}/revisions")
def api_report_revisions(report_id: int):
    out = []
    for r in svc.list_report_revisions(report_id):
        out.append({"id": r["id"], "revision": r["revision"],
                    "instruction": r["instruction"], "author": r["author"],
                    "created_at": r["created_at"]})
    return {"report_id": report_id, "revisions": out}


@app.get("/report/revision/{revision_id}", response_class=PlainTextResponse)
def api_report_revision_body(revision_id: int):
    row = svc.get_report_revision(revision_id)
    if not row:
        raise HTTPException(404, "Revision nicht gefunden")
    return row["body"]


@app.get("/report/{report_id}/view", response_class=PlainTextResponse)
def html_report_view(report_id: int):
    return svc.report_markdown(report_id)


@app.get("/report/{report_id}/export")
def html_report_export(report_id: int, format: str = "md"):
    try:
        path = svc.export_report(report_id, fmt=format)
    except OversightError as exc:
        raise HTTPException(403, str(exc))
    return JSONResponse({"ok": True, "path": path})


# ---------------- JSON-API (on-device Pipeline ohne CLI) ----------------
@app.get("/api/capabilities")
def api_capabilities():
    """Königin-Gedächtnis: Capability-Registry (Skills/Playbooks/Tools je Soldat).

    Wird bei jedem Abruf frisch aus den Soldaten aufgebaut und ins
    Königin-Gedächtnis persistiert (Single Source of Truth). Keine Secrets.
    """
    return JSONResponse(svc.capabilities(rebuild=True))


@app.get("/api/disclaimer")
def api_disclaimer():
    return {"disclaimer": DISCLAIMER_TEXT}


@app.get("/api/targets")
def api_targets():
    out = []
    for t in svc.list_targets():
        d = _rowdict(t)
        d["confirmed"] = svc.is_confirmed(t["id"])
        d["mode"] = svc.mode_status(t["id"])
        out.append(d)
    return out


@app.post("/api/targets")
def api_add_target(payload: dict):
    tid = svc.add_target(payload["name"], payload.get("description", ""))
    pol = payload.get("mode_policy", "auto")
    if pol in ("defensive", "auto", "offensive"):
        svc.set_mode_policy(tid, pol)
    return {"id": tid, "notice": new_target_notice(payload["name"]),
            "mode": svc.mode_status(tid)}


@app.get("/api/targets/{target_id}/scopes")
def api_scopes(target_id: int):
    return [_rowdict(s) for s in svc.list_scopes(target_id)]


@app.post("/api/targets/{target_id}/scopes")
def api_add_scope(target_id: int, payload: dict):
    sid = svc.add_scope(target_id, payload["kind"], payload["value"],
                        allowed=payload.get("allowed", True))
    return {"id": sid}


@app.delete("/api/targets/{target_id}/scopes/{scope_id}")
def api_delete_scope(target_id: int, scope_id: int):
    svc.delete_scope(scope_id)
    return {"ok": True}


@app.get("/api/targets/{target_id}/scope-check")
def api_scope_check(target_id: int, asset: str):
    res = svc.check_asset(target_id, asset)
    return {"allowed": res.allowed, "reason": res.reason, "matched": res.matched}


@app.post("/api/targets/{target_id}/oversight")
def api_oversight(target_id: int, payload: dict):
    svc.set_oversight(target_id, bool(payload.get("confirmed")),
                      confirmed_by=payload.get("by", "api"),
                      note=payload.get("note", ""))
    return {"confirmed": svc.is_confirmed(target_id),
            "mode": svc.mode_status(target_id)}


@app.get("/api/targets/{target_id}/mode")
def api_get_mode(target_id: int):
    return svc.mode_status(target_id)


@app.post("/api/targets/{target_id}/mode")
def api_set_mode(target_id: int, payload: dict):
    pol = payload.get("mode_policy", "auto")
    if pol not in ("defensive", "auto", "offensive"):
        raise HTTPException(400, "mode_policy muss defensive|auto|offensive sein")
    svc.set_mode_policy(target_id, pol)
    return svc.mode_status(target_id)


@app.post("/api/targets/{target_id}/scan")
def api_scan(target_id: int, payload: Optional[dict] = None):
    """Startet Scan asynchron (on-device). Antwortet sofort mit status=running."""
    payload = payload or {}
    active = bool(payload.get("active", False))
    fuzz = bool(payload.get("fuzz", False))
    offensive = payload.get("offensive", None)
    # Konsistentes Human-Oversight-Häkchen (akzeptiert "oversight_active" oder
    # "oversight_ack"). Nur relevant, wenn der Lauf aktiv/offensiv wäre.
    ack = payload.get("oversight_active", payload.get("oversight_ack", None))
    phases = payload.get("phases")
    ph = tuple(phases) if phases else None
    try:
        if not svc.is_confirmed(target_id):
            from ..oversight import require_oversight
            require_oversight(svc.store, target_id)
        will_engage = (active_trigger_requested(active=active, fuzz=fuzz,
                                                offensive=offensive)
                       and svc.mode_status(target_id)["offensive_allowed"])
        ack_val = bool(ack) if will_engage else None
        if will_engage:
            enforce_active_oversight(ack_val, action="offensiver/aktiver Schwarm-Lauf")
        return _start_scan_async(target_id, active=active, fuzz=fuzz, phases=ph,
                                 offensive=offensive, oversight_ack=ack_val)
    except OversightError as exc:
        raise HTTPException(403, str(exc))


@app.get("/api/targets/{target_id}/scan/status")
def api_scan_status(target_id: int):
    st = dict(SCAN_STATE)
    st["feed_len"] = len(LIVE_FEED)
    st["mode"] = svc.mode_status(target_id)
    st.update(_agents_payload())
    return st


@app.get("/api/feed")
def api_feed(since: int = 0):
    """Live-Feed ab Index `since` (Polling)."""
    return {"events": LIVE_FEED[since:], "total": len(LIVE_FEED),
            "scan": dict(SCAN_STATE), **_agents_payload()}


@app.get("/api/targets/{target_id}/findings")
def api_findings(target_id: int):
    return [_rowdict(f) for f in svc.list_findings(target_id)]


@app.get("/api/targets/{target_id}/reports")
def api_reports(target_id: int):
    return [_rowdict(r) for r in svc.list_reports(target_id)]


@app.post("/api/targets/{target_id}/reports")
def api_add_report(target_id: int, payload: dict):
    chain = empty_chain()
    chain.update(payload.get("chain", {}))
    draft = ReportDraft(
        target_id=target_id, title=payload.get("title", "Report"),
        chain=chain, cvss_score=payload.get("cvss_score"),
        cvss_vector=payload.get("cvss_vector", ""),
    )
    rid = svc.create_report(draft)
    return {"id": rid}


@app.get("/api/llm/status")
def api_llm_status():
    return svc.llm_status()


@app.get("/providers", response_class=HTMLResponse)
def providers_page():
    st = svc.llm_status()
    rows = []
    badge = {
        "lokal, keine Auth": "#2563eb",
        "authentifiziert": "#16a34a",
        "Key-Modus (Fallback)": "#ca8a04",
        "bereit zur Anmeldung": "#9333ea",
        "nicht erreichbar": "#dc2626",
        "nicht konfiguriert": "#6b7280",
    }
    for p in st["providers"]:
        color = badge.get(p["auth_state"], "#6b7280")
        can_login = p.get("oauth_available") and p["auth_state"] == "bereit zur Anmeldung"
        login = (f'<a href="/auth/{p["provider"]}/login">Anmelden (OAuth)</a>'
                 if can_login else "—")
        rows.append(
            f"<tr><td><b>{p['provider']}</b></td>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:10px'>{p['auth_state']}</span></td>"
            f"<td>{p['auth_mode']}</td>"
            f"<td>{'ja' if p['oauth_available'] else 'nein'}</td>"
            f"<td>{p['default_model']} / {p['fast_model']}</td>"
            f"<td><code>{p['base_url']}</code></td>"
            f"<td>{login}</td></tr>"
        )
    html = (
        "<html><head><meta charset='utf-8'><title>antbb – LLM-Provider</title></head>"
        "<body style='font-family:sans-serif;max-width:960px;margin:2rem auto'>"
        "<h1>🐜 antbb – LLM-Provider-Status</h1>"
        f"<p>Standard-Provider: <b>{st['default_provider']}</b> · "
        f"Hauptmodell: <b>{st['main_model']}</b> · Flash: <b>{st['fast_model']}</b></p>"
        "<p style='color:#6b7280'>Zentrale Regel: Kein LLM aktiviert von sich aus einen "
        "Schwarm. Das Schwarm-Verhalten kommt ausschließlich aus antbb.</p>"
        "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>"
        "<tr><th>Provider</th><th>Status</th><th>Auth-Modus</th><th>OAuth?</th>"
        "<th>Modelle (main/fast)</th><th>Base-URL</th><th>Aktion</th></tr>"
        + "".join(rows) +
        "</table><p><a href='/'>← zurück</a></p></body></html>"
    )
    return HTMLResponse(html)


@app.get("/auth/{provider}/login")
def auth_login(provider: str):
    inst = _oauth_provider(provider)
    if not inst.available:
        return HTMLResponse(
            f"<h2>OAuth nicht verfügbar</h2><p>Provider '{provider}' hat keinen "
            f"dokumentierten OAuth-Flow.</p>"
            f"<p><a href='/providers'>← Provider-Status</a></p>", status_code=400)
    try:
        url, _state = inst.build_authorize_url()
    except OAuthError as exc:
        return HTMLResponse(f"<h2>OAuth-Fehler</h2><pre>{exc}</pre>", status_code=400)
    return RedirectResponse(url, status_code=303)


@app.get("/auth/{provider}/callback")
def auth_callback(provider: str, code: Optional[str] = None,
                  state: Optional[str] = None, error: Optional[str] = None):
    if error:
        return HTMLResponse(f"<h2>OAuth abgebrochen</h2><pre>{error}</pre>", status_code=400)
    if not code or not state:
        return HTMLResponse("<h2>OAuth-Callback unvollständig.</h2>", status_code=400)
    inst = _oauth_provider(provider)
    try:
        meta = inst.exchange_code(code, state)
    except OAuthError as exc:
        return HTMLResponse(f"<h2>Token-Exchange fehlgeschlagen</h2><pre>{exc}</pre>",
                            status_code=400)
    return HTMLResponse(
        f"<h2>✅ {provider} authentifiziert</h2>"
        f"<p>Scope: {meta.get('scope','')}</p>"
        f"<p><a href='/providers'>← Provider-Status</a></p>")



# ---------------- Rating / Heatmap ----------------
@app.get("/api/targets/{target_id}/rating")
def api_rating(target_id: int, ai: int = 1):
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    return JSONResponse(svc.rating(target_id, with_ai=bool(ai)))


@app.get("/api/targets/{target_id}/heatmap")
def api_heatmap(target_id: int):
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    return JSONResponse(svc.heatmap(target_id))


# ---------------- Soldaten (Skills/Playbooks/Overrides/Mems) ----------------
@app.get("/api/soldiers")
def api_soldiers():
    """Alle Soldaten mit Skill + Playbooks + Task-Items (Registry, Volltext-fähig)."""
    return JSONResponse(svc.capabilities(rebuild=True))


@app.get("/api/soldiers/{name}")
def api_soldier(name: str, target_id: Optional[int] = None):
    try:
        return JSONResponse(svc.soldier_detail(name, target_id=target_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.post("/api/soldiers/{name}/override")
def api_soldier_override(name: str, payload: dict):
    """Setzt/aktualisiert einen Playbook/Skill-Parameter-Override.

    payload: {playbook?: str, key: str, value: str}. playbook='' = Soldat-weit.
    """
    key = payload.get("key")
    if not key:
        raise HTTPException(400, "key erforderlich (z.B. enabled|intensity|flags|description)")
    oid = svc.set_soldier_override(name, payload.get("playbook", ""),
                                   key, str(payload.get("value", "")))
    return {"ok": True, "id": oid, "soldier": name}


@app.delete("/api/soldiers/{name}/override")
def api_soldier_override_delete(name: str, playbook: str = "", key: str = ""):
    if not key:
        raise HTTPException(400, "key erforderlich")
    svc.delete_soldier_override(name, playbook, key)
    return {"ok": True}


@app.post("/api/soldiers/{name}/mem")
def api_soldier_mem(name: str, payload: dict):
    text = (payload.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "text erforderlich")
    mid = svc.add_soldier_mem(name, text)
    return {"ok": True, "id": mid}


@app.delete("/api/soldiers/{name}/mem/{mem_id}")
def api_soldier_mem_delete(name: str, mem_id: int):
    svc.delete_soldier_mem(mem_id)
    return {"ok": True}


@app.get("/api/brain/{target_id}")
def api_brain(target_id: int):
    """Daten fuer die Koenigin-Kammer: Gehirn, Memgraph, Memories.

    Zieht ALLE Werte aus dem bestehenden Store/Service. Fehlt eine Quelle,
    wird ein ehrlicher Leerzustand geliefert (keine erfundenen Platzhalter).
    """
    t = svc.get_target(target_id)
    if not t:
        raise HTTPException(404, "Target nicht gefunden")
    mode = svc.mode_status(target_id)
    brain = {
        "target": {"id": t["id"], "name": t["name"]},
        "mode_policy": mode["mode_policy"],
        "effective_mode": mode["effective_mode"],
        "oversight": mode["oversight"],
        "in_scope_count": mode["in_scope_count"],
        "offensive_allowed": mode["offensive_allowed"],
        "reason": mode["reason"],
        "agent_count": len(AGENT_NAMES),
        "agents": AGENT_NAMES,
        "capabilities": svc.capabilities(rebuild=True),
        "rules": [
            "Scope default-deny: ohne In-Scope-Eintrag blockiert jeder Check.",
            "Oversight-Gate ist hart: ohne Haekchen kein Scan/Export.",
            "Offensiv nur bei Scope + Oversight (mode_policy auto/offensive).",
            "Nicht-destruktiv; nur lokal autorisierte Ziele.",
        ],
    }
    scopes = [_rowdict(s) for s in svc.list_scopes(target_id)]
    findings = [_rowdict(f) for f in svc.list_findings(target_id)]
    reports = [_rowdict(r) for r in svc.list_reports(target_id)]
    sev = {}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    memories = {
        "scopes": [{"id": s["id"], "kind": s["kind"], "value": s["value"],
                    "allowed": bool(s["allowed"])} for s in scopes],
        "findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                      "asset": f["asset"], "agent": f["agent"]} for f in findings[:50]],
        "findings_total": len(findings),
        "severity": sev,
        "reports": [{"id": r["id"], "title": r["title"],
                     "severity": r["severity"]} for r in reports],
        "routines": [],
        "routines_note": "Keine Routinen im lokalen antbb-Store hinterlegt.",
        "baselines": [],
        "baselines_note": "Keine Baseline-Messungen im Store hinterlegt.",
    }
    nodes, edges = [], []
    tnode = f"t{t['id']}"
    nodes.append({"id": tnode, "label": t["name"], "type": "target"})
    for s in scopes:
        sid = f"s{s['id']}"
        nodes.append({"id": sid, "label": s["value"],
                      "type": "scope" if s["allowed"] else "scope-out"})
        edges.append({"from": tnode, "to": sid})
    sev_nodes = {}
    for f in findings:
        fid = f"f{f['id']}"
        nodes.append({"id": fid, "label": f["title"][:28], "type": "finding",
                      "severity": f["severity"]})
        edges.append({"from": tnode, "to": fid})
        sv = f["severity"]
        if sv not in sev_nodes:
            sev_nodes[sv] = f"sev-{sv}"
            nodes.append({"id": sev_nodes[sv], "label": sv, "type": "severity"})
        edges.append({"from": fid, "to": sev_nodes[sv]})
    memgraph = {"nodes": nodes, "edges": edges,
                "empty": len(scopes) == 0 and len(findings) == 0}
    return {"brain": brain, "memories": memories, "memgraph": memgraph}



# ---------------- WLAN-Survey (PASSIV: Coverage/Kanal/Optimierung) ----------------
@app.get("/api/wlan/adapters")
def api_wlan_adapters():
    """Vorhandene WLAN-Adapter inkl. Chipset/Driver/Monitor-Fähigkeit (honest-empty)."""
    return JSONResponse(svc.wlan_adapters())


@app.get("/api/wlan/scan")
def api_wlan_scan(iface: Optional[str] = None):
    """Passiver Umgebungs-Scan (iw/nmcli). Ohne Tool/Interface: ehrlich leer."""
    return JSONResponse(svc.wlan_scan(iface=iface))


@app.post("/api/wlan/scan")
def api_wlan_scan_post(payload: Optional[dict] = None):
    """Gleicher Scan wie GET; iface optional im JSON-Body."""
    payload = payload or {}
    iface = payload.get("iface") or None
    return JSONResponse(svc.wlan_scan(iface=iface))


@app.get("/api/wlan/survey")
def api_wlan_survey(target_id: Optional[int] = None, scan: int = 0,
                    iface: Optional[str] = None):
    """Voller Survey: Kanal-Analyse + Coverage + Empfehlungen (honest-empty)."""
    return JSONResponse(svc.wlan_survey(target_id=target_id, iface=iface,
                                        scan=bool(scan)))


@app.post("/api/wlan/point")
def api_wlan_add_point(payload: dict):
    """Mess-Punkt speichern. payload: {label, samples:{bssid:rssi}, own_bssids?, target_id?}."""
    label = (payload.get("label") or "").strip()
    samples = payload.get("samples") or {}
    if not label or not isinstance(samples, dict) or not samples:
        raise HTTPException(400, "label + samples{bssid:rssi} erforderlich")
    n = svc.wlan_add_point(label, samples,
                           target_id=payload.get("target_id"),
                           own_bssids=payload.get("own_bssids") or [])
    return {"ok": True, "label": label, "sample_count": n}


@app.delete("/api/wlan/point")
def api_wlan_delete_point(label: str, target_id: Optional[int] = None):
    svc.wlan_delete_point(label, target_id)
    return {"ok": True}


# ---------------- WLAN-OFFENSIV (AUTORISIERT: Engagement-Gate + Oversight) ----------------
@app.get("/api/wlan/offensive/status")
def api_wlan_off_status():
    """Tool-Verfügbarkeit + Freischaltung (für UI: Buttons sperren/zeigen)."""
    st = svc.wlan_offensive_tool_status()
    from ..wlan_offensive import LEGAL_NOTICE
    st["legal_notice"] = LEGAL_NOTICE
    st["oversight_prompt"] = ACTIVE_OVERSIGHT_PROMPT
    return JSONResponse(st)


@app.get("/api/wlan/engagements")
def api_wlan_engagements():
    return JSONResponse({"engagements": svc.wlan_engagement_list()})


@app.post("/api/wlan/engagements")
def api_wlan_engagement_create(payload: dict):
    name = (payload.get("name") or "").strip()
    bssids = payload.get("bssids") or []
    ssids = payload.get("ssids") or []
    if not name or (not bssids and not ssids):
        raise HTTPException(400, "name + mindestens eine BSSID oder SSID erforderlich")
    eid = svc.wlan_engagement_create(
        name, bssids=bssids, ssids=ssids,
        start_ts=payload.get("start_ts"), end_ts=payload.get("end_ts"),
        duration_hours=float(payload.get("duration_hours", 8.0)),
        client_mac=payload.get("client_mac", "") or "",
        location=payload.get("location", "") or "",
        target_id=payload.get("target_id"),
        oversight=bool(payload.get("oversight", False)))
    return {"ok": True, "id": eid}


@app.post("/api/wlan/engagements/{engagement_id}/oversight")
def api_wlan_engagement_oversight(engagement_id: int, payload: dict):
    svc.wlan_engagement_oversight(engagement_id, bool(payload.get("confirmed", False)))
    return {"ok": True}


@app.post("/api/wlan/engagements/{engagement_id}/revoke")
def api_wlan_engagement_revoke(engagement_id: int):
    svc.wlan_engagement_revoke(engagement_id)
    return {"ok": True}


@app.get("/api/wlan/authorize")
def api_wlan_authorize(bssid: str = "", ssid: str = "", client_mac: str = ""):
    return JSONResponse(svc.wlan_authorize_check(bssid=bssid, ssid=ssid,
                                                 client_mac=client_mac))


@app.post("/api/wlan/offensive/{action}")
def api_wlan_offensive_run(action: str, payload: dict):
    """Führt EINE offensive Aktion durch das Gate. Ohne Autorisierung: blockiert.

    Web-UI läuft default dry_run=True (kein Tool-Start aus dem Browser)."""
    try:
        res = svc.wlan_offensive_run(
            action,
            bssid=payload.get("bssid", "") or "",
            ssid=payload.get("ssid", "") or "",
            client_mac=payload.get("client_mac", "") or "",
            channel=payload.get("channel"),
            seconds=int(payload.get("seconds", 60)),
            packets=int(payload.get("packets", 10)),
            capture_path=payload.get("capture_path", "") or "",
            wordlist=payload.get("wordlist"),
            dry_run=bool(payload.get("dry_run", True)))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # Findings sind AgentFinding-dicts; nicht nötig für die UI-Kurzantwort.
    res.pop("findings", None)
    return JSONResponse(res)


@app.get("/api/wlan/credentials")
def api_wlan_credentials(engagement_id: Optional[int] = None):
    return JSONResponse({"credentials": svc.wlan_credentials_list(engagement_id)})


@app.delete("/api/wlan/credentials")
def api_wlan_credentials_purge(engagement_id: Optional[int] = None):
    n = svc.wlan_credentials_purge(engagement_id)
    return {"ok": True, "purged": n}



# ---------------- WLAN Airgorah-Status + Königin-Voll-Scan ----------------
@app.get("/api/wlan/airgorah/status")
def api_wlan_airgorah_status(iface: Optional[str] = None):
    """Tools/Monitor/Rechte/Action-Katalog (kein Angriff, honest-empty)."""
    return JSONResponse(svc.wlan_airgorah_status(iface=iface or ""))


@app.get("/api/wlan/clients")
def api_wlan_clients(iface: str = "", bssid: str = ""):
    """AP-Clients – ehrlich leer ohne Monitor/airodump; startet keinen Capture."""
    return JSONResponse(svc.wlan_clients(iface=iface, bssid=bssid))


@app.get("/api/wlan/full-scan/checks")
def api_wlan_full_scan_checks():
    return JSONResponse({"checks": svc.wlan_full_scan_checks()})


@app.post("/api/wlan/full-scan")
def api_wlan_full_scan(payload: Optional[dict] = None):
    """Ein-Klick-Voll-Scan: Königin dispatcht alle defensiven WLAN-Checks.

    Body: {iface?, checks?: [...], oversight_ack: bool, target_id?}
    Ohne oversight_ack → blockiert. Keine Offensiv-Aktion.
    """
    p = payload or {}
    res = svc.wlan_full_scan(
        iface=p.get("iface") or None,
        checks=p.get("checks"),
        oversight_ack=bool(p.get("oversight_ack", False)),
        target_id=p.get("target_id"))
    return JSONResponse(res)


# ---------------- ARES "acceptable half": defensive/Infra-Routen ----------------
@app.get("/api/targets/{target_id}/firewall")
def api_firewall_plan(target_id: int, resolve: int = 1):
    """Scope-Egress-Firewall-Plan (DRY-RUN). Ändert NIE die echte Firewall."""
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    return JSONResponse({"plan": svc.egress_firewall_plan(target_id, resolve=bool(resolve)),
                         "engines": svc.egress_firewall_engines()})


@app.get("/target/{target_id}/branded-report", response_class=HTMLResponse)
def html_branded_report(target_id: int, company: str = "", logo: str = "",
                        color: str = "", title: str = "", client: str = ""):
    """Gebrandetes HTML (inline anzeigbar/druckbar). Reine Finding-Daten."""
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    brand = {k: v for k, v in {"company_name": company, "logo_path": logo,
             "primary_color": color, "report_title": title,
             "client": client}.items() if v}
    eng = svc.pdf_engine()
    note = "" if eng else (
        "Keine PDF-Engine am Server (weasyprint oder wkhtmltopdf). "
        "Bitte „Drucken“ nutzen (Browser: Drucken → Als PDF speichern) "
        "oder weasyprint/wkhtmltopdf auf dem Server installieren.")
    return HTMLResponse(svc.branded_report_html(
        target_id, brand=brand or None, toolbar=True, engine_note=note))


@app.get("/target/{target_id}/report/print", response_class=HTMLResponse)
def html_report_print(target_id: int, company: str = "", logo: str = "",
                      color: str = "", title: str = "", client: str = ""):
    """Druck-optimierte HTML-Ansicht (@media print). Immer verfügbar."""
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    brand = {k: v for k, v in {"company_name": company, "logo_path": logo,
             "primary_color": color, "report_title": title,
             "client": client}.items() if v}
    eng = svc.pdf_engine()
    note = "" if eng else (
        "Keine PDF-Engine am Server (weasyprint oder wkhtmltopdf). "
        "Nutzen Sie die Browser-Funktion Drucken → Als PDF speichern.")
    return HTMLResponse(svc.branded_report_html(
        target_id, brand=brand or None, toolbar=True, engine_note=note))


@app.get("/target/{target_id}/report.pdf")
def html_report_pdf(target_id: int, company: str = "", logo: str = "",
                    color: str = "", title: str = "", client: str = ""):
    """PDF-Download des professionellen Reports (oder ehrlicher HTML-Fallback)."""
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    brand = {k: v for k, v in {"company_name": company, "logo_path": logo,
             "primary_color": color, "report_title": title,
             "client": client}.items() if v}
    res = svc.branded_report_pdf(target_id, brand=brand or None)
    if res.get("pdf"):
        return Response(
            content=res["pdf"],
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{res["filename"]}"')
            },
        )
    # Honest-empty: kein stiller Fehler — druckfertiges HTML mit klarem Hinweis.
    note = (res.get("note") or
            "Honest-empty: keine PDF-Engine (weasyprint/wkhtmltopdf) installiert.")
    note += (" Bitte weasyprint oder wkhtmltopdf auf dem Server installieren "
             "oder die Druckansicht nutzen (Drucken -> Als PDF speichern).")
    html = svc.branded_report_html(
        target_id, brand=brand or None, toolbar=True, engine_note=note)
    # HTTP-Header sind latin-1; der vollstaendige Hinweis steht im HTML-Body.
    note_hdr = note[:180].encode("ascii", "replace").decode("ascii")
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": (
                f'inline; filename="{res.get("html_filename", "antbb-report.html")}"'),
            "X-AntBB-PDF-Engine": "missing",
            "X-AntBB-PDF-Note": note_hdr,
        },
        status_code=200,
    )


@app.post("/api/targets/{target_id}/branded-report/export")
def api_branded_export(target_id: int, payload: Optional[dict] = None):
    payload = payload or {}
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    return JSONResponse(svc.branded_report_export(
        target_id, brand=payload.get("brand"),
        want_pdf=bool(payload.get("pdf", True))))


@app.get("/api/plugins")
def api_plugins():
    """Lokale Plugins (Module-SDK). Kein Netzwerk-Fetch."""
    return JSONResponse(svc.plugins_list())


@app.get("/api/targets/{target_id}/checkpoints")
def api_checkpoints(target_id: int):
    return JSONResponse({"checkpoints": svc.checkpoints_list(target_id)})


@app.post("/api/checkpoints/{run_id}/resume")
def api_checkpoint_resume(run_id: str):
    try:
        return JSONResponse(svc.checkpoint_resume(run_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/api/checkpoints/{run_id}/replay")
def api_checkpoint_replay(run_id: str):
    try:
        return JSONResponse(svc.checkpoint_replay(run_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/api/targets/{target_id}/attackpath")
def api_attackpath(target_id: int):
    """Hypothetischer Angriffspfad-Graph (nur Darstellung, kein Executor)."""
    if not svc.get_target(target_id):
        raise HTTPException(404, "Target nicht gefunden")
    return JSONResponse(svc.attack_graph(target_id))


@app.get("/target/{target_id}/attackpath", response_class=HTMLResponse)
def html_attackpath(target_id: int):
    t = svc.get_target(target_id)
    if not t:
        raise HTTPException(404, "Target nicht gefunden")
    return HTMLResponse(
        "<!doctype html><html lang='de'><head><meta charset='utf-8'>"
        f"<title>Angriffspfad – {t['name']}</title>"
        "<link rel='stylesheet' href='/static/style.css'></head><body>"
        f"<div style='padding:1rem'><h1>🕸️ Hypothetischer Angriffspfad – {t['name']}</h1>"
        "<p class='hint'>Nur Darstellung/Remediation – antbb führt keinen Pfad aus.</p>"
        "<div id='attackpath-view'></div></div>"
        f"<script>window.ANTBB_TARGET_ID={target_id};</script>"
        "<script src='/static/attackpath.js'></script></body></html>")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "antbb", "scan": SCAN_STATE["status"]}


# ===================================================================
# Neuronales Gehirn — Node-/Log-API (LESEN für alle) und HUMAN-ONLY
# Lösch-/Reset-Endpunkte.
#
# HUMAN-ONLY (durchgesetzt, nicht nur UI-Hinweis): Alle DELETE-/Reset-
# Endpunkte unten laufen über antbb.brain_ops, dessen Guard ein
# ausdrückliches menschliches Bestätigungs-Flag verlangt. Dieses Flag
# (``human_confirm``) setzt NUR die interaktive GUI nach einem Confirm-
# Dialog. Weder Soldaten noch die Königin (queen.py) importieren
# brain_ops oder erreichen diese Operationen; sie haben nur Lesezugriff.
# Jede Anfrage ohne Bestätigungs-Flag wird mit 403 abgelehnt und in
# data/brain_audit.log protokolliert. Vor jedem Löschen/Reset wird
# automatisch ein DB-Backup angelegt. antbb.env/Secrets bleiben unberührt.
# ===================================================================
from .. import brain_ops as _brain_ops  # noqa: E402
from ..brain_ops import HumanConfirmError  # noqa: E402


def _human_confirm_flag(request: Request, payload: Optional[dict],
                        human_confirm: Optional[bool]) -> bool:
    """Liest das menschliche Bestätigungs-Flag aus Query, Header oder Body.

    Nur ein ausdrückliches True (von der interaktiven GUI gesetzt) zählt.
    Der eigentliche harte Guard sitzt in brain_ops; dies ist nur die
    Transport-Extraktion."""
    if human_confirm is True:
        return True
    hdr = (request.headers.get("x-human-confirm") or "").strip().lower()
    if hdr in ("1", "true", "yes", "on"):
        return True
    if isinstance(payload, dict):
        v = payload.get("human_confirm")
        if v is True or str(v).strip().lower() in ("1", "true", "yes", "on"):
            return True
    return False


# ---------------- LESEN: Nodes / Node-Detail / Logs ----------------
@app.get("/api/brain/nodes")
def api_brain_nodes():
    """Vollständiger Node-Graph (Targets/Runs/Findings/Soldaten/Logs) aus dem
    echten Store. Reiner Lesezugriff."""
    return JSONResponse(_brain_ops.nodes_graph(svc.store))


@app.get("/api/brain/node/{ntype}/{nid}")
def api_brain_node_detail(ntype: str, nid: str):
    """Detail eines Nodes inkl. zugehöriger Logs/Evidence. Lesezugriff."""
    res = _brain_ops.node_detail(svc.store, ntype, nid)
    if not res.get("ok"):
        raise HTTPException(404, res.get("reason", "nicht gefunden"))
    return JSONResponse(res)


@app.get("/api/brain/logs")
def api_brain_logs(target_id: Optional[int] = None, run_id: Optional[str] = None,
                   limit: int = 200, offset: int = 0):
    """Vollständige Logs (scan_steps), neueste zuerst, filter-/paginierbar."""
    return JSONResponse(_brain_ops.logs_page(
        svc.store, target_id=target_id, run_id=run_id, limit=limit, offset=offset))


# ---------------- HUMAN-ONLY: Löschen ----------------
@app.delete("/api/brain/logs")
async def api_brain_delete_logs(request: Request, target_id: Optional[int] = None,
                                run_id: Optional[str] = None, all: bool = False,
                                human_confirm: Optional[bool] = None):
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        return JSONResponse(_brain_ops.delete_logs(
            svc.store, human_confirm=hc, target_id=target_id,
            run_id=run_id, all_logs=bool(all)))
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))


@app.delete("/api/brain/run/{run_id}")
async def api_brain_delete_run(request: Request, run_id: str,
                               human_confirm: Optional[bool] = None):
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        return JSONResponse(_brain_ops.delete_run(
            svc.store, run_id, human_confirm=hc))
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))


@app.delete("/api/brain/finding/{finding_id}")
async def api_brain_delete_finding(request: Request, finding_id: int,
                                   human_confirm: Optional[bool] = None):
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        return JSONResponse(_brain_ops.delete_finding(
            svc.store, finding_id, human_confirm=hc))
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))


@app.delete("/api/brain/target/{target_id}")
async def api_brain_delete_target(request: Request, target_id: int,
                                  human_confirm: Optional[bool] = None):
    """HARTE Löschung (Purge) — ausdrücklich NICHT der Soft-Delete/Papierkorb.
    Human-only."""
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        return JSONResponse(_brain_ops.delete_target(
            svc.store, target_id, human_confirm=hc))
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))


@app.delete("/api/brain/all")
async def api_brain_delete_all(request: Request,
                               human_confirm: Optional[bool] = None):
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        res = _brain_ops.delete_all(svc.store, human_confirm=hc)
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))
    # In-Memory-Live-Zustand ebenfalls zurücksetzen (keine Daten, nur Anzeige).
    with _SCAN_LOCK:
        LIVE_FEED.clear()
        SCAN_STATE.update({"status": "idle", "target_id": None, "run_id": None,
                           "finding_count": 0, "severity": {}})
    _reset_agents()
    return JSONResponse(res)


# ---------------- HUMAN-ONLY: Reset laufender/hängender Agenten/Läufe ----------------
@app.post("/api/brain/run/{run_id}/reset")
async def api_brain_reset_run(request: Request, run_id: str,
                              human_confirm: Optional[bool] = None):
    """Setzt einen laufenden/hängenden Lauf sauber zurück. Human-only."""
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        res = _brain_ops.reset_run(svc.store, run_id, human_confirm=hc)
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))
    # Falls genau dieser Lauf im In-Memory-Live-Zustand aktiv ist: Anzeige leeren.
    with _SCAN_LOCK:
        if SCAN_STATE.get("run_id") == run_id or SCAN_STATE.get("status") == "running":
            SCAN_STATE.update({"status": "idle"})
    _finish_agents("reset")
    return JSONResponse(res)


@app.post("/api/brain/agent/{name}/reset")
async def api_brain_reset_agent(request: Request, name: str,
                                human_confirm: Optional[bool] = None):
    """Setzt einen hängenden Soldaten im Live-Visualisierungslayer in den
    Ausgangszustand (idle) zurück. Human-only; verändert keine persistierten
    Funde/Läufe/Königin-Wissen (reiner In-Memory-Anzeigezustand)."""
    payload = await _maybe_json(request)
    hc = _human_confirm_flag(request, payload, human_confirm)
    try:
        _brain_ops._require_human(svc.store, hc, "reset_agent")
    except HumanConfirmError as exc:
        raise HTTPException(403, str(exc))
    if name not in AGENT_STATE:
        raise HTTPException(404, f"Soldat '{name}' unbekannt")
    AGENT_STATE[name] = {"state": "idle", "task": "zurückgesetzt",
                         "scope": "", "findings": 0}
    return JSONResponse({"ok": True, "agent": name, "state": "idle"})


async def _maybe_json(request: Request) -> Optional[dict]:
    """Liest optional einen JSON-Body (für human_confirm/confirm_phrase).
    Fehlt/ungültig -> None (kein Fehler)."""
    try:
        if "application/json" in (request.headers.get("content-type") or ""):
            return await request.json()
    except Exception:
        return None
    return None


# ---------------- Routen-Reihenfolge: literale /api/brain/*-Pfade zuerst ----------------
# Der ältere dynamische Pfad /api/brain/{target_id} (Königin-Kammer) würde sonst
# literale Pfade wie /api/brain/nodes oder /api/brain/logs verschlucken
# (FastAPI/Starlette matcht in Reihenfolge). Wir schieben den dynamischen Pfad
# ans Ende, damit die neuen literalen Node-/Log-Routen Vorrang haben.
def _reorder_brain_routes() -> None:
    routes = app.router.routes
    for r in list(routes):
        if getattr(r, "path", None) == "/api/brain/{target_id}":
            routes.remove(r)
            routes.append(r)


_reorder_brain_routes()
