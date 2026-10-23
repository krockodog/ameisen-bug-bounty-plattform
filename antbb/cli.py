"""CLI-Oberfläche (argparse). Nutzt ausschließlich die Service-Fassade."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from .disclaimer import disclaimer_text, new_target_notice
from .oversight import OVERSIGHT_PROMPT, OversightError
from .reports import CHAIN_STEPS, ReportDraft, empty_chain
from .service import AntBBService


def _ts(v):
    return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M") if v else "-"


def _print_disclaimer():
    print(disclaimer_text())
    print()


def _resolve_target(svc, ref):
    t = svc.get_target(ref)
    if not t:
        print(f"Fehler: Target '{ref}' nicht gefunden.", file=sys.stderr)
        sys.exit(2)
    return t


# ---------------- Command-Handler ----------------
def cmd_target_add(svc, args):
    print(new_target_notice(args.name))
    print()
    tid = svc.add_target(args.name, args.description or "")
    print(f"✅ Target angelegt: id={tid} name={args.name}")
    print("Hinweis: Scope-Einträge hinzufügen und Oversight-Häkchen setzen, "
          "bevor ein Scan möglich ist.")


def cmd_target_list(svc, args):
    rows = svc.list_targets()
    if not rows:
        print("Keine Targets.")
        return
    for t in rows:
        conf = "✔" if svc.is_confirmed(t["id"]) else "✘"
        print(f"[{t['id']}] {t['name']}  Oversight:{conf}  ({_ts(t['created_at'])})  {t['description']}")


def cmd_target_archive(svc, args):
    t = _resolve_target(svc, args.target)
    svc.archive_target(t["id"])
    print(f"🗑 Target archiviert (Papierkorb): [{t['id']}] {t['name']}")
    print("Soft-Delete: keine Daten gelöscht. Findings, Scan-Historie, Reports und")
    print("das Wissen der Königin (Registry/Erinnerungen) bleiben vollständig erhalten.")
    print("Wiederherstellen: antbb target restore " + t["name"])


def cmd_target_restore(svc, args):
    t = _resolve_target(svc, args.target)
    svc.restore_target(t["id"])
    print(f"↩ Target wiederhergestellt: [{t['id']}] {t['name']}")


def cmd_target_trash(svc, args):
    rows = svc.list_archived_targets()
    if not rows:
        print("Papierkorb ist leer.")
        return
    print("Papierkorb (archivierte Targets – Daten + Königin-Wissen erhalten):")
    for t in rows:
        print(f"[{t['id']}] {t['name']}  (archiviert: {_ts(t['archived_at'])})  {t['description']}")


def cmd_scope_add(svc, args):
    t = _resolve_target(svc, args.target)
    sid = svc.add_scope(t["id"], args.kind, args.value, allowed=not args.out)
    tag = "OUT-OF-SCOPE" if args.out else "in-scope"
    print(f"✅ Scope-Eintrag {sid} ({tag}): {args.kind}={args.value} für {t['name']}")


def cmd_scope_list(svc, args):
    t = _resolve_target(svc, args.target)
    rows = svc.list_scopes(t["id"])
    if not rows:
        print("Keine Scope-Einträge.")
        return
    for s in rows:
        tag = "in-scope " if s["allowed"] else "OUT-SCOPE"
        print(f"[{s['id']}] {tag} {s['kind']}={s['value']}")


def cmd_scope_check(svc, args):
    t = _resolve_target(svc, args.target)
    res = svc.check_asset(t["id"], args.asset)
    mark = "✅ ERLAUBT" if res.allowed else "⛔ BLOCKIERT"
    print(f"{mark}: {args.asset}\n  → {res.reason}")
    sys.exit(0 if res.allowed else 1)


def cmd_oversight(svc, args):
    t = _resolve_target(svc, args.target)
    confirm = args.set == "on"
    if confirm:
        print(f'Bestätigung: "{OVERSIGHT_PROMPT}"')
    svc.set_oversight(t["id"], confirm, confirmed_by=args.by or "cli-user",
                      note=args.note or "")
    state = "GESETZT ✔" if confirm else "ENTFERNT ✘"
    print(f"Oversight-Häkchen für '{t['name']}' {state}")


def cmd_oversight_status(svc, args):
    t = _resolve_target(svc, args.target)
    o = svc.get_oversight(t["id"])
    if o and o["confirmed"]:
        print(f"✔ bestätigt von '{o['confirmed_by']}' am {_ts(o['confirmed_at'])}"
              + (f"  Notiz: {o['note']}" if o["note"] else ""))
    else:
        print("✘ NICHT bestätigt – Scans/Exporte sind blockiert.")


def cmd_scan(svc, args):
    t = _resolve_target(svc, args.target)
    print(new_target_notice(t["name"]))
    print()
    phases = tuple(args.phases.split(",")) if args.phases else None
    active = bool(getattr(args, "active", False))
    fuzz = bool(getattr(args, "fuzz", False))
    offensive = True if bool(getattr(args, "offensive", False)) else None
    from .active_oversight import active_trigger_requested, ACTIVE_OVERSIGHT_PROMPT
    # Konsistentes Human-Oversight-Gate: aktiver/offensiver Lauf erfordert die
    # ausdrueckliche Freigabe --oversight-ack (serverseitiges Default-Deny).
    ack = None
    if active_trigger_requested(active=active, fuzz=fuzz, offensive=offensive):
        ack = bool(getattr(args, "oversight_ack", False))
        if not ack:
            print("\n⛔ BLOCKIERT (default-deny): aktive/offensive Aktion ohne "
                  "Human-Oversight-Freigabe.", file=sys.stderr)
            print(f'   Bitte --oversight-ack setzen und bestaetigen: "{ACTIVE_OVERSIGHT_PROMPT}"',
                  file=sys.stderr)
            sys.exit(3)
    if offensive:
        print("🗡️ Offensiv-Modus ENGAGIERT (autorisiert): aktive Angriffs-Playbooks + Fuzzing.")
    if active:
        print("🔬 Aktive Verifikation (autorisiert) ist für diesen Lauf AKTIV.")
    if fuzz:
        print("🔬 Offensives Fuzzing (autorisiert) ist für diesen Lauf AKTIV.")
    try:
        if phases:
            result = svc.run_scan(t["id"], phases=phases, emit=print_event,
                                  active=active, fuzz=fuzz, offensive=offensive,
                                  oversight_ack=ack)
        else:
            result = svc.run_scan(t["id"], emit=print_event,
                                  active=active, fuzz=fuzz, offensive=offensive,
                                  oversight_ack=ack)
    except OversightError as exc:
        print(f"\n⛔ {exc}", file=sys.stderr)
        sys.exit(3)
    print()
    print(f"👑 Schwarm-Lauf {result.run_id} fertig in {result.duration:.2f}s")
    print(f"   Findings: {len(result.findings)}  Verteilung: {result.by_severity()}")
    for f in result.findings[:args.limit]:
        print(f"   - [{f.severity:8}] {f.title}  ({f.asset})  <{f.agent}>")


def print_event(ev):
    print("   " + ev.get("msg", ""))


def cmd_findings(svc, args):
    t = _resolve_target(svc, args.target) if args.target else None
    rows = svc.list_findings(t["id"] if t else None)
    if not rows:
        print("Keine Findings.")
        return
    for f in rows[:args.limit]:
        print(f"[{f['id']}] [{f['severity']:8}] {f['title']}  ({f['asset']})  <{f['agent']}>")


def cmd_report_create(svc, args):
    t = _resolve_target(svc, args.target)
    chain = empty_chain()
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        chain.update(data.get("chain", data))
    # Scope-Nachweis automatisch befüllen
    if not chain.get("scope_proof"):
        scopes = svc.list_scopes(t["id"])
        chain["scope_proof"] = "In-Scope-Einträge: " + ", ".join(
            f"{s['kind']}={s['value']}" for s in scopes if s["allowed"]
        )
    draft = ReportDraft(
        target_id=t["id"], title=args.title, chain=chain,
        cvss_score=args.cvss, cvss_vector=args.vector or "",
    )
    rid = svc.create_report(draft)
    print(f"✅ Report erstellt: id={rid}  '{args.title}'  "
          f"(CVSS {args.cvss}, Schwere {draft.severity()})")


def cmd_report_professional(svc, args):
    t = _resolve_target(svc, args.target)
    ids = [args.finding] if getattr(args, "finding", None) else None
    md = svc.professional_report(t["id"], finding_ids=ids,
                                 instruction=getattr(args, "instruction", "") or "")
    if getattr(args, "out", None):
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"✅ Profi-Bericht geschrieben: {args.out}")
    else:
        print(md)


def cmd_report_list(svc, args):
    t = _resolve_target(svc, args.target) if args.target else None
    rows = svc.list_reports(t["id"] if t else None)
    if not rows:
        print("Keine Reports.")
        return
    for r in rows:
        print(f"[{r['id']}] {r['title']}  CVSS={r['cvss_score']}  "
              f"Schwere={r['severity']}  ({_ts(r['created_at'])})")


def cmd_report_show(svc, args):
    print(svc.report_markdown(args.id))


def cmd_report_export(svc, args):
    try:
        path = svc.export_report(args.id, fmt=args.format)
    except OversightError as exc:
        print(f"⛔ {exc}", file=sys.stderr)
        sys.exit(3)
    print(f"✅ Exportiert nach: {path}")


def cmd_report_pdf(svc, args):
    """Professionellen Pentest-Report als PDF (oder HTML-Fallback) speichern."""
    import os
    from . import brandedreport as br
    tid = t_id(svc, args.target)
    brand = {"company_name": getattr(args, "company", None) or "antbb Security",
             "report_title": getattr(args, "title", None) or "Pentest-Report"}
    if getattr(args, "client", None):
        brand["client"] = args.client
    res = svc.branded_report_pdf(tid, brand=brand)
    out = getattr(args, "out", None)
    if res.get("pdf"):
        path = out or res["filename"]
        with open(path, "wb") as fh:
            fh.write(res["pdf"])
        print(f"✅ PDF: {path} (engine={res['engine']})")
        return
    # Honest-empty: HTML schreiben + klaren Hinweis ausgeben.
    path = out or res.get("html_filename") or br.report_filename(svc.store, tid, "html")
    if path.lower().endswith(".pdf"):
        path = path[:-4] + ".html"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(res["html"])
    print(f"ℹ️ Keine PDF-Engine (weasyprint/wkhtmltopdf) – HTML geschrieben: {path}")
    print(f"   {res.get('note')}")



def cmd_rating(svc, args):
    t = _resolve_target(svc, args.target)
    r = svc.rating(t["id"], with_ai=not args.no_ai)
    print(f"🛡️  Sicherheits-Rating für {t['name']}: {r['score']}/100  Note {r['grade']} "
          f"(Risikopunkte {r['risk_points']})")
    print("   Teilscores:")
    for dim, v in r["subscores"].items():
        print(f"     - {dim:16} {v['grade']} ({v['score']})  Befunde={v['count']}")
    a = r.get("assessment", {})
    if a:
        print(f"   KI-Einschätzung ({a.get('source')}, {a.get('disclaimer')}):")
        print(f"     {a.get('text')}")
    hm = r.get("heatmap", {})
    if hm:
        from antbb.rating import heatmap_markdown
        print()
        print(heatmap_markdown(hm))


def cmd_llm_status(svc, args):
    st = svc.llm_status()
    print(f"Standard-Provider: {st['default_provider']}")
    print(f"Hauptmodell (Königin): {st['main_model']}")
    print(f"Flash-Modell (schnelle Schritte): {st['fast_model']}")
    print("Konfigurierte LLM-Provider:")
    for p in st["providers"]:
        dflt = " [default]" if p["is_default"] else ""
        extra = ""
        if p.get("provider") == "ollama":
            extra = f"  erreichbar={'ja' if p.get('reachable') else 'nein'}"
        print(f"  - {p['provider']:8}{dflt}  Status={p['auth_state']}  "
              f"(auth_mode={p['auth_mode']}, OAuth={'ja' if p['oauth_available'] else 'nein'})"
              f"{extra}")
        print(f"      Base-URL={p['base_url']}  Modelle={p['default_model']}/{p['fast_model']}  "
              f"(Key-EnvVar={p['key_env']})")


def cmd_capabilities(svc, args):
    reg = svc.capabilities(rebuild=True)
    print("👑 Königin-Gedächtnis · Capability-Registry (Single Source of Truth)")
    print(f"   Soldaten: {reg.get('soldier_count', 0)} · "
          f"Playbooks: {reg.get('playbook_count', 0)} · "
          f"Tools: {reg.get('tool_count', 0)}")
    print()
    if getattr(args, "json", False):
        print(json.dumps(reg, ensure_ascii=False, indent=2))
        return
    for sol in reg.get("soldiers", []):
        print(f"🐜 {sol['specialty']}  (Agent '{sol['name']}', Phasen: {', '.join(sol['phases']) or '-'})")
        print(f"   {sol['role']}")
        for pb in sol["playbooks"]:
            gate = "OVERSIGHT" if pb["oversight_required"] else "frei"
            print(f"     • [{pb['mode']:9}/{gate:9}] {pb['name']}: {', '.join(pb['tools'])}")
        print()



# ---------------- WLAN-Survey (passiv) ----------------
def _parse_samples(items):
    samples = {}
    for it in (items or []):
        if "=" not in it:
            print(f"Ignoriere Sample ohne '=': {it}", file=sys.stderr)
            continue
        bssid, rssi = it.split("=", 1)
        samples[bssid.strip().lower()] = rssi.strip()
    return samples


def _resolve_tid(svc, ref):
    if not ref:
        return None
    t = svc.get_target(ref)
    return t["id"] if t else None


def cmd_osint_username(svc, args):
    res = svc.osint_username(args.username, emit=print_event)
    print(f"🔎 OSINT Username-Enumeration: '{res['username']}' "
          f"(Tool: {res.get('tool') or '-'})")
    if not res.get("available"):
        print("   ⚠ weder sherlock noch maigret installiert – honest-empty "
              "(kein erfundener Treffer).")
        return
    results = res.get("results", [])
    if not results:
        print("   (keine Treffer – ehrlicher Leerzustand)")
        return
    for r in results:
        print(f"   - [{r['status']}] {r['title']}")
        for site in (r.get("evidence", {}) or {}).get("sites", [])[:40]:
            print(f"       · {site['site']:24} {site['url']}")
    print("   (REFERENZ/informativ – Profile wurden NICHT abgerufen/verifiziert.)")


def cmd_wlan_scan(svc, args):
    res = svc.wlan_scan(iface=args.iface, emit=print_event)
    print(f"🛰️  Passiver WLAN-Umgebungs-Scan (Tool: {res.get('tool') or '-'}, "
          f"Interface: {res.get('iface') or '-'})")
    if res.get("reason"):
        print(f"   ⚠ {res['reason']}")
    tools = res.get("tools", {})
    missing = [t for t, ok in tools.items() if not ok]
    if missing:
        print(f"   Fehlende Tools (für Deploy): {', '.join(missing)}")
    aps = res.get("aps", [])
    if not aps:
        print("   (keine APs – ehrlicher Leerzustand)")
        return
    for a in aps:
        print(f"   - {a.get('ssid') or '(versteckt)':24} {a['bssid']}  "
              f"Ch {a.get('channel') or '?':>3} ({a.get('band') or '?'} GHz)  "
              f"RSSI {a.get('rssi') if a.get('rssi') is not None else '?'} dBm  "
              f"{a.get('encryption') or '?'}")


def cmd_wlan_addpoint(svc, args):
    tid = _resolve_tid(svc, args.target)
    samples = _parse_samples(args.sample)
    if not samples:
        print("Keine gültigen Samples (BSSID=RSSI) angegeben.", file=sys.stderr)
        sys.exit(2)
    n = svc.wlan_add_point(args.label, samples, target_id=tid,
                           own_bssids=[b.lower() for b in (args.own or [])])
    print(f"✅ Mess-Punkt '{args.label}' gespeichert: {n} Sample(s)"
          + (f" (Target {tid})" if tid else " (ohne Target)"))


def cmd_wlan_channels(svc, args):
    tid = _resolve_tid(svc, args.target)
    survey = svc.wlan_survey(target_id=tid, own_bssids=[b.lower() for b in (args.own or [])],
                             iface=args.iface, scan=args.scan)
    ca = survey["channel_analysis"]
    print(f"📶 Kanal-Belegung (sichtbare APs: {ca['ap_count']}, eigene: {ca['own_ap_count']})")
    for band, usage in ca["channel_usage"].items():
        if usage:
            cells = ", ".join(f"Ch{ch}:{cnt}" for ch, cnt in sorted(usage.items()))
            print(f"   {band} GHz: {cells}")
    if ca["overlaps_24"]:
        print("   2,4-GHz-Überlappungen: " +
              ", ".join(f"{o['ch_a']}↔{o['ch_b']}" for o in ca["overlaps_24"]))
    if ca["self_interference"]:
        print(f"   ⚠ Selbst-Störung ({ca['self_interference_count']}):")
        for c in ca["self_interference"]:
            print(f"      - [{c['severity']}] {c['note']}")
    elif ca["own_ap_count"] >= 2:
        print("   ✅ Keine Selbst-Störung zwischen eigenen APs.")
    if ca["ap_count"] == 0:
        print("   (keine APs – führe 'wlan-survey scan' aus oder nutze --scan)")


def cmd_wlan_recommend(svc, args):
    tid = _resolve_tid(svc, args.target)
    survey = svc.wlan_survey(target_id=tid, own_bssids=[b.lower() for b in (args.own or [])],
                             iface=args.iface, scan=args.scan)
    rec = survey["recommendations"]
    cov = survey["coverage"]
    print("🧭 Optimierungs-Empfehlungen (regelbasiert, nur aus Messwerten):")
    if rec["best_channel_24"]:
        b = rec["best_channel_24"]
        print(f"   Bester 2,4-GHz-Kanal: {b['channel']} (Last {b['load']})")
    for r in rec["channel_recommendations"]:
        print(f"   • {r}")
    if rec["band_steering_hint"]:
        print(f"   • {rec['band_steering_hint']}")
    if rec["tx_power_hint"]:
        print(f"   • {rec['tx_power_hint']}")
    print(f"   Abdeckung: {cov['measured_count']} Messpunkt(e), "
          f"{cov['dead_zone_count']} Funkloch/-löcher "
          f"(Schwelle {cov['threshold_dbm']} dBm)")
    for pl in rec["placement"]:
        print(f"   • {pl}")
    if not rec["channel_recommendations"] and not rec["placement"]:
        print("   (zu wenig Daten – scanne die Umgebung und füge Messpunkte hinzu)")


# ---------------- WLAN-Offensiv (AUTORISIERT: Engagement-Gate) ----------------
def cmd_wlanoff_eng_create(svc, args):
    tid = _resolve_tid(svc, args.target) if getattr(args, "target", None) else None
    eid = svc.wlan_engagement_create(
        args.name, bssids=[b.lower() for b in (args.bssid or [])],
        ssids=(args.ssid or []), duration_hours=args.hours,
        client_mac=(args.client_mac or ""), location=(args.location or ""),
        target_id=tid, oversight=bool(args.oversight))
    print(f"✅ WLAN-Engagement #{eid} '{args.name}' angelegt "
          f"(Dauer {args.hours}h, Oversight={'✔' if args.oversight else '✘'}).")
    if not args.oversight:
        print("   ⚠ Oversight NICHT gesetzt – Aktionen bleiben blockiert "
              "(wlan-offensive eng oversight <id> on).")


def cmd_wlanoff_eng_list(svc, args):
    engs = svc.wlan_engagement_list()
    if not engs:
        print("Keine WLAN-Engagements.")
        return
    import time as _t
    now = _t.time()
    for e in engs:
        active = (not e["revoked"] and e["oversight"]
                  and e["start_ts"] <= now <= e["end_ts"])
        tag = "AKTIV" if active else ("WIDERRUFEN" if e["revoked"] else "inaktiv")
        print(f"[{e['id']}] {tag:10} {e['name']}  BSSID={e['bssids']} SSID={e['ssids']} "
              f"ov={'✔' if e['oversight'] else '✘'}  "
              f"Fenster {_ts(e['start_ts'])}–{_ts(e['end_ts'])}")


def cmd_wlanoff_eng_oversight(svc, args):
    svc.wlan_engagement_oversight(args.id, args.set == "on")
    print(f"Oversight für Engagement #{args.id}: {'GESETZT ✔' if args.set=='on' else 'ENTFERNT ✘'}")


def cmd_wlanoff_eng_revoke(svc, args):
    svc.wlan_engagement_revoke(args.id)
    print(f"Engagement #{args.id} widerrufen. Weitere Aktionen blockiert.")


def _run_off(svc, action, args):
    res = svc.wlan_offensive_run(
        action, bssid=getattr(args, "bssid", "") or "",
        ssid=getattr(args, "ssid", "") or "",
        client_mac=getattr(args, "client_mac", "") or "",
        seconds=int(getattr(args, "seconds", 60) or 60),
        packets=int(getattr(args, "packets", 10) or 10),
        capture_path=getattr(args, "capture", "") or "",
        dry_run=bool(getattr(args, "dry_run", False)))
    mark = "✅ Gate bestanden" if res["allowed"] else "⛔ BLOCKIERT (default-deny)"
    print(f"{mark}: {res['reason']}")
    if res["allowed"]:
        if res["honest_empty"]:
            print(f"   ℹ️ honest-empty (Tool/Hardware fehlt) – nichts erfunden.")
        if res.get("tool"):
            print(f"   Tool: {res['tool']}  invoked={res['tool_invoked']}")
        det = res.get("detail") or {}
        if det.get("warning"):
            print(f"   ⚠ {det['warning']}")
    import sys as _s
    _s.exit(0 if res["allowed"] else 1)


def cmd_wlanoff_capture(svc, args):
    _run_off(svc, "handshake-capture", args)


def cmd_wlanoff_deauth(svc, args):
    _run_off(svc, "targeted-deauth", args)


def cmd_wlanoff_crack(svc, args):
    _run_off(svc, "offline-crack", args)


def cmd_wlanoff_eviltwin(svc, args):
    _run_off(svc, "evil-twin-demo", args)


def cmd_wlanoff_creds(svc, args):
    if getattr(args, "purge", False):
        n = svc.wlan_credentials_purge(getattr(args, "engagement", None))
        print(f"🧹 {n} Credential-Datensatz/e gelöscht.")
        return
    creds = svc.wlan_credentials_list(getattr(args, "engagement", None))
    if not creds:
        print("Keine Credentials (ehrlich leer).")
        return
    for c in creds:
        print(f"[{c['id']}] [{c['kind']}] {c['masked']}  (eng#{c['engagement_id']}, sha256 gesalzen)")


# ---------------- ARES "acceptable half" (defensiv/Infra) ----------------
def cmd_firewall_plan(svc, args):
    t = _resolve_target(svc, args.target)
    plan = svc.egress_firewall_plan(t["id"], resolve=not args.no_resolve)
    print(f"🧱 Scope-Egress-Firewall (DRY-RUN) für {t['name']}")
    print(f"   In-Scope-Egress-Ziele: {plan['scopes_in']}  "
          f"(nicht auflösbar: {len(plan['unresolved'])})")
    print(f"   Engines am Laufort: {svc.egress_firewall_engines()}")
    if args.nft:
        print("\n# nftables:\n" + plan["nft_ruleset"])
    else:
        print("\n# iptables:")
        for r in plan["iptables_rules"]:
            print("   " + r)
    print("\n" + plan["apply_report"])
    if plan.get("note"):
        print("⚠ " + plan["note"])


def cmd_firewall_apply(svc, args):
    t = _resolve_target(svc, args.target)
    res = svc.egress_firewall_apply(t["id"], engine=args.engine, confirm=args.confirm)
    mark = "✅ ANGEWANDT" if res["applied"] else "ℹ️ NICHT angewandt (honest no-op)"
    print(f"{mark} (engine={args.engine})")
    print(res["apply_report"])


def cmd_branded_report(svc, args):
    brand = {"company_name": args.company or "antbb Security",
             "logo_path": args.logo or "",
             "primary_color": args.color or "#1f6feb",
             "report_title": args.title or "Sicherheitsbericht"}
    res = svc.branded_report_export(t_id(svc, args.target), brand=brand,
                                    want_pdf=not args.no_pdf)
    print(f"✅ Branded HTML: {res['html_path']}")
    if res.get("pdf_path"):
        print(f"✅ PDF: {res['pdf_path']} ({res['pdf_engine']})")
    else:
        print(f"ℹ️ PDF: {res['pdf_note']}")


def t_id(svc, ref):
    return _resolve_target(svc, ref)["id"]


def cmd_plugins_list(svc, args):
    blk = svc.plugins_list(args.dir)
    print(f"🔌 Plugins ({blk['plugin_count']}) aus {blk['plugins_dir']}")
    for m in blk["plugins"]:
        print(f"   • {m['name']} v{m['version']} [{m['mode']}/{m['category']}] "
              f"von {m['author']} – {m['description'][:60]}")
    for e in blk["errors"]:
        print(f"   ⚠ Ladefehler {e.get('class','')} in {e['source']}: {e['error']}")


def cmd_plugins_run(svc, args):
    t = _resolve_target(svc, args.target)
    try:
        res = svc.plugins_run(args.name, t["id"], plugins_dir=args.dir)
    except ValueError as exc:
        print(f"Fehler: {exc}", file=sys.stderr); sys.exit(2)
    mark = "✅" if res["ok"] else "❌"
    print(f"{mark} Plugin '{res['plugin']}' → {res['count']} Finding(s)"
          + (f"  Fehler: {res['error']}" if not res["ok"] else ""))


def cmd_checkpoints(svc, args):
    tid = _resolve_tid(svc, args.target) if getattr(args, "target", None) else None
    cps = svc.checkpoints_list(tid)
    if not cps:
        print("Keine Checkpoints/Läufe gespeichert.")
        return
    for c in cps:
        print(f"[{c['run_id']}] target={c['target_id']} status={c['status']} "
              f"steps={c['steps']}  ({_ts(c['started_at'])})")


def cmd_checkpoint_resume(svc, args):
    res = svc.checkpoint_resume(args.run_id)
    print(f"▶ Lauf {res['run_id']}: status={res['status']} – {res.get('note','')}")


def cmd_checkpoint_replay(svc, args):
    r = svc.checkpoint_replay(args.run_id, emit=print_event if args.verbose else None)
    print(f"🔁 Replay {r['run_id']}: {r['step_count']} Schritte "
          f"({r['events']} Events, {r['findings']} Findings, "
          f"Phasen: {', '.join(r['phases']) or '-'}) – keine Tools neu gestartet.")


def cmd_attackpath(svc, args):
    t = _resolve_target(svc, args.target)
    if args.markdown:
        print(svc.attack_paths_markdown(t["id"]))
        return
    g = svc.attack_graph(t["id"])
    print(f"🕸️ Hypothetischer Angriffspfad-Graph für {t['name']}: "
          f"{len(g['nodes'])} Knoten, {len(g['edges'])} Kanten "
          f"({g['counted']} Befunde).")
    print("   " + g["note"])
    for pth in g["paths"]:
        print(f"   ▸ {pth['asset']} (max {pth['max_severity']}):")
        for st in pth["steps"]:
            print(f"      - [{st['severity']}] {st['finding']} → {st['enables']}  "
                  f"(Fix: {st['remediation']})")


# ---------------- Parser ----------------
def cmd_remote_status(svc, args):
    st = svc.remote_status()
    print(f"Fernzugriff-Modus: {st['mode']}  (Default: off = nur lokal)")
    print(f"Lokal:      {st['local_url']}")
    if st['active_url']:
        print(f"Aktiv-URL:  {st['active_url']}")
    ts = st['tailscale']
    if ts['installed']:
        state = 'laeuft' if ts['running'] else 'inaktiv'
        ip = ts['ip'] or '-'
        print(f"Tailscale:  installiert · {state} · IP {ip}  ({ts['detail']})")
    else:
        print("Tailscale:  nicht installiert (honest-empty)")
    cf = st['cloudflare']
    if cf['installed']:
        print(f"cloudflared: installiert · {cf['version'] or 'Version unbekannt'}")
    else:
        print("cloudflared: nicht installiert (honest-empty)")
    print("Hinweis: Auswahl speichert nur die Praeferenz – es wird nichts "
          "gestartet oder exponiert.")


def cmd_remote_set(svc, args):
    m = svc.set_remote_mode(args.mode)
    print(f"Fernzugriff-Modus gespeichert: {m}  (nichts gestartet/exponiert)")
    for step in svc.remote_setup_steps(m):
        print(f"  - {step}")


def cmd_remote_tunnel_status(svc, args):
    from . import remote_access as ra
    rt = ra.cloudflare_tunnel_runtime()
    state = "laeuft" if rt["running"] else "aus"
    print(f"Cloudflare-Tunnel: {state}"
          + (f" · PID {rt['pid']}" if rt.get("pid") else "")
          + (f" · {rt['url']}" if rt.get("url") else ""))
    print(f"  {rt['detail']}")


def cmd_remote_tunnel_start(svc, args):
    from . import remote_access as ra
    if not args.oversight:
        print("ABGELEHNT: Start nur mit --oversight (menschliche Bestaetigung). "
              "Ein Cloudflare-Tunnel macht die GUI oeffentlich erreichbar.")
        return
    res = ra.start_cloudflare_tunnel(oversight=True, named=args.named)
    try:
        if res.get("ok"):
            svc.set_remote_mode("cloudflare")
    except Exception:
        pass
    print(("OK: " if res.get("ok") else "FEHLER: ") + res.get("reason", ""))
    if res.get("url"):
        print(f"  Oeffentliche URL: {res['url']}")
    elif res.get("ok"):
        print("  URL noch nicht im Log – gleich 'remote tunnel status' abfragen.")


def cmd_remote_tunnel_stop(svc, args):
    from . import remote_access as ra
    res = ra.stop_cloudflare_tunnel()
    print(("OK: " if res.get("ok") else "FEHLER: ") + res.get("reason", ""))


def build_parser():
    p = argparse.ArgumentParser(
        prog="antbb",
        description="Ameisen-Schwarm Bug-Bounty-Framework (lokal, simuliert).",
    )
    p.add_argument("--db", help="Pfad zur SQLite-DB (optional).")
    p.add_argument("--no-banner", action="store_true", help="Disclaimer nicht anzeigen.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # target
    tp = sub.add_parser("target", help="Targets verwalten").add_subparsers(dest="sub", required=True)
    a = tp.add_parser("add"); a.add_argument("name"); a.add_argument("-d", "--description"); a.set_defaults(fn=cmd_target_add)
    a = tp.add_parser("list"); a.set_defaults(fn=cmd_target_list)
    a = tp.add_parser("archive", help="Target in den Papierkorb (Soft-Delete, wiederherstellbar)"); a.add_argument("target"); a.set_defaults(fn=cmd_target_archive)
    a = tp.add_parser("restore", help="Target aus dem Papierkorb wiederherstellen"); a.add_argument("target"); a.set_defaults(fn=cmd_target_restore)
    a = tp.add_parser("trash", help="Papierkorb anzeigen (archivierte Targets)"); a.set_defaults(fn=cmd_target_trash)

    # scope
    sp = sub.add_parser("scope", help="Scope/Allowlist verwalten").add_subparsers(dest="sub", required=True)
    a = sp.add_parser("add"); a.add_argument("target"); a.add_argument("kind", choices=["domain", "ip", "path", "url"]); a.add_argument("value"); a.add_argument("--out", action="store_true", help="als Out-of-Scope markieren"); a.set_defaults(fn=cmd_scope_add)
    a = sp.add_parser("list"); a.add_argument("target"); a.set_defaults(fn=cmd_scope_list)
    a = sp.add_parser("check"); a.add_argument("target"); a.add_argument("asset"); a.set_defaults(fn=cmd_scope_check)

    # oversight
    op = sub.add_parser("oversight", help="Human-Oversight-Häkchen").add_subparsers(dest="sub", required=True)
    a = op.add_parser("set"); a.add_argument("target"); a.add_argument("set", choices=["on", "off"]); a.add_argument("--by"); a.add_argument("--note"); a.set_defaults(fn=cmd_oversight)
    a = op.add_parser("status"); a.add_argument("target"); a.set_defaults(fn=cmd_oversight_status)

    # scan
    a = sub.add_parser("scan", help="Schwarm-Scan starten (benötigt Oversight)")
    a.add_argument("target"); a.add_argument("--phases", help="z.B. recon,scan,verify,analyze,report")
    a.add_argument("--active", action="store_true",
                   help="TIEFE, kontrollierte aktive Verifikation freischalten (autorisiert; "
                        "benötigt weiterhin Oversight + Scope)")
    a.add_argument("--fuzz", action="store_true",
                   help="Kontrolliertes offensives Fuzzing freischalten (autorisiert; "
                        "GET Content-Discovery mit Catch-all-Baseline; "
                        "benötigt weiterhin Oversight + Scope; unabhängig von --active)")
    a.add_argument("--offensive", action="store_true",
                   help="Offensiv-Modus ENGAGIEREN: führt aktive Angriffs-Playbooks + Fuzzing "
                        "aus (kein read-only Fallback). Benötigt Scope + Oversight + "
                        "policy auto/offensive.")
    a.add_argument("--oversight-ack", dest="oversight_ack", action="store_true",
                   help="Human-Oversight-Freigabe fuer aktive/offensive Laeufe "
                        "(--active/--fuzz/--offensive). Ohne diese Freigabe wird "
                        "jede aktive/offensive Aktion verweigert (default-deny).")
    a.add_argument("--limit", type=int, default=20); a.set_defaults(fn=cmd_scan)

    # findings
    a = sub.add_parser("findings", help="Findings auflisten")
    a.add_argument("target", nargs="?"); a.add_argument("--limit", type=int, default=50); a.set_defaults(fn=cmd_findings)

    # llm
    lp = sub.add_parser("llm", help="LLM-Connector").add_subparsers(dest="sub", required=True)
    a = lp.add_parser("status"); a.set_defaults(fn=cmd_llm_status)

    # report
    rp = sub.add_parser("report", help="Reports verwalten").add_subparsers(dest="sub", required=True)
    a = rp.add_parser("create"); a.add_argument("target"); a.add_argument("title"); a.add_argument("--cvss", type=float); a.add_argument("--vector"); a.add_argument("--from-json", help="Chain aus JSON-Datei laden"); a.set_defaults(fn=cmd_report_create)
    a = rp.add_parser("list"); a.add_argument("target", nargs="?"); a.set_defaults(fn=cmd_report_list)
    a = rp.add_parser("show"); a.add_argument("id", type=int); a.set_defaults(fn=cmd_report_show)
    a = rp.add_parser("professional"); a.add_argument("target"); a.add_argument("--finding", type=int); a.add_argument("--instruction"); a.add_argument("--out"); a.set_defaults(fn=cmd_report_professional)
    a = rp.add_parser("export"); a.add_argument("id", type=int); a.add_argument("--format", choices=["md", "json"], default="md"); a.set_defaults(fn=cmd_report_export)
    a = rp.add_parser("pdf", help="Professionellen Pentest-Report als PDF (honest-empty → HTML)")
    a.add_argument("target"); a.add_argument("-o", "--out", help="Ausgabedatei")
    a.add_argument("--company"); a.add_argument("--title"); a.add_argument("--client")
    a.set_defaults(fn=cmd_report_pdf)

    # rating
    a = sub.add_parser("rating", help="Neutrales Sicherheits-Rating + Heatmap")
    a.add_argument("target"); a.add_argument("--no-ai", action="store_true",
                   help="ohne KI-Einschätzung")
    a.set_defaults(fn=cmd_rating)

    # capabilities (Königin-Gedächtnis: Skills/Playbooks/Tools aller Soldaten)
    a = sub.add_parser("capabilities", help="Capability-Registry der Königin anzeigen")
    a.add_argument("--json", action="store_true", help="als JSON ausgeben")
    a.set_defaults(fn=cmd_capabilities)

    # osint (passiv, read-only: Username-Enumeration via sherlock/maigret)
    osp = sub.add_parser("osint", help="Passive OSINT-Aktionen (read-only)")\
        .add_subparsers(dest="sub", required=True)
    a = osp.add_parser("username", help="Username/Handle ueber soziale Netze enumerieren (sherlock/maigret)")
    a.add_argument("username")
    a.set_defaults(fn=cmd_osint_username)

    # wlan-survey (PASSIV: Coverage/Kanal/Optimierung – keine Angriffe)
    wp = sub.add_parser("wlan-survey",
                        help="Passive WLAN-Abdeckung/Kanal-Analyse + Optimierung")\
        .add_subparsers(dest="sub", required=True)
    a = wp.add_parser("scan", help="Passiver Umgebungs-Scan (iw/nmcli, kein Monitor-Mode)")
    a.add_argument("--iface", help="WLAN-Interface (sonst Auto-Erkennung)")
    a.set_defaults(fn=cmd_wlan_scan)
    a = wp.add_parser("add-point", help="Mess-Punkt mit BSSID=RSSI-Samples speichern")
    a.add_argument("label"); a.add_argument("--sample", action="append",
                   help="BSSID=RSSI (dBm), mehrfach angebbar")
    a.add_argument("--own", action="append", help="eigene Fritzbox-BSSID (mehrfach)")
    a.add_argument("--target", help="optionales Target (Name/ID)")
    a.set_defaults(fn=cmd_wlan_addpoint)
    a = wp.add_parser("channels", help="Kanal-Belegung/Überlappung/Selbst-Störung zeigen")
    a.add_argument("--target"); a.add_argument("--iface")
    a.add_argument("--own", action="append"); a.add_argument("--scan", action="store_true",
                   help="vorher live scannen")
    a.set_defaults(fn=cmd_wlan_channels)
    a = wp.add_parser("recommend", help="Optimierungs-Empfehlungen zeigen")
    a.add_argument("--target"); a.add_argument("--iface")
    a.add_argument("--own", action="append"); a.add_argument("--scan", action="store_true")
    a.set_defaults(fn=cmd_wlan_recommend)


    # ---- ARES "acceptable half" (defensiv/Infra) ----
    fp = sub.add_parser("firewall", help="Scope-Egress-Firewall (DRY-RUN, default-deny)")\
        .add_subparsers(dest="sub", required=True)
    a = fp.add_parser("plan", help="iptables/nft-Egress-Regelsatz aus Scope zeigen (DRY-RUN)")
    a.add_argument("target"); a.add_argument("--nft", action="store_true", help="nftables statt iptables")
    a.add_argument("--no-resolve", action="store_true", help="keine DNS-Auflösung")
    a.set_defaults(fn=cmd_firewall_plan)
    a = fp.add_parser("apply", help="Regeln anwenden (nur mit root+Binary+ENV+--confirm)")
    a.add_argument("target"); a.add_argument("--engine", choices=["iptables", "nftables"], default="iptables")
    a.add_argument("--confirm", action="store_true"); a.set_defaults(fn=cmd_firewall_apply)

    a = sub.add_parser("branded-report", help="Gebrandeten HTML/PDF-Bericht exportieren")
    a.add_argument("target"); a.add_argument("--company"); a.add_argument("--logo")
    a.add_argument("--color"); a.add_argument("--title")
    a.add_argument("--no-pdf", action="store_true"); a.set_defaults(fn=cmd_branded_report)

    pp = sub.add_parser("plugins", help="Lokales Module-SDK (Plugins)")\
        .add_subparsers(dest="sub", required=True)
    a = pp.add_parser("list"); a.add_argument("--dir"); a.set_defaults(fn=cmd_plugins_list)
    a = pp.add_parser("run"); a.add_argument("name"); a.add_argument("target")
    a.add_argument("--dir"); a.set_defaults(fn=cmd_plugins_run)

    cp = sub.add_parser("checkpoint", help="Replay-/Checkpoint-Engine")\
        .add_subparsers(dest="sub", required=True)
    a = cp.add_parser("list"); a.add_argument("target", nargs="?"); a.set_defaults(fn=cmd_checkpoints)
    a = cp.add_parser("resume"); a.add_argument("run_id"); a.set_defaults(fn=cmd_checkpoint_resume)
    a = cp.add_parser("replay"); a.add_argument("run_id")
    a.add_argument("--verbose", action="store_true"); a.set_defaults(fn=cmd_checkpoint_replay)

    # ---- Fernzugriff / Remote-Access ----
    rmp = sub.add_parser("remote", help="Fernzugriff (off|tailscale|cloudflare): Status + Praeferenz")\
        .add_subparsers(dest="sub", required=True)
    a = rmp.add_parser("status", help="Ehrlicher, rein lesender Fernzugriff-Status")
    a.set_defaults(fn=cmd_remote_status)
    a = rmp.add_parser("set", help="Praeferenz setzen (startet/exponiert NICHTS)")
    a.add_argument("mode", choices=["off", "tailscale", "cloudflare"])
    a.set_defaults(fn=cmd_remote_set)
    tn = rmp.add_parser("tunnel", help="Cloudflare-Tunnel aktiv starten/stoppen (oversight-gated)")\
        .add_subparsers(dest="tsub", required=True)
    a = tn.add_parser("status", help="Laufzeit-Status des verwalteten Tunnels")
    a.set_defaults(fn=cmd_remote_tunnel_status)
    a = tn.add_parser("start", help="Tunnel starten – NUR mit --oversight")
    a.add_argument("--oversight", action="store_true", help="menschliche Bestaetigung (Pflicht)")
    a.add_argument("--named", action="store_true", help="benannter Tunnel via CLOUDFLARE_TUNNEL_TOKEN statt trycloudflare")
    a.set_defaults(fn=cmd_remote_tunnel_start)
    a = tn.add_parser("stop", help="verwalteten Tunnel stoppen")
    a.set_defaults(fn=cmd_remote_tunnel_stop)

    return p


def main(argv=None):
    import logging
    logging.basicConfig(level=logging.WARNING)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_banner and args.cmd in ("scan", "target"):
        _print_disclaimer()
    svc = AntBBService(db_path=getattr(args, "db", None))
    try:
        args.fn(svc, args)
    finally:
        svc.close()


if __name__ == "__main__":
    main()
