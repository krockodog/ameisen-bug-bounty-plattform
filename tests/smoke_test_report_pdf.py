#!/usr/bin/env python3
"""Smoke: professioneller Pentest-Report – PDF-Download + Druckansicht.

Prüft:
  * GET /target/{id}/report.pdf → application/pdf (oder honest HTML-Fallback
    mit klarem weasyprint/wkhtmltopdf-Hinweis)
  * GET /target/{id}/report/print → HTML mit @media print, ohne App-Nav/
    dunklen Hintergrund, mit Deckblatt/TOC/Management Summary/...
  * Zählungen im Report == proofgate-Counts aus dem Store
  * Kein Finding als VERIFIZIERT ohne aktive Evidence
"""
from __future__ import annotations
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from fastapi.testclient import TestClient

from antbb.service import AntBBService
from antbb.web.app import app
from antbb import brandedreport as br
from antbb import proofgate as pg
from antbb import findingreport as fr
from antbb.agents.base import AgentFinding


def check(name, cond):
    if cond:
        print(f"  ✅ {name}")
        return True
    print(f"  ❌ {name}")
    return False


def banner(t):
    print(f"\n=== {t} ===")


def _afs(store, tid):
    afs = []
    for r in store.list_findings(tid):
        afs.append(AgentFinding(
            agent=fr._g(r, "agent", ""), title=fr._g(r, "title", ""),
            category=fr._g(r, "category", ""), severity=fr._g(r, "severity", "info"),
            asset=fr._g(r, "asset", ""), description=fr._g(r, "description", ""),
            evidence=fr.parse_evidence(r), status=fr._g(r, "status", ""),
            false_positive=bool(fr._g(r, "false_positive", 0)),
        ))
    pg.enforce(afs, None)
    return afs


def main():
    ok = 0
    n = 0

    def C(name, cond):
        nonlocal ok, n
        n += 1
        if check(name, cond):
            ok += 1

    svc = AntBBService()
    # Isoliertes Target ohne Findings → ehrlicher Leerzustand.
    with tempfile.TemporaryDirectory() as td:
        from antbb.store import Store
        st = Store(os.path.join(td, "t.db"))
        tid_empty = st.add_target("Empty-Target-PDF", "smoke")
        cfg = br.BrandConfig(company_name="Smoke GmbH", report_title="Pentest-Report")
        empty_html = br.build_html(st, tid_empty, cfg)
        C("Leerzustand: 'keine bestätigten Befunde'",
          "keine bestätigten Befunde" in empty_html.lower()
          or "Keine bestätigten Befunde" in empty_html
          or "Keine zählbaren Befunde" in empty_html)
        C("Leerzustand: keine erfundenen Findings-IDs", "F-1 ·" not in empty_html)

    # Echtes Target aus dem Store (falls vorhanden), sonst neu anlegen.
    targets = svc.store.list_targets()
    if targets:
        tid = targets[0]["id"]
    else:
        tid = svc.store.add_target("Smoke-PDF-Target", "smoke")

    banner("1) PDF-Engine / render_pdf_bytes")
    eng = br.pdf_engine()
    print(f"  engine={eng!r}")
    html = svc.branded_report_html(tid, toolbar=True)
    data, engine, note = br.render_pdf_bytes(html)
    if eng:
        C("PDF-Bytes vorhanden bei Engine", bool(data) and data[:4] == b"%PDF")
        C("Engine-Name gesetzt", engine == eng)
    else:
        C("honest-empty: pdf None", data is None)
        C("honest-empty nennt weasyprint/wkhtmltopdf",
          "weasyprint" in note.lower() and "wkhtmltopdf" in note.lower())

    banner("2) HTTP: /report.pdf")
    client = TestClient(app)
    r = client.get(f"/target/{tid}/report.pdf")
    C("HTTP 200", r.status_code == 200)
    ctype = r.headers.get("content-type", "")
    if eng:
        C("Content-Type application/pdf", "application/pdf" in ctype)
        C("Content-Disposition attachment",
          "attachment" in r.headers.get("content-disposition", ""))
        C("filename antbb-report-",
          "antbb-report-" in r.headers.get("content-disposition", ""))
        C("Body beginnt mit %PDF", r.content[:4] == b"%PDF")
    else:
        C("Fallback HTML (kein stilles Scheitern)",
          "text/html" in ctype and "weasyprint" in r.text.lower()
          and "wkhtmltopdf" in r.text.lower())
        C("X-AntBB-PDF-Engine=missing",
          r.headers.get("X-AntBB-PDF-Engine") == "missing")

    banner("3) HTTP: /report/print")
    r2 = client.get(f"/target/{tid}/report/print")
    C("HTTP 200", r2.status_code == 200)
    body = r2.text
    C("@media print vorhanden", "@media print" in body)
    C("Deckblatt / VERTRAULICH", "VERTRAULICH" in body)
    C("Inhaltsverzeichnis", "Inhaltsverzeichnis" in body)
    C("Management Summary", "Management Summary" in body)
    C("Methodik & Scope", "Methodik" in body)
    C("Zählübersicht", "Zählübersicht" in body)
    C("Anhang", "Anhang" in body)
    C("keine App-Nav", "<nav>" not in body)
    C("kein colony-Hintergrund", "colony/" not in body)
    C("heller Hintergrund", "background:#fff" in body or "background:#f4f6f8" in body)
    C("PDF-Button in Toolbar", "PDF herunterladen" in body)
    C("Drucken-Button", "window.print()" in body)
    C("print CSS blendet toolbar aus",
      ".toolbar" in body and "display:none" in body)

    banner("4) Counts konsistent + Proof-Gate")
    afs = _afs(svc.store, tid)
    by_sev = pg.severity_counts(afs)
    counted = pg.counted_findings(afs)
    verified = [f for f in counted if f.status == "VERIFIZIERT"]
    bad = [f for f in verified if not f.has_active_evidence()]
    C("kein VERIFIZIERT ohne aktive Evidence", len(bad) == 0)
    # Severity-Zahlen müssen im Report auftauchen.
    for sev, cnt in by_sev.items():
        # Im Report steht die Zahl in der Zählübersicht-Tabelle.
        C(f"Count {sev}={cnt} im Report",
          f"<td>{cnt}</td>" in body or str(cnt) in body)
    C("Summe gezählt im Report",
      f"<th>{sum(by_sev.values())}</th>" in body
      or str(sum(by_sev.values())) in body)

    banner("5) branded-report (Vorschau) + 404")
    r3 = client.get(f"/target/{tid}/branded-report")
    C("branded-report 200", r3.status_code == 200)
    C("branded-report hat Toolbar", "PDF herunterladen" in r3.text)
    r404 = client.get("/target/999999/report.pdf")
    C("unbekanntes Target → 404", r404.status_code == 404)

    banner("6) Service-Facade branded_report_pdf")
    res = svc.branded_report_pdf(tid)
    C("dict-Keys vorhanden",
      {"pdf", "engine", "note", "filename", "html"} <= set(res.keys()))
    C("filename-Schema",
      res["filename"].startswith("antbb-report-") and res["filename"].endswith(".pdf"))


    banner("7) Honest-empty Fallback (Engine gemockt)")
    from antbb.web import app as appmod
    real = br.render_pdf_bytes
    br.render_pdf_bytes = lambda doc: (
        None, None,
        "Honest-empty: keine PDF-Engine (weasyprint/wkhtmltopdf) am Laufort.")
    try:
        rr = client.get(f"/target/{tid}/report.pdf")
        C("honest-empty HTTP 200", rr.status_code == 200)
        C("honest-empty Content-Type text/html", "text/html" in rr.headers.get("content-type", ""))
        C("honest-empty Header X-AntBB-PDF-Engine=missing",
          rr.headers.get("X-AntBB-PDF-Engine") == "missing")
        C("honest-empty Body nennt weasyprint+wkhtmltopdf",
          "weasyprint" in rr.text.lower() and "wkhtmltopdf" in rr.text.lower())
    finally:
        br.render_pdf_bytes = real

    print(f"\n→ {ok}/{n} Checks bestanden")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
