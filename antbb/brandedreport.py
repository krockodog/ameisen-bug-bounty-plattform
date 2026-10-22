"""Branded Report-Pipeline: konfigurierbarer, hochprofessioneller HTML-/PDF-Export.

Ergänzt die bestehende `findingreport.py`: nimmt dieselben ECHTEN Finding-Daten
(nichts erfunden) und rendert sie in ein gebrandetes, druck- und PDF-fähiges
Pentest-Dokument mit Deckblatt (Klassifizierung VERTRAULICH), Inhaltsverzeichnis,
Management Summary (Rating/Heatmap), Methodik & Scope, Pro-Finding-Abschnitten
(ID, Severity, CVSS, Status aus dem Proof-Gate, Beschreibung, PoC/Evidence,
konkrete Remediation, Referenzen), Zählübersicht und Anhang.

Harte Regeln (unverändert):
  * Proof-Gate bleibt die Wahrheitsquelle: `VERIFIZIERT` nur mit aktiver Evidence.
  * Zählungen kommen aus `proofgate` (Single Source of Truth) – keine
    Severity-Inflation, keine Geister-Funde, konsistente Counts.
  * Keine Secrets im Export.

Druck/PDF:
  * Das HTML trägt einen sauberen `@media print`-Stil (helles, druckfreundliches
    Dokument, Nav/Buttons/Hintergrund ausgeblendet, Seitenumbrüche, Kopf-/Fußzeile,
    Ränder). Der Browser-Druck (Print → Als PDF speichern) funktioniert damit immer.
  * Serverseitiges PDF wird NUR erzeugt, wenn eine Engine vorhanden ist
    (weasyprint-Python-Modul oder das Binary `wkhtmltopdf`). Fehlt beides →
    honest-empty auf PDF (klarer Hinweis), das HTML funktioniert immer.
"""
from __future__ import annotations

import html
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from . import findingreport as _fr
from .reports import CHAIN_STEPS


@dataclass
class BrandConfig:
    company_name: str = "antbb Security"
    logo_path: str = ""
    primary_color: str = "#1f6feb"
    accent_color: str = "#3fffa3"
    footer_note: str = ""
    report_title: str = "Pentest-Report"
    client: str = ""
    classification: str = "VERTRAULICH"

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "BrandConfig":
        d = d or {}
        known = {k: d[k] for k in cls().__dict__ if k in d}
        return cls(**known)


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _slug(s: str) -> str:
    import re
    s = (s or "report").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "report"


def _logo_tag(cfg: BrandConfig) -> str:
    """Bettet das Logo als data-URI ein, falls vorhanden (sonst Leerstring)."""
    p = cfg.logo_path
    if not p or not os.path.isfile(p):
        return ""
    import base64, mimetypes
    mime = mimetypes.guess_type(p)[0] or "image/png"
    try:
        with open(p, "rb") as fh:
            b = base64.b64encode(fh.read()).decode("ascii")
        return f'<img class="logo" src="data:{mime};base64,{b}" alt="logo">'
    except Exception:
        return ""


def pdf_engine() -> Optional[str]:
    """Verfügbare PDF-Engine: 'weasyprint' | 'wkhtmltopdf' | None."""
    try:
        import weasyprint  # noqa: F401
        return "weasyprint"
    except Exception:
        pass
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    return None


# Schlüssel, die nie in den Report-Anhang dürfen (Secret-Schutz).
_SECRET_KEYS = ("password", "passwort", "token", "secret", "apikey", "api_key",
                "authorization", "cookie", "set-cookie", "private_key",
                "privatekey", "credential", "credentials", "pwd", "pass")


def _is_secretish(key: str) -> bool:
    k = str(key).lower()
    return any(s in k for s in _SECRET_KEYS)


def _references_for(row) -> list:
    """Sammelt CVE/CWE/Referenzen aus der Finding-Evidence (nichts erfunden)."""
    ev = _fr.parse_evidence(row)
    out: list[str] = []
    for k in ("cve", "cve_id", "cves"):
        v = ev.get(k)
        if isinstance(v, (list, tuple)):
            out += [str(x) for x in v if x]
        elif v:
            out.append(str(v))
    for k in ("cwe", "cwe_id", "cwes"):
        v = ev.get(k)
        if isinstance(v, (list, tuple)):
            out += [str(x) for x in v if x]
        elif v:
            out.append(str(v))
    refs = ev.get("references") or ev.get("refs")
    if isinstance(refs, (list, tuple)):
        out += [str(x) for x in refs if x]
    elif refs:
        out.append(str(refs))
    # Dedupe unter Beibehaltung der Reihenfolge.
    seen, uniq = set(), []
    for r in out:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def _evidence_appendix(row) -> list:
    """Gekürzte, secret-gefilterte Evidence-Paare für den Anhang."""
    ev = _fr.parse_evidence(row)
    pairs = []
    for k, v in ev.items():
        if _is_secretish(k):
            continue
        if isinstance(v, (dict, list)):
            import json
            sval = json.dumps(v, ensure_ascii=False)[:400]
        else:
            sval = str(v)[:400]
        sval = sval.replace("\n", " ")
        pairs.append((str(k), sval))
    return pairs


def build_html(store, target_id: int, cfg: BrandConfig,
               finding_ids: Optional[list] = None, *,
               toolbar: bool = False,
               pdf_download_url: Optional[str] = None,
               engine_note: str = "") -> str:
    """Rendert das gebrandete, professionelle HTML aus echten Findings.

    `toolbar`           blendet die GUI-Aktionsleiste (PDF/Drucken) ein
                        (im Druck/PDF via @media print ausgeblendet).
    `pdf_download_url`  Ziel des „PDF herunterladen“-Buttons.
    `engine_note`       optionaler Hinweis-Banner (z. B. honest-empty: keine Engine).
    """
    from . import proofgate as pg
    from .agents.base import AgentFinding

    target = store.get_target(target_id)
    tname = _fr._g(target, "name", str(target_id)) if target else str(target_id)
    rows = store.list_findings(target_id)
    if finding_ids:
        idset = {int(i) for i in finding_ids}
        rows = [r for r in rows if int(_fr._g(r, "id", -1)) in idset]

    try:
        scopes = store.list_scopes(target_id)
    except Exception:
        scopes = []
    in_scope = [s for s in scopes if _fr._g(s, "allowed", 0)]

    # Rating + Heatmap + konsistente Zählungen aus denselben Daten.
    afs = []
    for r in rows:
        afs.append(AgentFinding(
            agent=_fr._g(r, "agent", ""), title=_fr._g(r, "title", ""),
            category=_fr._g(r, "category", ""), severity=_fr._g(r, "severity", "info"),
            asset=_fr._g(r, "asset", ""), description=_fr._g(r, "description", ""),
            evidence=_fr.parse_evidence(r), status=_fr._g(r, "status", ""),
            false_positive=bool(_fr._g(r, "false_positive", 0)),
        ))
    pg.enforce(afs, None)
    counted = pg.counted_findings(afs)
    by_sev = pg.severity_counts(afs)
    by_status = pg.status_counts(afs)
    fp_count = len([f for f in afs if f.false_positive])
    verified = [f for f in counted if f.status == "VERIFIZIERT"]
    proofgate_ok = all(f.has_active_evidence() for f in verified)

    rating = hm = None
    assess = {"text": "", "source": "", "disclaimer": ""}
    try:
        from . import rating as rating_mod
        rating = rating_mod.compute_rating(list(afs))
        hm = rating_mod.build_heatmap(list(afs))
        assess = rating_mod.ai_assessment(rating, llm=None)
    except Exception:
        pass

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    skip = {"report-summary", "llm-report", "analysis-cvss", "correlation",
            "llm-analysis", "poc", "proofgate-validation"}
    ordered = sorted(
        [r for r in rows if not bool(_fr._g(r, "false_positive", 0))
         and _fr._g(r, "category", "") not in skip],
        key=lambda r: rank.get(_fr._g(r, "severity", "info"), 0), reverse=True)

    pc, ac = _esc(cfg.primary_color), _esc(cfg.accent_color)
    sev_badge = {"critical": "#c0392b", "high": "#d35400", "medium": "#b9770e",
                 "low": "#1d7a46", "info": "#5b6672"}
    sev_label = {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel",
                 "low": "Niedrig", "info": "Info"}

    P = []
    P.append(f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(cfg.report_title)} – {_esc(tname)}</title>
<style>
  :root{{ --pc:{pc}; --ac:{ac}; }}
  *{{box-sizing:border-box;}}
  html,body{{background:#f4f6f8;}}
  body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:#1b1f24;
    margin:0;line-height:1.55;}}
  .page{{background:#fff;max-width:900px;margin:0 auto;box-shadow:0 2px 18px rgba(0,0,0,.12);}}
  /* Aktionsleiste (nur Bildschirm) */
  .toolbar{{position:sticky;top:0;z-index:50;background:#0c0f14;color:#e6edf3;
    display:flex;gap:.6rem;align-items:center;padding:.7rem 1rem;flex-wrap:wrap;}}
  .toolbar .sp{{flex:1;}}
  .btn{{display:inline-flex;align-items:center;gap:.4rem;background:var(--pc);color:#fff;
    border:none;border-radius:8px;padding:.55rem .95rem;font-size:.95rem;font-weight:600;
    cursor:pointer;text-decoration:none;}}
  .btn.secondary{{background:#2d333b;}}
  .btn:hover{{filter:brightness(1.08);}}
  .engine-note{{background:#fff8e1;border:1px solid #f0d58a;color:#6b5300;
    padding:.7rem 1rem;margin:0;font-size:.9rem;}}
  /* Deckblatt */
  .cover{{min-height:92vh;background:linear-gradient(140deg,var(--pc),#0b1b30);
    color:#fff;padding:3.2rem 3rem;display:flex;flex-direction:column;}}
  .cover .classif{{align-self:flex-start;border:2px solid #ff5a5a;color:#ffd4d4;
    letter-spacing:.14em;font-weight:700;padding:.3rem .8rem;border-radius:4px;
    font-size:.82rem;}}
  .cover .logo{{max-height:70px;margin:1.6rem 0 .4rem;}}
  .cover h1{{font-size:2.7rem;margin:1.2rem 0 .3rem;line-height:1.1;}}
  .cover .sub{{font-size:1.25rem;opacity:.95;}}
  .cover .cmeta{{margin-top:auto;line-height:1.8;opacity:.95;}}
  .cover .cmeta b{{color:var(--ac);}}
  .cover .brandline{{font-size:1.1rem;font-weight:700;margin-top:1.6rem;}}
  /* Inhalt */
  .wrap{{padding:2.4rem 3rem;}}
  h2{{color:var(--pc);border-bottom:2px solid var(--ac);padding-bottom:.35rem;
    margin-top:2.6rem;font-size:1.5rem;}}
  h3{{margin:1.1rem 0 .3rem;font-size:1.15rem;}}
  .toc ol{{line-height:1.9;}}
  .toc a{{color:var(--pc);text-decoration:none;}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;
    font-size:.78rem;font-weight:600;}}
  table{{border-collapse:collapse;width:100%;margin:.7rem 0;}}
  th,td{{border:1px solid #d7dde3;padding:6px 9px;text-align:left;font-size:.9rem;
    vertical-align:top;}}
  th{{background:#eef2f6;}}
  .kpi{{display:flex;gap:1rem;flex-wrap:wrap;margin:.6rem 0 1rem;}}
  .kpi .box{{border:1px solid #e1e6eb;border-radius:8px;padding:.7rem 1rem;min-width:120px;}}
  .kpi .box .n{{font-size:1.8rem;font-weight:800;color:var(--pc);}}
  .kpi .box .l{{font-size:.78rem;color:#5b6672;text-transform:uppercase;letter-spacing:.05em;}}
  .score{{font-size:2.6rem;font-weight:800;color:var(--pc);}}
  .grade{{display:inline-block;background:var(--pc);color:#fff;border-radius:10px;
    padding:.1rem .7rem;font-weight:800;}}
  .finding{{border:1px solid #e1e6eb;border-left:5px solid var(--pc);border-radius:8px;
    padding:1rem 1.2rem;margin:1.1rem 0;}}
  .finding h3{{margin-top:0;}}
  .meta-row{{color:#44505c;font-size:.86rem;margin:.2rem 0 .6rem;}}
  pre{{background:#0d1117;color:#c9d1d9;padding:.8rem;border-radius:6px;overflow:auto;
    font-size:.82rem;white-space:pre-wrap;word-break:break-word;}}
  .hint{{color:#5b6672;font-size:.86rem;}}
  ul.chain{{margin:.3rem 0 .3rem 1.1rem;padding:0;}}
  ul.chain li{{margin:.2rem 0;}}
  .refs{{font-size:.86rem;}}
  .docfooter{{margin:2.6rem 3rem;padding-top:1rem;border-top:1px solid #d7dde3;
    color:#5b6672;font-size:.82rem;}}
  .pagebreak{{break-before:page;}}
  .warnbox{{background:#fff4f4;border:1px solid #f0bcbc;color:#7a1f1f;
    padding:.7rem 1rem;border-radius:6px;margin:1rem 0;font-size:.9rem;}}
  /* ---------------- DRUCK / PDF ---------------- */
  @media print{{
    @page{{ size:A4; margin:18mm 15mm 20mm 15mm; }}
    html,body{{background:#fff;}}
    .page{{box-shadow:none;max-width:none;margin:0;}}
    .toolbar,.engine-note{{display:none !important;}}
    .cover{{min-height:auto;height:100vh;}}
    .wrap{{padding:0;}}
    h2{{break-before:page;}}
    h2:first-of-type{{break-before:avoid;}}
    .finding,table,pre{{break-inside:avoid;}}
    a{{color:#1b1f24;text-decoration:none;}}
    .docfooter{{margin:1.2rem 0 0;}}
  }}
</style></head><body><div class="page">""")

    # ---- Aktionsleiste (Bildschirm) ----
    if toolbar:
        pdf_url = pdf_download_url or f"/target/{target_id}/report.pdf"
        P.append('<div class="toolbar">')
        P.append(f'<span style="font-weight:700">🐜 {_esc(cfg.report_title)}</span>')
        P.append('<span class="sp"></span>')
        P.append(f'<a class="btn" href="{_esc(pdf_url)}">📄 PDF herunterladen</a>')
        P.append('<button class="btn secondary" onclick="window.print()">🖨 Drucken</button>')
        P.append("</div>")
    if engine_note:
        P.append(f'<p class="engine-note">⚠️ {_esc(engine_note)}</p>')

    # ---- Deckblatt ----
    P.append('<div class="cover">')
    P.append(f'<span class="classif">{_esc(cfg.classification or "VERTRAULICH")}</span>')
    logo = _logo_tag(cfg)
    if logo:
        P.append(logo)
    P.append(f"<h1>{_esc(cfg.report_title)}</h1>")
    P.append(f'<div class="sub">Ziel / Scope: {_esc(tname)}</div>')
    P.append('<div class="cmeta">')
    if cfg.client:
        P.append(f'<div><b>Kunde:</b> {_esc(cfg.client)}</div>')
    P.append(f'<div><b>Dienstleister:</b> {_esc(cfg.company_name)}</div>')
    P.append(f'<div><b>Erstellt:</b> {now} (Europe/Berlin)</div>')
    P.append(f'<div><b>Target-ID:</b> {target_id}</div>')
    P.append(f'<div><b>Klassifizierung:</b> {_esc(cfg.classification or "VERTRAULICH")}</div>')
    if rating:
        P.append(f'<div><b>Gesamtbewertung:</b> Note {_esc(rating["grade"])} '
                 f'· {rating["score"]}/100</div>')
    P.append(f'<div class="brandline">Erstellt mit antbb – lokales, autorisiertes '
             f'Pentest-Framework</div>')
    P.append("</div>")  # cmeta
    P.append("</div>")  # cover

    P.append('<div class="wrap">')

    # ---- Inhaltsverzeichnis ----
    P.append('<h2 id="toc">Inhaltsverzeichnis</h2>')
    P.append('<div class="toc"><ol>')
    toc_items = [
        ("mgmt", "Management Summary"),
        ("method", "Methodik &amp; Scope"),
        ("findings", "Befunde im Detail"),
        ("counts", "Zählübersicht"),
        ("anhang", "Anhang – Rohdaten / Evidence"),
    ]
    for anchor, label in toc_items:
        P.append(f'<li><a href="#{anchor}">{label}</a></li>')
    P.append("</ol></div>")

    # ---- Management Summary (Executive Summary) ----
    P.append('<h2 id="mgmt" class="pagebreak">Management Summary (Executive Summary)</h2>')
    if rating:
        P.append('<p>')
        P.append(f'<span class="score">{rating["score"]}</span>'
                 f'<span style="color:#5b6672">/100</span> &nbsp; '
                 f'Note <span class="grade">{_esc(rating["grade"])}</span>')
        P.append('</p>')
        P.append('<div class="kpi">')
        P.append(f'<div class="box"><div class="n">{rating["counted_findings"]}</div>'
                 f'<div class="l">Gezählte Befunde</div></div>')
        P.append(f'<div class="box"><div class="n">{rating["verified_count"]}</div>'
                 f'<div class="l">Aktiv verifiziert</div></div>')
        P.append(f'<div class="box"><div class="n">{rating["risk_points"]}</div>'
                 f'<div class="l">Risikopunkte</div></div>')
        P.append(f'<div class="box"><div class="n">{fp_count}</div>'
                 f'<div class="l">Als FP ausgeschlossen</div></div>')
        P.append('</div>')
        sc = rating["severity_counts"]
        P.append("<p><strong>Severity-Verteilung:</strong> ")
        for sev in ("critical", "high", "medium", "low", "info"):
            P.append(f'<span class="badge" style="background:{sev_badge[sev]};">'
                     f'{sev_label[sev]}: {sc.get(sev,0)}</span> ')
        P.append("</p>")
        # Klartext-Risikoeinschätzung (deterministisch aus den Zahlen).
        risk_txt = _plain_risk_text(rating, sc)
        P.append(f'<p>{_esc(risk_txt)}</p>')
        if assess.get("text"):
            P.append(f'<p class="hint"><strong>KI-Einschätzung</strong> '
                     f'({_esc(assess["source"])}, {_esc(assess["disclaimer"])}): '
                     f'{_esc(assess["text"])}</p>')
    else:
        P.append('<p class="hint">Keine zählbaren Befunde (ehrlicher Leerzustand – '
                 'keine bestätigten Befunde für dieses Target).</p>')

    if not proofgate_ok:
        P.append('<div class="warnbox">Proof-Gate-Verletzung erkannt: Ein als '
                 'VERIFIZIERT geführter Befund trägt keine aktive Evidence. Bitte prüfen.</div>')
    open_states = {"ZU BESTÄTIGEN", "BEDINGT", "REFERENZ"}
    if any(f.status in open_states for f in counted):
        P.append('<div class="warnbox">⚠️ ZWISCHENSTAND: Es existieren Befunde mit '
                 'Status ZU BESTÄTIGEN / BEDINGT / REFERENZ. Nur VERIFIZIERT ist aktiv '
                 'belegt; alles andere ist nicht als bewiesen zu behandeln.</div>')

    # ---- Risiko-Heatmap ----
    if hm and hm.get("total_cells"):
        P.append("<h3>Risiko-Heatmap (Dimension × Severity)</h3>")
        sevs = hm["severities"]; dims = hm["dimensions"]; sm = hm["severity_matrix"]
        P.append("<table><tr><th>Dimension \\ Severity</th>" +
                 "".join(f"<th>{_esc(sev_label.get(s,s))}</th>" for s in sevs) +
                 "<th>Σ</th></tr>")
        for d in dims:
            P.append(f"<tr><td>{_esc(d)}</td>")
            for s in sevs:
                c = sm.get(d, {}).get(s, {})
                cnt = c.get("count", 0)
                inten = c.get("intensity", 0.0)
                bg = f"rgba(192,57,43,{0.10+0.55*inten:.2f})" if cnt else "transparent"
                P.append(f'<td style="background:{bg};text-align:center;">{cnt or "·"}</td>')
            P.append(f"<td style='text-align:center;'>{hm['row_totals'].get(d,0)}</td></tr>")
        P.append("</table>")

    # ---- Methodik & Scope ----
    P.append('<h2 id="method" class="pagebreak">Methodik &amp; Scope</h2>')
    P.append("<h3>Scope / Allowlist (default-deny)</h3>")
    if in_scope:
        P.append("<table><tr><th>Typ</th><th>Wert</th><th>Status</th></tr>")
        for s in scopes:
            allowed = _fr._g(s, "allowed", 0)
            st = ('<span class="badge" style="background:#1d7a46;">in-scope</span>'
                  if allowed else
                  '<span class="badge" style="background:#5b6672;">out-of-scope</span>')
            P.append(f"<tr><td>{_esc(_fr._g(s,'kind',''))}</td>"
                     f"<td><code>{_esc(_fr._g(s,'value',''))}</code></td><td>{st}</td></tr>")
        P.append("</table>")
    else:
        P.append('<p class="hint">Kein In-Scope-Eintrag hinterlegt (default-deny: ohne '
                 'Allowlist blockiert jeder aktive Check).</p>')
    P.append("<h3>Vorgehen</h3>")
    P.append("<ul>")
    P.append("<li><strong>Modi:</strong> defensive Aufklärung (passiv) und – nur bei "
             "Scope + Human-Oversight – autorisierte aktive Verifikation "
             "(XSS/SQLi/Redirect/Traversal/Artefakte/CORS/Missing-Auth) sowie Fuzzing.</li>")
    P.append("<li><strong>Autorisierung &amp; Oversight:</strong> Alle aktiven/offensiven "
             "Aktionen sind serverseitig durch ein Human-Oversight-Gate geschützt "
             "(default-deny); ohne Freigabe wird nichts ausgeführt.</li>")
    P.append("<li><strong>Rechtlicher Rahmen:</strong> Tests ausschließlich im "
             "autorisierten Scope. § 202a–c StGB (Ausspähen/Abfangen/Vorbereiten) bzw. "
             "CFAA sind zu beachten; es wurde keine Handlung außerhalb der Freigabe "
             "durchgeführt.</li>")
    P.append("<li><strong>Beweis-Stufen (Proof-Gate):</strong> VERIFIZIERT nur mit aktiver "
             "Request+Response-Evidence; abgeleitete/versionsbasierte Treffer bleiben "
             "ZU BESTÄTIGEN, bedingte Funde BEDINGT, Fremd-CVEs REFERENZ. Catch-all-/"
             "Baseline-Artefakte werden als False-Positive ausgeschlossen.</li>")
    P.append("<li><strong>Tooling:</strong> antbb-Agenten-Schwarm (Recon, Scanning, API, "
             "Auth, Fuzzing, Verifikation, Analyse, Threat-Intel) – lokale, "
             "on-device-Ausführung; Secrets werden nicht in den Bericht geschrieben.</li>")
    P.append("</ul>")

    # ---- Befunde im Detail ----
    P.append('<h2 id="findings" class="pagebreak">Befunde im Detail</h2>')
    if not ordered:
        P.append('<p class="hint">Keine bestätigten Befunde für dieses Target '
                 '(ehrlicher Leerzustand – „keine bestätigten Befunde“).</p>')
    for i, r in enumerate(ordered, 1):
        c = _fr.chain_from_finding(store, r)
        sev = c["severity"]
        fid = c.get("finding_id")
        fid_txt = f"F-{fid}" if fid is not None else f"F{i:03d}"
        P.append('<div class="finding">')
        P.append(f'<h3>{fid_txt} · {i}. {_esc(c["title"])} '
                 f'<span class="badge" style="background:{sev_badge.get(sev,"#5b6672")};">'
                 f'{_esc(sev_label.get(sev,sev))}</span></h3>')
        vect = c.get("cvss_vector") or "Vektor n/a"
        P.append(f'<p class="meta-row">'
                 f'<strong>Status:</strong> {_esc(c["status"] or "n/a")} &nbsp;·&nbsp; '
                 f'<strong>CVSS (Schätzung):</strong> {c["cvss_score"]} ({_esc(vect)}) &nbsp;·&nbsp; '
                 f'<strong>Asset:</strong> {_esc(_fr._g(r,"asset","") or "n/a")} &nbsp;·&nbsp; '
                 f'<strong>Agent:</strong> {_esc(_fr._g(r,"agent",""))} &nbsp;·&nbsp; '
                 f'<strong>Kategorie:</strong> {_esc(c.get("category",""))}</p>')
        P.append('<ul class="chain">')
        for key, label in CHAIN_STEPS:
            val = c["chain"].get(key, "")
            if key == "poc":
                P.append(f'</ul><strong>{_esc(label)} / PoC &amp; Evidence:</strong>'
                         f'<pre>{_esc(val)}</pre><ul class="chain">')
            else:
                P.append(f'<li><strong>{_esc(label)}:</strong> {_esc(val)}</li>')
        P.append("</ul>")
        P.append(f'<strong>Behebung / Remediation:</strong>'
                 f'<pre>{_esc(_fr.remediation_for(r))}</pre>')
        refs = _references_for(r)
        if refs:
            P.append('<p class="refs"><strong>Referenzen:</strong> '
                     + ", ".join(_esc(x) for x in refs) + "</p>")
        P.append("</div>")

    # ---- Zählübersicht ----
    P.append('<h2 id="counts" class="pagebreak">Zählübersicht</h2>')
    P.append('<p class="hint">Einzige Wahrheitsquelle: Zählungen aus der Finding-Liste '
             '(Proof-Gate), ohne False-Positives/Meta-Aggregate – keine Doppel- oder '
             'Geister-Zählung, keine Severity-Inflation.</p>')
    P.append("<h3>Nach Severity</h3>")
    P.append("<table><tr><th>Severity</th><th>Anzahl</th></tr>")
    tot = 0
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0); tot += n
        P.append(f"<tr><td>{sev_label[sev]}</td><td>{n}</td></tr>")
    P.append(f"<tr><th>Summe (gezählt)</th><th>{tot}</th></tr>")
    P.append(f"<tr><td>Als Catch-all/False-Positive ausgeschlossen</td><td>{fp_count}</td></tr>")
    P.append("</table>")
    P.append("<h3>Nach Beweis-Stufe (Status)</h3>")
    P.append("<table><tr><th>Status</th><th>Anzahl</th></tr>")
    if by_status:
        for k, v in by_status.items():
            P.append(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>")
    else:
        P.append('<tr><td colspan="2">—</td></tr>')
    P.append("</table>")
    P.append(f'<p class="hint">Aktiv verifiziert (VERIFIZIERT): {len(verified)} · '
             f'Proof-Gate: {"bestanden – kein VERIFIZIERT ohne aktive Evidence" if proofgate_ok else "VERLETZT – bitte prüfen"}.</p>')

    # ---- Anhang ----
    P.append('<h2 id="anhang" class="pagebreak">Anhang – Rohdaten / Evidence</h2>')
    P.append('<p class="hint">Gekürzte, secret-gefilterte Evidence-Auszüge je Befund '
             '(Werte auf 400 Zeichen begrenzt; Passwörter/Token/Keys entfernt).</p>')
    if not ordered:
        P.append('<p class="hint">Keine Evidence – keine bestätigten Befunde.</p>')
    for i, r in enumerate(ordered, 1):
        fid = _fr._g(r, "id", None)
        fid_txt = f"F-{fid}" if fid is not None else f"F{i:03d}"
        pairs = _evidence_appendix(r)
        P.append(f'<h3>{fid_txt} · {_esc(_fr._g(r,"title",""))}</h3>')
        if not pairs:
            P.append('<p class="hint">Keine strukturierte Evidence erfasst.</p>')
            continue
        P.append("<table><tr><th>Schlüssel</th><th>Wert (gekürzt)</th></tr>")
        for k, v in pairs:
            P.append(f"<tr><td><code>{_esc(k)}</code></td><td>{_esc(v)}</td></tr>")
        P.append("</table>")

    P.append("</div>")  # wrap
    foot = cfg.footer_note or (
        f"{cfg.classification or 'VERTRAULICH'} · Erstellt mit antbb. Tests nur im "
        "autorisierten Scope. § 202a-c StGB / CFAA beachten. Keine Secrets im Bericht.")
    P.append(f'<div class="docfooter">{_esc(foot)}</div>')
    P.append("</div></body></html>")  # page
    return "\n".join(P)


def _plain_risk_text(rating: dict, sev_counts: dict) -> str:
    """Deterministische Klartext-Risikoeinschätzung aus den gezählten Zahlen."""
    crit = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)
    med = sev_counts.get("medium", 0)
    total = rating.get("counted_findings", 0)
    grade = rating.get("grade", "?")
    if total == 0:
        return ("Es wurden keine zählbaren Befunde festgestellt. Die Sicherheitslage "
                "des geprüften Scopes ist nach aktuellem Stand unauffällig.")
    if crit:
        posture = (f"kritisch: {crit} kritische(r) Befund(e) erfordern sofortiges Handeln")
    elif high:
        posture = (f"erhöht: {high} Befund(e) mit hoher Schwere sollten kurzfristig "
                   "behoben werden")
    elif med:
        posture = ("moderat: überwiegend mittlere/niedrige Befunde, geordnete Behebung "
                   "empfohlen")
    else:
        posture = ("niedrig: nur Befunde geringer Schwere / Informationscharakter")
    return (f"Die Gesamt-Risikolage ist {posture}. Note {grade} auf Basis von {total} "
            f"gezählten Befunden. Priorität: zuerst kritische und hohe Befunde, "
            "anschließend mittlere und niedrige gemäß Remediation-Abschnitt.")


@dataclass
class ExportResult:
    html_path: str
    pdf_path: Optional[str] = None
    pdf_engine: Optional[str] = None
    pdf_note: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def render_pdf_bytes(doc: str) -> tuple:
    """Rendert HTML → PDF-Bytes, falls Engine vorhanden.

    Rückgabe: (pdf_bytes|None, engine|None, note). honest-empty ohne Engine.
    """
    engine = pdf_engine()
    if not engine:
        return None, None, ("Honest-empty: keine PDF-Engine (weasyprint/wkhtmltopdf) "
                            "am Laufort installiert – es wurde kein PDF erzeugt.")
    try:  # pragma: no cover (nur mit installierter Engine)
        if engine == "weasyprint":
            import weasyprint
            data = weasyprint.HTML(string=doc).write_pdf()
            if data:
                return data, engine, f"PDF via {engine} erzeugt."
            return None, engine, f"PDF-Engine {engine} erzeugte keine Daten."
        else:
            with tempfile.TemporaryDirectory() as td:
                hp = os.path.join(td, "in.html")
                pp = os.path.join(td, "out.pdf")
                with open(hp, "w", encoding="utf-8") as fh:
                    fh.write(doc)
                subprocess.run(["wkhtmltopdf", hp, pp], check=False)
                if os.path.isfile(pp) and os.path.getsize(pp) > 0:
                    with open(pp, "rb") as fh:
                        return fh.read(), engine, f"PDF via {engine} erzeugt."
                return None, engine, f"PDF-Engine {engine} erzeugte keine Datei."
    except Exception as exc:  # pragma: no cover
        return None, engine, f"PDF-Erzeugung fehlgeschlagen ({engine}): {exc}"


def report_filename(store, target_id: int, ext: str = "pdf") -> str:
    """Sinnvoller Dateiname: antbb-report-<target>-<YYYY-MM-DD>.<ext>."""
    target = store.get_target(target_id)
    tname = _fr._g(target, "name", str(target_id)) if target else str(target_id)
    date = datetime.now().strftime("%Y-%m-%d")
    return f"antbb-report-{_slug(tname)}-{date}.{ext}"


def export(store, target_id: int, cfg: BrandConfig, out_dir: str,
           finding_ids: Optional[list] = None, want_pdf: bool = True) -> ExportResult:
    """Schreibt das gebrandete HTML (immer) + PDF (falls Engine vorhanden)."""
    os.makedirs(out_dir, exist_ok=True)
    doc = build_html(store, target_id, cfg, finding_ids=finding_ids)
    base = f"branded_report_target{target_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    html_path = os.path.join(out_dir, base + ".html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    res = ExportResult(html_path=html_path)
    if not want_pdf:
        res.pdf_note = "PDF nicht angefordert."
        return res
    data, engine, note = render_pdf_bytes(doc)
    res.pdf_engine = engine
    res.pdf_note = note
    if data:
        pdf_path = os.path.join(out_dir, base + ".pdf")
        with open(pdf_path, "wb") as fh:
            fh.write(data)
        res.pdf_path = pdf_path
    return res
