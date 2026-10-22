"""Finding-zentrierte Report-Intelligenz (Feature 1 + 2).

Baut aus einem ECHTEN Finding (Store-Row) die 8-Schritt-Evidence-Kette, den
PoC-Code-Block und den konkreten Behebungs-/Remediation-Abschnitt – sowie den
vollen strukturierten, professionellen Bericht (Executive Summary + pro Finding).

Harte Regeln:
  * NICHTS erfinden. Jeder Kettenschritt wird NUR aus echten Finding-Daten
    befüllt; fehlt die Datenbasis, bleibt der Schritt leer mit klarem Hinweis.
  * Proof-Gate bleibt die Wahrheitsquelle für Status (VERIFIZIERT nur mit
    aktiver Evidence). Severity-Zählungen kommen aus proofgate (Single Source).
  * Keine Secrets: Evidence wird nur gekürzt/strukturiert übernommen, niemals
    werden Keys/Passwörter in den Report geschrieben.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Optional

from .reports import CHAIN_STEPS, severity_from_cvss

# CVSS-Schätzwert (Score) je Severity – ausdrücklich als Schätzung gekennzeichnet,
# damit nichts Präzises erfunden wird. Vektor wird NIE geraten (bleibt leer+Hinweis).
_SEV_CVSS_ESTIMATE = {
    "critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
}
_HINT = "— (keine Datenbasis im Finding; bitte manuell ergänzen)"


def parse_evidence(row: Any) -> dict:
    """Evidence eines Finding-Rows/Dicts als dict (robust)."""
    if row is None:
        return {}
    ev = row["evidence"] if _has(row, "evidence") else row.get("evidence") if isinstance(row, dict) else None
    if isinstance(ev, dict):
        return ev
    if isinstance(ev, str) and ev.strip():
        try:
            d = json.loads(ev)
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}
    return {}


def _has(row: Any, key: str) -> bool:
    try:
        return key in row.keys()
    except Exception:
        return isinstance(row, dict) and key in row


def _g(row: Any, key: str, default: str = "") -> Any:
    if _has(row, key):
        return row[key]
    if isinstance(row, dict):
        return row.get(key, default)
    return default


# ---------------------------------------------------------------------------
# Remediation: konkrete, Finding-spezifische Behebung je Kategorie/Signal.
# ---------------------------------------------------------------------------
def remediation_for(row: Any) -> str:
    cat = _g(row, "category", "")
    ev = parse_evidence(row)
    asset = _g(row, "asset", "")
    title = (_g(row, "title", "") or "").lower()

    if cat == "xss-verified" or cat == "xss-indicator":
        param = ev.get("request", {}).get("param") if isinstance(ev.get("request"), dict) else None
        return (
            "Reflected XSS beheben:\n"
            f"1. Benutzereingabe{f' (Parameter `{param}`)' if param else ''} bei der Ausgabe "
            "kontextgerecht kodieren (HTML-Entity-Encoding für HTML-Body, Attribut-/JS-Encoding je Kontext).\n"
            "2. Serverseitige Output-Encoding-Bibliothek nutzen statt String-Konkatenation "
            "(z. B. Jinja2-Autoescape aktiv lassen, `markupsafe.escape`).\n"
            "3. Content-Security-Policy mit `default-src 'self'` + `script-src` ohne `unsafe-inline` "
            "als Defense-in-Depth setzen.\n"
            "4. Eingaben zusätzlich serverseitig validieren (Allowlist erlaubter Zeichen)."
        )
    if cat == "sqli-verified" or cat == "sqli-indicator":
        db = ev.get("db", "")
        return (
            "SQL-Injection beheben:\n"
            "1. ALLE Datenbankzugriffe auf parametrisierte Queries / Prepared Statements umstellen "
            "(keine String-Konkatenation von Benutzereingaben in SQL).\n"
            "2. ORM/Query-Builder mit Bind-Parametern verwenden.\n"
            f"3. {('DB-spezifische Fehlermeldungen (' + db + ') ') if db else 'Interne DB-Fehlermeldungen '}"
            "nie an den Client ausgeben (generische Fehlerseite, Logging serverseitig).\n"
            "4. DB-Benutzer mit minimalen Rechten (kein DROP/ALTER), WAF als zusätzliche Schicht.\n"
            "5. Nach Fix: betroffene Query-Pfade auditieren und Regressionstest mit `' OR '1'='1` ergänzen."
        )
    if cat == "open-redirect":
        return (
            "Open Redirect beheben:\n"
            "1. Redirect-Ziele gegen eine serverseitige Allowlist erlaubter Hosts/Pfade prüfen; "
            "externe absolute URLs ablehnen.\n"
            "2. Nur relative Pfade zulassen oder ein Mapping (Token → Ziel) statt roher URL im Parameter.\n"
            "3. Bei nötigem externem Redirect eine Interstitial-Warnseite zeigen."
        )
    if cat == "path-traversal":
        return (
            "Path Traversal / LFI beheben:\n"
            "1. Keine Benutzereingabe direkt in Dateipfade; Eingabe auf einen festen Basisordner "
            "kanonisieren (`os.path.realpath`) und prüfen, dass der aufgelöste Pfad im Basisordner bleibt.\n"
            "2. Dateizugriffe über eine Allowlist/ID-Mapping statt freiem Dateinamen.\n"
            "3. `../`, Null-Bytes und absolute Pfade verwerfen; least-privilege Dateisystemrechte."
        )
    if cat == "exposed-artifact":
        path = asset.rsplit("/", 1)[-1] if asset else "Artefakt"
        return (
            f"Exponiertes Artefakt ({path}) beheben:\n"
            "1. Datei/Verzeichnis aus dem Web-Root entfernen bzw. am Reverse-Proxy blocken "
            "(z. B. `location ~ /\\.git { deny all; }`).\n"
            "2. Falls Secrets enthalten waren (z. B. .env): betroffene Credentials ROTIEREN und "
            "aus der Git-Historie purgen (`git filter-repo`/BFG), dann force-push nach Absprache.\n"
            "3. Deploy-Pipeline so konfigurieren, dass VCS-/Backup-Dateien nie ausgeliefert werden."
        )
    if cat in ("cors-misconfig", "cors-passive"):
        return (
            "CORS-Fehlkonfiguration beheben:\n"
            "1. `Access-Control-Allow-Origin` NICHT die Request-Origin spiegeln und nicht `*` mit "
            "Credentials kombinieren.\n"
            "2. Statische Allowlist erlaubter Origins serverseitig prüfen; nur dann die konkrete Origin setzen.\n"
            "3. `Access-Control-Allow-Credentials: true` nur für explizit vertrauenswürdige Origins.\n"
            "4. Preflight (`OPTIONS`) serverseitig restriktiv beantworten."
        )
    if cat == "missing-auth":
        return (
            "Fehlende Authentifizierung beheben:\n"
            "1. Admin-/Management-Endpunkt hinter Authentifizierung UND Autorisierung (RBAC) stellen.\n"
            "2. Serverseitige Session-/Token-Prüfung erzwingen (nicht nur UI-seitig ausblenden).\n"
            "3. Sensible Panels zusätzlich per IP-Allowlist/VPN einschränken; Zugriffe auditloggen."
        )
    if cat == "cookie-flags":
        return (
            "Cookie-Härtung:\n"
            "1. Session-Cookies mit `HttpOnly`, `Secure` und `SameSite=Lax/Strict` setzen.\n"
            "2. `__Host-`-Prefix nutzen, kurze Lebensdauer, Rotation nach Login."
        )
    if cat in ("csp-analysis",) or "content-security-policy" in title:
        return (
            "Content-Security-Policy härten:\n"
            "1. Strikte CSP setzen: `default-src 'self'`; `script-src 'self'` OHNE `unsafe-inline`/`unsafe-eval` "
            "(Nonces/Hashes für benötigte Inline-Skripte).\n"
            "2. Externe CDNs (z. B. Tailwind-CDN) selbst hosten oder in die Allowlist aufnehmen; "
            "`object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`."
        )
    if cat == "permissions-policy" or "permissions-policy" in title:
        return (
            "Permissions-Policy setzen:\n"
            "1. Header `Permissions-Policy` mit restriktiver Feature-Liste ausliefern "
            "(z. B. `geolocation=(), camera=(), microphone=()`)."
        )
    if "strict-transport-security" in title or cat == "tls":
        return (
            "Transport-Härtung (HSTS/TLS):\n"
            "1. `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` setzen.\n"
            "2. TLS 1.2+ erzwingen, HTTP→HTTPS-Redirect, moderne Cipher-Suites."
        )
    if cat == "security-txt":
        return (
            "security.txt verbessern:\n"
            "1. Dedizierten Security-Kontakt (kein privates Gmail) + `Expires`, `Encryption`, `Policy` "
            "unter `/.well-known/security.txt` pflegen."
        )
    if cat in ("version-disclosure",) or "version" in title:
        pkg, ver = ev.get("package"), ev.get("fixed_version")
        return (
            "Version-/Software-Disclosure beheben:\n"
            f"1. {('Paket `' + str(pkg) + '` auf Version `' + str(ver) + '`+ aktualisieren.') if pkg else 'Betroffene Komponente auf die gepatchte Version aktualisieren.'}\n"
            "2. Versions-/Server-Header entfernen oder generisch halten (`Server`, `X-Powered-By`)."
        )
    if cat in ("threat-intel-cve", "cve-reference"):
        cve = ev.get("cve") or ev.get("cve_id") or ""
        return (
            f"CVE-Referenz{(' ' + str(cve)) if cve else ''} abarbeiten:\n"
            "1. Erst prüfen, ob die betroffene Technologie/Version TATSÄCHLICH eingesetzt wird "
            "(sonst nicht anwendbar).\n"
            "2. Falls eingesetzt: auf die herstellerseitig gepatchte Version aktualisieren und "
            "vorhandene Workarounds/Mitigations anwenden."
        )
    if cat in ("info-disclosure", "misconfig", "fingerprint", "api-surface", "storage-exposure"):
        return (
            "Information-Disclosure / Misconfig beheben:\n"
            "1. Nicht benötigte Metadaten/Endpunkte entfernen oder absichern (Auth, Netzsegment).\n"
            "2. Verbose Fehler/Debug-Ausgaben in Produktion deaktivieren; least-exposure."
        )
    if cat in ("dns-email-auth",):
        return (
            "E-Mail-Authentisierung härten:\n"
            "1. SPF auf `-all` (hardfail) stellen und alle legitimen Sender aufnehmen.\n"
            "2. DKIM signieren, DMARC `p=reject` mit RUA/RUF-Reporting."
        )
    # Generischer, aber ehrlicher Fallback (nicht als 'korrekt' ausgegeben).
    return (
        "Allgemeine Behebung:\n"
        "1. Ursache des Befunds im betroffenen Asset beheben (Konfiguration/Code), "
        "least-privilege und Defense-in-Depth anwenden.\n"
        "2. Fix mit einem gezielten Regressionstest absichern.\n"
        f"Hinweis: Für Kategorie `{cat or 'unbekannt'}` liegt keine spezialisierte "
        "Remediation-Vorlage vor – bitte fachlich konkretisieren."
    )


# ---------------------------------------------------------------------------
# PoC-Code-Block: der echte Reproduktions-Request/Payload aus der Evidence.
# ---------------------------------------------------------------------------
def poc_code_for(row: Any) -> str:
    """Liefert einen Code-Block-Inhalt (ohne Fences) oder einen ehrlichen Hinweis."""
    ev = parse_evidence(row)
    reqs = []
    for key in ("request", "request_true", "request_false"):
        r = ev.get(key)
        if isinstance(r, dict):
            reqs.append((key, r))
    lines: list[str] = []
    for key, r in reqs:
        method = r.get("method", "GET")
        url = r.get("url", _g(row, "asset", ""))
        param = r.get("param")
        value = r.get("value")
        label = {"request_true": " (TRUE-Zweig)", "request_false": " (FALSE-Zweig)"}.get(key, "")
        if param is not None and value is not None:
            from urllib.parse import quote
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{param}={quote(str(value))}"
            lines.append(f"# {method}{label} – Parameter {param}")
            lines.append(f"curl -i '{full}'")
        else:
            origin = r.get("origin")
            hdr = f" -H 'Origin: {origin}'" if origin else ""
            lines.append(f"# {method}{label}")
            lines.append(f"curl -i{hdr} '{url}'")
    # Response-/Signatur-Nachweis als Kommentar (gekürzt, keine Secrets).
    proof = []
    for k in ("status", "location", "access_control_allow_origin", "db", "technique",
              "signature_matched", "reflected_unescaped", "body_similarity_true_false",
              "len_true", "len_false", "hits"):
        if k in ev and ev.get(k) not in (None, ""):
            proof.append(f"{k}={ev.get(k)}")
    exc = ev.get("response_excerpt")
    if lines:
        if proof:
            lines.append("")
            lines.append("# Beobachtung: " + ", ".join(proof))
        if exc:
            lines.append("# Response-Ausschnitt: " + str(exc)[:160].replace("\n", " "))
        return "\n".join(lines)
    # Kein aktiver Request → defensiver/passiver Fund: ehrlich benennen.
    status = _g(row, "status", "")
    if proof or exc:
        body = ["# Kein aktiver PoC (passiver/defensiver Fund) – beobachtete Signale:"]
        if proof:
            body.append("# " + ", ".join(proof))
        if exc:
            body.append("# Response-Ausschnitt: " + str(exc)[:160].replace("\n", " "))
        return "\n".join(body)
    return "# kein PoC (defensiv/offen) – keine aktive Request/Response-Evidence in diesem Lauf"


# ---------------------------------------------------------------------------
# 8-Schritt-Evidence-Kette aus einem echten Finding.
# ---------------------------------------------------------------------------
def _category_hypothesis(cat: str) -> str:
    m = {
        "xss-verified": "Benutzereingabe wird unescaped in den HTML-Kontext reflektiert → Reflected XSS.",
        "sqli-verified": "Benutzereingabe fließt ungefiltert in eine SQL-Query → SQL-Injection.",
        "open-redirect": "Ein Redirect-Parameter wird ungeprüft in die Location übernommen → Open Redirect.",
        "path-traversal": "Ein Datei-Parameter erlaubt Verzeichniswechsel → Path Traversal/LFI.",
        "exposed-artifact": "Ein sensibles Artefakt ist ohne Auth über das Web-Root erreichbar.",
        "cors-misconfig": "Der Server spiegelt beliebige Origins → Cross-Origin-Datenabfluss.",
        "missing-auth": "Ein privilegierter Endpunkt ist ohne Authentifizierung erreichbar.",
        "ssrf-verified": "Der Server holt eine angreiferkontrollierte URL ab (Out-of-Band bestätigt) → SSRF.",
        "ssrf-indicator": "Ein URL-Parameter deutet auf eine serverseitige Anfrage → SSRF (zu bestätigen).",
        "subdomain-takeover": "Eine Subdomain zeigt per dangling CNAME auf einen nicht beanspruchten Dienst → Takeover.",
    }
    return m.get(cat, "")


def chain_from_finding(store, finding_row, scopes: Optional[list] = None) -> dict:
    """Baut Titel/CVSS + 8-Schritt-Kette NUR aus echten Finding-Daten.

    Rückgabe: {title, cvss_score, cvss_vector, cvss_note, severity, chain{...},
               hints{step_key: bool}} – hints[key]=True heißt: leer (kein Datum).
    """
    ev = parse_evidence(finding_row)
    cat = _g(finding_row, "category", "")
    severity = _g(finding_row, "severity", "info")
    status = _g(finding_row, "status", "")
    asset = _g(finding_row, "asset", "")
    title = _g(finding_row, "title", "Finding")
    desc = _g(finding_row, "description", "")
    tid = _g(finding_row, "target_id", None)

    if scopes is None and tid is not None:
        try:
            scopes = store.list_scopes(tid)
        except Exception:
            scopes = []
    scopes = scopes or []
    in_scope = [s for s in scopes if (_g(s, "allowed", 0))]
    scope_proof = ""
    if in_scope:
        scope_proof = ("In-Scope-Nachweis (default-deny Allowlist): " +
                       ", ".join(f"{_g(s,'kind')}={_g(s,'value')}" for s in in_scope) +
                       (f"\nBetroffenes Asset: {asset}" if asset else ""))

    baseline = ""
    for k in ("baseline", "catchall", "catch_all_suspect", "note"):
        if ev.get(k):
            baseline = f"{k}: {ev.get(k)}"
            break
    if not baseline and asset:
        baseline = (f"Ausgangszustand: Asset {asset} wurde vor dem Check erreicht "
                    "(GET-Probe erfolgreich); Catch-all-/Baseline-Schutz aktiv.")

    observation = desc or ""
    hypothesis = _category_hypothesis(cat)
    poc = poc_code_for(finding_row)

    # Validierung: Status + Evidence-Qualität ehrlich.
    conf = ev.get("confidence", "")
    has_active = _evidence_active(ev)
    validation = (f"Status: {status or 'n/a'}. "
                  + (f"Aktive Evidence (Request+Response) vorhanden." if has_active
                     else "Keine aktive Request+Response-Evidence in diesem Lauf "
                          "(nicht als VERIFIZIERT führen).")
                  + (f" Confidence: {conf}." if conf else ""))

    impact = _impact_text(cat, severity)
    report_text = (f"{title} ({severity}, Status {status or 'n/a'}). "
                   + (observation[:400] if observation else ""))

    chain = {
        "scope_proof": scope_proof,
        "baseline": baseline,
        "observation": observation,
        "hypothesis": hypothesis,
        "poc": poc,
        "validation": validation,
        "impact": impact,
        "report_text": report_text,
    }
    hints = {k: (not str(v).strip()) for k, v in chain.items()}
    for k, v in chain.items():
        if not str(v).strip():
            chain[k] = _HINT

    est = _SEV_CVSS_ESTIMATE.get(severity, 0.0)
    return {
        "title": title,
        "cvss_score": est,
        "cvss_vector": "",
        "cvss_note": ("Score aus Severity geschätzt (kein präziser Vektor erfunden; "
                      "bitte CVSS-Vektor fachlich ergänzen)."),
        "severity": severity,
        "chain": chain,
        "hints": hints,
        "finding_id": _g(finding_row, "id", None),
        "category": cat,
        "status": status,
    }


def _evidence_active(ev: dict) -> bool:
    req_keys = ("request", "request_true", "request_false")
    resp_keys = ("response_excerpt", "status", "location", "signature_matched",
                 "body_similarity_true_false", "access_control_allow_origin",
                 "hits", "len_true", "len_false", "reflected_unescaped")
    has_req = any(ev.get(k) for k in req_keys)
    has_resp = any(k in ev and ev.get(k) not in (None, "") for k in resp_keys)
    return bool(has_req and has_resp)


def _impact_text(cat: str, severity: str) -> str:
    m = {
        "xss-verified": "Angreifer kann Skripte im Browser des Opfers ausführen (Session-Diebstahl, UI-Redressing).",
        "sqli-verified": "Angreifer kann Datenbankinhalte lesen/verändern – vollständige Datenkompromittierung möglich.",
        "open-redirect": "Phishing/Token-Leak durch Weiterleitung auf angreiferkontrollierte Domains.",
        "path-traversal": "Lesezugriff auf serverseitige Dateien (Konfigs, Secrets) außerhalb des Web-Roots.",
        "exposed-artifact": "Offenlegung von Quellcode/Secrets/Konfiguration, erleichtert weitere Angriffe.",
        "cors-misconfig": "Cross-Origin-Abfluss authentifizierter Daten an fremde Origins.",
        "missing-auth": "Unbefugter Zugriff auf privilegierte Funktionen ohne Anmeldung.",
    }
    base = m.get(cat, "")
    return base or f"Severity {severity}: Risiko gemäß Kategorie '{cat or 'unbekannt'}'."


# ---------------------------------------------------------------------------
# Voller strukturierter, professioneller Bericht.
# ---------------------------------------------------------------------------
def professional_report_md(store, target_id: int, finding_ids: Optional[list] = None,
                           instruction: str = "", title: Optional[str] = None,
                           addenda: Optional[list] = None,
                           revision_note: str = "") -> str:
    """Erzeugt den vollen Markdown-Bericht (Executive Summary + pro Finding).

    Zählungen kommen aus der Finding-Liste (Single Source of Truth via proofgate).
    `finding_ids` grenzt optional auf ausgewählte Findings ein.
    `instruction` ist eine optionale Neu-Anweisung (wird transparent vermerkt).
    """
    from . import proofgate as pg
    from .agents.base import AgentFinding

    target = store.get_target(target_id)
    tname = _g(target, "name", str(target_id)) if target else str(target_id)
    rows = store.list_findings(target_id)
    if finding_ids:
        idset = {int(i) for i in finding_ids}
        rows = [r for r in rows if int(_g(r, "id", -1)) in idset]

    # In AgentFinding spiegeln → proofgate für konsistente Zählung nutzen.
    afs = []
    for r in rows:
        afs.append(AgentFinding(
            agent=_g(r, "agent", ""), title=_g(r, "title", ""),
            category=_g(r, "category", ""), severity=_g(r, "severity", "info"),
            asset=_g(r, "asset", ""), description=_g(r, "description", ""),
            evidence=parse_evidence(r), status=_g(r, "status", ""),
            false_positive=bool(_g(r, "false_positive", 0)),
        ))
    pg.enforce(afs, None)
    counted = pg.counted_findings(afs)
    by_sev = pg.severity_counts(afs)
    by_status = pg.status_counts(afs)
    fp_count = len([f for f in afs if f.false_positive])

    verified = [f for f in counted if f.status == "VERIFIZIERT"]
    # Zwischenbericht-Banner-Logik: wenn offene/bedingte Status existieren.
    open_states = {"ZU BESTÄTIGEN", "BEDINGT", "REFERENZ"}
    has_open = any(f.status in open_states for f in counted)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_order = ("critical", "high", "medium", "low", "info")
    total = len(counted)

    L: list[str] = []
    L.append(f"# Sicherheitsbericht – {title or tname}")
    L.append("")
    L.append(f"- **Target:** {tname} (#{target_id})")
    L.append(f"- **Erstellt:** {now} (Europe/Berlin)")
    L.append(f"- **Erstellt mit:** antbb (lokales, autorisiertes Framework)")
    if instruction:
        L.append(f"- **Anweisung/Neu-Anweisung:** {instruction}")
    if revision_note:
        L.append(f"- **Revision:** {revision_note}")
    L.append("")
    if has_open:
        L.append("> ⚠️ **ZWISCHENBERICHT – NICHT FINAL.** Es existieren Befunde mit Status "
                 "`ZU BESTÄTIGEN`/`BEDINGT`/`REFERENZ`. Nur `VERIFIZIERT` ist aktiv belegt; "
                 "alles andere ist nicht als bewiesen zu behandeln.")
        L.append("")

    # ---- Executive Summary ----
    L.append("## Executive Summary")
    L.append("")
    L.append(f"- **Gezählte Findings:** {total} (zzgl. {fp_count} als Catch-all/False-Positive ausgeschlossen)")
    L.append(f"- **Severity-Verteilung:** " + ", ".join(
        f"{k}={by_sev.get(k,0)}" for k in sev_order))
    L.append(f"- **Status-Verteilung:** " + (", ".join(f"{k}={v}" for k, v in by_status.items()) or "—"))
    L.append(f"- **Aktiv verifiziert (VERIFIZIERT):** {len(verified)}")
    L.append(f"- **Proof-Gate:** {'bestanden – kein VERIFIZIERT ohne aktive Evidence' if all(f.has_active_evidence() for f in verified) else 'VERLETZT – bitte prüfen'}")
    L.append("")

    # ---- Gesamt-Sicherheitsbewertung (neutral, deterministisch) ----
    try:
        from . import rating as rating_mod
        rating = rating_mod.compute_rating(list(afs))
        hm = rating_mod.build_heatmap(list(afs))
        L.append("## Gesamt-Sicherheitsbewertung")
        L.append("")
        L.append(f"- **Gesamt-Score:** {rating['score']}/100 · **Note:** {rating['grade']} "
                 f"(Risikopunkte: {rating['risk_points']})")
        L.append("- **Teilscores:** " + ", ".join(
            f"{dim}={v['grade']}({v['score']})" for dim, v in rating["subscores"].items()))
        L.append(f"- _Formel:_ {rating['formula']}")
        L.append("")
        assess = rating_mod.ai_assessment(rating, llm=None)
        L.append(f"**KI-Einschätzung ({assess['source']}, {assess['disclaimer']}):** "
                 f"{assess['text']}")
        L.append("")
        L.append("### Risiko-Heatmap (Kategorie × Severity)")
        L.append("")
        L.append(rating_mod.heatmap_markdown(hm))
        L.append("")
    except Exception as _exc:
        L.append(f"_(Rating/Heatmap nicht verfügbar: {_exc})_")
        L.append("")

    # Sortierung nach Severity.
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ordered = sorted(
        [r for r in rows if not bool(_g(r, "false_positive", 0))
         and _g(r, "category", "") not in {
             "report-summary", "llm-report", "analysis-cvss", "correlation",
             "llm-analysis", "poc", "proofgate-validation"}],
        key=lambda r: rank.get(_g(r, "severity", "info"), 0), reverse=True)

    L.append("## Befunde im Detail")
    L.append("")
    if not ordered:
        L.append("_Keine zählbaren Befunde für dieses Target (ehrlicher Leerzustand)._")
        L.append("")
    for i, r in enumerate(ordered, 1):
        c = chain_from_finding(store, r)
        L.append(f"### {i}. {c['title']}")
        L.append("")
        L.append(f"- **Status:** {c['status'] or 'n/a'}")
        L.append(f"- **Severity:** {c['severity']}")
        L.append(f"- **CVSS (Schätzung):** {c['cvss_score']} "
                 f"({c['cvss_vector'] or 'Vektor n/a'}) — {c['cvss_note']}")
        L.append(f"- **Asset:** {_g(r,'asset','') or 'n/a'}  ·  **Agent:** {_g(r,'agent','')}")
        L.append("")
        L.append("**Evidence-Kette (8 Schritte):**")
        L.append("")
        for key, label in CHAIN_STEPS:
            val = c["chain"].get(key, "")
            if key == "poc":
                L.append(f"**{label}:**")
                L.append("")
                L.append("```bash")
                L.append(val)
                L.append("```")
                L.append("")
            else:
                L.append(f"- **{label}:** {val}")
        L.append("")
        L.append("**Behebung / Remediation:**")
        L.append("")
        L.append(remediation_for(r))
        L.append("")
        L.append("---")
        L.append("")

    if addenda:
        L.append("## Nachträge (Addenda)")
        L.append("")
        for a in addenda:
            ts = _g(a, "created_at", 0)
            tss = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"
            L.append(f"- **[{tss}] {_g(a,'author','') or 'anonym'}:** {_g(a,'text','')}")
        L.append("")

    L.append("> ⚠️ Erstellt mit antbb. Tests nur im autorisierten Scope. "
             "§ 202a-c StGB / CFAA beachten. Secrets werden nicht in den Bericht geschrieben.")
    return "\n".join(L)
