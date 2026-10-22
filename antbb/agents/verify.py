"""Verify-Ameise: TIEFERE, kontrollierte AKTIVE Verifikation.

Diese Ameise verifiziert Befunde, statt sie nur zu vermuten. Sie läuft
AUSSCHLIESSLICH, wenn ZUSÄTZLICH zum Pflicht-Oversight-Häkchen der
ausdrückliche Schalter `scan.active_verification` (bzw. CLI `--active` /
Web-Checkbox „Aktive Verifikation (autorisiert)") gesetzt ist. Ohne diesen
Schalter dispatcht die Königin diese Phase gar nicht erst.

Harte Leitplanken (im Code erzwungen):
  * Jeder Request läuft über ctx.net → Scope default-deny + Rate-Limiting.
  * KEINE destruktiven Payloads (kein DROP/DELETE/UPDATE/INSERT, keine stacked
    queries), KEIN Brute-Force, KEINE Last-Erzeugung.
  * Nur wenige, konservativ begrenzte Payloads je Parameter (cfg-Limit).
  * Nur lesende GET-Requests; keine Daten werden verändert oder gelöscht.
  * Keine Secrets werden geloggt oder in Evidence geschrieben (Inhalte werden
    nur signatur-/längen-basiert bewertet, Ausschnitte werden gekürzt).

Jeder bestätigte Befund trägt confidence="bestätigt" und einen EVIDENCE-Block
(Request-Zusammenfassung + gekürzter Response-Ausschnitt), passend zur
8-Schritt-Evidence-/Report-Kette.
"""
from __future__ import annotations

import html as _html
import re
from urllib.parse import urlparse, parse_qs

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for, build_catchall_baseline, response_similarity

# Eindeutiger, benigner XSS-Marker mit HTML-Sonderzeichen (kein echtes Script).
_XSS_MARK = "antbbMARK9z"
_XSS_PAYLOAD = f"{_XSS_MARK}<antbb>\"'"

# Kontrollierte, externe Marker-URL für Open-Redirect (wird NIE aufgerufen).
_REDIR_HOST = "antbb-verify.example"
_REDIR_URL = f"https://{_REDIR_HOST}/antbbredir"

# Boolean-based SQLi: logisch-wahr vs. logisch-falsch, NUR SELECT-artig.
_SQLI_TRUE = "' AND '1'='1"
_SQLI_FALSE = "' AND '1'='2"

# DB-Fehler-Signaturen (Fingerprint pro DB-Familie).
_SQL_ERRORS = {
    "MySQL/MariaDB": ["you have an error in your sql syntax", "warning: mysql",
                      "mysql_fetch", "mysqli"],
    "PostgreSQL": ["pg::syntaxerror", "psqlexception", "unterminated quoted string",
                   "pg_query"],
    "MSSQL": ["unclosed quotation mark", "microsoft odbc", "sqlserver"],
    "Oracle": ["ora-01756", "ora-00933", "quoted string not properly terminated"],
    "SQLite": ["sqlite3.operationalerror", "sqlite error", "near \"'\":"],
    "Generisch": ["sql syntax", "syntax error at or near"],
}

# /etc/passwd-Signatur für den (lesenden) Path-Traversal-Indikator.
_PASSWD_RE = re.compile(r"root:.*?:0:0:")
_TRAVERSAL = "../../../../../../etc/passwd"

# Signaturen für exponierte Artefakte (Inhalts-Check statt nur Statuscode).
_ARTIFACTS = [
    ("/.git/HEAD", re.compile(r"ref:\s*refs/"), "Git-Repository (.git) exponiert"),
    ("/.git/config", re.compile(r"\[core\]"), "Git-Config exponiert"),
    ("/.env", re.compile(r"(?mi)^[A-Z0-9_]+\s*="), "Umgebungsdatei (.env) exponiert"),
    ("/config.php.bak", re.compile(r"<\?php"), "PHP-Backup-Datei exponiert"),
    ("/.DS_Store", re.compile(r"Bud1"), "macOS .DS_Store exponiert"),
]

# Offensichtliche Admin-Endpunkte (nur GET, kein Brute-Force).
_ADMIN_PATHS = ["/admin", "/admin/", "/manage", "/dashboard", "/phpmyadmin/"]
_ADMIN_SIG = re.compile(r"(?i)(admin|dashboard|logout|benutzerverwaltung|user management)")


def _excerpt(text: str, needle: str = "", span: int = 80) -> str:
    """Kurzer, gekürzter Response-Ausschnitt für die Evidence (keine Secrets dumpen)."""
    if not text:
        return ""
    if needle:
        i = text.find(needle)
        if i >= 0:
            start = max(0, i - span)
            return text[start:i + len(needle) + span].strip()[:400]
    return text[:200].strip()


class VerifyAnt(AntAgent):
    name = "verify"
    role = ("Aktive Verifikation: bestätigt Reflected-XSS, SQLi (bool/time/error), "
            "Open-Redirect, Path-Traversal, exponierte Artefakte, CORS, Missing-Auth "
            "(kontrolliert, nicht-destruktiv)")
    specialty = "payload-specialist"
    phases = ("verify",)
    playbooks = (
        Playbook("aktive-xss-bestaetigung", "offensive", True,
                 ["benign-html-marker", "reflection-context-check"],
                 "Reflected XSS aktiv bestätigen (benigner Marker, kein Script)."),
        Playbook("aktive-sqli-bestaetigung", "offensive", True,
                 ["error-based", "boolean-based", "time-based-conservative"],
                 "SQLi aktiv bestätigen (lesend, SELECT-artig, keine Destruktion)."),
        Playbook("open-redirect-bestaetigung", "offensive", True,
                 ["marker-url-redirect-check"],
                 "Open Redirect über kontrollierte Marker-URL bestätigen."),
        Playbook("path-traversal-bestaetigung", "offensive", True,
                 ["passwd-signature-read"],
                 "Path-Traversal/LFI über /etc/passwd-Signatur bestätigen (lesend)."),
        Playbook("exposed-artifact-bestaetigung", "offensive", True,
                 ["content-signature-match"],
                 "Exponierte Artefakte inhaltsbasiert bestätigen (.git/.env/...)."),
        Playbook("cors-bestaetigung", "offensive", True,
                 ["origin-reflection-check"],
                 "CORS-Fehlkonfiguration über Origin-Reflexion bestätigen."),
        Playbook("missing-auth-bestaetigung", "offensive", True,
                 ["admin-endpoint-get"],
                 "Admin-Endpunkte ohne Auth bestätigen (nur GET, kein Brute-Force)."),
        Playbook("ssrf-bestaetigung", "offensive", True,
                 ["url-param-discovery", "in-band-canary", "interactsh-oob",
                  "blind-ssrf-oob"],
                 "SSRF über eindeutige OOB-Callback-URL (interactsh) bestätigen; "
                 "ohne OOB nur In-Band-Indikator (zu bestätigen). Nicht-destruktiv."),
        Playbook("sqlmap-verify", "offensive", True,
                 ["sqlmap"],
                 "Aktive SQLi-Verifikation via sqlmap (--batch, nicht-destruktiv)."),
        Playbook("metasploit-aux-scanner", "offensive", True,
                 ["msfconsole"],
                 "NUR auxiliary/scanner/*-Module (hart allowlisted), nicht-destruktiv."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            self.ctx.log("[verify] Kein NetClient – übersprungen.")
            return findings
        # Doppelte Absicherung: ohne ausdrücklichen Schalter NICHTS tun.
        if not getattr(self.ctx, "active", False):
            self.ctx.log("[verify] ⏸️ Aktive Verifikation NICHT aktiviert "
                         "(Schalter scan.active_verification=false) – keine aktiven Checks.")
            return findings
        cfg = net.cfg
        checks = set(cfg.av_checks or [])
        self.ctx.log(f"[verify] 🔬 Aktive Verifikation AN (autorisiert). "
                     f"Checks: {sorted(checks)} · Limit {cfg.av_max_payloads_per_param} "
                     f"Payloads/Parameter · time-based ≥ {cfg.av_time_based_threshold}s.")

        done_bases: set[str] = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            for base in base_urls_for(asset):
                if base in done_bases:
                    continue
                # Erreichbarkeit prüfen (ein GET); nur bei Antwort weitermachen.
                probe = await net.http_get(base + "/")
                if probe is None:
                    continue
                done_bases.add(base)
                params = self._candidate_params(asset, cfg)

                # Catch-all-/Baseline-Schutz: Zufallspfade messen. Für Catch-all-
                # Hosts werden rein status-200-basierte Checks (Artefakte,
                # Missing-Auth) nur gemeldet, wenn sie signifikant von der
                # jitternden Platzhalterseite abweichen.
                sim_thr = float(getattr(cfg, "fuzz_similarity_threshold", 0.85) or 0.85)
                n_s = max(3, int(getattr(cfg, "catchall_min_samples", 3) or 3))
                baseline = await build_catchall_baseline(
                    net, base, n_samples=n_s, threshold=sim_thr,
                )
                if baseline.is_catch_all:
                    self.ctx.log("[verify] ⚠️ " + baseline.describe())

                if "xss" in checks:
                    findings += await self._xss(net, cfg, base, params)
                if "sqli" in checks:
                    findings += await self._sqli(net, cfg, base, params)
                if "open_redirect" in checks:
                    findings += await self._open_redirect(net, cfg, base)
                if "path_traversal" in checks:
                    findings += await self._path_traversal(net, cfg, base)
                if "exposed_artifact" in checks:
                    findings += await self._artifacts(net, base, baseline)
                if "cors" in checks:
                    findings += await self._cors(net, base)
                if "missing_auth" in checks:
                    findings += await self._missing_auth(net, base, baseline)
                if "ssrf" in checks:
                    findings += await self._ssrf(net, cfg, base)
        findings += await self._kali_ext(task)
        return findings

    # -- Kandidaten-Parameter: aus der Asset-URL + konservative Standardliste --
    def _candidate_params(self, asset: str, cfg) -> list[str]:
        out: list[str] = []
        try:
            if "://" in asset:
                q = parse_qs(urlparse(asset).query)
                out.extend(q.keys())
        except Exception:
            pass
        for p in cfg.av_param_candidates:
            if p not in out:
                out.append(p)
        # harte Obergrenze an getesteten Parametern (Last begrenzen)
        return out[: max(1, cfg.av_max_payloads_per_param)]

    def _req_summary(self, base, path, param, value):
        return {"method": "GET", "url": base + path, "param": param,
                "value": value, "note": "lesender GET, nicht-destruktiv"}

    # ---------------- Reflected XSS (Reflexions-/Kontext-Nachweis) ----------------
    async def _xss(self, net, cfg, base, params):
        out = []
        for param in params:
            resp = await net.http_get(base + "/", params={param: _XSS_PAYLOAD})
            if resp is None:
                continue
            body = resp.text or ""
            if _XSS_PAYLOAD in body:
                # unescaped im HTML-Body → echter reflektierter Kontext
                self.ctx.log(f"[verify] ✅ Reflected XSS bestätigt @ {base} (param '{param}', HTML-Kontext)")
                out.append(AgentFinding(
                    agent=self.name, title=f"Reflected XSS bestätigt (Parameter '{param}')",
                    category="xss-verified", severity="high", asset=base,
                    description=("Ein benigner Marker mit HTML-Sonderzeichen wurde UNESCAPED im "
                                 "HTML-Body reflektiert (reflektierter HTML-Kontext). Kein Script "
                                 "wurde ausgeführt – nur Reflexions-/Kontext-Nachweis."),
                    evidence={"request": self._req_summary(base, "/", param, _XSS_PAYLOAD),
                              "confidence": "bestätigt", "context": "html-body",
                              "reflected_unescaped": True,
                              "response_excerpt": _excerpt(body, _XSS_MARK)},
                    dedup_key=f"xss-verified:{base}:{param}",
                ))
                break
            elif _html.escape(_XSS_PAYLOAD) in body or _XSS_MARK in body:
                # Marker reflektiert, aber escaped → nur Indikator, nicht ausnutzbar
                self.ctx.log(f"[verify] ℹ️ XSS: Marker reflektiert aber escaped @ {base} (param '{param}')")
                out.append(AgentFinding(
                    agent=self.name, title=f"Reflexion (XSS escaped) Parameter '{param}'",
                    category="xss-indicator", severity="low", asset=base,
                    description=("Marker wurde reflektiert, aber korrekt HTML-escaped → derzeit "
                                 "nicht als XSS ausnutzbar (nur Reflexions-Indikator)."),
                    evidence={"request": self._req_summary(base, "/", param, _XSS_PAYLOAD),
                              "confidence": "indikator", "context": "escaped",
                              "response_excerpt": _excerpt(body, _XSS_MARK)},
                    dedup_key=f"xss-indicator:{base}:{param}",
                ))
                break
        return out

    # ---------------- SQL-Injection (bool + error + konservativ time-based) ----------------
    async def _sqli(self, net, cfg, base, params):
        out = []
        for param in params:
            # 1) Error-based (einzelnes Hochkomma) – Fingerprint pro DB
            err = await net.http_get(base + "/", params={param: "1'"})
            if err is not None:
                low = (err.text or "").lower()
                db = next((name for name, sigs in _SQL_ERRORS.items()
                           if any(s in low for s in sigs)), None)
                if db:
                    self.ctx.log(f"[verify] ✅ SQLi (error-based) bestätigt @ {base} (param '{param}', DB {db})")
                    out.append(AgentFinding(
                        agent=self.name, title=f"SQL-Injection bestätigt – error-based ({db})",
                        category="sqli-verified", severity="critical", asset=base,
                        description=(f"Ein einzelnes Hochkomma löste eine {db}-spezifische "
                                     "Fehlermeldung aus (error-based SQLi). KEINE Datenextraktion, "
                                     "keine schreibenden/destruktiven Payloads."),
                        evidence={"request": self._req_summary(base, "/", param, "1'"),
                                  "confidence": "bestätigt", "technique": "error-based", "db": db,
                                  "response_excerpt": _excerpt(low, "sql")},
                        dedup_key=f"sqli-verified:err:{base}:{param}",
                    ))
                    break
            # 2) Boolean-based: TRUE- vs. FALSE-Differenz (nur SELECT-artig)
            rt = await net.http_get(base + "/", params={param: _SQLI_TRUE})
            rf = await net.http_get(base + "/", params={param: _SQLI_FALSE})
            if rt is not None and rf is not None:
                lt, lf = len(rt.text or ""), len(rf.text or "")
                # Jitter-tolerant: nicht die ROHE Längendifferenz, sondern die
                # normalisierte Body-Ähnlichkeit (Zahlen/Hashes entfernt) werten.
                # Eine jitternde Catch-all-Seite ändert nur die Länge, nicht den
                # Inhalt → hohe Ähnlichkeit → KEIN Fund.
                sim_tf = response_similarity(rt, rf)
                thr = float(getattr(cfg, "fuzz_similarity_threshold", 0.85) or 0.85)
                if lt > 0 and sim_tf < thr:
                    self.ctx.log(f"[verify] ✅ SQLi (boolean-based) bestätigt @ {base} (param '{param}')")
                    out.append(AgentFinding(
                        agent=self.name, title=f"SQL-Injection bestätigt – boolean-based (Parameter '{param}')",
                        category="sqli-verified", severity="critical", asset=base,
                        description=("TRUE-Bedingung (1=1) und FALSE-Bedingung (1=2) liefern "
                                     "reproduzierbar unterschiedliche Antworten → boolean-based SQLi. "
                                     "Nur lesende SELECT-artige Bedingung, keine Datenänderung."),
                        evidence={"request_true": self._req_summary(base, "/", param, _SQLI_TRUE),
                                  "request_false": self._req_summary(base, "/", param, _SQLI_FALSE),
                                  "confidence": "bestätigt", "technique": "boolean-based",
                                  "len_true": lt, "len_false": lf,
                                  "body_similarity_true_false": round(sim_tf, 3)},
                        dedup_key=f"sqli-verified:bool:{base}:{param}",
                    ))
                    break
            # 3) Time-based (SEHR konservativ, wenige Versuche, SELECT-artig)
            hit = 0
            delay = cfg.av_time_based_delay
            payloads = [f"' AND SLEEP({delay})-- -", f"'||pg_sleep({delay})--"]
            for attempt in range(min(cfg.av_time_based_attempts, len(payloads))):
                resp = await net.http_get(base + "/", params={param: payloads[attempt]})
                if resp is None:
                    continue
                elapsed = resp.elapsed.total_seconds()
                if elapsed >= cfg.av_time_based_threshold:
                    hit += 1
            if hit >= 1 and cfg.av_time_based_attempts >= 1:
                self.ctx.log(f"[verify] ✅ SQLi (time-based) bestätigt @ {base} (param '{param}')")
                out.append(AgentFinding(
                    agent=self.name, title=f"SQL-Injection bestätigt – time-based (Parameter '{param}')",
                    category="sqli-verified", severity="critical", asset=base,
                    description=(f"Eine SLEEP/pg_sleep-Bedingung verzögerte die Antwort reproduzierbar "
                                 f"über {cfg.av_time_based_threshold:.0f}s → time-based SQLi. Konservativer "
                                 "Schwellwert, wenige Versuche, keine destruktiven Payloads."),
                    evidence={"request": self._req_summary(base, "/", param, payloads[0]),
                              "confidence": "bestätigt", "technique": "time-based",
                              "threshold_s": cfg.av_time_based_threshold, "hits": hit},
                    dedup_key=f"sqli-verified:time:{base}:{param}",
                ))
                break
        return out

    # ---------------- Open Redirect ----------------
    async def _open_redirect(self, net, cfg, base):
        out = []
        for param in cfg.av_redirect_param_candidates:
            resp = await net.http_get(base + "/", params={param: _REDIR_URL},
                                      allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if _REDIR_HOST in loc:
                    self.ctx.log(f"[verify] ✅ Open Redirect bestätigt @ {base} (param '{param}')")
                    out.append(AgentFinding(
                        agent=self.name, title=f"Open Redirect bestätigt (Parameter '{param}')",
                        category="open-redirect", severity="medium", asset=base,
                        description=("Eine kontrollierte Marker-URL im Parameter wurde in eine "
                                     f"{resp.status_code}-Weiterleitung übernommen (Location zeigt auf "
                                     "die externe Marker-Domain). Phishing-/Token-Leak-Risiko."),
                        evidence={"request": self._req_summary(base, "/", param, _REDIR_URL),
                                  "confidence": "bestätigt", "status": resp.status_code,
                                  "location": loc[:200]},
                        dedup_key=f"open-redirect:{base}:{param}",
                    ))
                    break
        return out

    # ---------------- Path Traversal / LFI (lesender Indikator) ----------------
    async def _path_traversal(self, net, cfg, base):
        out = []
        for param in cfg.av_file_param_candidates:
            resp = await net.http_get(base + "/", params={param: _TRAVERSAL})
            if resp is None:
                continue
            body = resp.text or ""
            if _PASSWD_RE.search(body):
                self.ctx.log(f"[verify] ✅ Path-Traversal/LFI bestätigt @ {base} (param '{param}')")
                out.append(AgentFinding(
                    agent=self.name, title=f"Path Traversal / LFI bestätigt (Parameter '{param}')",
                    category="path-traversal", severity="high", asset=base,
                    description=("Eine konservative, lesende Traversal-Probe gab Inhalt mit der "
                                 "/etc/passwd-Signatur zurück (root:…:0:0:). Nur Indikator-Lesen, "
                                 "KEINE Exfiltration weiterer Dateien."),
                    evidence={"request": self._req_summary(base, "/", param, _TRAVERSAL),
                              "confidence": "bestätigt", "signature": "root:*:0:0:",
                              "response_excerpt": _excerpt(body, "root:")},
                    dedup_key=f"path-traversal:{base}:{param}",
                ))
                break
        return out

    # ---------------- Exponierte Artefakte (Inhalts-Signatur) ----------------
    async def _artifacts(self, net, base, baseline=None):
        out = []
        for path, sig, label in _ARTIFACTS:
            resp = await net.http_get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if sig.search(body):
                if baseline is not None and baseline.is_catch_all:
                    significant, sim, reasons = baseline.significant(resp)
                    if not significant:
                        self.ctx.log(f"[verify] · Artefakt {path} @ {base} als "
                                     f"Catch-all-Artefakt verworfen (sim {sim:.2f}).")
                        continue
                self.ctx.log(f"[verify] ✅ Exponiertes Artefakt bestätigt: {base}{path} ({label})")
                out.append(AgentFinding(
                    agent=self.name, title=f"Exponiertes Artefakt bestätigt: {path}",
                    category="exposed-artifact", severity="high", asset=base + path,
                    description=(f"{label}: {base}{path} liefert HTTP 200 UND passt auf die erwartete "
                                 "Inhalts-Signatur (nicht nur Statuscode). Kein Inhalt wird gedumpt."),
                    evidence={"request": {"method": "GET", "url": base + path},
                              "confidence": "bestätigt", "status": 200,
                              "signature_matched": True},
                    dedup_key=f"exposed-artifact:{base}{path}",
                ))
        return out

    # ---------------- CORS-Fehlkonfiguration ----------------
    async def _cors(self, net, base):
        origin = "https://antbb-verify.evil.example"
        resp = await net.http_get(base + "/", headers={"Origin": origin})
        if resp is None:
            return []
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if acao == origin or acao == "*":
            reflected = acao == origin
            sev = "high" if (reflected and acac == "true") else "medium"
            self.ctx.log(f"[verify] ✅ CORS-Fehlkonfiguration @ {base} (ACAO='{acao}', creds={acac or 'n/a'})")
            return [AgentFinding(
                agent=self.name, title="CORS-Fehlkonfiguration bestätigt",
                category="cors-misconfig", severity=sev, asset=base,
                description=("Der Server spiegelt eine beliebige Origin in "
                             "Access-Control-Allow-Origin" + (" bei gleichzeitig erlaubten "
                             "Credentials" if (reflected and acac == 'true') else "") +
                             " – Cross-Origin-Datenabfluss möglich."),
                evidence={"request": {"method": "GET", "url": base + "/", "origin": origin},
                          "confidence": "bestätigt",
                          "access_control_allow_origin": acao,
                          "access_control_allow_credentials": acac or "n/a"},
                dedup_key=f"cors-misconfig:{base}",
            )]
        return []

    # ---------------- Missing-Auth auf Admin-Endpunkten (nur GET) ----------------
    async def _missing_auth(self, net, base, baseline=None):
        out = []
        for path in _ADMIN_PATHS:
            resp = await net.http_get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if _ADMIN_SIG.search(body):
                if baseline is not None and baseline.is_catch_all:
                    significant, sim, reasons = baseline.significant(resp)
                    if not significant:
                        self.ctx.log(f"[verify] · Admin {path} @ {base} als "
                                     f"Catch-all-Artefakt verworfen (sim {sim:.2f}).")
                        continue
                self.ctx.log(f"[verify] ✅ Admin-Endpunkt ohne Auth erreichbar: {base}{path}")
                out.append(AgentFinding(
                    agent=self.name, title=f"Admin-Endpunkt ohne Authentifizierung: {path}",
                    category="missing-auth", severity="high", asset=base + path,
                    description=(f"{base}{path} liefert ohne Authentifizierung HTTP 200 mit "
                                 "Admin-/Dashboard-Signatur. Nur GET geprüft, KEIN Brute-Force."),
                    evidence={"request": {"method": "GET", "url": base + path},
                              "confidence": "bestätigt", "status": 200,
                              "response_excerpt": _excerpt(body, "", 60)},
                    dedup_key=f"missing-auth:{base}{path}",
                ))
        return out

    # ---------------- SSRF (OOB via interactsh + In-Band-Canary) ----------------
    async def _ssrf(self, net, cfg, base):
        """SSRF-Check: eindeutige OOB-Callback-URL (interactsh) + in-scope Canary.

        OOB-Treffer → VERIFIZIERT (auch blind). Ohne interactsh/OOB bleibt ein
        In-Band-Signal bewusst „zu bestätigen". Alles scope-gated + nicht-destruktiv.
        """
        from . import ssrf as _ssrf_mod
        from ..tools.kali import KaliAdapter
        oob = None
        try:
            oob = KaliAdapter(self.ctx).interactsh()
        except Exception as exc:
            self.ctx.log(f"[verify] ℹ️ interactsh nicht initialisierbar ({exc}) – "
                         "SSRF fällt auf In-Band zurück.")
            oob = None
        try:
            return await _ssrf_mod.run_ssrf_checks(
                net, cfg, base, agent=self.name, oob=oob, log=self.ctx.log)
        finally:
            if oob is not None:
                try:
                    oob.close()
                except Exception:
                    pass

    async def _kali_ext(self, task):
        """Externe Kali-Verify-Tools (sqlmap, metasploit-aux). Honest-empty ohne Tool."""
        from ..tools.kali import KaliAdapter
        from ..netutil import host_of
        ka = KaliAdapter(self.ctx)
        out = []
        seen = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            if "?" in asset:
                out += await ka.sqlmap(asset, agent=self.name)
            h = host_of(asset)
            if h in seen:
                continue
            seen.add(h)
            out += await ka.metasploit_aux(
                "auxiliary/scanner/http/http_version", h, agent=self.name)
        return out
