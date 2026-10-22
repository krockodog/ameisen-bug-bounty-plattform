"""Scanning-Ameise: ECHTE, defensive Web-Checks.

- HTTP-Fingerprinting: Statuscode, Server-Header, Technologie-Hinweise.
- Header-Analyse: fehlende Security-Header (CSP, HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy).
- Erkennung offener Verzeichnisse / Directory-Listing und exponierter
  sensibler Pfade (/.git/, /.env, /server-status ...).
- SEHR einfache, nicht-destruktive Injection-INDIKATOREN:
  * Reflektierter Parameter (ein harmloser Marker wird im Body gespiegelt).
  * Fehler-Indikator: ein einzelnes `'` löst evtl. eine DB-Fehlermeldung aus.
  KEINE Exploits, keine destruktiven Payloads, nur lesende GETs.

Alle Requests laufen über ctx.net (Scope-Enforcement + Rate-Limiting).
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for, host_of, build_catchall_baseline

# (Header, Schweregrad, Beschreibung) – fehlende Security-Header
_SEC_HEADERS = [
    ("content-security-policy", "medium", "Content-Security-Policy (CSP) fehlt – XSS-Schutz reduziert."),
    ("strict-transport-security", "medium", "HSTS fehlt – Downgrade/MITM auf HTTPS erleichtert."),
    ("x-content-type-options", "low", "X-Content-Type-Options fehlt – MIME-Sniffing möglich."),
    ("x-frame-options", "low", "X-Frame-Options fehlt – Clickjacking möglich (falls keine CSP frame-ancestors)."),
    ("referrer-policy", "low", "Referrer-Policy fehlt – Referrer-Leak möglich."),
]

# Technologie-Hinweise aus Headern
_TECH_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "via", "x-generator"]

# Fehler-Signaturen für den (nicht-destruktiven) SQL-Fehler-Indikator
_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-01756", "pg::syntaxerror",
    "sqlite3.operationalerror", "sql syntax", "psqlexception",
]

# Directory-Listing-Signaturen
_LISTING_SIGS = ["index of /", "<title>directory listing", "[to parent directory]"]


class ScanningAnt(AntAgent):
    name = "scanning"
    role = "Web-Scan: Fingerprint, Security-Header, offene Verzeichnisse, Injection-Indikatoren (echt, defensiv)"
    specialty = "web-hunter"
    phases = ("scan",)
    playbooks = (
        Playbook("http-fingerprint", "defensive", False,
                 ["server-header", "x-powered-by", "content-type"],
                 "HTTP-Statuscode, Server-/Technologie-Hinweise."),
        Playbook("security-header-analyse", "defensive", False,
                 ["csp", "hsts", "x-content-type-options", "x-frame-options",
                  "referrer-policy"],
                 "Fehlende Security-Header erkennen."),
        Playbook("exposed-paths", "defensive", False,
                 ["directory-listing", "sensitive-paths"],
                 "Directory-Listing und sensible Pfade (/.git/, /.env, ...)."),
        Playbook("injection-indikatoren", "defensive", False,
                 ["reflected-param", "sql-error-indicator"],
                 "Nicht-destruktive XSS-/SQLi-Indikatoren (nur lesend)."),
        Playbook("whatweb-fingerprint", "defensive", False,
                 ["whatweb"],
                 "Technologie-Fingerprint via whatweb."),
        Playbook("waf-detect", "defensive", False,
                 ["wafw00f"],
                 "WAF-/IPS-Erkennung via wafw00f."),
        Playbook("nuclei-scan", "offensive", True,
                 ["nuclei"],
                 "Template-basierter Vuln-Scan via nuclei (JSON)."),
        Playbook("nikto-scan", "offensive", True,
                 ["nikto"],
                 "Web-Server-Schwachstellen-Scan via nikto."),
        Playbook("wpscan", "offensive", True,
                 ["wpscan"],
                 "WordPress-Scan via wpscan (nur falls WordPress erkannt)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            self.ctx.log("[scanning] Kein NetClient – übersprungen.")
            return findings
        cfg = net.cfg
        scanned_bases: set[str] = set()

        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            for base in base_urls_for(asset):
                if base in scanned_bases:
                    continue
                resp = await net.http_get(base + "/")
                if resp is None:
                    continue
                scanned_bases.add(base)
                # Catch-all-/Baseline-Schutz gegen jitternde Platzhalterseiten:
                # status-200-basierte Pfad-Funde nur melden, wenn sie signifikant
                # von der Catch-all-Antwort abweichen.
                sim_thr = float(getattr(cfg, "fuzz_similarity_threshold", 0.85) or 0.85)
                n_s = max(3, int(getattr(cfg, "catchall_min_samples", 3) or 3))
                baseline = await build_catchall_baseline(
                    net, base, n_samples=n_s, threshold=sim_thr,
                )
                if baseline.is_catch_all:
                    self.ctx.log("[scanning] ⚠️ " + baseline.describe())
                findings.extend(self._fingerprint(base, resp))
                findings.extend(self._headers(base, resp))
                findings.extend(await self._paths(net, cfg, base, baseline))
                findings.extend(await self._reflect(net, cfg, base))
                findings.extend(await self._sql_indicator(net, cfg, base))
        findings += await self._kali_ext(task)
        return findings

    # ---- HTTP-Fingerprint ----
    def _fingerprint(self, base, resp):
        server = resp.headers.get("server", "")
        tech = {h: resp.headers[h] for h in _TECH_HEADERS if h in resp.headers}
        self.ctx.log(f"[scanning] {base}/ → HTTP {resp.status_code}, Server '{server or 'n/a'}'")
        return [AgentFinding(
            agent=self.name, title=f"HTTP-Fingerprint: {base}",
            category="fingerprint", severity="info", asset=base,
            description=(f"Statuscode {resp.status_code}; Server '{server or 'n/a'}'; "
                         f"Technologie-Hinweise: {tech or 'keine'}."),
            evidence={"status": resp.status_code, "server": server, "tech": tech,
                      "content_type": resp.headers.get("content-type", "")},
            dedup_key=f"fp:{base}",
        )]

    # ---- fehlende Security-Header ----
    def _headers(self, base, resp):
        out = []
        missing = []
        for name, sev, desc in _SEC_HEADERS:
            if name not in resp.headers:
                missing.append(name)
                out.append(AgentFinding(
                    agent=self.name, title=f"Fehlender Security-Header: {name}",
                    category="misconfig", severity=sev, asset=base,
                    description=desc, evidence={"missing_header": name},
                    dedup_key=f"hdr:{base}:{name}",
                ))
        if missing:
            self.ctx.log(f"[scanning] {base}: fehlende Header {missing}")
        return out

    # ---- offene Verzeichnisse / sensible Pfade ----
    async def _paths(self, net, cfg, base, baseline=None):
        out = []
        catch_all = baseline is not None and baseline.is_catch_all
        for path in cfg.paths:
            resp = await net.http_get(base + path)
            if resp is None:
                continue
            # Catch-all-Host: status-200 allein ist bedeutungslos. Nur weiter,
            # wenn die Antwort signifikant von der Platzhalter-Baseline abweicht.
            if catch_all:
                significant, sim, reasons = baseline.significant(resp)
                if not significant:
                    self.ctx.log(f"[scanning] · {path} @ {base} als Catch-all-"
                                 f"Artefakt verworfen (sim {sim:.2f}).")
                    continue
            body = (resp.text or "")[:4000].lower()
            if resp.status_code == 200 and any(sig in body for sig in _LISTING_SIGS):
                out.append(AgentFinding(
                    agent=self.name, title=f"Directory-Listing offen: {path}",
                    category="info-disclosure", severity="medium", asset=base + path,
                    description=f"Verzeichnisauflistung unter {base}{path} erreichbar (HTTP 200).",
                    evidence={"path": path, "status": 200, "signature": "directory-listing"},
                    dedup_key=f"listing:{base}{path}",
                ))
                self.ctx.log(f"[scanning] {base}{path}: Directory-Listing offen")
            elif resp.status_code == 200 and path in ("/.git/", "/.env", "/server-status", "/backup/"):
                out.append(AgentFinding(
                    agent=self.name, title=f"Sensibler Pfad erreichbar: {path}",
                    category="info-disclosure", severity="high", asset=base + path,
                    description=f"Potenziell sensibler Pfad {base}{path} antwortet mit HTTP 200.",
                    evidence={"path": path, "status": 200},
                    dedup_key=f"sensitive:{base}{path}",
                ))
                self.ctx.log(f"[scanning] {base}{path}: sensibler Pfad erreichbar (200)")
        return out

    # ---- reflektierter Parameter (Indikator, nicht-destruktiv) ----
    async def _reflect(self, net, cfg, base):
        marker = f"antbbREF{abs(hash(base)) % 100000}"
        resp = await net.http_get(base + "/", params={cfg.reflect_param: marker})
        if resp is None:
            return []
        if marker in (resp.text or ""):
            self.ctx.log(f"[scanning] {base}: Parameter wird reflektiert (XSS-Indikator)")
            return [AgentFinding(
                agent=self.name, title="Reflektierter Parameter (XSS-Indikator)",
                category="xss-indicator", severity="low", asset=base,
                description=("Ein harmloser Marker im Query-Parameter wurde unverändert im "
                             "Response-Body reflektiert. Hinweis auf mögliche reflektierte "
                             "Eingaben (kein Exploit ausgeführt)."),
                evidence={"param": cfg.reflect_param, "reflected": True, "marker": marker},
                dedup_key=f"reflect:{base}",
            )]
        return []

    # ---- SQL-Fehler-Indikator (nicht-destruktiv: einzelnes Hochkomma) ----
    async def _sql_indicator(self, net, cfg, base):
        resp = await net.http_get(base + "/", params={"id": "1'"})
        if resp is None:
            return []
        body = (resp.text or "").lower()
        hit = next((e for e in _SQL_ERRORS if e in body), None)
        if hit:
            self.ctx.log(f"[scanning] {base}: DB-Fehlermeldung bei '-Payload (SQLi-Indikator)")
            return [AgentFinding(
                agent=self.name, title="SQL-Fehlermeldung (SQLi-Indikator)",
                category="sqli-indicator", severity="medium", asset=base,
                description=("Ein einzelnes Hochkomma im Parameter löste eine Datenbank-"
                             "Fehlermeldung aus. Indikator für mögliche SQL-Injection "
                             "(kein Exploit, keine Datenextraktion)."),
                evidence={"param": "id", "error_signature": hit},
                dedup_key=f"sqli-ind:{base}",
            )]
        return []

    async def _kali_ext(self, task):
        """Externe Kali-Web-Tools. Honest-empty, wenn nicht installiert."""
        from ..tools.kali import KaliAdapter
        from ..netutil import base_urls_for
        ka = KaliAdapter(self.ctx)
        out = []
        seen = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            for base in base_urls_for(asset):
                if base in seen:
                    continue
                seen.add(base)
                ww = await ka.whatweb(base, agent=self.name)
                out += ww
                out += await ka.wafw00f(base, agent=self.name)
                out += await ka.nuclei(base, agent=self.name)
                out += await ka.nikto(base, agent=self.name)
                blob = (str([f.evidence for f in ww]) +
                        str([f.evidence for f in task.context_findings])).lower()
                if "wordpress" in blob or "wp-content" in blob:
                    out += await ka.wpscan(base, agent=self.name)
        return out
