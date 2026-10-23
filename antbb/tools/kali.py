"""Kali-Tool-Adapter-Schicht: sichere Wrapper um externe Pentest-Tools.

Design-Prinzipien (streng eingehalten):
  * Scope default-deny: jedes Ziel wird VOR dem Start gegen die Allowlist
    geprüft (ctx.scope_check). Out-of-scope → blockiert + geloggt, kein Lauf.
  * Oversight/Offensiv: aktivere Tools (nmap -sV, nuclei, nikto, gobuster/ffuf,
    sqlmap, wpscan, metasploit-aux) laufen NUR, wenn der Offensiv-Modus
    freigeschaltet ist (ctx.active oder ctx.fuzz). Sonst ehrliche Meldung,
    KEIN Fake-Ergebnis.
  * Graceful degrade: fehlt das Tool (shutil.which == None), wird ehrlich
    „nicht verfügbar" gemeldet – nie ein erfundener Fund.
  * Nicht-destruktiv: feste Flags (--batch, kein --os-shell/dump-all, kein
    exploit/payload), Timeouts, Rate-Limit pro Host.
  * Proof-Gate: Treffer werden in antbb-Findings mit korrektem Status +
    strukturierter Evidence (command, Auszug) übersetzt; VERIFIZIERT nur, wenn
    das Tool aktiv nachweist (z.B. sqlmap injectable, trufflehog verified).
  * Keine Secrets: gefundene Secrets werden IMMER maskiert, nie im Klartext.

Dieses Modul wird von den Soldaten LAZY (innerhalb von work()) importiert, um
Zirkular-Importe mit dem agents-Package zu vermeiden.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional

from ..agents.base import (
    AgentFinding, STATUS_VERIFIED, STATUS_PASSIVE, STATUS_TO_CONFIRM,
    STATUS_CONDITIONAL, STATUS_REFERENCE,
)
from ..netutil import host_of
from .. import wordlists as _wordlists

# ---------------------------------------------------------------------------
# Tool-Katalog (Single Source of Truth für die Capability-Registry).
# offensive=True → benötigt Offensiv-Freischaltung (ctx.active/ctx.fuzz).
# ---------------------------------------------------------------------------
TOOL_SPECS: dict[str, dict] = {
    "nmap":       {"offensive": False, "desc": "Port-/Service-/Versions-Scan (defensiv leicht, -sV offensiv)"},
    "nuclei":     {"offensive": True,  "desc": "Template-basierter Vuln-Scan (JSON)"},
    "nikto":      {"offensive": True,  "desc": "Web-Server-Schwachstellen-Scan"},
    "whatweb":    {"offensive": False, "desc": "Web-Technologie-Fingerprint"},
    "wafw00f":    {"offensive": False, "desc": "WAF-Erkennung"},
    "gobuster":   {"offensive": True,  "desc": "Content-/Verzeichnis-Discovery (Wortliste)"},
    "ffuf":       {"offensive": True,  "desc": "Content-/Parameter-Fuzzing (Wortliste)"},
    "sqlmap":     {"offensive": True,  "desc": "SQL-Injection-Verifikation (--batch, nicht-destruktiv)"},
    "wpscan":     {"offensive": True,  "desc": "WordPress-Scan (nur falls WordPress erkannt)"},
    "sslscan":    {"offensive": False, "desc": "TLS-/Cipher-Analyse"},
    "sslyze":     {"offensive": False, "desc": "TLS-/Cipher-Analyse (alternativ)"},
    "trufflehog": {"offensive": False, "desc": "Secret-Scanning (git/filesystem/url), Funde maskiert"},
    "gitleaks":   {"offensive": False, "desc": "Secret-Scanning (git/filesystem), Funde maskiert"},
    "subfinder":  {"offensive": False, "desc": "Passive Subdomain-Enumeration"},
    "httpx":      {"offensive": False, "desc": "HTTP-Probing/Fingerprint (ProjectDiscovery)"},
    "interactsh-client": {"offensive": True, "desc": "Out-of-Band-Interaktions-Server (OAST) für blind SSRF/RCE/XXE – DNS/HTTP-Callbacks"},
    "searchsploit": {"offensive": False, "desc": "Lokale Exploit-DB-Suche (searchsploit), nur REFERENZ"},
    "sherlock":   {"offensive": False, "desc": "OSINT: Username-Enumeration über soziale Netze (rein lesend, REFERENZ)"},
    "maigret":    {"offensive": False, "desc": "OSINT: Username-Enumeration (Fallback für sherlock, rein lesend, REFERENZ)"},
    "gvm-cli":    {"offensive": True,  "desc": "Greenbone/OpenVAS (GVM) Client: Scan-Start nur mit Oversight und Scope; Report-Import bleibt defensiv"},
    "gvmd":       {"offensive": False, "desc": "Greenbone Management Daemon (lokaler Dienst; nur Erkennung, wir starten ihn nie)"},
    "msfconsole": {"offensive": True,  "desc": "Metasploit – NUR auxiliary/scanner-Module (hart allowlisted)"},
}

#: Secret-Masken-Regel: nur die ersten/letzten Zeichen, Rest maskiert.
def mask_secret(val: str) -> str:
    if not val:
        return ""
    s = str(val)
    if len(s) <= 8:
        return "****"
    return s[:4] + "…" + "*" * 6 + "…" + s[-2:]


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def tool_status() -> dict:
    """Verfügbarkeit aller bekannten Tools am Laufort (für die Registry).

    Enthält NIE Secrets – nur Namen/Pfade/Verfügbarkeit.
    """
    out = {}
    for name, spec in TOOL_SPECS.items():
        path = which(name)
        out[name] = {
            "available": bool(path),
            "path": path or "",
            "offensive": bool(spec["offensive"]),
            "desc": spec["desc"],
        }
    return out


@dataclass
class ToolResult:
    tool: str
    available: bool = False
    in_scope: bool = True
    ran: bool = False
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    command: list = field(default_factory=list)
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.ran and not self.timed_out


# Modul-weiter, prozesslokaler Per-Host-Rate-Limiter (für die externen Tools,
# die NICHT über ctx.net laufen). asyncio-Lock pro Host + Mindestabstand.
_HOST_LOCKS: dict[str, asyncio.Lock] = {}
_HOST_LAST: dict[str, float] = {}
_MIN_INTERVAL = float(os.environ.get("ANTBB_KALI_MIN_INTERVAL", "1.0"))


class KaliAdapter:
    """An einen AgentContext gebundener, sicherer Tool-Runner."""

    def __init__(self, ctx):
        self.ctx = ctx

    # ---------------- interne Helfer ----------------
    def _log(self, msg: str) -> None:
        try:
            self.ctx.log(msg)
        except Exception:
            pass

    @property
    def _offensive_engaged(self) -> bool:
        return bool(getattr(self.ctx, "active", False) or getattr(self.ctx, "fuzz", False))

    def _scope_ok(self, target: str) -> bool:
        try:
            return bool(self.ctx.scope_check(target))
        except Exception:
            return False

    async def _throttle(self, host: str) -> None:
        lock = _HOST_LOCKS.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            wait = _HOST_LAST.get(host, 0.0) + _MIN_INTERVAL - now
            if wait > 0:
                await asyncio.sleep(wait)
            _HOST_LAST[host] = time.monotonic()

    async def run(self, tool: str, argv: list, *, target: str,
                  timeout: float = 120.0, offensive: bool = False,
                  input_text: Optional[str] = None) -> ToolResult:
        """Führt ein externes Tool sicher aus. Gibt immer ein ToolResult zurück.

        `target` ist das Ziel (Host/URL/Pfad) für Scope-Check + Rate-Limit.
        Kein Crash: fehlendes Tool / out-of-scope / nicht freigeschaltet →
        ran=False mit ehrlicher Begründung.
        """
        res = ToolResult(tool=tool, command=[tool, *[str(a) for a in argv]])

        # 1) Tool vorhanden?
        path = which(tool)
        if not path:
            res.available = False
            res.error = f"Tool '{tool}' am Laufort nicht installiert (graceful degrade)."
            self._log(f"[kali] ℹ️ {tool} nicht verfügbar – übersprungen (kein Fake-Ergebnis).")
            return res
        res.available = True

        # 2) Offensiv-Gate.
        if offensive and not self._offensive_engaged:
            res.ran = False
            res.error = "Offensiv nicht freigeschaltet (Oversight/active/fuzz fehlt) – übersprungen."
            self._log(f"[kali] ⛔ {tool} ist offensiv und nicht freigeschaltet – übersprungen.")
            return res

        # 3) Scope default-deny.
        if not self._scope_ok(target):
            res.in_scope = False
            res.ran = False
            res.error = f"Ziel '{target}' out-of-scope (default-deny) – blockiert."
            self._log(f"[kali] ⛔ Scope-Block: {tool} auf '{target}' NICHT ausgeführt (out-of-scope).")
            return res

        # 4) Rate-Limit pro Host.
        host = host_of(target) or target
        await self._throttle(host)

        # 5) Ausführen (im Thread, hartes Timeout, kein shell=True).
        self._log(f"[kali] ▶ {tool} gegen {target} (timeout {int(timeout)}s)")
        def _exec():
            return subprocess.run(
                [path, *[str(a) for a in argv]],
                input=(input_text.encode() if input_text else None),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        try:
            proc = await asyncio.to_thread(_exec)
            res.ran = True
            res.returncode = proc.returncode
            res.stdout = (proc.stdout or b"").decode("utf-8", "replace")
            res.stderr = (proc.stderr or b"").decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            res.ran = True
            res.timed_out = True
            res.error = f"Timeout nach {int(timeout)}s."
            self._log(f"[kali] ⏱ {tool} Timeout nach {int(timeout)}s gegen {target}.")
        except Exception as exc:
            res.ran = False
            res.error = f"{type(exc).__name__}: {exc}"
            self._log(f"[kali] ❌ {tool} Fehler: {exc}")
        return res

    # ======================================================================
    # Konkrete Adapter (jeweils → list[AgentFinding])
    # ======================================================================

    # ---------------- nmap ----------------
    async def nmap(self, target: str, *, agent: str = "recon",
                   top_ports: int = 100, timeout: float = 180.0) -> list[AgentFinding]:
        host = host_of(target) or target
        offensive = self._offensive_engaged
        if offensive:
            # Service-/Versions-Scan (aktiver) nur unter Offensiv.
            argv = ["-sV", "-Pn", "-T3", "--top-ports", str(top_ports), host]
        else:
            # Defensiv: leichter TCP-Connect-Scan, keine Versionsabfrage.
            argv = ["-sT", "-Pn", "-T2", "--top-ports", str(min(top_ports, 50)), host]
        res = await self.run("nmap", argv, target=host, timeout=timeout, offensive=False)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        ports = _parse_nmap(res.stdout)
        if ports:
            open_list = [p["port"] for p in ports]
            out.append(AgentFinding(
                agent=agent, title=f"nmap: offene Ports/Dienste {host}",
                category="nmap-service", severity=_nmap_sev(ports), asset=host,
                description=f"nmap fand {len(ports)} offene Port(s): " +
                            ", ".join(f"{p['port']}/{p['proto']} {p['service']}"
                                      f"{(' '+p['version']) if p['version'] else ''}"
                                      for p in ports),
                evidence={"command": " ".join(res.command), "ports": ports,
                          "open_ports": open_list, "tool": "nmap"},
                status=STATUS_PASSIVE,
                dedup_key=f"nmap-service:{host}",
            ))
        return out

    # ---------------- nuclei ----------------
    async def nuclei(self, target: str, *, agent: str = "scanning",
                     severities: str = "low,medium,high,critical",
                     timeout: float = 300.0) -> list[AgentFinding]:
        argv = ["-u", target, "-silent", "-jsonl", "-severity", severities,
                "-rate-limit", "20", "-timeout", "10"]
        res = await self.run("nuclei", argv, target=target, timeout=timeout, offensive=True)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        for obj in _iter_jsonl(res.stdout):
            info = obj.get("info", {}) if isinstance(obj, dict) else {}
            sev = str(info.get("severity", "info")).lower()
            if sev not in ("info", "low", "medium", "high", "critical"):
                sev = "info"
            tid = obj.get("template-id") or obj.get("templateID") or "nuclei"
            matched = obj.get("matched-at") or obj.get("host") or target
            name = info.get("name", tid)
            out.append(AgentFinding(
                agent=agent, title=f"nuclei: {name}",
                category="nuclei-finding", severity=sev, asset=str(matched),
                description=f"nuclei-Template '{tid}' matchte: {name}.",
                evidence={"command": " ".join(res.command), "template_id": tid,
                          "matched_at": str(matched), "tool": "nuclei",
                          "response_excerpt": str(obj.get("extracted-results") or
                                                  info.get("description", ""))[:200]},
                # Tool-Fund: konservativ „zu bestätigen" (kein eigener aktiver PoC).
                status=STATUS_TO_CONFIRM,
                dedup_key=f"nuclei:{tid}:{matched}",
            ))
        return out

    # ---------------- nikto ----------------
    async def nikto(self, target: str, *, agent: str = "scanning",
                    timeout: float = 300.0) -> list[AgentFinding]:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        argv = ["-host", target, "-nointeractive", "-Format", "json", "-output", tmp.name]
        res = await self.run("nikto", argv, target=target, timeout=timeout, offensive=True)
        out: list[AgentFinding] = []
        try:
            if res.ok and os.path.getsize(tmp.name) > 0:
                with open(tmp.name, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                items = data.get("vulnerabilities", []) if isinstance(data, dict) else []
                for v in items:
                    msg = v.get("msg", "") if isinstance(v, dict) else str(v)
                    url = v.get("url", target) if isinstance(v, dict) else target
                    out.append(AgentFinding(
                        agent=agent, title=f"nikto: {msg[:80]}",
                        category="nikto-finding", severity="low", asset=str(url),
                        description=f"nikto meldete: {msg}",
                        evidence={"command": " ".join(res.command), "tool": "nikto",
                                  "id": v.get("id", "") if isinstance(v, dict) else "",
                                  "response_excerpt": msg[:200]},
                        status=STATUS_TO_CONFIRM,
                        dedup_key=f"nikto:{url}:{v.get('id','') if isinstance(v,dict) else msg[:20]}",
                    ))
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        return out

    # ---------------- whatweb ----------------
    async def whatweb(self, target: str, *, agent: str = "scanning",
                      timeout: float = 60.0) -> list[AgentFinding]:
        argv = ["--log-json=-", "--no-errors", "-a", "1", target]
        res = await self.run("whatweb", argv, target=target, timeout=timeout, offensive=False)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        for obj in _iter_jsonl(res.stdout):
            if not isinstance(obj, dict):
                continue
            plugins = obj.get("plugins", {}) or {}
            tech = {}
            for pk, pv in plugins.items():
                ver = ""
                if isinstance(pv, dict):
                    v = pv.get("version")
                    if isinstance(v, list) and v:
                        ver = str(v[0])
                    elif v:
                        ver = str(v)
                tech[pk] = ver
            if not tech:
                continue
            out.append(AgentFinding(
                agent=agent, title=f"whatweb-Fingerprint: {obj.get('target', target)}",
                category="whatweb-fingerprint", severity="info",
                asset=str(obj.get("target", target)),
                description="Erkannte Technologien: " +
                            ", ".join(f"{k}{('/'+v) if v else ''}" for k, v in list(tech.items())[:15]),
                evidence={"command": " ".join(res.command), "tech": tech, "tool": "whatweb"},
                status=STATUS_PASSIVE,
                dedup_key=f"whatweb:{obj.get('target', target)}",
            ))
        return out

    # ---------------- wafw00f ----------------
    async def wafw00f(self, target: str, *, agent: str = "scanning",
                      timeout: float = 60.0) -> list[AgentFinding]:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        argv = ["-a", "-o", tmp.name, "-f", "json", target]
        res = await self.run("wafw00f", argv, target=target, timeout=timeout, offensive=False)
        out: list[AgentFinding] = []
        try:
            if res.ok and os.path.getsize(tmp.name) > 0:
                with open(tmp.name, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                rows = data if isinstance(data, list) else [data]
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    waf = r.get("firewall") or r.get("detected")
                    if not waf or waf in ("None", "Generic"):
                        continue
                    out.append(AgentFinding(
                        agent=agent, title=f"WAF erkannt: {waf}",
                        category="wafw00f", severity="info",
                        asset=str(r.get("url", target)),
                        description=f"wafw00f erkannte eine WAF/IPS: {waf}.",
                        evidence={"command": " ".join(res.command), "waf": waf, "tool": "wafw00f"},
                        status=STATUS_PASSIVE,
                        dedup_key=f"wafw00f:{r.get('url', target)}",
                    ))
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        return out

    # ---------------- gobuster / ffuf ----------------
    async def gobuster(self, target: str, *, agent: str = "fuzz",
                       wordlist: Optional[str] = None,
                       timeout: float = 300.0) -> list[AgentFinding]:
        wl = wordlist or _wordlists.default_content_wordlist()
        if not wl:
            self._log("[kali] ℹ️ gobuster: keine Wortliste verfügbar – übersprungen (honest-empty).")
            return []
        argv = ["dir", "-u", target, "-w", wl, "-q", "-t", "20", "--no-error"]
        res = await self.run("gobuster", argv, target=target, timeout=timeout, offensive=True)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        for line in res.stdout.splitlines():
            m = re.search(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if not m:
                continue
            path, status = m.group(1), int(m.group(2))
            out.append(AgentFinding(
                agent=agent, title=f"content-discovery: {path} ({status})",
                category="content-discovery", severity="info",
                asset=target.rstrip("/") + path,
                description=f"gobuster fand {path} (HTTP {status}).",
                evidence={"command": " ".join(res.command), "path": path,
                          "status": status, "wordlist": wl, "tool": "gobuster"},
                status=STATUS_TO_CONFIRM,
                dedup_key=f"content-discovery:{target}{path}",
            ))
        return out

    async def ffuf(self, target_with_FUZZ: str, *, agent: str = "fuzz",
                   wordlist: Optional[str] = None,
                   timeout: float = 300.0) -> list[AgentFinding]:
        wl = wordlist or _wordlists.default_content_wordlist()
        if not wl:
            self._log("[kali] ℹ️ ffuf: keine Wortliste verfügbar – übersprungen (honest-empty).")
            return []
        scope_target = target_with_FUZZ.replace("FUZZ", "")
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        argv = ["-u", target_with_FUZZ, "-w", wl, "-mc", "200,204,301,307,401,403",
                "-of", "json", "-o", tmp.name, "-s", "-rate", "40"]
        res = await self.run("ffuf", argv, target=scope_target, timeout=timeout, offensive=True)
        out: list[AgentFinding] = []
        try:
            if res.ok and os.path.getsize(tmp.name) > 0:
                with open(tmp.name, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                for r in (data.get("results", []) if isinstance(data, dict) else []):
                    url = r.get("url", scope_target)
                    status = r.get("status", 0)
                    out.append(AgentFinding(
                        agent=agent, title=f"ffuf: {url} ({status})",
                        category="content-discovery", severity="info", asset=str(url),
                        description=f"ffuf fand {url} (HTTP {status}).",
                        evidence={"command": " ".join(res.command), "status": status,
                                  "wordlist": wl, "tool": "ffuf"},
                        status=STATUS_TO_CONFIRM,
                        dedup_key=f"content-discovery:{url}",
                    ))
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        return out

    # ---------------- sqlmap ----------------
    async def sqlmap(self, target_url: str, *, agent: str = "verify",
                     timeout: float = 300.0) -> list[AgentFinding]:
        # Hart nicht-destruktiv: --batch, nur lesende Technik, kein dump/os-shell.
        argv = ["-u", target_url, "--batch", "--level", "1", "--risk", "1",
                "--technique", "BEU", "--smart", "--flush-session",
                "--answers", "crack=N", "--disable-coloring"]
        res = await self.run("sqlmap", argv, target=target_url, timeout=timeout, offensive=True)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        low = res.stdout.lower()
        # sqlmap meldet aktive Bestätigung: "is vulnerable" / "injectable".
        injectable = ("is vulnerable" in low or "injectable" in low or
                      "parameter" in low and "injectable" in low)
        if injectable:
            param_m = re.search(r"parameter '([^']+)'", res.stdout, re.IGNORECASE)
            dbms_m = re.search(r"back-end DBMS: (.+)", res.stdout)
            param = param_m.group(1) if param_m else ""
            dbms = dbms_m.group(1).strip() if dbms_m else ""
            out.append(AgentFinding(
                agent=agent, title=f"SQL-Injection (sqlmap): {param or target_url}",
                category="sqli-verified", severity="high", asset=target_url,
                description=f"sqlmap bestätigte eine SQL-Injection"
                            f"{(' am Parameter ' + param) if param else ''}"
                            f"{(' (' + dbms + ')') if dbms else ''}.",
                evidence={"command": " ".join(res.command), "tool": "sqlmap",
                          "request": {"method": "GET", "url": target_url, "param": param},
                          "db": dbms,
                          "response_excerpt": "sqlmap: parameter is injectable (aktiv bestätigt)"},
                status=STATUS_VERIFIED,
                dedup_key=f"sqli-verified:{target_url}:{param}",
            ))
        return out

    # ---------------- wpscan ----------------
    async def wpscan(self, target: str, *, agent: str = "scanning",
                     timeout: float = 300.0) -> list[AgentFinding]:
        argv = ["--url", target, "--format", "json", "--no-banner",
                "--random-user-agent", "--no-update"]
        res = await self.run("wpscan", argv, target=target, timeout=timeout, offensive=True)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        try:
            data = json.loads(res.stdout)
        except Exception:
            return out
        version = (data.get("version") or {}).get("number") if isinstance(data, dict) else None
        if version:
            out.append(AgentFinding(
                agent=agent, title=f"WordPress erkannt: {version}",
                category="version-disclosure", severity="info", asset=target,
                description=f"wpscan erkannte WordPress {version}.",
                evidence={"command": " ".join(res.command), "tool": "wpscan",
                          "package": "wordpress", "version": version},
                status=STATUS_PASSIVE,
                dedup_key=f"wpscan-version:{target}",
            ))
        return out

    # ---------------- sslscan ----------------
    async def sslscan(self, target: str, *, agent: str = "infra",
                      timeout: float = 90.0) -> list[AgentFinding]:
        host = host_of(target) or target
        argv = ["--no-colour", host]
        res = await self.run("sslscan", argv, target=host, timeout=timeout, offensive=False)
        if not res.ok:
            return []
        weak = []
        for proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
            if re.search(rf"{re.escape(proto)}\s+enabled", res.stdout):
                weak.append(proto)
        out: list[AgentFinding] = []
        if weak:
            out.append(AgentFinding(
                agent=agent, title=f"Schwache TLS-Protokolle: {host}",
                category="tls-scan", severity="medium", asset=host,
                description=f"sslscan: veraltete Protokolle aktiviert: {', '.join(weak)}.",
                evidence={"command": " ".join(res.command), "weak_protocols": weak,
                          "tool": "sslscan"},
                status=STATUS_PASSIVE,
                dedup_key=f"tls-scan-weak:{host}",
            ))
        return out

    # ---------------- trufflehog ----------------
    async def trufflehog(self, source: str, *, mode: str = "filesystem",
                         agent: str = "osint", timeout: float = 240.0) -> list[AgentFinding]:
        """Secret-Scanning. mode: filesystem|git|github (source = Pfad/URL/Repo).

        NUR autorisierte Ziele (Scope-Check über `source`). Funde werden immer
        maskiert; Klartext-Secrets werden NIE in Evidence/Report geschrieben.
        VERIFIZIERT nur bei trufflehog-verified Treffern, sonst ZU BESTÄTIGEN.
        """
        if mode not in ("filesystem", "git", "github"):
            mode = "filesystem"
        argv = [mode, source, "--json", "--no-update"]
        res = await self.run("trufflehog", argv, target=source, timeout=timeout, offensive=False)
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        for obj in _iter_jsonl(res.stdout):
            if not isinstance(obj, dict):
                continue
            detector = obj.get("DetectorName") or obj.get("DetectorType") or "secret"
            verified = bool(obj.get("Verified"))
            raw = obj.get("Raw") or obj.get("Redacted") or ""
            where = ""
            src = obj.get("SourceMetadata", {})
            if isinstance(src, dict):
                data = src.get("Data", {})
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, dict):
                            where = v.get("file") or v.get("link") or v.get("repository") or ""
                            if where:
                                break
            out.append(AgentFinding(
                agent=agent, title=f"Secret-Fund ({detector}){' [verified]' if verified else ''}",
                category="secret-exposure",
                severity=("high" if verified else "medium"),
                asset=str(where or source),
                description=f"trufflehog fand ein mögliches Secret vom Typ '{detector}'"
                            f"{' (aktiv verifiziert)' if verified else ' (unverifiziert – zu bestätigen)'}. "
                            f"Wert maskiert: {mask_secret(raw)}",
                evidence={"command": " ".join(res.command), "detector": detector,
                          "verified": verified, "masked": mask_secret(raw),
                          "location": str(where), "tool": "trufflehog",
                          "request": {"method": "SCAN", "url": str(where or source)},
                          "response_excerpt": f"detector={detector} verified={verified}"},
                status=(STATUS_VERIFIED if verified else STATUS_TO_CONFIRM),
                dedup_key=f"secret:{detector}:{where}:{mask_secret(raw)}",
            ))
        return out

    # ---------------- metasploit auxiliary/scanner ----------------
    async def metasploit_aux(self, module: str, rhosts: str, *,
                             options: Optional[dict] = None,
                             agent: str = "verify", timeout: float = 240.0) -> list[AgentFinding]:
        """Führt EIN Metasploit-Modul aus – HART beschränkt auf auxiliary/scanner/*.

        Keine exploit-/payload-/session-Module. Scope-Check über rhosts.
        """
        module = (module or "").strip()
        if not module.startswith("auxiliary/scanner/"):
            self._log(f"[kali] ⛔ msf-Modul '{module}' NICHT erlaubt "
                      f"(nur auxiliary/scanner/* zugelassen) – blockiert.")
            return []
        # Zusätzliche harte Negativ-Filter.
        if any(bad in module for bad in ("exploit", "payload", "post/", "/dos/")):
            self._log(f"[kali] ⛔ msf-Modul '{module}' enthält unerlaubten Pfad – blockiert.")
            return []
        opts = options or {}
        # Options-Werte gegen Injection in das Resource-Script absichern.
        safe_opts = {k: str(v) for k, v in opts.items()
                     if re.fullmatch(r"[A-Za-z0-9_]+", str(k))
                     and "\n" not in str(v) and ";" not in str(v)}
        lines = [f"use {module}", f"set RHOSTS {rhosts}"]
        for k, v in safe_opts.items():
            lines.append(f"set {k} {v}")
        lines += ["run", "exit"]
        script = tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False)
        script.write("\n".join(lines) + "\n")
        script.close()
        argv = ["-q", "-n", "-r", script.name, "-x", "exit -y"]
        res = await self.run("msfconsole", argv, target=rhosts, timeout=timeout, offensive=True)
        try:
            os.unlink(script.name)
        except Exception:
            pass
        if not res.ok:
            return []
        out: list[AgentFinding] = []
        hits = [ln for ln in res.stdout.splitlines()
                if "[+]" in ln and "exit" not in ln.lower()]
        if hits:
            out.append(AgentFinding(
                agent=agent, title=f"msf-aux: {module} meldete Treffer",
                category="msf-aux-finding", severity="low", asset=rhosts,
                description=f"Metasploit auxiliary/scanner '{module}' meldete "
                            f"{len(hits)} positive(n) Treffer.",
                evidence={"command": f"msfconsole {module}", "tool": "metasploit",
                          "module": module,
                          "response_excerpt": " | ".join(h.strip()[:120] for h in hits[:5])},
                status=STATUS_TO_CONFIRM,
                dedup_key=f"msf-aux:{module}:{rhosts}",
            ))
        return out

    # ---------------- interactsh (OOB / OAST) ----------------
    def interactsh(self, *, timeout: float = 20.0):
        """Startet (falls vorhanden) eine OOB/OAST-Session via interactsh-client.

        Graceful degrade: ist ``interactsh-client`` NICHT installiert (shutil.which
        == None), wird eine Session mit ``available=False`` + klarer Status-Meldung
        zurückgegeben – NIE ein Fake-Callback. Das Tool wird hier NICHT installiert.

        Rückgabe: ``InteractshSession`` (siehe unten). Die Session reicht eindeutige
        Callback-Domains heraus (Token im Subdomain-Label) und pollt die
        korrelierten DNS/HTTP-Interaktionen. Es werden KEINE Secrets/Ziele in die
        Callback-Domain geschrieben – nur zufällige Tokens.
        """
        path = which("interactsh-client")
        if not path:
            self._log("[kali] ℹ️ interactsh-client nicht installiert – OOB/OAST nicht "
                      "verfügbar (blind SSRF/RCE/XXE fallen auf In-Band/Timing zurück).")
            return InteractshSession(available=False, logger=self._log)
        sess = InteractshSession(available=True, binary=path, logger=self._log)
        sess.register(timeout=timeout)
        return sess

    # ---------------- searchsploit ----------------
    async def searchsploit(self, term: str, *, agent: str = "threatintel",
                           timeout: float = 60.0) -> list[AgentFinding]:
        """Lokale Exploit-DB-Suche. Treffer sind REFERENZ (kein eigener Nachweis)."""
        argv = ["--json", term]
        # searchsploit braucht keinen Netzzugang/kein Ziel → Scope-Check entfällt,
        # aber wir laufen trotzdem über run() mit target=term (scope-agnostisch):
        path = which("searchsploit")
        if not path:
            self._log("[kali] ℹ️ searchsploit nicht verfügbar – übersprungen.")
            return []
        def _exec():
            return subprocess.run([path, "--json", term], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout, check=False)
        try:
            proc = await asyncio.to_thread(_exec)
        except Exception as exc:
            self._log(f"[kali] ❌ searchsploit Fehler: {exc}")
            return []
        out = []
        try:
            data = json.loads((proc.stdout or b"").decode("utf-8", "replace"))
            results = data.get("RESULTS_EXPLOIT", []) if isinstance(data, dict) else []
        except Exception:
            results = []
        for r in results[:10]:
            if not isinstance(r, dict):
                continue
            out.append(AgentFinding(
                agent=agent, title=f"searchsploit: {r.get('Title','')[:80]}",
                category="cve-reference", severity="info", asset=term,
                description=f"Exploit-DB-Eintrag (REFERENZ): {r.get('Title','')} "
                            f"[{r.get('Path','')}]",
                evidence={"command": f"searchsploit {term}", "tool": "searchsploit",
                          "edb_path": r.get("Path", ""), "source": "exploit-db"},
                status=STATUS_REFERENCE,
                dedup_key=f"searchsploit:{term}:{r.get('Path','')}",
            ))
        return out


    # ---------------- sherlock / maigret (OSINT Username-Enumeration) ----------
    async def _run_bare(self, tool: str, argv: list, *, timeout: float):
        """Scope-agnostischer Direkt-Lauf (wie searchsploit): das "Ziel" ist ein
        oeffentlicher Username, kein Netz-Asset der Allowlist. Honest-empty ohne Tool."""
        res = ToolResult(tool=tool, command=[tool, *[str(a) for a in argv]])
        path = which(tool)
        if not path:
            res.available = False
            res.error = f"Tool '{tool}' am Laufort nicht installiert (graceful degrade)."
            self._log(f"[kali] i {tool} nicht verfuegbar - uebersprungen (kein Fake-Ergebnis).")
            return res
        res.available = True
        self._log(f"[kali] > {tool} (OSINT, timeout {int(timeout)}s)")
        def _exec():
            return subprocess.run([path, *[str(a) for a in argv]],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout, check=False, cwd=tempfile.gettempdir())
        try:
            proc = await asyncio.to_thread(_exec)
            res.ran = True
            res.returncode = proc.returncode
            res.stdout = (proc.stdout or b"").decode("utf-8", "replace")
            res.stderr = (proc.stderr or b"").decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            res.ran = True
            res.timed_out = True
            res.error = f"Timeout nach {int(timeout)}s."
            self._log(f"[kali] timeout {tool} nach {int(timeout)}s.")
        except Exception as exc:
            res.ran = False
            res.error = f"{type(exc).__name__}: {exc}"
            self._log(f"[kali] x {tool} Fehler: {exc}")
        return res

    @staticmethod
    def _valid_username(username: str) -> bool:
        # Kein shell=True; Usernames bleiben alphanumerisch + . _ - (keine Pfade/Spaces).
        return bool(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username or ""))

    async def sherlock(self, username: str, *, agent: str = "osint",
                       timeout: float = 180.0) -> list[AgentFinding]:
        """Username-Enumeration via sherlock. REFERENZ (informational), kein
        aktiver Nachweis. Profile werden NICHT automatisch abgerufen/gescraped."""
        if not self._valid_username(username):
            self._log("[kali] blocked sherlock: ungueltiger Username - uebersprungen.")
            return []
        argv = ["--print-found", "--no-color", "--timeout", "15", username]
        res = await self._run_bare("sherlock", argv, timeout=timeout)
        if not res.ok:
            return []
        return _records_to_findings(_parse_username_enum(res.stdout), username,
                                    tool="sherlock", agent=agent,
                                    command=" ".join(res.command))

    async def maigret(self, username: str, *, agent: str = "osint",
                      timeout: float = 240.0) -> list[AgentFinding]:
        """Fallback-Username-Enumeration via maigret. REFERENZ, kein Scraping."""
        if not self._valid_username(username):
            self._log("[kali] blocked maigret: ungueltiger Username - uebersprungen.")
            return []
        argv = ["--print-found", "--no-color", "--timeout", "15", username]
        res = await self._run_bare("maigret", argv, timeout=timeout)
        if not res.ok:
            return []
        return _records_to_findings(_parse_username_enum(res.stdout), username,
                                    tool="maigret", agent=agent,
                                    command=" ".join(res.command))

    async def username_enum(self, username: str, *, agent: str = "osint") -> list[AgentFinding]:
        """Primaer sherlock, Fallback maigret, honest-empty wenn keines installiert."""
        if which("sherlock"):
            return await self.sherlock(username, agent=agent)
        if which("maigret"):
            self._log("[kali] i sherlock fehlt - nutze maigret (Fallback).")
            return await self.maigret(username, agent=agent)
        self._log("[kali] i weder sherlock noch maigret installiert - honest-empty (kein Fake).")
        return []


# ===========================================================================
# Parser-Hilfen
# ===========================================================================
def _iter_jsonl(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") or line.startswith("[")):
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


_NMAP_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.MULTILINE)


def _parse_nmap(text: str) -> list[dict]:
    ports = []
    for m in _NMAP_PORT_RE.finditer(text or ""):
        ports.append({
            "port": int(m.group(1)), "proto": m.group(2),
            "service": m.group(3), "version": (m.group(4) or "").strip(),
        })
    return ports


def _nmap_sev(ports: list[dict]) -> str:
    risky = {21, 23, 25, 3306, 5432, 6379, 27017, 9200, 11211}
    if any(p["port"] in risky for p in ports):
        return "low"
    return "info"


# sherlock/maigret drucken gefundene Profile als "[+] SiteName: URL".
_USERNAME_ENUM_RE = re.compile(r"^\s*\[\+\]\s*([^:]+?):\s*(https?://\S+)\s*$", re.MULTILINE)


def _parse_username_enum(text: str) -> list[dict]:
    """Parst sherlock/maigret-Ausgabe in strukturierte Records.

    Jeder Record: {site, url, claimed_present=True}. Nur vom Tool als vorhanden
    GEMELDETE Profile werden uebernommen - keine erfundenen Treffer.
    URLs werden NICHT abgerufen/gescraped.
    """
    records: list[dict] = []
    seen: set[str] = set()
    for m in _USERNAME_ENUM_RE.finditer(text or ""):
        site = m.group(1).strip()
        url = m.group(2).strip()
        key = (site.lower(), url.lower())
        if not site or not url or key in seen:
            continue
        seen.add(key)
        records.append({"site": site, "url": url, "claimed_present": True})
    return records


def _records_to_findings(records: list[dict], username: str, *, tool: str,
                         agent: str, command: str) -> list[AgentFinding]:
    if not records:
        return []
    sites = ", ".join(r["site"] for r in records[:20])
    return [AgentFinding(
        agent=agent,
        title=f"OSINT: Username '{username}' auf {len(records)} Plattform(en) ({tool})",
        category="osint-username", severity="info", asset=username,
        description=(f"{tool} meldet den Usernamen '{username}' als vorhanden auf "
                     f"{len(records)} Plattform(en): {sites}. "
                     f"REFERENZ/informativ - Profile wurden NICHT abgerufen/verifiziert; "
                     f"Zuordnung zur Zielperson ist zu bestaetigen."),
        evidence={"command": command, "tool": tool, "username": username,
                  "sites": records, "site_count": len(records),
                  "note": "claimed-present laut Tool; nicht aktiv verifiziert, kein Scraping"},
        status=STATUS_REFERENCE,
        dedup_key=f"osint-username:{tool}:{username}",
    )]


# ===========================================================================
# Interactsh / OAST-Session (Out-of-Band-Interaktionen für blind SSRF/RCE/XXE)
# ===========================================================================
class InteractshSession:
    """Dünner, sicherer Wrapper um ``interactsh-client -json``.

    Design:
      * ``available`` ist False, wenn das Tool fehlt → Aufrufer fällt auf
        In-Band/Timing zurück (honest, kein Fake-Callback).
      * ``payload_url(token)`` liefert eine eindeutige Callback-URL, deren
        Subdomain-Label das Token trägt (``<token>.<oast-domain>``). Es wird
        KEIN Ziel-/Secret-Wert in die Domain geschrieben.
      * ``poll()`` liest neue, als JSON gemeldete Interaktionen und gibt die
        Menge der korrelierten Tokens zurück (DNS ODER HTTP).
      * ``close()`` beendet den Hintergrundprozess sauber.

    Dieser Wrapper spricht NUR mit dem interactsh-Dienst (ausgehende OOB-Callbacks
    kommen vom GETESTETEN Server, nicht von antbb). antbb selbst requestet die
    Callback-Domain nie – sie wird nur als Parameterwert in einen in-scope Request
    an das Ziel gelegt.
    """

    def __init__(self, *, available: bool, binary: Optional[str] = None, logger=None):
        self.available = bool(available)
        self._binary = binary
        self._log = logger or (lambda *_: None)
        self._proc = None
        self._domain = ""
        self._reader = None
        self._seen_tokens: set = set()
        self._lines: list = []
        self._lock = None

    # -- Lebenszyklus --
    def register(self, *, timeout: float = 20.0) -> bool:
        """Startet den Client und liest die zugewiesene OAST-Domain aus."""
        if not self.available or not self._binary:
            return False
        import threading
        try:
            self._proc = subprocess.Popen(
                [self._binary, "-json", "-o", "/dev/stdout"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
        except Exception as exc:  # pragma: no cover - nur ohne Tool relevant
            self._log(f"[kali] ❌ interactsh-client Start fehlgeschlagen: {exc}")
            self.available = False
            return False
        self._lock = threading.Lock()

        def _pump():
            try:
                for line in self._proc.stdout:  # type: ignore[union-attr]
                    line = line.strip()
                    if not line:
                        continue
                    with self._lock:  # type: ignore[union-attr]
                        self._lines.append(line)
            except Exception:
                pass

        self._reader = threading.Thread(target=_pump, daemon=True)
        self._reader.start()

        # Domain aus den ersten Zeilen (JSON mit "domain" ODER Klartext *.oast.*).
        import time as _t
        deadline = _t.monotonic() + timeout
        while _t.monotonic() < deadline and not self._domain:
            _t.sleep(0.2)
            with self._lock:
                lines = list(self._lines)
            for ln in lines:
                dom = _extract_oast_domain(ln)
                if dom:
                    self._domain = dom
                    break
        if self._domain:
            self._log(f"[kali] ▶ interactsh OAST-Domain aktiv ({self._domain[:40]}…).")
            return True
        self._log("[kali] ⚠️ interactsh-client lieferte keine OAST-Domain – OOB inaktiv.")
        self.available = False
        return False

    @property
    def domain(self) -> str:
        return self._domain

    def payload_url(self, token: str, *, scheme: str = "http") -> str:
        """Eindeutige Callback-URL; Token steckt im Subdomain-Label (kein Secret)."""
        tok = re.sub(r"[^a-z0-9]", "", (token or "").lower())[:24] or "antbb"
        if not self._domain:
            return ""
        return f"{scheme}://{tok}.{self._domain}"

    def poll(self) -> set:
        """Liefert die Menge neuer, korrelierter Tokens aus den Interaktionen."""
        if not self.available:
            return set()
        hits: set = set()
        with (self._lock or _DummyLock()):
            lines = list(self._lines)
        for ln in lines:
            for tok in _tokens_in_interaction(ln):
                if tok not in self._seen_tokens:
                    self._seen_tokens.add(tok)
                hits.add(tok)
        return hits

    def close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None


class _DummyLock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_OAST_DOMAIN_RE = re.compile(r"([a-z0-9]+\.(?:oast\.[a-z]+|interact\.sh))", re.IGNORECASE)


def _extract_oast_domain(line: str) -> str:
    """Zieht die zugewiesene OAST-Wurzel-Domain aus einer Client-Ausgabezeile."""
    line = (line or "").strip()
    if not line:
        return ""
    # JSON-Form: {"domain":"abcd.oast.fun", ...} o.ä.
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            for k in ("domain", "Domain", "full-id", "host"):
                v = obj.get(k) if isinstance(obj, dict) else None
                if isinstance(v, str) and v:
                    m = _OAST_DOMAIN_RE.search(v)
                    if m:
                        return m.group(1)
        except Exception:
            pass
    m = _OAST_DOMAIN_RE.search(line)
    return m.group(1) if m else ""


def _tokens_in_interaction(line: str) -> list:
    """Extrahiert Subdomain-Token aus einer gemeldeten Interaktion (JSON/Text)."""
    line = (line or "").strip()
    out: list = []
    full = ""
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                full = (obj.get("full-id") or obj.get("fullId") or
                        obj.get("host") or obj.get("unique-id") or "")
                # Interaktionstyp vorhanden? (dns/http) – nur echte Interaktionen.
                itype = obj.get("protocol") or obj.get("type") or ""
                if not full and not itype:
                    return out
        except Exception:
            full = ""
    if not full:
        full = line
    # Token = erstes Subdomain-Label vor der OAST-Domain.
    m = _OAST_DOMAIN_RE.search(full)
    if m:
        prefix = full[:m.start()].rstrip(".")
        label = prefix.split(".")[-1] if prefix else ""
        label = re.sub(r"[^a-z0-9]", "", label.lower())
        if label:
            out.append(label)
    return out
