"""Greenbone Community Edition / OpenVAS (GVM) – Adapter für die Blue Queen.

Zwei klar getrennte Fähigkeiten:

  * DEFENSIV (immer erlaubt, kein Netzwerkverkehr): Report-Import aus Datei.
    Greenbone-XML (`get_reports`-Export), Greenbone-CSV und JSON werden robust
    geparst; es werden ausschließlich Felder übernommen, die tatsächlich im
    Report stehen (NVT, CVE, CVSS, Threat, QoD, Host, Port, Lösung). Nichts wird
    ergänzt oder erfunden. Aus High/Critical-Funden entstehen Härtungs-/
    Ticket-Hinweise (`remediation_hints`) – nie ein automatischer Fix.

  * AKTIV (nur mit ausdrücklicher Human-Oversight-Freigabe UND In-Scope-Ziel):
    einen Scan gegen EIN explizit übergebenes Einzelziel starten, Status
    abfragen, Report abholen. Keine Netze/CIDR/Listen, nur harmlose Scan-Configs
    (Allowlist, kein „deep/ultimate"), ein Scan gleichzeitig, Mindestabstand
    zwischen Starts, Timeouts. Fehlt GVM, kommt ein ehrlicher Fehler.

Transport: bevorzugt `python-gvm` (optionale Dependency), sonst `gvm-cli` als
Fallback. Beides spricht ausschließlich den lokalen gvmd-Unix-Socket.

Zugangsdaten: nur aus der Umgebung zur Laufzeit (`GVM_USERNAME`, `GVM_PASSWORD`,
`GVM_SOCKET`). Sie werden nie geloggt, nie in Findings/Evidence geschrieben und
nie auf der Kommandozeile übergeben (gvm-cli bekommt sie über eine flüchtige
0600-Config-Datei, die danach gelöscht wird).
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
from xml.sax.saxutils import escape as _xesc, quoteattr as _xattr

from . import config as _config

AGENT = "blue-greenbone"
CATEGORY_VULN = "blue-greenbone-vuln"
CATEGORY_STATUS = "blue-greenbone-status"
CATEGORY_SUMMARY = "blue-greenbone-summary"
CATEGORY_REMEDIATION = "blue-greenbone-remediation"
CATEGORY_SCAN = "blue-greenbone-scan"

#: Übliche Pfade des gvmd-Unix-Sockets (Debian/Kali, Docker-Setups, Source-Builds).
SOCKET_CANDIDATES = (
    "/run/gvmd/gvmd.sock",
    "/var/run/gvmd/gvmd.sock",
    "/run/gvm/gvmd.sock",
    "/var/run/gvm/gvmd.sock",
    "/opt/gvm/var/run/gvmd.sock",
    "/usr/local/var/run/gvmd/gvmd.sock",
)

MAX_IMPORT_BYTES = 50 * 1024 * 1024
IMPORT_SUFFIXES = (".xml", ".json", ".csv")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HOST_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9A-Fa-f:]{2,39})$")

#: Nur nicht-destruktive Scan-Configs (Name → wird per get_configs aufgelöst).
SAFE_SCAN_CONFIGS = ("Full and fast", "Base", "Discovery", "Host Discovery", "System Discovery")
DEFAULT_SCAN_CONFIG = "Full and fast"
DEFAULT_PORT_LIST = "All IANA assigned TCP"
SCAN_TASK_PREFIX = "antbb-"
TERMINAL_STATES = ("Done", "Stopped", "Interrupted")
ACTIVE_STATES = ("New", "Requested", "Queued", "Running", "Stop Requested")
MAX_WAIT_SECONDS = 900
MIN_SCAN_INTERVAL = float(os.environ.get("ANTBB_GVM_MIN_SCAN_INTERVAL", "60"))


class GvmError(RuntimeError):
    """Ehrlicher Fehler der Greenbone-Anbindung (nie ein Fake-Ergebnis)."""


class GvmUnavailable(GvmError):
    """Greenbone/GVM ist am Laufort nicht erreichbar."""


# ===========================================================================
# Datenmodell
# ===========================================================================
@dataclass
class GvmResult:
    """Ein einzelnes Greenbone-Ergebnis – nur Felder, die der Report enthält."""
    host: str
    port: str = ""                  # z. B. "443/tcp"; "" bei general/*
    hostname: str = ""
    nvt_oid: str = ""
    name: str = ""
    family: str = ""
    cves: list = field(default_factory=list)
    cvss: Optional[float] = None
    threat: str = ""                # High/Medium/Low/Log (Original aus Report)
    severity: str = "info"          # critical/high/medium/low/info (abgeleitet)
    qod: Optional[int] = None
    qod_type: str = ""
    summary: str = ""
    insight: str = ""
    solution: str = ""
    solution_type: str = ""
    description: str = ""
    result_id: str = ""

    @property
    def asset(self) -> str:
        p = self.port.split("/")[0] if self.port else ""
        return f"{self.host}:{p}" if p.isdigit() else self.host

    @property
    def dedup(self) -> str:
        ident = self.nvt_oid or self.name
        return f"{self.host}|{self.port}|{ident}"


@dataclass
class ParsedReport:
    results: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    fmt: str = ""
    log_level_skipped: int = 0
    duplicates_skipped: int = 0
    warnings: list = field(default_factory=list)

    def counts(self) -> dict:
        c = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for r in self.results:
            c[r.severity] = c.get(r.severity, 0) + 1
        return c

    def summary(self) -> dict:
        return {"format": self.fmt, "result_count": len(self.results),
                "severity": self.counts(), "hosts": len({r.host for r in self.results}),
                "log_level_skipped": self.log_level_skipped,
                "duplicates_skipped": self.duplicates_skipped,
                "warnings": list(self.warnings), **self.meta}


# ===========================================================================
# Hilfsfunktionen
# ===========================================================================
_REDACT = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)\b(\s*[:=]\s*)(\S+)")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


def _clip(text: str, n: int = 500) -> str:
    """Kürzt + maskiert offensichtliche Zugangsdaten in Scanner-Ausgaben."""
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    t = _REDACT.sub(r"\1\2***", t)
    t = _BEARER.sub(r"\1 ***", t)
    return t if len(t) <= n else t[: n - 1] + "…"


def _to_float(v) -> Optional[float]:
    try:
        if v is None or str(v).strip() == "":
            return None
        f = float(str(v).strip().replace(",", "."))
        return f if 0.0 <= f <= 10.0 else None
    except (TypeError, ValueError):
        return None


def _to_int(v) -> Optional[int]:
    try:
        return int(float(str(v).strip()))
    except (TypeError, ValueError):
        return None


def _clean_cves(vals: Iterable) -> list:
    out: list = []
    for v in vals:
        for part in re.split(r"[,\s;]+", str(v or "")):
            part = part.strip().upper()
            if _CVE_RE.match(part) and part not in out:
                out.append(part)
    return out


def severity_label(cvss: Optional[float], threat: str = "") -> str:
    """CVSS → critical/high/medium/low/info (Greenbone: ≥7 High, ≥4 Medium, >0 Low)."""
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0.0:
            return "low"
        return "info"
    t = (threat or "").strip().lower()
    return {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low"}.get(t, "info")


def _norm_port(p: str) -> str:
    p = (p or "").strip()
    if not p or p.lower().startswith("general"):
        return ""
    m = re.match(r"^(?:(.*?)\s*\()?(\d{1,5})/(tcp|udp)\)?$", p, re.I)
    if m:
        return f"{m.group(2)}/{m.group(3).lower()}"
    return p if re.match(r"^\d{1,5}(/\w+)?$", p) else ""


def _parse_tags(text: str) -> dict:
    out: dict = {}
    for part in (text or "").split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ===========================================================================
# Pfade / Import-Verzeichnis
# ===========================================================================
def drop_dir(create: bool = False) -> Path:
    d = Path(_config.DATA_DIR) / "greenbone"
    if create:
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except OSError:
            pass
    return d


def _allowed_roots() -> list:
    roots = [drop_dir()]
    for extra in (os.environ.get("ANTBB_GREENBONE_IMPORT_DIRS") or "").split(os.pathsep):
        if extra.strip():
            roots.append(Path(extra.strip()))
    return roots


def resolve_report_path(path: str) -> Path:
    """Löst einen Report-Pfad auf – NUR innerhalb von data/greenbone/ (bzw.
    `ANTBB_GREENBONE_IMPORT_DIRS`). Relative Namen gelten relativ zu data/greenbone/.
    Verhindert, dass die Import-API beliebige Server-Dateien liest."""
    if not path or not str(path).strip():
        raise GvmError("Kein Report-Pfad angegeben.")
    p = Path(str(path).strip())
    cand = p if p.is_absolute() else drop_dir() / p
    try:
        real = cand.resolve(strict=True)
    except (OSError, RuntimeError):
        raise GvmError(f"Report-Datei nicht gefunden: {p.name}")
    if not any(_is_within(real, r) for r in _allowed_roots()):
        raise GvmError("Pfad liegt außerhalb von data/greenbone/ – Import verweigert.")
    if not real.is_file():
        raise GvmError("Pfad ist keine Datei.")
    if real.suffix.lower() not in IMPORT_SUFFIXES:
        raise GvmError("Nur .xml, .json oder .csv Reports werden importiert.")
    return real


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def latest_report_path() -> Optional[Path]:
    d = drop_dir()
    try:
        files = [f for f in d.iterdir()
                 if f.is_file() and f.suffix.lower() in IMPORT_SUFFIXES]
    except OSError:
        return None
    return max(files, key=lambda f: f.stat().st_mtime) if files else None


def save_upload(filename: str, data: bytes) -> Path:
    """Legt einen hochgeladenen Report in data/greenbone/ ab (bereinigter Name)."""
    if len(data) > MAX_IMPORT_BYTES:
        raise GvmError("Report zu groß (max. 50 MB).")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename or "report.xml").name)[:80] or "report.xml"
    if Path(name).suffix.lower() not in IMPORT_SUFFIXES:
        raise GvmError("Nur .xml, .json oder .csv Reports werden angenommen.")
    d = drop_dir(create=True)
    dest = d / f"{int(time.time())}-{name}"
    dest.write_bytes(data)
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    return dest


# ===========================================================================
# Parser
# ===========================================================================
def parse_report_file(path) -> ParsedReport:
    """Parst eine Report-Datei (Format wird am Inhalt erkannt). Pfad ungeprüft –
    für Nutzereingaben vorher `resolve_report_path()` verwenden."""
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_IMPORT_BYTES:
        raise GvmError("Report zu groß (max. 50 MB).")
    raw = p.read_bytes()
    rep = parse_report(raw)
    rep.meta.setdefault("source_file", p.name)
    return rep


def parse_report(data) -> ParsedReport:
    """Parst Greenbone-XML / -CSV / -JSON (bytes oder str)."""
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        text = data.decode("utf-8", "replace")
    else:
        text = str(data)
    head = text.lstrip()[:1]
    if head == "<":
        return parse_xml(text)
    if head in ("{", "["):
        return parse_json(text)
    if "," in text.split("\n", 1)[0] and re.search(r"(?i)nvt oid|nvt name|\bcvss\b", text.split("\n", 1)[0]):
        return parse_csv(text)
    raise GvmError("Unbekanntes Report-Format (erwartet Greenbone-XML, -CSV oder -JSON).")


def _finish(rep: ParsedReport, raw: Iterable[GvmResult], include_log: bool) -> ParsedReport:
    seen: set = set()
    for r in raw:
        if not r.host:
            continue
        if r.severity == "info" and not include_log:
            rep.log_level_skipped += 1
            continue
        if r.dedup in seen:
            rep.duplicates_skipped += 1
            continue
        seen.add(r.dedup)
        rep.results.append(r)
    return rep


def parse_xml(text: str, include_log: bool = False) -> ParsedReport:
    low = text[:4096].lower()
    if "<!doctype" in low or "<!entity" in low:
        raise GvmError("XML mit DOCTYPE/ENTITY wird aus Sicherheitsgründen abgelehnt.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise GvmError(f"Report-XML nicht lesbar: {exc}")
    rep = ParsedReport(fmt="greenbone-xml")
    rpt = next((e for e in root.iter("report") if e.get("id")), None)
    if rpt is not None:
        rep.meta["report_id"] = rpt.get("id", "")
    task_name = root.findtext(".//task/name")
    if task_name:
        rep.meta["task_name"] = task_name.strip()
    for tag in ("scan_start", "scan_end", "creation_time"):
        v = root.findtext(f".//{tag}")
        if v and v.strip():
            rep.meta[tag] = v.strip()
    nodes = [r for r in root.iter("result")
             if r.find("nvt") is not None or r.find("host") is not None]
    if not nodes:
        rep.warnings.append("Report enthält keine <result>-Einträge.")
    raw = (_xml_result(n) for n in nodes)
    return _finish(rep, raw, include_log)


def _txt(el: Optional[ET.Element], path: str) -> str:
    if el is None:
        return ""
    n = el.find(path)
    return (n.text or "").strip() if n is not None and n.text else ""


def _xml_result(n: ET.Element) -> GvmResult:
    host_el = n.find("host")
    host = ((host_el.text or "").strip().splitlines() or [""])[0].strip() if host_el is not None else ""
    nvt = n.find("nvt")
    tags = _parse_tags(_txt(nvt, "tags"))
    cves: list = []
    if nvt is not None:
        cves += [r.get("id", "") for r in nvt.iter("ref") if (r.get("type") or "").lower() == "cve"]
        cves.append(_txt(nvt, "cve"))
    cvss = _to_float(_txt(n, "severity"))
    if cvss is None:
        cvss = _to_float(_txt(nvt, "severities/severity/score")) or _to_float(_txt(nvt, "cvss_base"))
    threat = _txt(n, "threat")
    sol_el = nvt.find("solution") if nvt is not None else None
    solution = _txt(nvt, "solution") or tags.get("solution", "")
    sol_type = (sol_el.get("type") if sol_el is not None else "") or tags.get("solution_type", "")
    qod_val = _to_int(_txt(n, "qod/value"))
    return GvmResult(
        host=host, hostname=_txt(host_el, "hostname"),
        port=_norm_port(_txt(n, "port")),
        nvt_oid=(nvt.get("oid") or "") if nvt is not None else "",
        name=_txt(nvt, "name") or _txt(n, "name"), family=_txt(nvt, "family"),
        cves=_clean_cves(cves), cvss=cvss, threat=threat,
        severity=severity_label(cvss, threat), qod=qod_val,
        qod_type=_txt(n, "qod/type") or tags.get("qod_type", ""),
        summary=tags.get("summary", ""), insight=tags.get("insight", ""),
        solution=solution, solution_type=sol_type,
        description=_txt(n, "description"), result_id=n.get("id", ""))


def parse_csv(text: str, include_log: bool = False) -> ParsedReport:
    rep = ParsedReport(fmt="greenbone-csv")
    reader = csv.DictReader(io.StringIO(text))
    rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()} for row in reader]

    def g(row, *keys):
        for k in keys:
            if row.get(k):
                return row[k]
        return ""

    out = []
    for row in rows:
        cvss = _to_float(g(row, "cvss"))
        sev_col = g(row, "severity")
        if cvss is None:
            cvss = _to_float(sev_col)
        threat = sev_col if _to_float(sev_col) is None else ""
        out.append(GvmResult(
            host=g(row, "ip", "host"), hostname=g(row, "hostname"),
            port=_norm_port(f"{g(row, 'port')}/{g(row, 'port protocol').lower()}"
                            if g(row, "port").isdigit() else g(row, "port")),
            nvt_oid=g(row, "nvt oid"), name=g(row, "nvt name"),
            cves=_clean_cves([g(row, "cves")]), cvss=cvss, threat=threat,
            severity=severity_label(cvss, threat), qod=_to_int(g(row, "qod")),
            summary=g(row, "summary"), insight=g(row, "vulnerability insight"),
            solution=g(row, "solution"), solution_type=g(row, "solution type"),
            description=g(row, "specific result"), result_id=g(row, "result id")))
        if g(row, "task name"):
            rep.meta.setdefault("task_name", g(row, "task name"))
    if not rows:
        rep.warnings.append("CSV enthält keine Datenzeilen.")
    return _finish(rep, out, include_log)


def _find_json_results(obj, depth: int = 0):
    if depth > 6:
        return None
    if isinstance(obj, list):
        return obj if obj and all(isinstance(x, dict) for x in obj) else None
    if isinstance(obj, dict):
        for key in ("results", "result"):
            if key in obj:
                v = obj[key]
                if isinstance(v, dict) and "result" in v:
                    v = v["result"]
                if isinstance(v, dict):
                    v = [v]
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
        for v in obj.values():
            if isinstance(v, (dict, list)):
                found = _find_json_results(v, depth + 1)
                if found is not None:
                    return found
    return None


def _jtext(v) -> str:
    if isinstance(v, dict):
        v = v.get("text") or v.get("#text") or v.get("ip") or v.get("value") or v.get("name") or ""
    return str(v).strip() if v is not None else ""


def parse_json(text: str, include_log: bool = False) -> ParsedReport:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GvmError(f"Report-JSON nicht lesbar: {exc}")
    rep = ParsedReport(fmt="greenbone-json")
    items = _find_json_results(obj)
    if items is None:
        raise GvmError("JSON enthält keine Ergebnisliste (erwartet 'results' bzw. 'result').")
    if isinstance(obj, dict):
        inner = obj.get("report") if isinstance(obj.get("report"), dict) else {}
        rid = obj.get("report_id") or inner.get("id") or inner.get("@id")
        if rid:
            rep.meta["report_id"] = str(rid)
    out = []
    for d in items:
        nvt = d.get("nvt") if isinstance(d.get("nvt"), dict) else {}
        refs = nvt.get("refs") or nvt.get("references") or {}
        ref_list = refs.get("ref") if isinstance(refs, dict) else refs
        if isinstance(ref_list, dict):
            ref_list = [ref_list]
        cves = [r.get("id", "") for r in (ref_list or [])
                if isinstance(r, dict) and str(r.get("type", "")).lower() == "cve"]
        for k in ("cves", "cve"):
            for src in (nvt.get(k), d.get(k)):
                if isinstance(src, list):
                    cves += [str(x) for x in src]
                elif src:
                    cves.append(str(src))
        sev_raw = d.get("severity")
        cvss = _to_float(sev_raw)                      # numerisch: CVSS-Score
        for v in (d.get("cvss"), nvt.get("cvss_base"), nvt.get("cvss")):
            if cvss is None:
                cvss = _to_float(v)
        threat = _jtext(d.get("threat"))
        if not threat and isinstance(sev_raw, str) and _to_float(sev_raw) is None:
            threat = sev_raw.strip()                   # textuell: High/Medium/Low/Log
        qod = d.get("qod")
        qod_val = _to_int(qod.get("value")) if isinstance(qod, dict) else _to_int(qod)
        host_raw = d.get("host", d.get("ip"))
        sol = nvt.get("solution")
        sol_text = _jtext(sol.get("text") or sol.get("#text")) if isinstance(sol, dict) else _jtext(sol or d.get("solution"))
        sol_type = (_jtext(sol.get("type") or sol.get("@type")) if isinstance(sol, dict) else "") or _jtext(d.get("solution_type"))
        out.append(GvmResult(
            host=_jtext(host_raw), hostname=_jtext(d.get("hostname") or (host_raw.get("hostname") if isinstance(host_raw, dict) else "")),
            port=_norm_port(_jtext(d.get("port"))),
            nvt_oid=_jtext(nvt.get("oid") or nvt.get("@oid") or d.get("nvt_oid") or d.get("oid")),
            name=_jtext(nvt.get("name") or d.get("name")), family=_jtext(nvt.get("family")),
            cves=_clean_cves(cves), cvss=cvss, threat=_jtext(threat),
            severity=severity_label(cvss, _jtext(threat)), qod=qod_val,
            qod_type=_jtext(qod.get("type")) if isinstance(qod, dict) else "",
            summary=_jtext(d.get("summary")), solution=sol_text, solution_type=sol_type,
            description=_jtext(d.get("description")), result_id=_jtext(d.get("id"))))
    return _finish(rep, out, include_log)


# ===========================================================================
# Mapping → Findings / Härtungs-Hinweise
# ===========================================================================
def to_findings(rep: ParsedReport, agent: str = AGENT, source_label: str = "") -> list:
    """Wandelt Report-Ergebnisse in AgentFindings um. Status immer REFERENZ
    (Fremd-Scanner, kein eigener Request/Response-Nachweis → Proof-Gate)."""
    from .agents.base import AgentFinding, STATUS_REFERENCE
    out = []
    for r in rep.results:
        ev = {"source": "greenbone", "nvt_oid": r.nvt_oid, "cves": r.cves,
              "cvss": r.cvss, "threat": r.threat, "qod": r.qod, "qod_type": r.qod_type,
              "port": r.port, "hostname": r.hostname, "family": r.family,
              "solution_type": r.solution_type, "solution": _clip(r.solution, 600),
              "summary": _clip(r.summary, 400), "result_id": r.result_id,
              "report_id": rep.meta.get("report_id", ""),
              "task_name": rep.meta.get("task_name", ""),
              "report_file": source_label or rep.meta.get("source_file", "")}
        if r.qod is not None and r.qod < 70:
            ev["low_confidence"] = True
        desc = _clip(r.summary or r.description or r.insight or "Siehe Greenbone-Report.", 500)
        if r.solution:
            desc += f" · Lösung laut Greenbone ({r.solution_type or 'k. A.'}): {_clip(r.solution, 240)}"
        cve_part = f" [{', '.join(r.cves[:3])}]" if r.cves else ""
        out.append(AgentFinding(
            agent=agent, title=f"{r.name or r.nvt_oid or 'Greenbone-Ergebnis'}{cve_part} – {r.asset}",
            category=CATEGORY_VULN, severity=r.severity, asset=r.asset,
            description=desc, evidence=ev, status=STATUS_REFERENCE,
            dedup_key=f"blue-greenbone:{r.dedup}"))
    return out


def summary_finding(rep: ParsedReport, source: str, agent: str = AGENT):
    from .agents.base import AgentFinding, STATUS_REFERENCE
    s = rep.summary()
    sev = s["severity"]
    return AgentFinding(
        agent=agent,
        title=(f"Greenbone-Import: {s['result_count']} Ergebnis(se) auf {s['hosts']} Host(s) "
               f"(crit {sev['critical']}/high {sev['high']}/med {sev['medium']}/low {sev['low']})"),
        category=CATEGORY_SUMMARY, severity="info", asset="greenbone-report",
        description=("Importierter Fremd-Scanner-Report (Greenbone/OpenVAS). Werte stammen "
                     "unverändert aus der Datei; Log-Level-Einträge werden nicht als Befund geführt."),
        evidence={"source": "greenbone", "report_file": source, **s},
        status=STATUS_REFERENCE, dedup_key=f"blue-greenbone-summary:{source}")


_TLS_RE = re.compile(r"\b(ssl|tls|cipher|certificate|x\.?509|heartbleed|poodle)\b", re.I)
_PATCH_RE = re.compile(r"\b(update|upgrade|patch|security advisory|kb\d+|usn-|dsa-|rhsa-|glsa-|cve-)", re.I)
_HARDEN_RE = re.compile(r"\b(ssh|telnet|ftp|snmp|smb|rdp|vnc|default (?:credential|account|community)|"
                        r"weak|anonymous|cleartext|unencrypted|misconfig)", re.I)
_FW_RE = re.compile(r"\b(firewall|filter|restrict access|limit access|expos|block)", re.I)


def _route(r: GvmResult) -> tuple:
    blob = f"{r.name} {r.family} {r.solution}"
    if _TLS_RE.search(r.name) or "ssl" in r.family.lower() or "tls" in r.family.lower():
        return "blue-tlsposture", "TLS-/Zertifikats-Konfiguration prüfen und härten"
    if r.solution_type.lower() == "vendorfix" or "local security checks" in r.family.lower() \
            or _PATCH_RE.search(r.solution):
        return "blue-patchmgmt", "Herstellerupdate/Patch einspielen (Patch-Fenster, Neustartbedarf)"
    if _HARDEN_RE.search(blob):
        return "blue-hardening", "Dienst-/Konfigurationshärtung gemäß Lösungstext"
    if r.solution_type.lower() in ("workaround", "mitigation") and _FW_RE.search(blob):
        return "blue-fwaudit", "Zugriff per Firewall einschränken (Mitigation)"
    return "blue-vulnticket", "als Ticket führen und Lösung manuell bewerten"


def remediation_hints(results: Iterable[GvmResult], min_severity: str = "high",
                      limit: int = 50) -> list:
    """Gruppiert High/Critical-Ergebnisse je NVT zu Härtungs-/Ticket-Hinweisen.

    Keine erfundenen Fixes: Lösungstext/-typ stammen aus dem Report; fehlt eine
    Lösung, steht dort ehrlich „keine Lösung im Report"."""
    floor = SEV_RANK.get(min_severity, 3)
    groups: dict = {}
    for r in results:
        if SEV_RANK.get(r.severity, 0) < floor:
            continue
        groups.setdefault(r.nvt_oid or r.name, []).append(r)
    hints = []
    for key, rs in groups.items():
        top = max(rs, key=lambda x: (SEV_RANK.get(x.severity, 0), x.cvss or 0))
        soldier, how = _route(top)
        tail = (top.nvt_oid.rsplit(".", 1)[-1] if top.nvt_oid
                else hashlib.sha1(top.name.encode()).hexdigest()[:8])
        hosts = sorted({r.asset for r in rs})
        fix_known = top.solution_type.lower() in ("vendorfix", "workaround", "mitigation") and bool(top.solution)
        hints.append({
            "ticket_id": f"GB-{tail}", "title": top.name or top.nvt_oid,
            "severity": top.severity, "cvss": top.cvss, "nvt_oid": top.nvt_oid,
            "cves": sorted({c for r in rs for c in r.cves})[:10],
            "hosts": hosts[:20], "host_count": len(hosts),
            "solution_type": top.solution_type,
            "solution": _clip(top.solution, 500) if top.solution else "keine Lösung im Report",
            "fix_known": fix_known, "route_to": soldier, "route_note": how,
            "close_criteria": ("Re-Scan (Greenbone) zeigt diese NVT auf den genannten Hosts nicht mehr; "
                               "Vorher-/Nachher-Report als Evidence (Proof-Gate)."),
        })
    hints.sort(key=lambda h: (-SEV_RANK.get(h["severity"], 0), -(h["cvss"] or 0), h["ticket_id"]))
    return hints[:limit]


def hint_findings(hints: list, agent: str = AGENT) -> list:
    from .agents.base import AgentFinding, STATUS_REFERENCE
    out = []
    for h in hints:
        out.append(AgentFinding(
            agent=agent,
            title=f"Ticket {h['ticket_id']}: {h['title']} → {h['route_to']}",
            category=CATEGORY_REMEDIATION, severity="info", asset="process",
            description=(f"{h['route_note']}. Lösung laut Greenbone ({h['solution_type'] or 'k. A.'}): "
                         f"{h['solution']} · Betroffen: {h['host_count']} Host(s). "
                         f"Close: {h['close_criteria']}"),
            evidence={**h, "source": "greenbone", "auto_fix": False},
            status=STATUS_REFERENCE, dedup_key=f"blue-greenbone-ticket:{h['ticket_id']}"))
    return out


# ===========================================================================
# Erkennung / Status
# ===========================================================================
def _creds() -> tuple:
    return os.environ.get("GVM_USERNAME", ""), os.environ.get("GVM_PASSWORD", "")


def find_socket() -> str:
    cands = []
    env = (os.environ.get("GVM_SOCKET") or "").strip()
    if env:
        cands.append(env)
    cands += list(SOCKET_CANDIDATES)
    for c in cands:
        try:
            if stat.S_ISSOCK(os.stat(c).st_mode):
                return c
        except OSError:
            continue
    return ""


def _python_gvm_version() -> str:
    if importlib.util.find_spec("gvm") is None:
        return ""
    try:
        from gvm import __version__ as v  # type: ignore
        return str(getattr(v, "__version__", v))
    except Exception:
        return "unbekannt"


def _which(name: str) -> str:
    return shutil.which(name) or ""


def status(probe: bool = True, timeout: float = 8.0) -> dict:
    """Ehrlicher Greenbone-Status. Enthält NIE Zugangsdaten (nur `credentials_configured`)."""
    cli, gvmd = _which("gvm-cli"), _which("gvmd")
    pygvm = _python_gvm_version()
    sock = find_socket()
    user, pw = _creds()
    st = {
        "available": False, "import_available": True,
        "gvm_cli": cli, "gvmd": gvmd,
        "python_gvm": bool(pygvm), "python_gvm_version": pygvm,
        "socket": sock, "credentials_configured": bool(user and pw),
        "transport": "python-gvm" if pygvm else ("gvm-cli" if cli else ""),
        "reachable": False, "can_scan": False,
        "version": "", "feed_ok": None, "feed_note": "unbekannt",
        "error": "", "message": "",
    }
    reasons = []
    if not sock:
        reasons.append("kein gvmd-Socket gefunden (GVM_SOCKET bzw. /run/gvmd/gvmd.sock)")
    if not (pygvm or cli):
        reasons.append("weder python-gvm noch gvm-cli installiert")
    if reasons:
        st["error"] = "Greenbone nicht verfügbar: " + "; ".join(reasons)
        st["message"] = st["error"] + ". Report-Import aus Datei bleibt möglich."
        return st
    if not probe:
        st["available"] = True
        st["message"] = "gvmd-Socket und Client vorhanden (nicht sondiert)."
        return st
    try:
        t = _make_transport(sock, timeout=timeout)
        ver = t.send("<get_version/>")
        st["version"] = (ver.findtext("version") or "").strip()
        st["reachable"] = True
        st["available"] = True
        st["can_scan"] = bool(user and pw)
        if st["can_scan"]:
            try:
                st["feed_ok"], st["feed_note"] = _feed_state(t)
            except GvmError as exc:
                st["feed_note"] = f"Feed-Status nicht abrufbar: {_short(exc)}"
        else:
            st["feed_note"] = "unbekannt (GVM_USERNAME/GVM_PASSWORD nicht gesetzt)"
        st["message"] = (f"Greenbone erreichbar (GMP {st['version'] or '?'}); "
                         + ("Scans möglich (mit Oversight)." if st["can_scan"]
                            else "ohne Zugangsdaten nur Import/Status."))
    except GvmError as exc:
        st["error"] = f"Greenbone nicht verfügbar: gvmd nicht erreichbar ({_short(exc)})"
        st["message"] = st["error"] + ". Report-Import aus Datei bleibt möglich."
    return st


def _short(exc: Exception) -> str:
    return re.sub(r"\s+", " ", str(exc))[:200]


def _feed_state(t) -> tuple:
    root = t.send("<get_feeds/>")
    for feed in root.iter("feed"):
        if (feed.findtext("type") or "").strip().upper() == "NVT":
            ver = (feed.findtext("version") or "").strip()
            try:
                ts = time.mktime(time.strptime(ver[:12], "%Y%m%d%H%M"))
            except ValueError:
                return None, f"NVT-Feed {ver or '?'} (Alter unbekannt)"
            age = (time.time() - ts) / 86400
            return age <= 14, f"NVT-Feed {ver} ({age:.0f} Tage alt)"
    return None, "kein NVT-Feed gemeldet"


# ===========================================================================
# Transport (python-gvm bevorzugt, gvm-cli als Fallback)
# ===========================================================================
class _Transport:
    def __init__(self, socket_path: str, timeout: float = 60.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def send(self, xml: str) -> ET.Element:
        user, pw = _creds()
        if _python_gvm_version():
            raw = self._send_pygvm(xml, user, pw)
        else:
            raw = self._send_cli(xml, user, pw)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise GvmError("Antwort von gvmd nicht lesbar.")
        code = root.get("status", "")
        if code and not code.startswith("2"):
            raise GvmError(f"gvmd lehnte ab ({code}): {root.get('status_text', '')}")
        return root

    def _send_pygvm(self, xml: str, user: str, pw: str) -> str:
        try:
            from gvm.connections import UnixSocketConnection  # type: ignore
            from gvm.protocols.gmp import Gmp  # type: ignore
        except Exception as exc:
            raise GvmUnavailable(f"python-gvm nicht nutzbar: {type(exc).__name__}")
        try:
            conn = UnixSocketConnection(path=self.socket_path, timeout=self.timeout)
            with Gmp(connection=conn) as gmp:
                if user and pw and not xml.lstrip().startswith("<get_version"):
                    gmp.authenticate(user, pw)
                return str(gmp.send_command(xml))
        except GvmError:
            raise
        except Exception as exc:
            raise GvmUnavailable(f"{type(exc).__name__}: {_short(exc)}")

    def _send_cli(self, xml: str, user: str, pw: str) -> str:
        cli = _which("gvm-cli")
        if not cli:
            raise GvmUnavailable("gvm-cli nicht installiert")
        cfg_dir = tempfile.mkdtemp(prefix="antbb-gvm-")
        try:
            os.chmod(cfg_dir, 0o700)
            argv = [cli, "--timeout", str(int(self.timeout))]
            if user and pw and not xml.lstrip().startswith("<get_version"):
                cfg = os.path.join(cfg_dir, "gvm-tools.conf")
                fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(f"[gmp]\nusername={user}\npassword={pw}\n")
                argv += ["--config", cfg]
            argv += ["socket", "--socketpath", self.socket_path, "--xml", xml]
            try:
                proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=self.timeout + 10, check=False)
            except subprocess.TimeoutExpired:
                raise GvmUnavailable(f"gvm-cli Timeout nach {int(self.timeout)}s")
            except OSError as exc:
                raise GvmUnavailable(f"gvm-cli nicht ausführbar: {exc.__class__.__name__}")
            out = proc.stdout.decode("utf-8", "replace")
            if proc.returncode != 0 or not out.strip():
                err = proc.stderr.decode("utf-8", "replace")
                err = err.replace(pw, "***") if pw else err
                raise GvmUnavailable(f"gvm-cli Fehler (rc={proc.returncode}): {_short(Exception(err))}")
            return out
        finally:
            shutil.rmtree(cfg_dir, ignore_errors=True)


def _make_transport(socket_path: str, timeout: float = 60.0):
    """Factory (in Tests ersetzbar)."""
    return _Transport(socket_path, timeout=timeout)


# ===========================================================================
# Aktiv: Scan gegen ein einzelnes In-Scope-Ziel
# ===========================================================================
_SCAN_LOCK = threading.Lock()
_LAST_SCAN_START = 0.0


def validate_scan_host(host: str) -> str:
    h = (host or "").strip()
    if not h or any(c in h for c in " ,;/*\t\n") or not _HOST_RE.match(h):
        raise GvmError("Scan-Ziel muss ein einzelner Host/eine einzelne IP sein "
                       "(keine Netze, Bereiche oder Listen).")
    return h


def _lookup_id(t, kind: str, name: str) -> str:
    flt = 'name="%s" rows=5' % name
    root = t.send(f"<get_{kind} filter={_xattr(flt)}/>")
    tag = {"configs": "config", "port_lists": "port_list", "scanners": "scanner"}[kind]
    for el in root.findall(tag):
        if (el.findtext("name") or "").strip() == name and el.get("id"):
            return el.get("id")
    raise GvmError(f"In Greenbone nicht gefunden ({kind}: '{name}') – Feed/Setup prüfen.")


def start_scan(host: str, *, scope_check: Callable[[str], bool], acknowledged: bool,
               scan_config: str = DEFAULT_SCAN_CONFIG, log: Optional[Callable[[str], None]] = None,
               socket_path: str = "", timeout: float = 60.0) -> dict:
    """Startet (nicht-blockierend) einen Scan gegen EIN In-Scope-Ziel.

    Gates in dieser Reihenfolge: Oversight-Freigabe → Host-Validierung → Scope
    (default-deny) → Config-Allowlist → GVM erreichbar + Zugangsdaten → genau ein
    Scan gleichzeitig + Mindestabstand. Gibt IMMER ein dict zurück (ok/error)."""
    global _LAST_SCAN_START
    say = log or (lambda m: None)
    if acknowledged is not True:
        return {"ok": False, "reason": "oversight",
                "error": "BLOCKIERT (default-deny): Human-Oversight-Freigabe fehlt – kein Scan gestartet."}
    try:
        h = validate_scan_host(host)
    except GvmError as exc:
        return {"ok": False, "reason": "target", "error": str(exc)}
    try:
        in_scope = bool(scope_check(h))
    except Exception:
        in_scope = False
    if not in_scope:
        say(f"[blue-greenbone] ⛔ Scan-Ziel '{h}' out-of-scope (default-deny) – nicht gestartet.")
        return {"ok": False, "reason": "scope",
                "error": f"Ziel '{h}' ist nicht in-scope (default-deny) – kein Scan gestartet."}
    if scan_config not in SAFE_SCAN_CONFIGS:
        return {"ok": False, "reason": "config",
                "error": f"Scan-Config '{scan_config}' nicht erlaubt (erlaubt: {', '.join(SAFE_SCAN_CONFIGS)})."}
    user, pw = _creds()
    sock = socket_path or find_socket()
    if not sock or not (_python_gvm_version() or _which("gvm-cli")):
        st = status(probe=False)
        return {"ok": False, "reason": "unavailable",
                "error": st["error"] or "Greenbone nicht verfügbar."}
    if not (user and pw):
        return {"ok": False, "reason": "credentials",
                "error": "Greenbone-Zugangsdaten fehlen (Umgebung GVM_USERNAME/GVM_PASSWORD) – kein Scan gestartet."}
    if not _SCAN_LOCK.acquire(blocking=False):
        return {"ok": False, "reason": "busy", "error": "Ein Scan-Start läuft bereits."}
    try:
        wait = MIN_SCAN_INTERVAL - (time.monotonic() - _LAST_SCAN_START)
        if _LAST_SCAN_START and wait > 0:
            return {"ok": False, "reason": "rate_limit",
                    "error": f"Rate-Limit: nächster Scan-Start frühestens in {int(wait)}s."}
        t = _make_transport(sock, timeout=timeout)
        try:
            tasks = t.send(f"<get_tasks filter={_xattr('name~' + SCAN_TASK_PREFIX + ' rows=50')}/>")
            running = [x for x in tasks.findall("task")
                       if (x.findtext("status") or "") in ACTIVE_STATES]
            if running:
                return {"ok": False, "reason": "busy",
                        "error": "Es läuft bereits ein antbb-Scan in Greenbone – kein paralleler Start."}
            cfg_id = _lookup_id(t, "configs", scan_config)
            pl_id = _lookup_id(t, "port_lists", DEFAULT_PORT_LIST)
            sc_id = _lookup_id(t, "scanners", "OpenVAS Default")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            tgt = t.send(
                f"<create_target><name>{_xesc(SCAN_TASK_PREFIX + h + '-' + stamp)}</name>"
                f"<hosts>{_xesc(h)}</hosts><port_list id={_xattr(pl_id)}/>"
                f"<alive_test>Consider Alive</alive_test></create_target>")
            tgt_id = tgt.get("id", "")
            task = t.send(
                f"<create_task><name>{_xesc(SCAN_TASK_PREFIX + h + '-' + stamp)}</name>"
                f"<config id={_xattr(cfg_id)}/><target id={_xattr(tgt_id)}/>"
                f"<scanner id={_xattr(sc_id)}/></create_task>")
            task_id = task.get("id", "")
            started = t.send(f"<start_task task_id={_xattr(task_id)}/>")
            _LAST_SCAN_START = time.monotonic()
        except GvmError as exc:
            return {"ok": False, "reason": "gvm", "error": f"Greenbone: {_short(exc)}"}
        say(f"[blue-greenbone] ▶ Scan gestartet gegen {h} (Config '{scan_config}', Task {task_id}).")
        return {"ok": True, "host": h, "task_id": task_id, "target_id": tgt_id,
                "report_id": (started.findtext("report_id") or "").strip(),
                "scan_config": scan_config, "state": "Requested"}
    finally:
        _SCAN_LOCK.release()


def scan_status(task_id: str, socket_path: str = "", timeout: float = 30.0) -> dict:
    """Rein lesend: Status eines (antbb-)Tasks."""
    tid = _check_id(task_id)
    sock = socket_path or find_socket()
    if not sock:
        return {"ok": False, "error": status(probe=False)["error"] or "Greenbone nicht verfügbar."}
    try:
        root = _make_transport(sock, timeout=timeout).send(f"<get_tasks task_id={_xattr(tid)}/>")
    except GvmError as exc:
        return {"ok": False, "error": f"Greenbone: {_short(exc)}"}
    task = root.find("task")
    if task is None:
        return {"ok": False, "error": "Task nicht gefunden."}
    last = task.find("last_report/report")
    cur = task.find("current_report/report")
    return {"ok": True, "task_id": tid, "state": (task.findtext("status") or "").strip(),
            "progress": _to_int(task.findtext("progress")),
            "report_id": ((last if last is not None else cur).get("id", "") if (last is not None or cur is not None) else ""),
            "done": (task.findtext("status") or "").strip() in TERMINAL_STATES}


def _check_id(v: str) -> str:
    v = (v or "").strip()
    if not re.match(r"^[0-9a-fA-F-]{8,64}$", v):
        raise GvmError("Ungültige Task-/Report-ID.")
    return v


def fetch_report(report_id: str, socket_path: str = "", timeout: float = 300.0) -> Path:
    """Holt einen Report (XML) und legt ihn unter data/greenbone/ ab."""
    rid = _check_id(report_id)
    sock = socket_path or find_socket()
    if not sock:
        raise GvmUnavailable(status(probe=False)["error"] or "Greenbone nicht verfügbar.")
    root = _make_transport(sock, timeout=timeout).send(
        f"<get_reports report_id={_xattr(rid)} details=\"1\" ignore_pagination=\"1\" "
        f"filter=\"apply_overrides=0 min_qod=30 levels=chml rows=-1\"/>")
    d = drop_dir(create=True)
    dest = d / f"gvm-{rid}.xml"
    dest.write_bytes(ET.tostring(root, encoding="utf-8"))
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    return dest


def wait_for_scan(task_id: str, wait_seconds: float = 0, interval: float = 10.0) -> dict:
    """Pollt begrenzt (max. 15 min) den Scan-Status; bei Timeout bleibt der Scan laufen."""
    deadline = time.monotonic() + max(0.0, min(float(wait_seconds), MAX_WAIT_SECONDS))
    st = scan_status(task_id)
    while st.get("ok") and not st.get("done") and time.monotonic() < deadline:
        time.sleep(min(interval, max(1.0, deadline - time.monotonic())))
        st = scan_status(task_id)
    return st


# ===========================================================================
# Komfort: Import-Pipeline (Datei → Findings + Hints)
# ===========================================================================
def import_report(path: str = "", *, resolve: bool = True, min_hint_severity: str = "high",
                  scope_filter: Optional[Callable[[str], bool]] = None) -> dict:
    """Importiert einen Report (Pfad leer → neuester Drop in data/greenbone/).

    `scope_filter(host)` (optional): nur Hosts in-scope übernehmen, Rest wird
    ehrlich als `out_of_scope_skipped` gezählt."""
    if path:
        p = resolve_report_path(path) if resolve else Path(path)
    else:
        p = latest_report_path()
        if p is None:
            return {"ok": False, "empty": True,
                    "error": "Kein Greenbone-Report vorhanden (data/greenbone/ ist leer).",
                    "report_file": "", "findings": [], "hints": []}
    rep = parse_report_file(p)
    skipped = 0
    if scope_filter is not None:
        kept = []
        for r in rep.results:
            if scope_filter(r.host):
                kept.append(r)
            else:
                skipped += 1
        rep.results = kept
    findings = to_findings(rep, source_label=p.name)
    hints = remediation_hints(rep.results, min_severity=min_hint_severity)
    return {"ok": True, "empty": False, "report_file": p.name, "summary": rep.summary(),
            "out_of_scope_skipped": skipped, "report": rep, "findings": findings, "hints": hints}
