"""Statische Quellcode-Sicherheitsprüfung (read-only, find-and-prove).

Integriert die Methodik des Cloudflare *security-audit-skill*
(https://github.com/cloudflare/security-audit-skill) als wiederverwendbare,
rein lesende Engine für antbb:

  * **Coverage-led:** es wird nur über explizit übergebene, autorisierte
    Quellpfade (lokales Code-Repo) gearbeitet – nie Netzwerk, nie Tools.
  * **Candidate → Verdict:** jeder Kandidat trägt eine KONKRETE Quell-Stelle
    (Datei:Zeile + Ausschnitt). Ein Secret, das wörtlich im Quelltext steht,
    ist passiv BELEGT (`confirmed`-Äquivalent, read-only). Ein Injection-Sink
    mit variabler/untainted Eingabe bleibt „zu bestätigen" (`needs_validation`)
    – ohne Severity, exakt wie im Skill.
  * **Severity requires impact:** reine Best-Practice-Abweichungen / Defense-in-
    Depth-Lücken sind KEINE Schwachstelle, sondern Härtungshinweis (info).
  * **Non-destruktiv:** nur Dateien lesen. NICHTS wird ausgeführt, verändert,
    exfiltriert. Secrets werden IMMER maskiert (nie Klartext).

Die Engine ist bewusst pur (keine I/O-Abhängigkeit in der Kern-Logik):
``scan_source_text`` arbeitet auf einem String und ist ohne Netz/Tools testbar.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

# Proof-Gate-Labels wiederverwenden (Single Source of Truth bleibt base.py).
from .agents.base import (
    STATUS_PASSIVE, STATUS_TO_CONFIRM, STATUS_REFERENCE,
)

# ---------------------------------------------------------------------------
# Secret-Maskierung – NIE Klartext. Zeigt nur Prefix + Länge.
# ---------------------------------------------------------------------------
def mask_secret(value: str) -> str:
    v = (value or "").strip().strip("'\"")
    if not v:
        return "<leer>"
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}…{v[-2:]} (len={len(v)})"


# ---------------------------------------------------------------------------
# Detektoren. Jeder: (kind, regex, verdict-hint, builder). Pur, zeilenbasiert.
# verdict-hint: "passive" (wörtlich belegt), "needs_validation" (Sink/Hypothese),
# "hardening" (Best-Practice/Defense-in-Depth → info, keine Schwachstelle).
# ---------------------------------------------------------------------------

# Attacker-controlled Indikatoren (grobe Taint-Heuristik, bewusst konservativ):
_TAINT_HINTS = (
    "request", "req.", "params", "query", "argv", "input(", "environ",
    "getenv", "body", "form", "args", "stdin", "user", "payload", "data",
    "%s", "{", "+ ", " +", "f\"", "f'", "`${", "${",
)


def _looks_literal(arg: str) -> bool:
    """True, wenn das Argument klar eine Konstante ist (kein Taint-Hinweis)."""
    a = (arg or "").strip()
    if not a:
        return False
    # Reines, vollständig gequotetes String-Literal ODER Zahl → Konstante,
    # auch wenn der Inhalt zufällig '+'/'{' enthält (z.B. eval("1 + 1")).
    if re.match(r'^([\'"]).*\1$', a) and a.count(a[0]) == 2:
        return True
    if re.match(r'^[\d_.]+$', a):
        return True
    low = a.lower()
    if any(h in low for h in _TAINT_HINTS):
        return False
    return False


# Secret-Muster: Zuweisung eines langen Literals an einen secret-artigen Namen.
_SECRET_NAME = (r'(?i)(?:api[_-]?key|secret|token|passwd|password|private[_-]?key'
                r'|aws_secret|client_secret|minimax)')
_SECRET_ASSIGN = re.compile(
    _SECRET_NAME + r'''\s*[:=]\s*(?P<q>['"])(?P<val>[^'"]{8,})(?P=q)''')
# Bekannte Hochentropie-Token-Präfixe (AWS, GitHub, Slack, Google, private key).
_TOKEN_PATTERNS = [
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("GitHub Token", re.compile(r'\bghp_[0-9A-Za-z]{30,}\b')),
    ("Slack Token", re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b')),
    ("Google API Key", re.compile(r'\bAIza[0-9A-Za-z_\-]{30,}\b')),
    ("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
]

# Code-/Command-Injection-Sinks (Sprach-übergreifend, grob).
_SINKS = [
    ("code-injection", re.compile(r'\beval\s*\(\s*(?P<arg>[^)]*)')),
    ("code-injection", re.compile(r'\bexec\s*\(\s*(?P<arg>[^)]*)')),
    ("command-injection", re.compile(r'\bos\.system\s*\(\s*(?P<arg>[^)]*)')),
    ("command-injection", re.compile(r'\bsubprocess\.(?:call|run|Popen|check_output)\s*\((?P<arg>[^)]*shell\s*=\s*True[^)]*)')),
    ("command-injection", re.compile(r'child_process\.(?:exec|execSync)\s*\(\s*(?P<arg>[^)]*)')),
]
# SQL via String-Konkatenation / Interpolation.
_SQL = re.compile(
    r'(?i)(?:select|insert|update|delete)\b.*?(?:\+\s*\w|%\s*\(|%s|f["\']|\$\{|\|\|)')
# Unsichere Deserialisierung.
_DESER = [
    ("insecure-deserialization", re.compile(r'\bpickle\.loads?\s*\(')),
    ("insecure-deserialization", re.compile(r'\byaml\.load\s*\((?![^)]*Safe)')),
    ("insecure-deserialization", re.compile(r'\bmarshal\.loads?\s*\(')),
]
# Schwache Krypto (Härtungshinweis, keine Schwachstelle per se).
_WEAK_CRYPTO = re.compile(r'(?i)\b(?:md5|sha1)\s*\(')

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
              "dist", "build", ".mypy_cache", ".pytest_cache"}
_TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php",
             ".java", ".cs", ".c", ".cpp", ".h", ".sh", ".yml", ".yaml",
             ".json", ".env", ".cfg", ".ini", ".txt", ".tf", ".conf"}


@dataclass
class Candidate:
    kind: str
    verdict: str                 # "passive" | "needs_validation" | "hardening"
    rel_path: str
    line: int
    snippet: str
    detail: str = ""
    evidence: dict = field(default_factory=dict)


def scan_source_text(rel_path: str, text: str) -> list[Candidate]:
    """Kern-Detektion auf einem Quelltext-String. Pur, ohne I/O."""
    out: list[Candidate] = []
    lines = text.splitlines()
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            # Kommentare überspringen (reduziert False-Positives), außer Keys.
            if "BEGIN" not in line:
                pass

        # --- Secrets: benannte Zuweisung ---
        m = _SECRET_ASSIGN.search(line)
        if m:
            val = m.group("val")
            # Offensichtliche Platzhalter ignorieren (keine Scheinbefunde).
            if not re.search(r'(?i)(your_|example|xxxx|changeme|placeholder|<[^>]+>|\$\{?[a-z_]+\}?|os\.environ|getenv)', val):
                out.append(Candidate(
                    kind="hardcoded-secret", verdict="passive",
                    rel_path=rel_path, line=i, snippet=_redact_line(line),
                    detail="Secret-artiger Name mit literalem Wert im Quelltext.",
                    evidence={"masked_value": mask_secret(val)}))
        # --- Secrets: bekannte Token-Formate ---
        for label, pat in _TOKEN_PATTERNS:
            tm = pat.search(line)
            if tm:
                out.append(Candidate(
                    kind="hardcoded-secret", verdict="passive",
                    rel_path=rel_path, line=i, snippet=_redact_line(line),
                    detail=f"Erkanntes {label}-Format im Quelltext.",
                    evidence={"masked_value": mask_secret(tm.group(0)), "token_type": label}))

        # --- Injection-Sinks ---
        for kind, pat in _SINKS:
            sm = pat.search(line)
            if sm:
                arg = sm.groupdict().get("arg", "")
                if _looks_literal(arg):
                    # Konstante Eingabe → kein erreichbarer Boundary-Crossing.
                    out.append(Candidate(
                        kind=kind, verdict="hardening",
                        rel_path=rel_path, line=i, snippet=line.strip()[:200],
                        detail="Gefährlicher Sink mit konstantem Argument – "
                               "kein angreiferkontrollierter Pfad erkennbar (Härtungshinweis)."))
                else:
                    out.append(Candidate(
                        kind=kind, verdict="needs_validation",
                        rel_path=rel_path, line=i, snippet=line.strip()[:200],
                        detail="Gefährlicher Sink mit variabler/ggf. "
                               "angreiferkontrollierter Eingabe – Taint-Pfad zu bestätigen."))

        # --- SQL-Konkatenation ---
        if _SQL.search(line):
            out.append(Candidate(
                kind="sql-injection", verdict="needs_validation",
                rel_path=rel_path, line=i, snippet=line.strip()[:200],
                detail="SQL-Query per String-Konkatenation/Interpolation – "
                       "mögliche SQL-Injection, Taint-Pfad zu bestätigen."))

        # --- Unsichere Deserialisierung ---
        for kind, pat in _DESER:
            if pat.search(line):
                out.append(Candidate(
                    kind=kind, verdict="needs_validation",
                    rel_path=rel_path, line=i, snippet=line.strip()[:200],
                    detail="Unsichere Deserialisierung – RCE möglich, wenn die "
                           "Eingabe angreiferkontrolliert ist (zu bestätigen)."))

        # --- Schwache Krypto (Härtung) ---
        if _WEAK_CRYPTO.search(line) and not stripped.startswith(("#", "//")):
            out.append(Candidate(
                kind="weak-crypto", verdict="hardening",
                rel_path=rel_path, line=i, snippet=line.strip()[:200],
                detail="Schwache Hash-Funktion (md5/sha1) – Härtungshinweis "
                       "(keine Schwachstelle ohne konkreten Impact)."))
    return out


def _redact_line(line: str) -> str:
    """Zeile mit maskiertem Secret-Wert (nie Klartext ins Evidence/Log)."""
    def _r(m):
        return line[m.start():m.start(0)] if False else (
            line[:m.start("val")] + mask_secret(m.group("val")) + line[m.end("val"):])
    red = _SECRET_ASSIGN.sub(lambda m: m.group(0).replace(m.group("val"), mask_secret(m.group("val"))), line)
    for _lbl, pat in _TOKEN_PATTERNS:
        red = pat.sub(lambda m: mask_secret(m.group(0)), red)
    return red.strip()[:200]


def iter_source_files(root: str, max_files: int = 2000, max_bytes: int = 1_500_000):
    """Liefert (abs_path, rel_path) für lesbare Quelltext-Dateien. Read-only."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _TEXT_EXT and fn not in (".env",):
                continue
            ap = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(ap) > max_bytes:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(ap, root)
            yield ap, rel
            n += 1
            if n >= max_files:
                return


@dataclass
class AuditResult:
    candidates: list[Candidate]
    files_reviewed: int
    root: str


def audit_tree(root: str, max_files: int = 2000) -> AuditResult:
    """Rein lesende Begehung eines autorisierten lokalen Quellbaums."""
    cands: list[Candidate] = []
    reviewed = 0
    for ap, rel in iter_source_files(root, max_files=max_files):
        try:
            with open(ap, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        reviewed += 1
        cands.extend(scan_source_text(rel, text))
    return AuditResult(candidates=cands, files_reviewed=reviewed, root=root)


# Verdict → antbb Proof-Gate-Status + Severity (severity nur bei Impact).
def verdict_to_status(verdict: str) -> str:
    if verdict == "passive":
        return STATUS_PASSIVE          # wörtlich im Quelltext belegt (read-only)
    if verdict == "hardening":
        return STATUS_REFERENCE        # Best-Practice-Hinweis, kein eigener Impact
    return STATUS_TO_CONFIRM           # needs_validation – keine Severity


def verdict_to_severity(kind: str, verdict: str) -> str:
    if verdict == "hardening":
        return "info"
    if verdict == "needs_validation":
        # needs_validation trägt KEINE Severity (Skill-Prinzip) → neutral "info".
        return "info"
    # passive/confirmed: wörtlich belegtes Secret ist real exponiert.
    if kind == "hardcoded-secret":
        return "high"
    return "medium"
