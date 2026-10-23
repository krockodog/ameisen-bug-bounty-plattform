"""Supply-Chain / Dependency-Audit – rein lesend, OSV optional.

Liest Manifest-Dateien (requirements.txt, pyproject.toml, package-lock.json
Ausschnitt) und gleicht Pakete gegen OSV ab (wenn online). Nichts erfinden.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger("antbb.supplychain")


@dataclass
class Dep:
    name: str
    version: str = ""
    ecosystem: str = "PyPI"
    source: str = ""


@dataclass
class DepFinding:
    check_id: str
    title: str
    status: str
    severity: str
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


_REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.+]*)")


def parse_requirements(path: Path) -> list[Dep]:
    deps: list[Dep] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        deps.append(Dep(name=m.group(1), version=m.group(2) or "",
                        ecosystem="PyPI", source=str(path)))
    return deps


def parse_package_lock(path: Path, limit: int = 80) -> list[Dep]:
    deps: list[Dep] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    packages = data.get("packages") or data.get("dependencies") or {}
    if isinstance(packages, dict):
        for name, meta in list(packages.items())[:limit]:
            if not name or name == "":
                continue
            # npm lock v2/v3: keys like "node_modules/foo"
            clean = name.split("node_modules/")[-1] if "node_modules/" in name else name
            if not clean or clean.startswith("node_modules"):
                continue
            ver = ""
            if isinstance(meta, dict):
                ver = str(meta.get("version") or "")
            deps.append(Dep(name=clean, version=ver, ecosystem="npm",
                            source=str(path)))
    return deps


def discover_manifests(root: Optional[Path] = None) -> list[Path]:
    root = root or Path.cwd()
    out: list[Path] = []
    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml",
                 "package-lock.json", "package.json"):
        p = root / name
        if p.is_file():
            out.append(p)
    # one level of common subdirs
    for sub in ("antbb", "backend", "frontend", "app"):
        d = root / sub
        if not d.is_dir():
            continue
        for name in ("requirements.txt", "package-lock.json"):
            p = d / name
            if p.is_file():
                out.append(p)
    return out


def collect_deps(root: Optional[Path] = None) -> list[Dep]:
    deps: list[Dep] = []
    for p in discover_manifests(root):
        if p.name.startswith("requirements"):
            deps.extend(parse_requirements(p))
        elif p.name == "package-lock.json":
            deps.extend(parse_package_lock(p))
        elif p.name == "pyproject.toml":
            # minimal: look for name==version patterns
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in re.finditer(r'([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+]+)', text):
                deps.append(Dep(name=m.group(1), version=m.group(2),
                                ecosystem="PyPI", source=str(p)))
    # dedup
    seen = set()
    uniq = []
    for d in deps:
        k = (d.ecosystem, d.name.lower(), d.version)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(d)
    return uniq


def audit(root: Optional[Path] = None, online: bool = True,
          max_osv: int = 40) -> list[DepFinding]:
    """Dependency-Audit. Ohne Manifeste → info-Finding (honest)."""
    from . import softwarescan as _sw
    findings: list[DepFinding] = []
    deps = collect_deps(root)
    manifests = discover_manifests(root)
    findings.append(DepFinding(
        check_id="sc-inventory",
        title=f"Supply-Chain-Inventar: {len(deps)} Abhängigkeit(en) in {len(manifests)} Manifest(en)",
        status="info", severity="info",
        detail="Read-only Parse lokaler Manifeste.",
        evidence={"manifests": [str(m) for m in manifests],
                  "dep_count": len(deps),
                  "sample": [{"name": d.name, "version": d.version,
                              "ecosystem": d.ecosystem} for d in deps[:20]]},
    ))
    if not deps:
        return findings

    if not online:
        findings.append(DepFinding(
            check_id="sc-osv-skipped",
            title="OSV-Abgleich übersprungen (offline)",
            status="info", severity="info",
            detail="online=False – nur Inventar.",
            evidence={"online": False},
        ))
        return findings

    # Map to softwarescan.Package for OSV
    pkgs = [_sw.Package(name=d.name, version=d.version or "0",
                        ecosystem=d.ecosystem) for d in deps[:max_osv]
            if d.version]
    if not pkgs:
        findings.append(DepFinding(
            check_id="sc-no-versions",
            title="Abhängigkeiten ohne Version – OSV nicht anwendbar",
            status="info", severity="info",
            detail="Manifeste ohne pinnenbare Versionen.",
            evidence={"dep_count": len(deps)},
        ))
        return findings
    try:
        matches = _sw.query_osv(pkgs)
    except Exception as exc:
        findings.append(DepFinding(
            check_id="sc-osv-error",
            title="OSV-Abfrage fehlgeschlagen",
            status="skip", severity="info",
            detail=str(exc)[:200], evidence={"error": str(exc)[:200]},
        ))
        return findings
    for m in matches:
        findings.append(DepFinding(
            check_id=f"sc-vuln:{m.vuln_id}:{m.package}",
            title=f"{m.vuln_id} – {m.package}@{m.version}",
            status="fail", severity=m.severity if m.severity != "unknown" else "medium",
            detail=m.summary or "Siehe OSV.",
            recommendation=(f"Auf {m.fixed} aktualisieren." if m.fixed
                            else "Version prüfen / Patch einspielen."),
            evidence={"vuln_id": m.vuln_id, "package": m.package,
                      "version": m.version, "ecosystem": m.ecosystem,
                      "fixed": m.fixed, "source": "osv.dev"},
        ))
    if not matches:
        findings.append(DepFinding(
            check_id="sc-osv-clean",
            title=f"Keine OSV-Treffer in {len(pkgs)} gepinnten Paketen",
            status="pass", severity="info",
            detail="OSV-Abgleich ohne Treffer (kein Beweis absoluter Sicherheit).",
            evidence={"checked": len(pkgs)},
        ))
    return findings


def capability_summary() -> dict:
    return {"manifests_supported": ["requirements.txt", "package-lock.json",
                                    "pyproject.toml"],
            "status": "installed"}
