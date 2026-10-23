"""Software-/Versions-Scan (echt, non-destruktiv, read-only).

Erfasst installierte Software am Laufort über vorhandene Paketmanager (rein
lesende Abfragen: `dpkg-query`, `rpm`, `pip`) und gleicht sie optional gegen
die ÖFFENTLICHE OSV-Datenbank (https://osv.dev, kein Key nötig) ab, um bekannte
Schwachstellen / veraltete Versionen zu erkennen.

Harte Leitplanken:
  * REIN LESEND. Es wird nichts installiert, verändert, entfernt.
  * Keine Secrets, keine PII. Nur Paketname + Version.
  * Netzwerk-Abgleich (OSV) ist OPTIONAL. Ohne Netz/deaktiviert liefert der
    Scan weiterhin das vollständige, ehrliche Inventar (honest-partial).
  * Niemals erfundene CVEs – IDs/Severity kommen ausschließlich aus OSV.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str          # "PyPI" | "Debian" | "RPM" | ...
    source: str = ""        # welcher Paketmanager


@dataclass
class VulnMatch:
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    summary: str = ""
    severity: str = "unknown"   # critical|high|medium|low|unknown (aus OSV CVSS/DB)
    fixed: str = ""             # erste fixed-Version falls bekannt
    aliases: list = field(default_factory=list)


def _run(cmd: list[str], timeout: float = 20.0) -> str:
    """Rein lesendes Kommando ausführen; '' bei Fehler (nie crashen)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return out.stdout or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Inventar (read-only Paketmanager-Abfragen)
# ---------------------------------------------------------------------------
def inventory_pip() -> list[Package]:
    pkgs: list[Package] = []
    # `pip list --format=json` – rein lesend.
    for exe in ("pip", "pip3"):
        if not shutil.which(exe):
            continue
        raw = _run([exe, "list", "--format=json", "--disable-pip-version-check"])
        if not raw:
            continue
        try:
            for item in json.loads(raw):
                name = str(item.get("name", "")).strip()
                ver = str(item.get("version", "")).strip()
                if name and ver:
                    pkgs.append(Package(name, ver, "PyPI", exe))
        except Exception:
            pass
        break
    return pkgs


def inventory_dpkg() -> list[Package]:
    if not shutil.which("dpkg-query"):
        return []
    raw = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
    pkgs: list[Package] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append(Package(parts[0], parts[1], "Debian", "dpkg"))
    return pkgs


def inventory_rpm() -> list[Package]:
    if not shutil.which("rpm"):
        return []
    raw = _run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"])
    pkgs: list[Package] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append(Package(parts[0], parts[1], "RPM", "rpm"))
    return pkgs


def collect_inventory(ecosystems: Optional[list[str]] = None) -> list[Package]:
    """Komplettes Inventar über alle verfügbaren Paketmanager (read-only)."""
    out: list[Package] = []
    out.extend(inventory_pip())
    out.extend(inventory_dpkg())
    out.extend(inventory_rpm())
    if ecosystems:
        want = {e.lower() for e in ecosystems}
        out = [p for p in out if p.ecosystem.lower() in want]
    # dedup
    seen = set()
    uniq = []
    for p in out:
        k = (p.ecosystem, p.name, p.version)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(p)
    return uniq


# ---------------------------------------------------------------------------
# OSV-Abgleich (optional, öffentlich, kein Key)
# ---------------------------------------------------------------------------
def _osv_severity(vuln: dict) -> str:
    # OSV liefert teils database_specific.severity oder CVSS-Vektoren.
    db = vuln.get("database_specific") or {}
    sev = str(db.get("severity", "")).lower()
    if sev in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if sev == "moderate" else sev
    # Aus CVSS-Score ableiten, falls vorhanden.
    for s in vuln.get("severity", []) or []:
        score = str(s.get("score", ""))
        if "CVSS" in score or score.replace(".", "").isdigit():
            return "unknown"
    return "unknown"


def _first_fixed(vuln: dict, pkg: str) -> str:
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def query_osv(packages: list[Package], timeout: float = 20.0,
              enrich: bool = True) -> tuple[list[VulnMatch], Optional[str]]:
    """Fragt OSV im Batch ab. Rückgabe (matches, error).

    error != None heißt: Abgleich nicht möglich (z.B. offline) – das Inventar
    bleibt trotzdem gültig (honest-partial). Niemals erfundene Daten.
    """
    if not packages:
        return [], None
    try:
        import httpx
    except Exception:
        return [], "httpx nicht verfügbar – OSV-Abgleich übersprungen."

    queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem},
                "version": p.version} for p in packages]
    matches: list[VulnMatch] = []
    try:
        with httpx.Client(timeout=timeout) as client:
            # Batch in Blöcken (OSV akzeptiert große Batches, wir chunked sicher).
            CHUNK = 200
            results: list = []
            for i in range(0, len(queries), CHUNK):
                resp = client.post(OSV_BATCH_URL,
                                   json={"queries": queries[i:i + CHUNK]})
                resp.raise_for_status()
                results.extend(resp.json().get("results", []))
            # Ergebnisse den Paketen zuordnen.
            for pkg, res in zip(packages, results):
                for v in (res.get("vulns") or []):
                    vid = v.get("id", "")
                    summary = ""
                    sev = "unknown"
                    fixed = ""
                    aliases: list = []
                    if enrich and vid:
                        try:
                            det = client.get(OSV_VULN_URL + vid)
                            if det.status_code == 200:
                                dj = det.json()
                                summary = dj.get("summary", "") or dj.get("details", "")[:160]
                                sev = _osv_severity(dj)
                                fixed = _first_fixed(dj, pkg.name)
                                aliases = dj.get("aliases", []) or []
                        except Exception:
                            pass
                    matches.append(VulnMatch(
                        package=pkg.name, version=pkg.version,
                        ecosystem=pkg.ecosystem, vuln_id=vid,
                        summary=(summary or "")[:240], severity=sev,
                        fixed=fixed, aliases=aliases))
    except Exception as exc:
        return matches, f"OSV-Abgleich unvollständig: {type(exc).__name__}: {exc}"
    return matches, None


@dataclass
class ScanReport:
    packages: list[Package] = field(default_factory=list)
    matches: list[VulnMatch] = field(default_factory=list)
    osv_error: Optional[str] = None
    osv_used: bool = False

    def summary(self) -> dict:
        by_sev: dict[str, int] = {}
        for m in self.matches:
            by_sev[m.severity] = by_sev.get(m.severity, 0) + 1
        return {
            "package_count": len(self.packages),
            "vuln_count": len(self.matches),
            "affected_packages": len({(m.ecosystem, m.package) for m in self.matches}),
            "by_severity": by_sev,
            "osv_used": self.osv_used,
            "osv_error": self.osv_error,
        }


def scan(ecosystems: Optional[list[str]] = None, online: bool = True,
         enrich: bool = True, limit_osv: int = 400) -> ScanReport:
    """Vollständiger Software-/Versions-Scan (read-only).

    `online=False` → nur Inventar, kein OSV (deterministisch, offline-fähig).
    """
    pkgs = collect_inventory(ecosystems)
    rep = ScanReport(packages=pkgs)
    if online and pkgs:
        # OSV-Abgleich fokussiert auf eindeutig auflösbare Ökosysteme (PyPI
        # zuverlässig; Debian/RPM nur, wenn gewünscht – größer/langsamer).
        osv_targets = [p for p in pkgs if p.ecosystem == "PyPI"]
        if ecosystems and any(e.lower() in ("debian", "rpm") for e in ecosystems):
            osv_targets = pkgs
        osv_targets = osv_targets[:limit_osv]
        matches, err = query_osv(osv_targets, enrich=enrich)
        rep.matches = matches
        rep.osv_error = err
        rep.osv_used = err is None
    return rep
