"""Threat-Intel-Ameise: korreliert BEOBACHTETE Technologie → bekannte CVEs.

Quellen:
  1. Minimaler, dokumentierter Technologie→CVE-Referenzkatalog (offline).
  2. ECHTE NVD-API-Abfrage (services.nvd.nist.gov) nach erkannten
     Technologien/Versionen – mit Rate-Limit, Timeout, graceful degrade bei
     fehlendem Netz. Optionaler NVD_API_KEY aus der Umgebung (nicht nötig).
  3. Lokale Exploit-DB via searchsploit (falls vorhanden).

ALLE Ergebnisse werden AUSSCHLIESSLICH als REFERENZ (Fremd-CVE) bzw. BEDINGT
geführt – niemals als eigener aktiver Nachweis. CVSS-Werte werden von NVD
ÜBERNOMMEN, nie erfunden. Keine Severity-Inflation.
"""
from __future__ import annotations

import os
import re

from .base import (AntAgent, AgentFinding, Task, Playbook,
                   STATUS_REFERENCE, STATUS_CONDITIONAL)

# Minimaler, dokumentierter Technologie→CVE-Referenzkatalog (erweiterbar).
_CATALOG = [
    (re.compile(r"(?i)starlette"), "CVE-2026-48710",
     "Starlette Host-Header/BadHost → möglicher Auth-Bypass (versionsabhängig).", True),
    (re.compile(r"(?i)litellm"), "CVE-2026-42271",
     "LiteLLM unauth RCE-Muster (nur falls tatsächlich eingesetzt).", False),
    (re.compile(r"(?i)python-multipart"), "CVE-2026-53537",
     "python-multipart Parameter-Smuggling (versionsabhängig).", False),
    (re.compile(r"(?i)(nginx)/?(\d+\.\d+\.\d+)?"), "CVE-REF-NGINX",
     "nginx: je nach Version diverse CVEs – Version prüfen.", False),
    (re.compile(r"(?i)(apache)/?(\d+\.\d+\.\d+)?"), "CVE-REF-APACHE",
     "Apache httpd: je nach Version diverse CVEs – Version prüfen.", False),
    (re.compile(r"(?i)(openssh|libssh)"), "CVE-REF-SSH",
     "SSH-Dienst erkannt – Version gegen bekannte CVEs prüfen.", False),
]

# Tech-Strings mit Version (z.B. "nginx/1.25.3", "Apache/2.4.58").
_TECH_VER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-\.]{2,30})/(\d+\.\d+(?:\.\d+)?)")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class ThreatIntelAnt(AntAgent):
    name = "threatintel"
    role = "Threat-Intel: beobachtete Technologie → bekannte CVEs (NVD + Katalog, nur REFERENZ)"
    specialty = "threat-intel-analyst"
    phases = ("analyze",)
    playbooks = (
        Playbook("tech-cve-korrelation", "defensive", False,
                 ["fingerprint-parse", "cve-catalog-match", "version-gating"],
                 "Beobachtete Technologie bekannten CVEs zuordnen (REFERENZ/BEDINGT)."),
        Playbook("nvd-cve-lookup", "defensive", False,
                 ["nvd-api", "keyword-search", "cvss-from-nvd"],
                 "Echte NVD-API-Abfrage nach Technologie/Version (REFERENZ, CVSS von NVD)."),
        Playbook("searchsploit-lookup", "defensive", False,
                 ["searchsploit"],
                 "Lokale Exploit-DB-Suche (REFERENZ, kein eigener Nachweis)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        out: list[AgentFinding] = []
        observed: list[str] = []
        for f in task.context_findings:
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            if f.category in ("fingerprint", "whatweb-fingerprint", "nmap-service"):
                observed.append(str(ev.get("server", "")))
                tech = ev.get("tech") or {}
                if isinstance(tech, dict):
                    for k, v in tech.items():
                        observed.append(f"{k}/{v}" if v else str(k))
                for p in (ev.get("ports") or []):
                    if isinstance(p, dict) and p.get("version"):
                        observed.append(str(p["version"]))
        blob = " ".join(t for t in observed if t)

        # ---- 1) Offline-Katalog ----
        seen = set()
        if blob.strip():
            for rx, cve, desc, kev in _CATALOG:
                m = rx.search(blob)
                if not m or cve in seen:
                    continue
                seen.add(cve)
                version = ""
                if m.lastindex and m.lastindex >= 2 and m.group(2):
                    version = m.group(2)
                status = STATUS_REFERENCE if version else STATUS_CONDITIONAL
                out.append(AgentFinding(
                    agent=self.name, title=f"CVE-Referenz: {cve} ({m.group(0)})",
                    category="threat-intel-cve", severity="info", asset=task.target_name,
                    description=(f"Beobachtete Technologie '{m.group(0)}' passt zum Muster {cve}: {desc} "
                                 + ("Version erkannt – als Referenz geführt." if version
                                    else "Keine Version bestätigt – Anwendbarkeit offen (BEDINGT).")
                                 + (" [KEV]" if kev else "")),
                    evidence={"cve": cve, "observed_tech": m.group(0),
                              "version": version or "unbekannt", "kev": kev,
                              "source": "offline-katalog", "note": "Fremd-CVE, kein eigener Nachweis"},
                    status=status,
                    dedup_key=f"threatintel:{cve}:{task.target_name}",
                ))

        # ---- 2) Echte NVD-API-Abfrage nach Tech/Version ----
        products = []
        for m in _TECH_VER_RE.finditer(blob):
            prod, ver = m.group(1), m.group(2)
            if prod.lower() in ("mozilla", "text", "html"):
                continue
            key = f"{prod} {ver}"
            if key not in products:
                products.append(key)
        out += await self._nvd_lookup(products[:4], task)

        # ---- 3) searchsploit (lokale Exploit-DB) ----
        try:
            from ..tools.kali import KaliAdapter
            ka = KaliAdapter(self.ctx)
            for term in products[:3]:
                out += await ka.searchsploit(term, agent=self.name)
        except Exception:
            pass

        if not out:
            self.ctx.log("[threatintel] Keine Technologie/Version → keine CVE-Korrelation (ehrlich leer).")
        return out

    async def _nvd_lookup(self, products: list[str], task: Task) -> list[AgentFinding]:
        if not products:
            return []
        # NVD-Netzabfrage ist opt-in (ANTBB_NVD=1), damit Läufe deterministisch
        # bleiben und nicht ungewollt externe Requests/Sleeps auslösen. Auf dem
        # Kali-Host einfach ANTBB_NVD=1 setzen. Ohne Flag: graceful skip.
        if os.environ.get("ANTBB_NVD", "").strip() not in ("1", "true", "yes"):
            self.ctx.log("[threatintel] NVD-Lookup nicht freigeschaltet (ANTBB_NVD!=1) – übersprungen.")
            return []
        import asyncio
        import httpx
        out: list[AgentFinding] = []
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")  # optional, nicht erforderlich
        if api_key:
            headers["apiKey"] = api_key
        seen = set()
        for i, term in enumerate(products):
            if i > 0:
                # NVD-Rate-Limit respektieren (ohne Key: 5 Anfragen/30s).
                await asyncio.sleep(6.5 if not api_key else 0.8)
            params = {"keywordSearch": term, "keywordExactMatch": "",
                      "resultsPerPage": 5}
            try:
                async with httpx.AsyncClient(timeout=12.0, headers=headers) as c:
                    r = await c.get(_NVD_URL, params=params)
                if r.status_code != 200:
                    self.ctx.log(f"[threatintel] NVD HTTP {r.status_code} für '{term}' – übersprungen.")
                    continue
                data = r.json()
            except Exception as exc:
                self.ctx.log(f"[threatintel] NVD nicht erreichbar ({type(exc).__name__}) – graceful degrade.")
                break  # Netz weg → gar nicht weiter versuchen
            for item in data.get("vulnerabilities", [])[:5]:
                cve = (item.get("cve") or {})
                cid = cve.get("id")
                if not cid or cid in seen:
                    continue
                seen.add(cid)
                # CVSS VON NVD übernehmen (nie erfinden).
                cvss_score, cvss_vec, cvss_sev = _extract_cvss(cve)
                descs = cve.get("descriptions", [])
                text = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
                out.append(AgentFinding(
                    agent=self.name, title=f"NVD-Referenz: {cid} ({term})",
                    category="cve-reference",
                    severity="info",  # REFERENZ zählt nicht als eigene Schwere
                    asset=task.target_name,
                    description=(f"NVD-Treffer für '{term}': {cid}. "
                                 f"{(text[:240]) if text else ''} "
                                 "(REFERENZ – nur gültig, wenn Technologie/Version tatsächlich eingesetzt wird.)"),
                    evidence={"cve": cid, "nvd_cvss_score": cvss_score,
                              "nvd_cvss_vector": cvss_vec, "nvd_cvss_severity": cvss_sev,
                              "keyword": term, "source": "nvd-api",
                              "note": "Fremd-CVE von NVD, CVSS übernommen, kein eigener Nachweis"},
                    status=STATUS_REFERENCE,
                    dedup_key=f"nvd:{cid}:{task.target_name}",
                ))
        return out


def _extract_cvss(cve: dict):
    metrics = cve.get("metrics", {}) if isinstance(cve, dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr and isinstance(arr, list):
            d = arr[0].get("cvssData", {})
            return (d.get("baseScore"), d.get("vectorString"),
                    d.get("baseSeverity") or arr[0].get("baseSeverity"))
    return (None, "", "")
