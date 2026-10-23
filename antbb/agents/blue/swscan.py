"""Blue-Soldat: Software-/Versions-Scan (echt, non-destruktiv, read-only).

Erfasst installierte Software über vorhandene Paketmanager und gleicht sie
gegen die öffentliche OSV-Datenbank ab (bekannte CVEs / veraltete Versionen).
Nichts wird erfunden: CVE-IDs/Severity kommen ausschließlich aus OSV.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import softwarescan as _sw


class SoftwareScanAnt(BlueAgent):
    name = "blue-swscan"
    specialty = "blue-software-scanner"
    role = ("Software-/Versions-Scan (read-only): installierte Pakete erfassen "
            "und gegen OSV auf bekannte CVEs/veraltete Versionen abgleichen.")
    blue_phases = ("assess",)
    playbooks = (
        Playbook("sw-inventory", "defensive", False,
                 ["dpkg-query", "rpm", "pip-list"],
                 "Installierte Software rein lesend inventarisieren "
                 "(Paketname+Version, keine Secrets)."),
        Playbook("sw-cve-match-osv", "defensive", False,
                 ["osv-querybatch", "osv-enrich"],
                 "Inventar gegen die öffentliche OSV-Datenbank abgleichen; "
                 "bekannte CVEs/veraltete Versionen als Report (nie erfunden)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        params = task.params or {}
        online = bool(params.get("online", True))
        ecosystems = params.get("ecosystems")
        self.ctx.log("[blue-swscan] 🔎 Rein lesender Software-/Versions-Scan "
                     f"(online={online}).")
        rep = _sw.scan(ecosystems=ecosystems, online=online)
        summ = rep.summary()
        self.ctx.log(f"[blue-swscan] {summ['package_count']} Paket(e) erfasst, "
                     f"{summ['vuln_count']} OSV-Treffer "
                     f"({'OSV genutzt' if summ['osv_used'] else 'nur Inventar'}).")

        # Coverage-/Inventar-Finding (informativ, REFERENZ).
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Software-Inventar: {summ['package_count']} Paket(e) erfasst",
            category="blue-sw-inventory", severity="info",
            asset="localhost",
            description=("Read-only Inventar über verfügbare Paketmanager. "
                         + (summ["osv_error"] or
                            ("OSV-Abgleich aktiv." if summ["osv_used"]
                             else "Kein OSV-Abgleich (offline/deaktiviert)."))),
            evidence={"summary": summ},
            status="REFERENZ",
            dedup_key="blue-sw-inventory:localhost",
        ))

        # Je Schwachstelle ein Finding – Severity/ID NUR aus OSV.
        _sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                    "low": "low", "unknown": "info"}
        for m in rep.matches:
            sev = _sev_map.get(m.severity, "info")
            loc = f"{m.ecosystem}:{m.package}@{m.version}"
            desc = m.summary or "Siehe OSV-Eintrag."
            if m.fixed:
                desc += f" (behoben in {m.fixed})"
            findings.append(AgentFinding(
                agent=self.name,
                title=f"{m.vuln_id} – {m.package} {m.version} ({m.ecosystem})",
                category="blue-outdated-software", severity=sev,
                asset=loc,
                description=desc,
                evidence={"vuln_id": m.vuln_id, "package": m.package,
                          "version": m.version, "ecosystem": m.ecosystem,
                          "fixed": m.fixed, "aliases": m.aliases,
                          "source": "osv.dev"},
                status="REFERENZ",   # Fremd-CVE/DB-Abgleich = Referenz, kein eigener aktiver Nachweis
                dedup_key=f"blue-outdated:{loc}:{m.vuln_id}",
            ))
        return findings
