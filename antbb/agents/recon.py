"""Recon-Ameise: ECHTE, defensive Aufklärung.

- DNS-Abfragen (A/AAAA/CNAME/MX/TXT) für in-scope Hosts.
- Subdomain-Auflösung über eine kleine Wortliste; nur in-scope Subdomains
  werden überhaupt aufgelöst, der Rest wird (scope-geblockt) übersprungen.
- Optionaler, leichter TCP-Connect-Portscan (nur Verbindungsaufbau, kein
  Payload) auf einer kleinen Standard-Portliste mit kurzen Timeouts.

Alle Netzwerkzugriffe laufen über den scope- und ratengebundenen NetClient
(ctx.net). Kein Zugriff auf out-of-scope Ziele.
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import host_of, looks_like_domain, is_ip_literal


class ReconAnt(AntAgent):
    name = "recon"
    role = "Aufklärung: DNS, Subdomain-Auflösung, leichter TCP-Portscan (echt, defensiv)"
    specialty = "recon-master"
    phases = ("recon",)
    playbooks = (
        Playbook("dns-aufklaerung", "defensive", False,
                 ["dns-a", "dns-aaaa", "dns-cname", "dns-mx", "dns-txt"],
                 "DNS-Records für in-scope Hosts auflösen."),
        Playbook("subdomain-enumeration", "defensive", False,
                 ["wordlist-resolve", "scope-gated-resolve"],
                 "Subdomains aus Wortliste auflösen (nur in-scope)."),
        Playbook("tcp-connect-portscan", "defensive", False,
                 ["tcp-connect"],
                 "Leichter TCP-Connect-Portscan ohne Payload."),
        Playbook("nmap-service-scan", "offensive", True,
                 ["nmap"],
                 "nmap Port-/Service-Scan (leicht defensiv, -sV offensiv; nur wenn nmap vorhanden)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            self.ctx.log("[recon] Kein NetClient – übersprungen.")
            return findings
        cfg = net.cfg
        seen: set[str] = set()

        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            host = host_of(asset)
            if host in seen:
                continue
            seen.add(host)

            # ---- DNS-Abfragen ----
            records: dict[str, list[str]] = {}
            if not is_ip_literal(host):
                for rd in ("A", "AAAA", "CNAME", "MX", "TXT"):
                    vals = await net.resolve(host, rd)
                    if vals:
                        records[rd] = vals[:10]
                if records:
                    self.ctx.log(f"[recon] {host}: DNS {sorted(records)}")
                    findings.append(AgentFinding(
                        agent=self.name,
                        title=f"DNS-Aufklärung: {host}",
                        category="recon-dns", severity="info", asset=host,
                        description=f"Aufgelöste DNS-Records für {host}: {sorted(records)}.",
                        evidence={"records": records},
                        dedup_key=f"recon-dns:{host}",
                    ))

            # ---- Subdomain-Auflösung (nur in-scope) ----
            if looks_like_domain(host):
                discovered: list[dict] = []
                for sub in cfg.subdomain_wordlist:
                    fqdn = f"{sub}.{host}"
                    if not net.in_scope(fqdn):
                        # out-of-scope Subdomain: NICHT auflösen (wird in net.blocked geloggt
                        # nur bei tatsächlichem Zugriff – hier bewusst gar kein Request)
                        self.ctx.log(f"[recon] ⛔ nicht aufgelöst (out-of-scope): {fqdn}")
                        continue
                    ips = await net.resolve(fqdn, "A")
                    if ips:
                        discovered.append({"host": fqdn, "ips": ips})
                for d in discovered:
                    findings.append(AgentFinding(
                        agent=self.name,
                        title=f"Subdomain gefunden: {d['host']}",
                        category="recon-subdomain", severity="info", asset=d["host"],
                        description=f"{d['host']} löst auf {d['ips']} (in-scope).",
                        evidence=d, dedup_key=f"recon-sub:{d['host']}",
                    ))
                if discovered:
                    self.ctx.log(f"[recon] {host}: {len(discovered)} in-scope Subdomain(s).")

            # ---- Leichter TCP-Connect-Portscan ----
            if cfg.enable_portscan:
                open_ports: list[int] = []
                for port in cfg.ports:
                    if await net.scan_port(host, port):
                        open_ports.append(port)
                if open_ports:
                    self.ctx.log(f"[recon] {host}: offene Ports {open_ports}")
                    sev = "low" if any(p in (21, 22, 25, 3306) for p in open_ports) else "info"
                    findings.append(AgentFinding(
                        agent=self.name,
                        title=f"Offene Ports: {host}",
                        category="recon-ports", severity=sev, asset=host,
                        description=f"TCP-Connect-Scan fand offene Ports {open_ports} auf {host}.",
                        evidence={"open_ports": open_ports},
                        dedup_key=f"recon-ports:{host}",
                    ))
        findings += await self._kali_ext(task)
        return findings

    async def _kali_ext(self, task):
        """Externe Kali-Recon-Tools (nmap). Honest-empty, wenn nicht installiert."""
        from ..tools.kali import KaliAdapter
        from ..netutil import host_of
        ka = KaliAdapter(self.ctx)
        out = []
        seen = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            h = host_of(asset)
            if h in seen:
                continue
            seen.add(h)
            out += await ka.nmap(asset, agent=self.name)
        return out
