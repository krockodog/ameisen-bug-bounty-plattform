"""Infra-Ameise: ECHTE, defensive TLS-/Service-Inspektion.

Prüft für in-scope HTTPS-Hosts (Port 443) das ausgehandelte TLS-Protokoll und –
sofern verifizierbar – Zertifikatsdaten (Ablaufdatum). Rein lesend, keine
destruktiven Checks. Nutzt ctx.net (Scope + Rate-Limit).
"""
from __future__ import annotations

from datetime import datetime, timezone

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import host_of, is_ip_literal

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


class InfraAnt(AntAgent):
    name = "infra"
    role = "Netzwerk/Infrastruktur: TLS, Zertifikat, SPF/DMARC, CAA (echt, defensiv)"
    specialty = "network-hunter"
    phases = ("scan",)
    playbooks = (
        Playbook("tls-inspektion", "defensive", False,
                 ["tls-protocol", "cert-expiry", "weak-protocol-detect"],
                 "Ausgehandeltes TLS-Protokoll und Zertifikatsablauf (lesend)."),
        Playbook("email-auth-dns", "defensive", False,
                 ["spf-txt", "dmarc-txt"],
                 "SPF-/DMARC-DNS-Records auswerten (sofern auflösbar)."),
        Playbook("caa-dns", "defensive", False,
                 ["caa-record"],
                 "CAA-Records auswerten (sofern auflösbar)."),
        Playbook("sslscan-tls", "defensive", False,
                 ["sslscan", "sslyze"],
                 "TLS-/Cipher-Analyse via sslscan/sslyze (nur wenn vorhanden)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            return findings
        seen: set[str] = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            host = host_of(asset)
            if host in seen:
                continue
            seen.add(host)
            if not is_ip_literal(host):
                findings += await self._email_auth(net, host)
                findings += await self._caa(net, host)
            info = await net.tls_info(host, 443)
            if not info:
                continue
            proto = info.get("protocol") or "?"
            self.ctx.log(f"[infra] {host}:443 TLS {proto} (verifiziert={info.get('verified')})")
            if proto in _WEAK_PROTOCOLS:
                findings.append(AgentFinding(
                    agent=self.name, title=f"Schwaches TLS-Protokoll: {proto}",
                    category="tls", severity="medium", asset=f"{host}:443",
                    description=f"Server handelt schwaches TLS-Protokoll {proto} aus.",
                    evidence={"protocol": proto}, dedup_key=f"tls-weak:{host}",
                ))
            else:
                findings.append(AgentFinding(
                    agent=self.name, title=f"TLS-Protokoll: {proto}",
                    category="tls", severity="info", asset=f"{host}:443",
                    description=f"Server nutzt {proto}.",
                    evidence={"protocol": proto, "verified": info.get("verified")},
                    dedup_key=f"tls:{host}",
                ))
            # Zertifikatsablauf (nur wenn verifiziert verfügbar)
            cert = info.get("cert") or {}
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if days < 0:
                        sev, msg = "high", f"Zertifikat ABGELAUFEN (seit {-days} Tagen)."
                    elif days < 21:
                        sev, msg = "low", f"Zertifikat läuft in {days} Tagen ab."
                    else:
                        sev, msg = "info", f"Zertifikat gültig, Ablauf in {days} Tagen."
                    findings.append(AgentFinding(
                        agent=self.name, title=f"TLS-Zertifikat: {msg}",
                        category="tls-cert", severity=sev, asset=f"{host}:443",
                        description=msg, evidence={"not_after": not_after, "days_left": days},
                        dedup_key=f"tls-cert:{host}",
                    ))
                except Exception:
                    pass
        findings += await self._kali_ext(task)
        return findings

    # ---------------- SPF / DMARC (DNS TXT) ----------------
    async def _email_auth(self, net, host):
        out = []
        txt = await net.resolve(host, "TXT")
        spf = [t for t in txt if "v=spf1" in t.lower()]
        if spf:
            val = spf[0]
            softfail = "~all" in val or "?all" in val
            sev = "low" if softfail else "info"
            out.append(AgentFinding(
                agent=self.name, title="SPF-Record vorhanden",
                category="dns-email-auth", severity=sev, asset=host,
                description=("SPF-Record gefunden" + (" mit Softfail (~all/?all) – "
                             "Spoofing-Schutz abgeschwächt." if softfail else ".")),
                evidence={"record_type": "TXT", "spf": val[:300],
                          "softfail": softfail, "status": "dns-resolved"},
                dedup_key=f"spf:{host}",
            ))
        dmarc = await net.resolve("_dmarc." + host, "TXT")
        dm = [t for t in dmarc if "v=dmarc1" in t.lower()]
        if dm:
            val = dm[0]
            policy = "none"
            for part in val.replace('"', "").split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part.split("=", 1)[1].strip()
            sev = "info" if policy in ("reject", "quarantine") else "low"
            out.append(AgentFinding(
                agent=self.name, title=f"DMARC-Policy: p={policy}",
                category="dns-email-auth", severity=sev, asset=host,
                description=f"DMARC-Record gefunden, Policy p={policy}.",
                evidence={"record_type": "TXT", "dmarc": val[:300],
                          "policy": policy, "status": "dns-resolved"},
                dedup_key=f"dmarc:{host}",
            ))
        return out

    # ---------------- CAA (DNS) ----------------
    async def _caa(self, net, host):
        caa = await net.resolve(host, "CAA")
        if not caa:
            return []
        issuers = len(caa)
        sev = "info"
        return [AgentFinding(
            agent=self.name, title=f"CAA-Records: {issuers} Einträge",
            category="dns-caa", severity=sev, asset=host,
            description=f"{issuers} CAA-Record(s) gefunden.",
            evidence={"record_type": "CAA", "records": [c[:120] for c in caa[:10]],
                      "status": "dns-resolved"},
            dedup_key=f"caa:{host}",
        )]

    async def _kali_ext(self, task):
        """Externe Kali-TLS-Tools (sslscan). Honest-empty ohne Tool."""
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
            out += await ka.sslscan(asset, agent=self.name)
        return out
