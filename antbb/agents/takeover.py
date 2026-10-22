"""Takeover-Ameise: Subdomain-Takeover-Fingerprinting (defensiv, nicht-destruktiv).

Für jede in-scope (Sub-)Domain mit einem dangling CNAME auf einen bekannten
Dienst wird geprüft, ob der Dienst die charakteristische „kein-solcher-App/
Bucket"-Signatur ausliefert. NUR wenn BEIDES zutrifft (passender CNAME-Ziel-
Pattern UND Dienst-Fingerprint), gilt der Befund als VERIFIZIERT; sonst bleibt
er „zu bestätigen".

Harte Leitplanken:
  * Alle DNS-/HTTP-Zugriffe über ctx.net → Scope default-deny + Rate-Limit.
  * Rein lesend (CNAME-Auflösung + ein GET je Kandidat). NICHTS wird beansprucht,
    registriert oder verändert (kein Claiming) – reiner Nachweis.
"""
from __future__ import annotations

import re

from .base import AntAgent, AgentFinding, Task, Playbook, STATUS_VERIFIED, STATUS_TO_CONFIRM
from ..netutil import host_of, looks_like_domain, base_urls_for

# Bekannte, takeover-fähige Dienste: CNAME-Ziel-Muster + „nicht beansprucht"-Signatur.
TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": [r"\.github\.io$"],
     "signatures": ["there isn't a github pages site here",
                    "for root urls (like http://example.com/) you must provide an index.html file"]},
    {"service": "AWS S3", "cname": [r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$",
                                     r"\.s3\.amazonaws\.com$", r"s3-website"],
     "signatures": ["nosuchbucket", "the specified bucket does not exist"]},
    {"service": "Heroku", "cname": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
     "signatures": ["no such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "Microsoft Azure", "cname": [r"\.cloudapp\.net$", r"\.cloudapp\.azure\.com$",
                                              r"\.azurewebsites\.net$", r"\.trafficmanager\.net$",
                                              r"\.blob\.core\.windows\.net$"],
     "signatures": ["404 web site not found", "this azure app service app has been stopped"]},
    {"service": "Shopify", "cname": [r"\.myshopify\.com$"],
     "signatures": ["sorry, this shop is currently unavailable",
                    "only one step left!"]},
    {"service": "Fastly", "cname": [r"\.fastly\.net$"],
     "signatures": ["fastly error: unknown domain"]},
    {"service": "Zendesk", "cname": [r"\.zendesk\.com$"],
     "signatures": ["help center closed", "this help center no longer exists"]},
    {"service": "GitHub (Pages, alt)", "cname": [r"\.github\.com$"],
     "signatures": ["there isn't a github pages site here"]},
    {"service": "Cargo", "cname": [r"\.cargocollective\.com$"],
     "signatures": ["404 not found", "if you're moving your domain away from cargo"]},
    {"service": "Surge.sh", "cname": [r"\.surge\.sh$"],
     "signatures": ["project not found", "repository not found"]},
    {"service": "Pantheon", "cname": [r"\.pantheonsite\.io$"],
     "signatures": ["the gods are wise", "404 error unknown site"]},
    {"service": "Tumblr", "cname": [r"\.domains\.tumblr\.com$"],
     "signatures": ["whatever you were looking for doesn't currently exist at this address"]},
]


def _cname_matches(cname: str, patterns: list) -> bool:
    low = (cname or "").lower().rstrip(".")
    return any(re.search(p, low) for p in patterns)


class TakeoverAnt(AntAgent):
    name = "takeover"
    role = ("Subdomain-Takeover-Fingerprinting: dangling CNAME + Dienst-Signatur "
            "(GitHub Pages, S3, Heroku, Azure, Shopify, Fastly …), nicht-destruktiv")
    specialty = "takeover-hunter"
    phases = ("recon",)
    playbooks = (
        Playbook("subdomain-takeover-fingerprint", "defensive", False,
                 ["cname-resolve", "service-fingerprint", "dangling-check"],
                 "CNAME auflösen + bekannte Takeover-Dienst-Signatur prüfen "
                 "(VERIFIZIERT nur bei CNAME-Match UND Signatur-Match)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            self.ctx.log("[takeover] Kein NetClient – übersprungen.")
            return findings
        cfg = net.cfg

        # Kandidaten-Hosts: die in-scope Asset-Hosts + deren in-scope Subdomains
        # aus der Wortliste (nur in-scope wird aufgelöst – wie recon).
        candidates: list[str] = []
        seen: set[str] = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            host = host_of(asset)
            if host and host not in seen:
                seen.add(host)
                candidates.append(host)
            if looks_like_domain(host):
                for sub in cfg.subdomain_wordlist:
                    fqdn = f"{sub}.{host}"
                    if fqdn in seen:
                        continue
                    if not net.in_scope(fqdn):
                        continue
                    seen.add(fqdn)
                    candidates.append(fqdn)
        # Auch bereits gefundene Subdomains aus vorherigem Kontext berücksichtigen.
        for f in task.context_findings:
            if f.category == "recon-subdomain" and f.asset and f.asset not in seen:
                if net.in_scope(f.asset):
                    seen.add(f.asset)
                    candidates.append(f.asset)

        for host in candidates:
            cnames = await net.resolve(host, "CNAME")
            if not cnames:
                continue
            cname = cnames[0].rstrip(".")
            match = next((fp for fp in TAKEOVER_FINGERPRINTS
                          if _cname_matches(cname, fp["cname"])), None)
            if not match:
                continue
            # Dienst-Signatur über ein lesendes GET prüfen.
            fetched = None
            fetched_url = ""
            for base in base_urls_for(host):
                fetched_url = base + "/"
                fetched = await net.http_get(fetched_url)
                if fetched is not None:
                    break
            body_low = (fetched.text or "").lower() if fetched is not None else ""
            sig_hit = any(sig in body_low for sig in match["signatures"])

            if sig_hit:
                self.ctx.log(f"[takeover] ✅ Subdomain-Takeover bestätigt @ {host} "
                             f"→ {match['service']} (CNAME {cname})")
                findings.append(AgentFinding(
                    agent=self.name,
                    title=f"Subdomain-Takeover bestätigt: {host} ({match['service']})",
                    category="subdomain-takeover", severity="high", asset=host,
                    description=(f"{host} verweist per CNAME auf {cname} "
                                 f"({match['service']}), und der Dienst liefert die "
                                 "charakteristische „nicht beansprucht/kein solcher "
                                 "App/Bucket\"-Signatur → übernehmbarer Subdomain-Takeover. "
                                 "Rein lesender Nachweis; NICHTS wurde beansprucht."),
                    evidence={"request": {"method": "GET", "url": fetched_url},
                              "confidence": "bestätigt", "cname": cname,
                              "service": match["service"],
                              "status": getattr(fetched, "status_code", None),
                              "signature_matched": True,
                              "response_excerpt": _first_sig_excerpt(body_low, match["signatures"])},
                    status=STATUS_VERIFIED,
                    dedup_key=f"subdomain-takeover:{host}",
                ))
            else:
                self.ctx.log(f"[takeover] ℹ️ dangling CNAME @ {host} → {cname} "
                             f"({match['service']}), Signatur NICHT bestätigt – zu bestätigen")
                findings.append(AgentFinding(
                    agent=self.name,
                    title=f"Möglicher Subdomain-Takeover: {host} ({match['service']})",
                    category="subdomain-takeover", severity="medium", asset=host,
                    description=(f"{host} zeigt per CNAME auf {cname} "
                                 f"({match['service']}), aber die Dienst-„nicht "
                                 "beansprucht\"-Signatur wurde NICHT bestätigt → noch "
                                 "zu bestätigen (kein verifizierter Takeover)."),
                    evidence={"cname": cname, "service": match["service"],
                              "confidence": "zu bestätigen",
                              "note": "CNAME passt, Signatur nicht aktiv belegt"},
                    status=STATUS_TO_CONFIRM,
                    dedup_key=f"subdomain-takeover-maybe:{host}",
                ))
        return findings


def _first_sig_excerpt(body_low: str, signatures: list) -> str:
    for sig in signatures:
        i = body_low.find(sig)
        if i >= 0:
            start = max(0, i - 20)
            return body_low[start:i + len(sig) + 40].strip()[:200]
    return ""
