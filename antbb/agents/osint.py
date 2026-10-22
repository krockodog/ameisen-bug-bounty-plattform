"""OSINT-Ameise: passive, defensive Informations-Beobachtung.

- security.txt (/.well-known/security.txt, /security.txt): Kontakt + Policy.
- CSP-Analyse: unsafe-inline/unsafe-eval, externe CDNs im Header.
- Permissions-Policy-Vorhandensein.

Rein lesende GETs über ctx.net (Scope + Rate-Limit). Keine aktiven Checks.
"""
from __future__ import annotations

import re

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for

_PRIVATE_MAIL = re.compile(r"(?i)(gmail|googlemail|yahoo|hotmail|outlook|gmx|web\.de|proton)\.")
_CONTACT_RE = re.compile(r"(?im)^contact:\s*(.+)$")


class OsintHunterAnt(AntAgent):
    name = "osint"
    role = "OSINT: security.txt, CSP-/Permissions-Policy-Analyse (passiv, defensiv)"
    specialty = "osint-hunter"
    phases = ("scan",)
    playbooks = (
        Playbook("security-txt", "defensive", False,
                 ["well-known-security-txt", "contact-parse", "private-mail-detect"],
                 "security.txt auswerten (Kontakt, private Mailadresse)."),
        Playbook("csp-analyse", "defensive", False,
                 ["csp-unsafe-inline", "csp-unsafe-eval", "external-cdn-detect"],
                 "Content-Security-Policy inhaltlich bewerten."),
        Playbook("permissions-policy", "defensive", False,
                 ["permissions-policy-present"],
                 "Vorhandensein/Abdeckung der Permissions-Policy prüfen."),
        Playbook("trufflehog-secrets", "defensive", False,
                 ["trufflehog", "gitleaks"],
                 "Secret-Scanning autorisierter Git-Repos/Dateisysteme/GitHub; Funde maskiert."),
        Playbook("username-enumeration", "defensive", False,
                 ["sherlock", "maigret"],
                 "OSINT: Username/Handle ueber soziale Netze enumerieren (sherlock, "
                 "Fallback maigret). Rein lesend, REFERENZ, kein Scraping gefundener Profile."),
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
            for base in base_urls_for(asset):
                if base in seen:
                    continue
                root = await net.http_get(base + "/")
                if root is None:
                    continue
                seen.add(base)
                findings += await self._security_txt(net, base)
                findings += self._csp(base, root)
                findings += self._permissions_policy(base, root)
        findings += await self._kali_ext(task)
        return findings

    async def _security_txt(self, net, base):
        out = []
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = await net.http_get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = (resp.text or "")[:4000]
            if "contact" not in body.lower():
                continue
            m = _CONTACT_RE.search(body)
            contact = (m.group(1).strip() if m else "")[:200]
            private = bool(_PRIVATE_MAIL.search(contact))
            out.append(AgentFinding(
                agent=self.name, title="security.txt gefunden",
                category="security-txt", severity=("low" if private else "info"),
                asset=base + path,
                description=("security.txt vorhanden. " + (
                    "Kontakt ist eine private/Freemail-Adresse – unprofessionell/Zuordnungsrisiko."
                    if private else f"Kontakt: {contact or 'n/a'}.")),
                evidence={"path": path, "status": 200, "contact": contact,
                          "private_mail": private},
                dedup_key=f"security-txt:{base}",
            ))
            break
        return out

    def _csp(self, base, resp):
        csp = resp.headers.get("content-security-policy", "")
        if not csp:
            return []
        low = csp.lower()
        issues = []
        if "unsafe-inline" in low:
            issues.append("unsafe-inline")
        if "unsafe-eval" in low:
            issues.append("unsafe-eval")
        cdns = sorted(set(re.findall(r"https?://([a-z0-9.\-]+)", low)))
        if not issues and not cdns:
            return []
        sev = "low" if issues else "info"
        return [AgentFinding(
            agent=self.name, title="CSP-Analyse: Schwächen/Externe Quellen",
            category="csp-analysis", severity=sev, asset=base,
            description=("CSP vorhanden" + (f", unsichere Direktiven: {issues}" if issues else "")
                         + (f", externe Quellen: {cdns[:6]}" if cdns else "") + "."),
            evidence={"csp_excerpt": csp[:400], "unsafe": issues, "external_sources": cdns[:12],
                      "status": resp.status_code},
            dedup_key=f"csp:{base}",
        )]

    def _permissions_policy(self, base, resp):
        pp = resp.headers.get("permissions-policy", "") or resp.headers.get("feature-policy", "")
        if not pp:
            return []
        return [AgentFinding(
            agent=self.name, title="Permissions-Policy vorhanden",
            category="permissions-policy", severity="info", asset=base,
            description="Permissions-Policy-Header ist gesetzt (positiv).",
            evidence={"permissions_policy": pp[:400], "status": resp.status_code},
            dedup_key=f"permissions-policy:{base}",
        )]

    async def _kali_ext(self, task):
        """Externe Secret-Scanner (trufflehog). NUR Git/FS/GitHub-Quellen; honest-empty sonst."""
        from ..tools.kali import KaliAdapter
        ka = KaliAdapter(self.ctx)
        out = []
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            low = asset.lower()
            if low.endswith(".git"):
                out += await ka.trufflehog(asset, mode="git", agent=self.name)
            elif "github.com" in low:
                out += await ka.trufflehog(asset, mode="github", agent=self.name)
            elif asset.startswith("/"):
                out += await ka.trufflehog(asset, mode="filesystem", agent=self.name)
        out += await self._username_enum(task, ka)
        return out

    async def _username_enum(self, task, ka):
        """OSINT Username-Enumeration. Nur bei EXPLIZIT uebergebenem Username/Handle
        (task.params['username'|'usernames']). sherlock primaer, maigret Fallback,
        honest-empty wenn keines installiert. Rein lesend, kein Scraping."""
        params = task.params or {}
        names = params.get("usernames")
        if not names:
            single = params.get("username")
            names = [single] if single else []
        out = []
        for name in names:
            if not name:
                continue
            out += await ka.username_enum(str(name).strip(), agent=self.name)
        return out
