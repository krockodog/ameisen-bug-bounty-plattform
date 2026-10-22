"""Auth-Ameise: defensive Session-/Auth-Oberflächen-Analyse.

- Set-Cookie-Flag-Analyse (HttpOnly, Secure, SameSite) der Startseite.
- Auth-Oberflächen-Erkennung (/login, /operator/login, /admin/login).

Rein lesend. Die AKTIVE Auth-Bypass-/Missing-Auth-Bestätigung macht die
Verify-Ameise (payload-specialist) nur unter Oversight + aktiver Freischaltung.
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for

_LOGIN_PATHS = ["/login", "/operator/login", "/admin/login", "/signin", "/auth/login"]


class AuthSpecialistAnt(AntAgent):
    name = "auth"
    role = "Auth-Security: Cookie-Flags + Auth-Oberflächen-Erkennung (defensiv)"
    specialty = "auth-specialist"
    phases = ("scan",)
    playbooks = (
        Playbook("cookie-flag-analyse", "defensive", False,
                 ["httponly", "secure", "samesite"],
                 "Set-Cookie-Sicherheitsflags der Startseite bewerten."),
        Playbook("auth-surface-discovery", "defensive", False,
                 ["login-path-probe"],
                 "Login-/Operator-Oberflächen defensiv erkennen (nur GET)."),
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
                findings += self._cookies(base, root)
                findings += await self._auth_surface(net, base)
        return findings

    def _cookies(self, base, resp):
        out = []
        raw = resp.headers.get("set-cookie", "")
        if not raw:
            return out
        low = raw.lower()
        missing = [flag for flag, tok in
                   (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                   if tok not in low]
        if missing:
            out.append(AgentFinding(
                agent=self.name, title=f"Session-Cookie ohne Flags: {', '.join(missing)}",
                category="cookie-flags", severity="low", asset=base,
                description=(f"Set-Cookie der Startseite ohne {missing} – "
                             "Session-Schutz reduziert."),
                evidence={"missing_flags": missing, "set_cookie_excerpt": raw[:200],
                          "status": resp.status_code},
                dedup_key=f"cookie-flags:{base}",
            ))
        return out

    async def _auth_surface(self, net, base):
        out = []
        for path in _LOGIN_PATHS:
            resp = await net.http_get(base + path)
            if resp is None or resp.status_code >= 400:
                continue
            body = (resp.text or "").lower()
            if "login" in body or "password" in body or "passwort" in body or "anmelden" in body:
                out.append(AgentFinding(
                    agent=self.name, title=f"Auth-Oberfläche erreichbar: {path}",
                    category="info-disclosure", severity="info", asset=base + path,
                    description=f"Login-/Auth-Oberfläche {base}{path} öffentlich erreichbar (HTTP {resp.status_code}).",
                    evidence={"path": path, "status": resp.status_code},
                    dedup_key=f"auth-surface:{base}{path}",
                ))
        return out
