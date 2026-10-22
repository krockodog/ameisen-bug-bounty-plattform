"""API-Ameise: ECHTE, defensive Erkennung exponierter API-Oberflächen.

Fragt (nur lesende GETs) eine kleine Liste typischer API-/Doku-Pfade ab und
meldet erreichbare OpenAPI/Swagger-Specs oder GraphQL-Endpunkte. KEINE
BOLA/Mass-Assignment-Ausnutzung – nur Oberflächen-Erkennung. ctx.net erzwingt
Scope + Rate-Limit.
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for

_API_PATHS = [
    ("/openapi.json", "OpenAPI-Spezifikation", "medium"),
    ("/swagger.json", "Swagger-Spezifikation", "medium"),
    ("/swagger-ui.html", "Swagger-UI", "low"),
    ("/api", "API-Wurzel", "info"),
    ("/api/v1", "API v1", "info"),
    ("/graphql", "GraphQL-Endpunkt", "low"),
    ("/.well-known/openapi.json", "OpenAPI (well-known)", "low"),
]


class ApiAnt(AntAgent):
    name = "api"
    role = "API-Security: Erkennung exponierter API-/Doku-Endpunkte (echt, defensiv)"
    specialty = "api-tester"
    phases = ("scan",)
    playbooks = (
        Playbook("api-surface-discovery", "defensive", False,
                 ["openapi", "swagger", "graphql", "api-root", "well-known"],
                 "Exponierte OpenAPI/Swagger/GraphQL-Oberflächen (nur GET)."),
        Playbook("nuclei-api", "offensive", True,
                 ["nuclei"],
                 "Vuln-Scan erkannter API-Oberflächen via nuclei."),
        Playbook("sqlmap-verify", "offensive", True,
                 ["sqlmap"],
                 "SQLi-Verifikation parametrisierter API-URLs via sqlmap (--batch, nicht-destruktiv)."),
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
                # nur weitermachen, wenn die Wurzel erreichbar ist
                root = await net.http_get(base + "/")
                if root is None:
                    continue
                seen.add(base)
                for path, label, sev in _API_PATHS:
                    resp = await net.http_get(base + path)
                    if resp is None or resp.status_code >= 400:
                        continue
                    ctype = resp.headers.get("content-type", "")
                    self.ctx.log(f"[api] {base}{path} erreichbar ({resp.status_code}, {ctype})")
                    findings.append(AgentFinding(
                        agent=self.name, title=f"Exponierte API-Oberfläche: {label}",
                        category="api-surface", severity=sev, asset=base + path,
                        description=f"{label} unter {base}{path} antwortet mit HTTP {resp.status_code}.",
                        evidence={"path": path, "status": resp.status_code, "content_type": ctype},
                        dedup_key=f"api:{base}{path}",
                    ))
        findings += await self._kali_ext(task)
        return findings

    async def _kali_ext(self, task):
        """Externe Kali-API-Tools (nuclei/sqlmap). Honest-empty ohne Tools."""
        from ..tools.kali import KaliAdapter
        from ..netutil import base_urls_for
        ka = KaliAdapter(self.ctx)
        out = []
        seen = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            if "?" in asset:
                out += await ka.sqlmap(asset, agent=self.name)
            for base in base_urls_for(asset):
                if base in seen:
                    continue
                seen.add(base)
                out += await ka.nuclei(base, agent=self.name)
        return out
