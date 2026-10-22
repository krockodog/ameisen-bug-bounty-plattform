"""LLM-Security-Ameise: erkennt KI-/LLM-Endpunkte (defensiv).

Defensiv: typische LLM-/Chat-API-Pfade erkennen (nur GET, Oberflächen-Erkennung).
Die AKTIVE Prompt-Injection-Prüfung läuft nur unter Oversight + aktiver
Freischaltung und braucht einen bekannten Chat-API-Kontrakt; ohne steuerbares
Eingabefeld wird NICHTS behauptet (ehrlicher Leerzustand).
"""
from __future__ import annotations

from .base import AntAgent, AgentFinding, Task, Playbook

_LLM_PATHS = [
    "/v1/chat/completions", "/v1/completions", "/api/chat", "/api/generate",
    "/api/ai", "/chat", "/completions", "/v1/models",
]


class LlmSecurityAnt(AntAgent):
    name = "llmsec"
    role = "LLM-Security: Erkennung von KI-/Chat-Endpunkten (defensiv; aktiv nur unter Oversight)"
    specialty = "llm-security-tester"
    phases = ("scan",)
    playbooks = (
        Playbook("llm-endpoint-discovery", "defensive", False,
                 ["chat-completions-path", "models-path", "generate-path"],
                 "Typische LLM-/Chat-API-Pfade defensiv erkennen (nur GET)."),
        Playbook("prompt-injection-aktiv", "offensive", True,
                 ["benign-injection-marker", "reflection-detect"],
                 "Prompt-Injection mit gutartigem Marker (nur Oversight + aktiv; braucht API-Kontrakt)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            return findings
        from ..netutil import base_urls_for
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
                for path in _LLM_PATHS:
                    resp = await net.http_get(base + path)
                    if resp is None or resp.status_code >= 400:
                        continue
                    ctype = resp.headers.get("content-type", "")
                    findings.append(AgentFinding(
                        agent=self.name, title=f"LLM-/KI-Endpunkt erkannt: {path}",
                        category="api-surface", severity="info", asset=base + path,
                        description=(f"Möglicher LLM-/Chat-Endpunkt {base}{path} antwortet "
                                     f"HTTP {resp.status_code}. Nur Oberflächen-Erkennung."),
                        evidence={"path": path, "status": resp.status_code, "content_type": ctype},
                        dedup_key=f"llm-endpoint:{base}{path}",
                    ))
                if not getattr(self.ctx, "active", False):
                    self.ctx.log("[llmsec] ℹ️ Aktive Prompt-Injection-Prüfung AUS "
                                 "(benötigt Oversight + --active + API-Kontrakt).")
        return findings
