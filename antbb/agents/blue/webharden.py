"""Blue-Soldat: Web-Härtung (Headers, Cookies, TLS)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import webharden as _wh


class WebHardenAnt(BlueAgent):
    name = "blue-webharden"
    specialty = "blue-web-hardener"
    role = ("Web-Härtung: Security-Headers, Cookie-Flags und TLS gegen ein "
            "Ziel prüfen (read-only). Ohne URL: honest-empty.")
    blue_phases = ("assess", "harden")
    playbooks = (
        Playbook("web-security-headers", "defensive", False,
                 ["hsts", "csp", "xcto", "xfo", "referrer-policy", "permissions-policy"],
                 "OWASP-nahe Security-Header prüfen.",
                 tasks=["HTTP-Response holen", "Header-Katalog prüfen",
                        "Fehlende Header als Finding", "Empfehlungen geben"]),
        Playbook("web-cookie-flags", "defensive", False,
                 ["httponly", "secure", "samesite"],
                 "Set-Cookie-Flags (HttpOnly/Secure/SameSite) prüfen.",
                 tasks=["Set-Cookie lesen", "Flags prüfen", "Lücken melden"]),
        Playbook("web-tls-basics", "defensive", False,
                 ["tls-version", "cipher"],
                 "TLS-Version/Cipher grundlegend prüfen.",
                 tasks=["TLS-Handshake", "Version lesen", "Schwache Protokolle melden"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        params = task.params or {}
        url = params.get("url") or params.get("target_url") or ""
        # Fallback: erstes Asset wenn http(s)
        if not url:
            for a in task.assets or []:
                if isinstance(a, str) and ("." in a or a.startswith("http")):
                    if a not in ("localhost", "monitoring", "decoy"):
                        url = a
                        break
        if not url:
            self.ctx.log("[blue-webharden] Keine URL – honest-empty.")
            findings.append(AgentFinding(
                agent=self.name, title="Web-Härtung: keine URL übergeben",
                category="blue-webharden-empty", severity="info",
                asset="web", description="params.url/target_url setzen für Audit.",
                evidence={"capabilities": _wh.capability_summary()},
                status="REFERENZ", dedup_key="blue-webharden-empty",
            ))
            return findings

        self.ctx.log(f"[blue-webharden] 🔒 Audit gegen Ziel (host only in log).")
        for r in _wh.audit_url(url):
            sev = r.severity if r.status == "fail" else "info"
            status = ("ZU BESTÄTIGEN" if r.status == "fail"
                      else ("BESTÄTIGT(PASSIV)" if r.status == "pass" else "REFERENZ"))
            findings.append(AgentFinding(
                agent=self.name, title=r.title,
                category=f"blue-webharden-{r.status}", severity=sev,
                asset=url.split("/")[2] if "://" in url else url,
                description=r.detail + (f" · {r.recommendation}" if r.recommendation else ""),
                evidence=r.to_dict(), status=status,
                dedup_key=f"blue-webharden:{r.check_id}",
            ))
        return findings
