"""Blue-Soldat: TLS-/Zertifikats-Posture auf eigenen/autorisierten Assets rein lesend prüfen (Ablauf, Protokolle).

Rein lesend / non-destruktiv. Aktive Änderungen nur oversight-gated (Scaffold).
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task


class TlsPostureAnt(BlueAgent):
    name = "blue-tlsposture"
    specialty = "blue-tls-posture"
    role = ("TLS-/Zertifikats-Posture auf eigenen/autorisierten Assets rein lesend prüfen (Ablauf, Protokolle).")
    blue_phases = ("assess", "harden")
    playbooks = (
        Playbook("tls-cert-inventory", "defensive", False,
                 ["openssl-s-client", "cert-expiry"],
                 "Zertifikate am Ziel rein lesend lesen und Ablaufdatum melden (nur Scope).",
                 tasks=["TLS-Handshake am Scope-Ziel", "notAfter lesen",
                        "Tage bis Ablauf berechnen", "Kritisch <14 Tage"]),
        Playbook("tls-protocol-review", "defensive", False,
                 ["min-tls-version", "weak-ciphers-note"],
                 "Protokoll-/Cipher-Hinweise als Report (ohne aktives Brute-Force).",
                 tasks=["TLS-Version beobachten", "TLS 1.2+ empfehlen",
                        "Schwache Protokolle melden"]),
    )

    def _host(self, task: Task) -> str:
        params = task.params or {}
        for key in ("url", "host", "target_url"):
            v = (params.get(key) or "").strip()
            if v:
                if "://" in v:
                    v = v.split("://", 1)[1].split("/")[0].split(":")[0]
                return v
        for a in task.assets or []:
            if isinstance(a, str) and a and a not in ("localhost", "monitoring", "decoy"):
                if "://" in a:
                    a = a.split("://", 1)[1].split("/")[0].split(":")[0]
                return a
        # Demo-Fallback nur für Framework-Demos; Live setzt Scope-Assets.
        return "127.0.0.1"

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-tlsposture] 🔐 TLS-Posture (read-only, scope-bound).")
        host = self._host(task)
        import ssl, socket
        from datetime import datetime, timezone
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    ver = ssock.version()
            not_after = cert.get("notAfter") if cert else None
            days = None
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
            sev = "high" if days is not None and days < 14 else (
                  "medium" if days is not None and days < 45 else "info")
            findings.append(AgentFinding(
                agent=self.name, title=f"TLS {host}: {ver or '?'}, Ablauf in {days}d",
                category="blue-tls-cert", severity=sev, asset=host,
                description=f"Zertifikat notAfter={not_after}. Rein lesender Handshake.",
                evidence={"tls_version": ver, "not_after": not_after, "days_left": days,
                          "subject": str(cert.get("subject"))[:200] if cert else None},
                status="BESTÄTIGT(PASSIV)", dedup_key=f"blue-tls:{host}:cert",
            ))
            findings.append(AgentFinding(
                agent=self.name, title=f"TLS-Protokoll-Hinweis {host}",
                category="blue-tls-proto", severity="info", asset=host,
                description="Empfehlung: TLS 1.2+ erzwingen, schwache Ciphers abschalten.",
                evidence={"observed_version": ver}, status="REFERENZ",
                dedup_key=f"blue-tls:{host}:proto",
            ))
        except Exception as e:
            findings.append(AgentFinding(
                agent=self.name, title=f"TLS-Check {host} nicht möglich",
                category="blue-tls-na", severity="info", asset=host,
                description=f"Handshake fehlgeschlagen oder Port 443 nicht erreichbar: {e}",
                evidence={"error": str(e)[:200]}, status="REFERENZ",
                dedup_key=f"blue-tls:{host}:na",
            ))
        return findings
