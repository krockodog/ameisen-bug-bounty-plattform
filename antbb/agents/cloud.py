"""Cloud-Ameise: passive Cloud-/Storage-Exposure-Heuristik (defensiv).

Sucht in erreichbaren Seiten nach referenzierten Cloud-Storage-Endpunkten
(S3/GCS/Azure/R2) und erkennt Cloud-Provider-Hinweise in Antwort-Headern.
KEINE aktive Bucket-Enumeration, keine Objekt-Downloads – rein beobachtend.
"""
from __future__ import annotations

import re

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for

_STORAGE_RE = re.compile(
    r"(?i)https?://[a-z0-9.\-]*"
    r"(s3[.\-][a-z0-9.\-]*amazonaws\.com|[a-z0-9\-]+\.s3\.amazonaws\.com|"
    r"storage\.googleapis\.com|[a-z0-9\-]+\.blob\.core\.windows\.net|"
    r"[a-z0-9\-]+\.r2\.cloudflarestorage\.com)[^\"'\s<>)]*"
)
_CLOUD_HEADERS = ["x-amz-request-id", "x-amz-id-2", "x-goog-generation",
                  "x-ms-request-id", "x-served-by", "via"]


class CloudHunterAnt(AntAgent):
    name = "cloud"
    role = "Cloud-Security: referenzierte Storage-Endpunkte + Provider-Hinweise (passiv, defensiv)"
    specialty = "cloud-hunter"
    phases = ("scan",)
    playbooks = (
        Playbook("storage-reference-detect", "defensive", False,
                 ["s3-url", "gcs-url", "azure-blob-url", "r2-url"],
                 "Im Markup referenzierte Cloud-Storage-Endpunkte erkennen."),
        Playbook("cloud-header-hints", "defensive", False,
                 ["x-amz", "x-goog", "x-ms", "x-served-by", "via"],
                 "Cloud-Provider-Hinweise aus Antwort-Headern lesen."),
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
                resp = await net.http_get(base + "/")
                if resp is None:
                    continue
                seen.add(base)
                body = (resp.text or "")[:200000]
                refs = sorted(set(m.group(0) for m in _STORAGE_RE.finditer(body)))[:12]
                if refs:
                    findings.append(AgentFinding(
                        agent=self.name, title="Referenzierte Cloud-Storage-Endpunkte",
                        category="storage-exposure", severity="low", asset=base,
                        description=(f"{len(refs)} Cloud-Storage-URL(s) im Markup referenziert. "
                                     "Nur beobachtet, keine Bucket-Enumeration."),
                        evidence={"references": refs, "status": resp.status_code},
                        dedup_key=f"storage-ref:{base}",
                    ))
                hints = {h: resp.headers[h] for h in _CLOUD_HEADERS if h in resp.headers}
                if hints:
                    findings.append(AgentFinding(
                        agent=self.name, title="Cloud-Provider-Hinweise in Headern",
                        category="storage-exposure", severity="info", asset=base,
                        description="Antwort-Header deuten auf Cloud-/CDN-Provider hin.",
                        evidence={"headers": hints, "status": resp.status_code},
                        dedup_key=f"cloud-hdr:{base}",
                    ))
        return findings
