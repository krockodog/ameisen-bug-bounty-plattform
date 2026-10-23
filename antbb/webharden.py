"""Web-Härtungs-Checks (Headers, Cookies, TLS-Hinweise) – rein lesend.

Prüft HTTP-Security-Header, Cookie-Flags und grundlegende TLS-Hinweise
gegen ein Ziel. Ohne erreichbares Ziel → honest-empty. Keine Secrets.
"""
from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("antbb.webharden")

REQUIRED_HEADERS = [
    ("strict-transport-security", "HSTS fehlt", "medium"),
    ("content-security-policy", "CSP fehlt", "medium"),
    ("x-content-type-options", "X-Content-Type-Options fehlt", "low"),
    ("x-frame-options", "X-Frame-Options / frame-ancestors fehlt", "low"),
    ("referrer-policy", "Referrer-Policy fehlt", "low"),
    ("permissions-policy", "Permissions-Policy fehlt", "info"),
]


@dataclass
class WebCheck:
    check_id: str
    title: str
    status: str          # pass | fail | info | skip
    severity: str
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _fetch_headers(url: str, timeout: float = 8.0) -> tuple[dict, dict]:
    """Holt Response-Header via urllib (stdlib). Bei Fehler → ({}, meta)."""
    import urllib.request
    meta = {"url": url, "ok": False}
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "antbb-webharden/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            meta.update({"ok": True, "status": resp.status,
                         "final_url": resp.geturl()})
            set_cookie = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
            if set_cookie:
                meta["set_cookie"] = set_cookie
            elif "set-cookie" in headers:
                meta["set_cookie"] = [headers["set-cookie"]]
            return headers, meta
    except Exception as exc:
        meta["error"] = str(exc)[:200]
        return {}, meta


def _tls_probe(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    out = {"host": host, "port": port, "ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ver = ssock.version()
                out.update({
                    "ok": True, "tls_version": ver,
                    "cipher": (ssock.cipher() or (None,))[0],
                    "not_after": (cert or {}).get("notAfter", ""),
                    "subject": str((cert or {}).get("subject", ""))[:200],
                })
    except Exception as exc:
        out["error"] = str(exc)[:200]
    return out


def audit_url(url: str, timeout: float = 8.0) -> list[WebCheck]:
    """Web-Härtungs-Audit gegen eine URL. Ohne URL → []."""
    if not url or not str(url).strip():
        return []
    url = str(url).strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    checks: list[WebCheck] = []

    headers, meta = _fetch_headers(url, timeout=timeout)
    if not meta.get("ok"):
        checks.append(WebCheck(
            check_id="web-reachability", title="Ziel nicht erreichbar",
            status="skip", severity="info",
            detail=meta.get("error") or "kein HTTP-Response",
            evidence=meta,
        ))
        return checks

    for hdr, title, sev in REQUIRED_HEADERS:
        present = hdr in headers
        # frame-ancestors in CSP zählt als XFO-Ersatz
        if hdr == "x-frame-options" and not present:
            csp = headers.get("content-security-policy", "")
            if "frame-ancestors" in csp.lower():
                present = True
        checks.append(WebCheck(
            check_id=f"hdr-{hdr}",
            title=title if not present else f"{hdr} gesetzt",
            status="pass" if present else "fail",
            severity=sev if not present else "info",
            detail=(headers.get(hdr, "")[:240] if present else "Header fehlt"),
            recommendation=("Header setzen gemäß OWASP Secure Headers."
                            if not present else ""),
            evidence={"header": hdr, "value": headers.get(hdr, "")[:240],
                      "url": meta.get("final_url") or url},
        ))

    # Cookie-Flags
    cookies = meta.get("set_cookie") or []
    if cookies:
        for i, c in enumerate(cookies[:8]):
            cl = c.lower()
            missing = [f for f in ("httponly", "secure", "samesite") if f not in cl]
            # Secure nur bei HTTPS sinnvoll
            if parsed.scheme != "https" and "secure" in missing:
                missing = [m for m in missing if m != "secure"]
            ok = not missing
            checks.append(WebCheck(
                check_id=f"cookie-{i}",
                title=("Cookie-Flags ok" if ok else f"Cookie-Flags fehlen: {', '.join(missing)}"),
                status="pass" if ok else "fail",
                severity="low" if not ok else "info",
                detail=c[:200],
                recommendation=("HttpOnly; Secure; SameSite=Lax/Strict setzen."
                                if not ok else ""),
                evidence={"cookie_excerpt": c[:200], "missing": missing},
            ))
    else:
        checks.append(WebCheck(
            check_id="cookie-none", title="Keine Set-Cookie im Response",
            status="info", severity="info",
            detail="Kein Cookie gesetzt – Cookie-Flag-Check übersprungen.",
            evidence={"url": url},
        ))

    # TLS
    if parsed.scheme == "https" and host:
        tls = _tls_probe(host, parsed.port or 443, timeout=min(timeout, 6.0))
        if tls.get("ok"):
            ver = tls.get("tls_version") or ""
            weak = ver in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2")
            checks.append(WebCheck(
                check_id="tls-version",
                title=("Schwaches TLS" if weak else f"TLS ok ({ver})"),
                status="fail" if weak else "pass",
                severity="high" if weak else "info",
                detail=f"Version={ver} Cipher={tls.get('cipher')}",
                recommendation=("TLS 1.2+ erzwingen, alte Protokolle abschalten."
                                if weak else ""),
                evidence=tls,
            ))
        else:
            checks.append(WebCheck(
                check_id="tls-version", title="TLS-Probe fehlgeschlagen",
                status="skip", severity="info",
                detail=tls.get("error") or "", evidence=tls,
            ))
    return checks


def capability_summary() -> dict:
    return {"checks": [h[0] for h in REQUIRED_HEADERS] + ["cookie-flags", "tls-version"],
            "status": "installed"}
