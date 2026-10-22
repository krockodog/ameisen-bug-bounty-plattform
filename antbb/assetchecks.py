"""Opt-in ungefaehrliche Checks (TLS + HTTP-Security-Header).

STRIKT NICHT-OFFENSIV: nur rein LESENDE, passive Pruefungen.
  * TLS: Zertifikat (Subject/Issuer/Gueltigkeit), ausgehandelte Protokoll-
    Version und Cipher-Suite – via stdlib ssl-Handshake. Kein Payload.
  * HTTP-Security-Header: ein einzelnes GET, Auswertung der Response-Header
    (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    Permissions-Policy). Kein Body-Fuzzing, keine Manipulation.

DEFAULT-DENY: Ein Check laeuft NUR gegen Assets, die der Nutzer ausdruecklich
als EIGEN bestaetigt hat (owned_assets.confirmed_owner=1). Ohne bestaetigtes
Asset wird NICHTS ausgefuehrt (AssetOwnershipError). Das fuegt sich in das
bestehende Oversight-/Scope-Modell ein (keine aktiven/offensiven Payloads).
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional

from .store import Store

#: Sicherheits-Header, die ausgewertet werden (rein informativ).
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


class AssetOwnershipError(PermissionError):
    """Wird geworfen, wenn das Asset nicht als eigenes bestaetigt ist."""


def _require_confirmed(store: Store, asset_id: int):
    row = store.get_owned_asset(asset_id)
    if not row:
        raise AssetOwnershipError(f"Asset #{asset_id} existiert nicht.")
    if not row["confirmed_owner"]:
        raise AssetOwnershipError(
            "BLOCKIERT (default-deny): Asset ist NICHT als eigenes Asset "
            "bestaetigt. Bitte zuerst die Ownership-Bestaetigung (Opt-in) setzen."
        )
    return row


def check_tls(host: str, port: int = 443, timeout: float = 6.0) -> dict[str, Any]:
    """Rein lesender TLS-Handshake. Gibt Zertifikat-/Protokoll-/Cipher-Infos."""
    result: dict[str, Any] = {"host": host, "port": port, "kind": "tls"}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                result["subject"] = _flatten_name(cert.get("subject"))
                result["issuer"] = _flatten_name(cert.get("issuer"))
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                result["valid"] = _cert_time_valid(cert)
                san = cert.get("subjectAltName") or []
                result["san"] = [v for (_t, v) in san]
                result["ok"] = True
    except ssl.SSLCertVerificationError as exc:
        result.update(ok=False, error=f"Zertifikatspruefung fehlgeschlagen: {exc}")
    except (socket.timeout, OSError) as exc:
        result.update(ok=False, error=f"Verbindung fehlgeschlagen: {exc}")
    except Exception as exc:  # defensiv: nie crashen
        result.update(ok=False, error=f"{type(exc).__name__}: {exc}")
    return result


def check_headers(host: str, port: int = 443, timeout: float = 6.0,
                  scheme: Optional[str] = None) -> dict[str, Any]:
    """Einzelnes GET; wertet Security-Header aus. Kein Fuzzing, keine Payloads."""
    import httpx
    scheme = scheme or ("https" if int(port) in (443, 8443) else "http")
    url = f"{scheme}://{host}:{port}/" if port not in (80, 443) else f"{scheme}://{host}/"
    result: dict[str, Any] = {"host": host, "port": port, "kind": "headers", "url": url}
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        present, missing = {}, []
        for h in SECURITY_HEADERS:
            if h in headers:
                present[h] = headers[h]
            else:
                missing.append(h)
        result.update(ok=True, status=resp.status_code,
                      server=headers.get("server", ""),
                      present=present, missing=missing,
                      score=f"{len(present)}/{len(SECURITY_HEADERS)} Security-Header gesetzt")
    except Exception as exc:  # defensiv
        result.update(ok=False, error=f"{type(exc).__name__}: {exc}")
    return result


def run_check(store: Store, asset_id: int, kind: str = "tls") -> dict[str, Any]:
    """Fuehrt einen Check NUR gegen ein bestaetigtes eigenes Asset aus.

    kind: 'tls' | 'headers'. Persistiert das Ergebnis in asset_check_runs.
    """
    row = _require_confirmed(store, asset_id)
    host, port = row["host"], int(row["port"])
    kind = (kind or "tls").lower()
    if kind == "headers":
        res = check_headers(host, port)
    elif kind == "tls":
        res = check_tls(host, port)
    else:
        raise ValueError(f"Unbekannter Check-Typ '{kind}' (erlaubt: tls, headers).")
    summary = res.get("error") or res.get("score") or (
        f"{res.get('protocol','?')} / {res.get('cipher','?')}" if kind == "tls" else "")
    store.add_asset_check_run(asset_id, host, port, kind,
                              ok=bool(res.get("ok")), summary=str(summary)[:300],
                              result=res)
    return res


def _flatten_name(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for (k, v) in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _cert_time_valid(cert: dict) -> bool:
    try:
        na = cert.get("notAfter")
        nb = cert.get("notBefore")
        fmt = "%b %d %H:%M:%S %Y %Z"
        now = datetime.now(timezone.utc)
        after = datetime.strptime(na, fmt).replace(tzinfo=timezone.utc)
        before = datetime.strptime(nb, fmt).replace(tzinfo=timezone.utc)
        return before <= now <= after
    except Exception:
        return False
