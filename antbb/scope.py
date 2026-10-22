"""Scope-Verwaltung und Allowlist-Prüfung.

Jede aktive Aktion muss gegen die Allowlist eines Targets geprüft werden.
Out-of-Scope-Einträge (allowed=0) haben Vorrang und blockieren immer.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from typing import Optional
from urllib.parse import urlparse

from .store import Store


def _host_of(asset: str) -> str:
    if "://" in asset:
        return urlparse(asset).hostname or asset
    # host:port oder host/path
    return asset.split("/")[0].split(":")[0]


def _match_domain(pattern: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern == host:
        return True
    # *.example.com matcht sub.example.com, aber auch example.com
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, pattern)


def _match_ip(pattern: str, asset: str) -> bool:
    host = _host_of(asset)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    try:
        if "/" in pattern:
            return ip in ipaddress.ip_network(pattern, strict=False)
        return ip == ipaddress.ip_address(pattern)
    except ValueError:
        return False


def _match_path(pattern: str, asset: str) -> bool:
    if "://" in asset:
        path = urlparse(asset).path or "/"
    elif "/" in asset:
        path = "/" + asset.split("/", 1)[1]
    else:
        path = "/"
    return fnmatch.fnmatch(path, pattern)


def _match_url(pattern: str, asset: str) -> bool:
    return fnmatch.fnmatch(asset.lower(), pattern.lower())


def _match(kind: str, value: str, asset: str) -> bool:
    if kind == "domain":
        return _match_domain(value, _host_of(asset))
    if kind == "ip":
        return _match_ip(value, asset)
    if kind == "path":
        return _match_path(value, asset)
    if kind == "url":
        return _match_url(value, asset)
    return False


class ScopeResult:
    def __init__(self, allowed: bool, reason: str, matched: Optional[str] = None):
        self.allowed = allowed
        self.reason = reason
        self.matched = matched

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"ScopeResult(allowed={self.allowed}, reason={self.reason!r})"


def check_asset(store: Store, target_id: int, asset: str) -> ScopeResult:
    """Prüft, ob `asset` für `target_id` in-scope ist.

    Reihenfolge:
      1. Explizite Out-of-Scope-Treffer blockieren sofort.
      2. In-Scope-Treffer erlauben.
      3. Kein Treffer => blockiert (default-deny).
    """
    scopes = store.list_scopes(target_id)
    if not scopes:
        return ScopeResult(False, "Keine Scope-Einträge definiert (default-deny).")

    # Out-of-Scope zuerst
    for s in scopes:
        if not s["allowed"] and _match(s["kind"], s["value"], asset):
            return ScopeResult(
                False, f"Asset ist explizit OUT-OF-SCOPE ({s['kind']}:{s['value']}).",
                matched=f"{s['kind']}:{s['value']}",
            )
    for s in scopes:
        if s["allowed"] and _match(s["kind"], s["value"], asset):
            return ScopeResult(
                True, f"Asset ist in-scope ({s['kind']}:{s['value']}).",
                matched=f"{s['kind']}:{s['value']}",
            )
    return ScopeResult(False, "Asset passt auf keinen In-Scope-Eintrag (default-deny).")


def allowed_assets(store: Store, target_id: int) -> list[str]:
    """Liefert die reinen In-Scope-Werte als Angriffsflächen-Hinweis für Agenten."""
    return [s["value"] for s in store.list_scopes(target_id) if s["allowed"]]
