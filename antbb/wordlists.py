"""Zentrale Wortlisten-Konfiguration (SecLists / /usr/share/wordlists).

Graceful degrade: existiert eine Liste am Laufort nicht (z.B. auf der Box),
liefert `resolve()` None und die aufrufenden Adapter bleiben ehrlich-leer –
nie wird eine nicht vorhandene Liste „erfunden".

Harte Regel (nicht-destruktiv): rockyou & Co. sind NUR für autorisierte,
offline Hash-Cracking-Kontexte gedacht und werden NIE automatisch für
Passwort-Brute-Force gegen echte Logins im Webscan verwendet. Die Web-Content-
Discovery (gobuster/ffuf) nutzt ausschließlich Pfad-/Verzeichnis-Listen.
"""
from __future__ import annotations

import os

#: Basisverzeichnisse, in denen Wortlisten gesucht werden (Kali-Standard).
WORDLIST_DIRS = [
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/usr/share/wordlists",
]

#: Logische Namen → Kandidatenpfade (erste existierende gewinnt).
_CANDIDATES: dict[str, list[str]] = {
    # Web-Content-/Verzeichnis-Discovery (nicht-destruktiv).
    "web-content-common": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "web-content-medium": [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "web-content-big": [
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/wordlists/dirb/big.txt",
    ],
    "dns-subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
    ],
    # NUR für autorisiertes Offline-Hash-Cracking – NICHT im Webscan.
    "rockyou": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    ],
}

#: Env-Override: ANTBB_WORDLIST_<LOGISCHER_NAME_IN_GROSS_MIT_UNDERSCORE>
_ENV_PREFIX = "ANTBB_WORDLIST_"


def _env_key(name: str) -> str:
    return _ENV_PREFIX + name.upper().replace("-", "_")


def resolve(name: str) -> str | None:
    """Liefert den Pfad der ersten existierenden Wortliste für `name` oder None.

    Env-Override hat Vorrang (falls die Datei existiert).
    """
    env = os.environ.get(_env_key(name))
    if env and os.path.isfile(env):
        return env
    for cand in _CANDIDATES.get(name, []):
        if os.path.isfile(cand):
            return cand
    return None


def default_content_wordlist() -> str | None:
    """Sinnvolle Default-Liste für Content-Discovery (gobuster/ffuf)."""
    for name in ("web-content-common", "web-content-medium", "web-content-big"):
        p = resolve(name)
        if p:
            return p
    return None


def status() -> dict:
    """Übersicht, welche logischen Listen am Laufort verfügbar sind (für Registry).

    Enthält NIE Inhalte – nur Pfade/Verfügbarkeit.
    """
    out = {}
    for name in _CANDIDATES:
        p = resolve(name)
        out[name] = {"available": bool(p), "path": p or ""}
    out["_dirs_present"] = [d for d in WORDLIST_DIRS if os.path.isdir(d)]
    return out
