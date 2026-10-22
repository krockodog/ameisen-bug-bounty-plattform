"""Optionale Authentifizierung / Multi-User fuer den antbb-Webserver.

Standard: AUS (Einzelnutzer-Betrieb) – bestehende Installationen brechen nicht.
Aktivierung ueber Umgebungsvariable ANTBB_AUTH=1 (bzw. true/on/yes).
Mit ANTBB_AUTH=0 bleibt es explizit deaktiviert.

Sicherheit:
  * Passwoerter werden NUR als gesalzener PBKDF2-HMAC-SHA256-Hash gespeichert
    (stdlib hashlib, keine Fremd-Dependency), NIE im Klartext, NIE geloggt.
  * Session ueber ein zufaelliges, serverseitig gespeichertes Token
    (secrets.token_urlsafe) in einem HttpOnly-Cookie. Kein Secret im Cookie-Wert
    ausser dem opaken Token.
  * Rollen: admin | viewer. Human-only-Aktionen (brain-reset/delete) bleiben
    strikt admin-geschuetzt.
  * Erster Admin-Bootstrap via ENV (ANTBB_ADMIN_USER/ANTBB_ADMIN_PASSWORD) oder
    CLI – NICHT hartkodiert.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional

from .store import Store

COOKIE_NAME = "antbb_session"
_PW_ITER = 240000
_TRUE = {"1", "true", "yes", "on"}


def auth_enabled() -> bool:
    """True, wenn ANTBB_AUTH truthy gesetzt ist. Default (unset/0) -> AUS."""
    return os.environ.get("ANTBB_AUTH", "").strip().lower() in _TRUE


# ---- Passwort-Hashing (PBKDF2-HMAC-SHA256, stdlib) ------------------------
def hash_password(password: str, salt: Optional[str] = None,
                  iterations: int = _PW_ITER) -> tuple[str, str, int]:
    """Gibt (hash_hex, salt_hex, iterations) zurueck. Klartext wird nie geloggt."""
    if not password:
        raise ValueError("Leeres Passwort ist nicht erlaubt.")
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt_bytes, iterations)
    return dk.hex(), salt_bytes.hex(), iterations


def verify_password(password: str, pw_hash: str, pw_salt: str,
                    iterations: int = _PW_ITER) -> bool:
    """Konstantzeit-Vergleich. Nie Klartext/Hash loggen."""
    try:
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"),
                                 bytes.fromhex(pw_salt), int(iterations))
    except Exception:
        return False
    return hmac.compare_digest(dk.hex(), pw_hash or "")


# ---- Nutzerverwaltung -----------------------------------------------------
def create_user(store: Store, username: str, password: str,
                role: str = "viewer") -> int:
    username = (username or "").strip()
    if not username:
        raise ValueError("Leerer Benutzername.")
    h, salt, it = hash_password(password)
    return store.create_user(username, h, salt, role=role, pw_iter=it)


def set_password(store: Store, username: str, password: str) -> None:
    h, salt, it = hash_password(password)
    store.update_user_password(username, h, salt, pw_iter=it)


def authenticate(store: Store, username: str, password: str):
    """Gibt die User-Row bei Erfolg zurueck, sonst None."""
    row = store.get_user((username or "").strip())
    if not row or not row["active"]:
        return None
    if verify_password(password, row["pw_hash"], row["pw_salt"],
                       row["pw_iter"] if "pw_iter" in row.keys() else _PW_ITER):
        return row
    return None


def start_session(store: Store, row) -> str:
    token = secrets.token_urlsafe(32)
    store.create_session(token, row["username"], row["role"])
    return token


def session_user(store: Store, token: Optional[str]):
    """Gibt die Session-Row ({username, role, ...}) oder None zurueck."""
    return store.get_session(token) if token else None


def bootstrap_admin(store: Store) -> Optional[str]:
    """Legt bei aktiver Auth den ersten Admin aus ENV an, falls noch keiner da.

    ANTBB_ADMIN_USER / ANTBB_ADMIN_PASSWORD. Gibt den Benutzernamen zurueck,
    wenn ein Admin angelegt wurde, sonst None. Das Passwort wird NIE geloggt.
    """
    if store.count_users() > 0:
        return None
    user = os.environ.get("ANTBB_ADMIN_USER", "").strip()
    pw = os.environ.get("ANTBB_ADMIN_PASSWORD", "")
    if not user or not pw:
        return None
    try:
        create_user(store, user, pw, role="admin")
        return user
    except Exception:
        return None


# ---- CLI: Erst-Admin / Benutzer anlegen (NICHT hartkodiert) ---------------
def _cli(argv: Optional[list] = None) -> int:
    """Minimale CLI: `python -m antbb.webauth add-user <name> [--role admin]`.

    Das Passwort wird interaktiv (getpass) ODER aus ANTBB_NEW_PASSWORD gelesen,
    NIE als Argument (damit es nicht in der Prozessliste/History landet).
    """
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="antbb.webauth")
    sub = ap.add_subparsers(dest="cmd", required=True)
    au = sub.add_parser("add-user", help="Benutzer anlegen/aktualisieren")
    au.add_argument("username")
    au.add_argument("--role", choices=["admin", "viewer"], default="viewer")
    sub.add_parser("list-users", help="Benutzer auflisten")
    args = ap.parse_args(argv)
    store = Store()
    try:
        if args.cmd == "list-users":
            for u in store.list_users():
                print(f"{u['username']}\t{u['role']}\t"
                      f"{'aktiv' if u['active'] else 'inaktiv'}")
            return 0
        if args.cmd == "add-user":
            pw = os.environ.get("ANTBB_NEW_PASSWORD")
            if not pw:
                pw = getpass.getpass("Passwort: ")
            if store.get_user(args.username):
                set_password(store, args.username, pw)
                store.set_user_role(args.username, args.role)
                print(f"Benutzer '{args.username}' aktualisiert (Rolle {args.role}).")
            else:
                create_user(store, args.username, pw, role=args.role)
                print(f"Benutzer '{args.username}' angelegt (Rolle {args.role}).")
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
