"""Generischer OAuth-2.0-Baustein + verschlüsselter Token-Store.

Zweck: ein EINZIGER, erweiterbarer Baustein, den jeder OAuth-fähige Provider
nutzt. Er stellt den Authorization-Code-Flow (mit optionalem PKCE) bereit und
legt Access-/Refresh-Tokens VERSCHLÜSSELT ab (Fernet, Key lokal in data/).

Wichtig / Ehrlichkeit:
  * Es werden KEINE OAuth-Endpunkte, Client-IDs oder Scopes erfunden. Die
    konkreten URLs kommen pro Provider aus der Config (llm.providers.*.oauth).
  * Recherche-Stand (offizielle Docs):
      - OpenAI: "Sign in with ChatGPT" bietet einen echten Auth-Code+PKCE-Flow
        (auth.openai.com) für berechtigte Dritt-/Open-Source-Apps. Der volle
        Flow nutzt dynamische Client-Registrierung – die client_id entsteht zur
        Laufzeit, wird hier nicht hartkodiert.
      - MiniMax: KEIN OAuth für API-Zugang → Key-Modus (Fallback).
      - Kimi/Moonshot Open Platform: KEIN Auth-Code-OAuth für API-Zugang
        (API-Key). Nur "Kimi Code" (managed service) hat Device-Code-OAuth.
    Deshalb ist dieser Baustein generisch gebaut und greift nur dort real, wo
    ein Provider in der Config einen dokumentierten oauth-Block hat.

Token-Werte werden NIEMALS geloggt, geechot oder im Klartext gespeichert.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional

from .config import DATA_DIR

_KEY_FILE = DATA_DIR / "oauth.key"
_STORE_FILE = DATA_DIR / "oauth_tokens.enc"


# ──────────────────────────── verschlüsselter Store ────────────────────────
def _fernet():
    from cryptography.fernet import Fernet
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        _KEY_FILE.write_bytes(key)
        try:
            os.chmod(_KEY_FILE, 0o600)
        except OSError:
            pass
    return Fernet(key)


class TokenStore:
    """Fernet-verschlüsselter Token-Store (Datei in data/).

    Struktur im Klartext (nur im Speicher): {provider: {access_token,
    refresh_token, expires_at, scope, token_type}}. Auf der Platte liegt
    ausschließlich das verschlüsselte Blob.
    """

    def _load_all(self) -> dict[str, Any]:
        if not _STORE_FILE.exists():
            return {}
        try:
            raw = _fernet().decrypt(_STORE_FILE.read_bytes())
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _save_all(self, data: dict[str, Any]) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        blob = _fernet().encrypt(json.dumps(data).encode("utf-8"))
        _STORE_FILE.write_bytes(blob)
        try:
            os.chmod(_STORE_FILE, 0o600)
        except OSError:
            pass

    def save(self, provider: str, tokens: dict[str, Any]) -> None:
        data = self._load_all()
        data[provider] = tokens
        self._save_all(data)

    def get(self, provider: str) -> Optional[dict[str, Any]]:
        return self._load_all().get(provider)

    def delete(self, provider: str) -> None:
        data = self._load_all()
        if provider in data:
            del data[provider]
            self._save_all(data)

    def has_valid(self, provider: str) -> bool:
        """True, wenn ein (nicht abgelaufenes) Access-Token vorliegt."""
        tok = self.get(provider)
        if not tok or not tok.get("access_token"):
            return False
        exp = tok.get("expires_at")
        if exp and time.time() > float(exp):
            # abgelaufen – gilt nur dann als gültig, wenn ein Refresh-Token da ist
            return bool(tok.get("refresh_token"))
        return True


# ──────────────────────────── OAuth-Provider ───────────────────────────────
@dataclass
class OAuthProvider:
    """Generischer Authorization-Code-Flow (optional mit PKCE).

    Erfindet nichts: authorize_url/token_url/scopes/redirect_uri kommen aus der
    Config. Ohne konfigurierten oauth-Block ist ``available`` False.
    """
    name: str
    authorize_url: str = ""
    token_url: str = ""
    redirect_uri: str = ""
    scopes: str = ""
    client_id: str = ""          # wird NICHT erfunden; ggf. leer bis Registrierung
    client_secret_env: str = ""  # NAME der Env-Var, nie der Wert

    # transiente Flow-States (state → pkce_verifier), nur im Speicher
    _pending: dict[str, str] = None  # type: ignore

    def __post_init__(self):
        if self._pending is None:
            self._pending = {}

    @property
    def available(self) -> bool:
        return bool(self.authorize_url and self.token_url)

    def build_authorize_url(self, use_pkce: bool = True) -> tuple[str, str]:
        """Baut die Authorize-URL + gibt den state zurück (für die Callback-
        Validierung). Ohne konfigurierte URLs wird ein klarer Fehler geworfen."""
        if not self.available:
            raise OAuthError(
                f"Provider '{self.name}' hat keinen dokumentierten OAuth-Flow "
                f"konfiguriert (kein authorize_url/token_url)."
            )
        from urllib.parse import urlencode
        state = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
        }
        if self.client_id:
            params["client_id"] = self.client_id
        if use_pkce:
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            self._pending[state] = verifier
        else:
            self._pending[state] = ""
        return f"{self.authorize_url}?{urlencode(params)}", state

    def exchange_code(self, code: str, state: str,
                      store: Optional[TokenStore] = None) -> dict[str, Any]:
        """Tauscht den Authorization-Code gegen Tokens und speichert sie
        verschlüsselt. Gibt Metadaten OHNE Token-Werte zurück."""
        import httpx
        if state not in self._pending:
            raise OAuthError("Unbekannter/abgelaufener state – Flow abgebrochen.")
        verifier = self._pending.pop(state)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        if self.client_id:
            data["client_id"] = self.client_id
        if verifier:
            data["code_verifier"] = verifier
        secret = os.environ.get(self.client_secret_env) if self.client_secret_env else None
        if secret:
            data["client_secret"] = secret
        resp = httpx.post(self.token_url, data=data, timeout=30.0)
        if resp.status_code != 200:
            raise OAuthError(f"Token-Exchange HTTP {resp.status_code}: "
                             f"{resp.text[:300]}")
        tok = resp.json()
        saved = _normalize_tokens(tok)
        (store or TokenStore()).save(self.name, saved)
        return {"ok": True, "provider": self.name,
                "scope": saved.get("scope", ""),
                "expires_at": saved.get("expires_at")}

    def refresh(self, store: Optional[TokenStore] = None) -> dict[str, Any]:
        """Erneuert das Access-Token via Refresh-Token (falls vorhanden)."""
        import httpx
        store = store or TokenStore()
        tok = store.get(self.name)
        if not tok or not tok.get("refresh_token"):
            raise OAuthError("Kein Refresh-Token vorhanden.")
        data = {
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
        }
        if self.client_id:
            data["client_id"] = self.client_id
        resp = httpx.post(self.token_url, data=data, timeout=30.0)
        if resp.status_code != 200:
            raise OAuthError(f"Refresh HTTP {resp.status_code}: {resp.text[:300]}")
        saved = _normalize_tokens(resp.json())
        # Refresh-Token ggf. beibehalten, wenn der Server keins neu liefert
        saved.setdefault("refresh_token", tok.get("refresh_token"))
        store.save(self.name, saved)
        return {"ok": True, "provider": self.name}


class OAuthError(RuntimeError):
    """Sauberer, nicht-geheimnis-tragender OAuth-Fehler."""


def _normalize_tokens(tok: dict[str, Any]) -> dict[str, Any]:
    out = {
        "access_token": tok.get("access_token", ""),
        "refresh_token": tok.get("refresh_token", ""),
        "token_type": tok.get("token_type", "Bearer"),
        "scope": tok.get("scope", ""),
    }
    expires_in = tok.get("expires_in")
    if expires_in:
        try:
            out["expires_at"] = time.time() + float(expires_in)
        except (TypeError, ValueError):
            pass
    return out


def provider_from_config(name: str, redirect_base: str = "http://127.0.0.1:8000") -> "OAuthProvider":
    """Baut einen OAuthProvider aus der Config (llm.providers.<name>.oauth).

    Erfindet nichts: Wenn kein oauth-Block existiert, ist der zurückgegebene
    Provider ``available=False`` und der Flow verweigert sauber den Start.
    """
    from .config import llm_config
    providers = (llm_config().get("providers", {}) or {})
    p = providers.get(name, {}) or {}
    o = p.get("oauth", {}) or {}
    redirect_path = o.get("redirect_path", f"/auth/{name}/callback")
    return OAuthProvider(
        name=name,
        authorize_url=o.get("authorize_url", ""),
        token_url=o.get("token_url", ""),
        redirect_uri=redirect_base.rstrip("/") + redirect_path,
        scopes=o.get("scopes", ""),
        client_id=o.get("client_id", ""),           # NICHT erfunden; meist leer
        client_secret_env=o.get("client_secret_env", ""),
    )
