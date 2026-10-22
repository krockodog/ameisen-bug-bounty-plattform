"""Smoke-Test für das einheitliche LLM-Auth-Modell (API-Key + OAuth).

Prüft (ohne Netzaufrufe, ohne echte Keys/Tokens):
  * Auth-Methoden-Registry lädt für alle Provider (methods/selected/flow).
  * PKCE-Challenge-Generierung funktioniert (S256, base64url ohne Padding).
  * Authorization-Code-Flow startet nur mit konfigurierten URLs (openai), sonst
    sauberer OAuthError — KEIN Crash.
  * Device-Code-Flow ist für den konfigurierten Provider (moonshot/Kimi Code)
    verfügbar; ohne Config → available=False, sauberer OAuthError.
  * Fehlende OAuth-Credentials → sauberer Fehler, kein Crash.
"""
import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antbb import oauth
from antbb import llm as llm_mod


def test_auth_overview_loads():
    rows = oauth.auth_overview()
    names = {r["provider"] for r in rows}
    assert {"openai", "moonshot", "minimax", "ollama"} <= names
    for r in rows:
        assert r["methods"], f"{r['provider']}: keine Methoden"
        assert r["selected"] in r["methods"]


def test_method_classification():
    # openai: api_key + oauth (authorization_code)
    assert "oauth" in oauth.supported_auth_methods("openai")
    assert oauth.oauth_flow("openai") == "authorization_code"
    # moonshot: api_key + oauth (device_code, Kimi Code)
    assert "oauth" in oauth.supported_auth_methods("moonshot")
    assert oauth.oauth_flow("moonshot") == "device_code"
    # key-only providers: nur api_key, kein OAuth-Flow
    for p in ["minimax", "gemini", "mistral", "deepseek", "xai", "anthropic"]:
        assert oauth.supported_auth_methods(p) == ["api_key"], p
        assert oauth.oauth_flow(p) == ""
    # ollama: lokal, keine Auth
    assert oauth.supported_auth_methods("ollama") == ["none"]


def test_pkce_challenge():
    prov = oauth.provider_from_config("openai")
    assert prov.available, "openai sollte konfigurierten Auth-Code-Flow haben"
    url, state = prov.build_authorize_url(use_pkce=True)
    assert state and state in prov._pending
    verifier = prov._pending[state]
    assert verifier, "PKCE-Verifier fehlt"
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert f"code_challenge={expected}" in url
    assert "code_challenge_method=S256" in url
    assert url.startswith("https://auth.openai.com/api/accounts/authorize?")


def test_authcode_without_config_raises_cleanly():
    prov = oauth.OAuthProvider(name="minimax")  # kein authorize_url/token_url
    assert prov.available is False
    try:
        prov.build_authorize_url()
        assert False, "sollte OAuthError werfen"
    except oauth.OAuthError:
        pass


def test_device_provider_available_and_missing():
    dev = oauth.device_provider_from_config("moonshot")
    assert dev.available, "moonshot/Kimi-Code sollte Device-Flow haben"
    # key-only Provider hat keinen Device-Flow → available False, sauberer Fehler
    nodev = oauth.device_provider_from_config("minimax")
    assert nodev.available is False
    try:
        nodev.request_device_code()
        assert False, "sollte OAuthError werfen"
    except oauth.OAuthError:
        pass


def test_missing_oauth_token_no_crash():
    # Kein Token im Store → _oauth_token liefert None, kein Crash.
    cfg = llm_mod.get_provider("openai")
    tok = llm_mod._oauth_token(cfg)
    assert tok is None or isinstance(tok, str)
    # provider_status enthält die neuen Auth-Metadaten
    st = llm_mod.provider_status("openai")
    assert "auth_methods" in st and "oauth_flow" in st


if __name__ == "__main__":
    test_auth_overview_loads()
    test_method_classification()
    test_pkce_challenge()
    test_authcode_without_config_raises_cleanly()
    test_device_provider_available_and_missing()
    test_missing_oauth_token_no_crash()
    print("[test_oauth] OK — Auth-Registry, PKCE, Device-Flow, saubere Fehler.")
