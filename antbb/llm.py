"""Konfigurierbarer Multi-Provider-LLM-Connector für den Ameisen-Schwarm.

ZENTRALE REGEL (siehe README): Kein einzelnes LLM aktiviert von sich aus einen
Schwarm. Das Schwarm-Verhalten (Königin + Spezial-Agenten, Phasen, Dispatch)
kommt AUSSCHLIESSLICH aus dem antbb-Framework. Die LLMs hier sind nur
austauschbare Denk-/Text-Bausteine, die der Router (antbb/router.py) pro
Aufgabe aufruft.

Provider:
  * minimax – OpenAI-kompatibel, Key-Modus (MINIMAX_API_KEY). Kein OAuth-API-Flow.
  * openai  – OpenAI-kompatibel, Key-Modus (OPENAI_API_KEY) als Fallback;
              OAuth ("Sign in with ChatGPT") verfügbar (siehe oauth.py).
  * kimi    – OpenAI-kompatibel. Open-Platform nutzt API-Keys; hier Login-/Plan-
              Modus-Platzhalter (keine Env-Var angelegt, bis der Nutzer einen Key nennt).
  * ollama  – LOKAL, keine Auth, natives /api/chat. Nicht erreichbar → sauberer Fehler.

Keys werden AUSSCHLIESSLICH aus Umgebungsvariablen gelesen und NIEMALS geloggt,
geechot, in die DB oder in Reports geschrieben. OAuth-Tokens liegen verschlüsselt
im Token-Store (oauth.py).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from . import config as _config

_log = logging.getLogger("antbb.llm")

#: LLM-Defaults aus der Config (config/default.yaml + Env-Overrides).
_LLM_CFG = _config.llm_config()

#: Hauptmodell (Königin / Haupt-LLM) und schnelles Modell (Spezial-Agenten).
MAIN_MODEL = _LLM_CFG.get("main_model", "MiniMax-M3")
FAST_MODEL = _LLM_CFG.get("fast_model", "MiniMax-M3.1-Flash")

#: Standard-Provider, wenn keiner explizit gewählt wird (aus der Config).
DEFAULT_PROVIDER = _LLM_CFG.get("default_provider", _LLM_CFG.get("provider", "minimax"))


@dataclass(frozen=True)
class ProviderConfig:
    """Beschreibt einen LLM-Provider. Enthält NIE den Key-/Token-Wert selbst,
    nur den NAMEN der Umgebungsvariable, aus der ein Key gelesen wird."""
    name: str
    base_url: str
    default_model: str
    fast_model: str = ""
    key_env: Optional[str] = None      # Name der Env-Var (z.B. "MINIMAX_API_KEY")
    auth_mode: str = "key"             # key | oauth | login | none
    oauth_available: bool = False
    #: API-Stil: "openai" (/chat/completions) oder "ollama" (/api/chat).
    api_style: str = "openai"
    chat_path: str = "/chat/completions"
    oauth: dict[str, Any] = field(default_factory=dict)


def _build_providers() -> dict[str, ProviderConfig]:
    out: dict[str, ProviderConfig] = {}
    for name, p in (_LLM_CFG.get("providers", {}) or {}).items():
        api_style = "ollama" if name == "ollama" else "openai"
        chat_path = "/api/chat" if api_style == "ollama" else "/chat/completions"
        out[name] = ProviderConfig(
            name=name,
            base_url=p.get("base_url", ""),
            default_model=p.get("default_model", ""),
            fast_model=p.get("fast_model", "") or p.get("default_model", ""),
            key_env=p.get("key_env"),
            auth_mode=p.get("auth_mode", "key"),
            oauth_available=bool(p.get("oauth_available", False)),
            api_style=api_style,
            chat_path=chat_path,
            oauth=p.get("oauth", {}) or {},
        )
    return out


#: Registrierte Provider (aus der Config gebaut).
PROVIDERS: dict[str, ProviderConfig] = _build_providers()


class LLMError(RuntimeError):
    """Sauberer, nicht-geheimnis-tragender Fehler aus dem LLM-Connector."""


@dataclass
class ChatResult:
    """Ergebnis eines Chat-Aufrufs. Enthält niemals Key-/Token-Werte."""
    ok: bool
    provider: str
    model: str
    content: str = ""
    error: str = ""
    status: Optional[int] = None
    raw: dict[str, Any] = field(default_factory=dict)


def get_provider(provider: Optional[str] = None) -> ProviderConfig:
    pname = (provider or DEFAULT_PROVIDER).lower()
    cfg = PROVIDERS.get(pname)
    if not cfg:
        raise LLMError(
            f"Provider '{pname}' unbekannt. Bekannt: {', '.join(sorted(PROVIDERS))}."
        )
    return cfg


def _read_key(cfg: ProviderConfig) -> Optional[str]:
    """Liest den Key NUR aus der Env-Var. Gibt None zurück, wenn nicht gesetzt.
    Der Wert wird niemals geloggt."""
    if not cfg.key_env:
        return None
    val = os.environ.get(cfg.key_env)
    if val and val.strip():
        return val.strip()
    return None


def _oauth_token(cfg: ProviderConfig) -> Optional[str]:
    """Liest ein gültiges OAuth-Access-Token aus dem verschlüsselten Store."""
    if not cfg.oauth_available:
        return None
    try:
        from .oauth import TokenStore
        tok = TokenStore().get(cfg.name)
        if tok and tok.get("access_token"):
            return tok["access_token"]
    except Exception:
        return None
    return None


def is_configured(provider: Optional[str] = None) -> bool:
    """True, wenn der Provider nutzbar ist (Key ODER OAuth-Token ODER keine Auth)."""
    try:
        cfg = get_provider(provider)
    except LLMError:
        return False
    if cfg.auth_mode == "none":
        return True
    return _read_key(cfg) is not None or _oauth_token(cfg) is not None


def auth_state(cfg: ProviderConfig) -> str:
    """Menschlich lesbarer Auth-Status pro Provider (nie Key-/Token-Werte).

    Werte: 'lokal, keine Auth' | 'authentifiziert' | 'Key-Modus (Fallback)' |
           'bereit zur Anmeldung' | 'nicht konfiguriert'.
    """
    if cfg.auth_mode == "none":
        return "lokal, keine Auth"
    if _oauth_token(cfg) is not None:
        return "authentifiziert"
    if _read_key(cfg) is not None:
        return "Key-Modus (Fallback)" if cfg.oauth_available else "authentifiziert"
    if cfg.oauth_available or cfg.auth_mode in ("oauth", "login"):
        return "bereit zur Anmeldung"
    return "nicht konfiguriert"


def _ollama_reachable(cfg: ProviderConfig) -> bool:
    import httpx
    try:
        r = httpx.get(cfg.base_url.rstrip("/") + "/api/tags", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False


def provider_status(provider: Optional[str] = None) -> dict[str, Any]:
    """Status EINES Providers – ohne Key-/Token-Werte."""
    cfg = get_provider(provider)
    st: dict[str, Any] = {
        "provider": cfg.name,
        "auth_mode": cfg.auth_mode,
        "oauth_available": cfg.oauth_available,
        "configured": is_configured(cfg.name),
        "auth_state": auth_state(cfg),
        "base_url": cfg.base_url,
        "default_model": cfg.default_model,
        "fast_model": cfg.fast_model,
        "key_env": cfg.key_env,          # nur der NAME der Env-Var (oder None)
        "is_default": cfg.name == DEFAULT_PROVIDER.lower(),
    }
    if cfg.name == "ollama":
        reachable = _ollama_reachable(cfg)
        st["reachable"] = reachable
        if not reachable:
            st["auth_state"] = "nicht erreichbar"
    return st


def status_all() -> list[dict[str, Any]]:
    """Status ALLER registrierten Provider – niemals Key-/Token-Werte."""
    return [provider_status(name) for name in PROVIDERS]


class LLMClient:
    """Generischer Chat-Client (OpenAI-kompatibel ODER Ollama-nativ).

    Liest Key/Token lazy bei jedem Aufruf; speichert nichts als Attribut,
    loggt nie Geheimnisse. Gibt immer ein ChatResult zurück (ok=False bei
    Fehlern), wirft also nicht bei Netzwerk-/HTTP-Fehlern.
    """

    def __init__(self, provider: Optional[str] = None,
                 timeout: float = 30.0, retries: int = 2):
        self.cfg = get_provider(provider)
        self.timeout = timeout
        self.retries = max(0, retries)

    @property
    def configured(self) -> bool:
        return is_configured(self.cfg.name)

    def chat(self, messages: list[dict[str, str]], model: Optional[str] = None,
             provider: Optional[str] = None, temperature: float = 0.2,
             max_tokens: int = 1024, **extra: Any) -> ChatResult:
        import httpx

        cfg = get_provider(provider) if provider else self.cfg
        mdl = model or cfg.default_model

        if cfg.api_style == "ollama":
            return self._chat_ollama(cfg, mdl, messages, temperature, max_tokens)

        # OpenAI-kompatibel: Bearer aus Key ODER OAuth-Token
        key = _read_key(cfg) or _oauth_token(cfg)
        if not key:
            hint = (f"Umgebungsvariable {cfg.key_env} nicht gesetzt"
                    if cfg.key_env else "kein Key/Token hinterlegt")
            return ChatResult(
                ok=False, provider=cfg.name, model=mdl,
                error=f"Provider {cfg.name} nicht konfiguriert ({hint}; "
                      f"Auth-Status: {auth_state(cfg)}).",
            )

        url = cfg.base_url.rstrip("/") + cfg.chat_path
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": mdl, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens,
        }
        payload.update(extra)
        return self._post(cfg, mdl, url, headers, payload, kind="openai")

    def _chat_ollama(self, cfg, mdl, messages, temperature, max_tokens) -> ChatResult:
        """Ollama-nativer /api/chat-Aufruf. Keine Auth. Nicht erreichbar →
        sauberer Fehler, kein Crash."""
        import httpx
        url = cfg.base_url.rstrip("/") + "/api/chat"
        payload = {
            "model": mdl, "messages": messages, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        try:
            resp = httpx.post(url, json=payload, timeout=self.timeout)
        except Exception as exc:
            return ChatResult(
                ok=False, provider=cfg.name, model=mdl,
                error=f"Ollama nicht erreichbar unter {cfg.base_url} "
                      f"({type(exc).__name__}). Läuft der lokale Ollama-Dienst?",
            )
        if resp.status_code != 200:
            return ChatResult(ok=False, provider=cfg.name, model=mdl,
                              status=resp.status_code,
                              error=f"HTTP {resp.status_code}: {_safe_body(resp)}")
        data = resp.json()
        content = (data.get("message") or {}).get("content", "")
        return ChatResult(ok=True, provider=cfg.name, model=mdl, status=200,
                          content=content, raw=data)

    def _post(self, cfg, mdl, url, headers, payload, kind) -> ChatResult:
        import httpx
        last_err = ""
        last_status = None
        for attempt in range(self.retries + 1):
            try:
                _log.info("[llm] chat → provider=%s model=%s (Versuch %d)",
                          cfg.name, mdl, attempt + 1)
                resp = httpx.post(url, headers=headers, json=payload,
                                  timeout=self.timeout)
                last_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    return ChatResult(ok=True, provider=cfg.name, model=mdl,
                                      status=200, content=_extract_content(data),
                                      raw=data)
                last_err = f"HTTP {resp.status_code}: {_safe_body(resp)}"
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    break
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
            if attempt < self.retries:
                import time
                time.sleep(0.5 * (attempt + 1))
        return ChatResult(ok=False, provider=cfg.name, model=mdl,
                          status=last_status, error=last_err)


def _extract_content(data: dict[str, Any]) -> str:
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""


def _safe_body(resp) -> str:
    try:
        return resp.text[:500]
    except Exception:
        return "<kein Body>"


# ──────────────────────────────────────────────────────────────────────────
#  Statische Modellwahl pro Aufgabentyp (Basis-Defaults, bleibt erhalten).
#  Die dynamische PROVIDER+Modell-Entscheidung macht der Router (router.py),
#  der diese Funktion als Baustein nutzt.
# ──────────────────────────────────────────────────────────────────────────
TASK_MODEL_RULES: dict[str, str] = {
    "analysis": "main", "correlation": "main", "report": "main",
    "report_narrative": "main", "queen": "main", "deep": "main",
    "strategy": "main", "attack_plan": "main", "prioritization": "main",
    "exploit_decision": "main",
    "gate": "fast", "gatekeeper": "fast", "validation": "fast",
    "classification": "fast", "triage": "fast", "quick": "fast", "fast": "fast",
}
_DEFAULT_TASK_CLASS = "fast"


def select_model(task_type: Optional[str] = None) -> str:
    """Wählt anhand des Aufgabentyps das konkrete Modell des Default-Providers.

    Komplexe Aufgaben → MAIN_MODEL, schnelle/einfache Schritte → FAST_MODEL.
    """
    cls = TASK_MODEL_RULES.get((task_type or "").lower().strip(), _DEFAULT_TASK_CLASS)
    return MAIN_MODEL if cls == "main" else FAST_MODEL
