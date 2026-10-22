"""Austauschbare LLM-Provider-Adapter mit einheitlicher chat()-Schnittstelle.

ZENTRALE REGEL: Kein einzelnes LLM aktiviert von sich aus einen Schwarm. Das
Schwarm-Verhalten (Koenigin + Spezial-Agenten, Phasen, Dispatch) kommt
AUSSCHLIESSLICH aus dem antbb-Framework. Die Adapter hier sind nur
austauschbare Denk-/Text-Bausteine: messages rein -> Text raus.

Jeder Adapter kapselt genau EINEN Provider und bietet:
  * .name            – Provider-Name
  * .key_env         – Name(n) der Umgebungsvariable(n) fuer den Key (nie der Wert)
  * .available()     – True, wenn der Provider nutzbar ist (Key gesetzt bzw.
                       lokaler Dienst erreichbar). KEIN Key -> False, kein Crash.
  * .chat(messages, model=None, **kw) -> ChatResult

Auth ausschliesslich zur Laufzeit ueber Umgebungsvariablen. Es ist KEIN Key im
Code/Repo hinterlegt und es wird KEINE Variable mit echtem Wert angelegt.
Fehlt der Key/Dienst, wird der Provider einfach als nicht verfuegbar gelistet.

Die konkreten Request-/Response-Formate liegen in antbb/llm.py (api_style:
openai | anthropic | gemini | ollama). Dieses Modul ist die Registry-/Fassade-
Schicht, die der Router (antbb/router.py) nutzen kann.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from . import llm as _llm

#: Zusatz-Env-Vars, die ein Provider alternativ akzeptiert (nur NAMEN).
_ALT_KEY_ENVS: dict[str, list[str]] = {
    "gemini": ["GOOGLE_API_KEY"],
}


@dataclass
class ProviderAdapter:
    """Einheitlicher Adapter um einen in llm.PROVIDERS registrierten Provider."""
    name: str

    @property
    def cfg(self):
        return _llm.PROVIDERS[self.name]

    @property
    def api_style(self) -> str:
        return self.cfg.api_style

    @property
    def key_env(self) -> list[str]:
        envs: list[str] = []
        if self.cfg.key_env:
            envs.append(self.cfg.key_env)
        envs += _ALT_KEY_ENVS.get(self.name, [])
        return envs

    def available(self) -> bool:
        """Nutzbar? Key gesetzt (bzw. bei Ollama Dienst erreichbar). Nie Crash."""
        try:
            if self.api_style == "ollama":
                return _llm._ollama_reachable(self.cfg)
            return _llm.is_configured(self.name)
        except Exception:
            return False

    def status(self) -> dict[str, Any]:
        try:
            return _llm.provider_status(self.name)
        except Exception as exc:  # defensiv: nie crashen
            return {"provider": self.name, "configured": False,
                    "auth_state": "nicht konfiguriert", "error": str(exc)}

    def chat(self, messages: list[dict[str, str]], model: Optional[str] = None,
             **kw: Any) -> "_llm.ChatResult":
        """messages rein -> ChatResult raus. Fehlender Key -> ok=False, kein Crash."""
        client = _llm.LLMClient(self.name)
        return client.chat(messages, model=model, **kw)


class ProviderRegistry:
    """Zentrale Registry aller austauschbaren Provider-Adapter."""

    def __init__(self) -> None:
        self._adapters: dict[str, ProviderAdapter] = {
            name: ProviderAdapter(name) for name in _llm.PROVIDERS
        }

    def names(self) -> list[str]:
        return list(self._adapters)

    def get(self, name: str) -> ProviderAdapter:
        key = (name or "").lower()
        if key not in self._adapters:
            raise KeyError(f"Unbekannter Provider '{name}'. "
                           f"Bekannt: {', '.join(self._adapters)}.")
        return self._adapters[key]

    def all(self) -> list[ProviderAdapter]:
        return list(self._adapters.values())

    def available(self) -> list[ProviderAdapter]:
        """Nur Adapter, die aktuell nutzbar sind (Key/Dienst vorhanden)."""
        return [a for a in self._adapters.values() if a.available()]

    def available_names(self) -> list[str]:
        return [a.name for a in self.available()]

    def status_all(self) -> list[dict[str, Any]]:
        return [a.status() for a in self._adapters.values()]

    def chat(self, provider: str, messages: list[dict[str, str]],
             model: Optional[str] = None, **kw: Any) -> "_llm.ChatResult":
        return self.get(provider).chat(messages, model=model, **kw)


#: Prozessweite Standard-Registry.
REGISTRY = ProviderRegistry()


def get_registry() -> ProviderRegistry:
    return REGISTRY


def available_providers() -> list[str]:
    """Namen aller aktuell nutzbaren Provider (Key gesetzt / Dienst erreichbar)."""
    return REGISTRY.available_names()


def chat(provider: str, messages: list[dict[str, str]],
         model: Optional[str] = None, **kw: Any) -> "_llm.ChatResult":
    """Komfort-Fassade: ueber die Registry an den gewaehlten Adapter delegieren."""
    return REGISTRY.chat(provider, messages, model=model, **kw)
