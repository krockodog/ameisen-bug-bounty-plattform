"""LLM-Router der Königin: wählt pro Aufgabe PROVIDER UND Modell.

ZENTRALE REGEL: Der Router ist Teil des antbb-Frameworks. Er entscheidet, welcher
austauschbare LLM-Baustein eine Teilaufgabe denkt – aber das Schwarm-Verhalten
(Phasen, Dispatch, Königin) kommt aus dem Framework, nie aus einem LLM.

Grundregeln (nachvollziehbar, nur verfügbare/authentifizierte Provider):
  * Kleine Arbeiter-Schritte / niedrige Komplexität → günstiges/schnelles Modell
    (bevorzugt lokales Ollama, sonst MiniMax-Flash).
  * Entscheidungs-/komplexe Aufgaben ("was wie angreifen", Reihenfolge, tiefe
    Analyse, Report-Narrativ) → stärkeres Modell (OpenAI/Kimi/MiniMax-M3).
  * Nicht konfigurierte/erreichbare Provider werden übersprungen.

Kritische/unsichere Entscheidungen lösen eine NUTZER-RÜCKFRAGE aus (Hook),
statt still selbst zu entscheiden – siehe UserQuery / ask_user.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import llm as llm_mod
from . import config as _config

_CFG = _config.llm_config()
_ROUTER_CFG = _CFG.get("router", {})
CRITICAL_TASK_TYPES = set(_ROUTER_CFG.get("critical_task_types", []))
COMPLEXITY_THRESHOLD = float(_ROUTER_CFG.get("complexity_threshold", 0.5))

#: Präferenz-Reihenfolge für starke ("decision") vs. schnelle ("fast") Modelle.
STRONG_PRIORITY = ["openai", "anthropic", "gemini", "xai", "deepseek",
                   "mistral", "moonshot", "minimax"]
FAST_PRIORITY = ["ollama", "gemini", "mistral", "minimax", "deepseek",
                 "moonshot", "openai", "anthropic", "xai"]


@dataclass
class RouteDecision:
    provider: str
    model: str
    tier: str                      # "strong" | "fast"
    reason: str
    needs_user: bool = False
    query: Optional["UserQuery"] = None


@dataclass
class UserQuery:
    """Eine Rückfrage der Königin an den Nutzer bei kritischen Entscheidungen."""
    question: str
    options: list[str]
    context: dict[str, Any] = field(default_factory=dict)
    default: Optional[str] = None


def _available() -> dict[str, dict[str, Any]]:
    """Aktuell nutzbare Provider (konfiguriert bzw. lokal erreichbar)."""
    out: dict[str, dict[str, Any]] = {}
    for st in llm_mod.status_all():
        name = st["provider"]
        usable = st["configured"]
        if name == "ollama":
            usable = bool(st.get("reachable"))
        if usable:
            out[name] = st
    return out


def _model_for(provider: str, tier: str) -> str:
    cfg = llm_mod.PROVIDERS[provider]
    if provider == llm_mod.DEFAULT_PROVIDER.lower():
        # beim Default-Provider die zentral festgenagelten Modelle nutzen
        return llm_mod.MAIN_MODEL if tier == "strong" else llm_mod.FAST_MODEL
    return cfg.default_model if tier == "strong" else (cfg.fast_model or cfg.default_model)


def _pick(priority: list[str], avail: dict[str, dict[str, Any]]) -> list[str]:
    ranked = [p for p in priority if p in avail]
    # übrige verfügbare Provider hinten anhängen
    ranked += [p for p in avail if p not in ranked]
    return ranked


def route(task_type: Optional[str] = None, complexity: float = 0.0,
          ask_user: Optional[Callable[["UserQuery"], str]] = None) -> RouteDecision:
    """Router-Entscheidung: (provider, model) für eine Aufgabe.

    task_type   – z.B. "recon", "classification", "attack_plan", "report"
    complexity  – 0..1; ab COMPLEXITY_THRESHOLD gilt die Aufgabe als komplex
    ask_user    – optionaler Hook; wird bei kritischen/unsicheren Fällen gerufen
                  und soll die gewählte Option (Provider-Name) zurückgeben.
    """
    tt = (task_type or "").lower().strip()
    avail = _available()

    if not avail:
        # Fallback: Default-Provider nennen, auch wenn (noch) nicht nutzbar –
        # der Connector meldet dann sauber "nicht konfiguriert".
        dp = llm_mod.DEFAULT_PROVIDER.lower()
        tier = "strong" if (tt in CRITICAL_TASK_TYPES or complexity >= COMPLEXITY_THRESHOLD) else "fast"
        return RouteDecision(dp, _model_for(dp, tier), tier,
                             "Kein Provider verfügbar – Default genannt (Connector meldet Status).")

    is_critical = tt in CRITICAL_TASK_TYPES
    is_complex = complexity >= COMPLEXITY_THRESHOLD or llm_mod.TASK_MODEL_RULES.get(tt) == "main"
    tier = "strong" if (is_critical or is_complex) else "fast"
    ranked = _pick(STRONG_PRIORITY if tier == "strong" else FAST_PRIORITY, avail)

    # ── Nutzer-Rückfrage bei kritischen ODER mehrdeutigen Entscheidungen ──
    strong_candidates = [p for p in ranked if p in avail]
    ambiguous = tier == "strong" and len(strong_candidates) >= 2
    if is_critical or ambiguous:
        q = UserQuery(
            question=(
                f"Kritische Entscheidung für Aufgabe '{task_type}': welcher LLM-"
                f"Provider soll diese heikle/komplexe Teilaufgabe übernehmen?"
                if is_critical else
                f"Mehrere Provider passen gleich gut für '{task_type}'. Welcher soll es sein?"
            ),
            options=strong_candidates or ranked,
            context={"task_type": task_type, "complexity": complexity, "tier": tier},
            default=(strong_candidates or ranked)[0],
        )
        if ask_user is not None:
            chosen = ask_user(q)
            if chosen and chosen in avail:
                return RouteDecision(chosen, _model_for(chosen, tier), tier,
                                     f"Vom Nutzer gewählt (kritisch={is_critical}).")
            # ungültige/leere Antwort → Default der Frage
            return RouteDecision(q.default, _model_for(q.default, tier), tier,
                                 "Nutzer-Default übernommen (keine valide Auswahl).")
        # Kein Hook vorhanden → Entscheidung dem Aufrufer melden
        return RouteDecision(q.default, _model_for(q.default, tier), tier,
                             "Kritische Entscheidung – Nutzer-Rückfrage erforderlich.",
                             needs_user=True, query=q)

    provider = ranked[0]
    return RouteDecision(provider, _model_for(provider, tier), tier,
                         f"Automatisch gewählt (tier={tier}, Komplexität={complexity:.2f}).")


# ── Standard-Hooks für Nutzer-Rückfragen ───────────────────────────────────
def headless_ask(default_choice: Optional[str] = None) -> Callable[["UserQuery"], str]:
    """Hook für headless/Test-Betrieb: nimmt automatisch die Default-Option
    (oder eine fest vorgegebene Wahl). Dokumentiert die simulierte Antwort."""
    def _ask(q: UserQuery) -> str:
        return default_choice or q.default or (q.options[0] if q.options else "")
    return _ask


def cli_ask(input_fn: Callable[[str], str] = input) -> Callable[["UserQuery"], str]:
    """Hook für die CLI: stellt die Frage im Terminal und liest die Auswahl."""
    def _ask(q: UserQuery) -> str:
        print("\n⚠️  Königin braucht eine Entscheidung:")
        print("   " + q.question)
        for i, opt in enumerate(q.options, 1):
            dflt = " (Default)" if opt == q.default else ""
            print(f"     [{i}] {opt}{dflt}")
        try:
            raw = input_fn("   Auswahl (Nummer/Name, Enter = Default): ").strip()
        except EOFError:
            raw = ""
        if not raw:
            return q.default or (q.options[0] if q.options else "")
        if raw.isdigit() and 1 <= int(raw) <= len(q.options):
            return q.options[int(raw) - 1]
        return raw
    return _ask
