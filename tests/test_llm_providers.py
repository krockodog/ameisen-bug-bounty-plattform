"""Smoke-Test fuer die austauschbare LLM-Provider-Adapter-Registry.

Prueft: Registry laedt alle erwarteten Provider; fehlende Keys fuehren NICHT
zum Crash, sondern zu ok=False bzw. available()=False. Es werden KEINE echten
Netzaufrufe mit echten Keys gemacht und KEINE Keys angelegt.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Deterministisch: alle bekannten Provider-Keys fuer diesen Test entfernen,
# damit "fehlender Key -> kein Crash" sauber geprueft wird.
for env in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "GOOGLE_API_KEY", "MINIMAX_API_KEY", "MOONSHOT_API_KEY",
            "MISTRAL_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY"]:
    os.environ.pop(env, None)

from antbb import llm_providers as lp

EXPECTED = {"openai", "anthropic", "gemini", "minimax", "moonshot",
            "mistral", "deepseek", "xai", "ollama"}


def test_registry_loads_all():
    reg = lp.get_registry()
    names = set(reg.names())
    missing = EXPECTED - names
    assert not missing, f"Fehlende Provider-Adapter: {missing}"


def test_missing_key_no_crash():
    reg = lp.get_registry()
    for name in reg.names():
        if name == "ollama":
            continue  # lokaler Dienst, keine Key-Logik
        a = reg.get(name)
        # available() darf nicht crashen und muss ohne Key False liefern
        assert a.available() is False, f"{name} sollte ohne Key nicht verfuegbar sein"
        # chat() darf nicht werfen, sondern ein ok=False-Ergebnis liefern
        res = a.chat([{"role": "user", "content": "ping"}])
        assert res.ok is False
        assert res.error, f"{name}: erwartete saubere Fehlermeldung"


def test_status_all_no_crash():
    reg = lp.get_registry()
    st = reg.status_all()
    assert len(st) == len(EXPECTED)
    for row in st:
        assert "provider" in row


if __name__ == "__main__":
    test_registry_loads_all()
    test_missing_key_no_crash()
    test_status_all_no_crash()
    print("[test_llm_providers] OK — Registry laedt, fehlende Keys crashen nicht.")
