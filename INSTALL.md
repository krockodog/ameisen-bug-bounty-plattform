# antbb – Schnellstart (GitHub-Distribution)

Keyfreie, anonymisierte Version **ohne Secrets und ohne persönliche Daten**.

## Voraussetzungen

- Python **3.11–3.13** (`python3`)
- Internet (einmalig für `pip install`)

## Ein Befehl

```bash
unzip antbb-clean-*.zip -d antbb && cd antbb
bash install-and-start.sh
```

Ausgabe z. B. `Startseite: http://127.0.0.1:8000/`  
`./run.sh` ist ein Wrapper. Port: `ANTBB_PORT=1001 bash install-and-start.sh`

## Optional: KI-Anbieter (interaktiv)

Das Script fragt nach den bekanntesten Anbietern:

OpenAI · Anthropic · Google/Gemini · MiniMax · Grok/xAI · Kimi/Moonshot · Ollama · OpenCode · Eigener Anbieter

Pro Anbieter: **[1] API-Schlüssel** (→ lokale `antbb.env`, `chmod 600`) oder **[2] OAuth**
nur dort, wo wirklich verdrahtet (aktuell: OpenAI über die Web-GUI nach dem Start).
Wo kein OAuth existiert (MiniMax, Kimi Open Platform, Ollama, …), sagt das Script
ehrlich „OAuth nicht verfügbar“ — nichts wird vorgetäuscht.

- **Enter** = ohne Key starten (Plattform läuft, KI inaktiv).
- Es werden **nur** Variablen geschrieben, die du wirklich eingibst (keine leere `KIMI_`/`MOONSHOT_`-Variable).
- `antbb.env` steht in `.gitignore`. Vorlage: `antbb.env.example` (nur Kommentare/Platzhalter).

Non-interactive: `ANTBB_ASK_KEY=0 bash install-and-start.sh`

MiniMax-Host: `https://api.minimax.io` — Key nur zur Laufzeit als `MINIMAX_API_KEY`.

## Bewusst entfernt

Keine API-Keys/Tokens/Passwörter · keine persönlichen Daten · keine echten Scope-Ziele/Reports/Captures · `data/` startet leer · kein `external/`-Upstream.
