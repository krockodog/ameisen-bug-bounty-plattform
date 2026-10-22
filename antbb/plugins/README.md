# antbb Plugins (Module-SDK)

Lege eine `.py`-Datei in diesen Ordner und definiere eine Subklasse von
`antbb.sdk.CheckPlugin`. Der Loader (`antbb.sdk.discover_plugins`) findet,
validiert und registriert sie automatisch – rein lokal, kein Netzwerk-Fetch.

Vertrag:
- Klassen-Attribute: `name`, `version`, `author`, `description`, `category`
- optional: `mode` = `"defensive"` (Default) oder `"offensive"`
- Methode `run(context) -> list[dict]` – `context` bietet `scope_check(asset)`,
  `log(msg)`, `assets`, `target_id`.

Regeln: `scope_check` VOR jedem Request nutzen (default-deny). Keine Secrets in
Findings. Siehe `example_header_check.py` als Vorlage.

CLI: `antbb plugins list` · `antbb plugins run <name> <target>`
