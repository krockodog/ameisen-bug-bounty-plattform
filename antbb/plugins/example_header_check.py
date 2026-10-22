"""Beispiel-Plugin für das antbb Module-SDK (dokumentiertes Vorbild).

Zeigt den CheckPlugin-Vertrag: Metadaten + run(context). Dieses Beispiel ist
rein defensiv, nutzt KEIN Netzwerk und erfindet KEINE Funde – es demonstriert
nur die Schnittstelle (scope_check, log, Finding-Dicts) und liefert einen
honest-empty-Lauf, solange keine echten Eingangsdaten vorliegen.

Kopiere diese Datei als Vorlage für eigene Checks in den Plugins-Ordner.
"""
from antbb.sdk import CheckPlugin, PluginContext


class ExampleHeaderCheck(CheckPlugin):
    name = "example-header-check"
    version = "1.0.0"
    author = "antbb"
    description = ("Demo-Plugin: prüft (hypothetisch) auf fehlende Security-Header "
                   "und zeigt den SDK-Vertrag. Liefert ehrlich leer ohne echte Daten.")
    category = "misconfig"
    mode = "defensive"

    def run(self, context: PluginContext) -> list:
        findings: list = []
        # Scope-Check-PFLICHT vor jeder (hier simulierten) Aktion.
        for asset in context.assets:
            if not context.scope_check(asset):
                context.log(f"[plugin:{self.name}] ⛔ out-of-scope übersprungen: {asset}")
                continue
            context.log(f"[plugin:{self.name}] würde {asset} auf Security-Header prüfen.")
            # Demo: KEIN echter Request → honest-empty, nichts erfunden.
        return findings
