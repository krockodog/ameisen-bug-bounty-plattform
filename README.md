# Blue Queen

![Python](https://img.shields.io/badge/Python-3.11--3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-lokal-009688?logo=fastapi&logoColor=white)
![Lizenz](https://img.shields.io/badge/Lizenz-MIT-blue)
![Nur autorisiert](https://img.shields.io/badge/Einsatz-nur%20autorisiert%20(%C2%A7%20202a--c%20StGB)-critical)

Ich baue hier die **Blue Queen**, die Verteidigungs-Königin. Sie führt eine
Kolonie, die mein eigenes System liest, Lücken benennt und Belege sammelt.
Das ist dieses Repository. Es ist keine Plattform für mehrere Königinnen
und kein Werkzeugkasten für Angriffe.

Standard ist lesend. Aktive Fixes und Honeypot-Starts brauchen Human Oversight.
Ohne Allowlist-Eintrag bleibt ein fremdes Asset blockiert (default-deny).

> Prüfen oder verändern von Systemen ohne schriftliche oder öffentliche
> Autorisierung ist strafbar (§ 202a–c StGB, CFAA).

## Start

```bash
./run.sh
```

Die Oberfläche liegt unter `http://127.0.0.1:8000/blue` (Port über `ANTBB_PORT`).
`./run.sh` ruft `install-and-start.sh` auf: venv, Abhängigkeiten, dann der
Webserver. Direkt, wenn die Umgebung schon steht:

```bash
source .venv/bin/activate
python run_web.py
```

Scope und Oversight: `http://127.0.0.1:8000/scope`.

## Was die Kolonie tut

Phasen: **Assess → Watch → Harden → Defend → Remediate → Verify**.

Die Königin verteilt jede Phase an die Soldaten unter `antbb/agents/blue/`
und sammelt die Ergebnisse. „Nachweislich geschlossen“ gilt erst, wenn ein
lesender Re-Check Vorher und Nachher belegt.

Dazu gehören unter anderem Software-Inventar, Härtung, Firewall, TLS,
Patches, Logs, Backups, Wächter, Detection, Honeypots als Rezept, Remediation,
der append-only Attack-Log und der Greenbone-/OpenVAS-Import. Wiederholbare
Jobs liegen in der Datenbank.

Greenbone: einen Report (XML, CSV, JSON) lege ich nach `data/greenbone/` oder
lade ihn unter `/blue` hoch. Das ist defensiv und braucht kein Oversight.
Ein Scan startet nur mit Human Oversight gegen genau ein In-Scope-Ziel.
`GVM_USERNAME`, `GVM_PASSWORD` und optional `GVM_SOCKET` kommen nur aus der
Umgebung. Fehlt GVM, steht dort „Greenbone nicht verfügbar“; der Import aus
Datei bleibt möglich. Der Job `greenbone` importiert den neuesten Report und
startet keinen Scan.
Splunk-HEC ist optional (`ANTBB_SPLUNK_HEC_URL` und `ANTBB_SPLUNK_HEC_TOKEN`);
ohne die Variablen wird nichts gesendet.

Playbooks: `antbb/playbooks/blue/`.

## Orchestrierung

Die Laufsteuerung steckt in `antbb/blue_queen.py`. Sie plant die Phasen und
kann für Einordnung und Text den Provider-Router (`antbb/router.py`) nutzen.

- Keys stehen nicht im Repository. Ein Provider kommt nur zur Laufzeit aus
  der Umgebung (`antbb.env`, siehe `antbb.env.example`).
- Ohne Provider laufen die Checks trotzdem.
- `ANTBB_NO_LLM=1` lässt den Router aus.
- Den Status sehe ich unter `/providers` und mit `python -m antbb llm status`.
  Angezeigt werden Namen und ob ein Key gesetzt ist, nie der Key selbst.

Der Installer fragt optional nach einem Provider und schreibt nur, was ich
eintippe, in die lokale `antbb.env` (`chmod 600`, gitignored).

## Leitplanken

1. **Default-deny Scope** (`antbb/scope.py`).
2. **Human Oversight** für aktive Schritte (`antbb/oversight.py`,
   `antbb/active_oversight.py`).
3. **Proof-Gate** für „nachweislich geschlossen“.
4. Lokal unter `127.0.0.1`, solange ich nichts anderes selbst hochfahre.
5. Keine Schlüssel, keine personenbezogenen Daten im Baum.

## Kurz prüfen

```bash
python -m unittest tests.test_bluequeen
python smoke_test_greenbone.py
```

Der erste Test lädt die Soldaten, einen kleinen Kolonie-Lauf und die Route `/blue`.
Der zweite prüft den Greenbone-Import und die Scan-Gates ohne laufendes GVM.

## Lizenz

MIT. Siehe `LICENSE`.
