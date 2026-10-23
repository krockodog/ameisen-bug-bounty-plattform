# Blue Queen – Start

Keyfrei. Keine Schlüssel und keine personenbezogenen Daten in diesem Baum.

## Voraussetzung

Python 3.11–3.13.

## Ein Befehl

```bash
./run.sh
```

Das öffnet die Kolonie, zum Beispiel `http://127.0.0.1:8000/blue`.
Anderer Port: `ANTBB_PORT=1001 ./run.sh`.

Scope und Oversight liegen unter `/scope`.

## Provider (optional)

Der Installer kann nach einem Provider fragen. Enter heißt: ohne Key starten.
Die Kolonie läuft dann ohne externen Dienst. Was ich eingebe, landet nur in
der lokalen `antbb.env` (nicht im Git). Vorlage: `antbb.env.example`.

Ohne TTY oder mit `ANTBB_ASK_KEY=0` entfällt die Frage.

`ANTBB_NO_LLM=1` schaltet den Router aus, auch wenn ein Key gesetzt ist.

## Recht

Nur an Systemen, die ich prüfen darf. § 202a–c StGB, CFAA.
