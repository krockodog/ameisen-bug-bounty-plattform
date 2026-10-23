---
id: pb-logging-status
soldier: blue-logging
title: Splunk-Status
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Splunk-Status

**Soldat:** `blue-logging` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. ENV prüfen
2. configured?
3. Index/Sourcetype
4. Token nie ausgeben

## Checkliste
- [ ] ENV prüfen
- [ ] configured?
- [ ] Index/Sourcetype
- [ ] Token nie ausgeben

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
