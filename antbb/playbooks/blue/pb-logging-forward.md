---
id: pb-logging-forward
soldier: blue-logging
title: HEC-Forward-Smoke
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: HEC-Forward-Smoke

**Soldat:** `blue-logging` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Event mappen
2. send_events
3. Skip ohne Config = ok

## Checkliste
- [ ] Event mappen
- [ ] send_events
- [ ] Skip ohne Config = ok

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
