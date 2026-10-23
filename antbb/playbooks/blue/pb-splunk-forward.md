---
id: pb-splunk-forward
soldier: blue-defense
title: Splunk-HEC Forward
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Splunk-HEC Forward

**Soldat:** `blue-defense` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. HEC-Status prüfen
2. Events mappen
3. Senden oder Skip
4. Token nie loggen

## Checkliste
- [ ] HEC-Status prüfen
- [ ] Events mappen
- [ ] Senden oder Skip
- [ ] Token nie loggen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
