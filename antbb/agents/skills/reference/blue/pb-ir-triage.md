---
id: pb-ir-triage
soldier: blue-incident
title: IR Triage
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: IR Triage

**Soldat:** `blue-incident` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Klassifizieren
2. Impact
3. SEV setzen
4. On-Call

## Checkliste
- [ ] Klassifizieren
- [ ] Impact
- [ ] SEV setzen
- [ ] On-Call

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
