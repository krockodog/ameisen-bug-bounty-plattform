---
id: pb-patch-verify-finding
soldier: blue-patchverify
title: Finding schließen prüfen
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Finding schließen prüfen

**Soldat:** `blue-patchverify` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Finding-Key
2. verify_closed
3. Evidence speichern

## Checkliste
- [ ] Finding-Key
- [ ] verify_closed
- [ ] Evidence speichern

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
