---
id: pb-remediation-plan
soldier: blue-remediation
title: Remediation-Plan
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Remediation-Plan

**Soldat:** `blue-remediation` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Finding kategorisieren
2. Fix-Aktion ableiten
3. Befehl vorschlagen
4. Verify-Methode festlegen

## Checkliste
- [ ] Finding kategorisieren
- [ ] Fix-Aktion ableiten
- [ ] Befehl vorschlagen
- [ ] Verify-Methode festlegen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
