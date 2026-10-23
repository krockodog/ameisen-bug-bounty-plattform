---
id: pb-sc-inventory
soldier: blue-supplychain
title: Manifest-Inventar
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Manifest-Inventar

**Soldat:** `blue-supplychain` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. requirements/lock/pyproject
2. Pakete parsen
3. Inventar-Finding

## Checkliste
- [ ] requirements/lock/pyproject
- [ ] Pakete parsen
- [ ] Inventar-Finding

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
