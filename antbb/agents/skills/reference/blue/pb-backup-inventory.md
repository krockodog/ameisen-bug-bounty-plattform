---
id: pb-backup-inventory
soldier: blue-backup
title: Backup-Inventar
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Backup-Inventar

**Soldat:** `blue-backup` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Pfade finden
2. Alter berechnen
3. Veraltet melden
4. Fehlend melden

## Checkliste
- [ ] Pfade finden
- [ ] Alter berechnen
- [ ] Veraltet melden
- [ ] Fehlend melden

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
