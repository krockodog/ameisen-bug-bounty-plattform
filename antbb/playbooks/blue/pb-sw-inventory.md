---
id: pb-sw-inventory
soldier: blue-swscan
title: Software-Inventar
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Software-Inventar

**Soldat:** `blue-swscan` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Paketmanager erkennen (dpkg/rpm/pip)
2. Paketname+Version erfassen
3. Inventar als Finding ablegen
4. Keine Secrets in Evidence

## Checkliste
- [ ] Paketmanager erkennen (dpkg/rpm/pip)
- [ ] Paketname+Version erfassen
- [ ] Inventar als Finding ablegen
- [ ] Keine Secrets in Evidence

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
