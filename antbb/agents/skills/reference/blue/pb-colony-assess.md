---
id: pb-colony-assess
soldier: blue-queen
title: Phase Assess
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Phase Assess

**Soldat:** `blue-queen` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. swscan
2. netdef
3. webharden
4. credhygiene
5. supplychain
6. backup

## Checkliste
- [ ] swscan
- [ ] netdef
- [ ] webharden
- [ ] credhygiene
- [ ] supplychain
- [ ] backup

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
