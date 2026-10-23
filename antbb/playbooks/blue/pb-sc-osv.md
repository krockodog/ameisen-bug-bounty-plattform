---
id: pb-sc-osv
soldier: blue-supplychain
title: Dependency-OSV
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Dependency-OSV

**Soldat:** `blue-supplychain` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Gepinnte Pakete
2. OSV query
3. fixed-Version
4. Offline skip

## Checkliste
- [ ] Gepinnte Pakete
- [ ] OSV query
- [ ] fixed-Version
- [ ] Offline skip

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
