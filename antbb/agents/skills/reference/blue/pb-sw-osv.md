---
id: pb-sw-osv
soldier: blue-swscan
title: OSV-CVE-Abgleich
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: OSV-CVE-Abgleich

**Soldat:** `blue-swscan` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Inventar an OSV senden
2. CVE-IDs nur aus OSV übernehmen
3. Severity aus OSV mappen
4. Offline: sauber skippen

## Checkliste
- [ ] Inventar an OSV senden
- [ ] CVE-IDs nur aus OSV übernehmen
- [ ] Severity aus OSV mappen
- [ ] Offline: sauber skippen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
