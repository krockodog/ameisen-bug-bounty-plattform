---
id: pb-net-listen
soldier: blue-netdef
title: Listening-Port-Audit
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Listening-Port-Audit

**Soldat:** `blue-netdef` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. ss/netstat
2. Ports extrahieren
3. Risiko-Katalog
4. Empfehlungen

## Checkliste
- [ ] ss/netstat
- [ ] Ports extrahieren
- [ ] Risiko-Katalog
- [ ] Empfehlungen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
