---
id: pb-ir-contain
soldier: blue-incident
title: IR Containment
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: IR Containment

**Soldat:** `blue-incident` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Isolieren
2. Credentials planen
3. Honeypot prüfen
4. Temp-Firewall

## Checkliste
- [ ] Isolieren
- [ ] Credentials planen
- [ ] Honeypot prüfen
- [ ] Temp-Firewall

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
