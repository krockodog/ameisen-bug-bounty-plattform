---
id: pb-net-firewall
soldier: blue-netdef
title: Firewall-Status
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Firewall-Status

**Soldat:** `blue-netdef` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Tool erkennen
2. Aktiv?
3. Default-Deny empfehlen

## Checkliste
- [ ] Tool erkennen
- [ ] Aktiv?
- [ ] Default-Deny empfehlen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
