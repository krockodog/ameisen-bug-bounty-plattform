---
id: pb-honeypot-divert
soldier: blue-honeypot
title: Honeypot-Umleitung
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Honeypot-Umleitung

**Soldat:** `blue-honeypot` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Signal klassifizieren
2. Rezept wählen
3. Divert planen
4. Mit Oversight anwenden
5. Im Attack-Log dokumentieren

## Checkliste
- [ ] Signal klassifizieren
- [ ] Rezept wählen
- [ ] Divert planen
- [ ] Mit Oversight anwenden
- [ ] Im Attack-Log dokumentieren

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
