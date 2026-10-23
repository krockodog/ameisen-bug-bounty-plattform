---
id: pb-attacklog-append
soldier: blue-attacklog
title: Attack-Log schreiben
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Attack-Log schreiben

**Soldat:** `blue-attacklog` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Event normalisieren
2. Secrets redakten
3. Append in Store
4. Optional Splunk spiegeln

## Checkliste
- [ ] Event normalisieren
- [ ] Secrets redakten
- [ ] Append in Store
- [ ] Optional Splunk spiegeln

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
