---
id: pb-ir-recover
soldier: blue-incident
title: IR Recovery & Lessons
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: IR Recovery & Lessons

**Soldat:** `blue-incident` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Wiederherstellen
2. Monitoring schärfen
3. Post-Incident-Report
4. Playbook-Lücken schließen

## Checkliste
- [ ] Wiederherstellen
- [ ] Monitoring schärfen
- [ ] Post-Incident-Report
- [ ] Playbook-Lücken schließen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
