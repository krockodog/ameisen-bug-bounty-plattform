---
id: pb-watcher-divert-protect
soldier: blue-watcher
title: Divert + Sofortschutz
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Divert + Sofortschutz

**Soldat:** `blue-watcher` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Divert je Detection
2. Rate-Limit/Block empfehlen
3. Asset markieren
4. Aktives Protect nur mit Oversight

## Checkliste
- [ ] Divert je Detection
- [ ] Rate-Limit/Block empfehlen
- [ ] Asset markieren
- [ ] Aktives Protect nur mit Oversight

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
