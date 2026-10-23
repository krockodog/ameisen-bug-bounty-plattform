---
id: pb-watcher-traceback
soldier: blue-watcher
title: Angreifer-Rückverfolgung
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Angreifer-Rückverfolgung

**Soldat:** `blue-watcher` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Sources korrelieren
2. Sessions/Fingerprints
3. Timeline first/last
4. Keine erfundenen Identitäten
5. Attribution loggen

## Checkliste
- [ ] Sources korrelieren
- [ ] Sessions/Fingerprints
- [ ] Timeline first/last
- [ ] Keine erfundenen Identitäten
- [ ] Attribution loggen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
