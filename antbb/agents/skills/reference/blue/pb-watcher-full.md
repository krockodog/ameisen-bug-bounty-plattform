---
id: pb-watcher-full
soldier: blue-watcher
title: Voller Wächter-Lauf
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Voller Wächter-Lauf

**Soldat:** `blue-watcher` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Oversight prüfen
2. run_watch
3. Log-IDs sammeln
4. Summary melden

## Checkliste
- [ ] Oversight prüfen
- [ ] run_watch
- [ ] Log-IDs sammeln
- [ ] Summary melden

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
