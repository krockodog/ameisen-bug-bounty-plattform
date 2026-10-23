---
id: pb-cred-keys
soldier: blue-credhygiene
title: Key/.env-Rechte
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Key/.env-Rechte

**Soldat:** `blue-credhygiene` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Pfade scannen
2. mode prüfen
3. world-readable melden
4. Keine Klartext-Secrets

## Checkliste
- [ ] Pfade scannen
- [ ] mode prüfen
- [ ] world-readable melden
- [ ] Keine Klartext-Secrets

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
