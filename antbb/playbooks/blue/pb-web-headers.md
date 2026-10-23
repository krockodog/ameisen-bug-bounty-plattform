---
id: pb-web-headers
soldier: blue-webharden
title: Security-Headers
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Security-Headers

**Soldat:** `blue-webharden` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. HTTP holen
2. HSTS/CSP/XCTO/XFO/RP/PP
3. Fehlende melden

## Checkliste
- [ ] HTTP holen
- [ ] HSTS/CSP/XCTO/XFO/RP/PP
- [ ] Fehlende melden

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
