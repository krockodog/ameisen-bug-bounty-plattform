---
id: pb-honeypot-recipes
soldier: blue-honeypot
title: Decoy-Rezepte
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Decoy-Rezepte

**Soldat:** `blue-honeypot` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. SSH-Decoy
2. HTTP-Canary
3. Decoy-File
4. SMTP-Decoy
5. Safety prüfen

## Checkliste
- [ ] SSH-Decoy
- [ ] HTTP-Canary
- [ ] Decoy-File
- [ ] SMTP-Decoy
- [ ] Safety prüfen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
