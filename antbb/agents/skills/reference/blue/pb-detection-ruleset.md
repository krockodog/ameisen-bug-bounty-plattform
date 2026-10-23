---
id: pb-detection-ruleset
soldier: blue-defense
title: Detection-Regelset
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Detection-Regelset

**Soldat:** `blue-defense` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Brute-Force-Regel
2. Neuer Listening-Port
3. Suspicious Outbound
4. Priv-Esc/sudo
5. Persistenz cron/systemd

## Checkliste
- [ ] Brute-Force-Regel
- [ ] Neuer Listening-Port
- [ ] Suspicious Outbound
- [ ] Priv-Esc/sudo
- [ ] Persistenz cron/systemd

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
