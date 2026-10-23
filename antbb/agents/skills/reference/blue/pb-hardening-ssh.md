---
id: pb-hardening-ssh
soldier: blue-hardening
title: SSH-Härtungs-Audit
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: SSH-Härtungs-Audit

**Soldat:** `blue-hardening` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. sshd_config lesen
2. PermitRootLogin prüfen
3. PasswordAuthentication prüfen
4. Fix-Befehl vorschlagen (nicht anwenden)

## Checkliste
- [ ] sshd_config lesen
- [ ] PermitRootLogin prüfen
- [ ] PasswordAuthentication prüfen
- [ ] Fix-Befehl vorschlagen (nicht anwenden)

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
