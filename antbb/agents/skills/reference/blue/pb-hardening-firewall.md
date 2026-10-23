---
id: pb-hardening-firewall
soldier: blue-hardening
title: Firewall-Status-Audit
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Firewall-Status-Audit

**Soldat:** `blue-hardening` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. ufw/firewalld/nft/iptables erkennen
2. Aktiv-Status lesen
3. Default-Deny empfehlen
4. World-writable /etc prüfen

## Checkliste
- [ ] ufw/firewalld/nft/iptables erkennen
- [ ] Aktiv-Status lesen
- [ ] Default-Deny empfehlen
- [ ] World-writable /etc prüfen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
