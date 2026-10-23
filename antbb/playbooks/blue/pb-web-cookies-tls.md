---
id: pb-web-cookies-tls
soldier: blue-webharden
title: Cookies & TLS
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Cookies & TLS

**Soldat:** `blue-webharden` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Cookie-Flags
2. TLS-Version
3. Schwache Protokolle

## Checkliste
- [ ] Cookie-Flags
- [ ] TLS-Version
- [ ] Schwache Protokolle

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
