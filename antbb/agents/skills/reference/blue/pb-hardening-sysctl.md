---
id: pb-hardening-sysctl
soldier: blue-hardening
title: Kernel-sysctl-Härtung
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Kernel-sysctl-Härtung

**Soldat:** `blue-hardening` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. sysctl-Werte lesen
2. rp_filter/syn-cookies prüfen
3. Abweichungen melden

## Checkliste
- [ ] sysctl-Werte lesen
- [ ] rp_filter/syn-cookies prüfen
- [ ] Abweichungen melden

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
