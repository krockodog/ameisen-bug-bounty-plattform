---
id: pb-hardening-apply
soldier: blue-hardening
title: Härtung anwenden (gated)
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Härtung anwenden (gated)

**Soldat:** `blue-hardening` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Oversight bestätigen
2. Fix-Befehl zeigen
3. Nur mit Freigabe anwenden
4. Re-Check danach anstoßen

## Checkliste
- [ ] Oversight bestätigen
- [ ] Fix-Befehl zeigen
- [ ] Nur mit Freigabe anwenden
- [ ] Re-Check danach anstoßen

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
