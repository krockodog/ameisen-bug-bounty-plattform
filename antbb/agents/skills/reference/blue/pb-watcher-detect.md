---
id: pb-watcher-detect
soldier: blue-watcher
title: Angriffserkennung
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Angriffserkennung

**Soldat:** `blue-watcher` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Ausführbares Blue-Team-Playbook der Verteidigungs-Kolonie. Non-destruktiv
standardmäßig; aktive Schritte nur mit Human-Oversight.

## Schritte
1. Events laden
2. Signal-Katalog (web/auth/net/wlan/api)
3. Marker matchen
4. Detection mit Evidence
5. Ohne Events: honest-empty

## Checkliste
- [ ] Events laden
- [ ] Signal-Katalog (web/auth/net/wlan/api)
- [ ] Marker matchen
- [ ] Detection mit Evidence
- [ ] Ohne Events: honest-empty

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Nichts erfinden – honest-empty ohne Daten
- Scope default-deny; fremde Ziele nie ohne Allowlist

## Ergebnis
Findings mit Status-Label und Evidence; bei Remediation ggf.
„nachweislich geschlossen".
