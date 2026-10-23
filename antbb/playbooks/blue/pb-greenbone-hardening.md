---
id: pb-greenbone-hardening
soldier: blue-greenbone
playbook: gb-to-hardening
title: Greenbone → Härtung/Remediation
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Greenbone → Härtung/Remediation

**Soldat:** `blue-greenbone` · **Mode:** defensive · **Oversight:** nein

## Ziel
High/Critical-Funde aus dem Import als Ticket-/Härtungs-Hinweise strukturieren – ohne automatischen Fix.

## Schritte
1. High/Critical-Funde je NVT gruppieren (betroffene Hosts, CVEs)
2. Lösungstext/-typ unverändert aus dem Report übernehmen (sonst „keine Lösung im Report“)
3. Zuständigen Soldaten zuweisen: patchmgmt, hardening, tlsposture, fwaudit oder vulnticket
4. Close-Kriterium festlegen: Re-Scan ohne NVT + Vorher/Nachher-Evidence

## Checkliste
- [ ] High/Critical-Funde je NVT gruppieren (betroffene Hosts, CVEs)
- [ ] Lösungstext/-typ unverändert aus dem Report übernehmen (sonst „keine Lösung im Report“)
- [ ] Zuständigen Soldaten zuweisen: patchmgmt, hardening, tlsposture, fwaudit oder vulnticket
- [ ] Close-Kriterium festlegen: Re-Scan ohne NVT + Vorher/Nachher-Evidence

## Safety
- Keine Secrets/PII in Logs oder Evidence (Zugangsdaten nur aus der Umgebung)
- Nichts erfinden – ohne Greenbone/Report: „nicht verfügbar“ bzw. honest-empty
- Scope default-deny; Findings sind REFERENZ (Fremd-Scanner)

## Ergebnis
Findings der Kategorie `blue-greenbone-remediation` (`auto_fix: false`). „Nachweislich geschlossen“ erst nach Re-Scan.
