---
id: pb-greenbone-scan
soldier: blue-greenbone
playbook: gb-scoped-scan
title: Greenbone-Scan (scoped)
mode: offensive
oversight_required: true
colony: blue
---

# Playbook: Greenbone-Scan (scoped)

**Soldat:** `blue-greenbone` · **Mode:** offensive · **Oversight:** ja (Human Oversight Pflicht)

## Ziel
Einen nicht-destruktiven Greenbone-Scan gegen genau ein In-Scope-Ziel starten. Nur mit Human Oversight.

## Schritte
1. Oversight-Freigabe prüfen (default-deny)
2. Ziel muss ein einzelner In-Scope-Host/eine IP sein (keine Netze/Listen)
3. Nur Allowlist-Scan-Config (Full and fast, Base, Discovery, Host/System Discovery)
4. Genau ein Scan gleichzeitig, Mindestabstand zwischen Starts
5. Task starten, Status begrenzt abfragen, Report nach data/greenbone/ ablegen und importieren

## Checkliste
- [ ] Oversight-Freigabe prüfen (default-deny)
- [ ] Ziel muss ein einzelner In-Scope-Host/eine IP sein (keine Netze/Listen)
- [ ] Nur Allowlist-Scan-Config (Full and fast, Base, Discovery, Host/System Discovery)
- [ ] Genau ein Scan gleichzeitig, Mindestabstand zwischen Starts
- [ ] Task starten, Status begrenzt abfragen, Report nach data/greenbone/ ablegen und importieren

## Safety
- Keine Secrets/PII in Logs oder Evidence (Zugangsdaten nur aus der Umgebung)
- Nichts erfinden – ohne Greenbone/Report: „nicht verfügbar“ bzw. honest-empty
- Scope default-deny; Findings sind REFERENZ (Fremd-Scanner)

## Nutzung
`POST /api/blue/greenbone/scan` mit `target_id`, `host`, `oversight_ack: true`. Ohne GVM/Zugangsdaten: ehrlicher Fehler, nichts gestartet.
