---
id: pb-greenbone-status
soldier: blue-greenbone
playbook: gb-status
title: Greenbone-Status prüfen
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Greenbone-Status prüfen

**Soldat:** `blue-greenbone` · **Mode:** defensive · **Oversight:** nein

## Ziel
Prüfen, ob Greenbone/GVM am Laufort erreichbar ist – ohne Scan, ohne Zugangsdaten-Ausgabe.

## Schritte
1. gvmd-Unix-Socket suchen (GVM_SOCKET, /run/gvmd/gvmd.sock)
2. Client erkennen (python-gvm oder gvm-cli)
3. GMP-Version per get_version erfragen
4. Feed-Alter nur mit konfigurierten Zugangsdaten bewerten
5. Nicht verfügbar → ehrliche Meldung, Import bleibt möglich

## Checkliste
- [ ] gvmd-Unix-Socket suchen (GVM_SOCKET, /run/gvmd/gvmd.sock)
- [ ] Client erkennen (python-gvm oder gvm-cli)
- [ ] GMP-Version per get_version erfragen
- [ ] Feed-Alter nur mit konfigurierten Zugangsdaten bewerten
- [ ] Nicht verfügbar → ehrliche Meldung, Import bleibt möglich

## Safety
- Keine Secrets/PII in Logs oder Evidence (Zugangsdaten nur aus der Umgebung)
- Nichts erfinden – ohne Greenbone/Report: „nicht verfügbar“ bzw. honest-empty
- Scope default-deny; Findings sind REFERENZ (Fremd-Scanner)

## Nutzung
`GET /api/blue/greenbone/status` oder Karte „Greenbone“ auf `/blue`.
