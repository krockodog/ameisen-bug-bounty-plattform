---
id: pb-greenbone-import
soldier: blue-greenbone
playbook: gb-import-report
title: Greenbone-Report importieren
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: Greenbone-Report importieren

**Soldat:** `blue-greenbone` · **Mode:** defensive · **Oversight:** nein

## Ziel
Greenbone/OpenVAS-Report (XML, CSV oder JSON) als Blue-Findings übernehmen. Rein lesend, kein Netzwerkverkehr.

## Schritte
1. Report nach data/greenbone/ legen (oder über /blue hochladen)
2. Format erkennen und parsen (nur echte Felder: NVT, CVE, CVSS, QoD, Host, Port)
3. Severity aus CVSS/Threat ableiten; Log-Level nicht als Befund führen
4. Mit Target: Hosts gegen Scope filtern (default-deny)
5. Findings als REFERENZ mit Evidence (OID, CVEs, QoD, Lösung) ausgeben

## Checkliste
- [ ] Report nach data/greenbone/ legen (oder über /blue hochladen)
- [ ] Format erkennen und parsen (nur echte Felder: NVT, CVE, CVSS, QoD, Host, Port)
- [ ] Severity aus CVSS/Threat ableiten; Log-Level nicht als Befund führen
- [ ] Mit Target: Hosts gegen Scope filtern (default-deny)
- [ ] Findings als REFERENZ mit Evidence (OID, CVEs, QoD, Lösung) ausgeben

## Safety
- Keine Secrets/PII in Logs oder Evidence (Zugangsdaten nur aus der Umgebung)
- Nichts erfinden – ohne Greenbone/Report: „nicht verfügbar“ bzw. honest-empty
- Scope default-deny; Findings sind REFERENZ (Fremd-Scanner)

## Nutzung
`POST /api/blue/greenbone/import` (Datei-Upload oder `{"path": "datei.xml"}` relativ zu `data/greenbone/`), Colony-Param `report_path`.
