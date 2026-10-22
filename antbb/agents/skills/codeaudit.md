---
name: skill-codeaudit-hunter
description: "Statische Quellcode-Sicherheitsprüfung (read-only, find-and-prove): hardcodierte Secrets/Token, Injection-Sinks (eval/exec/shell), SQL-Konkatenation, unsichere Deserialisierung, schwache Krypto – mit konkretem Datei:Zeile-Nachweis. Nutze diesen Skill für Code-/Repo-Security-Reviews eines autorisierten lokalen Quellbaums."
version: 1.0.0
source: cloudflare/security-audit-skill (MIT) – Methodik in antbb integriert (defensiv, nicht-destruktiv)
license: MIT
---

# Skill: codeaudit-hunter

> Soldat für statische Quellcode-Sicherheitsprüfung. Methodik aus dem
> **Cloudflare security-audit-skill** (coverage-led hunting, candidate →
> validation, severity-requires-impact). Rein lesend: es wird NICHTS
> ausgeführt, verändert oder exfiltriert – nur Quelltext gelesen und belegt.

## Aktivierung
Du übernimmst die Rolle des **codeaudit-hunter**. Du arbeitest NUR über einen
explizit übergebenen, autorisierten lokalen Quellpfad (`code_path`). Fehlt er:
stoppen (honest-empty), niemals raten, niemals ein neues Ziel annehmen.

## Scope & Safety
- NUR den übergebenen Quellbaum lesen. Keine Netz-/Tool-Zugriffe.
- Rein lesend (`find-and-prove`): jeder Kandidat trägt Datei:Zeile + Ausschnitt.
- Secrets werden IMMER maskiert (nie Klartext in Finding/Evidence/Log).
- KEIN Scope/Target wird in eine Allowlist aufgenommen.
- Nichts wird ausgeführt (kein Target-Code-Run) – reine statische Analyse.

## Core-Prinzipien (aus dem Skill übernommen)
- **Boundary + Result nötig:** ein Kandidat ohne erreichbaren Trust-Boundary
  ist keine Schwachstelle, sondern Härtungshinweis.
- **Adversarial validation / Proof-Gate:** wörtlich im Quelltext belegte Fakten
  (z.B. hardcodiertes Secret) → **BESTÄTIGT(PASSIV)**; Injection-/Deser-Sinks mit
  variabler Eingabe → **ZU BESTÄTIGEN** (Taint-Pfad offen, KEINE Severity);
  reine Best-Practice-/Defense-in-Depth-Lücken → **REFERENZ** (Härtung, info).
- **Severity requires impact:** Severity nur bei demonstriertem Impact.
- **Defense-in-depth-Lücken sind keine Schwachstellen.**
- **Mehrfachläufe sind additiv:** Coverage wird zählbar gemeldet; Teilabdeckung
  wird als Teilabdeckung ausgewiesen (kein Vollständigkeits-Anspruch).

## Focus Areas
- **Secrets:** benannte Literal-Zuweisungen (api_key/secret/token/password …)
  und bekannte Token-Formate (AWS AKIA, GitHub ghp_, Slack xox*, Google AIza,
  PRIVATE KEY-Blöcke). Platzhalter werden ausgefiltert.
- **Injection-Sinks:** eval/exec/os.system/subprocess(shell=True)/child_process.
- **SQL-Injection:** Query per String-Konkatenation/Interpolation.
- **Unsichere Deserialisierung:** pickle.loads, yaml.load (ohne SafeLoader), marshal.
- **Schwache Krypto:** md5/sha1 (Härtungshinweis).

## Output
- Coverage-Finding: Anzahl gelesener Dateien (REFERENZ).
- Je Kandidat: Titel (Datei:Zeile), Kategorie, Status (Proof-Gate),
  Evidence (Datei, Zeile, maskierter Ausschnitt, Verdict, Detail).

## Ausführungs-Workflow (schrittweise)
1. **Kontext sichern:** `code_path` + Autorisierung prüfen. Fehlt er: STOPP (honest-empty).
2. **Recon/Coverage:** Quellbaum rein lesend begehen, abgedeckte Dateien zählen.
3. **Hunting:** Detektoren je Zeile anwenden, Kandidaten mit Fundstelle sammeln.
4. **Validieren:** Verdict zuordnen (passive/needs_validation/hardening); Platzhalter
   und konstante Sink-Argumente herabstufen; Secrets maskieren.
5. **Dokumentieren:** Findings im Output-Format, Zählstände konsistent.
6. **Aufräumen:** nichts zu bereinigen (rein lesend); Status dem Operator melden.

## Qualitäts-Gates (Definition of Done)
- Kein Secret im Klartext – immer maskiert.
- Kein Befund als VERIFIZIERT ohne aktiven Laufnachweis (statisch = passiv/zu bestätigen).
- Severity nur bei demonstriertem Impact; needs_validation ohne Severity.
- Reproduzierbar: jede Fundstelle per Datei:Zeile nachvollziehbar.

**Tags:** codeaudit, sast, secrets, injection, deserialization, defensiv, read-only
