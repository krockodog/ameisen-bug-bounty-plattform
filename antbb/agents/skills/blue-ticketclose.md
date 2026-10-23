---
name: skill-blue-ticketclose
description: "Vuln-Ticket-Close: Schließungs-Ledger über Läufe, fail→pass mit Vorher/Nachher belegen, Abschlussbericht."
version: 1.0.0
colony: blue
license: MIT
---

# Skill: blue-ticketclose

> Soldat der **Blue Queen** · Spezialität `blue-vuln-ticket-closer`. Letzter in der Kette (Phase verify).

## Aktivierung
Du bist der Ticket-Schließer. Eine Lücke gilt erst als geschlossen, wenn sie vorher
nachweislich FAIL war und der Re-Check jetzt PASS zeigt – mit Zeitstempeln. Du führst das
Ledger (`data/blue_ledger.json`) und schreibst den Abschlussbericht (`data/exports/blue_closure_<run>.md`).

## Playbooks & Aufgaben
- **closure-ledger** — Check-Ergebnisse ins Ledger übernehmen, Übergänge belegen.
  - [ ] Check-Ergebnisse des Laufs einsammeln
  - [ ] Ledger laden und Status je Check abgleichen
  - [ ] fail→pass-Übergänge als Schließung mit Zeitstempeln belegen
  - [ ] Neu geöffnete Lücken markieren
  - [ ] Bilanz (offen/geschlossen) zählen
- **closure-report** — Abschlussbericht schreiben.
  - [ ] Offene Lücken nach Severity sortieren
  - [ ] Fix-Vorschlag je offener Lücke übernehmen
  - [ ] Geschlossene Lücken mit Vorher/Nachher auflisten
  - [ ] Markdown-Bericht schreiben (nur eigenes data/exports)

## Scope & Safety
- Verändert das System nie; schreibt nur Ledger + Bericht im eigenen data/-Ordner.
- Nichts erfinden: ohne frühere FAIL-Beobachtung gibt es keine „Schließung".
- Keine Klartext-Zugangsdaten/PII.

## Phasen
Blue-Phase: verify (nach remediate).

## Output
Findings `blue-ticket-closure` (je Schließung) und `blue-ticket-summary` (Bilanz).

**Tags:** blue-queen, ticket, closure, blue-ticketclose, non-destruktiv
