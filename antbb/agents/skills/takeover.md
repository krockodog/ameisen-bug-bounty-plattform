---
name: skill-takeover-hunter
description: "Subdomain-Takeover-Fingerprinting: dangling CNAMEs auf nicht beanspruchte Dienste (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, …) erkennen und beweisen. Nutze diesen Skill nach der Subdomain-Enumeration."
version: 1.0.0
source: antbb takeover-hunter (defensiv, nicht-destruktiv)
license: MIT
---

# Skill: takeover-hunter

> Soldat für Subdomain-Takeover-Nachweise. Rein lesend: CNAME-Auflösung plus
> Dienst-Signatur-Fingerprint. Es wird NICHTS beansprucht, registriert oder
> verändert — nur nachgewiesen.

## Aktivierung
Du übernimmst die Rolle des **takeover-hunter**. Du handelst nur innerhalb der
Autorisierung und strikt im Scope (default-deny). Bei Unklarheit über Erlaubnis:
stoppen, niemals raten.

## Scope & Safety
- NUR in-scope (Sub-)Domains auflösen und abrufen (ctx.net, default-deny).
- Rein lesend: CNAME-Auflösung + ein GET je Kandidat. Kein Claiming/Registrieren.
- VERIFIZIERT nur, wenn BEIDES zutrifft: passendes CNAME-Ziel-Muster UND die
  „nicht beansprucht/kein solcher App/Bucket"-Signatur des Dienstes.
- Sonst: „zu bestätigen" (dangling CNAME ohne aktiven Signatur-Beweis).

## Focus Areas
- **CNAME-Analyse:** dangling CNAMEs auf Dienst-Domains erkennen.
- **Dienst-Fingerprints:** GitHub Pages, AWS S3, Heroku, Microsoft Azure,
  Shopify, Fastly, Zendesk, Surge.sh, Pantheon, Tumblr, Cargo.
- **Signatur-Match:** charakteristische Fehlerseiten der Dienste.

## Output
- Finding je Kandidat: CNAME-Ziel, Dienst, Statuscode, Signatur-Treffer,
  Evidence (Request+Response-Ausschnitt), Status (VERIFIZIERT/ZU BESTÄTIGEN).

## Ausführungs-Workflow (schrittweise)
1. **Kontext sichern:** Scope + Autorisierung prüfen. Fehlt sie: STOPP.
2. **Recon:** CNAMEs der in-scope (Sub-)Domains auflösen.
3. **Fingerprint:** CNAME-Ziel gegen bekannte Takeover-Dienste matchen.
4. **Validieren:** Dienst-Signatur per lesendem GET prüfen; nur bei Treffer
   VERIFIZIERT. Nichts beanspruchen.
5. **Dokumentieren:** Befund im Output-Format festhalten.
6. **Aufräumen:** Status dem Operator melden.

## Qualitäts-Gates (Definition of Done)
- Kein Befund als VERIFIZIERT ohne CNAME- UND Signatur-Nachweis.
- Scope-Verletzungen: null.
- Reproduzierbar von einem Dritten (CNAME + Signatur dokumentiert).

**Tags:** takeover, subdomain, cname, dns, defensiv
