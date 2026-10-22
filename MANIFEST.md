# antbb – Projekt-Manifest / Struktur

**Das ist die VOLLSTÄNDIGE antbb-Plattform**, keyfrei und anonymisiert für den
geteilten/öffentlichen Gebrauch. Die Dateien unter `tests/` sind reine
Selbsttests (Smoke-Tests) – NICHT der Produktivcode. Der echte Code liegt im
Package `antbb/`.

## Wurzelverzeichnis
| Pfad | Zweck |
|------|-------|
| `install-and-start.sh` / `install.sh` | All-in-One: System-Deps (apt/dnf/pacman) + venv + pip + optionale KI-Anbieter-Abfrage + frische DB + Start der Web-GUI. Ein Befehl. |
| `run.sh` | Dünner Alias auf `install-and-start.sh`. |
| `run_web.py` | Direkter Uvicorn-Start (ohne Installer), für Entwickler. |
| `requirements.txt` | Python-Abhängigkeiten (FastAPI/uvicorn/pydantic/httpx/…). |
| `antbb.env.example` | Vorlage für lokale `antbb.env` (nur auskommentierte Platzhalter, keine echten Keys). |
| `.gitignore` | Hält Secrets/Runtime-State (`antbb.env`, `data/`, `*.db`, `*.log`, `*.cap`, …) aus dem Repo. |
| `tools_vuln_testserver.py` | Bewusst verwundbarer lokaler Test-Server (127.0.0.1) – NUR für lokale Tests. |
| `README.md` / `INSTALL.md` / `MANIFEST.md` | Doku. |
| `antbb/` | Das Produktiv-Package (siehe unten). |
| `config/` | `default.yaml` – Standard-Konfiguration (Modi, Router, Scope-Policy). |
| `tools/` | Hilfs-/Dev-Skripte (z. B. Brain-Determinismus-Test). |
| `tests/` | 18 Smoke-/Selbsttests (`smoke_test_*.py`). Keine Produktivlogik. |
| `data/` | Leerer Laufzeit-Ordner (DB/Exports entstehen hier; via `.gitignore` ausgenommen). |

## Package `antbb/` – Hauptmodule
| Modul | Beschreibung (1 Zeile) |
|-------|------------------------|
| `queen.py` | **Königin** – Orchestrierung: verteilt Aufgaben in Phasen, dispatcht Agenten parallel (asyncio), dedupliziert/priorisiert Findings. |
| `agents/` | **Arbeiter-/Soldaten-Ameisen** – spezialisierte Agenten (siehe Tabelle unten). |
| `scope.py` | **Scope-Gate** – default-deny Allowlist; out-of-scope hat Vorrang, jede Aktion wird geprüft. |
| `oversight.py` / `active_oversight.py` | **Human-Oversight** – hartes Freigabe-Gate (Häkchen) pro Target; aktive Checks nur mit aktiver Freigabe. |
| `proofgate.py` | **Proof-Gate** – Findings gelten erst mit aktiver Evidenz als „VERIFIZIERT". |
| `wlan_survey.py` | **WLAN-Scope / Coverage** – passives Site-Survey, Kanal-/Funkloch-Analyse (read-only). |
| `wlan_offensive.py` | **Offensiv-WLAN** – orchestriert etablierte Kali-WLAN-Tools (gate-pflichtig). |
| `wlan_airgorah.py` | **Airgorah-inspirierte** WLAN-Audit-Schicht (Monitor/AP/Clients/Handshake/Crack), web-nativ, oversight-gated. |
| `web/app.py` | **Web-Backend** (FastAPI) – GUI-Routen, ruft ausschließlich definierte antbb-Operationen. |
| `web/templates/` | Frontend-Templates: `base`, `index`, `target`, `trash`, `brain`, `wlan`. |
| `web/static/` | Frontend-Assets: `wlan*.js`, `soldiers.js`, `brain/*` (Neural-Brain), Sprites, `style.css`, 3D-Vendor (three.js). |
| `service.py` | Service-Fassade – gemeinsame Logik für CLI und Web. |
| `cli.py` / `__main__.py` | CLI-Einstieg (pydantic-frei nutzbar). |
| `store.py` | SQLite-Persistenz (Targets, Scopes, Findings, Reports, Brain). |
| `brain_ops.py` | **Neural-Brain** – Node-/Log-Operationen, Auto-Backup, Secret-/Env-Schutz. |
| `reports.py` / `brandedreport.py` / `rating.py` | Report-Erzeugung (inkl. gebrandeter PDF/Print-Report) + Risiko-Rating. |
| `registry.py` / `router.py` | Agenten-/Tool-Registry und LLM-Provider-Router. |
| `llm.py` / `prompts.py` / `oauth.py` | LLM-Anbindung, Prompt-Vorlagen, OAuth-Token-Store (verschlüsselt). |
| `config.py` | Konfig-Laden/Defaults. |
| `netutil.py` | Netz-Hilfen (DNS/HTTP/TLS, nicht-destruktiv). |
| `egress_firewall.py` | Ausgehende Verbindungen gegen Scope prüfen. |
| `poc_builder.py` / `replay.py` / `attackpath.py` | PoC-Erzeugung, Request-Replay, Angriffspfad-Analyse. |
| `codeaudit.py` | Statische Quell-Review (read-only) mit Secret-Maskierung. |
| `remote_access.py` | Optionaler Fernzugriff/Tunnel (lokal gesteuert). |
| `sdk.py` | Programmatische SDK-Fassade. |
| `disclaimer.py` | Pflicht-Rechtshinweis (§202a-c StGB / CFAA). |
| `wordlists.py` | Zentrale Wortlisten-Auflösung (SecLists/rockyou-Pfade, graceful-degrade). |
| `telemetry.py` | **Optionale, anonyme, standardmäßig AUSgeschaltete** Telemetrie (siehe README). |
| `plugins/` | Plugin-Beispiele (z. B. Header-Check). |
| `tools/kali.py` | Adapter für externe CLI-Tools (nmap/ffuf/gobuster/nikto/nuclei/wpscan/…). |

## Agenten/Soldaten (`antbb/agents/`)
`base` (Basisklasse), `recon`, `scanning`, `osint`, `auth`, `mobile`, `fuzz`,
`poc`, `ssrf`, `takeover`, `verify`, `reporting`, `codeaudit`, `llmsec`,
`threatintel`, `infra`, `cloud`, `wifi`, `analysis`, `api`.
Je Agent eine Skill-Beschreibung unter `agents/skills/*.md` (+ `reference/`).

## Roadmap / NOCH NICHT enthalten (ehrlich)
- **Blue Queen (Verteidigungs-Königin):** noch **nicht gebaut**. Sie folgt
  separat (eigener Job, u. a. lokaler CVE-Lab-Fall mit Detection + Auto-Fix).
  In dieser Distribution ist **kein** Blue-Queen-Code enthalten; es wird nichts
  dergleichen vorgetäuscht.
