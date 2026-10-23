# Blue Queen – was in diesem Baum liegt

Dieses Repository ist die **Verteidigungs-Königin** (Blue Queen): Kolonie,
Orchestrierung, Scope, Human Oversight, Web unter `/blue`.

Keine Angriffs-Kolonie, kein WLAN-Offensiv, kein Pentest-Gehirn als Oberfläche.

## Start

| Pfad | Zweck |
|------|--------|
| `run.sh` | Startet `install-and-start.sh` |
| `install-and-start.sh` | venv, Abhängigkeiten, optional Provider, Web auf `/blue` |
| `run_web.py` | Uvicorn ohne Installer |
| `requirements.txt` | Python-Abhängigkeiten |
| `antbb.env.example` | Platzhalter, keine echten Keys |

## Kolonie

| Pfad | Zweck |
|------|--------|
| `antbb/blue_queen.py` | Königin: Phasen, Dispatch, Proof-Gate, Router |
| `antbb/agents/blue/` | Verteidigungs-Soldaten |
| `antbb/agents/skills/blue-*.md` | Skill-Texte |
| `antbb/playbooks/blue/` | Playbooks |
| `antbb/jobs.py` | Wiederholbare Jobs |
| `antbb/router.py`, `antbb/llm.py`, `antbb/llm_providers.py` | Provider-Router, nur Laufzeit-Keys |
| `antbb/prompts.py` | Textvorlagen für die Einordnung |
| `antbb/hardening.py`, `antbb/remediation.py`, `antbb/softwarescan.py` | Lesende Checks |
| `antbb/watcher.py`, `antbb/honeypot.py`, `antbb/attack_log.py` | Wächter, Decoy-Plan, Attack-Log |
| `antbb/splunk.py` | Optionaler HEC-Adapter |
| `antbb/greenbone.py` | Greenbone/OpenVAS: Report-Import (defensiv), Scan nur mit Oversight + Scope |
| `antbb/agents/blue/greenbone.py` | Soldat `blue-greenbone` |

## Gemeinsame Fassung

| Pfad | Zweck |
|------|--------|
| `antbb/service.py` | Fassade für Web und CLI |
| `antbb/store.py` | SQLite |
| `antbb/scope.py`, `antbb/oversight.py`, `antbb/active_oversight.py` | Gates |
| `antbb/proofgate.py` | Beleg-Pflicht |
| `antbb/disclaimer.py` | Rechtshinweis § 202a–c StGB / CFAA |
| `antbb/web/` | FastAPI, Vorlage `/blue` |

`tests/test_bluequeen.py` prüft Soldaten, einen Lauf und `/blue`.
