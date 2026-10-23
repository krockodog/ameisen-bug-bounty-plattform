"""Capability-Registry der Königin (Single Source of Truth).

Beim Start liest die Königin JEDEN Soldaten (Agenten-Klasse) ein und baut die
Registry FRISCH aus den deklarativen `playbooks` jedes Soldaten auf — nie
hartkodiert, nie veraltet. Jeder Soldat hat einen klar benannten SKILL mit
seiner Playbook-Liste; jedes Playbook trägt eine Liste konkreter AUFGABEN/
CHECKS (task items) mit Default-Status, damit die GUI-Checklisten gefüllt sind.

Zusätzlich werden die am Laufort verfügbaren externen Kali-Tools und die
Wortlisten erfasst (nutzbare Tools der Königin). NIEMALS Secrets.
"""
from __future__ import annotations

import time
from typing import Optional

from .agents import WORKER_AGENTS
from .agents.blue import BLUE_AGENTS, BLUE_PHASES

_SECRET_MARKERS = ("api_key", "apikey", "token", "secret", "password", "minimax")


def _scrub(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _SECRET_MARKERS)


import os as _os

_SKILLS_DIR = _os.path.join(_os.path.dirname(__file__), "agents", "skills")

def load_skill_md(soldier: str) -> str:
    """Lädt den Octogent-SKILL.md-Volltext eines Soldaten (oder '' wenn keiner)."""
    path = _os.path.join(_SKILLS_DIR, f"{soldier}.md")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""

# OctoGent-Orchestrator-Phasenmodell (recon → vuln-assessment → exploitation →
# post-exploitation → reporting). Ordnet antbb-Soldaten + Tools je Phase zu.
# Exploitation/Post-Exploitation nur unter Offensiv+Oversight, nicht-destruktiv.
OCTOGENT_PHASES = [
    {"phase": "recon", "label": "Reconnaissance & OSINT", "mode": "defensive",
     "soldiers": ["recon", "takeover", "osint", "infra", "mobile", "wifi"],
     "tools": ["nmap", "subfinder", "httpx", "whatweb", "sslscan"],
     "maps_to": "recon"},
    {"phase": "vuln-assessment", "label": "Vulnerability Assessment", "mode": "defensive",
     "soldiers": ["scanning", "api", "cloud", "auth", "llmsec", "codeaudit"],
     "tools": ["nuclei", "nikto", "wafw00f", "wpscan"],
     "maps_to": "scan"},
    {"phase": "exploitation", "label": "Exploitation (Offensiv+Oversight)", "mode": "offensive",
     "soldiers": ["fuzz", "verify", "poc"],
     "tools": ["sqlmap", "gobuster", "ffuf", "interactsh-client (OOB/OAST)", "metasploit (nur auxiliary/scanner)"],
     "maps_to": "verify",
     "note": "Nur unter Offensiv+Oversight, nicht-destruktiv."},
    {"phase": "post-exploitation", "label": "Post-Exploitation (dokumentiert, nicht automatisch)",
     "mode": "offensive", "soldiers": ["analysis"],
     "tools": ["(dokumentiert: Persistenz/Lateral/C2 NICHT automatisch)"],
     "maps_to": "analyze",
     "note": "Persistenz/Laterale Bewegung/C2 nur als dokumentierte, oversight-"
             "pflichtige Optionen – NIE automatisch gegen fremde Systeme."},
    {"phase": "reporting", "label": "Reporting & Debrief", "mode": "defensive",
     "soldiers": ["threatintel", "reporting"],
     "tools": ["NVD-API", "searchsploit", "report-builder"],
     "maps_to": "report"},
]

# Hinterlegter Scope aus den Octogent-Vorlagen – NUR Vorschlag/Historie, NICHT
# automatisch erlaubt. Die echte Allowlist bleibt explizit + default-deny.
SCOPE_SUGGESTIONS = {
    "note": ("Vorschlag/Historie – NICHT automatisch erlaubt. Die echte Allowlist bleibt explizit + default-deny."),
    "targets": ["demo.example.com", "shop.example.com", "app.example.com"],
    "separate_engagement": ["engagement.example.com"],
}


# ---------------------------------------------------------------------------
# Zentrale Aufgaben-/Check-Liste je Playbook (konkrete Schritte, nicht nur Titel).
# Gefüllt für ALLE Soldaten. Default-Status pro Task: "offen".
# ---------------------------------------------------------------------------
TASK_CATALOG: dict[str, list[str]] = {
    # --- recon ---
    "dns-aufklaerung": ["A/AAAA-Records auflösen", "CNAME prüfen", "MX-Records erfassen",
                         "TXT-Records (SPF/Verifikation) lesen"],
    "subdomain-enumeration": ["Wortliste gegen Zone auflösen", "nur in-scope Subdomains behalten",
                              "Wildcard-DNS erkennen"],
    "tcp-connect-portscan": ["Standard-Ports verbinden", "offene Ports protokollieren",
                             "riskante Ports (FTP/SMTP/DB) markieren"],
    "nmap-service-scan": ["Top-Ports scannen (nmap)", "Dienst-/Versionsbanner lesen (-sV, offensiv)",
                          "riskante Dienste markieren"],
    # --- mobile ---
    "manifest-analyse": ["AndroidManifest-Permissions prüfen", "exported Components erkennen",
                         "cleartextTraffic-Flag prüfen"],
    "certificate-pinning": ["Pinning-Konfiguration suchen", "fehlendes Pinning melden"],
    "ios-ats": ["App Transport Security prüfen", "ATS-Ausnahmen erkennen"],
    # --- scanning ---
    "http-fingerprint": ["Statuscode erfassen", "Server-Header lesen", "x-powered-by auswerten",
                         "Content-Type bestimmen"],
    "security-header-analyse": ["CSP vorhanden?", "HSTS vorhanden?", "X-Content-Type-Options prüfen",
                                "X-Frame-Options prüfen", "Referrer-Policy prüfen"],
    "exposed-paths": ["/.git/ prüfen", "/.env prüfen", "/server-status prüfen",
                      "Directory-Listing erkennen"],
    "injection-indikatoren": ["Parameter-Reflektion testen (Marker)", "SQL-Fehler-Indikator (')"],
    "whatweb-fingerprint": ["Technologien via whatweb erkennen", "Versionen extrahieren"],
    "waf-detect": ["WAF/IPS via wafw00f erkennen"],
    "nuclei-scan": ["nuclei-Templates (low–critical) laufen", "Treffer nach Severity einordnen",
                    "als 'zu bestätigen' führen (kein eigener PoC)"],
    "nikto-scan": ["nikto Web-Server-Checks", "Treffer als 'zu bestätigen' führen"],
    "wpscan": ["WordPress erkennen", "Version/Plugins auflisten (nur wenn WP)"],
    # --- api ---
    "api-surface-discovery": ["OpenAPI/Swagger suchen", "GraphQL-Endpoint prüfen", "API-Wurzeln prüfen"],
    "nuclei-api": ["nuclei gegen API-Oberfläche", "Treffer einordnen"],
    "sqlmap-verify": ["parametrisierte URL finden", "sqlmap --batch (nicht-destruktiv)",
                      "Injizierbarkeit aktiv bestätigen", "kein dump/os-shell"],
    # --- infra ---
    "tls-inspektion": ["TLS-Protokollversion lesen", "Zertifikatsablauf prüfen",
                       "schwache Protokolle erkennen"],
    "email-auth-dns": ["SPF (TXT) auswerten", "DMARC-Policy prüfen"],
    "caa-dns": ["CAA-Records auswerten"],
    "sslscan-tls": ["sslscan Cipher/Protokolle", "SSLv2/3 & TLS1.0/1.1 melden"],
    # --- osint ---
    "security-txt": ["/.well-known/security.txt lesen", "Kontakt prüfen", "Freemail-Kontakt melden"],
    "csp-analyse": ["unsafe-inline erkennen", "unsafe-eval erkennen", "externe CDNs auflisten"],
    "permissions-policy": ["Permissions-Policy-Header prüfen"],
    "trufflehog-secrets": ["autorisierte Git/FS/GitHub-Quelle scannen", "verifizierte Secrets melden",
                           "Secrets IMMER maskieren (nie Klartext)"],
    "username-enumeration": ["Username/Handle explizit uebergeben", "sherlock laufen (Fallback maigret)",
                             "gefundene Plattformen/URLs strukturieren", "als REFERENZ fuehren (kein aktiver Nachweis)",
                             "Profile NICHT abrufen/scrapen", "honest-empty wenn Tool fehlt"],
    # --- cloud ---
    "storage-reference-detect": ["S3/GCS/Azure-Blob-Referenzen suchen", "öffentliche Buckets markieren"],
    "cloud-header-hints": ["Cloud-/CDN-Header erkennen (via, x-amz, x-azure)"],
    # --- auth ---
    "cookie-flag-analyse": ["HttpOnly prüfen", "Secure prüfen", "SameSite prüfen"],
    "auth-surface-discovery": ["Login-/Admin-Oberflächen finden", "Auth-Endpunkte erfassen"],
    # --- llmsec ---
    "llm-endpoint-discovery": ["LLM-/Chat-Endpunkte erkennen"],
    "prompt-injection-aktiv": ["benigne Prompt-Injection-Marker testen (nur offensiv)",
                               "Reflexion als Indikator melden"],
    # --- fuzz ---
    "content-discovery": ["Baseline/Catch-all messen", "Wortliste GET-probing",
                          "nur signifikante Abweichungen melden"],
    "parameter-fuzzing": ["Parameter-Marker einsetzen", "Reflektion/Fehler erkennen"],
    "gobuster-discovery": ["SecLists-Wortliste wählen", "gobuster dir-Modus", "gefundene Pfade melden"],
    "ffuf-fuzzing": ["FUZZ-Platzhalter setzen", "ffuf mit Wortliste", "Treffer nach Status filtern"],
    # --- verify ---
    "aktive-xss-bestaetigung": ["benignen XSS-Marker einsetzen", "unescaped Reflektion prüfen",
                                "Evidence (Request+Response) erfassen"],
    "aktive-sqli-bestaetigung": ["Boolean TRUE/FALSE vergleichen", "DB-Fehler-Signatur prüfen",
                                 "time-based nur konservativ"],
    "open-redirect-bestaetigung": ["Redirect-Parameter testen", "Location auf externe Domain prüfen"],
    "path-traversal-bestaetigung": ["../-Sequenz testen", "Datei-Signatur in Response prüfen"],
    "exposed-artifact-bestaetigung": ["Artefakt abrufen (.git/.env)", "Inhaltssignatur bestätigen"],
    "cors-bestaetigung": ["Origin-Spiegelung testen", "ACAO + credentials prüfen"],
    "missing-auth-bestaetigung": ["privilegierten Endpunkt ohne Auth abrufen", "Zugriff bestätigen"],
    "ssrf-bestaetigung": ["URL-/Webhook-/Image-Parameter entdecken",
                          "in-scope Canary + eindeutige interactsh-OOB-URL injizieren",
                          "OOB-Interaktion korrelieren (blind SSRF)",
                          "ohne OOB nur In-Band-Signal als 'zu bestätigen' führen",
                          "nur GET/HEAD, nach Beweis stoppen (nicht-destruktiv)"],
    "subdomain-takeover-fingerprint": ["CNAME der (Sub-)Domain auflösen",
                                       "gegen bekannte Takeover-Dienste matchen (GitHub/S3/Heroku/Azure/…)",
                                       "Dienst-'nicht beansprucht'-Signatur prüfen",
                                       "VERIFIZIERT nur bei CNAME- UND Signatur-Match",
                                       "nichts beanspruchen/registrieren (nur Nachweis)"],
    "metasploit-aux-scanner": ["nur auxiliary/scanner/* (hart allowlisted)", "nicht-destruktiv run",
                               "Treffer als 'zu bestätigen' führen"],
    # --- analysis ---
    "cvss-vorschlag": ["Severity je Finding ableiten", "CVSS-Score schätzen (als Schätzung markiert)"],
    "angriffsketten-korrelation": ["zusammenhängende Findings verketten", "Angriffspfad skizzieren"],
    # --- codeaudit (statische Quell-Review, read-only) ---
    "source-credential-scan": ["autorisierten Quellpfad (code_path) rein lesend begehen",
                           "benannte Secret-Literale erkennen (api_key/token/password/…)",
                           "bekannte Token-Formate matchen (AWS/GitHub/Slack/Google/PRIVATE KEY)",
                           "Platzhalter/Env-Referenzen ausfiltern (keine Scheinbefunde)",
                           "Werte IMMER maskieren (nie Klartext)"],
    "source-injection-review": ["gefährliche Sinks finden (eval/exec/os.system/subprocess shell=True)",
                                "SQL per String-Konkatenation/Interpolation erkennen",
                                "unsichere Deserialisierung (pickle/yaml.load/marshal) erkennen",
                                "konstantes Sink-Argument zu Härtungshinweis herabstufen",
                                "variable Eingabe als ZU BESTÄTIGEN führen (Taint-Pfad offen, keine Severity)",
                                "Coverage (gelesene Dateien) zählbar melden"],
    # --- threatintel ---
    "tech-cve-korrelation": ["Fingerprints parsen", "Katalog-CVE zuordnen", "Version-Gating (REFERENZ/BEDINGT)"],
    "nvd-cve-lookup": ["Technologie+Version extrahieren", "NVD-API abfragen (Rate-Limit)",
                       "CVSS von NVD übernehmen (nie erfinden)"],
    "searchsploit-lookup": ["lokale Exploit-DB durchsuchen", "Treffer als REFERENZ führen"],
    # --- poc ---
    "poc-template-builder": ["Reproduktions-Request bauen", "nur aus echter Evidence"],
    # --- reporting ---
    "report-aggregation": ["Findings aggregieren", "Severity-/Status-Zählung (Single Source)"],
    "proof-gate-validierung": ["VERIFIZIERT ohne Evidence herabstufen", "Catch-all als FP markieren",
                               "Zählstände konsistent halten"],
    # --- wifi ---
    "wlan-scan": ["lokale WLANs scannen (nmcli/iw)", "SSID/Kanal/Signal erfassen",
                  "Verschlüsselung bestimmen"],
    "wlan-konfig-check": ["WEP/offen erkennen", "WPS/TKIP-Schwächen melden"],
    "wlan-optimierung": ["Kanalbelegung bewerten", "Kanal-/Signal-Empfehlung geben"],
    "wlan-handshake-capture": ["Engagement-Gate prüfen (default-deny)", "Rechtshinweis loggen",
                               "WPA-Handshake/PMKID gegen autorisierte BSSID erfassen",
                               "Capture-Pfad+Meta speichern (nie Secrets)", "honest-empty ohne Tool"],
    "wlan-targeted-deauth": ["Engagement-Gate prüfen (default-deny)", "Rechtshinweis loggen",
                             "GEZIELTER Deauth nur gegen autorisierte BSSID (paket-/zeitbegrenzt)",
                             "kein Broadcast/Massen-Deauth", "Warnung: trennt Clients"],
    "wlan-offline-crack": ["Engagement-Gate prüfen (default-deny)", "Wortliste wählen (rockyou/SecLists)",
                           "OFFLINE gegen eigene/autorisierte Capture cracken",
                           "Ergebnis maskiert speichern (nie Klartext)", "honest-empty ohne Tool/Capture"],
    "wlan-evil-twin-demo": ["Engagement-Gate prüfen (default-deny)", "Rechtshinweis loggen",
                            "Rogue-AP + Captive-Portal zeitbegrenzt (operator-getrieben)",
                            "Credentials nur als Nachweis (maskiert/gehasht)",
                            "Auto-Purge nach Report"],
    # --- blue queen ---
    "sw-inventory": ["Paketmanager rein lesend abfragen (dpkg/rpm/pip)",
                     "Paketname+Version erfassen", "keine Secrets"],
    "sw-cve-match-osv": ["Inventar gegen OSV abgleichen", "CVE-IDs nur aus OSV übernehmen",
                         "nie erfundene Schwachstellen"],
    "hardening-audit": ["SSH-Config prüfen", "Firewall-Status prüfen",
                        "world-writable Dateien in /etc finden", "sysctl-Härtung prüfen"],
    "hardening-apply": ["Fix-Vorschlag NUR mit Oversight anwenden (default-deny)",
                        "nie automatisch ohne Freigabe"],
    "detection-ruleset": ["Detection-Regeln bereitstellen", "Quellen zuordnen"],
    "splunk-forward": ["Events an HEC spiegeln wenn konfiguriert",
                       "ohne Config sauber überspringen"],
    "remediation-plan": ["Finding→Fix-Schritt ableiten", "konkreten Behebungsschritt vorschlagen"],
    "remediation-verify": ["rein lesender Re-Check", "Vorher/Nachher-Evidence",
                           "nachweislich geschlossen belegen"],
    "honeypot-recipes": ["sichere Decoy-Rezepte dokumentieren"],
    "honeypot-deploy": ["Decoy NUR mit Oversight starten (default-deny, Scaffold)"]
}


def _tasks_for(pb: dict) -> list[dict]:
    """Baut die Task-Items (mit Default-Status) für ein Playbook."""
    name = pb.get("name", "")
    items = list(pb.get("tasks") or []) or TASK_CATALOG.get(name)
    if not items:
        # Fallback: aus Tools/Beschreibung ableiten (ehrlich, generisch).
        items = [f"{t} ausführen" for t in pb.get("tools", [])] or [pb.get("description", name)]
    return [{"task": t, "status": "offen",
             "oversight": bool(pb.get("oversight_required"))} for t in items]


def build_registry(agents=None, include_blue: bool = True) -> dict:
    if agents is None:
        agents = list(WORKER_AGENTS) + (list(BLUE_AGENTS) if include_blue else [])
    soldiers = []
    pb_count = 0
    tool_count = 0
    task_count = 0
    for cls in agents:
        desc = cls.describe()
        clean_pbs = []
        for pb in desc.get("playbooks", []):
            if _scrub(pb.get("name", "")) or _scrub(pb.get("description", "")):
                continue
            pb["tools"] = [t for t in pb.get("tools", []) if not _scrub(t)]
            pb["task_items"] = _tasks_for(pb)
            clean_pbs.append(pb)
            pb_count += 1
            tool_count += len(pb["tools"])
            task_count += len(pb["task_items"])
        desc["playbooks"] = clean_pbs
        # Klar benannter Skill je Soldat (mit seiner Playbook-Liste).
        skill_md = load_skill_md(cls.name)
        desc["skill"] = {
            "name": desc.get("specialty") or desc.get("name"),
            "skill_md": skill_md,
            "has_skill_md": bool(skill_md),
            "summary": desc.get("role", ""),
            "playbooks": [p["name"] for p in clean_pbs],
            "playbook_count": len(clean_pbs),
            "task_count": sum(len(p["task_items"]) for p in clean_pbs),
        }
        try:
            from . import prompts as _prompts
            desc["prompt"] = _prompts.for_soldier(cls.name)
        except Exception:
            desc["prompt"] = {}
        soldiers.append(desc)
    soldiers.sort(key=lambda d: d.get("specialty", d.get("name", "")))

    # Nutzbare externe Tools + Wortlisten am Laufort (keine Secrets).
    try:
        from .tools import kali as _kali
        kali_tools = _kali.tool_status()
    except Exception:
        kali_tools = {}
    try:
        from . import wordlists as _wl
        wl_status = _wl.status()
    except Exception:
        wl_status = {}

    try:
        from . import sdk as _sdk
        plugins_block = _sdk.registry_block()
    except Exception:
        plugins_block = {"plugin_count": 0, "plugins": [], "errors": []}

    return {
        "built_at": time.time(),
        "soldier_count": len(soldiers),
        "playbook_count": pb_count,
        "tool_count": tool_count,
        "task_count": task_count,
        "soldiers": soldiers,
        "kali_tools": kali_tools,
        "wordlists": wl_status,
        "plugins": plugins_block,
        "octogent_phases": OCTOGENT_PHASES,
        "blue_phases": list(BLUE_PHASES),
        "blue_soldier_count": sum(1 for s in soldiers if s.get("colony") == "blue"),
        "scope_suggestions": SCOPE_SUGGESTIONS,
        "prompt_categories": list(__import__("antbb.prompts", fromlist=["PROMPT_TEMPLATES"]).PROMPT_TEMPLATES),
    }


def persist_registry(store, registry: Optional[dict] = None) -> dict:
    registry = registry or build_registry()
    store.replace_capabilities(registry)
    return registry


def get_registry(store) -> dict:
    return store.get_capabilities()
