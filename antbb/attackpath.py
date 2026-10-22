"""DAG-Angriffspfad-VISUALISIERUNG (nur Planung/Darstellung, KEIN Executor).

Baut aus den (proofgate-bereinigten) Findings + Asset-/Service-Daten einen
gerichteten Graphen HYPOTHETISCHER Angriffspfade: Knoten = Asset oder Finding,
Kante = „könnte führen zu" (hypothetisch, für die Remediation). Pro Kante gibt
es einen Remediation-Hinweis. Es wird NICHTS ausgeführt, verkettet oder
ausgenutzt – reine Darstellung für den Bericht.

Harte Regel: Kanten sind als `hypothetical=True` markiert und tragen einen
Remediation-Hinweis. Keine aktive Aktion, kein Tool-Aufruf, kein Chaining.
"""
from __future__ import annotations

from typing import Optional

from . import proofgate as _pg
from .agents.base import AgentFinding, STATUS_VERIFIED
from .rating import dimension_for, SEV_WEIGHT

# Logische Phasen eines Angriffspfads (nur zur Anordnung der Knoten/Spalten).
STAGE_INTERNET = "internet"
STAGE_ASSET = "asset"
STAGE_FOOTHOLD = "foothold"      # initialer Zugang (z.B. XSS, SQLi, exposed artifact)
STAGE_ESCALATION = "escalation"  # Ausweitung (auth bypass, secret, info-disclosure)
STAGE_IMPACT = "impact"          # Wirkung (Datenabfluss, Übernahme)

# Welche Kategorie liegt auf welcher Stufe + was sie hypothetisch ermöglicht.
_CATEGORY_STAGE = {
    "xss-verified": (STAGE_FOOTHOLD, "Session-/Token-Diebstahl im Opfer-Browser"),
    "xss-indicator": (STAGE_FOOTHOLD, "möglicher Session-/Token-Diebstahl"),
    "sqli-verified": (STAGE_FOOTHOLD, "Lesezugriff auf die Datenbank"),
    "sqli-indicator": (STAGE_FOOTHOLD, "möglicher DB-Zugriff"),
    "exposed-artifact": (STAGE_FOOTHOLD, "Offenlegung von Quellcode/Konfiguration"),
    "secret-exposure": (STAGE_ESCALATION, "Nutzung exponierter Credentials/Keys"),
    "missing-auth": (STAGE_ESCALATION, "Zugriff auf privilegierte Funktion ohne Login"),
    "cors-misconfig": (STAGE_ESCALATION, "Cross-Origin-Abfluss authentifizierter Daten"),
    "cors-passive": (STAGE_ESCALATION, "potenzieller Cross-Origin-Abfluss"),
    "path-traversal": (STAGE_ESCALATION, "Lesezugriff auf serverseitige Dateien/Secrets"),
    "open-redirect": (STAGE_FOOTHOLD, "Phishing/Token-Leak über Weiterleitung"),
    "info-disclosure": (STAGE_ESCALATION, "Informationsgewinn für Folgeangriffe"),
    "version-disclosure": (STAGE_ESCALATION, "Zuordnung bekannter CVEs zur Version"),
    "threat-intel-cve": (STAGE_ESCALATION, "Ausnutzung einer bekannten CVE (falls eingesetzt)"),
    "cve-reference": (STAGE_ESCALATION, "Referenz-CVE (nur falls Technologie eingesetzt)"),
    "nmap-service": (STAGE_ASSET, "exponierter Dienst als Angriffsfläche"),
    "nuclei-finding": (STAGE_FOOTHOLD, "Template-Treffer als möglicher Einstieg"),
    "tls-scan": (STAGE_ASSET, "schwache Transport-Sicherheit"),
}

# Remediation-Hinweis je Kante-Zielkategorie (knapp; der Report hat die Details).
_EDGE_REMED = {
    "xss-verified": "Output-Encoding + strikte CSP schließen den Einstieg.",
    "sqli-verified": "Prepared Statements/ORM verhindern den DB-Zugriff.",
    "exposed-artifact": "Artefakt aus dem Web-Root entfernen, Secrets rotieren.",
    "secret-exposure": "Exponierte Secrets rotieren und Quelle schließen.",
    "missing-auth": "Authentifizierung + Autorisierung (RBAC) erzwingen.",
    "cors-misconfig": "CORS-Allowlist statt Origin-Spiegelung.",
    "path-traversal": "Pfad-Kanonisierung + Allowlist für Dateizugriffe.",
    "open-redirect": "Redirect-Ziele gegen Allowlist prüfen.",
    "version-disclosure": "Komponente patchen, Versions-Header entfernen.",
    "threat-intel-cve": "Betroffene Komponente auf gepatchte Version heben.",
    "missing-default": "Ursächlichen Befund beheben (siehe Detailbericht).",
}

_STAGE_ORDER = [STAGE_INTERNET, STAGE_ASSET, STAGE_FOOTHOLD, STAGE_ESCALATION, STAGE_IMPACT]


def _stage_for(cat: str) -> tuple[str, str]:
    return _CATEGORY_STAGE.get(cat, (STAGE_ESCALATION, "potenzieller Folgeschritt"))


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def build_attack_graph(findings: list[AgentFinding]) -> dict:
    """Baut den hypothetischen Angriffspfad-Graphen aus Findings.

    Rückgabe: {nodes, edges, paths, stages, empty, note}. Jede Kante trägt
    hypothetical=True + remediation. Keine Ausführung, keine Verkettung.
    """
    _pg.enforce(findings, None)
    counted = _pg.counted_findings(findings)

    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids = set()

    def add_node(nid, label, ntype, stage, **extra):
        if nid in node_ids:
            return
        node_ids.add(nid)
        nodes.append({"id": nid, "label": label, "type": ntype,
                      "stage": stage, **extra})

    def add_edge(a, b, label, remediation):
        edges.append({"from": a, "to": b, "label": label,
                      "hypothetical": True, "remediation": remediation})

    # Wurzel: Internet/Angreifer.
    add_node("internet", "Internet / Angreifer", "origin", STAGE_INTERNET)

    # Assets gruppieren.
    assets: dict[str, list[AgentFinding]] = {}
    for f in counted:
        assets.setdefault(f.asset or "(unbestimmtes Asset)", []).append(f)

    for asset, fs in assets.items():
        anid = "asset:" + asset
        add_node(anid, asset, "asset", STAGE_ASSET)
        add_edge("internet", anid, "erreichbar", "Angriffsfläche minimieren, Netzsegmentierung.")
        # Findings dieses Assets als Knoten + Kanten Asset→Finding.
        stage_nodes: dict[str, list[str]] = {}
        for f in fs:
            fid = f"finding:{f.category}:{f.title}:{asset}"
            stage, enables = _stage_for(f.category)
            verified = (f.status == STATUS_VERIFIED)
            add_node(fid, f.title, "finding", stage,
                     severity=f.severity, status=f.status, category=f.category,
                     verified=verified, enables=enables)
            remed = _EDGE_REMED.get(f.category, _EDGE_REMED["missing-default"])
            add_edge(anid, fid, f"könnte ermöglichen: {enables}", remed)
            stage_nodes.setdefault(stage, []).append(fid)
        # Hypothetische Eskalation: foothold → escalation → impact (nur Darstellung).
        foots = stage_nodes.get(STAGE_FOOTHOLD, [])
        escs = stage_nodes.get(STAGE_ESCALATION, [])
        for a in foots:
            for b in escs:
                add_edge(a, b, "könnte eskalieren zu (hypothetisch)",
                         "Jeden Einzelbefund beheben unterbricht die Kette.")

    # Textuelle Pfadliste (vom schwersten verifizierten Fund ausgehend).
    paths = _textual_paths(counted, assets)

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "stages": _STAGE_ORDER,
        "empty": len(counted) == 0,
        "counted": len(counted),
        "note": ("Alle Kanten sind HYPOTHETISCH und dienen der Remediation-Planung. "
                 "antbb führt keinen Pfad aus, verkettet und exploitet nichts."),
    }


def _textual_paths(counted: list[AgentFinding], assets: dict) -> list[dict]:
    """Erzeugt lesbare „A könnte zu B führen"-Pfade je Asset (max. sinnvoll)."""
    out: list[dict] = []
    for asset, fs in assets.items():
        ordered = sorted(fs, key=lambda f: _severity_rank(f.severity), reverse=True)
        steps = []
        for f in ordered:
            _, enables = _stage_for(f.category)
            steps.append({
                "finding": f.title,
                "severity": f.severity,
                "status": f.status,
                "enables": enables,
                "verified": f.status == STATUS_VERIFIED,
                "remediation": _EDGE_REMED.get(f.category, _EDGE_REMED["missing-default"]),
            })
        if steps:
            out.append({"asset": asset, "steps": steps,
                        "max_severity": ordered[0].severity})
    out.sort(key=lambda p: _severity_rank(p["max_severity"]), reverse=True)
    return out


def _as_findings(rows) -> list[AgentFinding]:
    from .findingreport import parse_evidence, _g
    out = []
    for r in rows:
        out.append(AgentFinding(
            agent=_g(r, "agent", ""), title=_g(r, "title", ""),
            category=_g(r, "category", ""), severity=_g(r, "severity", "info"),
            asset=_g(r, "asset", ""), description=_g(r, "description", ""),
            evidence=parse_evidence(r), status=_g(r, "status", ""),
            false_positive=bool(_g(r, "false_positive", 0)),
        ))
    return out


def graph_for_target(store, target_id: int) -> dict:
    return build_attack_graph(_as_findings(store.list_findings(target_id)))


def paths_markdown(graph: dict) -> str:
    """Textuelle Pfadliste als Markdown (für den Bericht)."""
    paths = graph.get("paths", [])
    if not paths:
        return "_Keine Befunde – kein Angriffspfad (ehrlicher Leerzustand)._"
    L = ["**Hypothetische Angriffspfade (nur zur Remediation, nichts wird ausgeführt):**", ""]
    for p in paths:
        L.append(f"- **Asset `{p['asset']}`** (max. Severity {p['max_severity']}):")
        for s in p["steps"]:
            vtag = "VERIFIZIERT" if s["verified"] else (s["status"] or "offen")
            L.append(f"  - [{s['severity']}/{vtag}] {s['finding']} → *könnte ermöglichen:* "
                     f"{s['enables']}  ·  _Fix:_ {s['remediation']}")
    L.append("")
    L.append("_Alle Pfade sind hypothetisch und dienen der Priorisierung der Behebung._")
    return "\n".join(L)
