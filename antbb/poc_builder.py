"""Echter, nicht-ausführender PoC-Builder (Single Source of Truth).

Baut aus der bereits erfassten Evidence eines Findings (evidence.request +
evidence-Response-Nachweis) eine copy-paste-fähige, MENSCHLICH auszuführende
Reproduktion:

  * exakter ``curl``-Befehl (reproduziert den Request 1:1),
  * nummerierte Repro-Schritte,
  * beobachteter Beweis (was in der Response die Lücke belegt),
  * Erwartet-vs-Beobachtet.

Der PoC wird NIE automatisch abgefeuert – er ist reiner Text/Markdown, den ein
Triager/Mensch ausführt. Keine Secrets (Werte kommen nur aus der bereits
maskierten/gekürzten Evidence).

Dieses Modul importiert KEINE Agenten/Netz-Module (zyklenfrei); es arbeitet auf
den reinen Evidence-/Finding-Feldern und wird sowohl von der PoC-Ameise
(``agents/poc.py``) als auch von den Reports (``findingreport.py``) genutzt.
"""
from __future__ import annotations

from urllib.parse import quote
from typing import Any

#: Request-Schlüssel, die einen echten Request belegen (deckungsgleich mit base._REQUEST_KEYS).
_REQUEST_KEYS = ("request", "request_true", "request_false")

#: Response-Nachweis-Schlüssel aus der Evidence (deckungsgleich mit base._RESPONSE_PROOF_KEYS).
_RESPONSE_PROOF_KEYS = (
    "response_excerpt", "status", "location", "signature_matched",
    "body_similarity_true_false", "access_control_allow_origin",
    "hits", "len_true", "len_false", "reflected_unescaped", "oob_token",
    "oob_interaction", "cname", "service",
)

_LABELS = {
    "request": "",
    "request_true": " (TRUE-Zweig)",
    "request_false": " (FALSE-Zweig)",
}

# Erwartet-vs-Beobachtet je Kategorie (generisch, honest).
_EXPECTED_ACTUAL = {
    "xss-verified": (
        "Eingabe mit HTML-Sonderzeichen wird escaped oder nicht reflektiert.",
        "Benigner Marker wird UNESCAPED im HTML-Body reflektiert (ausführbarer Kontext)."),
    "sqli-verified": (
        "Eingabe wird parametrisiert; kein DB-Fehler, keine logik-/zeitabhängige Differenz.",
        "DB-Fehler bzw. TRUE/FALSE- oder Zeit-Differenz belegt SQL-Injection."),
    "open-redirect": (
        "Ein externer Zielwert wird ignoriert oder auf eine lokale Seite gezwungen.",
        "Der Server leitet mit 3xx auf die kontrollierte externe Marker-Domain um."),
    "path-traversal": (
        "Der Datei-Parameter bleibt auf das erlaubte Verzeichnis beschränkt.",
        "Die Antwort enthält die /etc/passwd-Signatur (root:…:0:0:)."),
    "exposed-artifact": (
        "Sensible Artefakte liefern 404/403 (nicht öffentlich).",
        "Artefakt liefert HTTP 200 und die erwartete Inhalts-Signatur."),
    "cors-misconfig": (
        "Access-Control-Allow-Origin spiegelt keine beliebige Origin.",
        "Der Server spiegelt die Angreifer-Origin (ggf. mit Credentials)."),
    "missing-auth": (
        "Privilegierter Endpunkt verlangt Authentifizierung (401/403).",
        "Endpunkt liefert ohne Auth HTTP 200 mit Admin-/Dashboard-Signatur."),
    "ssrf-verified": (
        "Der Server stellt KEINE ausgehende Anfrage an eine angreiferkontrollierte URL.",
        "Der Server holt die eindeutige Callback-URL ab (Out-of-Band-Interaktion) → SSRF."),
    "ssrf-indicator": (
        "Der Server stellt keine serverseitige Anfrage anhand des Parameters.",
        "In-Band-/Timing-Signal deutet auf serverseitige Anfrage (noch OOB zu bestätigen)."),
    "subdomain-takeover": (
        "Der CNAME zeigt auf einen beanspruchten Dienst, der Inhalt ausliefert.",
        "Dangling CNAME auf einen NICHT beanspruchten Dienst (Takeover-Signatur)."),
}


def _req_from_evidence(ev: dict) -> list[tuple[str, dict]]:
    out = []
    for key in _REQUEST_KEYS:
        r = ev.get(key)
        if isinstance(r, dict):
            out.append((key, r))
    return out


def _curl_for(method: str, url: str, param, value, headers: dict, label: str) -> list[str]:
    lines: list[str] = []
    hdr = ""
    for hk, hv in (headers or {}).items():
        hdr += f" -H '{hk}: {hv}'"
    # Origin ist bei CORS als eigenes Feld hinterlegt.
    if param is not None and value is not None:
        sep = "&" if "?" in url else "?"
        full = f"{url}{sep}{param}={quote(str(value))}"
        lines.append(f"# {method}{label} – Parameter {param}")
        if method.upper() == "HEAD":
            lines.append(f"curl -I{hdr} '{full}'")
        elif method.upper() not in ("GET", "HEAD", "SCAN"):
            lines.append(f"curl -i -X {method}{hdr} '{full}'")
        else:
            lines.append(f"curl -i{hdr} '{full}'")
    else:
        lines.append(f"# {method}{label}")
        verb = "" if method.upper() in ("GET", "SCAN") else f" -X {method}"
        lines.append(f"curl -i{verb}{hdr} '{url}'")
    return lines


def _observed_proof(ev: dict) -> list[str]:
    proof = []
    for k in ("status", "location", "access_control_allow_origin",
              "access_control_allow_credentials", "db", "technique",
              "signature_matched", "reflected_unescaped", "context",
              "body_similarity_true_false", "len_true", "len_false", "hits",
              "threshold_s", "oob_token", "oob_interaction", "cname", "service"):
        if k in ev and ev.get(k) not in (None, ""):
            proof.append(f"{k}={ev.get(k)}")
    return proof


def build(category: str, asset: str, title: str, evidence: Any,
          severity: str = "", description: str = "", status: str = "") -> dict:
    """Baut den echten PoC aus der Evidence. Immer ein dict (nie Exception).

    Rückgabe-Keys: curl (str), steps (list[str]), proof (str), expected (str),
    actual (str), has_active (bool), markdown (str), text (str).
    """
    ev = evidence if isinstance(evidence, dict) else {}
    reqs = _req_from_evidence(ev)

    curl_lines: list[str] = []
    for key, r in reqs:
        method = r.get("method", "GET")
        url = r.get("url", asset or "")
        param = r.get("param")
        value = r.get("value")
        headers = {}
        origin = r.get("origin")
        if origin:
            headers["Origin"] = origin
        if isinstance(r.get("headers"), dict):
            headers.update(r["headers"])
        curl_lines += _curl_for(method, url, param, value, headers, _LABELS.get(key, ""))

    proof_parts = _observed_proof(ev)
    excerpt = ev.get("response_excerpt")
    proof_text = ", ".join(proof_parts)
    if excerpt:
        proof_text += (("; " if proof_text else "") +
                       "Response-Ausschnitt: " + str(excerpt)[:200].replace("\n", " "))

    expected, actual = _EXPECTED_ACTUAL.get(category, ("", ""))

    has_active = bool(reqs) and bool(proof_parts or excerpt)

    # Nummerierte Repro-Schritte.
    steps: list[str] = []
    if curl_lines:
        steps.append("Stelle sicher, dass das Ziel in-scope/autorisiert ist.")
        steps.append("Führe den folgenden curl-Befehl aus (reiner GET/lesender Nachweis):")
        steps.append("Vergleiche die Antwort mit dem erwarteten Verhalten (siehe unten).")
        steps.append("Bestätige den Beweis anhand der beobachteten Signatur/Statuscodes.")
        if category in ("ssrf-verified",):
            steps.append("Prüfe den Out-of-Band-Listener auf die korrelierte Interaktion (Token).")
        steps.append("STOPP nach dem Nachweis – keine weitere Ausnutzung.")

    # Markdown-Block (für Reports/Triage).
    md: list[str] = []
    md.append(f"### PoC – {title}")
    if status:
        md.append(f"**Status:** {status}  ")
    if curl_lines:
        md.append("**Reproduktion (curl):**")
        md.append("```bash")
        md.extend(curl_lines)
        md.append("```")
    if steps:
        md.append("**Schritte:**")
        for i, s in enumerate(steps, 1):
            md.append(f"{i}. {s}")
    if proof_text:
        md.append(f"**Beobachteter Beweis:** {proof_text}")
    if expected:
        md.append(f"**Erwartet:** {expected}")
    if actual:
        md.append(f"**Beobachtet:** {actual}")
    if not curl_lines:
        md.append("_Kein aktiver Request/Response-Nachweis in diesem Lauf – "
                  "kein ausführbarer PoC (passiver/offener Fund)._")

    return {
        "curl": "\n".join(curl_lines),
        "steps": steps,
        "proof": proof_text,
        "expected": expected,
        "actual": actual,
        "has_active": has_active,
        "markdown": "\n".join(md),
        "text": "\n".join(md),
    }
