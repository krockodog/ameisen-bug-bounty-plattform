"""SSRF-Checks (Server-Side Request Forgery) – aktiv, nicht-destruktiv.

Leitplanken (hart eingehalten, deckungsgleich mit verify.py):
  * Läuft NUR unter Oversight + aktivem Verifikations-Schalter (ctx.active).
  * Jeder Request an das ZIEL läuft über ctx.net → Scope default-deny +
    Rate-Limit. Die Callback-/Canary-URL wird nur als PARAMETERWERT in einen
    in-scope Request an das Ziel gelegt; antbb selbst ruft die Callback-Domain
    NIE auf (kein Scope-Bypass).
  * Nur lesende GET/HEAD; keine interne Ausnutzung über den Fetch-Nachweis
    hinaus. Nach dem Beweis wird gestoppt (demonstrate-and-stop).
  * Out-of-Band (OOB) via interactsh beweist blind SSRF → VERIFIZIERT.
    Ohne OOB bleibt ein In-Band-/Timing-Signal bewusst „zu bestätigen".
  * Keine Secrets/Ziele in der Callback-Domain (nur Zufalls-Token).

Die eigentliche Logik steht als wiederverwendbare Funktion ``run_ssrf_checks``
hier, damit sie (a) von VerifyAnt._ssrf aufgerufen und (b) im Smoke-Test direkt
mit einem lokalen OOB-Stub geprüft werden kann.
"""
from __future__ import annotations

import secrets

from .base import AgentFinding, STATUS_VERIFIED, STATUS_TO_CONFIRM

#: URL-/Redirect-/Webhook-/Image-Fetch-ähnliche Parameter (SSRF-Kandidaten).
DEFAULT_SSRF_PARAMS = [
    "url", "uri", "u", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_uri", "next", "target", "callback", "webhook",
    "image", "img", "imageurl", "image_url", "fetch", "load", "feed",
    "proxy", "data", "path", "file", "domain", "host", "site", "page",
]

#: Eindeutiger In-Band-Canary-Marker (wird vom Ziel-Fetch im Body sichtbar).
_CANARY_MARK = "antbbSSRFCANARY"


def _canary_marker(token: str) -> str:
    return f"{_CANARY_MARK}{token}"


async def run_ssrf_checks(net, cfg, base, *, agent="verify", oob=None,
                          log=None, params=None):
    """Führt die SSRF-Checks gegen eine Basis-URL aus. Gibt list[AgentFinding].

    `net`  : scope-/ratengebundener NetClient.
    `cfg`   : ScanConfig (für Parameter-Kandidaten + Obergrenzen).
    `base`  : in-scope Basis-URL (z.B. http://host).
    `oob`   : optionale OOB/OAST-Session (InteractshSession-artig) mit
              .available, .payload_url(token), .poll()->set(tokens).
    """
    def _log(msg):
        if log:
            log(msg)

    out: list[AgentFinding] = []
    cand = list(params or getattr(cfg, "av_ssrf_param_candidates", None) or DEFAULT_SSRF_PARAMS)
    # Harte Obergrenze an getesteten Parametern (Last begrenzen).
    max_params = max(1, int(getattr(cfg, "av_ssrf_max_params", 12) or 12))
    cand = cand[:max_params]

    oob_ready = bool(oob is not None and getattr(oob, "available", False))

    for param in cand:
        # --- (i) In-Band-Canary: in-scope Callback auf das Ziel selbst ---
        c_token = secrets.token_hex(6)
        marker = _canary_marker(c_token)
        canary_url = base.rstrip("/") + f"/antbb-ssrf-canary-{c_token}?m={marker}"
        resp = await net.http_get(base + "/", params={param: canary_url})
        inband_proven = False
        if resp is not None:
            body = resp.text or ""
            if marker in body:
                inband_proven = True

        # --- (ii) OOB-Callback: eindeutige interactsh-URL als Parameterwert ---
        oob_hit = False
        oob_token = ""
        if oob_ready:
            oob_token = "ssrf" + secrets.token_hex(6)
            cb = ""
            try:
                cb = oob.payload_url(oob_token)
            except Exception:
                cb = ""
            if cb:
                # antbb requestet NUR das in-scope Ziel; der Callback kommt (falls
                # verwundbar) vom Server selbst.
                await net.http_get(base + "/", params={param: cb})

        if oob_ready and oob_token:
            try:
                hits = oob.poll() or set()
            except Exception:
                hits = set()
            # Token steckt im Subdomain-Label; interactsh lowercased es.
            if oob_token.lower() in {str(h).lower() for h in hits}:
                oob_hit = True

        if oob_hit:
            _log(f"[ssrf] ✅ SSRF (OOB) bestätigt @ {base} (param '{param}', interactsh-Callback)")
            out.append(AgentFinding(
                agent=agent, title=f"SSRF bestätigt – Out-of-Band (Parameter '{param}')",
                category="ssrf-verified", severity="high", asset=base,
                description=("Der Server holte eine eindeutige, angreiferkontrollierte "
                             "Callback-URL ab (Out-of-Band-Interaktion über interactsh) → "
                             "Server-Side Request Forgery, auch blind nachweisbar. Nur der "
                             "Fetch wurde bewiesen; keine interne Ausnutzung."),
                evidence={"request": {"method": "GET", "url": base + "/", "param": param,
                                      "value": "<interactsh-callback-url>",
                                      "note": "lesender GET; Callback kam vom Server (OOB)"},
                          "confidence": "bestätigt", "technique": "oob-interactsh",
                          "oob_interaction": True, "oob_token": oob_token,
                          "response_excerpt": "OOB-Interaktion (DNS/HTTP) korreliert zum Token"},
                status=STATUS_VERIFIED,
                dedup_key=f"ssrf-verified:{base}:{param}",
            ))
            continue

        if inband_proven:
            _log(f"[ssrf] ℹ️ SSRF In-Band-Signal @ {base} (param '{param}') – zu bestätigen (kein OOB)")
            out.append(AgentFinding(
                agent=agent, title=f"SSRF-Indikator – serverseitiger Fetch (Parameter '{param}')",
                category="ssrf-indicator", severity="medium", asset=base,
                description=("Der eindeutige In-Band-Canary (in-scope URL) tauchte in der "
                             "Antwort auf → Hinweis auf serverseitige Anfrage. Ohne "
                             "Out-of-Band-Bestätigung bleibt der Befund „zu bestätigen"
                             "\" (kein interactsh verfügbar / kein OOB-Treffer)."),
                evidence={"request": {"method": "GET", "url": base + "/", "param": param,
                                      "value": canary_url,
                                      "note": "lesender GET auf in-scope Canary"},
                          "confidence": "indikator", "technique": "in-band-canary",
                          "signature_matched": True,
                          "response_excerpt": f"Canary-Marker {marker} in der Antwort reflektiert"},
                status=STATUS_TO_CONFIRM,
                dedup_key=f"ssrf-indicator:{base}:{param}",
            ))
    return out
