"""Optionale, anonyme, standardmäßig AUSgeschaltete Telemetrie.

Transparenz-Prinzip (nichts verstecken):
  * Es wird NUR gesendet, wenn der Betreiber selbst ``ANTBB_TELEMETRY_URL``
    auf eine nicht-leere URL setzt. Ohne URL passiert NICHTS.
  * Zusätzlicher harter Aus-Schalter: ``ANTBB_TELEMETRY=0``.
  * Payload ist minimal und anonym – KEINE personenbezogenen Daten, KEINE
    API-Keys, KEINE Hostnamen/Usernamen/IPs im Body. (Die rohe IP sieht
    technisch nur der Endpunkt des Betreibers; das ist in der README offengelegt.)
  * Fehlertolerant: kurzes Timeout, Fehler werden still geschluckt und
    blockieren Start/Betrieb NIE. Die Funktion bleibt bewusst sichtbar und
    dokumentiert – nicht in anderen Funktionen versteckt.

Events:
  * ``install``   – einmalig vom Installer (install-and-start.sh).
  * ``heartbeat`` – periodisch vom laufenden Webserver ("ist aktiv").
Body jeweils: ``{"event": <str>, "version": <str>, "ts": <unix int>}``.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request

from . import __version__

_TIMEOUT = 3.0  # Sekunden – bewusst kurz


def is_enabled() -> bool:
    """True nur, wenn eine Telemetrie-URL gesetzt ist UND nicht per Flag aus."""
    url = os.environ.get("ANTBB_TELEMETRY_URL", "").strip()
    if not url:
        return False
    if os.environ.get("ANTBB_TELEMETRY", "1").strip() in ("0", "false", "no", "off"):
        return False
    return True


def status_line() -> str:
    """Kurzer, klarer Konsolen-Hinweis zum aktuellen Telemetrie-Status."""
    if is_enabled():
        url = os.environ.get("ANTBB_TELEMETRY_URL", "").strip()
        return (f"Optionale anonyme Telemetrie an {url} ist AN "
                f"– abschaltbar via ANTBB_TELEMETRY=0 oder leere ANTBB_TELEMETRY_URL.")
    return ("Optionale anonyme Telemetrie ist AUS (keine ANTBB_TELEMETRY_URL gesetzt) "
            "– nichts wird gesendet.")


def send_telemetry(event: str) -> bool:
    """Sendet EIN anonymes Event. Gibt True bei Versand zurück, sonst False.

    Niemals blockierend für den Aufrufer-Erfolg: Fehler → still False.
    """
    if not is_enabled():
        return False
    url = os.environ.get("ANTBB_TELEMETRY_URL", "").strip()
    body = json.dumps({
        "event": str(event),
        "version": __version__,
        "ts": int(time.time()),
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"antbb/{__version__}"},
        )
        urllib.request.urlopen(req, timeout=_TIMEOUT).close()  # noqa: S310 (operator-set URL)
        return True
    except Exception:
        return False  # bewusst still – darf Start/Betrieb nie stören


def send_async(event: str) -> None:
    """Feuert ein Event in einem Daemon-Thread ab (nicht-blockierend)."""
    if not is_enabled():
        return
    threading.Thread(target=send_telemetry, args=(event,), daemon=True).start()


def start_heartbeat(interval_s: float | None = None) -> threading.Thread | None:
    """Startet einen periodischen Heartbeat-Task (nur wenn aktiviert).

    Intervall via ``ANTBB_TELEMETRY_INTERVAL`` (Sekunden, Default 6h).
    Gibt den Daemon-Thread zurück oder None (wenn Telemetrie aus).
    """
    if not is_enabled():
        return None
    if interval_s is None:
        try:
            interval_s = float(os.environ.get("ANTBB_TELEMETRY_INTERVAL", str(6 * 3600)))
        except ValueError:
            interval_s = 6 * 3600
    interval_s = max(60.0, float(interval_s))

    def _loop() -> None:
        # Erster Heartbeat direkt nach Start, danach periodisch.
        while True:
            send_telemetry("heartbeat")
            time.sleep(interval_s)

    t = threading.Thread(target=_loop, name="antbb-telemetry-heartbeat", daemon=True)
    t.start()
    return t
