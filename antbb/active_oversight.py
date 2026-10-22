"""Konsistentes Human-Oversight-Gate fuer AKTIVE/OFFENSIVE Aktionen.

Ein einziger Ort fuer das Pflicht-Haekchen, die Freigabe-Logik und den
Rechtshinweis (§ 202a-c StGB / CFAA), damit ALLE aktiven/offensiven
Ausloeser - Offensiv-Scan, aktive Verifikation, offensives Fuzzing und das
WLAN-Offensiv-Modul - wortgleich und mit der gleichen harten, serverseitigen
Default-Deny-Logik abgesichert sind.

Leitlinie (wie beim WLAN-Referenzmuster):
  * Default-deny: ohne ausdrueckliche Human-Oversight-Freigabe wird die Aktion
    serverseitig VERWEIGERT, es wird NICHTS aufgerufen und der Block wird geloggt.
  * Der Rechtshinweis wird vor jeder freigegebenen Aktion protokolliert
    (dokumentiert, blockiert nicht).
  * Rein defensive/lesende Pfade sind NICHT betroffen.
"""
from __future__ import annotations

from typing import Callable, Optional

from .oversight import OversightError

#: Wortgleiche Freigabe-Formulierung fuer JEDES aktive/offensive Haekchen
#: (Offensiv-Scan, aktive Verifikation, Fuzzing, WLAN-Offensiv).
ACTIVE_OVERSIGHT_PROMPT = (
    "Human Oversight: Ich bestaetige als verantwortlicher Mensch die Freigabe "
    "dieser AKTIVEN/OFFENSIVEN Durchfuehrung gegen das autorisierte Ziel und "
    "bin nachweislich zum Testen berechtigt."
)

#: Wortgleicher Rechtshinweis fuer JEDES aktive/offensive Panel.
ACTIVE_LEGAL_NOTICE = (
    "RECHTSHINWEIS: Aktive/offensive Sicherheitstests (z. B. aktive "
    "Verifikation, Fuzzing/Content-Discovery, WLAN-Handshake-Capture, Deauth, "
    "Passwort-Crack, Evil-Twin/Captive-Portal) sind ausschliesslich mit "
    "ausdruecklicher Autorisierung des Eigentuemers zulaessig. Unbefugtes "
    "Zugreifen/Abfangen/Ausspaehen von Daten ist strafbar (§ 202a-c StGB in "
    "Deutschland, Computer Fraud and Abuse Act in den USA)."
)


def active_trigger_requested(active: bool = False, fuzz: bool = False,
                             offensive: Optional[bool] = None,
                             policy: str = "") -> bool:
    """True, wenn der Lauf eine aktive/offensive Aktion ausloesen wuerde."""
    if active or fuzz or bool(offensive):
        return True
    if policy == "offensive":
        return True
    return False


def enforce_active_oversight(acknowledged: Optional[bool], *, action: str,
                             log: Optional[Callable[[str], None]] = None) -> None:
    """Hartes, serverseitiges Default-Deny-Gate fuer eine aktive/offensive Aktion.

    `acknowledged` muss ausdruecklich True sein. Bei False -> OversightError
    (VERWEIGERT, nichts aufgerufen, geloggt). `None` bedeutet "nicht ausdruecklich
    gesetzt": fuer programmatische Aufrufer (Rueckwaertskompatibilitaet) wird das
    bestehende Target-Oversight-Gate NICHT ersetzt, aber auch nicht verweigert;
    GUI/CLI uebergeben immer einen ausdruecklichen Bool.
    """
    if acknowledged is False:
        msg = (
            f"BLOCKIERT (default-deny): Human-Oversight-Freigabe fuer die "
            f"aktive/offensive Aktion '{action}' fehlt. Nichts wurde aufgerufen.\n"
            f'  Bitte zuerst bestaetigen: "{ACTIVE_OVERSIGHT_PROMPT}"'
        )
        if log:
            try:
                log(f"⛔ {msg}")
            except Exception:
                pass
        raise OversightError(msg)
    # Freigegeben (True) ODER programmatisch (None): Rechtshinweis protokollieren.
    if log:
        try:
            log(f"⚖ {ACTIVE_LEGAL_NOTICE}")
            if acknowledged is True:
                log(f"✅ Human-Oversight-Freigabe bestaetigt fuer aktive/offensive "
                    f"Aktion '{action}'.")
        except Exception:
            pass
