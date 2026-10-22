"""Fernzugriff / Remote-Access: Präferenz + ehrliche, rein lesende Status-Erkennung.

Diese Datei trifft KEINE Netz-Entscheidungen und startet NICHTS. Sie:
  * liest die gespeicherte Präferenz (off | tailscale | cloudflare) aus dem Store,
  * erkennt rein lesend, ob `tailscale` bzw. `cloudflared` installiert sind und
    (bei Tailscale) ob der Dienst läuft inkl. der 100.x-IP – via
    `tailscale status --json` mit kurzem Timeout,
  * liefert ehrliche, handfeste Setup-Schritte je Modus.

Harte Sicherheits-Prinzipien (wie der Rest von antbb):
  * honest-empty: fehlt ein Binary, wird das ehrlich gemeldet – NIE eine
    IP/Hostname/Status erfunden.
  * read-only: nur `--version` bzw. `status --json`. Es wird NIE ein Tunnel
    gestartet, nichts ins Internet exponiert, keine Konfig geschrieben.
  * keine Secrets: ein etwaiger Cloudflare-Token wird ausschließlich zur
    Laufzeit aus der Umgebungsvariable CLOUDFLARE_TUNNEL_TOKEN gelesen – NIE in
    DB/Datei geschrieben, NIE geloggt, NIE ausgegeben.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

#: Erlaubte Modi (Single Source of Truth).
MODES = ("off", "tailscale", "cloudflare")
DEFAULT_MODE = "off"

#: Lokaler GUI-Port (nur zur Anzeige der Beispiel-URLs).
GUI_PORT = 1001

#: Name der Env-Var für ein etwaiges Cloudflare-Tunnel-Token. Der WERT wird NIE
#: gespeichert/geloggt – nur zur Laufzeit von `cloudflared` selbst gelesen.
CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_TUNNEL_TOKEN"


def normalize_mode(mode: Optional[str]) -> str:
    m = (mode or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run_readonly(argv: list, timeout: float = 4.0) -> tuple[int, str, str]:
    """Führt ein rein lesendes Kommando aus (kein shell=True, hartes Timeout).

    Gibt (returncode, stdout, stderr) zurück; bei Timeout/Fehler returncode=-1.
    """
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        return (proc.returncode,
                (proc.stdout or b"").decode("utf-8", "replace"),
                (proc.stderr or b"").decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except Exception as exc:  # pragma: no cover - defensiv
        return (-1, "", str(exc))


def tailscale_status() -> dict:
    """Rein lesender Tailscale-Status. honest-empty ohne Binary/Daemon.

    NIE erfundene IP/Hostname: Werte stammen ausschließlich aus
    `tailscale status --json`.
    """
    path = resolve_binary("tailscale")
    out: dict = {
        "installed": bool(path),
        "path": path or "",
        "running": False,
        "backend_state": "",
        "ip": "",            # 100.x CGNAT-IP des eigenen Geräts
        "hostname": "",
        "url": "",
        "detail": "",
    }
    if not path:
        out["detail"] = "tailscale nicht installiert"
        return out
    rc, so, se = _run_readonly([path, "status", "--json"])
    if rc != 0 or not so.strip():
        out["detail"] = (se.strip() or "tailscale status nicht verfügbar "
                         "(Daemon aus / nicht angemeldet)")
        return out
    try:
        data = json.loads(so)
    except Exception:
        out["detail"] = "tailscale status nicht lesbar (kein gültiges JSON)"
        return out
    state = str(data.get("BackendState") or "")
    out["backend_state"] = state
    out["running"] = (state == "Running")
    self_node = data.get("Self") or {}
    ips = self_node.get("TailscaleIPs") or []
    ip4 = next((ip for ip in ips if ip.startswith("100.")), "")
    out["ip"] = ip4 or (ips[0] if ips else "")
    dns = str(self_node.get("DNSName") or "").rstrip(".")
    out["hostname"] = dns
    if out["ip"]:
        out["url"] = f"http://{out['ip']}:{GUI_PORT}"
    if not out["detail"]:
        out["detail"] = (f"Tailscale läuft (BackendState={state})"
                         if out["running"]
                         else f"Tailscale installiert, aber nicht aktiv "
                              f"(BackendState={state or 'unbekannt'})")
    return out


def cloudflared_status() -> dict:
    """Rein lesender cloudflared-Status (nur Verfügbarkeit/Version)."""
    path = resolve_binary("cloudflared")
    out: dict = {
        "installed": bool(path),
        "path": path or "",
        "version": "",
        "token_env_present": False,  # nur Vorhandensein, NIE der Wert
        "url": "",
        "detail": "",
    }
    # Nur Vorhandensein der Env-Var melden – niemals den Token-WERT.
    import os as _os
    out["token_env_present"] = bool(_os.environ.get(CLOUDFLARE_TOKEN_ENV, "").strip())
    if not path:
        out["detail"] = "cloudflared nicht installiert"
        return out
    rc, so, se = _run_readonly([path, "--version"])
    ver = (so or se).strip().splitlines()
    out["version"] = ver[0] if ver else ""
    out["detail"] = out["version"] or "cloudflared installiert"
    return out


def status_for(mode: Optional[str] = None) -> dict:
    """Vollständiger, ehrlicher Status beider Transporte + aktiver Modus."""
    m = normalize_mode(mode)
    ts = tailscale_status()
    cf = cloudflared_status()
    rt = cloudflare_tunnel_runtime()
    if rt.get("running") and rt.get("url"):
        cf["url"] = rt["url"]
    cf["tunnel"] = rt
    active_url = ""
    if m == "tailscale":
        active_url = ts.get("url", "")
    elif m == "cloudflare":
        active_url = (rt.get("url") or cf.get("url", ""))
    return {
        "mode": m,
        "modes": list(MODES),
        "local_url": f"http://127.0.0.1:{GUI_PORT}",
        "active_url": active_url,
        "tailscale": ts,
        "cloudflare": cf,
        "token_env_name": CLOUDFLARE_TOKEN_ENV,
    }


def setup_steps(mode: str) -> list:
    """Ehrliche, manuelle Schritte, um den gewählten Transport hochzufahren.

    Es werden NUR Anweisungen zurückgegeben – hier wird nichts ausgeführt.
    """
    m = normalize_mode(mode)
    if m == "off":
        return [
            "Kein Fernzugriff: die GUI ist nur lokal erreichbar "
            f"(http://127.0.0.1:{GUI_PORT}).",
            "Nichts ist nach außen exponiert – die sicherste Grundeinstellung.",
        ]
    if m == "tailscale":
        return [
            "Tailscale installieren (falls nicht vorhanden): "
            "https://tailscale.com/download",
            "Anmelden/verbinden:  sudo tailscale up",
            "Status prüfen:  tailscale status",
            f"Danach ist die GUI im eigenen Tailnet erreichbar unter "
            f"http://<100.x.y.z>:{GUI_PORT} (nur für Geräte in deinem Tailnet, "
            "kein offenes Internet).",
            "antbb startet oder exponiert Tailscale NICHT automatisch – du "
            "entscheidest und führst 'tailscale up' selbst aus.",
        ]
    # cloudflare
    return [
        "cloudflared installieren (falls nicht vorhanden): "
        "https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/",
        "Schnell-Variante (temporärer trycloudflare-Hostname, öffentlich!):  "
        f"cloudflared tunnel --url http://127.0.0.1:{GUI_PORT}",
        "Benannter Tunnel mit Token: Token als Umgebungsvariable "
        f"{CLOUDFLARE_TOKEN_ENV} setzen und  cloudflared tunnel run  starten.",
        "WICHTIG: Ein Cloudflare-Tunnel macht die lokale GUI über das "
        "ÖFFENTLICHE Internet erreichbar. Nur mit eigener Authentifizierung/"
        "Access-Policy verwenden.",
        "Der Token wird NIE von antbb gespeichert oder geloggt – er wird nur "
        f"zur Laufzeit aus der Env-Var {CLOUDFLARE_TOKEN_ENV} von cloudflared "
        "selbst gelesen.",
        "antbb startet den Tunnel NICHT automatisch – du führst den Befehl "
        "selbst aus.",
    ]


# ===========================================================================
# AKTIVE Tunnel-Steuerung (oversight-gated). NEU: antbb kann den Cloudflare-
# Tunnel (und ein Tailscale-up) jetzt selbst STARTEN/STOPPEN – aber nur, wenn
# der Mensch das Oversight-Flag setzt. Default bleibt: nichts wird automatisch
# exponiert. Es werden KEINE Secrets gespeichert: ein benannter Tunnel liest
# sein Token nur zur Laufzeit aus CLOUDFLARE_TUNNEL_TOKEN.
# ===========================================================================
import os as _os
import re as _re
import signal as _signal
import time as _time
import json as _json
from pathlib import Path as _Path

#: Zusätzliche Binary-Suchpfade (die systemd-PATH enthält ~/.local/bin oft NICHT).
_EXTRA_BIN_DIRS = [
    _os.environ.get("ANTBB_BIN", "").strip(),
    str(_Path(__file__).resolve().parent.parent / "bin"),   # <antbb_root>/bin
    _os.path.expanduser("~/.local/bin"),
    _os.path.expanduser("~/bin"),
    "/opt/antbb/bin",
]


def resolve_binary(binary: str) -> Optional[str]:
    """shutil.which + bekannte antbb-lokale bin-Verzeichnisse (ohne root nutzbar)."""
    hit = shutil.which(binary)
    if hit:
        return hit
    override = _os.environ.get("ANTBB_" + binary.upper().replace("-", "_"), "").strip()
    if override and _os.path.isfile(override) and _os.access(override, _os.X_OK):
        return override
    for d in _EXTRA_BIN_DIRS:
        if not d:
            continue
        cand = _os.path.join(d, binary)
        if _os.path.isfile(cand) and _os.access(cand, _os.X_OK):
            return cand
    return None


def _state_path() -> str:
    data_dir = _Path(__file__).resolve().parent.parent / "data"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        data_dir = _Path(_os.path.expanduser("~"))
    return str(data_dir / "cf_tunnel.json")


def _read_state() -> dict:
    try:
        with open(_state_path(), "r", encoding="utf-8") as fh:
            return _json.load(fh) or {}
    except Exception:
        return {}


def _write_state(st: dict) -> None:
    try:
        with open(_state_path(), "w", encoding="utf-8") as fh:
            _json.dump(st, fh)
    except Exception:
        pass


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        _os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _log_path() -> str:
    return str(_Path(_state_path()).parent / "cf_tunnel.log")


def cloudflare_tunnel_runtime() -> dict:
    """Laufzeit-Status des von antbb verwalteten Cloudflare-Tunnels.

    honest: meldet nur, was wirklich läuft (PID lebt) und welche URL im Log
    tatsächlich auftauchte – nichts erfunden.
    """
    st = _read_state()
    pid = st.get("pid")
    alive = _pid_alive(pid)
    url = st.get("url", "")
    if alive and not url:
        url = _scrape_trycloudflare_url()
        if url:
            st["url"] = url
            _write_state(st)
    return {
        "running": bool(alive),
        "pid": pid if alive else None,
        "url": url if alive else "",
        "mode": st.get("kind", ""),
        "started_ts": st.get("started_ts"),
        "detail": ("Tunnel läuft" if alive else "kein von antbb verwalteter Tunnel aktiv"),
    }


def _scrape_trycloudflare_url() -> str:
    try:
        with open(_log_path(), "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read()
    except Exception:
        return ""
    m = _re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", txt)
    return m[-1] if m else ""


def start_cloudflare_tunnel(oversight: bool = False, named: bool = False,
                            local_port: int = GUI_PORT) -> dict:
    """Startet den Cloudflare-Tunnel – NUR mit Oversight (Mensch).

    * named=False: schneller trycloudflare-Tunnel (öffentliche Zufalls-URL).
    * named=True : benannter Tunnel; Token NUR aus CLOUDFLARE_TUNNEL_TOKEN zur
      Laufzeit (nie gespeichert/geloggt). Erfordert gesetztes Token.
    Gibt einen ehrlichen Status zurück; exponiert NICHTS ohne oversight=True.
    """
    if not oversight:
        return {"ok": False, "running": False, "url": "",
                "reason": "Oversight-Gate: Start nur mit menschlichem Oversight-Haken."}
    cur = cloudflare_tunnel_runtime()
    if cur["running"]:
        return {"ok": True, "running": True, "url": cur["url"], "pid": cur["pid"],
                "reason": "Tunnel läuft bereits."}
    cfd = resolve_binary("cloudflared")
    if not cfd:
        return {"ok": False, "running": False, "url": "",
                "reason": "cloudflared nicht gefunden (installiere es nach "
                          "<antbb>/bin/ oder setze ANTBB_CLOUDFLARED)."}
    run_env = None
    if named:
        token = _os.environ.get(CLOUDFLARE_TOKEN_ENV, "").strip()
        if not token:
            return {"ok": False, "running": False, "url": "",
                    "reason": f"Benannter Tunnel braucht {CLOUDFLARE_TOKEN_ENV} "
                              "(Token nur zur Laufzeit, nie gespeichert)."}
        # Token NICHT auf die Kommandozeile (waere in `ps` sichtbar), sondern nur
        # als TUNNEL_TOKEN in die Subprozess-Umgebung – cloudflared liest ihn dort.
        run_env = dict(_os.environ)
        run_env["TUNNEL_TOKEN"] = token
        argv = [cfd, "tunnel", "--no-autoupdate", "run"]
        kind = "named"
    else:
        argv = [cfd, "tunnel", "--no-autoupdate",
                "--url", f"http://127.0.0.1:{local_port}"]
        kind = "quick"
    try:
        logf = open(_log_path(), "w", encoding="utf-8")
    except Exception as exc:
        return {"ok": False, "running": False, "url": "",
                "reason": f"Log-Datei nicht schreibbar: {exc}"}
    try:
        proc = subprocess.Popen(
            argv, stdout=logf, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
            close_fds=True, env=run_env,
        )
    except Exception as exc:
        return {"ok": False, "running": False, "url": "",
                "reason": f"cloudflared-Start fehlgeschlagen: {exc}"}
    _write_state({"pid": proc.pid, "kind": kind, "url": "",
                  "started_ts": _time.time()})
    # Kurz auf die trycloudflare-URL warten (nur beim quick-Tunnel sinnvoll).
    url = ""
    if kind == "quick":
        for _ in range(20):
            _time.sleep(0.5)
            url = _scrape_trycloudflare_url()
            if url:
                break
    if url:
        st = _read_state(); st["url"] = url; _write_state(st)
    return {"ok": True, "running": _pid_alive(proc.pid), "pid": proc.pid,
            "url": url, "kind": kind,
            "reason": ("Tunnel gestartet." if url or kind == "named"
                       else "Tunnel gestartet, URL noch nicht im Log – gleich erneut Status abfragen.")}


def stop_cloudflare_tunnel() -> dict:
    """Beendet den von antbb verwalteten Cloudflare-Tunnel (SIGTERM der Gruppe)."""
    st = _read_state()
    pid = st.get("pid")
    if not _pid_alive(pid):
        _write_state({})
        return {"ok": True, "running": False, "reason": "Kein aktiver Tunnel."}
    try:
        try:
            _os.killpg(_os.getpgid(int(pid)), _signal.SIGTERM)
        except Exception:
            _os.kill(int(pid), _signal.SIGTERM)
        for _ in range(10):
            _time.sleep(0.3)
            if not _pid_alive(pid):
                break
        if _pid_alive(pid):
            try:
                _os.killpg(_os.getpgid(int(pid)), _signal.SIGKILL)
            except Exception:
                _os.kill(int(pid), _signal.SIGKILL)
    except Exception as exc:
        return {"ok": False, "running": _pid_alive(pid),
                "reason": f"Stop fehlgeschlagen: {exc}"}
    _write_state({})
    return {"ok": True, "running": False, "reason": "Tunnel gestoppt."}
