"""Echte, rein lesende Blue-Team-Checks für die erweiterten Blue-Soldaten.

Domänen: patchmgmt · logintegrity (+ Ledger für alle Blue-Audit-Soldaten)
Jeder Check liefert ein `hardening.CheckResult` (pass/fail/info) mit konkreter
Fix-EMPFEHLUNG. Es wird NICHTS verändert; fehlt Tool/Recht, liefert der Check
ehrlich `info` (nie Schein-Pass). Dazu: ein kleines Ledger (data/blue_ledger.json),
das über Läufe hinweg fail→pass-Übergänge als „nachweislich geschlossen"
(Vorher/Nachher mit Zeitstempeln) belegt.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from .hardening import CheckResult, _read, _run
from . import config as _config

DOMAINS = ("patchmgmt", "logintegrity")

def _data_dir() -> Path:
    try:
        return Path(_config.DATA_DIR)
    except Exception:
        return Path(__file__).resolve().parent.parent / "data"


def _age_days(ts: float) -> float:
    return max(0.0, (time.time() - ts) / 86400.0)


# ===========================================================================
# patchmgmt
# ===========================================================================
def _apt_upgradable() -> Optional[list[str]]:
    if not shutil.which("apt"):
        return None
    out = _run(["apt", "list", "--upgradable"], timeout=20)
    lines = [l for l in out.splitlines() if "/" in l and "upgradable" in l]
    return lines


def check_pending_updates() -> CheckResult:
    cid, title = "patch-pending-updates", "Patch-Management: keine ausstehenden Updates"
    lines = _apt_upgradable()
    mgr = "apt"
    if lines is None:
        if shutil.which("dnf"):
            out = _run(["dnf", "-C", "-q", "check-update"], timeout=25)
            lines = [l for l in out.splitlines()
                     if l.strip() and not l.startswith(("Obsoleting", "Security:"))
                     and len(l.split()) >= 3]
            mgr = "dnf"
        else:
            return CheckResult(cid, title, "info",
                               "Kein unterstützter Paketmanager (apt/dnf) gefunden.")
    sec = [l for l in lines if "-security" in l or "security" in l.lower()]
    ev = {"manager": mgr, "pending": len(lines), "security": len(sec),
          "sample": [l.split("/")[0].split()[0] for l in lines[:12]]}
    if not lines:
        return CheckResult(cid, title, "pass", f"{mgr}: System aktuell (laut lokalem Cache).",
                           evidence=ev)
    sev = "high" if sec else ("medium" if len(lines) > 20 else "low")
    cmd = "sudo apt update && sudo apt upgrade" if mgr == "apt" else "sudo dnf upgrade --refresh"
    return CheckResult(cid, title, "fail",
                       f"{len(lines)} Update(s) ausstehend, davon {len(sec)} sicherheitsrelevant.",
                       "Ausstehende Updates im Wartungsfenster einspielen.", sev, cmd, ev)


def check_reboot_required() -> CheckResult:
    cid, title = "patch-reboot-required", "Patch-Management: kein Neustart ausstehend"
    flag = "/var/run/reboot-required"
    if os.path.exists(flag):
        pk = _read("/var/run/reboot-required.pkgs").split()
        return CheckResult(cid, title, "fail", "Neustart nach Updates erforderlich.",
                           "Neustart einplanen, damit Kernel/Bibliotheks-Patches greifen.",
                           "medium", "sudo systemctl reboot",
                           {"packages": pk[:12]})
    if os.path.isdir("/var/run") and shutil.which("apt"):
        return CheckResult(cid, title, "pass", "Kein Neustart-Flag gesetzt.")
    return CheckResult(cid, title, "info", "Kein reboot-required-Mechanismus erkennbar.")


def check_unattended_upgrades() -> CheckResult:
    cid, title = "patch-auto-security", "Patch-Management: automatische Sicherheits-Updates"
    if not shutil.which("apt"):
        return CheckResult(cid, title, "info", "Nur für apt-Systeme geprüft.")
    conf = _read("/etc/apt/apt.conf.d/20auto-upgrades")
    on = bool(re.search(r'Unattended-Upgrade\s+"1"', conf))
    installed = "install ok installed" in _run(["dpkg", "-s", "unattended-upgrades"])
    ev = {"unattended_upgrades_installed": installed, "periodic_enabled": on}
    if installed and on:
        return CheckResult(cid, title, "pass", "unattended-upgrades installiert und aktiv.",
                           evidence=ev)
    return CheckResult(cid, title, "fail",
                       "Automatische Sicherheits-Updates nicht aktiv "
                       f"(installiert={installed}, periodic={on}).",
                       "unattended-upgrades installieren und aktivieren.", "low",
                       "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
                       ev)


def check_kernel_current() -> CheckResult:
    cid, title = "patch-kernel-current", "Patch-Management: laufender Kernel = neuester installierter"
    running = _run(["uname", "-r"]).strip()
    kernels = []
    try:
        for fn in os.listdir("/boot"):
            if fn.startswith("vmlinuz-"):
                kernels.append(fn[len("vmlinuz-"):])
    except Exception:
        pass
    if not running or not kernels:
        return CheckResult(cid, title, "info", "Kernel-Liste (/boot) nicht verfügbar.")

    def key(v: str):
        return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+_~]", v)]
    try:
        newest = sorted(kernels, key=key)[-1]
    except TypeError:
        newest = sorted(kernels)[-1]
    ev = {"running": running, "newest_installed": newest}
    if running == newest:
        return CheckResult(cid, title, "pass", f"Läuft auf {running}.", evidence=ev)
    return CheckResult(cid, title, "fail",
                       f"Läuft auf {running}, neuer installiert: {newest}.",
                       "Neustart einplanen, um den neuesten Kernel zu booten.", "medium",
                       "sudo systemctl reboot", ev)


def run_patchmgmt() -> list[CheckResult]:
    return _run_all([check_pending_updates, check_reboot_required,
                     check_unattended_upgrades, check_kernel_current])


# ===========================================================================
# logintegrity
# ===========================================================================
def check_log_journal_persistent() -> CheckResult:
    cid, title = "log-journal-persistent", "Logs: journald speichert persistent"
    if not shutil.which("journalctl"):
        return CheckResult(cid, title, "info", "journald nicht vorhanden.")
    if os.path.isdir("/var/log/journal"):
        return CheckResult(cid, title, "pass", "/var/log/journal vorhanden (persistent).")
    conf = _read("/etc/systemd/journald.conf")
    if re.search(r"^\s*Storage\s*=\s*persistent", conf, re.M):
        return CheckResult(cid, title, "pass", "Storage=persistent konfiguriert.")
    return CheckResult(cid, title, "fail", "Journal nur flüchtig (geht beim Neustart verloren).",
                       "Persistentes Journal anlegen (Forensik/Nachvollziehbarkeit).", "low",
                       "sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald")


def check_log_auditd() -> CheckResult:
    cid, title = "log-auditd-active", "Logs: Audit-Subsystem (auditd) aktiv"
    act = _run(["systemctl", "is-active", "auditd"]).strip()
    if act == "active":
        return CheckResult(cid, title, "pass", "auditd aktiv.")
    if os.path.isdir("/var/log/audit") and shutil.which("auditctl"):
        return CheckResult(cid, title, "fail", f"auditd installiert, Status: {act or 'unbekannt'}.",
                           "auditd aktivieren.", "low", "sudo systemctl enable --now auditd")
    return CheckResult(cid, title, "fail", "auditd nicht installiert/aktiv.",
                       "auditd installieren und Basis-Regeln (Identität/sudo/ssh) laden.", "low",
                       "sudo apt install auditd")


def check_log_permissions() -> CheckResult:
    cid, title = "log-permissions", "Logs: keine world-writable Logdateien"
    bad: list[str] = []
    try:
        for root, _d, files in os.walk("/var/log"):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    if not os.path.islink(p) and os.lstat(p).st_mode & 0o002:
                        bad.append(p)
                except Exception:
                    continue
            if len(bad) >= 20:
                break
    except Exception:
        return CheckResult(cid, title, "info", "/var/log nicht lesbar.")
    if not bad:
        return CheckResult(cid, title, "pass", "Keine world-writable Dateien in /var/log.")
    return CheckResult(cid, title, "fail", f"{len(bad)} world-writable Logdatei(en).",
                       "Schreibrechte für 'other' entfernen (Manipulationsschutz).", "high",
                       "sudo chmod o-w <datei>", {"files": bad[:20]})


def check_log_rotation() -> CheckResult:
    cid, title = "log-rotation", "Logs: Rotation aktiv"
    if not os.path.exists("/etc/logrotate.conf"):
        return CheckResult(cid, title, "info", "logrotate nicht installiert (journald-only möglich).")
    timer = _run(["systemctl", "is-active", "logrotate.timer"]).strip() == "active"
    cron = os.path.exists("/etc/cron.daily/logrotate")
    if timer or cron:
        return CheckResult(cid, title, "pass",
                           "logrotate geplant (" + ("timer" if timer else "cron") + ").")
    return CheckResult(cid, title, "fail", "logrotate konfiguriert, aber nicht geplant.",
                       "logrotate.timer aktivieren.", "low",
                       "sudo systemctl enable --now logrotate.timer")


def check_log_time_sync() -> CheckResult:
    cid, title = "log-time-sync", "Logs: Systemzeit synchronisiert (Beweiswert)"
    v = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip().lower()
    if v == "yes":
        return CheckResult(cid, title, "pass", "NTP-synchronisiert.")
    if v == "no":
        return CheckResult(cid, title, "fail", "Zeit nicht synchronisiert.",
                           "NTP aktivieren – nicht synchronisierte Logs haben geringen Beweiswert.",
                           "low", "sudo timedatectl set-ntp true")
    return CheckResult(cid, title, "info", "timedatectl nicht verfügbar.")


def check_log_offhost_copy() -> CheckResult:
    cid, title = "log-offhost-copy", "Logs: Off-Host-Kopie (Manipulationsschutz)"
    conf = ""
    for f in ["/etc/rsyslog.conf"] + [
            os.path.join("/etc/rsyslog.d", x) for x in
            (os.listdir("/etc/rsyslog.d") if os.path.isdir("/etc/rsyslog.d") else [])]:
        conf += _read(f)
    fwd = bool(re.search(r"^\s*[^#\n]*(@@?[A-Za-z0-9.\-]+|omfwd)", conf, re.M))
    try:
        from . import splunk as _sp
        splunk = bool(_sp.status().get("configured"))
    except Exception:
        splunk = False
    ev = {"syslog_forwarding": fwd, "splunk_hec": splunk}
    if fwd or splunk:
        return CheckResult(cid, title, "pass",
                           "Logs werden extern gespiegelt (" + ("syslog" if fwd else "Splunk-HEC") + ").",
                           evidence=ev)
    return CheckResult(cid, title, "fail", "Keine Off-Host-Kopie der Logs konfiguriert.",
                       "Logs an Syslog-Ziel oder Splunk (HEC) weiterleiten – Angreifer können "
                       "lokale Logs löschen.", "low", evidence=ev)


def run_logintegrity() -> list[CheckResult]:
    return _run_all([check_log_journal_persistent, check_log_auditd, check_log_permissions,
                     check_log_rotation, check_log_time_sync, check_log_offhost_copy])


# ===========================================================================
# Registry + Helfer
# ===========================================================================
RUNNERS: dict[str, Callable[[], list[CheckResult]]] = {
    "patchmgmt": run_patchmgmt, "logintegrity": run_logintegrity,
}


def _run_all(fns: list[Callable[[], CheckResult]]) -> list[CheckResult]:
    out: list[CheckResult] = []
    for fn in fns:
        try:
            out.append(fn())
        except Exception as exc:
            out.append(CheckResult(fn.__name__, fn.__name__, "info",
                                   f"Check-Fehler: {type(exc).__name__}"))
    return out


def recheck(check_id: str) -> Optional[CheckResult]:
    """Führt die Domäne des Checks erneut aus und liefert das Ergebnis (read-only)."""
    prefix_domain = {"patch": "patchmgmt", "log": "logintegrity"}
    dom = prefix_domain.get(check_id.split("-")[0])
    if not dom:
        return None
    for r in RUNNERS[dom]():
        if r.check_id == check_id:
            return r
    return None


def is_domain_check(check_id: str) -> bool:
    return check_id.split("-")[0] in ("patch", "log")


# ---------------------------------------------------------------------------
# Ledger: Vorher/Nachher über Läufe (data/blue_ledger.json)
# ---------------------------------------------------------------------------
def _ledger_path() -> Path:
    return _data_dir() / "blue_ledger.json"


def ledger_load() -> dict:
    try:
        return json.loads(_ledger_path().read_text(encoding="utf-8"))
    except Exception:
        return {"checks": {}}


def ledger_update(observations: list[dict]) -> dict:
    """observations: [{check_id,title,status,severity,detail}] → Ledger + Übergänge.

    Liefert {"closed": [...], "opened": [...], "open_total": n, "closed_total": n}.
    Ein Check gilt erst als geschlossen, wenn er VORHER 'fail' war und JETZT 'pass' ist.
    """
    led = ledger_load()
    checks = led.setdefault("checks", {})
    now = time.time()
    closed, opened = [], []
    for o in observations:
        cid, st = o.get("check_id"), o.get("status")
        if not cid or st not in ("pass", "fail"):
            continue
        e = checks.get(cid)
        if e is None:
            checks[cid] = e = {"title": o.get("title", cid), "first_seen": now,
                               "status": st, "severity": o.get("severity", "low"),
                               "history": []}
            if st == "fail":
                e["failed_since"] = now
                opened.append(cid)
        else:
            prev = e.get("status")
            if prev == "fail" and st == "pass":
                e["closed_at"] = now
                e["closed_count"] = int(e.get("closed_count", 0)) + 1
                closed.append({"check_id": cid, "title": e.get("title", cid),
                               "failed_since": e.get("failed_since"), "closed_at": now,
                               "before": "fail", "after": "pass"})
                e.pop("failed_since", None)
            elif prev == "pass" and st == "fail":
                e["failed_since"] = now
                opened.append(cid)
            e["status"] = st
            e["severity"] = o.get("severity", e.get("severity", "low"))
            e["title"] = o.get("title", e.get("title", cid))
        e["last_seen"] = now
        e["last_detail"] = (o.get("detail") or "")[:200]
        e["history"] = (e.get("history") or [])[-19:] + [{"t": now, "s": st}]
    led["updated_at"] = now
    try:
        p = _ledger_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".ledger-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(led, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, p)
    except Exception:
        pass
    return {"closed": closed, "opened": opened, **ledger_stats(led)}


def ledger_stats(led: Optional[dict] = None) -> dict:
    led = led if led is not None else ledger_load()
    checks = led.get("checks", {})
    return {
        "tracked": len(checks),
        "open_total": sum(1 for e in checks.values() if e.get("status") == "fail"),
        "pass_total": sum(1 for e in checks.values() if e.get("status") == "pass"),
        "closed_total": sum(int(e.get("closed_count", 0)) for e in checks.values()),
        "updated_at": led.get("updated_at"),
    }
