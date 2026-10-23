"""Hardening-Audit (echt, non-destruktiv, read-only, CIS-artig).

Führt rein LESENDE Prüfungen der lokalen System-/Dienst-Konfiguration durch und
gibt je Check einen Status (pass/fail/info) plus eine konkrete Fix-EMPFEHLUNG.
Es wird NICHTS verändert. Fixes werden nur VORGESCHLAGEN (Anwenden ist ein
separater, oversight-gated Schritt).

Jeder Check ist defensiv implementiert: fehlt eine Datei/ein Tool, liefert der
Check `status="info"` (nicht anwendbar), niemals einen Crash.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str            # pass | fail | info
    detail: str = ""
    recommendation: str = ""
    severity: str = "low"  # fail-Schweregrad: low|medium|high
    fix_command: str = ""  # VORSCHLAG (nie automatisch ausgeführt)
    evidence: dict = field(default_factory=dict)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Einzelne, rein lesende Checks
# ---------------------------------------------------------------------------
def check_ssh_root_login() -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    cid, title = "ssh-root-login", "SSH: PermitRootLogin deaktiviert"
    if not cfg:
        return CheckResult(cid, title, "info",
                           "Keine /etc/ssh/sshd_config gefunden (SSH evtl. nicht installiert).")
    val = ""
    for line in cfg.splitlines():
        s = line.strip()
        if s.lower().startswith("permitrootlogin"):
            val = s.split()[1].lower() if len(s.split()) > 1 else ""
    if val in ("no", "prohibit-password"):
        return CheckResult(cid, title, "pass", f"PermitRootLogin {val}")
    return CheckResult(cid, title, "fail",
                       f"PermitRootLogin={val or 'default(yes)'}",
                       "PermitRootLogin auf 'no' setzen (Root-SSH-Login verbieten).",
                       severity="high",
                       fix_command="sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")


def check_ssh_password_auth() -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    cid, title = "ssh-password-auth", "SSH: PasswordAuthentication deaktiviert"
    if not cfg:
        return CheckResult(cid, title, "info", "Keine sshd_config gefunden.")
    val = ""
    for line in cfg.splitlines():
        s = line.strip()
        if s.lower().startswith("passwordauthentication"):
            val = s.split()[1].lower() if len(s.split()) > 1 else ""
    if val == "no":
        return CheckResult(cid, title, "pass", "PasswordAuthentication no")
    return CheckResult(cid, title, "fail",
                       f"PasswordAuthentication={val or 'default(yes)'}",
                       "Auf key-basierte Auth umstellen (PasswordAuthentication no).",
                       severity="medium",
                       fix_command="sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")


def check_firewall() -> CheckResult:
    cid, title = "host-firewall", "Host-Firewall aktiv"
    if shutil.which("ufw"):
        out = _run(["ufw", "status"]).lower()
        if "status: active" in out:
            return CheckResult(cid, title, "pass", "ufw aktiv")
        if out:
            return CheckResult(cid, title, "fail", "ufw installiert, aber inaktiv",
                               "Firewall aktivieren.", "medium",
                               "sudo ufw enable")
    if shutil.which("firewall-cmd"):
        out = _run(["firewall-cmd", "--state"]).lower()
        if "running" in out:
            return CheckResult(cid, title, "pass", "firewalld läuft")
    if shutil.which("nft"):
        out = _run(["nft", "list", "ruleset"])
        if out.strip():
            return CheckResult(cid, title, "pass", "nftables-Regeln vorhanden")
    return CheckResult(cid, title, "info",
                       "Keine bekannte Firewall (ufw/firewalld/nft) erkennbar.",
                       "Eine Host-Firewall einrichten (Default-Deny-Inbound).")


def check_world_writable_etc() -> CheckResult:
    cid, title = "etc-world-writable", "Keine world-writable Dateien in /etc"
    bad: list[str] = []
    try:
        for root, _dirs, files in os.walk("/etc"):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    st = os.lstat(p)
                    if os.path.islink(p):
                        continue
                    if st.st_mode & 0o002:
                        bad.append(p)
                        if len(bad) >= 20:
                            raise StopIteration
                except StopIteration:
                    raise
                except Exception:
                    continue
    except StopIteration:
        pass
    except Exception:
        return CheckResult(cid, title, "info", "/etc nicht vollständig lesbar.")
    if not bad:
        return CheckResult(cid, title, "pass", "Keine world-writable Dateien in /etc.")
    return CheckResult(cid, title, "fail",
                       f"{len(bad)} world-writable Datei(en) in /etc",
                       "Schreibrechte für 'other' entfernen (chmod o-w).",
                       severity="high",
                       evidence={"files": bad[:20]})


def check_sysctl_hardening() -> CheckResult:
    cid, title = "sysctl-hardening", "Kernel-Netzwerk-Härtung (sysctl)"
    wanted = {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
    }
    missing = []
    for key, exp in wanted.items():
        path = "/proc/sys/" + key.replace(".", "/")
        cur = _read(path).strip()
        if cur and cur != exp:
            missing.append(f"{key}={cur} (empfohlen {exp})")
    if not any(os.path.exists("/proc/sys/" + k.replace(".", "/")) for k in wanted):
        return CheckResult(cid, title, "info", "sysctl/proc nicht verfügbar.")
    if not missing:
        return CheckResult(cid, title, "pass", "Empfohlene sysctl-Werte gesetzt.")
    return CheckResult(cid, title, "fail", "; ".join(missing),
                       "Empfohlene sysctl-Härtung setzen (rp_filter, syncookies, "
                       "accept_redirects=0).", severity="medium",
                       evidence={"deviations": missing})


#: Registry der verfügbaren Checks (erweiterbar).
CHECKS: list[Callable[[], CheckResult]] = [
    check_ssh_root_login,
    check_ssh_password_auth,
    check_firewall,
    check_world_writable_etc,
    check_sysctl_hardening,
]


def run_audit() -> list[CheckResult]:
    """Führt ALLE Checks aus (read-only). Ein fehlerhafter Check killt nie den Lauf."""
    out: list[CheckResult] = []
    for fn in CHECKS:
        try:
            out.append(fn())
        except Exception as exc:
            out.append(CheckResult(fn.__name__, fn.__name__, "info",
                                   f"Check-Fehler: {type(exc).__name__}"))
    return out
