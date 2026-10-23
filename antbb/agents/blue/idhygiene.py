"""Blue-Soldat: Identity-Hygiene (read-only).

Bewertet lokale Konten- und Schlüsselhygiene: zusätzliche UID-0-Konten, leere
Passwort-Hashes (nur wenn /etc/shadow lesbar), Passwort-Alterungsrichtlinie,
Admin-Gruppengröße, SSH-Schlüsselrechte und Login-Drosselung. In Evidence
stehen nur Zahlen – keine Kontonamen, Hashes oder Schlüsselinhalte.
"""
from __future__ import annotations

import glob
import os
import re

from ._sys import read, have, mode_of, proc_names
from .audit import AuditAnt, CheckResult, Playbook, Task

_NOLOGIN = ("nologin", "false", "sync", "shutdown", "halt")


def _passwd() -> list[list[str]]:
    return [l.split(":") for l in read("/etc/passwd").splitlines()
            if l and not l.startswith("#") and len(l.split(":")) >= 7]


def collect(task=None, scope_check=None) -> list[CheckResult]:
    res: list[CheckResult] = []
    users = _passwd()

    cid, title = "uid0-accounts", "Identity: nur root hat UID 0"
    if not users:
        res.append(CheckResult(cid, title, "info", "/etc/passwd nicht lesbar."))
    else:
        extra = [u for u in users if u[2] == "0" and u[0] != "root"]
        if extra:
            res.append(CheckResult(cid, title, "fail", f"{len(extra)} zusätzliche(s) UID-0-Konto/Konten.",
                                   "Konten mit UID 0 außer root entfernen oder umstellen.", severity="high",
                                   evidence={"count": len(extra)}))
        else:
            res.append(CheckResult(cid, title, "pass", "Nur root besitzt UID 0.", evidence={"accounts": len(users)}))

    cid, title = "empty-passwords", "Identity: keine Konten ohne Passwort-Hash"
    shadow = read("/etc/shadow")
    if not shadow:
        res.append(CheckResult(cid, title, "info", "/etc/shadow ohne Root nicht lesbar – als Dienst mit Rechten wiederholen."))
    else:
        empty = [l.split(":")[0] for l in shadow.splitlines() if l.count(":") >= 2 and l.split(":")[1] == ""]
        if empty:
            res.append(CheckResult(cid, title, "fail", f"{len(empty)} Konto/Konten mit leerem Passwort-Feld.",
                                   "Passwort setzen oder Konto sperren (passwd -l).", severity="high",
                                   evidence={"count": len(empty)}))
        else:
            res.append(CheckResult(cid, title, "pass", "Keine leeren Passwort-Felder."))

    cid, title = "password-aging", "Identity: Passwort-Höchstalter definiert (≤ 365 Tage)"
    ld = read("/etc/login.defs")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", ld, re.M)
    if not ld:
        res.append(CheckResult(cid, title, "info", "/etc/login.defs nicht vorhanden."))
    elif m and int(m.group(1)) <= 365:
        res.append(CheckResult(cid, title, "pass", f"PASS_MAX_DAYS={m.group(1)}", evidence={"max_days": int(m.group(1))}))
    else:
        res.append(CheckResult(cid, title, "fail", f"PASS_MAX_DAYS={m.group(1) if m else 'nicht gesetzt'}.",
                               "PASS_MAX_DAYS sinnvoll begrenzen (z. B. 365) bzw. auf Schlüssel-Login setzen.",
                               severity="low", fix_command="sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs"))

    cid, title = "admin-group-size", "Identity: Admin-Gruppen klein gehalten (≤ 5 Mitglieder)"
    members = set()
    for l in read("/etc/group").splitlines():
        f = l.split(":")
        if len(f) >= 4 and f[0] in ("sudo", "wheel", "admin"):
            members |= {x for x in f[3].split(",") if x}
    if not read("/etc/group"):
        res.append(CheckResult(cid, title, "info", "/etc/group nicht lesbar."))
    elif len(members) <= 5:
        res.append(CheckResult(cid, title, "pass", f"{len(members)} Mitglied(er) in sudo/wheel/admin.",
                               evidence={"members": len(members)}))
    else:
        res.append(CheckResult(cid, title, "fail", f"{len(members)} Konten mit Admin-Rechten.",
                               "Least-Privilege: Admin-Mitgliedschaften überprüfen und reduzieren.",
                               severity="medium", evidence={"members": len(members)}))

    humans = [u for u in users if u[2].isdigit() and int(u[2]) >= 1000 and not u[6].endswith(_NOLOGIN)]
    res.append(CheckResult("login-accounts", "Identity: Inventar interaktiver Konten",
                           "pass" if users else "info",
                           f"{len(humans)} interaktive(s) Konto/Konten (UID ≥ 1000 mit Login-Shell).",
                           evidence={"interactive_accounts": len(humans)}))

    cid, title = "ssh-key-permissions", "Identity: SSH-Schlüssel & Verzeichnisse korrekt geschützt"
    homes = {os.path.expanduser("~")} | set(glob.glob("/home/*"))
    bad, checked = 0, 0
    for h in homes:
        d = os.path.join(h, ".ssh")
        if not os.path.isdir(d):
            continue
        dm = mode_of(d)
        checked += 1
        if dm is not None and dm & 0o077:
            bad += 1
        for fn in glob.glob(os.path.join(d, "id_*")) + [os.path.join(d, "authorized_keys")]:
            if fn.endswith(".pub") or not os.path.isfile(fn):
                continue
            fm = mode_of(fn)
            checked += 1
            limit = 0o022 if fn.endswith("authorized_keys") else 0o077
            if fm is not None and fm & limit:
                bad += 1
    if checked == 0:
        res.append(CheckResult(cid, title, "info", "Keine lesbaren ~/.ssh-Verzeichnisse gefunden."))
    elif bad:
        res.append(CheckResult(cid, title, "fail", f"{bad} von {checked} Objekten mit zu offenen Rechten.",
                               "chmod 700 ~/.ssh; chmod 600 private Schlüssel/authorized_keys.", severity="high",
                               fix_command="chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/authorized_keys",
                               evidence={"bad": bad, "checked": checked}))
    else:
        res.append(CheckResult(cid, title, "pass", f"{checked} SSH-Objekte mit korrekten Rechten.",
                               evidence={"checked": checked}))

    cid, title = "login-throttling", "Identity: Login-Drosselung aktiv (fail2ban/faillock)"
    pam = read("/etc/pam.d/common-auth") + read("/etc/pam.d/system-auth") + read("/etc/pam.d/password-auth")
    if "fail2ban" in proc_names() or "faillock" in pam or "pam_tally2" in pam:
        res.append(CheckResult(cid, title, "pass", "Login-Drosselung erkannt (fail2ban oder PAM-faillock)."))
    elif not pam and not have("fail2ban-client"):
        res.append(CheckResult(cid, title, "info", "Keine PAM-Konfiguration lesbar."))
    else:
        res.append(CheckResult(cid, title, "fail", "Weder fail2ban noch PAM-faillock erkannt.",
                               "fail2ban oder pam_faillock einrichten.", severity="low",
                               fix_command="sudo apt-get install fail2ban"))
    return res


class IdentityHygieneAnt(AuditAnt):
    name = "blue-idhygiene"
    specialty = "blue-identity-keeper"
    role = ("Identity-Hygiene (read-only): UID-0, leere Passwörter, Aging, "
            "Admin-Gruppen, SSH-Schlüsselrechte, Login-Drosselung.")
    blue_phases = ("assess", "harden")
    audit_id = "idhygiene"
    playbooks = (
        Playbook("identity-account-audit", "defensive", False,
                 ["passwd-uid0", "shadow-empty-hash", "login-defs", "admin-groups"],
                 "Auditiert lokale Konten (nur Zahlen, keine Namen/Hashes in Evidence)."),
        Playbook("identity-ssh-key-hygiene", "defensive", False,
                 ["ssh-dir-modes", "private-key-modes", "faillock-check"],
                 "Prüft SSH-Schlüsselrechte und Login-Drosselung."),
        Playbook("identity-lockdown-apply", "defensive", True,
                 ["lock-account-gated"],
                 "Konto sperren/Rechte korrigieren – NUR mit Oversight (default-deny, dokumentiert)."),
    )

    def collect(self, task: Task):
        return collect(task, self.ctx.scope_check)
