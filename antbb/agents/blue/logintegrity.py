"""Blue-Soldat: Log-Integrität (read-only).

Prüft, ob Protokolle vollständig, geschützt und manipulationsarm gesammelt
werden: Logging-Dienst, persistentes Journal, auditd, Dateirechte, Rotation,
Zeitsynchronisation und Remote-/SIEM-Weiterleitung. Keine Logs werden
geändert oder gelöscht; Evidence enthält keine Log-Inhalte.
"""
from __future__ import annotations

import glob
import os
import re

from ._sys import read, run, have, proc_names, age_days, mode_of
from .audit import AuditAnt, CheckResult, Playbook, Task


def collect(task=None, scope_check=None) -> list[CheckResult]:
    res: list[CheckResult] = []
    procs = proc_names()

    cid, title = "logging-daemon", "Logs: Logging-Dienst läuft (journald/rsyslog/syslog-ng)"
    d = [n for n in ("systemd-journal", "rsyslogd", "syslog-ng") if n in procs]
    if d:
        res.append(CheckResult(cid, title, "pass", "Aktiv: " + ", ".join(d), evidence={"daemons": d}))
    elif os.path.isdir("/run/systemd/journal"):
        res.append(CheckResult(cid, title, "pass", "journald-Socket vorhanden."))
    else:
        res.append(CheckResult(cid, title, "fail", "Kein Logging-Dienst erkannt.",
                               "journald oder rsyslog aktivieren.", severity="high"))

    cid, title = "journal-persistent", "Logs: Journal persistent gespeichert"
    jc = read("/etc/systemd/journald.conf") + "".join(read(p) for p in glob.glob("/etc/systemd/journald.conf.d/*.conf"))
    st = re.findall(r"^\s*Storage\s*=\s*(\w+)", jc, re.M)
    if os.path.isdir("/var/log/journal") or (st and st[-1] == "persistent"):
        res.append(CheckResult(cid, title, "pass", "Persistentes Journal (/var/log/journal bzw. Storage=persistent)."))
    elif os.path.isdir("/run/systemd/journal"):
        res.append(CheckResult(cid, title, "fail", "Journal nur flüchtig (geht beim Neustart verloren).",
                               "Storage=persistent setzen / /var/log/journal anlegen.", severity="low",
                               fix_command="sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald"))
    else:
        res.append(CheckResult(cid, title, "info", "Kein systemd-journald – nicht anwendbar."))

    cid, title = "auditd-running", "Logs: auditd erfasst Systemereignisse"
    if "auditd" in procs:
        res.append(CheckResult(cid, title, "pass", "auditd läuft."))
    else:
        res.append(CheckResult(cid, title, "fail", "auditd läuft nicht (kein Kernel-Audit-Trail).",
                               "auditd installieren und Basisregeln laden.", severity="low",
                               fix_command="sudo apt-get install auditd"))

    cid, title = "log-permissions", "Logs: Dateirechte schützen vor Manipulation"
    bad = 0
    n = 0
    for root, dirs, files in os.walk("/var/log"):
        if root.count("/") > 3:
            dirs[:] = []
        for fn in files:
            m = mode_of(os.path.join(root, fn))
            if m is None:
                continue
            n += 1
            if m & 0o002:
                bad += 1
        if n > 1500:
            break
    sens = [mode_of(p) for p in ("/var/log/auth.log", "/var/log/secure", "/var/log/btmp") if os.path.exists(p)]
    sens_bad = [m for m in sens if m is not None and m & 0o004]
    if n == 0:
        res.append(CheckResult(cid, title, "info", "/var/log nicht lesbar."))
    elif bad or sens_bad:
        res.append(CheckResult(cid, title, "fail",
                               f"{bad} welt-schreibbare Logdatei(en), {len(sens_bad)} sensible Log(s) welt-lesbar.",
                               "Rechte auf 640/root:adm setzen.", severity="medium",
                               fix_command="sudo chmod o-rwx /var/log/auth.log",
                               evidence={"world_writable": bad, "sensitive_world_readable": len(sens_bad), "files": n}))
    else:
        res.append(CheckResult(cid, title, "pass", f"{n} Logdatei(en) geprüft, keine welt-schreibbar.",
                               evidence={"files": n}))

    cid, title = "log-rotation", "Logs: Rotation konfiguriert (logrotate)"
    if os.path.exists("/etc/logrotate.conf"):
        k = len(glob.glob("/etc/logrotate.d/*"))
        res.append(CheckResult(cid, title, "pass", f"logrotate.conf + {k} Regelwerk(e).", evidence={"rules": k}))
    else:
        res.append(CheckResult(cid, title, "fail" if os.path.isdir("/var/log") else "info",
                               "Keine logrotate-Konfiguration.", "logrotate installieren/konfigurieren.",
                               severity="low"))

    cid, title = "time-sync", "Logs: Zeitsynchronisation (verlässliche Zeitstempel)"
    rc, o = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=5) if have("timedatectl") else (-1, "")
    if rc == 0 and o.strip() == "yes":
        res.append(CheckResult(cid, title, "pass", "NTP-Synchronisation aktiv."))
    elif rc == 0:
        res.append(CheckResult(cid, title, "fail", "Systemzeit nicht NTP-synchronisiert.",
                               "systemd-timesyncd/chrony aktivieren.", severity="low",
                               fix_command="sudo timedatectl set-ntp true"))
    else:
        res.append(CheckResult(cid, title, "info", "timedatectl nicht verfügbar."))

    cid, title = "log-forwarding", "Logs: Remote-/SIEM-Weiterleitung gegen lokale Manipulation"
    rs = read("/etc/rsyslog.conf") + "".join(read(p) for p in glob.glob("/etc/rsyslog.d/*.conf"))
    fw = bool(re.search(r"^\s*[^#\s].*@@?[\w\.\-\[]+", rs, re.M)) or bool(re.search(r'target\s*=\s*"', rs))
    try:
        from ... import splunk as _sp
        siem = bool(_sp.status().get("configured"))
    except Exception:
        siem = False
    if fw or siem:
        res.append(CheckResult(cid, title, "pass", "Weiterleitung konfiguriert" + (" (Splunk-HEC)" if siem else " (rsyslog)") + ".",
                               evidence={"rsyslog": fw, "splunk_hec": siem}))
    else:
        res.append(CheckResult(cid, title, "fail", "Keine Remote-Weiterleitung – lokale Logs sind einziger Beleg.",
                               "Logs an zentrale Senke (rsyslog/Splunk-HEC) spiegeln.", severity="low"))

    cid, title = "log-activity", "Logs: Auth-/Syslog zeigen aktuelle Aktivität"
    cands = [p for p in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure") if os.path.exists(p)]
    ages = [(p, age_days(p)) for p in cands]
    ages = [(p, a) for p, a in ages if a is not None]
    if not ages:
        res.append(CheckResult(cid, title, "info", "Keine klassischen Logdateien (journald-only System?)."))
    elif min(a for _, a in ages) > 7:
        res.append(CheckResult(cid, title, "fail", f"Logs seit {min(a for _, a in ages):.0f} Tagen still – Lücke?",
                               "Logging-Pipeline prüfen.", severity="medium"))
    else:
        res.append(CheckResult(cid, title, "pass", f"{len(ages)} Logdatei(en) aktuell beschrieben."))
    return res


class LogIntegrityAnt(AuditAnt):
    name = "blue-logintegrity"
    specialty = "blue-log-guardian"
    role = ("Log-Integrität (read-only): Dienst, Persistenz, auditd, Rechte, "
            "Rotation, Zeitsync und Remote-Weiterleitung prüfen.")
    blue_phases = ("defend", "verify")
    audit_id = "logintegrity"
    playbooks = (
        Playbook("log-pipeline-audit", "defensive", False,
                 ["journald-conf", "auditd-process", "rsyslog-forwarding"],
                 "Prüft, ob Logs erfasst, persistent gehalten und weitergeleitet werden."),
        Playbook("log-tamper-resistance", "defensive", False,
                 ["var-log-modes", "logrotate", "ntp-sync", "activity-gap"],
                 "Bewertet Dateirechte, Rotation, Zeitsync und Aktivitätslücken."),
    )

    def collect(self, task: Task):
        return collect(task, self.ctx.scope_check)
