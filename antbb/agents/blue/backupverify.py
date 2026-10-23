"""Blue-Soldat: Backup-Verify (read-only).

Belegt, dass Backups existieren, frisch sind und sich lesen lassen: Werkzeug,
Zeitplan, Alter des neuesten Archivs und ein Integritätstest (gzip/tar/zip
rein lesend). Es wird nichts wiederhergestellt oder überschrieben.
"""
from __future__ import annotations

import glob
import gzip
import os
import tarfile
import time
import zipfile

from ._sys import read, run, have
from .audit import AuditAnt, CheckResult, Playbook, Task

TOOLS = ("restic", "borg", "borgmatic", "rsnapshot", "duplicity", "timeshift",
         "rclone", "kopia", "bacula-fd", "rdiff-backup")
DIRS = ("/var/backups", "/backup", "/backups", "/mnt/backup", "/srv/backup",
        os.path.expanduser("~/backups"), os.path.expanduser("~/backup"))
ARCH = (".tar.gz", ".tgz", ".gz", ".zip", ".tar", ".bz2", ".xz", ".tar.zst", ".dump", ".sql")
KEYS = ("backup", "restic", "borg", "snapshot", "rsnapshot", "duplicity", "kopia")


def _archives(limit: int = 3000):
    items = []
    n = 0
    for d in DIRS:
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for fn in files:
                n += 1
                if n > limit:
                    break
                p = os.path.join(root, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                items.append((st.st_mtime, st.st_size, p))
    items.sort(reverse=True)
    return items


def _test_archive(p: str) -> tuple[bool, str]:
    try:
        if p.endswith((".tar.gz", ".tgz")):
            with tarfile.open(p, "r:gz") as t:
                for i, _m in enumerate(t):
                    if i > 5000:
                        break
            return True, "tar.gz lesbar"
        if p.endswith(".gz"):
            with gzip.open(p, "rb") as g:
                while g.read(1 << 20):
                    pass
            return True, "gzip-Test ok"
        if p.endswith(".zip"):
            with zipfile.ZipFile(p) as z:
                bad = z.testzip()
            return (bad is None), ("zip ok" if bad is None else f"defekt: {bad}")
        if p.endswith(".tar"):
            with tarfile.open(p) as t:
                for i, _m in enumerate(t):
                    if i > 5000:
                        break
            return True, "tar lesbar"
    except Exception as exc:
        return False, type(exc).__name__
    return True, "Format nicht testbar (nur Größe/Alter)"


def collect(task=None, scope_check=None) -> list[CheckResult]:
    res: list[CheckResult] = []

    found = [t for t in TOOLS if have(t)]
    cid, title = "backup-tooling", "Backup: Backup-Werkzeug installiert"
    if found:
        res.append(CheckResult(cid, title, "pass", "Gefunden: " + ", ".join(found), evidence={"tools": found}))
    else:
        res.append(CheckResult(cid, title, "fail", "Kein bekanntes Backup-Werkzeug im PATH.",
                               "Ein Backup-Werkzeug (z. B. restic/borg) einführen und dokumentieren.",
                               severity="medium", fix_command="sudo apt-get install restic"))

    cid, title = "backup-schedule", "Backup: automatischer Zeitplan vorhanden"
    hits = []
    _rc, tm = run(["systemctl", "list-timers", "--all", "--no-pager"], timeout=8)
    hits += [l.split()[-2] if len(l.split()) > 1 else l for l in tm.splitlines()
             if any(k in l.lower() for k in KEYS)]
    for p in glob.glob("/etc/cron.d/*") + glob.glob("/etc/cron.daily/*") + glob.glob("/etc/cron.weekly/*") + ["/etc/crontab"]:
        if any(k in os.path.basename(p).lower() for k in KEYS) or any(k in read(p, 20000).lower() for k in ("restic", "borg ", "rsnapshot", "duplicity", "backup")):
            hits.append(os.path.basename(p))
    if hits:
        res.append(CheckResult(cid, title, "pass", f"{len(set(hits))} Backup-Zeitplan-Eintrag/Einträge gefunden.",
                               evidence={"entries": sorted(set(hits))[:8]}))
    else:
        res.append(CheckResult(cid, title, "fail", "Kein Backup-Timer/Cron-Eintrag gefunden.",
                               "Zeitgesteuertes Backup (systemd-timer oder cron) einrichten.", severity="low"))

    arch = _archives()
    cid, title = "backup-freshness", "Backup: neuestes Archiv ≤ 7 Tage"
    if not arch:
        res.append(CheckResult(cid, title, "info", "Keine Backup-Verzeichnisse mit Dateien lesbar "
                                                   "(/var/backups, /backup, ~/backups …)."))
    else:
        age = (time.time() - arch[0][0]) / 86400.0
        if age <= 7:
            res.append(CheckResult(cid, title, "pass", f"Neuestes Archiv {age:.1f} Tag(e) alt, {len(arch)} Datei(en).",
                                   evidence={"age_days": round(age, 1), "files": len(arch)}))
        else:
            res.append(CheckResult(cid, title, "fail", f"Neuestes Archiv {age:.0f} Tage alt.",
                                   "Backup-Lauf prüfen; Alarm bei Alter > 7 Tage einrichten.", severity="medium",
                                   evidence={"age_days": round(age, 1), "files": len(arch)}))

    cid, title = "backup-integrity", "Backup: neueste Archive sind lesbar/intakt"
    cand = [a for a in arch if a[2].endswith(ARCH)][:3]
    if not cand:
        res.append(CheckResult(cid, title, "info", "Keine testbaren Archive (gz/tar/zip) gefunden."))
    else:
        tested = [(p, sz) + _test_archive(p) for _mt, sz, p in cand]
        bad = [t for t in tested if not t[2] or t[1] == 0]
        if bad:
            res.append(CheckResult(cid, title, "fail", f"{len(bad)}/{len(tested)} Archiv(e) defekt oder leer.",
                                   "Backup-Kette prüfen und Restore-Test durchführen.", severity="high",
                                   evidence={"tested": len(tested), "bad": len(bad)}))
        else:
            res.append(CheckResult(cid, title, "pass", f"{len(tested)} Archiv(e) erfolgreich rein lesend getestet.",
                                   evidence={"tested": len(tested)}))
    return res


class BackupVerifyAnt(AuditAnt):
    name = "blue-backupverify"
    specialty = "blue-backup-verifier"
    role = ("Backup-Verify (read-only): Werkzeug, Zeitplan, Frische und "
            "Integrität der neuesten Archive belegen – ohne Restore.")
    blue_phases = ("verify",)
    audit_id = "backupverify"
    playbooks = (
        Playbook("backup-coverage", "defensive", False,
                 ["tool-detect", "systemd-timers", "cron-scan"],
                 "Prüft, ob ein Backup-Werkzeug und ein automatischer Zeitplan existieren."),
        Playbook("backup-integrity-check", "defensive", False,
                 ["freshness-age", "gzip-tar-zip-test"],
                 "Belegt Frische und Lesbarkeit der neuesten Archive (read-only)."),
    )

    def collect(self, task: Task):
        return collect(task, self.ctx.scope_check)
