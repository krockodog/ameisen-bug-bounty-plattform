"""Persistenz-Schicht (SQLite) für Targets, Oversight, Findings und Reports.

Ein einziger Store, den sowohl CLI als auch Webserver nutzen. Keine
Logik-Duplizierung: alle Lese-/Schreibzugriffe laufen hier durch.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

DEFAULT_DB_PATH = os.environ.get(
    "ANTBB_DB",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "antbb.db"),
)


def _now() -> float:
    return time.time()


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    mode_policy TEXT NOT NULL DEFAULT 'auto',  -- defensive | auto | offensive
    created_at  REAL NOT NULL,
    archived_at REAL  -- NULL = aktiv; gesetzt = im Papierkorb (Soft-Delete)
);

CREATE TABLE IF NOT EXISTS scopes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL,
    kind       TEXT NOT NULL,          -- domain | ip | path | url
    value      TEXT NOT NULL,
    allowed    INTEGER NOT NULL DEFAULT 1,  -- 1 = in-scope, 0 = out-of-scope
    created_at REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oversight (
    target_id   INTEGER PRIMARY KEY,
    confirmed   INTEGER NOT NULL DEFAULT 0,
    confirmed_by TEXT DEFAULT '',
    note        TEXT DEFAULT '',
    confirmed_at REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    run_id      TEXT NOT NULL,
    agent       TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,          -- info|low|medium|high|critical
    asset       TEXT DEFAULT '',
    description TEXT DEFAULT '',
    evidence    TEXT DEFAULT '',        -- JSON
    dedup_key   TEXT NOT NULL,
    status      TEXT DEFAULT '',        -- Beweis-Stufe (VERIFIZIERT/BESTÄTIGT(PASSIV)/...)
    false_positive INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    title       TEXT NOT NULL,
    cvss_score  REAL,
    cvss_vector TEXT DEFAULT '',
    severity    TEXT DEFAULT '',
    chain       TEXT NOT NULL,          -- JSON mit 8-Schritt-Evidence-Kette
    created_at  REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS capabilities (
    id         INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton: Königin-Gedächtnis
    registry   TEXT NOT NULL,          -- JSON der Capability-Registry
    built_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS report_addenda (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    author      TEXT DEFAULT '',
    text        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_revisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    revision    INTEGER NOT NULL,
    instruction TEXT DEFAULT '',
    body        TEXT NOT NULL,
    author      TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS soldier_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    soldier     TEXT NOT NULL,
    playbook    TEXT NOT NULL DEFAULT '',   -- '' = Soldat-weit
    key         TEXT NOT NULL,              -- enabled | intensity | flags | description | task:<name>
    value       TEXT NOT NULL DEFAULT '',
    updated_at  REAL NOT NULL,
    UNIQUE(soldier, playbook, key)
);

CREATE TABLE IF NOT EXISTS soldier_mems (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    soldier     TEXT NOT NULL,
    text        TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wlan_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,                    -- optional; Survey kann target-los sein
    point_label TEXT NOT NULL,              -- Mess-Punkt (z.B. "Wohnzimmer")
    bssid       TEXT NOT NULL,
    ssid        TEXT DEFAULT '',
    rssi        INTEGER,                     -- dBm (gemessen)
    channel     INTEGER,
    band        TEXT DEFAULT '',            -- 2.4 | 5 | 6
    is_own      INTEGER NOT NULL DEFAULT 0, -- eigene Fritzbox getaggt
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wlan_engagements (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    target_id    INTEGER,                    -- optional Verknüpfung zu einem Target
    bssids       TEXT NOT NULL DEFAULT '[]', -- JSON-Liste autorisierter BSSIDs (Allowlist)
    ssids        TEXT NOT NULL DEFAULT '[]', -- JSON-Liste autorisierter SSIDs (Allowlist)
    client_mac   TEXT DEFAULT '',            -- optionaler, eng begrenzter Client
    location     TEXT DEFAULT '',
    start_ts     REAL NOT NULL,              -- Beginn des autorisierten Zeitfensters
    end_ts       REAL NOT NULL,              -- Ende des autorisierten Zeitfensters
    oversight    INTEGER NOT NULL DEFAULT 0, -- Oversight-Häkchen für diese Engagement
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    run_id      TEXT PRIMARY KEY,           -- Replay/Checkpoint: Lauf-ID
    target_id   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running', -- running|paused|done|error
    phases      TEXT DEFAULT '[]',          -- JSON der geplanten Phasen
    meta        TEXT DEFAULT '{}',          -- JSON (active/fuzz/offensive etc.)
    started_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    finished_at REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    seq         INTEGER NOT NULL,           -- deterministische Reihenfolge
    phase       TEXT DEFAULT '',
    agent       TEXT DEFAULT '',
    kind        TEXT NOT NULL,              -- event|finding|phase|status
    payload     TEXT NOT NULL DEFAULT '{}', -- JSON (re-emittierbar)
    created_at  REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wlan_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    kind          TEXT NOT NULL,             -- handshake|pmkid|cracked|portal-cred
    bssid         TEXT DEFAULT '',
    ssid          TEXT DEFAULT '',
    label         TEXT DEFAULT '',           -- z.B. Benutzername (maskiert) / Capture-Datei
    masked        TEXT NOT NULL DEFAULT '',  -- maskierte Darstellung (NIE Klartext)
    digest        TEXT NOT NULL DEFAULT '',  -- gesalzener SHA-256 (NIE Klartext)
    char_count    INTEGER,                   -- Länge als Nachweis
    created_at    REAL NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES wlan_engagements(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,          -- z.B. 'remote_access_mode'
    value      TEXT NOT NULL DEFAULT '',  -- NIE Secrets; nur Präferenzen/Status
    updated_at REAL NOT NULL
);

-- ---- Auth / Multi-User (optional, via ANTBB_AUTH=1) ----------------------
-- Passwoerter werden NUR als gesalzener PBKDF2-HMAC-Hash gespeichert, NIE im
-- Klartext. pw_hash/pw_salt sind Hex-Strings; kein Klartext, kein Log.
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    pw_hash    TEXT NOT NULL,             -- PBKDF2-HMAC-SHA256 (hex)
    pw_salt    TEXT NOT NULL,             -- zufaelliges Salz (hex)
    pw_iter    INTEGER NOT NULL DEFAULT 240000,
    role       TEXT NOT NULL DEFAULT 'viewer',  -- admin | viewer
    active      INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,          -- zufaelliges Token (nie geloggt)
    username   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'viewer',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

-- ---- Opt-in: eigene Assets fuer ungefaehrliche TLS/Header-Checks ----------
-- Default-deny: ein Check laeuft NUR gegen Assets, die hier als EIGEN bestaetigt
-- sind (confirmed_owner=1). Kein aktiver/offensiver Payload.
CREATE TABLE IF NOT EXISTS owned_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT DEFAULT '',
    host            TEXT NOT NULL,         -- Hostname/Domain (ohne Schema)
    port            INTEGER NOT NULL DEFAULT 443,
    confirmed_owner INTEGER NOT NULL DEFAULT 0,  -- 1 = Besitz ausdruecklich bestaetigt
    confirmed_by    TEXT DEFAULT '',
    note            TEXT DEFAULT '',
    created_at      REAL NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS asset_check_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 443,
    kind        TEXT NOT NULL,             -- tls | headers
    ok          INTEGER NOT NULL DEFAULT 0,
    summary     TEXT DEFAULT '',
    result      TEXT NOT NULL DEFAULT '{}',-- JSON (keine Secrets)
    created_at  REAL NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES owned_assets(id) ON DELETE CASCADE
);

-- ---- Persistente Run-Historie (UI) ---------------------------------------
-- Jeder abgeschlossene/abgebrochene Lauf wird mit Metadaten festgehalten.
CREATE TABLE IF NOT EXISTS run_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT,
    target_id     INTEGER,
    target_name   TEXT DEFAULT '',
    mode          TEXT DEFAULT 'defensive', -- defensive | active | fuzz | offensive
    active        INTEGER NOT NULL DEFAULT 0,
    fuzz          INTEGER NOT NULL DEFAULT 0,
    offensive     INTEGER NOT NULL DEFAULT 0,
    status        TEXT DEFAULT 'done',      -- done | error
    finding_count INTEGER NOT NULL DEFAULT 0,
    severity      TEXT NOT NULL DEFAULT '{}',-- JSON Verteilung
    error         TEXT DEFAULT '',
    started_at    REAL,
    finished_at   REAL,
    duration      REAL,
    created_at    REAL NOT NULL
);

"""


class Store:
    """Zentraler Datenspeicher. Thread-/prozessübergreifend via SQLite-Datei."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        """Idempotente Schema-Erweiterungen für bestehende DBs."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(targets)").fetchall()}
        if "mode_policy" not in cols:
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN mode_policy TEXT NOT NULL DEFAULT 'auto'"
            )
        if "archived_at" not in cols:
            # Soft-Delete / Papierkorb: NULL = aktiv, Zeitstempel = archiviert.
            # Keine Daten werden entfernt, nur ausgeblendet.
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN archived_at REAL"
            )
        fcols = {r[1] for r in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "status" not in fcols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN status TEXT DEFAULT ''"
            )
        if "false_positive" not in fcols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0"
            )

    # ---------------- Targets ----------------
    def add_target(self, name: str, description: str = "",
                   mode_policy: str = "auto") -> int:
        pol = mode_policy if mode_policy in ("defensive", "auto", "offensive") else "auto"
        cur = self._conn.execute(
            "INSERT INTO targets (name, description, mode_policy, created_at) "
            "VALUES (?,?,?,?)",
            (name, description, pol, _now()),
        )
        tid = cur.lastrowid
        self._conn.execute(
            "INSERT OR IGNORE INTO oversight (target_id, confirmed) VALUES (?, 0)",
            (tid,),
        )
        self._conn.commit()
        return tid

    def get_target(self, name_or_id: Any) -> Optional[sqlite3.Row]:
        if isinstance(name_or_id, int) or str(name_or_id).isdigit():
            row = self._conn.execute(
                "SELECT * FROM targets WHERE id=?", (int(name_or_id),)
            ).fetchone()
            if row:
                return row
        return self._conn.execute(
            "SELECT * FROM targets WHERE name=?", (str(name_or_id),)
        ).fetchone()

    def list_targets(self, include_archived: bool = False) -> list[sqlite3.Row]:
        """Aktive Targets (Default). Archivierte (Papierkorb) sind ausgeblendet,
        bleiben aber vollständig in der DB. include_archived=True listet alle."""
        if include_archived:
            return self._conn.execute(
                "SELECT * FROM targets ORDER BY created_at DESC"
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM targets WHERE archived_at IS NULL ORDER BY created_at DESC"
        ).fetchall()

    def list_archived_targets(self) -> list[sqlite3.Row]:
        """Papierkorb: nur archivierte Targets, zuletzt archiviert zuerst."""
        return self._conn.execute(
            "SELECT * FROM targets WHERE archived_at IS NOT NULL "
            "ORDER BY archived_at DESC"
        ).fetchall()

    def is_archived(self, target_id: int) -> bool:
        row = self._conn.execute(
            "SELECT archived_at FROM targets WHERE id=?", (target_id,),
        ).fetchone()
        return bool(row and row["archived_at"] is not None)

    def archive_target(self, target_id: int) -> None:
        """Soft-Delete: verschiebt ein Target in den Papierkorb. Es verschwindet
        aus der aktiven Liste und wird von aktiven Scans ausgeschlossen, aber
        ALLE Daten (Scopes, Findings, Scan-Historie, WLAN, Reports) bleiben
        unangetastet erhalten. Das Königin-Gedächtnis (Registry/Neural-Brain,
        Skills/Playbooks, soldier_mems/overrides) wird NICHT berührt."""
        self._conn.execute(
            "UPDATE targets SET archived_at=? WHERE id=? AND archived_at IS NULL",
            (_now(), target_id),
        )
        self._conn.commit()

    def restore_target(self, target_id: int) -> None:
        """Hebt die Archivierung auf (wiederherstellen aus dem Papierkorb)."""
        self._conn.execute(
            "UPDATE targets SET archived_at=NULL WHERE id=?", (target_id,),
        )
        self._conn.commit()

    def delete_target(self, target_id: int) -> None:
        """Harte, endgültige Löschung (Purge) EINES Targets samt seiner
        target-skopierten Zeilen (Scopes/Findings/Reports/Scan-Historie via
        ON DELETE CASCADE). Das aggregierte Königin-Wissen bleibt erhalten:
        capabilities-Registry, soldier_mems und soldier_overrides sind NICHT
        an ein Target gebunden und werden von dieser Löschung nicht berührt.
        Wird aktuell NICHT über die GUI angeboten (Default: nur Papierkorb)."""
        self._conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        self._conn.commit()

    def set_mode_policy(self, target_id: int, policy: str) -> None:
        pol = policy if policy in ("defensive", "auto", "offensive") else "auto"
        self._conn.execute(
            "UPDATE targets SET mode_policy=? WHERE id=?", (pol, target_id),
        )
        self._conn.commit()

    def get_mode_policy(self, target_id: int) -> str:
        row = self._conn.execute(
            "SELECT mode_policy FROM targets WHERE id=?", (target_id,),
        ).fetchone()
        if not row:
            return "auto"
        val = row["mode_policy"] if "mode_policy" in row.keys() else "auto"
        return val if val in ("defensive", "auto", "offensive") else "auto"

    # ---------------- Scopes ----------------
    def add_scope(self, target_id: int, kind: str, value: str, allowed: bool = True) -> int:
        cur = self._conn.execute(
            "INSERT INTO scopes (target_id, kind, value, allowed, created_at) "
            "VALUES (?,?,?,?,?)",
            (target_id, kind, value, 1 if allowed else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_scopes(self, target_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scopes WHERE target_id=? ORDER BY id", (target_id,)
        ).fetchall()

    def delete_scope(self, scope_id: int) -> None:
        self._conn.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
        self._conn.commit()

    # ---------------- Oversight ----------------
    def set_oversight(self, target_id: int, confirmed: bool,
                      confirmed_by: str = "", note: str = "") -> None:
        self._conn.execute(
            "INSERT INTO oversight (target_id, confirmed, confirmed_by, note, confirmed_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(target_id) DO UPDATE SET confirmed=excluded.confirmed, "
            "confirmed_by=excluded.confirmed_by, note=excluded.note, "
            "confirmed_at=excluded.confirmed_at",
            (target_id, 1 if confirmed else 0, confirmed_by, note,
             _now() if confirmed else None),
        )
        self._conn.commit()

    def get_oversight(self, target_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM oversight WHERE target_id=?", (target_id,)
        ).fetchone()

    def is_confirmed(self, target_id: int) -> bool:
        row = self.get_oversight(target_id)
        return bool(row and row["confirmed"])

    # ---------------- Findings ----------------
    def add_finding(self, target_id: int, run_id: str, agent: str, title: str,
                    category: str, severity: str, asset: str = "",
                    description: str = "", evidence: Optional[dict] = None,
                    dedup_key: str = "", status: str = "",
                    false_positive: bool = False) -> Optional[int]:
        dedup_key = dedup_key or f"{category}:{title}:{asset}"
        # Dedup: gleiche dedup_key innerhalb desselben Targets wird verworfen
        existing = self._conn.execute(
            "SELECT id FROM findings WHERE target_id=? AND dedup_key=?",
            (target_id, dedup_key),
        ).fetchone()
        if existing:
            return None
        cur = self._conn.execute(
            "INSERT INTO findings (target_id, run_id, agent, title, category, "
            "severity, asset, description, evidence, dedup_key, status, "
            "false_positive, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, run_id, agent, title, category, severity, asset,
             description, json.dumps(evidence or {}), dedup_key, status,
             1 if false_positive else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    # ---------------- Capability-Registry (Königin-Gedächtnis) ----------------
    def replace_capabilities(self, registry: dict) -> None:
        """Ersetzt die persistierte Capability-Registry (Singleton, id=1)."""
        self._conn.execute("DELETE FROM capabilities WHERE id=1")
        self._conn.execute(
            "INSERT INTO capabilities (id, registry, built_at) VALUES (1, ?, ?)",
            (json.dumps(registry, ensure_ascii=False),
             float(registry.get("built_at") or _now())),
        )
        self._conn.commit()

    def get_capabilities(self) -> dict:
        """Liest die persistierte Capability-Registry (oder {} wenn leer)."""
        row = self._conn.execute(
            "SELECT registry FROM capabilities WHERE id=1"
        ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["registry"])
        except Exception:
            return {}

    # ---------------- Settings (kleines KV, NIE Secrets) ----------------
    def get_setting(self, key: str, default: str = "") -> str:
        """Liest eine Einstellung. Nur Präferenzen/Status – niemals Secrets."""
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Setzt eine Einstellung (Upsert). Es werden NIE Secrets/Tokens hier
        abgelegt – nur unkritische Präferenzen (z.B. Fernzugriff-Modus)."""
        self._conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at",
            (key, str(value), _now()),
        )
        self._conn.commit()

    # ---------------- Auth / Multi-User (optional) ----------------
    def count_users(self) -> int:
        r = self._conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return int(r["c"]) if r else 0

    def get_user(self, username: str):
        return self._conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def list_users(self):
        return self._conn.execute(
            "SELECT id, username, role, active, created_at FROM users "
            "ORDER BY created_at").fetchall()

    def create_user(self, username: str, pw_hash: str, pw_salt: str,
                    role: str = "viewer", pw_iter: int = 240000) -> int:
        role = role if role in ("admin", "viewer") else "viewer"
        cur = self._conn.execute(
            "INSERT INTO users (username, pw_hash, pw_salt, pw_iter, role, "
            "active, created_at) VALUES (?,?,?,?,?,1,?)",
            (username, pw_hash, pw_salt, int(pw_iter), role, _now()))
        self._conn.commit()
        return cur.lastrowid

    def update_user_password(self, username: str, pw_hash: str, pw_salt: str,
                             pw_iter: int = 240000) -> None:
        self._conn.execute(
            "UPDATE users SET pw_hash=?, pw_salt=?, pw_iter=? WHERE username=?",
            (pw_hash, pw_salt, int(pw_iter), username))
        self._conn.commit()

    def set_user_role(self, username: str, role: str) -> None:
        role = role if role in ("admin", "viewer") else "viewer"
        self._conn.execute("UPDATE users SET role=? WHERE username=?",
                           (role, username))
        self._conn.commit()

    def delete_user(self, username: str) -> None:
        self._conn.execute("DELETE FROM users WHERE username=?", (username,))
        self._conn.commit()

    # ---- Sessions (Token nie geloggt) ----
    def create_session(self, token: str, username: str, role: str,
                       ttl_seconds: float = 86400 * 7) -> None:
        now = _now()
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions (token, username, role, created_at, "
            "expires_at) VALUES (?,?,?,?,?)",
            (token, username, role, now, now + ttl_seconds))
        self._conn.commit()

    def get_session(self, token: str):
        if not token:
            return None
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        if row["expires_at"] < _now():
            self.delete_session(token)
            return None
        return row

    def delete_session(self, token: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        self._conn.commit()

    def purge_expired_sessions(self) -> int:
        cur = self._conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (_now(),))
        self._conn.commit()
        return cur.rowcount or 0

    # ---------------- Opt-in eigene Assets (TLS/Header-Checks) ----------------
    def add_owned_asset(self, host: str, port: int = 443, label: str = "",
                        confirmed_owner: bool = False, confirmed_by: str = "",
                        note: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO owned_assets (label, host, port, confirmed_owner, "
            "confirmed_by, note, created_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(host, port) DO UPDATE SET label=excluded.label, "
            "confirmed_owner=excluded.confirmed_owner, "
            "confirmed_by=excluded.confirmed_by, note=excluded.note",
            (label, host, int(port), 1 if confirmed_owner else 0,
             confirmed_by, note, _now()))
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM owned_assets WHERE host=? AND port=?",
            (host, int(port))).fetchone()
        return int(row["id"]) if row else int(cur.lastrowid)

    def get_owned_asset(self, asset_id: int):
        return self._conn.execute(
            "SELECT * FROM owned_assets WHERE id=?", (int(asset_id),)).fetchone()

    def list_owned_assets(self):
        return self._conn.execute(
            "SELECT * FROM owned_assets ORDER BY created_at DESC").fetchall()

    def set_owned_asset_confirmed(self, asset_id: int, confirmed: bool,
                                  confirmed_by: str = "") -> None:
        self._conn.execute(
            "UPDATE owned_assets SET confirmed_owner=?, confirmed_by=? WHERE id=?",
            (1 if confirmed else 0, confirmed_by, int(asset_id)))
        self._conn.commit()

    def delete_owned_asset(self, asset_id: int) -> None:
        self._conn.execute("DELETE FROM owned_assets WHERE id=?", (int(asset_id),))
        self._conn.commit()

    def add_asset_check_run(self, asset_id: int, host: str, port: int, kind: str,
                            ok: bool, summary: str, result: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO asset_check_runs (asset_id, host, port, kind, ok, "
            "summary, result, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (int(asset_id), host, int(port), kind, 1 if ok else 0, summary,
             json.dumps(result or {}), _now()))
        self._conn.commit()
        return cur.lastrowid

    def list_asset_check_runs(self, asset_id: Optional[int] = None, limit: int = 50):
        if asset_id is not None:
            return self._conn.execute(
                "SELECT * FROM asset_check_runs WHERE asset_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (int(asset_id), int(limit))).fetchall()
        return self._conn.execute(
            "SELECT * FROM asset_check_runs ORDER BY created_at DESC LIMIT ?",
            (int(limit),)).fetchall()

    # ---------------- Run-Historie (UI) ----------------
    def add_run_history(self, run_id: Optional[str], target_id: Optional[int],
                        target_name: str = "", mode: str = "defensive",
                        active: bool = False, fuzz: bool = False,
                        offensive: bool = False, status: str = "done",
                        finding_count: int = 0, severity: Optional[dict] = None,
                        error: str = "", started_at: Optional[float] = None,
                        finished_at: Optional[float] = None,
                        duration: Optional[float] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO run_history (run_id, target_id, target_name, mode, "
            "active, fuzz, offensive, status, finding_count, severity, error, "
            "started_at, finished_at, duration, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, target_id, target_name, mode, 1 if active else 0,
             1 if fuzz else 0, 1 if offensive else 0, status, int(finding_count),
             json.dumps(severity or {}), error, started_at, finished_at,
             duration, _now()))
        self._conn.commit()
        return cur.lastrowid

    def list_run_history(self, target_id: Optional[int] = None, limit: int = 200):
        if target_id is not None:
            return self._conn.execute(
                "SELECT * FROM run_history WHERE target_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (int(target_id), int(limit))).fetchall()
        return self._conn.execute(
            "SELECT * FROM run_history ORDER BY created_at DESC LIMIT ?",
            (int(limit),)).fetchall()

    # ---------------- Report-Nachträge (Addenda) ----------------
    def add_addendum(self, report_id: int, text: str, author: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO report_addenda (report_id, author, text, created_at) "
            "VALUES (?,?,?,?)", (report_id, author, text, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_addenda(self, report_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM report_addenda WHERE report_id=? ORDER BY created_at",
            (report_id,),
        ).fetchall()

    # ---------------- Report-Revisionen (Neu-Anweisung / Historie) ----------------
    def add_revision(self, report_id: int, body: str, instruction: str = "",
                     author: str = "") -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(revision),0) AS m FROM report_revisions WHERE report_id=?",
            (report_id,),
        ).fetchone()
        nextrev = int(row["m"]) + 1 if row else 1
        cur = self._conn.execute(
            "INSERT INTO report_revisions (report_id, revision, instruction, body, "
            "author, created_at) VALUES (?,?,?,?,?,?)",
            (report_id, nextrev, instruction, body, author, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_revisions(self, report_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM report_revisions WHERE report_id=? ORDER BY revision",
            (report_id,),
        ).fetchall()

    def get_revision(self, revision_id: int) -> "Optional[sqlite3.Row]":
        return self._conn.execute(
            "SELECT * FROM report_revisions WHERE id=?", (revision_id,),
        ).fetchone()


    # ---------------- Soldaten-Overrides (editierbare Playbook-Parameter) ----------------
    def set_soldier_override(self, soldier: str, playbook: str, key: str,
                             value: str) -> int:
        self._conn.execute(
            "INSERT INTO soldier_overrides (soldier, playbook, key, value, updated_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(soldier, playbook, key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at",
            (soldier, playbook or "", key, str(value), _now()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM soldier_overrides WHERE soldier=? AND playbook=? AND key=?",
            (soldier, playbook or "", key)).fetchone()
        return int(row["id"]) if row else -1

    def list_soldier_overrides(self, soldier: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM soldier_overrides WHERE soldier=? ORDER BY playbook, key",
            (soldier,)).fetchall()

    def delete_soldier_override(self, soldier: str, playbook: str, key: str) -> None:
        self._conn.execute(
            "DELETE FROM soldier_overrides WHERE soldier=? AND playbook=? AND key=?",
            (soldier, playbook or "", key))
        self._conn.commit()

    # ---------------- Soldaten-Mems (Notizen/Gedächtnis je Soldat) ----------------
    def add_soldier_mem(self, soldier: str, text: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO soldier_mems (soldier, text, created_at) VALUES (?,?,?)",
            (soldier, text, _now()))
        self._conn.commit()
        return cur.lastrowid

    def list_soldier_mems(self, soldier: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM soldier_mems WHERE soldier=? ORDER BY created_at DESC",
            (soldier,)).fetchall()

    def delete_soldier_mem(self, mem_id: int) -> None:
        self._conn.execute("DELETE FROM soldier_mems WHERE id=?", (mem_id,))
        self._conn.commit()

    def all_soldier_overrides(self) -> dict:
        """Alle Overrides gruppiert nach Soldat (für den Lauf)."""
        out: dict = {}
        for r in self._conn.execute("SELECT * FROM soldier_overrides").fetchall():
            out.setdefault(r["soldier"], []).append(
                {"playbook": r["playbook"], "key": r["key"], "value": r["value"]})
        return out

    def all_soldier_mems(self) -> dict:
        out: dict = {}
        for r in self._conn.execute(
                "SELECT * FROM soldier_mems ORDER BY created_at").fetchall():
            out.setdefault(r["soldier"], []).append(r["text"])
        return out

    def list_findings(self, target_id: Optional[int] = None,
                      run_id: Optional[str] = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings"
        conds, args = [], []
        if target_id is not None:
            conds.append("target_id=?")
            args.append(target_id)
        if run_id is not None:
            conds.append("run_id=?")
            args.append(run_id)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY created_at DESC"
        return self._conn.execute(q, args).fetchall()


    # ---------------- WLAN-Survey (passive Coverage-Messpunkte) ----------------
    def add_wlan_sample(self, point_label: str, bssid: str, rssi: Optional[int] = None,
                        ssid: str = "", channel: Optional[int] = None,
                        band: str = "", is_own: bool = False,
                        target_id: Optional[int] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_samples (target_id, point_label, bssid, ssid, rssi, "
            "channel, band, is_own, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (target_id, point_label, (bssid or "").lower(), ssid, rssi, channel,
             band, 1 if is_own else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_wlan_samples(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_samples ORDER BY created_at").fetchall()
        return self._conn.execute(
            "SELECT * FROM wlan_samples WHERE target_id=? OR target_id IS NULL "
            "ORDER BY created_at", (target_id,)).fetchall()

    def delete_wlan_point(self, point_label: str,
                          target_id: Optional[int] = None) -> None:
        if target_id is None:
            self._conn.execute(
                "DELETE FROM wlan_samples WHERE point_label=?", (point_label,))
        else:
            self._conn.execute(
                "DELETE FROM wlan_samples WHERE point_label=? AND "
                "(target_id=? OR target_id IS NULL)", (point_label, target_id))
        self._conn.commit()

    # ---------------- WLAN-Offensiv-Engagements (Autorisierungs-Record) ----------------
    def add_wlan_engagement(self, name: str, bssids: list, ssids: list,
                            start_ts: float, end_ts: float,
                            client_mac: str = "", location: str = "",
                            target_id: Optional[int] = None,
                            oversight: bool = False) -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_engagements (name, target_id, bssids, ssids, "
            "client_mac, location, start_ts, end_ts, oversight, revoked, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,0,?)",
            (name, target_id, json.dumps([str(b).lower() for b in (bssids or [])]),
             json.dumps([str(x) for x in (ssids or [])]),
             (client_mac or "").lower(), location, float(start_ts), float(end_ts),
             1 if oversight else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_wlan_engagement(self, engagement_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM wlan_engagements WHERE id=?", (engagement_id,)
        ).fetchone()

    def list_wlan_engagements(self, include_revoked: bool = True) -> list[sqlite3.Row]:
        q = "SELECT * FROM wlan_engagements"
        if not include_revoked:
            q += " WHERE revoked=0"
        q += " ORDER BY created_at DESC"
        return self._conn.execute(q).fetchall()

    def set_wlan_engagement_oversight(self, engagement_id: int, confirmed: bool) -> None:
        self._conn.execute(
            "UPDATE wlan_engagements SET oversight=? WHERE id=?",
            (1 if confirmed else 0, engagement_id))
        self._conn.commit()

    def revoke_wlan_engagement(self, engagement_id: int) -> None:
        self._conn.execute(
            "UPDATE wlan_engagements SET revoked=1 WHERE id=?", (engagement_id,))
        self._conn.commit()

    # ---------------- WLAN-Offensiv-Credentials (NUR maskiert) ----------------
    def add_wlan_credential(self, engagement_id: int, kind: str,
                            masked: str = "", digest: str = "",
                            char_count: Optional[int] = None, bssid: str = "",
                            ssid: str = "", label: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_credentials (engagement_id, kind, bssid, ssid, label, "
            "masked, digest, char_count, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (engagement_id, kind, (bssid or "").lower(), ssid, label,
             masked, digest, char_count, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_wlan_credentials(self, engagement_id: Optional[int] = None) -> list[sqlite3.Row]:
        if engagement_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_credentials ORDER BY created_at DESC").fetchall()
        return self._conn.execute(
            "SELECT * FROM wlan_credentials WHERE engagement_id=? ORDER BY created_at DESC",
            (engagement_id,)).fetchall()

    def purge_wlan_credentials(self, engagement_id: Optional[int] = None) -> int:
        if engagement_id is None:
            cur = self._conn.execute("DELETE FROM wlan_credentials")
        else:
            cur = self._conn.execute(
                "DELETE FROM wlan_credentials WHERE engagement_id=?", (engagement_id,))
        self._conn.commit()
        return cur.rowcount

    # ---------------- Replay / Checkpoint (scan_runs + scan_steps) ----------------
    def create_scan_run(self, run_id: str, target_id: int, phases=None,
                        meta: Optional[dict] = None, status: str = "running") -> str:
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_runs (run_id, target_id, status, phases, "
            "meta, started_at, updated_at, finished_at) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, target_id, status, json.dumps(list(phases or [])),
             json.dumps(meta or {}), _now(), _now(), None),
        )
        self._conn.commit()
        return run_id

    def set_scan_run_status(self, run_id: str, status: str) -> None:
        fin = _now() if status in ("done", "error") else None
        self._conn.execute(
            "UPDATE scan_runs SET status=?, updated_at=?, "
            "finished_at=COALESCE(?, finished_at) WHERE run_id=?",
            (status, _now(), fin, run_id),
        )
        self._conn.commit()

    def get_scan_run(self, run_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scan_runs WHERE run_id=?", (run_id,)).fetchone()

    def list_scan_runs(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is not None:
            return self._conn.execute(
                "SELECT * FROM scan_runs WHERE target_id=? ORDER BY started_at DESC",
                (target_id,)).fetchall()
        return self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC").fetchall()

    def add_scan_step(self, run_id: str, kind: str, payload: Optional[dict] = None,
                      phase: str = "", agent: str = "") -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS m FROM scan_steps WHERE run_id=?",
            (run_id,)).fetchone()
        seq = int(row["m"]) + 1 if row else 1
        cur = self._conn.execute(
            "INSERT INTO scan_steps (run_id, seq, phase, agent, kind, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (run_id, seq, phase, agent, kind, json.dumps(payload or {}), _now()),
        )
        self._conn.execute("UPDATE scan_runs SET updated_at=? WHERE run_id=?",
                           (_now(), run_id))
        self._conn.commit()
        return seq

    def list_scan_steps(self, run_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scan_steps WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()

    def delete_scan_run(self, run_id: str) -> None:
        self._conn.execute("DELETE FROM scan_runs WHERE run_id=?", (run_id,))
        self._conn.commit()

    # ---------------- Reports ----------------
    def add_report(self, target_id: int, title: str, chain: dict,
                   cvss_score: Optional[float] = None, cvss_vector: str = "",
                   severity: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO reports (target_id, title, cvss_score, cvss_vector, "
            "severity, chain, created_at) VALUES (?,?,?,?,?,?,?)",
            (target_id, title, cvss_score, cvss_vector, severity,
             json.dumps(chain), _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_report(self, report_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM reports WHERE id=?", (report_id,)
        ).fetchone()

    def list_reports(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is not None:
            return self._conn.execute(
                "SELECT * FROM reports WHERE target_id=? ORDER BY created_at DESC",
                (target_id,),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC"
        ).fetchall()

    # ===================================================================
    # Neuronales-Gehirn: Node-/Log-Lesezugriffe + harte Lösch-/Reset-
    # Primitive. WICHTIG: Diese rohen DELETE/RESET-Primitive werden NUR
    # von antbb.brain_ops (human-gated, aus dem Web-UI) aufgerufen.
    # Soldaten/Queen/Service-Agenten-Fassade rufen sie NIE auf.
    # ===================================================================
    def get_finding(self, finding_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (int(finding_id),)
        ).fetchone()

    def count_findings(self, target_id: Optional[int] = None) -> int:
        if target_id is None:
            r = self._conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()
        else:
            r = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE target_id=?",
                (int(target_id),)).fetchone()
        return int(r["c"]) if r else 0

    def count_scopes(self, target_id: int) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM scopes WHERE target_id=?",
            (int(target_id),)).fetchone()
        return int(r["c"]) if r else 0

    def list_logs(self, target_id: Optional[int] = None,
                  run_id: Optional[str] = None, limit: int = 200,
                  offset: int = 0) -> list[sqlite3.Row]:
        """Log-Zeilen = scan_steps (event|finding|phase|status), neueste zuerst.

        Optional nach Target (join scan_runs) oder Run gefiltert; paginiert.
        Reiner Lesezugriff."""
        q = ("SELECT st.*, r.target_id AS target_id FROM scan_steps st "
             "JOIN scan_runs r ON r.run_id = st.run_id")
        conds, args = [], []
        if run_id is not None:
            conds.append("st.run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("r.target_id=?")
            args.append(int(target_id))
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY st.created_at DESC, st.id DESC LIMIT ? OFFSET ?"
        args.extend([int(limit), int(offset)])
        return self._conn.execute(q, args).fetchall()

    def count_logs(self, target_id: Optional[int] = None,
                   run_id: Optional[str] = None) -> int:
        q = ("SELECT COUNT(*) AS c FROM scan_steps st "
             "JOIN scan_runs r ON r.run_id = st.run_id")
        conds, args = [], []
        if run_id is not None:
            conds.append("st.run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("r.target_id=?")
            args.append(int(target_id))
        if conds:
            q += " WHERE " + " AND ".join(conds)
        r = self._conn.execute(q, args).fetchone()
        return int(r["c"]) if r else 0

    def count_run_steps(self, run_id: str) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM scan_steps WHERE run_id=?",
            (str(run_id),)).fetchone()
        return int(r["c"]) if r else 0

    def delete_finding(self, finding_id: int) -> int:
        """Harte Löschung EINES Findings. Nur via brain_ops (human-gated)."""
        cur = self._conn.execute("DELETE FROM findings WHERE id=?",
                                 (int(finding_id),))
        self._conn.commit()
        return cur.rowcount

    def purge_logs(self, target_id: Optional[int] = None,
                   run_id: Optional[str] = None, all_logs: bool = False) -> int:
        """Harte Löschung von Log-Zeilen (scan_steps). Nur via brain_ops.

        all_logs=True leert ALLE scan_steps. Sonst scoped nach run_id und/oder
        target_id (letzteres via Sub-Select auf scan_runs)."""
        if all_logs:
            cur = self._conn.execute("DELETE FROM scan_steps")
            self._conn.commit()
            return cur.rowcount
        conds, args = [], []
        if run_id is not None:
            conds.append("run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("run_id IN (SELECT run_id FROM scan_runs WHERE target_id=?)")
            args.append(int(target_id))
        if not conds:
            return 0
        cur = self._conn.execute(
            "DELETE FROM scan_steps WHERE " + " AND ".join(conds), args)
        self._conn.commit()
        return cur.rowcount

    def reset_scan_run(self, run_id: str) -> dict:
        """Setzt EINEN laufenden/hängenden Lauf zurück: Status -> 'reset',
        finished_at gesetzt, unfertige Teil-Artefakte (scan_steps) verworfen.

        Fertige Läufe (done/error) werden NICHT verändert; Findings/Reports/
        Königin-Wissen bleiben unangetastet. Nur via brain_ops (human-gated)."""
        row = self.get_scan_run(run_id)
        if not row:
            return {"ok": False, "reason": "run_not_found", "run_id": run_id}
        status = row["status"]
        if status in ("done", "error", "reset"):
            return {"ok": False, "reason": "run_already_final",
                    "run_id": run_id, "status": status}
        steps = self.count_run_steps(run_id)
        self._conn.execute("DELETE FROM scan_steps WHERE run_id=?", (str(run_id),))
        self._conn.execute(
            "UPDATE scan_runs SET status='reset', updated_at=?, finished_at=? "
            "WHERE run_id=?", (_now(), _now(), str(run_id)))
        self._conn.commit()
        return {"ok": True, "run_id": run_id, "previous_status": status,
                "steps_discarded": steps}

    def list_stuck_runs(self) -> list[sqlite3.Row]:
        """Läufe, die nicht final sind (running|paused|queued|stuck)."""
        return self._conn.execute(
            "SELECT * FROM scan_runs WHERE status NOT IN ('done','error','reset') "
            "ORDER BY started_at DESC").fetchall()

    def wipe_operational(self) -> dict:
        """Harte Löschung ALLER operativen Daten (Targets samt CASCADE:
        Scopes/Findings/Reports/Scan-Historie/Oversight, plus WLAN-Daten).

        Das Königin-Wissen bleibt erhalten: capabilities (Registry),
        soldier_mems, soldier_overrides und settings werden NICHT berührt.
        Nur via brain_ops (human-gated)."""
        counts = {}
        for tbl in ("findings", "reports", "scopes", "scan_steps", "scan_runs",
                    "wlan_credentials", "wlan_engagements", "wlan_samples",
                    "oversight", "targets"):
            try:
                r = self._conn.execute(f"SELECT COUNT(*) AS c FROM {tbl}").fetchone()
                counts[tbl] = int(r["c"]) if r else 0
            except Exception:
                counts[tbl] = 0
        # targets-CASCADE räumt scopes/findings/reports/scan_runs/oversight mit ab;
        # WLAN-Samples/-Engagements/-Credentials sind teils target-los -> explizit.
        self._conn.execute("DELETE FROM wlan_credentials")
        self._conn.execute("DELETE FROM wlan_samples")
        self._conn.execute("DELETE FROM wlan_engagements")
        self._conn.execute("DELETE FROM scan_steps")
        self._conn.execute("DELETE FROM scan_runs")
        self._conn.execute("DELETE FROM targets")  # CASCADE: scopes/findings/reports/oversight
        self._conn.commit()
        return counts
