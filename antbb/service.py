"""Service-Fassade: die gemeinsame Kern-API für CLI und Webserver.

Hier wird alles verdrahtet: Store, Scope, Oversight-Gate, Queen, Reports.
CLI und Web rufen NUR diese Fassade auf → keine Logik-Duplizierung.
"""
from __future__ import annotations

import logging
import os
from typing import Callable, Optional

from . import llm as llm_mod
from . import reports as reports_mod
from . import registry as registry_mod
from . import scope as scope_mod
from .oversight import OversightError, require_oversight
from .queen import PHASES, Queen, SwarmResult
from .reports import ReportDraft
from .store import Store

DEFAULT_EXPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "exports"
)


def _gb_finding_public(finding) -> dict:
    """JSON-fähige Finding-Sicht für den Greenbone-Import (ohne Secrets)."""
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    return {
        "title": finding.title,
        "severity": finding.severity,
        "asset": finding.asset,
        "status": finding.status,
        "category": finding.category,
        "agent": finding.agent,
        "description": finding.description,
        "cves": list(ev.get("cves") or []),
        "qod": ev.get("qod"),
        "cvss": ev.get("cvss"),
        "nvt_oid": ev.get("nvt_oid") or "",
    }


class AntBBService:
    """Zentrale Fassade. Eine Instanz pro Prozess."""

    def __init__(self, db_path: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        self.store = Store(db_path) if db_path else Store()
        self.logger = logger or logging.getLogger("antbb")

    def close(self) -> None:
        self.store.close()

    # ---------------- Targets ----------------
    def add_target(self, name: str, description: str = "",
                   mode_policy: str = "auto") -> int:
        return self.store.add_target(name, description, mode_policy=mode_policy)

    def list_targets(self, include_archived: bool = False):
        return self.store.list_targets(include_archived=include_archived)

    def list_archived_targets(self):
        """Papierkorb: archivierte Targets (Soft-Delete), Daten bleiben erhalten."""
        return self.store.list_archived_targets()

    def get_target(self, name_or_id):
        return self.store.get_target(name_or_id)

    def is_archived(self, target_id: int) -> bool:
        return self.store.is_archived(target_id)

    def archive_target(self, target_id: int) -> None:
        """Soft-Delete in den Papierkorb. Königin-Wissen bleibt unberührt."""
        self.store.archive_target(target_id)

    def restore_target(self, target_id: int) -> None:
        """Wiederherstellen aus dem Papierkorb."""
        self.store.restore_target(target_id)

    def delete_target(self, target_id: int) -> None:
        self.store.delete_target(target_id)

    # ---------------- Scope ----------------
    def add_scope(self, target_id: int, kind: str, value: str, allowed: bool = True) -> int:
        return self.store.add_scope(target_id, kind, value, allowed)

    def list_scopes(self, target_id: int):
        return self.store.list_scopes(target_id)

    def delete_scope(self, scope_id: int) -> None:
        self.store.delete_scope(scope_id)

    def check_asset(self, target_id: int, asset: str) -> scope_mod.ScopeResult:
        return scope_mod.check_asset(self.store, target_id, asset)

    # ---------------- Oversight ----------------
    def set_oversight(self, target_id: int, confirmed: bool,
                      confirmed_by: str = "", note: str = "") -> None:
        self.store.set_oversight(target_id, confirmed, confirmed_by, note)

    def get_oversight(self, target_id: int):
        return self.store.get_oversight(target_id)

    def is_confirmed(self, target_id: int) -> bool:
        return self.store.is_confirmed(target_id)

    # ---------------- Mode policy ----------------
    def set_mode_policy(self, target_id: int, policy: str) -> None:
        self.store.set_mode_policy(target_id, policy)

    def get_mode_policy(self, target_id: int) -> str:
        return self.store.get_mode_policy(target_id)

    def mode_status(self, target_id: int) -> dict:
        """Effektiver Modus + Begründung für die GUI (kein Scan)."""
        policy = self.get_mode_policy(target_id)
        confirmed = self.is_confirmed(target_id)
        in_scope = [s for s in self.list_scopes(target_id) if s["allowed"]]
        has_scope = len(in_scope) > 0
        reasons = []
        if policy == "defensive":
            effective = "defensive"
            reasons.append("mode_policy=defensive – Offensiv-Features gesperrt")
        elif not confirmed:
            effective = "defensive"
            reasons.append("Oversight fehlt – Scan/Offensiv blockiert")
        elif not has_scope:
            effective = "defensive"
            reasons.append("kein In-Scope-Eintrag (default-deny)")
        elif policy == "offensive":
            effective = "offensive"
            reasons.append("offensiv aktiv: Scope autorisiert + Oversight gesetzt "
                           "(mode_policy=offensive)")
        else:  # auto
            effective = "offensive"
            reasons.append("offensiv aktiv: Scope autorisiert + Oversight gesetzt "
                           "(mode_policy=auto)")
        return {
            "mode_policy": policy,
            "effective_mode": effective,
            "oversight": confirmed,
            "in_scope_count": len(in_scope),
            "reason": "; ".join(reasons),
            "offensive_allowed": effective == "offensive",
        }

    # ---------------- Swarm / Scan ----------------
    def run_scan(self, target_id: int, phases: tuple[str, ...] = PHASES,
                 emit: Optional[Callable[[dict], None]] = None,
                 active: bool = False, fuzz: bool = False,
                 offensive: Optional[bool] = None,
                 oversight_ack: Optional[bool] = None,
                 use_llm: Optional[bool] = None) -> SwarmResult:
        """Startet den Schwarm. Wirft OversightError ohne Häkchen (hartes Gate).

        `active=True` / `fuzz=True` werden zusätzlich gegen mode_policy geprüft:
        bei mode_policy=defensive werden sie verworfen. Bei auto/offensive nur
        wirksam mit Oversight + In-Scope (Oversight-Gate bleibt hart).
        """
        if self.store.is_archived(target_id):
            raise ValueError(
                "Target ist archiviert (Papierkorb) – bitte zuerst wiederherstellen, "
                "bevor ein Scan läuft."
            )
        status = self.mode_status(target_id)
        if not status["offensive_allowed"]:
            # Kein Offensiv erlaubt (defensive policy ODER kein Oversight/Scope):
            # jeglicher aktive/fuzz-Lauf wird hart auf rein defensiv heruntergefahren.
            active = False
            fuzz = False
            offensive = False
        else:
            # Offensiv ist autorisiert (Scope + Oversight + policy auto/offensive).
            # Das Setzen des Oversight-/Offensiv-Häkchens ENGAGIERT den Offensiv-Modus:
            #   * offensive=True (explizit, z.B. GUI-Häkchen) ODER
            #   * policy=offensive (immer offensiv, wenn erlaubt) ODER
            #   * offensive=None (Default) -> engagiert automatisch,
            # führt die aktiven Angriffs-Playbooks + Fuzzing aus (kein Read-only-Fallback).
            policy = status.get("mode_policy")
            # Engagieren, wenn der Offensiv-Schalter explizit gesetzt ist (GUI-/CLI-
            # Häkchen) ODER die Policy fest "offensive" ist. Ein explizites
            # offensive=False bleibt rein defensiv; active/fuzz-Flags wirken
            # weiterhin eigenständig (Rückwärtskompatibilität, Feinsteuerung).
            engage = bool(offensive) or policy == "offensive"
            if engage:
                active = True
                fuzz = True
        # -------- Konsistentes Human-Oversight-Gate fuer AKTIVE/OFFENSIVE Laeufe --------
        # Wird ausschliesslich scharf, wenn dieser Lauf wirklich eine aktive/offensive
        # Aktion ausloesen wuerde (active/fuzz/offensive bzw. policy=offensive). Rein
        # defensive Laeufe bleiben un-gated. Default-deny: ohne ausdrueckliche Freigabe
        # (oversight_ack is False) wird serverseitig VERWEIGERT und NICHTS gestartet.
        from .active_oversight import (
            active_trigger_requested, enforce_active_oversight,
        )
        # active/fuzz/offensive spiegeln hier bereits den FINALEN Zustand
        # (nach evtl. Herunterstufung auf defensiv) wider.
        if active_trigger_requested(active=active, fuzz=fuzz,
                                    offensive=offensive):
            _log = (lambda m: emit({"ts": __import__("time").time(), "msg": m})) \
                if emit else None
            enforce_active_oversight(oversight_ack,
                                     action="offensiver/aktiver Schwarm-Lauf",
                                     log=_log)
        if use_llm is None:
            use_llm = os.environ.get("ANTBB_NO_LLM", "").strip() not in (
                "1", "true", "True", "yes",
            )
        queen = Queen(self.store, logger=self.logger, emit=emit, use_llm=use_llm)
        return queen.run_swarm_sync(target_id, phases, active=active, fuzz=fuzz)

    def list_findings(self, target_id: Optional[int] = None, run_id: Optional[str] = None):
        return self.store.list_findings(target_id, run_id)

    # ---------------- Reports ----------------
    def create_report(self, draft: ReportDraft) -> int:
        return reports_mod.create_report(self.store, draft)

    def list_reports(self, target_id: Optional[int] = None):
        return self.store.list_reports(target_id)

    def get_report(self, report_id: int):
        return self.store.get_report(report_id)

    def report_markdown(self, report_id: int) -> str:
        return reports_mod.report_to_markdown(self.store, report_id)

    def export_report(self, report_id: int, fmt: str = "md",
                      out_dir: str = DEFAULT_EXPORT_DIR) -> str:
        """Export MIT Oversight-Gate: ohne Häkchen des Targets => blockiert."""
        row = self.store.get_report(report_id)
        if not row:
            raise ValueError(f"Report {report_id} existiert nicht.")
        require_oversight(self.store, row["target_id"])  # HARTES GATE
        if fmt == "json":
            return reports_mod.export_json(self.store, report_id, out_dir)
        return reports_mod.export_markdown(self.store, report_id, out_dir)


    # ---------------- Rating / Heatmap (neutral) ----------------
    def rating(self, target_id: int, with_ai: bool = True) -> dict:
        """Neutrales Gesamt-Rating + Teilscores + KI-Einschätzung + Heatmap."""
        from . import rating as rating_mod
        llm = None
        try:
            client = llm_mod.LLMClient()
            if client.configured:
                llm = client
        except Exception:
            llm = None
        return rating_mod.rating_for_target(self.store, target_id, llm=llm,
                                             with_ai=with_ai)

    def heatmap(self, target_id: int) -> dict:
        from . import rating as rating_mod
        return rating_mod.heatmap_for_target(self.store, target_id)


    # ---------------- WLAN-Survey (passiv: Coverage/Kanal/Optimierung) ----------------
    def osint_username(self, username: str,
                       emit: Optional[Callable[[dict], None]] = None) -> dict:
        """OSINT Username-Enumeration (sherlock primaer, maigret Fallback).

        Rein lesend, REFERENZ; gefundene Profile werden NICHT abgerufen/gescraped.
        Honest-empty (results=[]) wenn weder sherlock noch maigret installiert.
        """
        import asyncio as _asyncio
        from .agents.base import AgentContext
        from .tools.kali import KaliAdapter, which
        log = (lambda m: emit({"ts": __import__("time").time(), "msg": m})) if emit else None
        ctx = AgentContext(run_id="osint-username",
                           scope_check=lambda a: True,  # Username ist kein Netz-Asset der Allowlist
                           logger=self.logger,
                           emit=(lambda ev: log(ev.get("msg", ""))) if log else None)
        ka = KaliAdapter(ctx)
        findings = _asyncio.run(ka.username_enum(str(username).strip(), agent="osint"))
        tool = "sherlock" if which("sherlock") else ("maigret" if which("maigret") else None)
        results = [{"title": f.title, "category": f.category, "severity": f.severity,
                    "status": f.status, "asset": f.asset, "description": f.description,
                    "evidence": f.evidence} for f in findings]
        return {"username": username, "tool": tool,
                "available": bool(tool), "result_count": len(results),
                "results": results}

    def wlan_adapters(self) -> dict:
        """Vorhandene WLAN-Adapter + bekannte Hardware-Metadaten (honest-empty)."""
        from . import wlan_survey as ws
        return ws.list_adapters()

    def wlan_scan(self, iface: Optional[str] = None,
                  emit: Optional[Callable[[dict], None]] = None) -> dict:
        """Passiver Umgebungs-Scan (iw/nmcli). Ohne Tool/Interface: ehrlich leer."""
        from . import wlan_survey as ws
        log = (lambda m: emit({"ts": __import__("time").time(), "msg": m})) if emit else None
        return ws.scan_environment(iface=iface, log=log, force=True)

    def wlan_add_point(self, point_label: str, samples: dict,
                       target_id: Optional[int] = None,
                       own_bssids: Optional[list] = None) -> int:
        """Persistiert einen Mess-Punkt (label + {bssid: rssi}) in SQLite."""
        own = {b.lower() for b in (own_bssids or [])}
        n = 0
        for bssid, rssi in (samples or {}).items():
            try:
                r = int(rssi)
            except (TypeError, ValueError):
                r = None
            self.store.add_wlan_sample(point_label, bssid, rssi=r,
                                       is_own=bssid.lower() in own,
                                       target_id=target_id)
            n += 1
        return n

    def wlan_delete_point(self, point_label: str,
                          target_id: Optional[int] = None) -> None:
        self.store.delete_wlan_point(point_label, target_id)

    # ---------------- WLAN-Coverage-Heatmap (verortete passive RSSI-Messung) ----------------
    @staticmethod
    def _rssi_quality(rssi: Optional[int]) -> str:
        """Regelbasierte Einstufung der Signalstärke (dBm). Keine erfundenen Werte."""
        if rssi is None:
            return "none"
        if rssi >= -55:
            return "gut"
        if rssi >= -67:
            return "ok"
        if rssi >= -75:
            return "schwach"
        return "funkloch"

    def wlan_heatmap_add_sample(self, x: float, y: float, samples: dict,
                                ort: str = "", target_id: Optional[int] = None,
                                own_bssids: Optional[list] = None,
                                ap_meta: Optional[dict] = None) -> int:
        """Nimmt an Position (x,y normalisiert 0..1) einen Mess-Sample auf:
        pro sichtbarem AP {bssid: rssi}. Echte RSSI-Werte aus dem Scan.
        ap_meta optional {bssid: {ssid, channel, band}} für Anzeige."""
        try:
            x = float(x); y = float(y)
        except (TypeError, ValueError):
            raise ValueError("x/y müssen Zahlen 0..1 sein")
        if x != x or y != y:  # NaN
            raise ValueError("x/y müssen gültige Zahlen 0..1 sein")
        x = min(1.0, max(0.0, x)); y = min(1.0, max(0.0, y))
        own = {b.lower() for b in (own_bssids or [])}
        meta = ap_meta or {}
        n = 0
        for bssid, rssi in (samples or {}).items():
            try:
                r = int(rssi)
            except (TypeError, ValueError):
                r = None
            m = meta.get(bssid) or meta.get((bssid or "").lower()) or {}
            self.store.add_wlan_heatmap_sample(
                x, y, bssid, rssi=r, ssid=m.get("ssid", ""),
                channel=m.get("channel"), band=m.get("band", ""),
                is_own=(bssid or "").lower() in own, ort=ort, target_id=target_id)
            n += 1
        return n

    def wlan_heatmap_delete_sample(self, sample_id: int) -> None:
        self.store.delete_wlan_heatmap_sample(sample_id)

    def wlan_heatmap_clear(self, target_id: Optional[int] = None) -> int:
        return self.store.clear_wlan_heatmap_samples(target_id)

    def wlan_heatmap_set_floorplan(self, data_url: str, filename: str = "",
                                   mime: str = "image/png",
                                   target_id: Optional[int] = None) -> int:
        if not isinstance(data_url, str) or not data_url.startswith("data:image/"):
            raise ValueError("data_url muss eine data:image/... Base64-URL sein")
        if len(data_url) > 12_000_000:
            raise ValueError("Grundriss zu groß (max ~9 MB Bild)")
        return self.store.set_wlan_floorplan(data_url, filename=filename,
                                             mime=mime, target_id=target_id)

    def wlan_heatmap_floorplan(self, target_id: Optional[int] = None) -> Optional[dict]:
        row = self.store.get_wlan_floorplan(target_id)
        if not row:
            return None
        return {"id": row["id"], "filename": row["filename"], "mime": row["mime"],
                "data_url": row["data_url"], "target_id": row["target_id"]}

    def wlan_heatmap_delete_floorplan(self, target_id: Optional[int] = None) -> None:
        self.store.delete_wlan_floorplan(target_id)

    def wlan_heatmap_data(self, target_id: Optional[int] = None) -> dict:
        """Liefert alle verorteten Messpunkte strukturiert für die Visualisierung:
        rohe Samples, Liste sichtbarer APs (bssid/ssid), und pro Position das beste
        Signal aggregiert. Interpolation (IDW) passiert clientseitig im Canvas.
        honest-empty: ohne Samples leere, aber valide Struktur."""
        rows = self.store.list_wlan_heatmap_samples(target_id)
        aps: dict = {}
        points: dict = {}          # key (x,y,ort) -> {bssid: rssi}
        samples_out = []
        for r in rows:
            b = r["bssid"]
            if b not in aps:
                aps[b] = {"bssid": b, "ssid": r["ssid"] or "",
                          "band": r["band"] or "", "channel": r["channel"],
                          "is_own": bool(r["is_own"])}
            elif r["ssid"] and not aps[b]["ssid"]:
                aps[b]["ssid"] = r["ssid"]
            key = (round(r["x"], 4), round(r["y"], 4), r["ort"] or "")
            points.setdefault(key, {"x": r["x"], "y": r["y"], "ort": r["ort"] or "",
                                    "rssi": {}})
            if r["rssi"] is not None:
                prev = points[key]["rssi"].get(b)
                # bei mehreren Messungen an gleicher Stelle: besten (höchsten) RSSI behalten
                if prev is None or r["rssi"] > prev:
                    points[key]["rssi"][b] = r["rssi"]
            samples_out.append({"id": r["id"], "x": r["x"], "y": r["y"],
                                "ort": r["ort"] or "", "bssid": b,
                                "ssid": r["ssid"] or "", "rssi": r["rssi"],
                                "is_own": bool(r["is_own"])})
        pts = []
        for p in points.values():
            best = None
            for v in p["rssi"].values():
                if best is None or v > best:
                    best = v
            pts.append({"x": p["x"], "y": p["y"], "ort": p["ort"],
                        "rssi": p["rssi"], "best_rssi": best,
                        "quality": self._rssi_quality(best)})
        return {
            "points": pts,
            "samples": samples_out,
            "aps": sorted(aps.values(), key=lambda a: (not a["is_own"], a["ssid"], a["bssid"])),
            "point_count": len(pts),
            "sample_count": len(samples_out),
            "has_floorplan": self.store.get_wlan_floorplan(target_id) is not None,
            "legend": {"gut": ">= -55 dBm", "ok": "-56..-67 dBm",
                       "schwach": "-68..-75 dBm", "funkloch": "< -75 dBm"},
        }


    def _wlan_points_from_store(self, target_id: Optional[int] = None):
        """Rekonstruiert Mess-Punkte + eigene BSSIDs aus den gespeicherten Samples."""
        rows = self.store.list_wlan_samples(target_id)
        points: dict = {}
        own: set = set()
        for r in rows:
            lbl = r["point_label"]
            points.setdefault(lbl, {})[r["bssid"]] = r["rssi"]
            if r["is_own"]:
                own.add(r["bssid"])
        pts = [{"label": k, "samples": v} for k, v in points.items()]
        return pts, sorted(own)

    def wlan_survey(self, target_id: Optional[int] = None,
                    aps: Optional[list] = None,
                    own_bssids: Optional[list] = None,
                    iface: Optional[str] = None,
                    scan: bool = False) -> dict:
        """Voller Survey: (optional) Live-Scan + gespeicherte Messpunkte →
        Kanal-Analyse + Coverage + Empfehlungen. Reine Daten, honest-empty."""
        from . import wlan_survey as ws
        scan_result = None
        if aps is None:
            if scan:
                scan_result = ws.scan_environment(iface=iface, force=True)
                aps = scan_result.get("aps", [])
            else:
                aps = []
        points, store_own = self._wlan_points_from_store(target_id)
        merged_own = sorted(set(store_own) | {b.lower() for b in (own_bssids or [])})
        survey = ws.full_survey(aps, points=points, own_bssids=merged_own)
        survey["own_bssids"] = merged_own
        survey["scan"] = scan_result
        survey["tools"] = ws.tool_availability()
        survey["enabled"] = ws.wifi_enabled()
        return survey

    def _not_in_blue_queen(self, what: str) -> None:
        raise RuntimeError(
            f"{what} ist in dieser Blue-Queen-Ausgabe nicht enthalten.")

    def _wifi_off(self, dry_run: bool = False):
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_engagement_create(self, name: str, bssids=None, ssids=None,
                               start_ts: Optional[float] = None,
                               end_ts: Optional[float] = None,
                               duration_hours: float = 8.0,
                               client_mac: str = "", location: str = "",
                               target_id: Optional[int] = None,
                               oversight: bool = False) -> int:
        self._not_in_blue_queen("WLAN-Engagement")

    def wlan_engagement_list(self, include_revoked: bool = True) -> list:
        self._not_in_blue_queen("WLAN-Engagement")

    def wlan_engagement_get(self, engagement_id: int):
        self._not_in_blue_queen("WLAN-Engagement")

    def wlan_engagement_oversight(self, engagement_id: int, confirmed: bool) -> None:
        self._not_in_blue_queen("WLAN-Engagement")

    def wlan_engagement_revoke(self, engagement_id: int) -> None:
        self._not_in_blue_queen("WLAN-Engagement")

    def wlan_authorize_check(self, bssid: str = "", ssid: str = "",
                             client_mac: str = "") -> dict:
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_offensive_run(self, action: str, *, bssid: str = "", ssid: str = "",
                           client_mac: str = "", channel=None, seconds: int = 60,
                           packets: int = 10, capture_path: str = "",
                           wordlist: Optional[str] = None,
                           dry_run: bool = False) -> dict:
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_credentials_list(self, engagement_id: Optional[int] = None) -> list:
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_credentials_purge(self, engagement_id: Optional[int] = None) -> int:
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_offensive_tool_status(self) -> dict:
        self._not_in_blue_queen("WLAN-Offensiv")

    def wlan_airgorah_status(self, iface: Optional[str] = "") -> dict:
        self._not_in_blue_queen("WLAN-Airgorah")

    def wlan_clients(self, iface: str = "", bssid: str = "") -> dict:
        self._not_in_blue_queen("WLAN-Airgorah")

    def wlan_full_scan_checks(self) -> list:
        self._not_in_blue_queen("WLAN-Airgorah")

    def wlan_full_scan(self, *, iface: Optional[str] = None, checks=None,
                       oversight_ack: bool = False,
                       target_id: Optional[int] = None,
                       emit: Optional[Callable[[dict], None]] = None) -> dict:
        self._not_in_blue_queen("WLAN-Airgorah")

    # ---------------- Soldaten (Skills/Playbooks/Overrides/Mems) ----------------
    def soldier_detail(self, name: str, target_id: Optional[int] = None) -> dict:
        """Skill+Playbooks (aus Registry) + Overrides + Mems + letzter Lauf."""
        reg = registry_mod.build_registry()
        sol = next((s for s in reg["soldiers"] if s["name"] == name), None)
        if sol is None:
            raise ValueError(f"Soldat '{name}' unbekannt.")
        overrides = [dict(r) for r in self.store.list_soldier_overrides(name)]
        # SKILL.md-Override (editierbarer Volltext) anwenden, falls gesetzt.
        for o in overrides:
            if o.get("playbook", "") == "" and o.get("key") == "skill_md" and o.get("value"):
                sol["skill"]["skill_md"] = o["value"]
                sol["skill"]["skill_md_edited"] = True
        mems = [dict(r) for r in self.store.list_soldier_mems(name)]
        results = []
        if target_id is not None:
            for f in self.store.list_findings(target_id):
                if f["agent"] == name:
                    results.append({"id": f["id"], "title": f["title"],
                                    "severity": f["severity"], "status": f["status"],
                                    "asset": f["asset"], "category": f["category"]})
        return {"soldier": sol, "overrides": overrides, "mems": mems,
                "results": results, "result_count": len(results)}

    def set_soldier_override(self, name: str, playbook: str, key: str, value: str) -> int:
        return self.store.set_soldier_override(name, playbook, key, value)

    def delete_soldier_override(self, name: str, playbook: str, key: str) -> None:
        self.store.delete_soldier_override(name, playbook, key)

    def add_soldier_mem(self, name: str, text: str) -> int:
        return self.store.add_soldier_mem(name, text)

    def delete_soldier_mem(self, mem_id: int) -> None:
        self.store.delete_soldier_mem(mem_id)

    # ---------------- LLM ----------------
    # ---------------- Capability-Registry (Königin-Gedächtnis) ----------------
    def capabilities(self, rebuild: bool = True) -> dict:
        """Liefert die Capability-Registry der Königin.

        Mit rebuild=True (Default) wird sie FRISCH aus den Soldaten aufgebaut und
        ins Königin-Gedächtnis (Store) persistiert – Single Source of Truth,
        aktualisiert sich automatisch bei neuen Playbooks/Skills/Tools.
        """
        if rebuild:
            return registry_mod.persist_registry(self.store)
        reg = registry_mod.get_registry(self.store)
        return reg or registry_mod.persist_registry(self.store)

    # ---------------- Report-Builder-Hilfen (Feature 1 + 2) ----------------
    def report_prefill(self, target_id: int, finding_id: int) -> dict:
        """Prefill der 8-Schritt-Kette + Titel/CVSS aus einem ECHTEN Finding."""
        from . import findingreport as fr
        rows = self.store.list_findings(target_id)
        row = next((r for r in rows if int(r["id"]) == int(finding_id)), None)
        if row is None:
            raise ValueError(f"Finding {finding_id} nicht in Target {target_id}.")
        return fr.chain_from_finding(self.store, row)

    def professional_report(self, target_id: int, finding_ids=None,
                            instruction: str = "", title: Optional[str] = None,
                            include_addenda_for: Optional[int] = None) -> str:
        """Voller strukturierter Markdown-Bericht (Code + Remediation je Finding)."""
        from . import findingreport as fr
        addenda = None
        if include_addenda_for is not None:
            addenda = self.store.list_addenda(include_addenda_for)
        return fr.professional_report_md(
            self.store, target_id, finding_ids=finding_ids,
            instruction=instruction, title=title, addenda=addenda)

    # ---- Nachträge (Addenda) ----
    def add_report_addendum(self, report_id: int, text: str, author: str = "") -> int:
        row = self.store.get_report(report_id)
        if not row:
            raise ValueError(f"Report {report_id} existiert nicht.")
        return self.store.add_addendum(report_id, text, author=author)

    def list_report_addenda(self, report_id: int):
        return self.store.list_addenda(report_id)

    # ---- Neu-Anweisung (Revision mit Historie) ----
    def reinstruct_report(self, report_id: int, instruction: str,
                          author: str = "", finding_ids=None) -> dict:
        """Regeneriert den strukturierten Berichtstext aus (aktuellen) Findings +
        Neu-Anweisung und speichert ihn als NEUE Revision (Historie bleibt)."""
        row = self.store.get_report(report_id)
        if not row:
            raise ValueError(f"Report {report_id} existiert nicht.")
        from . import findingreport as fr
        addenda = self.store.list_addenda(report_id)
        body = fr.professional_report_md(
            self.store, row["target_id"], finding_ids=finding_ids,
            instruction=instruction, title=row["title"], addenda=addenda,
            revision_note="auf Basis einer Neu-Anweisung regeneriert")
        rev_id = self.store.add_revision(report_id, body, instruction=instruction,
                                         author=author)
        revs = self.store.list_revisions(report_id)
        return {"revision_id": rev_id, "revision": len(revs), "body": body}

    def list_report_revisions(self, report_id: int):
        return self.store.list_revisions(report_id)

    def get_report_revision(self, revision_id: int):
        return self.store.get_revision(revision_id)

    # ===================================================================
    # ARES "acceptable half" – defensive/Infrastruktur-Features
    # ===================================================================

    # ---------------- 1) Scope-Firewall / Egress-Filter (DRY-RUN) ----------------
    def egress_firewall_plan(self, target_id: int, resolve: bool = True) -> dict:
        """Baut den OS-Egress-Regelsatz (iptables+nft) aus der In-Scope-Allowlist.

        Immer DRY-RUN: es wird NIE die echte Firewall angefasst.
        """
        from . import egress_firewall as fw
        scopes = self.store.list_scopes(target_id)
        return fw.generate(scopes, resolve=resolve).to_dict()

    def egress_firewall_apply(self, target_id: int, engine: str = "iptables",
                              confirm: bool = False) -> dict:
        """Wendet die Egress-Regeln NUR bei erfüllten Gates an (sonst honest no-op)."""
        from . import egress_firewall as fw
        scopes = self.store.list_scopes(target_id)
        return fw.apply(scopes, engine=engine, confirm=confirm).to_dict()

    def egress_firewall_engines(self) -> dict:
        from . import egress_firewall as fw
        return fw.available_engines()

    # ---------------- 2) Branded Report-Pipeline ----------------
    def branded_report_html(self, target_id: int, brand: Optional[dict] = None,
                            finding_ids=None, toolbar: bool = False,
                            engine_note: str = "") -> str:
        from . import brandedreport as br
        cfg = br.BrandConfig.from_dict(brand)
        return br.build_html(self.store, target_id, cfg, finding_ids=finding_ids,
                             toolbar=toolbar, engine_note=engine_note)

    def branded_report_pdf(self, target_id: int, brand: Optional[dict] = None,
                           finding_ids=None) -> dict:
        """PDF-Bytes des professionellen Reports (falls Engine vorhanden).

        Rueckgabe: {pdf: bytes|None, engine, note, filename, html}. Ohne Engine
        honest-empty (pdf=None, note nennt weasyprint/wkhtmltopdf).
        """
        from . import brandedreport as br
        cfg = br.BrandConfig.from_dict(brand)
        doc = br.build_html(self.store, target_id, cfg, finding_ids=finding_ids)
        data, engine, note = br.render_pdf_bytes(doc)
        return {
            "pdf": data,
            "engine": engine,
            "note": note,
            "filename": br.report_filename(self.store, target_id, "pdf"),
            "html": doc,
            "html_filename": br.report_filename(self.store, target_id, "html"),
        }

    def branded_report_export(self, target_id: int, brand: Optional[dict] = None,
                              finding_ids=None, want_pdf: bool = True,
                              out_dir: Optional[str] = None) -> dict:
        from . import brandedreport as br
        cfg = br.BrandConfig.from_dict(brand)
        od = out_dir or DEFAULT_EXPORT_DIR
        return br.export(self.store, target_id, cfg, od,
                         finding_ids=finding_ids, want_pdf=want_pdf).to_dict()

    def pdf_engine(self) -> Optional[str]:
        from . import brandedreport as br
        return br.pdf_engine()

    # ---------------- 3) Module-SDK (lokale Plugins) ----------------
    def plugins_list(self, plugins_dir: Optional[str] = None) -> dict:
        from . import sdk
        return sdk.registry_block(plugins_dir)

    def plugins_run(self, name: str, target_id: int,
                    plugins_dir: Optional[str] = None) -> dict:
        from . import sdk
        rep = sdk.discover_plugins(plugins_dir)
        lp = next((p for p in rep.plugins if p.meta["name"] == name), None)
        if lp is None:
            raise ValueError(f"Plugin '{name}' nicht gefunden "
                             f"(verfügbar: {[p.meta['name'] for p in rep.plugins]}).")
        assets = scope_mod.allowed_assets(self.store, target_id)
        ctx = sdk.PluginContext(
            scope_check=lambda a: self.check_asset(target_id, a).allowed,
            assets=assets, target_id=target_id, logger=self.logger)
        return sdk.run_plugin(lp.cls, ctx)

    # ---------------- 4) Replay / Checkpoint ----------------
    def checkpoints_list(self, target_id: Optional[int] = None) -> list:
        from . import replay
        return replay.list_checkpoints(self.store, target_id)

    def checkpoint_resume(self, run_id: str) -> dict:
        from . import replay
        return replay.resume(self.store, run_id)

    def checkpoint_replay(self, run_id: str,
                          emit: Optional[Callable[[dict], None]] = None) -> dict:
        from . import replay
        r = replay.replay(self.store, run_id, emit=emit)
        return {"run_id": r.run_id, "target_id": r.target_id, "status": r.status,
                "step_count": r.step_count, "events": r.events,
                "findings": r.findings, "phases": r.phases}

    def checkpoint_recorder(self, run_id: str, target_id: int, phases=None,
                            meta: Optional[dict] = None):
        """Gibt einen Recorder zurück (für Integration in einen Lauf)."""
        from . import replay
        return replay.Recorder(self.store, run_id, target_id, phases=phases, meta=meta)

    # ---------------- 5) DAG-Angriffspfad-Visualisierung (nur Darstellung) ----------------
    def attack_graph(self, target_id: int) -> dict:
        from . import attackpath
        return attackpath.graph_for_target(self.store, target_id)

    def attack_paths_markdown(self, target_id: int) -> str:
        from . import attackpath
        return attackpath.paths_markdown(attackpath.graph_for_target(self.store, target_id))

    # ---------------- Fernzugriff / Remote-Access (Präferenz + Status) ----------------
    REMOTE_MODE_KEY = "remote_access_mode"

    def get_remote_mode(self) -> str:
        """Gespeicherter Fernzugriff-Modus (off | tailscale | cloudflare).
        Default: off (nur lokal). Es wird KEIN Secret gelesen/geschrieben."""
        from . import remote_access as ra
        return ra.normalize_mode(
            self.store.get_setting(self.REMOTE_MODE_KEY, ra.DEFAULT_MODE))

    def set_remote_mode(self, mode: str) -> str:
        """Speichert NUR die Präferenz. Startet NICHTS, exponiert NICHTS,
        schreibt KEIN Token. Gibt den normalisierten Modus zurück."""
        from . import remote_access as ra
        m = ra.normalize_mode(mode)
        self.store.set_setting(self.REMOTE_MODE_KEY, m)
        return m

    def remote_status(self) -> dict:
        """Ehrlicher, rein lesender Status beider Transporte + aktiver Modus.
        honest-empty, wenn Binaries fehlen; erfindet nie IP/Hostname/Status."""
        from . import remote_access as ra
        return ra.status_for(self.get_remote_mode())

    def remote_setup_steps(self, mode: str) -> list:
        """Manuelle Setup-Schritte für den gewählten Transport (nur Text)."""
        from . import remote_access as ra
        return ra.setup_steps(mode)

    def llm_status(self):
        """Status aller konfigurierten LLM-Provider – ohne Key-Werte."""
        return {
            "default_provider": llm_mod.DEFAULT_PROVIDER,
            "main_model": llm_mod.MAIN_MODEL,
            "fast_model": llm_mod.FAST_MODEL,
            "providers": llm_mod.status_all(),
        }

    # ---------------- Blue Queen (Verteidigungs-Kolonie) ----------------
    def blue_capabilities(self) -> dict:
        """Blue-Soldaten aus der Registry (colony=blue)."""
        reg = self.capabilities(rebuild=True)
        blues = [s for s in reg.get("soldiers", []) if s.get("colony") == "blue"]
        import os as _os
        pb_dir = _os.path.join(_os.path.dirname(__file__), "playbooks", "blue")
        try:
            pb_md = len([f for f in _os.listdir(pb_dir) if f.endswith(".md")])
        except Exception:
            pb_md = 0
        pb_n = sum(len(s.get("playbooks") or []) for s in blues)
        task_n = sum(((s.get("skill") or {}).get("task_count") or 0) for s in blues)
        return {
            "blue_phases": reg.get("blue_phases", []),
            "soldier_count": len(blues),
            "playbook_count": pb_n,
            "task_count": task_n,
            "playbook_md_count": pb_md,
            "soldiers": blues,
            "soldier_ids": [s.get("name") for s in blues],
            "splunk": __import__("antbb.splunk", fromlist=["status"]).status(),
        }

    def run_blue(self, target_id: Optional[int] = None,
                 phases: Optional[tuple] = None, apply_fixes: bool = False,
                 oversight_ack: Optional[bool] = None,
                 params: Optional[dict] = None,
                 emit: Optional[Callable[[dict], None]] = None,
                 use_llm: Optional[bool] = None):
        """Startet die Verteidigungs-Kolonie (Blue Queen). Default: read-only.

        Der Provider-Router hängt an der Königin, sobald ein Provider zur
        Laufzeit konfiguriert ist. ``ANTBB_NO_LLM=1`` schaltet das ab. Ohne
        Provider läuft der Lauf trotzdem (kein Key im Repo).
        """
        from .blue_queen import BlueQueen, PHASES as BP
        if use_llm is None:
            use_llm = os.environ.get("ANTBB_NO_LLM", "").strip().lower() not in (
                "1", "true", "yes", "on",
            )
        queen = BlueQueen(self.store, logger=self.logger, emit=emit, use_llm=use_llm)
        result = queen.run_colony_sync(
            target_id=target_id, phases=phases or BP,
            apply_fixes=apply_fixes, oversight_ack=oversight_ack,
            params=params)
        try:
            self.store.add_run_history(
                run_id=result.run_id, target_id=target_id,
                target_name=result.target_name, mode="blue",
                active=bool(apply_fixes), fuzz=False, offensive=False,
                status="done", finding_count=len(result.findings),
                severity=result.by_severity(),
                started_at=result.started_at, finished_at=result.finished_at,
                duration=result.duration)
        except Exception:
            self.logger.exception("Blue-Lauf nicht in der Historie gespeichert")
        return result

    def blue_jobs_list(self, enabled_only: bool = False):
        from .jobs import JobScheduler
        return JobScheduler(self.store, logger=self.logger).list(enabled_only)

    def blue_job_create(self, name: str, kind: str, interval_sec: int = 86400,
                        target_id: Optional[int] = None,
                        params: Optional[dict] = None) -> int:
        from .jobs import JobScheduler
        return JobScheduler(self.store, logger=self.logger).create(
            name, kind, interval_sec=interval_sec, target_id=target_id,
            params=params)

    def blue_job_run(self, job_id: int) -> dict:
        from .jobs import JobScheduler
        return JobScheduler(self.store, logger=self.logger).run_once(job_id)

    def blue_job_runs(self, job_id: Optional[int] = None, limit: int = 50):
        from .jobs import JobScheduler
        return JobScheduler(self.store, logger=self.logger).runs(job_id, limit)

    def blue_jobs_tick(self) -> list:
        from .jobs import JobScheduler
        return JobScheduler(self.store, logger=self.logger).tick()

    def softwarescan(self, online: bool = True, ecosystems=None) -> dict:
        """Direkter Software-/Versions-Scan (ohne Kolonie-Lauf)."""
        from . import softwarescan as sw
        rep = sw.scan(ecosystems=ecosystems, online=online)
        return {
            "summary": rep.summary(),
            "packages": [{"name": p.name, "version": p.version,
                          "ecosystem": p.ecosystem, "source": p.source}
                         for p in rep.packages],
            "matches": [{"package": m.package, "version": m.version,
                         "ecosystem": m.ecosystem, "vuln_id": m.vuln_id,
                         "summary": m.summary, "severity": m.severity,
                         "fixed": m.fixed, "aliases": m.aliases}
                        for m in rep.matches],
        }

    # ---------------- Greenbone / OpenVAS (Blue Queen) ----------------
    def greenbone_status(self) -> dict:
        """Ehrlicher GVM-Status (kein Secret). Import bleibt immer möglich."""
        from . import greenbone as gb
        try:
            st = gb.status()
            d = gb.drop_dir()
            try:
                files = sorted(
                    (f for f in d.iterdir()
                     if f.is_file() and f.suffix.lower() in gb.IMPORT_SUFFIXES),
                    key=lambda f: f.stat().st_mtime)
                st["drop_files"] = [f.name for f in files][-20:]
            except OSError:
                st["drop_files"] = []
            st["drop_dir"] = "data/greenbone/"
            return st
        except Exception as exc:
            return {
                "available": False, "import_available": True, "can_scan": False,
                "error": f"Greenbone nicht verfügbar ({type(exc).__name__})",
                "message": "", "drop_files": [], "drop_dir": "data/greenbone/",
            }

    def greenbone_import(self, path: str = "", data: Optional[bytes] = None,
                         filename: str = "", target_id: Optional[int] = None,
                         min_severity: str = "high") -> dict:
        """Defensiv: Report importieren (Upload-Bytes ODER Pfad unter data/greenbone/).

        Mit `target_id` werden nur In-Scope-Hosts übernommen und als Findings
        persistiert; ohne Target ist es eine reine Datei-Analyse. Kein Oversight.
        """
        from . import greenbone as gb
        import uuid as _uuid
        if data is not None:
            path = str(gb.save_upload(filename or "report.xml", data))
        scope_filter = None
        if target_id is not None:
            if not self.store.get_target(target_id):
                raise ValueError(f"Target {target_id} existiert nicht.")

            def scope_filter(host: str, tid: int = int(target_id)) -> bool:
                return bool(scope_mod.check_asset(self.store, tid, host))

        res = gb.import_report(path or "", min_hint_severity=min_severity or "high",
                               scope_filter=scope_filter)
        if not res.get("ok"):
            return {
                "ok": False, "empty": bool(res.get("empty")),
                "error": res.get("error") or "Import fehlgeschlagen.",
                "report_file": res.get("report_file") or "",
                "findings": [], "hints": [], "persisted": 0,
            }
        findings = list(res.get("findings") or [])
        hints = list(res.get("hints") or [])
        persisted = 0
        if target_id is not None:
            run_id = "greenbone-" + _uuid.uuid4().hex[:12]
            bundle = [gb.summary_finding(res["report"], res["report_file"])]
            bundle.extend(findings)
            bundle.extend(gb.hint_findings(hints))
            for f in bundle:
                rid = self.store.add_finding(
                    int(target_id), run_id, f.agent, f.title, f.category,
                    f.severity, asset=f.asset, description=f.description,
                    evidence=f.evidence, dedup_key=f.dedup_key, status=f.status,
                    false_positive=bool(f.false_positive))
                if rid is not None:
                    persisted += 1
        return {
            "ok": True, "empty": False,
            "report_file": res["report_file"],
            "summary": res["summary"],
            "out_of_scope_skipped": res.get("out_of_scope_skipped", 0),
            "persisted": persisted,
            "findings": [_gb_finding_public(f) for f in findings],
            "hints": hints,
        }

    def greenbone_scan(self, target_id: int, host: str, oversight_ack: Optional[bool],
                       scan_config: str = "", wait_seconds: int = 0) -> dict:
        """AKTIV: Scan gegen ein In-Scope-Einzelziel (Oversight + Scope Pflicht)."""
        from . import greenbone as gb
        if not self.store.get_target(target_id):
            raise ValueError(f"Target {target_id} existiert nicht.")
        cfg = scan_config or gb.DEFAULT_SCAN_CONFIG

        def scope_check(h: str, tid: int = int(target_id)) -> bool:
            return bool(scope_mod.check_asset(self.store, tid, h))

        res = gb.start_scan(host, scope_check=scope_check,
                            acknowledged=oversight_ack is True, scan_config=cfg)
        if res.get("ok") and int(wait_seconds or 0) > 0:
            res["status"] = gb.wait_for_scan(res["task_id"], int(wait_seconds))
        return res

    def greenbone_scan_status(self, task_id: str, import_report: bool = False,
                              target_id: Optional[int] = None) -> dict:
        """Lesend: Task-Status; bei fertigem Scan optional Report abholen + importieren."""
        from . import greenbone as gb
        st = gb.scan_status(task_id)
        if st.get("ok") and import_report and st.get("done") and st.get("report_id"):
            path = gb.fetch_report(st["report_id"])
            st["import"] = self.greenbone_import(path=str(path), target_id=target_id)
        return st

    def attack_log_list(self, limit: int = 50, run_id: str = "",
                        event_type: str = ""):
        from .attack_log import AttackLog
        alog = AttackLog(self.store)
        return {
            "events": alog.list(run_id=run_id, event_type=event_type, limit=limit),
            "total": alog.count(),
            "summary": alog.summary(),
        }

    def watcher_run(self, events=None, active: bool = False,
                    apply_protect: bool = False, kinds=None,
                    run_id: str = "", target_id=None) -> dict:
        from . import watcher as _w
        report = _w.run_watch(
            events or [], active=active, apply_protect=apply_protect,
            kinds=kinds, store=self.store, run_id=run_id or "",
            target_id=target_id)
        return report.to_dict()

