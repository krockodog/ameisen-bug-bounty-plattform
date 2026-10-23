"""Blue-Soldat: Greenbone/OpenVAS (GVM) – Schwachstellen-Import & Härtungs-Hinweise.

Defensiv (immer): GVM-Status, Report-Import aus Datei (XML/CSV/JSON) und
Überführung von High/Critical-Funden in Härtungs-/Ticket-Hinweise.
Aktiv (nur Oversight + In-Scope-Ziel): ein einzelner, nicht-destruktiver Scan.
Nichts wird erfunden – fehlt GVM, kommt ein ehrliches „nicht verfügbar".
Die Fachlogik liegt in `antbb.greenbone`.
"""
from __future__ import annotations

import asyncio

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import greenbone as gb
from ...agents.base import STATUS_REFERENCE


class GreenboneAnt(BlueAgent):
    name = "blue-greenbone"
    specialty = "blue-greenbone-vuln-importer"
    role = ("Greenbone/OpenVAS-Anbindung: GVM-Status prüfen, Scan-Reports importieren "
            "(CVE/CVSS/QoD) und High/Critical-Funde als Härtungs-/Ticket-Hinweise "
            "für Patch-Mgmt, Hardening und Vuln-Ticket aufbereiten. Scan-Start nur "
            "mit Oversight gegen ein In-Scope-Einzelziel.")
    blue_phases = ("assess", "remediate")
    playbooks = (
        Playbook("gb-status", "defensive", False,
                 ["gvm-cli", "python-gvm", "gvmd-socket"],
                 "Prüft, ob Greenbone/GVM erreichbar ist (Socket, Client, Version, Feed) – "
                 "ehrlich „nicht verfügbar“, wenn nicht.",
                 tasks=["gvmd-Socket und Client (python-gvm / gvm-cli) erkennen",
                        "GMP-Version über get_version erfragen (ohne Zugangsdaten)",
                        "Feed-Alter nur mit konfigurierten Zugangsdaten bewerten",
                        "Nicht verfügbar ehrlich melden – keine Fake-Daten"]),
        Playbook("gb-import-report", "defensive", False,
                 ["greenbone-xml", "greenbone-csv", "greenbone-json"],
                 "Importiert einen Greenbone/OpenVAS-Report (XML/CSV/JSON) aus data/greenbone/ "
                 "und führt Ergebnisse mit CVE, CVSS, QoD, Host und Port als Findings.",
                 tasks=["Report-Datei in data/greenbone/ wählen (Param report_path oder neueste)",
                        "Format erkennen und robust parsen (nur echte Felder)",
                        "Severity aus CVSS/Threat ableiten, Log-Level nicht als Befund führen",
                        "Hosts gegen den Scope des Targets filtern (default-deny)",
                        "Findings als REFERENZ (Fremd-Scanner) mit Evidence ausgeben"]),
        Playbook("gb-scoped-scan", "offensive", True,
                 ["gvm-cli", "python-gvm", "get_tasks", "start_task"],
                 "Startet einen nicht-destruktiven Greenbone-Scan gegen genau ein In-Scope-Ziel "
                 "(nur mit Human Oversight); Report später per Import abholen.",
                 tasks=["Oversight-Freigabe und Scope des Einzelziels prüfen (default-deny)",
                        "Nur Allowlist-Scan-Config (Full and fast, Base, Discovery …) verwenden",
                        "Parallelstart und Rate-Limit ausschließen, dann Task starten",
                        "Status begrenzt abfragen, Report nach data/greenbone/ ablegen"]),
        Playbook("gb-to-hardening", "defensive", False,
                 ["remediation-hints", "ticket-backlog"],
                 "Strukturiert importierte High/Critical-Funde als Ticket-/Härtungs-Hinweise "
                 "und weist sie Patch-Mgmt, Hardening, TLS, Firewall oder Vuln-Ticket zu.",
                 tasks=["High/Critical-Funde je NVT gruppieren",
                        "Lösungstext und Lösungstyp unverändert aus dem Report übernehmen",
                        "Zuständigen Blue-Soldaten (Patch, Hardening, TLS, Firewall) vorschlagen",
                        "Close-Kriterium: Re-Scan ohne NVT + Vorher/Nachher-Evidence"]),
    )

    # ---------------------------------------------------------------- Helfer
    def _scope_filter(self, task: Task):
        if not task.target_id:
            return None            # lokaler Modus ohne Target: Datei-Analyse, keine Persistenz
        return lambda host: bool(self.ctx.scope_check(host))

    def _status_finding(self, st: dict) -> AgentFinding:
        if st.get("available"):
            title = f"Greenbone erreichbar (GMP {st.get('version') or '?'})"
        else:
            title = "Greenbone nicht verfügbar"
        ev = {k: st.get(k) for k in ("available", "reachable", "transport", "python_gvm",
                                     "gvm_cli", "socket", "credentials_configured",
                                     "version", "feed_ok", "feed_note", "error")}
        return AgentFinding(
            agent=self.name, title=title, category=gb.CATEGORY_STATUS, severity="info",
            asset="greenbone", description=st.get("message", ""), evidence=ev,
            status=STATUS_REFERENCE, dedup_key="blue-greenbone-status")

    def _import(self, task: Task, params: dict) -> dict:
        try:
            return gb.import_report(params.get("report_path") or "",
                                    min_hint_severity=str(params.get("gvm_min_severity") or "high"),
                                    scope_filter=self._scope_filter(task))
        except gb.GvmError as exc:
            return {"ok": False, "empty": False, "error": str(exc), "findings": [], "hints": []}

    # ------------------------------------------------------------------ work
    async def work(self, task: Task) -> list[AgentFinding]:
        params = task.params or {}
        if task.phase == "remediate":
            return await self._remediate(task, params)
        out: list[AgentFinding] = []

        if self.playbook_enabled("gb-status"):
            st = await asyncio.to_thread(gb.status)
            out.append(self._status_finding(st))
            self.ctx.log(f"[blue-greenbone] 🛰 {st.get('message')}")
        else:
            self.ctx.log("[blue-greenbone] ⏸ Playbook 'gb-status' deaktiviert – übersprungen.")

        imported = None
        if self.playbook_enabled("gb-import-report"):
            imported = self._import(task, params)
            out.extend(self._import_findings(imported))
        else:
            self.ctx.log("[blue-greenbone] ⏸ Playbook 'gb-import-report' deaktiviert – übersprungen.")

        scan_target = str(params.get("gvm_scan_target") or "").strip()
        if scan_target:
            if self.playbook_enabled("gb-scoped-scan"):
                out.extend(await self._scan(scan_target, params, task))
            else:
                self.ctx.log("[blue-greenbone] ⏸ Playbook 'gb-scoped-scan' deaktiviert – übersprungen.")
        return out

    def _import_findings(self, res: dict) -> list[AgentFinding]:
        if res.get("empty") or not res.get("ok"):
            msg = res.get("error") or "Kein Greenbone-Report vorhanden."
            self.ctx.log(f"[blue-greenbone] ℹ️ {msg}")
            return [AgentFinding(
                agent=self.name, title="Kein Greenbone-Report importiert",
                category=gb.CATEGORY_SUMMARY, severity="info", asset="greenbone-report",
                description=(msg + " Report (XML/CSV/JSON) nach data/greenbone/ legen oder "
                             "über /blue importieren – es werden keine Daten erfunden."),
                evidence={"source": "greenbone", "empty": bool(res.get("empty"))},
                status=STATUS_REFERENCE, dedup_key="blue-greenbone-summary:none")]
        rep = res["report"]
        s = gb.summary_finding(rep, res["report_file"])
        if res.get("out_of_scope_skipped"):
            s.description += (f" {res['out_of_scope_skipped']} Ergebnis(se) außerhalb des Scopes "
                              "wurden verworfen (default-deny).")
            s.evidence["out_of_scope_skipped"] = res["out_of_scope_skipped"]
        self.ctx.log(f"[blue-greenbone] 📥 {res['report_file']}: {len(rep.results)} Ergebnis(se), "
                     f"{res.get('out_of_scope_skipped', 0)} out-of-scope verworfen.")
        return [s, *res["findings"]]

    async def _scan(self, host: str, params: dict, task: Task) -> list[AgentFinding]:
        if not self.active_allowed():
            self.ctx.log("[blue-greenbone] ⛔ Scan nicht gestartet: Human-Oversight-Freigabe fehlt.")
            return [AgentFinding(
                agent=self.name, title=f"Greenbone-Scan nicht gestartet ({host}): Oversight fehlt",
                category=gb.CATEGORY_SCAN, severity="info", asset="greenbone",
                description="Aktive Scans laufen nur mit ausdrücklicher Human-Oversight-Freigabe.",
                evidence={"started": False, "reason": "oversight"}, status=STATUS_REFERENCE,
                dedup_key=f"blue-greenbone-scan:{host}")]
        res = await asyncio.to_thread(
            gb.start_scan, host, scope_check=self.ctx.scope_check,
            acknowledged=True, scan_config=str(params.get("gvm_scan_config") or gb.DEFAULT_SCAN_CONFIG),
            log=self.ctx.log)
        ev = {k: v for k, v in res.items() if k != "ok"}
        ev["started"] = bool(res.get("ok"))
        out = [AgentFinding(
            agent=self.name,
            title=(f"Greenbone-Scan gestartet: {host}" if res.get("ok")
                   else f"Greenbone-Scan nicht gestartet ({host})"),
            category=gb.CATEGORY_SCAN, severity="info", asset=host if res.get("ok") else "greenbone",
            description=(f"Task {res.get('task_id')} läuft; Report nach Abschluss importieren."
                         if res.get("ok") else res.get("error", "")),
            evidence=ev, status=STATUS_REFERENCE, dedup_key=f"blue-greenbone-scan:{host}")]
        wait = int(params.get("gvm_wait") or 0)
        if res.get("ok") and wait > 0:
            st = await asyncio.to_thread(gb.wait_for_scan, res["task_id"], wait)
            if st.get("ok") and st.get("done") and st.get("report_id"):
                try:
                    path = await asyncio.to_thread(gb.fetch_report, st["report_id"])
                    imp = await asyncio.to_thread(
                        gb.import_report, str(path), scope_filter=self._scope_filter(task))
                    out.extend(self._import_findings(imp))
                except gb.GvmError as exc:
                    self.ctx.log(f"[blue-greenbone] ⚠ Report-Abholung fehlgeschlagen: {exc}")
            else:
                self.ctx.log(f"[blue-greenbone] ⏳ Scan noch nicht fertig (Status {st.get('state', '?')}).")
        return out

    async def _remediate(self, task: Task, params: dict) -> list[AgentFinding]:
        if not self.playbook_enabled("gb-to-hardening"):
            self.ctx.log("[blue-greenbone] ⏸ Playbook 'gb-to-hardening' deaktiviert – übersprungen.")
            return []
        res = self._import(task, params)
        hints = res.get("hints") or []
        if not hints:
            self.ctx.log("[blue-greenbone] ℹ️ Keine High/Critical-Funde → keine Härtungs-Hinweise.")
            return []
        self.ctx.log(f"[blue-greenbone] 🎫 {len(hints)} Härtungs-/Ticket-Hinweis(e) aus High/Critical-Funden "
                     "(keine automatischen Fixes).")
        return gb.hint_findings(hints, agent=self.name)
