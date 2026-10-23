"""Blue-Soldat: Vuln-Ticket-Close – Schließungs-Ledger und Abschlussbericht.

Wertet alle Check-Ergebnisse des Laufs aus, führt das Ledger (data/blue_ledger.json)
und belegt Lücken, die seit einem früheren Lauf von fail → pass gewechselt sind, als
„nachweislich geschlossen" (Vorher/Nachher mit Zeitstempeln). Schreibt zusätzlich einen
Markdown-Abschlussbericht nach data/exports/. Rein lesend gegenüber dem System.
"""
from __future__ import annotations

import time
from pathlib import Path

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import blue_checks as _bc
from ... import config as _config

_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class TicketCloseAnt(BlueAgent):
    name = "blue-ticketclose"
    specialty = "blue-closure-ledger-keeper"
    role = ("Vuln-Ticket-Close: führt das Schließungs-Ledger über Läufe, belegt "
            "fail→pass-Übergänge mit Vorher/Nachher und erstellt den Abschlussbericht.")
    blue_phases = ("verify",)
    playbooks = (
        Playbook("closure-ledger", "defensive", False,
                 ["ledger-json", "proof-gate"],
                 "Check-Ergebnisse ins Ledger übernehmen; fail→pass-Übergänge als "
                 "nachweislich geschlossen belegen.",
                 tasks=["Check-Ergebnisse des Laufs einsammeln",
                        "Ledger laden und Status je Check abgleichen",
                        "fail→pass-Übergänge als Schließung mit Zeitstempeln belegen",
                        "Neu geöffnete Lücken markieren",
                        "Bilanz (offen/geschlossen) zählen"]),
        Playbook("closure-report", "defensive", False,
                 ["markdown-report"],
                 "Abschlussbericht mit offenen Tickets (nach Severity) und Fix-Vorschlägen "
                 "nach data/exports/ schreiben.",
                 tasks=["Offene Lücken nach Severity sortieren",
                        "Fix-Vorschlag je offener Lücke übernehmen",
                        "Geschlossene Lücken mit Vorher/Nachher auflisten",
                        "Markdown-Bericht schreiben (nur eigenes data/exports)"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        obs, details = [], {}
        for f in task.context_findings or []:
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            cid, st = ev.get("check_id"), ev.get("check_status")
            if cid and st in ("pass", "fail"):
                obs.append({"check_id": cid, "status": st, "severity": f.severity,
                            "title": f.title.split("] ", 1)[-1], "detail": f.description})
                details[cid] = ev
        out: list[AgentFinding] = []
        if not obs:
            self.ctx.log("[blue-ticketclose] Keine Check-Ergebnisse im Kontext – "
                         "nichts zu buchen (honest-empty).")
            return out
        res = _bc.ledger_update(obs) if self.playbook_enabled("closure-ledger") else \
            {"closed": [], "opened": [], **_bc.ledger_stats()}
        for c in res["closed"]:
            fs = c.get("failed_since")
            out.append(AgentFinding(
                agent=self.name, title=f"[TICKET GESCHLOSSEN] {c['title']}",
                category="blue-ticket-closure", severity="info", asset="localhost",
                description=("Nachweislich geschlossen: Check war zuvor FAIL"
                             + (f" (seit {time.strftime('%Y-%m-%d %H:%M', time.localtime(fs))})" if fs else "")
                             + ", jetzt PASS (Re-Check dieses Laufs)."),
                evidence={"check_id": c["check_id"], "before": "fail", "after": "pass",
                          "failed_since": fs, "closed_at": c["closed_at"]},
                status="BESTÄTIGT(PASSIV)", dedup_key=f"blue-ticket-closure:{c['check_id']}:{int(c['closed_at'])}"))
        open_rows = sorted(
            [o for o in obs if o["status"] == "fail"],
            key=lambda o: -_SEV.get(o["severity"], 0))
        report_path = ""
        if self.playbook_enabled("closure-report"):
            report_path = self._write_report(task, open_rows, details, res)
        out.append(AgentFinding(
            agent=self.name,
            title=(f"Ticket-Bilanz: {len(open_rows)} offen · {len(res['closed'])} in diesem Lauf "
                   f"geschlossen · {res['closed_total']} gesamt geschlossen"),
            category="blue-ticket-summary", severity="info", asset="localhost",
            description=("Ledger-Stand über alle Läufe. Offen: "
                         + (", ".join(o["check_id"] for o in open_rows[:10]) or "—")),
            evidence={"open": [o["check_id"] for o in open_rows],
                      "closed_this_run": [c["check_id"] for c in res["closed"]],
                      "ledger": {k: res[k] for k in ("tracked", "open_total", "pass_total", "closed_total")},
                      "report": report_path},
            status="REFERENZ", dedup_key="blue-ticket-summary"))
        self.ctx.log(f"[blue-ticketclose] Bilanz: {len(open_rows)} offen, "
                     f"{len(res['closed'])} neu geschlossen, Ledger tracked={res['tracked']}.")
        return out

    def _write_report(self, task, open_rows, details, res) -> str:
        try:
            d = Path(_config.DATA_DIR) / "exports"
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"blue_closure_{self.ctx.run_id}.md"
            L = [f"# Blue Queen – Abschlussbericht `{self.ctx.run_id}`",
                 f"_Ziel: {task.target_name} · {time.strftime('%Y-%m-%d %H:%M')}_", "",
                 f"**Offen:** {len(open_rows)} · **In diesem Lauf geschlossen:** {len(res['closed'])} · "
                 f"**Gesamt geschlossen (Ledger):** {res['closed_total']}", "",
                 "## Offene Tickets (nach Severity)"]
            for o in open_rows:
                ev = details.get(o["check_id"], {})
                L.append(f"- **[{o['severity']}] {o['title']}** (`{o['check_id']}`)")
                if ev.get("recommendation"):
                    L.append(f"  - Empfehlung: {ev['recommendation']}")
                if ev.get("fix_command"):
                    L.append(f"  - Vorschlag-Befehl: `{ev['fix_command']}`")
            if not open_rows:
                L.append("- keine")
            L += ["", "## Nachweislich geschlossen (Vorher/Nachher)"]
            for c in res["closed"]:
                L.append(f"- {c['title']} (`{c['check_id']}`): fail → pass")
            if not res["closed"]:
                L.append("- in diesem Lauf keine Statuswechsel")
            p.write_text("\n".join(L) + "\n", encoding="utf-8")
            return str(p.name)
        except Exception:
            return ""
