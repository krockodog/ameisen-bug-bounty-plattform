"""Smoke-Tests für die Blue Queen (Verteidigungs-Kolonie)."""
from __future__ import annotations

import os
import tempfile
import unittest

from antbb.agents.blue import BLUE_AGENTS, BLUE_PHASES
from antbb.blue_queen import BlueQueen
from antbb.jobs import JobScheduler, VALID_KINDS
from antbb.registry import build_registry
from antbb import softwarescan, hardening, remediation, splunk
from antbb.store import Store


class BlueQueenSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)

    def tearDown(self):
        self.store.close()
        try:
            os.unlink(self.tmp.name)
        except Exception:
            pass

    def test_blue_agents_registered(self):
        names = {a.name for a in BLUE_AGENTS}
        self.assertEqual(names, {
            "blue-swscan", "blue-hardening", "blue-defense",
            "blue-remediation", "blue-honeypot",
        })
        self.assertEqual(BLUE_PHASES,
                         ("assess", "harden", "defend", "remediate", "verify"))
        reg = build_registry()
        self.assertEqual(reg.get("blue_soldier_count"), 5)
        blues = [s for s in reg["soldiers"] if s.get("colony") == "blue"]
        self.assertEqual(len(blues), 5)
        for s in blues:
            self.assertTrue(s["skill"]["has_skill_md"], s["name"])

    def test_softwarescan_structure(self):
        # Offline (kein Netz nötig) – nur Inventar.
        rep = softwarescan.scan(online=False)
        self.assertIsInstance(rep.packages, list)
        self.assertGreaterEqual(len(rep.packages), 0)
        summ = rep.summary()
        self.assertIn("package_count", summ)
        self.assertIn("vuln_count", summ)
        self.assertFalse(summ["osv_used"])

    def test_hardening_audit_non_destructive(self):
        results = hardening.run_audit()
        self.assertGreaterEqual(len(results), 3)
        for r in results:
            self.assertIn(r.status, ("pass", "fail", "info"))
            self.assertTrue(r.check_id)

    def test_remediation_verify_logic(self):
        # Simuliertes Hardening-Finding (fail) – Re-Check muss echten Status liefern.
        # Wir nehmen einen Check, der auf diesem System "info" oder "pass"/"fail" ist.
        results = hardening.run_audit()
        target = next((r for r in results if r.status == "fail"), None)
        if target is None:
            # Kein fail → prüfe pass-Pfad: closed muss True sein.
            target = next(r for r in results if r.status == "pass")
            finding = {"category": "blue-hardening-gap",
                       "title": target.title,
                       "dedup_key": f"blue-hardening:{target.check_id}",
                       "evidence": {"check_id": target.check_id,
                                    "recommendation": target.recommendation,
                                    "fix_command": target.fix_command}}
            step = remediation.verify_closed(finding)
            self.assertIs(step.closed, True)
        else:
            finding = {"category": "blue-hardening-gap",
                       "title": target.title,
                       "dedup_key": f"blue-hardening:{target.check_id}",
                       "evidence": {"check_id": target.check_id,
                                    "recommendation": target.recommendation,
                                    "fix_command": target.fix_command}}
            step = remediation.verify_closed(finding)
            self.assertIs(step.closed, False)
            self.assertEqual(step.evidence.get("after"), "fail")

    def test_splunk_skipped_without_config(self):
        # Sicherstellen, dass keine ENV gesetzt ist.
        for k in ("ANTBB_SPLUNK_HEC_URL", "ANTBB_SPLUNK_HEC_TOKEN"):
            os.environ.pop(k, None)
        st = splunk.status()
        self.assertFalse(st["configured"])
        res = splunk.send_events([{"title": "x"}])
        self.assertTrue(res["skipped"])
        self.assertTrue(res["ok"])

    def test_blue_queen_loads_and_runs(self):
        queen = BlueQueen(self.store, use_llm=False)
        # Nur assess+defend, online=False → schnell, offline.
        result = queen.run_colony_sync(
            target_id=None, phases=("assess", "defend"),
            params={"online": False, "only_agents": ["blue-swscan", "blue-defense"]})
        self.assertTrue(result.run_id.startswith("blue-"))
        self.assertGreaterEqual(len(result.findings), 2)  # inventar + detection rules
        # Defense liefert Detection-Regeln
        cats = {f.category for f in result.findings}
        self.assertIn("blue-detection-rule", cats)
        self.assertIn("blue-sw-inventory", cats)

    def test_job_scheduler_create_and_run(self):
        sched = JobScheduler(self.store)
        self.assertEqual(VALID_KINDS, {"swscan", "hardening", "remediate", "colony"})
        jid = sched.create("nightly-sw", "swscan", interval_sec=3600,
                           params={"online": False})
        self.assertGreater(jid, 0)
        res = sched.run_once(jid)
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(res["finding_count"], 1)
        runs = sched.runs(jid)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "done")


if __name__ == "__main__":
    unittest.main()
