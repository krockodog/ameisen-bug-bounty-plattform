"""Smoke-Tests für die Blue Queen (Verteidigungs-Kolonie) – Union-Stand."""
from __future__ import annotations

import os
import tempfile
import unittest

from antbb.agents.blue import BLUE_AGENTS, BLUE_PHASES
from antbb.blue_queen import BlueQueen
from antbb.jobs import JobScheduler, VALID_KINDS
from antbb.registry import build_registry
from antbb import softwarescan, hardening, remediation, splunk, watcher, honeypot
from antbb.attack_log import AttackLog, AttackEvent
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

    def test_blue_agents_union(self):
        names = {a.name for a in BLUE_AGENTS}
        # Mindestens die 12 Live + Kern-Extras
        required = {
            "blue-swscan", "blue-hardening", "blue-defense",
            "blue-remediation", "blue-honeypot",
            "blue-patchmgmt", "blue-fwaudit", "blue-tlsposture",
            "blue-backupverify", "blue-idhygiene", "blue-logintegrity",
            "blue-vulnticket",
            "blue-watcher", "blue-attacklog", "blue-webharden",
            "blue-netdef", "blue-credhygiene", "blue-supplychain",
            "blue-incident", "blue-logging", "blue-patchverify",
        }
        self.assertTrue(required.issubset(names), f"missing={required-names}")
        self.assertGreaterEqual(len(names), 20)
        self.assertIn("watch", BLUE_PHASES)
        reg = build_registry()
        self.assertGreaterEqual(reg.get("blue_soldier_count"), 20)
        blues = [s for s in reg["soldiers"] if s.get("colony") == "blue"]
        self.assertGreaterEqual(len(blues), 20)
        for s in blues:
            self.assertTrue(s["skill"]["has_skill_md"], s["name"])
            self.assertGreaterEqual(len(s.get("playbooks") or []), 1, s["name"])

    def test_playbook_md_present(self):
        root = os.path.join(os.path.dirname(__file__), "..", "antbb", "playbooks", "blue")
        mds = [f for f in os.listdir(root) if f.endswith(".md")]
        self.assertGreaterEqual(len(mds), 25)

    def test_watcher_honest_empty(self):
        rep = watcher.run_watch([], store=self.store, run_id="t1")
        self.assertTrue(rep.summary.get("honest_empty"))
        self.assertEqual(rep.summary.get("detection_count"), 0)

    def test_watcher_detect_and_log(self):
        events = [{"source": "10.0.0.1", "path": "/x", "query": "1' OR 1=1",
                   "ts": 1.0}]
        rep = watcher.run_watch(events, store=self.store, run_id="t2")
        self.assertGreaterEqual(rep.summary["detection_count"], 1)
        self.assertGreater(len(rep.log_ids), 0)
        alog = AttackLog(self.store)
        self.assertGreater(alog.count(), 0)
        summ = alog.summary()
        self.assertTrue(summ["append_only"])
        self.assertFalse(summ["delete_api"])

    def test_honeypot_divert_deny(self):
        plan = honeypot.divert_plan({"kind": "web", "source": "x"})
        self.assertEqual(plan.status, "planned")
        denied = honeypot.divert_apply({"kind": "web"}, active=False)
        self.assertEqual(denied.status, "denied")
        applied = honeypot.divert_apply({"kind": "web"}, active=True)
        self.assertTrue(applied.applied)

    def test_softwarescan_structure(self):
        rep = softwarescan.scan(online=False)
        self.assertIsInstance(rep.packages, list)
        summ = rep.summary()
        self.assertIn("package_count", summ)
        self.assertFalse(summ["osv_used"])

    def test_hardening_audit_non_destructive(self):
        results = hardening.run_audit()
        self.assertGreaterEqual(len(results), 3)

    def test_remediation_verify_logic(self):
        results = hardening.run_audit()
        target = next((r for r in results if r.status == "fail"), None)
        if target is None:
            target = next(r for r in results if r.status == "pass")
            finding = {"category": "blue-hardening-gap", "title": target.title,
                       "dedup_key": f"blue-hardening:{target.check_id}",
                       "evidence": {"check_id": target.check_id,
                                    "recommendation": target.recommendation,
                                    "fix_command": target.fix_command}}
            step = remediation.verify_closed(finding)
            self.assertIs(step.closed, True)
        else:
            finding = {"category": "blue-hardening-gap", "title": target.title,
                       "dedup_key": f"blue-hardening:{target.check_id}",
                       "evidence": {"check_id": target.check_id,
                                    "recommendation": target.recommendation,
                                    "fix_command": target.fix_command}}
            step = remediation.verify_closed(finding)
            self.assertIs(step.closed, False)

    def test_splunk_skipped_without_config(self):
        for k in ("ANTBB_SPLUNK_HEC_URL", "ANTBB_SPLUNK_HEC_TOKEN"):
            os.environ.pop(k, None)
        st = splunk.status()
        self.assertFalse(st["configured"])
        res = splunk.send_events([{"title": "x"}])
        self.assertTrue(res["skipped"])

    def test_blue_queen_loads_and_runs(self):
        queen = BlueQueen(self.store, use_llm=False)
        result = queen.run_colony_sync(
            target_id=None, phases=("assess", "defend"),
            params={"online": False, "only_agents": ["blue-swscan", "blue-defense"]})
        self.assertTrue(result.run_id.startswith("blue-"))
        self.assertGreaterEqual(len(result.findings), 2)
        cats = {f.category for f in result.findings}
        self.assertIn("blue-detection-rule", cats)
        self.assertIn("blue-sw-inventory", cats)

    def test_job_scheduler_create_and_run(self):
        sched = JobScheduler(self.store)
        self.assertIn("swscan", VALID_KINDS)
        self.assertIn("watcher", VALID_KINDS)
        jid = sched.create("nightly-sw", "swscan", interval_sec=3600,
                           params={"online": False})
        res = sched.run_once(jid)
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(res["finding_count"], 1)


class BlueRouteSmoke(unittest.TestCase):
    def test_blue_page_and_api(self):
        os.environ.setdefault("ANTBB_NO_LLM", "1")
        from fastapi.testclient import TestClient
        from antbb.web.app import app
        client = TestClient(app)
        page = client.get("/blue")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Blue Queen", page.text)
        self.assertIn("Human Oversight", page.text)
        home = client.get("/", follow_redirects=False)
        self.assertEqual(home.status_code, 302)
        self.assertIn("/blue", home.headers.get("location", ""))
        api = client.get("/api/blue")
        self.assertEqual(api.status_code, 200)
        body = api.json()
        self.assertGreaterEqual(body.get("soldier_count") or 0, 20)
        names = {s.get("name") for s in body.get("soldiers") or []}
        self.assertIn("blue-swscan", names)
        self.assertIn("blue-hardening", names)
        self.assertTrue(body.get("blue_phases"))
        self.assertIn("watch", body.get("blue_phases") or [])


if __name__ == "__main__":
    unittest.main()
