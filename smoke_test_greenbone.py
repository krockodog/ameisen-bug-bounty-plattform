"""Smoke-Tests: Greenbone/OpenVAS-Integration der Blue Queen.

Offline, ohne GVM: Fixtures nutzen nur 192.0.2.x / example.com. Der aktive Pfad
wird gegen einen Fake-Transport bzw. ein Fake-`gvm-cli` geprüft.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from antbb import config as cfg
from antbb import greenbone as gb
from antbb.agents.blue import BLUE_AGENTS
from antbb.blue_queen import BlueQueen
from antbb.registry import build_registry
from antbb.store import Store
import antbb.web.app as app_mod  # vor dem DATA_DIR-Patch importieren
from antbb.service import AntBBService

FIX = Path(__file__).parent / "tests" / "fixtures"
XML = FIX / "greenbone_sample.xml"


class _Env:
    """Isoliert DATA_DIR + GVM-Umgebung pro Test."""
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = cfg.DATA_DIR
        cfg.DATA_DIR = Path(self._tmp.name)
        self._env = {k: os.environ.pop(k, None)
                     for k in ("GVM_SOCKET", "GVM_USERNAME", "GVM_PASSWORD")}
        self._orig = (gb.find_socket, gb._which, gb._python_gvm_version, gb._make_transport,
                      gb.MIN_SCAN_INTERVAL, gb._LAST_SCAN_START)
        gb.find_socket = lambda: ""
        gb._which = lambda n: ""
        gb._python_gvm_version = lambda: ""

    def tearDown(self):
        (gb.find_socket, gb._which, gb._python_gvm_version, gb._make_transport,
         gb.MIN_SCAN_INTERVAL, gb._LAST_SCAN_START) = self._orig
        cfg.DATA_DIR = self._old
        for k, v in self._env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        self._tmp.cleanup()

    def drop(self, src: Path = XML) -> Path:
        d = gb.drop_dir(create=True)
        dest = d / src.name
        dest.write_bytes(src.read_bytes())
        return dest


class ParserTests(_Env, unittest.TestCase):
    def test_xml_fixture_fields_and_cves(self):
        rep = gb.parse_report_file(XML)
        self.assertEqual(rep.fmt, "greenbone-xml")
        self.assertEqual(len(rep.results), 4)
        self.assertEqual(rep.log_level_skipped, 1)       # Log-Level ≠ Befund
        self.assertEqual(rep.duplicates_skipped, 1)      # r-0003 = Duplikat von r-0002
        top = rep.results[0]
        self.assertEqual((top.host, top.port, top.severity, top.cvss, top.qod),
                         ("192.0.2.1", "443/tcp", "critical", 9.8, 80))
        self.assertEqual(top.cves, ["CVE-2099-0001", "CVE-2099-0002"])
        self.assertEqual(top.solution_type, "VendorFix")
        ssh = rep.results[1]
        self.assertEqual(ssh.cves, ["CVE-2099-0003"])     # <cve>-Element (Altformat)
        self.assertEqual(rep.results[3].port, "")          # general/tcp → kein Port
        self.assertEqual(rep.counts(), {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0})
        self.assertEqual(rep.meta["task_name"], "antbb-fixture-scan")

    def test_json_and_csv(self):
        j = gb.parse_report_file(FIX / "greenbone_sample.json")
        self.assertEqual((j.fmt, len(j.results)), ("greenbone-json", 1))
        self.assertEqual(j.results[0].cves, ["CVE-2099-0010"])
        self.assertEqual(j.results[0].severity, "high")
        c = gb.parse_report_file(FIX / "greenbone_sample.csv")
        self.assertEqual((c.fmt, len(c.results)), ("greenbone-csv", 1))
        self.assertEqual((c.results[0].asset, c.results[0].severity), ("192.0.2.4:25", "medium"))

    def test_rejects_garbage_and_entities(self):
        with self.assertRaises(gb.GvmError):
            gb.parse_report("kein report")
        with self.assertRaises(gb.GvmError):
            gb.parse_report('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><report/>')
        with self.assertRaises(gb.GvmError):
            gb.parse_report("{not json")

    def test_findings_are_reference_with_cve_and_no_secret(self):
        fs = gb.to_findings(gb.parse_report_file(XML))
        self.assertEqual(len(fs), 4)
        self.assertTrue(all(f.status == "REFERENZ" and f.category == "blue-greenbone-vuln" for f in fs))
        crit = fs[0]
        self.assertEqual(crit.severity, "critical")
        self.assertIn("CVE-2099-0001", crit.title)
        self.assertEqual(crit.evidence["cves"], ["CVE-2099-0001", "CVE-2099-0002"])
        blob = json.dumps([(f.description, f.evidence) for f in fs])
        self.assertNotIn("hunter2", blob)                  # Zugangsdaten maskiert
        from antbb import proofgate
        proofgate.enforce(fs, None)
        self.assertTrue(all(f.status == "REFERENZ" for f in fs))   # Proof-Gate stuft nicht hoch

    def test_remediation_hints_only_high_critical_and_honest(self):
        hints = gb.remediation_hints(gb.parse_report_file(XML).results)
        self.assertEqual([h["severity"] for h in hints], ["critical", "high"])
        self.assertEqual(hints[0]["route_to"], "blue-patchmgmt")
        self.assertEqual(hints[1]["route_to"], "blue-hardening")
        self.assertTrue(all(not h["fix_known"] or h["solution"] != "keine Lösung im Report" for h in hints))
        fs = gb.hint_findings(hints)
        self.assertTrue(all(f.evidence["auto_fix"] is False for f in fs))
        self.assertEqual(gb.remediation_hints([]), [])


class StatusAndPathTests(_Env, unittest.TestCase):
    def test_status_without_gvm_is_honest_and_does_not_crash(self):
        st = gb.status()
        self.assertFalse(st["available"])
        self.assertTrue(st["import_available"])
        self.assertIn("Greenbone nicht verfügbar", st["error"])
        self.assertNotIn("GVM_PASSWORD", json.dumps(st))

    def test_status_never_leaks_credentials(self):
        os.environ["GVM_USERNAME"], os.environ["GVM_PASSWORD"] = "scanuser", "s3cr3t-pw"
        st = gb.status(probe=False)
        self.assertTrue(st["credentials_configured"])
        blob = json.dumps(st)
        self.assertNotIn("s3cr3t-pw", blob)
        self.assertNotIn("scanuser", blob)

    def test_import_path_is_confined_to_drop_dir(self):
        self.drop()
        self.assertEqual(gb.resolve_report_path("greenbone_sample.xml").name, "greenbone_sample.xml")
        for bad in ("/etc/passwd", "../../../etc/passwd", "nope.xml"):
            with self.assertRaises(gb.GvmError):
                gb.resolve_report_path(bad)
        outside = Path(self._tmp.name) / "outside.xml"
        outside.write_text("<a/>")
        with self.assertRaises(gb.GvmError):
            gb.resolve_report_path(str(outside))

    def test_import_empty_dir_is_honest_empty(self):
        res = gb.import_report("")
        self.assertFalse(res["ok"])
        self.assertTrue(res["empty"])
        self.assertEqual(res["findings"], [])


class SoldierTests(_Env, unittest.TestCase):
    def test_registered_with_four_playbooks_skill_and_mds(self):
        names = {a.name for a in BLUE_AGENTS}
        self.assertIn("blue-greenbone", names)
        cls = next(a for a in BLUE_AGENTS if a.name == "blue-greenbone")
        self.assertEqual([p.name for p in cls.playbooks],
                         ["gb-status", "gb-import-report", "gb-scoped-scan", "gb-to-hardening"])
        scan = next(p for p in cls.playbooks if p.name == "gb-scoped-scan")
        self.assertTrue(scan.oversight_required and scan.mode == "offensive")
        self.assertTrue(all(not p.oversight_required for p in cls.playbooks if p.name != "gb-scoped-scan"))
        self.assertIn("assess", cls.blue_phases)
        reg = build_registry()
        sol = next(s for s in reg["soldiers"] if s["name"] == "blue-greenbone")
        self.assertEqual(len(sol["playbooks"]), 4)           # nichts vom Registry-Scrub entfernt
        self.assertTrue(sol["skill"]["has_skill_md"])
        pbdir = Path(gb.__file__).parent / "playbooks" / "blue"
        ids = {p.stem for p in pbdir.glob("pb-greenbone-*.md")}
        self.assertEqual(ids, {"pb-greenbone-status", "pb-greenbone-import",
                               "pb-greenbone-scan", "pb-greenbone-hardening"})

    def test_kali_tool_specs_list_gvm_cli_as_offensive(self):
        from antbb.tools import kali
        self.assertTrue(kali.TOOL_SPECS["gvm-cli"]["offensive"])
        self.assertFalse(kali.TOOL_SPECS["gvmd"]["offensive"])

    def _run(self, **params):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False); tmp.close()
        store = Store(tmp.name)
        try:
            q = BlueQueen(store, use_llm=False)
            return q.run_colony_sync(target_id=None, phases=("assess", "remediate"),
                                     params={"only_agents": ["blue-greenbone"], **params})
        finally:
            store.close(); os.unlink(tmp.name)

    def test_colony_imports_fixture_findings_and_tickets(self):
        self.drop()
        res = self._run()
        cats = {f.category for f in res.findings}
        self.assertTrue({"blue-greenbone-status", "blue-greenbone-summary",
                         "blue-greenbone-vuln", "blue-greenbone-remediation"} <= cats)
        vulns = [f for f in res.findings if f.category == "blue-greenbone-vuln"]
        self.assertEqual(len(vulns), 4)
        self.assertIn("CVE-2099-0001", {c for f in vulns for c in f.evidence["cves"]})
        self.assertTrue(all(f.status == "REFERENZ" for f in res.findings))
        tickets = [f for f in res.findings if f.category == "blue-greenbone-remediation"]
        self.assertEqual(len(tickets), 2)
        self.assertTrue(any("Greenbone nicht verfügbar" in f.title for f in res.findings))

    def test_colony_without_report_invents_nothing(self):
        res = self._run()
        self.assertFalse([f for f in res.findings if f.category == "blue-greenbone-vuln"])
        self.assertTrue(any(f.title == "Kein Greenbone-Report importiert" for f in res.findings))

    def test_playbook_override_disables_import(self):
        self.drop()
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False); tmp.close()
        store = Store(tmp.name)
        try:
            store.set_soldier_override("blue-greenbone", "gb-import-report", "enabled", "false")
            res = BlueQueen(store, use_llm=False).run_colony_sync(
                target_id=None, phases=("assess",), params={"only_agents": ["blue-greenbone"]})
            self.assertFalse([f for f in res.findings if f.category == "blue-greenbone-vuln"])
        finally:
            store.close(); os.unlink(tmp.name)

    def test_scan_param_without_oversight_is_not_started(self):
        called = []
        gb._make_transport = lambda *a, **k: called.append(1)
        res = self._run(gvm_scan_target="192.0.2.1")
        self.assertFalse(called)
        scan = [f for f in res.findings if f.category == "blue-greenbone-scan"]
        self.assertEqual(len(scan), 1)
        self.assertFalse(scan[0].evidence["started"])


class _FakeGvm:
    """Minimaler gvmd-Ersatz für den Scan-Pfad."""
    def __init__(self, running=False):
        self.cmds, self.running = [], running

    def send(self, xml):
        self.cmds.append(xml)
        tag = ET.fromstring(xml).tag
        body = {
            "get_version": '<get_version_response status="200"><version>22.5</version></get_version_response>',
            "get_feeds": '<get_feeds_response status="200"><feed><type>NVT</type><version>%s</version></feed></get_feeds_response>' % __import__("time").strftime("%Y%m%d%H%M"),
            "get_tasks": ('<get_tasks_response status="200"><task id="t0"><status>Running</status></task></get_tasks_response>'
                          if self.running else '<get_tasks_response status="200"/>'),
            "get_configs": '<get_configs_response status="200"><config id="c1"><name>Full and fast</name></config></get_configs_response>',
            "get_port_lists": '<r status="200"><port_list id="p1"><name>All IANA assigned TCP</name></port_list></r>',
            "get_scanners": '<r status="200"><scanner id="s1"><name>OpenVAS Default</name></scanner></r>',
            "create_target": '<create_target_response status="201" id="tg1"/>',
            "create_task": '<create_task_response status="201" id="aaaaaaaa-1111"/>',
            "start_task": '<start_task_response status="202"><report_id>bbbbbbbb-2222</report_id></start_task_response>',
        }[tag]
        return ET.fromstring(body)


class ScanGateTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        gb.MIN_SCAN_INTERVAL = 0
        gb._LAST_SCAN_START = 0.0
        self.in_scope = lambda h: h == "192.0.2.1"

    def go(self, host="192.0.2.1", ack=True, scope=None, **kw):
        return gb.start_scan(host, scope_check=scope or self.in_scope, acknowledged=ack, **kw)

    def test_oversight_is_mandatory(self):
        for ack in (False, None, "true", 1):
            self.assertEqual(self.go(ack=ack)["reason"], "oversight")

    def test_single_in_scope_host_only(self):
        for bad in ("192.0.2.0/24", "192.0.2.1,192.0.2.2", "192.0.2.1 192.0.2.2", "*.example.com", ""):
            self.assertEqual(self.go(host=bad)["reason"], "target", bad)
        self.assertEqual(self.go(host="192.0.2.9")["reason"], "scope")     # default-deny
        self.assertEqual(self.go(scope=lambda h: 1 / 0)["reason"], "scope")  # Fehler = deny

    def test_config_allowlist(self):
        self.assertEqual(self.go(scan_config="Full and very deep ultimate")["reason"], "config")

    def test_no_gvm_is_honest_error(self):
        res = self.go()
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "unavailable")
        self.assertIn("Greenbone nicht verfügbar", res["error"])

    def test_missing_credentials(self):
        gb.find_socket = lambda: "/run/gvmd/gvmd.sock"
        gb._which = lambda n: "/usr/bin/" + n
        self.assertEqual(self.go()["reason"], "credentials")

    def _ready(self, fake):
        os.environ["GVM_USERNAME"], os.environ["GVM_PASSWORD"] = "u", "p"
        gb.find_socket = lambda: "/run/gvmd/gvmd.sock"
        gb._which = lambda n: "/usr/bin/" + n
        gb._make_transport = lambda *a, **k: fake

    def test_happy_path_starts_exactly_one_scan(self):
        fake = _FakeGvm(); self._ready(fake)
        res = self.go()
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["task_id"], res["report_id"]), ("aaaaaaaa-1111", "bbbbbbbb-2222"))
        tags = [ET.fromstring(c).tag for c in fake.cmds]
        self.assertEqual(tags.count("start_task"), 1)
        tgt = next(c for c in fake.cmds if c.startswith("<create_target"))
        self.assertIn("<hosts>192.0.2.1</hosts>", tgt)

    def test_parallel_scan_and_rate_limit_blocked(self):
        self._ready(_FakeGvm(running=True))
        self.assertEqual(self.go()["reason"], "busy")
        self._ready(_FakeGvm())
        gb.MIN_SCAN_INTERVAL = 3600
        self.assertTrue(self.go()["ok"])
        self.assertEqual(self.go()["reason"], "rate_limit")

    def test_status_with_fake_gvm(self):
        os.environ["GVM_USERNAME"], os.environ["GVM_PASSWORD"] = "u", "p"
        gb.find_socket = lambda: "/run/gvmd/gvmd.sock"
        gb._which = lambda n: "/usr/bin/" + n
        gb._make_transport = lambda *a, **k: _FakeGvm()
        st = gb.status()
        self.assertTrue(st["available"] and st["reachable"] and st["can_scan"])
        self.assertEqual(st["version"], "22.5")
        self.assertTrue(st["feed_ok"])


class CliBackendTests(_Env, unittest.TestCase):
    """gvm-cli-Fallback gegen ein Fake-Binary: Zugangsdaten nie in argv."""
    def test_credentials_via_temp_config_not_argv(self):
        d = Path(self._tmp.name)
        log = d / "calls.log"
        cfgcopy = d / "cfg.copy"
        cli = d / "gvm-cli"
        cli.write_text(
            "#!/bin/bash\n"
            f"echo \"$@\" >> {log}\n"
            "while [ $# -gt 0 ]; do if [ \"$1\" = --config ]; then "
            f"cp \"$2\" {cfgcopy}; stat -c %a \"$2\" > {d}/mode; fi; shift; done\n"
            "echo '<get_tasks_response status=\"200\"/>'\n")
        cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
        gb._which = lambda n: str(cli)
        os.environ["GVM_USERNAME"], os.environ["GVM_PASSWORD"] = "scanuser", "s3cr3t-pw"
        t = gb._Transport("/run/gvmd/gvmd.sock", timeout=5)
        root = t.send("<get_tasks/>")
        self.assertEqual(root.get("status"), "200")
        self.assertNotIn("s3cr3t-pw", log.read_text())
        self.assertNotIn("scanuser", log.read_text())
        self.assertIn("password=s3cr3t-pw", cfgcopy.read_text())
        self.assertEqual((d / "mode").read_text().strip(), "600")
        # get_version läuft ohne Zugangsdaten
        log.write_text(""); t.send("<get_version/>")
        self.assertNotIn("--config", log.read_text())

    def test_error_status_becomes_gvm_error(self):
        d = Path(self._tmp.name)
        cli = d / "gvm-cli"
        cli.write_text("#!/bin/bash\necho '<x status=\"400\" status_text=\"Failed to authenticate\"/>'\n")
        cli.chmod(0o755)
        gb._which = lambda n: str(cli)
        with self.assertRaises(gb.GvmError):
            gb._Transport("/s", timeout=5).send("<get_tasks/>")


class ApiTests(_Env, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        self._db = tempfile.NamedTemporaryFile(suffix=".db", delete=False); self._db.close()
        self.app_mod, self._svc = app_mod, app_mod.svc
        app_mod.svc = AntBBService(self._db.name)
        self.client = TestClient(app_mod.app)
        self.tid = app_mod.svc.add_target("gb-test", "")
        app_mod.svc.add_scope(self.tid, "ip", "192.0.2.1")

    def tearDown(self):
        self.app_mod.svc.close()
        self.app_mod.svc = self._svc
        os.unlink(self._db.name)
        super().tearDown()

    def test_blue_page_and_status_endpoint(self):
        r = self.client.get("/blue")
        self.assertEqual(r.status_code, 200)
        self.assertIn('id="blue-greenbone"', r.text)
        self.assertIn("Greenbone nicht verfügbar", r.text)
        self.assertNotIn("Brain", r.text.split('id="blue-greenbone"')[1].split("</section>")[0])
        s = self.client.get("/api/blue/greenbone/status")
        self.assertEqual(s.status_code, 200)
        self.assertFalse(s.json()["available"])
        self.assertEqual(self.client.get("/brain").status_code, 200)

    def test_import_upload_with_scope_filter_persists(self):
        with open(XML, "rb") as fh:
            r = self.client.post("/api/blue/greenbone/import",
                                 files={"file": ("report.xml", fh, "text/xml")},
                                 data={"target_id": str(self.tid)})
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        # Nur 192.0.2.1 ist in-scope → 2 Funde; 192.0.2.2 wird verworfen
        self.assertEqual(len(d["findings"]), 2)
        self.assertEqual(d["out_of_scope_skipped"], 2)
        self.assertIn("CVE-2099-0001", d["findings"][0]["cves"])
        self.assertGreaterEqual(d["persisted"], 3)
        self.assertEqual(len(d["hints"]), 2)
        self.assertTrue(list(gb.drop_dir().glob("*report.xml")))

    def test_import_json_path_and_traversal(self):
        self.drop()
        ok = self.client.post("/api/blue/greenbone/import", json={"path": "greenbone_sample.xml"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["summary"]["result_count"], 4)   # ohne Target: reine Analyse
        bad = self.client.post("/api/blue/greenbone/import", json={"path": "/etc/passwd"})
        self.assertEqual(bad.status_code, 400)
        empty_dir_missing = self.client.post("/api/blue/greenbone/import",
                                             json={"path": "../../etc/hosts"})
        self.assertEqual(empty_dir_missing.status_code, 400)

    def test_import_nothing_available_is_404_honest(self):
        r = self.client.post("/api/blue/greenbone/import", json={})
        self.assertEqual(r.status_code, 404)
        self.assertIn("Kein Greenbone-Report", r.json()["error"])

    def test_scan_requires_oversight_scope_and_gvm(self):
        url = "/api/blue/greenbone/scan"
        self.assertEqual(self.client.post(url, json={"host": "192.0.2.1"}).status_code, 400)  # kein Target
        self.assertEqual(self.client.post(url, json={"target_id": self.tid, "host": "192.0.2.1"}).status_code, 403)
        self.assertEqual(self.client.post(url, json={"target_id": self.tid, "host": "192.0.2.77",
                                                     "oversight_ack": True}).status_code, 403)
        r = self.client.post(url, json={"target_id": self.tid, "host": "192.0.2.1", "oversight_ack": True})
        self.assertEqual(r.status_code, 503)                       # GVM fehlt → ehrlich
        self.assertIn("Greenbone nicht verfügbar", r.json()["error"])
        self.assertEqual(self.client.post(url, json={"target_id": 9999, "host": "192.0.2.1",
                                                     "oversight_ack": True}).status_code, 400)

    def test_job_kind_greenbone(self):
        from antbb.jobs import VALID_KINDS, JobScheduler
        self.assertIn("greenbone", VALID_KINDS)
        self.drop()
        sched = JobScheduler(self.app_mod.svc.store)
        jid = sched.create("gb-nightly", "greenbone", interval_sec=3600)
        res = sched.run_once(jid)
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(res["finding_count"], 5)


if __name__ == "__main__":
    unittest.main()
