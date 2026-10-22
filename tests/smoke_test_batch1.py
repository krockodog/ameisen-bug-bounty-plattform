#!/usr/bin/env python3
"""Smoke-Test für Batch 1: echter PoC-Generator, SSRF (OOB+In-Band), Takeover.

NUR lokal (127.0.0.1, bewusst verwundbarer Mini-Server + lokale Stubs).
Kein echter interactsh-Server nötig: der OOB-Treffer wird mit einem lokalen
Stub-Listener simuliert. Kein Zugriff auf fremde Systeme.
"""
from __future__ import annotations
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))
logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stdout)

import tools_vuln_testserver as vuln
from antbb import netutil, poc_builder
from antbb.agents.base import AgentFinding, AgentContext, Task
from antbb.agents.poc import PocAnt
from antbb.agents.takeover import TakeoverAnt
from antbb.agents import ssrf as ssrf_mod

OK = 0
N = 0


def C(name, cond):
    global OK, N
    N += 1
    mark = "✅" if cond else "❌"
    print(f"  {mark} {name}")
    if cond:
        OK += 1


def banner(t):
    print(f"\n=== {t} ===")


# --------------------------------------------------------------------------
# OOB-Stub: lokaler Listener, der angefragte Tokens (Pfad) protokolliert.
# --------------------------------------------------------------------------
class _OobRecorder(BaseHTTPRequestHandler):
    seen: set = set()

    def log_message(self, *a):
        pass

    def do_GET(self):
        tok = self.path.lstrip("/").split("?")[0].split("/")[0]
        if tok:
            _OobRecorder.seen.add(tok.lower())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


class StubOob:
    """InteractshSession-kompatibler Stub (available=True, lokaler Listener)."""

    def __init__(self, port):
        self.available = True
        self._port = port

    def payload_url(self, token, scheme="http"):
        return f"http://127.0.0.1:{self._port}/{token}"

    def poll(self):
        return set(_OobRecorder.seen)

    def close(self):
        pass


# --------------------------------------------------------------------------
# Fake-Net für den Takeover-Test (keine echten DNS-Abfragen).
# --------------------------------------------------------------------------
class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class FakeNet:
    def __init__(self, cfg, cnames, bodies):
        self.cfg = cfg
        self._cnames = cnames    # host -> cname
        self._bodies = bodies    # host -> body text
        self.blocked = []
        self.request_count = 0

    def in_scope(self, asset):
        return True

    async def resolve(self, host, rd="A"):
        if rd == "CNAME" and host in self._cnames:
            return [self._cnames[host]]
        return []

    async def http_get(self, url, **kw):
        self.request_count += 1
        from antbb.netutil import host_of
        h = host_of(url)
        if h in self._bodies:
            return _Resp(self._bodies[h])
        return _Resp("<html>nothing</html>", 404)


def make_ctx(net):
    return AgentContext(
        run_id="batch1-smoke",
        scope_check=lambda a: True,
        logger=logging.getLogger("batch1"),
        net=net,
        active=True,
    )


def main():
    PORT = 8921
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), vuln.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    OOB_PORT = 8922
    oob_srv = ThreadingHTTPServer(("127.0.0.1", OOB_PORT), _OobRecorder)
    threading.Thread(target=oob_srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    BASE = f"http://127.0.0.1:{PORT}"

    cfg = netutil.ScanConfig()
    cfg.max_rps_per_host = 50.0
    cfg.request_delay = 0.0

    # ---------------------------------------------------------------- PoC
    banner("1) Echter PoC-Generator (nicht ausgeführt)")
    verified = AgentFinding(
        agent="verify", title="Reflected XSS bestätigt (Parameter 'q')",
        category="xss-verified", severity="high", asset=BASE,
        description="unescaped reflektiert",
        evidence={"request": {"method": "GET", "url": BASE + "/", "param": "q",
                              "value": "antbbMARK9z<antbb>\"'"},
                  "reflected_unescaped": True, "context": "html-body",
                  "response_excerpt": "Suche: antbbMARK9z<antbb>"},
        status="VERIFIZIERT",
    )
    passive = AgentFinding(
        agent="infra", title="DNS-Record", category="recon-dns", severity="info",
        asset="example.test", evidence={"records": {"A": ["1.2.3.4"]}}, status="BESTÄTIGT(PASSIV)")
    ctx = make_ctx(None)
    poc_ant = PocAnt(ctx)
    task = Task(phase="analyze", target_id=1, target_name="t", assets=[BASE],
                context_findings=[verified, passive])
    poc_findings = asyncio.run(poc_ant.work(task))
    C("genau 1 PoC (nur für aktives Finding)", len(poc_findings) == 1)
    if poc_findings:
        ev = poc_findings[0].evidence
        C("PoC enthält curl-Befehl", "curl -i" in ev.get("curl", ""))
        C("PoC-curl reproduziert Parameter q", "q=" in ev.get("curl", ""))
        C("PoC hat Repro-Schritte", len(ev.get("repro_steps", [])) >= 2)
        C("PoC nicht ausgeführt (non_executing)", ev.get("non_executing") is True)
        C("PoC hat Erwartet/Beobachtet", bool(ev.get("expected")) and bool(ev.get("actual")))
    # passiv/ohne aktive Evidence → KEIN PoC
    poc_passive = asyncio.run(poc_ant.work(
        Task(phase="analyze", target_id=1, target_name="t", assets=[], context_findings=[passive])))
    C("kein PoC für passives Finding ohne aktive Evidence", len(poc_passive) == 0)

    # ---------------------------------------------------------------- SSRF in-band
    banner("2) SSRF – Param-Discovery + In-Band-Canary (ohne OOB → zu bestätigen)")
    net = netutil.NetClient(lambda a: True, cfg, logging.getLogger("net"))
    inband = asyncio.run(ssrf_mod.run_ssrf_checks(
        net, cfg, BASE, agent="verify", oob=None, log=None, params=["url"]))
    C("In-Band SSRF-Indikator gefunden", len(inband) >= 1)
    if inband:
        f = inband[0]
        C("In-Band ist 'ssrf-indicator'", f.category == "ssrf-indicator")
        C("In-Band Status ZU BESTÄTIGEN", f.status == "ZU BESTÄTIGEN")

    # ---------------------------------------------------------------- SSRF OOB
    banner("3) SSRF – OOB-Treffer via interactsh-Stub (blind SSRF → VERIFIZIERT)")
    _OobRecorder.seen = set()
    stub = StubOob(OOB_PORT)
    net2 = netutil.NetClient(lambda a: True, cfg, logging.getLogger("net"))
    oobres = asyncio.run(ssrf_mod.run_ssrf_checks(
        net2, cfg, BASE, agent="verify", oob=stub, log=None, params=["url"]))
    verified_ssrf = [f for f in oobres if f.category == "ssrf-verified"]
    C("OOB SSRF VERIFIZIERT gefunden", len(verified_ssrf) >= 1)
    if verified_ssrf:
        f = verified_ssrf[0]
        C("OOB Status VERIFIZIERT", f.status == "VERIFIZIERT")
        C("OOB trägt aktive Evidence (Request+Response)", f.has_active_evidence())
        C("OOB-Token in Evidence (kein Ziel/Secret in Domain)",
          f.evidence.get("oob_token", "").startswith("ssrf"))

    # ---------------------------------------------------------------- Takeover
    banner("4) Subdomain-Takeover-Fingerprinting (CNAME + Signatur)")
    tcfg = netutil.ScanConfig()
    tcfg.subdomain_wordlist = []  # nur explizite Assets prüfen
    GH_SIG = "<html><body>There isn't a GitHub Pages site here.</body></html>"
    fake = FakeNet(
        tcfg,
        cnames={"vuln.example.test": "myrepo.github.io",
                "maybe.example.test": "app.herokuapp.com",
                "clean.example.test": "lb.internal.example.test"},  # CNAME ohne bekannten Dienst
        bodies={"vuln.example.test": GH_SIG,
                "maybe.example.test": "<html>normal heroku app running</html>",
                "clean.example.test": "<html>welcome, real site</html>"},
    )
    tctx = make_ctx(fake)
    tant = TakeoverAnt(tctx)
    ttask = Task(phase="recon", target_id=1, target_name="t",
                 assets=["vuln.example.test", "maybe.example.test", "clean.example.test"])
    tfind = asyncio.run(tant.work(ttask))
    by_asset = {f.asset: f for f in tfind}
    C("VERIFIZIERTER Takeover bei dangling CNAME + Signatur (vuln)",
      by_asset.get("vuln.example.test") is not None
      and by_asset["vuln.example.test"].status == "VERIFIZIERT")
    C("ZU BESTÄTIGEN bei CNAME-Match ohne Signatur (maybe)",
      by_asset.get("maybe.example.test") is not None
      and by_asset["maybe.example.test"].status == "ZU BESTÄTIGEN")
    C("KEIN Takeover bei CNAME ohne bekannten Dienst (clean)",
      by_asset.get("clean.example.test") is None)
    if "vuln.example.test" in by_asset:
        C("Takeover-Evidence trägt aktive Belege",
          by_asset["vuln.example.test"].has_active_evidence())
        C("Takeover nennt den Dienst (GitHub Pages)",
          by_asset["vuln.example.test"].evidence.get("service") == "GitHub Pages")

    # ---------------------------------------------------------------- graceful degrade
    banner("5) interactsh graceful degrade (Tool nicht installiert)")
    from antbb.tools.kali import KaliAdapter
    sess = KaliAdapter(make_ctx(None)).interactsh()
    C("interactsh-Session available=False ohne Tool", sess.available is False)
    C("payload_url leer ohne Domain", sess.payload_url("tok") == "")
    C("poll() leer ohne Tool", sess.poll() == set())

    srv.shutdown()
    oob_srv.shutdown()
    print(f"\n→ {OK}/{N} Checks bestanden")
    return 0 if OK == N else 1


if __name__ == "__main__":
    sys.exit(main())
