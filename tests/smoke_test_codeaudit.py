#!/usr/bin/env python3
"""Smoke-Test für den codeaudit-Soldaten (statische Quell-Review, read-only).

Prüft reine Logik OHNE Netz/Tools: synthetische Quelltexte in einen temporären
Baum schreiben, den Soldaten darauf laufen lassen und Proof-Gate-Verdicts +
Secret-Maskierung verifizieren. Honest-empty ohne code_path.
"""
from __future__ import annotations
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stdout)

from antbb import codeaudit as ca
from antbb.agents.base import AgentContext, Task
from antbb.agents.codeaudit import CodeAuditAnt
from antbb.registry import build_registry

OK = 0
N = 0


def C(name, cond):
    global OK, N
    N += 1
    print(f"  {'✅' if cond else '❌'} {name}")
    if cond:
        OK += 1


def banner(t):
    print(f"\n=== {t} ===")


def make_ctx():
    return AgentContext(
        run_id="codeaudit-smoke",
        scope_check=lambda a: True,
        logger=logging.getLogger("codeaudit"),
    )


# Synthetische Quelldateien (bewusst "verwundbar", nur lokal, nie ausgeführt).
VULN_PY = '''
import os, subprocess, pickle, yaml, hashlib

API_KEY = "sk_live_ABCDEFGH12345678ZZ"
password = "SuperGeheim123!"
AWS = "AKIAIOSFODNN7EXAMPLE"
placeholder_token = "your_token_here"
env_secret = os.environ["SECRET"]

def run(cmd_from_user):
    os.system("ls " + cmd_from_user)          # command-injection (variabel)
    subprocess.run(user_input, shell=True)     # command-injection (variabel)
    eval("1 + 1")                              # eval konstant -> Härtung
    eval(request.args["x"])                    # code-injection (variabel)

def q(uid):
    return "SELECT * FROM users WHERE id = " + uid   # sql-injection

def load(blob):
    return pickle.loads(blob)                  # unsichere Deserialisierung

def weak(p):
    return hashlib.md5(p).hexdigest()          # schwache Krypto (Härtung)
'''


def main():
    # ---------------------------------------------------------------- pure engine
    banner("1) Pure Engine (scan_source_text)")
    cands = ca.scan_source_text("vuln.py", VULN_PY)
    kinds = [c.kind for c in cands]
    C("hardcoded-secret erkannt", "hardcoded-secret" in kinds)
    C("command-injection erkannt", "command-injection" in kinds)
    C("code-injection erkannt", "code-injection" in kinds)
    C("sql-injection erkannt", "sql-injection" in kinds)
    C("insecure-deserialization erkannt", "insecure-deserialization" in kinds)
    C("weak-crypto erkannt", "weak-crypto" in kinds)

    secrets = [c for c in cands if c.kind == "hardcoded-secret"]
    C("AWS-Token-Format erkannt",
      any(c.evidence.get("token_type") == "AWS Access Key" for c in secrets))
    C("Platzhalter 'your_token_here' NICHT als Secret gemeldet",
      not any("your_token" in (c.evidence.get("masked_value", "") or c.snippet) for c in secrets))
    C("Env-Referenz (os.environ) NICHT als Secret gemeldet",
      not any("environ" in c.snippet for c in secrets))
    C("Secret-Wert maskiert (kein Klartext 'SuperGeheim123!')",
      all("SuperGeheim123!" not in str(c.evidence) and "SuperGeheim123!" not in c.snippet
          for c in cands))
    C("Secret-Wert maskiert (kein Klartext 'sk_live_ABCDEFGH12345678ZZ')",
      all("sk_live_ABCDEFGH12345678ZZ" not in str(c.evidence) and
          "sk_live_ABCDEFGH12345678ZZ" not in c.snippet for c in cands))

    # Verdict-Logik
    evals = [c for c in cands if c.kind == "code-injection"]
    const_evals = [c for c in cands if c.kind == "code-injection" and c.verdict == "hardening"]
    # eval("1 + 1") ist code-injection? Nein: eval ist 'code-injection' sink.
    C("eval(konstant) -> hardening (Defense-in-Depth, keine Schwachstelle)",
      any(c.verdict == "hardening" for c in cands if "eval" in c.snippet and "1 + 1" in c.snippet))
    C("eval(variabel) -> needs_validation",
      any(c.verdict == "needs_validation" for c in evals))
    C("sql-injection -> needs_validation (keine Severity)",
      all(c.verdict == "needs_validation" for c in cands if c.kind == "sql-injection"))
    C("hardcoded-secret -> passive (wörtlich belegt)",
      all(c.verdict == "passive" for c in secrets))

    # Status/Severity-Mapping
    C("passive -> BESTÄTIGT(PASSIV)", ca.verdict_to_status("passive") == "BESTÄTIGT(PASSIV)")
    C("needs_validation -> ZU BESTÄTIGEN", ca.verdict_to_status("needs_validation") == "ZU BESTÄTIGEN")
    C("hardening -> REFERENZ", ca.verdict_to_status("hardening") == "REFERENZ")
    C("needs_validation hat KEINE Severity (info)",
      ca.verdict_to_severity("sql-injection", "needs_validation") == "info")
    C("hardcoded-secret passive -> high", ca.verdict_to_severity("hardcoded-secret", "passive") == "high")

    # ---------------------------------------------------------------- soldier run
    banner("2) Soldat auf temporärem Quellbaum (read-only)")
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "vuln.py"), "w", encoding="utf-8") as fh:
            fh.write(VULN_PY)
        os.makedirs(os.path.join(td, ".git"), exist_ok=True)
        with open(os.path.join(td, ".git", "ignored.py"), "w", encoding="utf-8") as fh:
            fh.write('API_KEY = "sk_live_SHOULDNOTappear9999"\n')

        ant = CodeAuditAnt(make_ctx())
        task = Task(phase="analyze", target_id=1, target_name="repo",
                    params={"code_path": td})
        findings = asyncio.run(ant.work(task))
        cats = {f.category for f in findings}
        C("Findings erzeugt", len(findings) >= 5)
        C("Coverage-Finding vorhanden", "codeaudit-coverage" in cats)
        cov = [f for f in findings if f.category == "codeaudit-coverage"][0]
        C("Coverage zählt genau 1 Datei (.git übersprungen)",
          cov.evidence.get("files_reviewed") == 1)
        C(".git-Inhalt NICHT gescannt (kein SHOULDNOTappear)",
          all("SHOULDNOTappear" not in str(f.evidence) for f in findings))
        C("Secret-Finding hat Datei:Zeile-Evidence",
          any(f.category == "hardcoded-secret" and f.evidence.get("line") for f in findings))
        C("dedup_key stabil (codeaudit:)", all(f.dedup_key.startswith("codeaudit") for f in findings))

    # ---------------------------------------------------------------- honest empty
    banner("3) Honest-empty ohne code_path / fehlender Pfad")
    ant2 = CodeAuditAnt(make_ctx())
    empty = asyncio.run(ant2.work(Task(phase="analyze", target_id=1, target_name="x")))
    C("ohne code_path: keine Findings", empty == [])
    missing = asyncio.run(ant2.work(Task(phase="analyze", target_id=1, target_name="x",
                                         params={"code_path": "/nonexistent/path/xyz"})))
    C("fehlender Pfad: keine Findings", missing == [])

    # ---------------------------------------------------------------- registry
    banner("4) Registry/Skill-Anbindung")
    reg = build_registry()
    sold = {s["name"]: s for s in reg["soldiers"]}
    C("codeaudit im Schwarm registriert", "codeaudit" in sold)
    if "codeaudit" in sold:
        ca_s = sold["codeaudit"]
        C("SKILL.md geladen", ca_s["skill"]["has_skill_md"])
        pbs = ca_s["skill"]["playbooks"]
        C("beide Playbooks registriert",
          "source-credential-scan" in pbs and "source-injection-review" in pbs)
        C("Playbooks haben Task-Items", ca_s["skill"]["task_count"] >= 10)

    print(f"\n→ {OK}/{N} Checks bestanden")
    return 0 if OK == N else 1


if __name__ == "__main__":
    sys.exit(main())
