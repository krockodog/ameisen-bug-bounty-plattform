"""CodeAudit-Ameise: statische Quellcode-Sicherheitsprüfung (read-only).

Integriert die Methodik des Cloudflare *security-audit-skill* als antbb-Soldat.
Begeht einen EXPLIZIT übergebenen, autorisierten lokalen Quellbaum und meldet
find-and-prove-Kandidaten mit konkreter Quell-Stelle (Datei:Zeile + Ausschnitt).

Harte Leitplanken (deckungsgleich mit der Plattform-Posture):
  * Rein lesend. NICHTS wird ausgeführt, verändert, gelöscht oder exfiltriert.
  * Kein Netzwerk, keine externen Tools nötig (honest-empty ohne Quellpfad).
  * Der Quellpfad kommt NUR aus task.params['code_path'] (operator-/oversight-
    getrieben). Es wird KEIN Scope/Target in irgendeine Allowlist aufgenommen.
  * Secrets werden IMMER maskiert (nie Klartext in Finding/Evidence/Log).
  * Severity nur bei echtem Impact: wörtlich belegtes Secret = real exponiert
    (BESTÄTIGT(PASSIV)); Injection-Sinks mit variabler Eingabe = ZU BESTÄTIGEN
    (keine Severity); reine Best-Practice-/Defense-in-Depth-Lücken = REFERENZ
    (Härtungshinweis, keine Schwachstelle).
"""
from __future__ import annotations

import os

from .base import AntAgent, AgentFinding, Task, Playbook
from .. import codeaudit as _ca


class CodeAuditAnt(AntAgent):
    name = "codeaudit"
    role = ("Statische Quellcode-Sicherheitsprüfung (read-only, find-and-prove): "
            "hardcodierte Secrets, Injection-/Deserialisierungs-Sinks, schwache "
            "Krypto – Methodik des Cloudflare security-audit-skill")
    specialty = "codeaudit-hunter"
    phases = ("analyze",)
    playbooks = (
        Playbook("source-credential-scan", "defensive", False,
                 ["literal-credential-scan", "known-key-formats", "value-masking"],
                 "Hardcodierte Zugangsdaten/Schlüssel im autorisierten Quellbaum "
                 "erkennen (rein lesend, Werte IMMER maskiert)."),
        Playbook("source-injection-review", "defensive", False,
                 ["sink-review", "sql-concat-review", "deserialization-review",
                  "weak-crypto-review", "coverage-ledger"],
                 "Statische Review gefährlicher Sinks (eval/exec/shell/SQL/"
                 "Deserialisierung) mit Datei:Zeile-Nachweis; Taint-Pfad bleibt "
                 "bleibt zu bestätigen, Defense-in-Depth-Lücken nur als Härtungshinweis."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        code_path = ""
        params = task.params or {}
        for k in ("code_path", "audit_path", "source_path", "repo_path"):
            if params.get(k):
                code_path = str(params[k])
                break
        if not code_path:
            self.ctx.log("[codeaudit] Kein code_path übergeben – übersprungen "
                         "(honest-empty, read-only Quell-Audit erfordert expliziten Pfad).")
            return findings
        if not os.path.isdir(code_path):
            self.ctx.log(f"[codeaudit] Pfad nicht gefunden/kein Verzeichnis: {code_path} – übersprungen.")
            return findings

        self.ctx.log(f"[codeaudit] 🔎 Rein lesende Quell-Audit von {code_path}")
        result = _ca.audit_tree(code_path)
        self.ctx.log(f"[codeaudit] {result.files_reviewed} Datei(en) gelesen, "
                     f"{len(result.candidates)} Kandidat(en).")

        # Coverage-Ledger-Hinweis als eigenes (informatives) Finding – macht die
        # Abdeckung zählbar (Skill-Prinzip: coverage-led, partial = partial).
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Quell-Audit Coverage: {result.files_reviewed} Datei(en) geprüft",
            category="codeaudit-coverage", severity="info",
            asset=os.path.basename(code_path.rstrip("/")) or code_path,
            description=("Deterministische Abdeckung der statischen Quell-Review "
                         "(rein lesend). Mehrfachläufe sind additiv; diese Zahl "
                         "beschreibt NUR die abgedeckten Dateien, nicht Vollständigkeit."),
            evidence={"files_reviewed": result.files_reviewed, "root": code_path},
            status="REFERENZ",
            dedup_key=f"codeaudit-coverage:{code_path}",
        ))

        for c in result.candidates:
            status = _ca.verdict_to_status(c.verdict)
            severity = _ca.verdict_to_severity(c.kind, c.verdict)
            loc = f"{c.rel_path}:{c.line}"
            title = f"{_KIND_LABEL.get(c.kind, c.kind)} @ {loc}"
            ev = {"file": c.rel_path, "line": c.line, "snippet": c.snippet,
                  "verdict": c.verdict, "detail": c.detail}
            ev.update(c.evidence or {})
            findings.append(AgentFinding(
                agent=self.name, title=title, category=c.kind,
                severity=severity, asset=c.rel_path,
                description=c.detail,
                evidence=ev, status=status,
                dedup_key=f"codeaudit:{c.kind}:{loc}",
            ))
        return findings


_KIND_LABEL = {
    "hardcoded-secret": "Hardcodiertes Secret",
    "code-injection": "Code-Injection-Sink",
    "command-injection": "Command-Injection-Sink",
    "sql-injection": "SQL-Injection (String-Konkatenation)",
    "insecure-deserialization": "Unsichere Deserialisierung",
    "weak-crypto": "Schwache Krypto",
}
