"""Fuzz-Ameise: kontrolliertes OFFENSIVES Content-/Path-Discovery.

Läuft AUSSCHLIESSLICH, wenn ZUSÄTZLICH zum Pflicht-Oversight-Häkchen der
ausdrückliche Schalter `scan.fuzz.enabled` (bzw. CLI `--fuzz` / Web-Checkbox
„Offensives Fuzzing (autorisiert)" / Env `ANTBB_FUZZ`) gesetzt ist. Unabhängig
von der aktiven Verifikation (`--active`).

Harte Leitplanken (im Code erzwungen):
  * Jeder Request läuft über ctx.net → Scope default-deny + Rate-Limiting.
  * Nur GET (lesend). Keine Schreib-/DELETE-/Login-Brute-Force-Angriffe.
  * Harte Obergrenze an Requests (cfg.fuzz_max_requests).
  * Catch-all/WAF-Schutz: zuerst Baseline aus 2–3 Zufallspfaden messen;
    ein Pfad wird NUR gemeldet, wenn er sich signifikant von der Baseline
    unterscheidet (Statuscode ODER Content-Length ±Toleranz ODER Signatur).

Ohne Schalter: wie bisher nur Hinweis, keine Findings.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urljoin

from .base import AntAgent, AgentFinding, Task, Playbook
from ..netutil import base_urls_for, build_catchall_baseline

_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")

# Pfade, die bei Abweichung höher priorisiert werden (sensible Artefakte).
_SENSITIVE_HINTS = (
    "/.git/", "/.env", "/phpmyadmin", "/wp-admin", "/wp-login",
    "/backup", "/dump.sql", "/db.sql", "/config.php.bak", "/.DS_Store",
    "/actuator", "/server-status", "/swagger", "/openapi",
)


@dataclass
class _Profile:
    status: int
    length: int
    signature: str          # Titel oder Hash der ersten Bytes
    content_type: str

    def differs(self, other: "_Profile", length_tol: int) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        if self.status != other.status:
            reasons.append(f"status {other.status}≠{self.status}")
        if abs(self.length - other.length) > length_tol:
            reasons.append(f"length {other.length}≠{self.length}±{length_tol}")
        if self.signature and other.signature and self.signature != other.signature:
            reasons.append("signatur≠baseline")
        return (bool(reasons), reasons)


def _profile_of(resp) -> _Profile:
    body = resp.content or b""
    text = ""
    try:
        text = body[:4096].decode("utf-8", errors="replace")
    except Exception:
        text = ""
    m = _TITLE_RE.search(text)
    title = (m.group(1).strip()[:120] if m else "")
    head = body[:96]
    sig = title or ("sha1:" + hashlib.sha1(head).hexdigest()[:16])
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    return _Profile(
        status=int(resp.status_code),
        length=len(body),
        signature=sig,
        content_type=ctype,
    )


def _severity_for(path: str) -> str:
    p = path.lower()
    for hint in _SENSITIVE_HINTS:
        if hint in p:
            return "medium"
    return "low"


class FuzzAnt(AntAgent):
    name = "fuzz"
    role = ("Fuzzing: kontrollierte Content-/Path-Discovery + Parameter-Fuzzing "
            "(GET-only, Baseline gegen Catch-all; nur mit --fuzz)")
    specialty = "web-hunter"
    phases = ("scan",)
    playbooks = (
        Playbook("content-discovery", "offensive", True,
                 ["wordlist-get", "catchall-baseline", "similarity-filter"],
                 "GET-basierte Pfad-Discovery mit Catch-all-Baseline."),
        Playbook("parameter-fuzzing", "offensive", True,
                 ["benign-markers", "reflection-detect"],
                 "Parameter-Fuzzing mit gutartigen Markern (GET-only)."),
        Playbook("gobuster-discovery", "offensive", True,
                 ["gobuster"],
                 "Content-/Verzeichnis-Discovery via gobuster (SecLists-Wortliste)."),
        Playbook("ffuf-fuzzing", "offensive", True,
                 ["ffuf"],
                 "Content-Fuzzing via ffuf (SecLists-Wortliste)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        net = self.ctx.net
        if net is None:
            self.ctx.log("[fuzz] Kein NetClient – übersprungen.")
            return findings

        # Doppelte Absicherung: ohne ausdrücklichen Schalter NICHTS tun.
        if not getattr(self.ctx, "fuzz", False):
            self.ctx.log("[fuzz] ⏸️ Offensives Fuzzing NICHT aktiviert "
                         "(Schalter scan.fuzz.enabled=false / kein --fuzz) – keine Findings.")
            return findings

        cfg = net.cfg
        wordlist = list(cfg.fuzz_wordlist or [])
        max_req = max(1, int(cfg.fuzz_max_requests or 200))
        n_base = max(2, int(cfg.fuzz_baseline_samples or 3))
        tol = max(0, int(cfg.fuzz_length_tolerance or 64))
        params = list(cfg.fuzz_param_candidates or ["q"])
        markers = list(cfg.fuzz_param_markers or ["antbbFUZZ1"])

        self.ctx.log(
            f"[fuzz] 🔬 Offensives Fuzzing AN (autorisiert). "
            f"Wortliste={len(wordlist)} · max_requests={max_req} · "
            f"baseline_samples={n_base} · length_tol={tol}."
        )

        done_bases: set[str] = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            for base in base_urls_for(asset):
                if base in done_bases:
                    continue
                # Erreichbarkeit: ein GET; nur bei Antwort fuzz'en.
                probe = await net.http_get(base + "/")
                if probe is None:
                    continue
                done_bases.add(base)
                findings.extend(await self._fuzz_base(
                    net, base, wordlist, max_req, n_base, tol, params, markers,
                ))
        findings += await self._kali_ext(task)
        return findings

    async def _fuzz_base(self, net, base: str, wordlist: list, max_req: int,
                         n_base: int, tol: int, params: list, markers: list
                         ) -> list[AgentFinding]:
        out: list[AgentFinding] = []
        budget = [max_req]  # geteiltes Request-Budget (hartes max_requests)

        # ── 1) Ähnlichkeits-Baseline aus Zufallspfaden (Jitter-tolerant) ──
        sim_thr = float(getattr(net.cfg, "fuzz_similarity_threshold", 0.85) or 0.85)
        n_samples = max(n_base, int(getattr(net.cfg, "catchall_min_samples", 3) or 3))
        bl = await build_catchall_baseline(
            net, base, n_samples=n_samples, threshold=sim_thr, budget=budget,
        )
        if not bl.samples:
            self.ctx.log(f"[fuzz] ⚠️ Keine Baseline für {base} – übersprungen.")
            return out
        self.ctx.log("[fuzz] " + ("⚠️ " if bl.is_catch_all else "") + bl.describe())

        # ── 2) Content-Discovery (Wortliste) ──
        seen_paths: set[str] = set()
        for path in wordlist:
            if budget[0] <= 0:
                self.ctx.log(f"[fuzz] ⏹️ max_requests={max_req} erreicht @ {base}.")
                break
            if not path.startswith("/"):
                path = "/" + path
            if path in seen_paths:
                continue
            seen_paths.add(path)
            url = base.rstrip("/") + path
            resp = await net.http_get(url)
            budget[0] -= 1
            if resp is None:
                continue
            prof = _profile_of(resp)
            significant, sim, reasons = bl.significant(resp)
            if not significant:
                # Catch-all-Artefakt: still verwerfen, als Rauschen protokollieren.
                self.ctx.log(
                    f"[fuzz] · {path} @ {base} als Catch-all-Artefakt verworfen "
                    f"(HTTP {prof.status}, {reasons[0] if reasons else ''})"
                )
                continue
            sev = _severity_for(path)
            title = f"Fuzz-Treffer (von Baseline abweichend): {path}"
            self.ctx.log(
                f"[fuzz] ✅ {path} @ {base} → HTTP {prof.status} "
                f"len={prof.length} sim={sim:.2f} ({'; '.join(reasons)})"
            )
            out.append(AgentFinding(
                agent=self.name,
                title=title,
                category="fuzz-discovery",
                severity=sev,
                asset=url,
                description=(
                    f"Pfad {path} weicht signifikant von der Catch-all-/Baseline-Antwort ab "
                    f"({'; '.join(reasons)}; body-ähnlichkeit={sim:.2f}). Kein Schreibzugriff, nur GET."
                ),
                evidence={
                    "request": {"method": "GET", "url": url},
                    "response_status": prof.status,
                    "response_length": prof.length,
                    "response_signature": prof.signature,
                    "content_type": prof.content_type,
                    "baseline_statuses": sorted(bl.statuses),
                    "baseline_length": bl.rep_len,
                    "body_similarity": round(sim, 3),
                    "similarity_threshold": sim_thr,
                    "diff_reasons": reasons,
                    "catch_all_detected": bl.is_catch_all,
                    "confidence": "indikator",
                },
                dedup_key=f"fuzz-discovery:{url}",
            ))

        # ── 3) Parameter-Fuzzing mit gutartigen Markern (wenige) ──
        # Reflexion eines Markers ist ein eigenständiges Signal (Catch-all
        # spiegelt Parameter nicht), bleibt also unabhängig von der Baseline.
        for param in params[:6]:
            for marker in markers[:3]:
                if budget[0] <= 0:
                    break
                url = base.rstrip("/") + "/"
                resp = await net.http_get(url, params={param: marker})
                budget[0] -= 1
                if resp is None:
                    continue
                body = ""
                try:
                    body = (resp.content or b"")[:8000].decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                if marker not in body:
                    continue
                prof = _profile_of(resp)
                _, sim, reasons = bl.significant(resp)
                sev = "medium" if ("<" in marker and marker in body) else "low"
                self.ctx.log(
                    f"[fuzz] ℹ️ Parameter-Reflexion param={param!r} marker={marker!r} @ {base}"
                )
                out.append(AgentFinding(
                    agent=self.name,
                    title=f"Fuzz: Parameter '{param}' reflektiert Marker",
                    category="fuzz-param-reflection",
                    severity=sev,
                    asset=url,
                    description=(
                        f"GET-Parameter '{param}' spiegelt den gutartigen Marker "
                        f"'{marker}' in der Antwort wider (body-ähnlichkeit zur "
                        f"Catch-all-Baseline={sim:.2f})."
                    ),
                    evidence={
                        "request": {"method": "GET", "url": url, "params": {param: marker}},
                        "response_status": prof.status,
                        "response_length": prof.length,
                        "reflected": True,
                        "marker": marker,
                        "baseline_statuses": sorted(bl.statuses),
                        "body_similarity": round(sim, 3),
                        "catch_all_detected": bl.is_catch_all,
                        "confidence": "indikator",
                    },
                    dedup_key=f"fuzz-param:{base}:{param}:{marker}",
                ))
            if budget[0] <= 0:
                break

        used = max_req - budget[0]
        self.ctx.log(f"[fuzz] {base}: {used} Requests, {len(out)} Treffer.")
        return out

    async def _kali_ext(self, task):
        """Externe Kali-Fuzz-Tools (gobuster/ffuf). Honest-empty ohne Tool/Wortliste."""
        from ..tools.kali import KaliAdapter
        from ..netutil import base_urls_for
        ka = KaliAdapter(self.ctx)
        out = []
        seen = set()
        for asset in task.assets:
            if not self._in_scope(asset):
                continue
            for base in base_urls_for(asset):
                if base in seen:
                    continue
                seen.add(base)
                out += await ka.gobuster(base, agent=self.name)
                out += await ka.ffuf(base.rstrip("/") + "/FUZZ", agent=self.name)
        return out
