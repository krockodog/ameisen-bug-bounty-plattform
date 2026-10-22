"""Defensive Netzwerk-Hilfen mit Scope-Enforcement und Rate-Limiting.

Zentrale Stelle, über die ALLE Agenten echte Netzwerkzugriffe machen. Jede
Methode prüft das Ziel ZUERST gegen den Scope (default-deny über den von der
Königin injizierten `scope_check`). Out-of-Scope-Ziele werden NICHT kontaktiert,
sondern übersprungen und in `blocked` protokolliert. Zusätzlich erzwingt ein
Per-Host-Rate-Limiter sinnvolle Pausen, damit Ziele nicht überlastet werden.

Ausschliesslich defensive, nicht-destruktive Operationen:
  * DNS-Auflösung (A/AAAA/CNAME/MX/TXT)
  * TCP-Connect-Portscan (nur Verbindungsaufbau, kein Payload)
  * HTTP(S)-GET/HEAD (lesend)
  * TLS-Zertifikats-/Protokoll-Inspektion
Keine Exploits, keine Brute-Force, keine destruktiven Payloads.
"""
from __future__ import annotations

import asyncio
import difflib
import hashlib
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from . import scope as scope_mod

try:  # dnspython ist optional – Fallback auf socket für A/AAAA
    import dns.resolver as _dnsresolver
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


def host_of(asset: str) -> str:
    """Extrahiert den Host aus einem Asset (URL, host:port, host/path, host)."""
    return scope_mod._host_of(asset)


def is_ip_literal(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def looks_like_domain(host: str) -> bool:
    return ("." in host) and not is_ip_literal(host) and host not in ("localhost",)


@dataclass
class ScanConfig:
    """Konfigurierbare Scan-Parameter (aus config/default.yaml, Abschnitt `scan`)."""
    max_rps_per_host: float = 2.0
    request_delay: float = 0.3
    http_timeout: float = 8.0
    user_agent: str = "antbb/1.0 (local authorized scan)"
    # Recon
    enable_portscan: bool = True
    ports: list = field(default_factory=lambda: [80, 443, 8080, 8443, 22, 21, 25, 3306])
    port_timeout: float = 1.0
    subdomain_wordlist: list = field(default_factory=lambda: [
        "www", "api", "dev", "staging", "admin", "mail", "test", "cdn", "blog", "app",
    ])
    dns_timeout: float = 3.0
    # Scanner
    paths: list = field(default_factory=lambda: [
        "/", "/robots.txt", "/.git/", "/admin/", "/backup/", "/.env", "/server-status",
    ])
    reflect_param: str = "antbbtest"
    verify_tls: bool = False
    # ── Aktive Verifikation (TIEFER, kontrolliert) – Default AUS ──
    # Wird nur wirksam, wenn zusätzlich zum Oversight-Häkchen dieser Schalter
    # ausdrücklich gesetzt ist (CLI --active / Web-Checkbox). Konservative Limits.
    active_verification: bool = False
    av_max_payloads_per_param: int = 4     # harte Obergrenze an Payloads je Parameter
    av_time_based_threshold: float = 4.0   # Delay-Schwelle (s) für time-based SQLi
    av_time_based_delay: int = 3           # angefordertes SLEEP (s), konservativ
    av_time_based_attempts: int = 2        # wenige Versuche
    av_checks: list = field(default_factory=lambda: [
        "xss", "sqli", "open_redirect", "path_traversal",
        "exposed_artifact", "cors", "missing_auth", "ssrf",
    ])
    av_param_candidates: list = field(default_factory=lambda: [
        "q", "s", "search", "query", "name", "id", "page", "lang", "ref",
    ])
    av_redirect_param_candidates: list = field(default_factory=lambda: [
        "next", "url", "redirect", "redirect_uri", "return", "returnUrl",
        "dest", "destination", "r", "u", "to",
    ])
    av_file_param_candidates: list = field(default_factory=lambda: [
        "file", "path", "page", "template", "doc", "include", "view",
    ])
    # SSRF: URL-/Webhook-/Image-Fetch-ähnliche Parameter (+ harte Obergrenze).
    av_ssrf_max_params: int = 12
    av_ssrf_param_candidates: list = field(default_factory=lambda: [
        "url", "uri", "u", "link", "src", "source", "dest", "destination",
        "redirect", "redirect_uri", "next", "target", "callback", "webhook",
        "image", "img", "imageurl", "image_url", "fetch", "load", "feed",
        "proxy", "data", "domain", "host", "site",
    ])
    # ── Offensives Fuzzing (kontrolliert) – Default AUS ──
    # Eigener Schalter, unabhängig von active_verification. Nur wirksam mit
    # Oversight + Scope + CLI --fuzz / Web-Checkbox / ANTBB_FUZZ=1.
    # Nur GET-basierte Content-/Path-Discovery + Parameter-Fuzzing mit
    # gutartigen Markern. Harte Obergrenzen, Baseline gegen Catch-all/WAF.
    fuzz_enabled: bool = False
    fuzz_max_requests: int = 200
    fuzz_baseline_samples: int = 3
    fuzz_length_tolerance: int = 64   # Content-Length-Toleranz (Bytes) ggü. Baseline
    # Ähnlichkeits-Baseline gegen jitternde Catch-all-/Anti-Bot-Seiten.
    # Jaccard-Ähnlichkeit (0..1) des normalisierten Bodys ggü. Baseline; ab
    # diesem Wert gilt eine Antwort als „gleich wie Catch-all" (Jitter-tolerant).
    fuzz_similarity_threshold: float = 0.85
    # Wie viele Zufallspfade zur Catch-all-Erkennung (zusätzlich zu Baseline).
    catchall_min_samples: int = 3
    fuzz_wordlist: list = field(default_factory=lambda: [
        "/admin", "/admin/", "/login", "/login/", "/wp-admin/", "/wp-login.php",
        "/dashboard", "/manage", "/console", "/phpmyadmin/", "/pma/",
        "/api", "/api/v1", "/api/v2", "/graphql", "/swagger.json", "/openapi.json",
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.DS_Store",
        "/backup", "/backup/", "/backups/", "/dump.sql", "/db.sql", "/config.php.bak",
        "/server-status", "/server-info", "/actuator", "/actuator/health",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/debug", "/trace", "/test", "/tmp", "/old", "/bak",
        "/config", "/config.json", "/package.json", "/composer.json",
        "/uploads/", "/files/", "/static/", "/assets/",
        "/user", "/users", "/account", "/settings", "/panel",
    ])
    fuzz_param_candidates: list = field(default_factory=lambda: [
        "q", "s", "search", "query", "id", "page", "file", "path", "lang", "ref",
    ])
    fuzz_param_markers: list = field(default_factory=lambda: [
        "antbbFUZZ1", "../antbb", "antbb'\"<>",
    ])


class NetClient:
    """Scope- und ratengebundener Netzwerk-Client für die Agenten."""

    def __init__(self, scope_check: Callable[[str], bool], cfg: ScanConfig,
                 logger, emit: Optional[Callable[[dict], None]] = None):
        self.scope_check = scope_check
        self.cfg = cfg
        self.logger = logger
        self.emit = emit
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        #: Protokoll aller geblockten (out-of-scope) Zugriffsversuche.
        self.blocked: list[dict] = []
        #: Zähler tatsächlich abgesetzter Netzwerk-Operationen.
        self.request_count = 0

    # ---------------- interne Helfer ----------------
    def _log(self, msg: str) -> None:
        self.logger.info(msg)
        if self.emit:
            self.emit({"ts": time.time(), "msg": msg})

    def in_scope(self, asset: str) -> bool:
        return bool(self.scope_check(asset))

    def _block(self, asset: str, kind: str) -> None:
        self.blocked.append({"asset": asset, "op": kind, "ts": time.time()})
        self._log(f"[net] ⛔ Scope-Block: {kind} auf '{asset}' NICHT ausgeführt (out-of-scope).")

    async def _throttle(self, host: str) -> None:
        """Serialisiert + spaced Requests pro Host (Rate-Limit + Pause)."""
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            interval = 0.0
            if self.cfg.max_rps_per_host > 0:
                interval = 1.0 / self.cfg.max_rps_per_host
            interval = max(interval, self.cfg.request_delay)
            now = time.monotonic()
            wait = self._last.get(host, 0.0) + interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[host] = time.monotonic()

    # ---------------- HTTP ----------------
    async def http_request(self, method: str, url: str, *, params: Optional[dict] = None,
                           allow_redirects: bool = False,
                           headers: Optional[dict] = None) -> Optional[httpx.Response]:
        if not self.in_scope(url):
            self._block(url, f"http/{method}")
            return None
        host = host_of(url)
        await self._throttle(host)
        self.request_count += 1
        hdrs = {"User-Agent": self.cfg.user_agent}
        if headers:
            hdrs.update(headers)
        try:
            async with httpx.AsyncClient(
                timeout=self.cfg.http_timeout, follow_redirects=allow_redirects,
                headers=hdrs, verify=self.cfg.verify_tls,
            ) as client:
                return await client.request(method, url, params=params)
        except Exception as exc:
            self._log(f"[net] ⚠️ Request fehlgeschlagen ({method} {url}): {exc}")
            return None

    async def http_get(self, url: str, **kw) -> Optional[httpx.Response]:
        return await self.http_request("GET", url, **kw)

    # ---------------- DNS ----------------
    async def resolve(self, host: str, rdtype: str = "A") -> list[str]:
        if not self.in_scope(host):
            self._block(host, f"dns/{rdtype}")
            return []
        return await asyncio.to_thread(self._resolve_sync, host, rdtype)

    def _resolve_sync(self, host: str, rdtype: str) -> list[str]:
        out: list[str] = []
        if _HAS_DNS:
            try:
                res = _dnsresolver.Resolver()
                res.lifetime = self.cfg.dns_timeout
                res.timeout = self.cfg.dns_timeout
                for r in res.resolve(host, rdtype):
                    out.append(r.to_text())
            except Exception:
                pass
        elif rdtype in ("A", "AAAA"):
            fam = socket.AF_INET if rdtype == "A" else socket.AF_INET6
            try:
                infos = socket.getaddrinfo(host, None, fam)
                out = sorted({i[4][0] for i in infos})
            except Exception:
                pass
        self.request_count += 1
        return out

    # ---------------- TCP-Portscan ----------------
    async def scan_port(self, host: str, port: int) -> bool:
        if not self.in_scope(host):
            self._block(f"{host}:{port}", "tcp-connect")
            return False
        await self._throttle(host)
        return await asyncio.to_thread(self._connect_sync, host, port)

    def _connect_sync(self, host: str, port: int) -> bool:
        self.request_count += 1
        try:
            with socket.create_connection((host, port), timeout=self.cfg.port_timeout):
                return True
        except Exception:
            return False

    # ---------------- TLS ----------------
    async def tls_info(self, host: str, port: int = 443) -> Optional[dict]:
        if not self.in_scope(host):
            self._block(f"{host}:{port}", "tls")
            return None
        await self._throttle(host)
        return await asyncio.to_thread(self._tls_sync, host, port)

    def _tls_sync(self, host: str, port: int) -> Optional[dict]:
        self.request_count += 1
        # 1) verifizierender Kontext → liefert Zertifikatsdaten (notAfter etc.)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.cfg.port_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return {"protocol": ss.version(), "cert": ss.getpeercert(),
                            "verified": True}
        except Exception:
            pass
        # 2) Fallback ohne Verifikation → nur Protokoll (Zertifikat nicht prüfbar)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.cfg.port_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return {"protocol": ss.version(), "cert": {}, "verified": False}
        except Exception:
            return None


def base_urls_for(asset: str) -> list[str]:
    """Leitet kandidierende Basis-URLs aus einem Asset ab."""
    if "://" in asset:
        return [asset.rstrip("/")]
    return [f"https://{asset}", f"http://{asset}"]


# ===========================================================================
# Catch-all-/Baseline-Schutz (Jitter-tolerant, Body-Ähnlichkeit statt nur Länge)
# ===========================================================================
#
# Motivation: Eine jitternde Anti-Bot-/SPA-Platzhalterseite liefert auf (fast)
# jeden Pfad eine sehr ähnliche 200-Seite, deren Content-Length um >100 Byte
# schwankt (oder teils 301). Ein reiner Längenvergleich (±Toleranz) erzeugt dann
# massenhaft Geister-Funde. Stattdessen:
#   1) Baseline aus mehreren garantiert nicht existierenden Zufallspfaden bilden.
#   2) Body normalisieren (Zahlen/Hashes/Whitespace entfernen) und per Jaccard-
#      Shingle-Ähnlichkeit vergleichen → Jitter wird toleriert.
#   3) „Catch-all" markieren, wenn die Zufallspfade überwiegend 200 (oder
#      wechselnd 200/301/302) mit hoher gegenseitiger Body-Ähnlichkeit liefern.
#   4) Für Catch-all-Hosts gilt ein Treffer nur dann als echt, wenn die Antwort
#      SIGNIFIKANT abweicht: Ähnlichkeit unter Schwellwert ODER relevanter
#      Statuswechsel (weg von den Baseline-Status). Sonst: Catch-all-Artefakt.

_WS_RE = re.compile(r"\s+")
_HEX_RE = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)  # UUIDs/CSRF/Hashes/Nonces
_NUM_RE = re.compile(r"\d+")                           # Timestamps/Counter/IDs
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _normalize_body(resp) -> str:
    """Volatile Teile entfernen, damit Jitter nicht als Unterschied zählt."""
    body = getattr(resp, "content", b"") or b""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    text = text.lower()
    text = _HEX_RE.sub("", text)
    text = _NUM_RE.sub("", text)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def _shingles(text: str) -> frozenset:
    """Token-Set (unigram) als Shingle-Repräsentation für Jaccard."""
    return frozenset(text.split())


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 1.0


def _ratio(a: str, b: str) -> float:
    """SequenceMatcher-Verhältnis als Zweitmetrik (deckelt Jaccard-Ausreisser)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # quick_ratio ist günstig und reicht als Obergrenze/Hinweis.
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).quick_ratio()


@dataclass
class _Sample:
    status: int
    norm: str
    shingles: frozenset
    length: int


@dataclass
class CatchAllBaseline:
    """Baseline aus Zufallspfaden; erkennt Catch-all und bewertet Abweichungen."""
    base: str
    samples: list = field(default_factory=list)       # list[_Sample]
    is_catch_all: bool = False
    statuses: frozenset = field(default_factory=frozenset)
    threshold: float = 0.85
    rep_shingles: frozenset = field(default_factory=frozenset)
    rep_len: int = 0
    reason: str = ""

    def significant(self, resp) -> tuple[bool, float, list[str]]:
        """Weicht `resp` SIGNIFIKANT von der Catch-all-Baseline ab?

        Rückgabe: (ist_signifikant, similarity, gründe).
        * is_catch_all=False → immer signifikant (kein Catch-all → normal werten).
        * is_catch_all=True  → signifikant nur bei Ähnlichkeit < Schwellwert
          ODER relevantem Statuswechsel (Status NICHT in Baseline-Status).
        """
        if resp is None:
            return (False, 0.0, ["keine Antwort"])
        status = int(getattr(resp, "status_code", 0))
        norm = _normalize_body(resp)
        sh = _shingles(norm)
        # Max-Ähnlichkeit zu IRGENDEINEM Sample (konservativ: matcht eine
        # Catch-all-Variante → Artefakt).
        sim = max((_jaccard(sh, s.shingles) for s in self.samples), default=0.0)
        if not self.is_catch_all:
            return (True, sim, ["kein Catch-all-Host"])
        # Catch-all-Host: Signifikanz wird vom INHALT getrieben, nicht von
        # Status allein. Eine jitternde Anti-Bot-Seite liefert u.a. leere
        # 301-Redirects ohne Body; die sind Rauschen, kein Fund.
        if not sh:
            # Kein verwertbarer Body (leer / Redirect ohne Inhalt) → Artefakt.
            return (False, 0.0, [f"catch-all-redirect/leer (status {status}, kein Body-Inhalt)"])
        if sim < self.threshold:
            # Inhalt weicht deutlich ab → echter Fund (ggf. mit Statuswechsel).
            reasons = [f"body-ähnlichkeit {sim:.2f} < {self.threshold:.2f}"]
            if status not in self.statuses and status not in _REDIRECT_STATUSES:
                reasons.append(f"+ statuswechsel {status} ∉ baseline {sorted(self.statuses)}")
            return (True, sim, reasons)
        # Inhalt ähnlich zur Baseline → Catch-all-Artefakt, auch bei Statusjitter.
        return (False, sim, [f"catch-all-artefakt (sim {sim:.2f} ≥ {self.threshold:.2f}, "
                             f"status {status})"])

    def describe(self) -> str:
        if self.is_catch_all:
            return (f"Catch-all erkannt @ {self.base}: {len(self.samples)} Zufallspfade "
                    f"status∈{sorted(self.statuses)} len≈{self.rep_len} ({self.reason}) "
                    f"→ nur signifikant abweichende Treffer gelten als Fund.")
        return (f"Baseline @ {self.base}: {len(self.samples)} Zufallspfade "
                f"status∈{sorted(self.statuses)} len≈{self.rep_len} (kein Catch-all).")


def response_similarity(resp_a, resp_b) -> float:
    """Normalisierte Body-Ähnlichkeit (Jaccard, Jitter-tolerant) zweier Antworten."""
    if resp_a is None or resp_b is None:
        return 0.0
    return _jaccard(_shingles(_normalize_body(resp_a)),
                    _shingles(_normalize_body(resp_b)))


async def build_catchall_baseline(net, base: str, n_samples: int = 4,
                                   threshold: float = 0.85,
                                   budget: Optional[list] = None) -> CatchAllBaseline:
    """Baseline aus n garantiert nicht existierenden Zufallspfaden bilden.

    `net` ist ein NetClient (Scope + Rate-Limit greifen weiter). `budget`, wenn
    übergeben, ist eine 1-elementige Liste [verbleibende_requests]; jede Probe
    dekrementiert sie und stoppt bei 0 (damit max_requests im Fuzzer gilt).
    """
    bl = CatchAllBaseline(base=base, threshold=threshold)
    for _ in range(max(1, n_samples)):
        if budget is not None and budget[0] <= 0:
            break
        rnd = secrets.token_hex(16)
        url = base.rstrip("/") + f"/antbb-baseline-{rnd}"
        resp = await net.http_get(url)
        if budget is not None:
            budget[0] -= 1
        if resp is None:
            continue
        norm = _normalize_body(resp)
        bl.samples.append(_Sample(
            status=int(resp.status_code),
            norm=norm,
            shingles=_shingles(norm),
            length=len(getattr(resp, "content", b"") or b""),
        ))
    if not bl.samples:
        return bl

    statuses = [s.status for s in bl.samples]
    bl.statuses = frozenset(statuses)
    # Repräsentatives Sample = Medoid (höchste mittlere Ähnlichkeit zu den anderen).
    def _mean_sim(i):
        others = [bl.samples[j].shingles for j in range(len(bl.samples)) if j != i]
        if not others:
            return 1.0
        return sum(_jaccard(bl.samples[i].shingles, o) for o in others) / len(others)
    medoid_idx = max(range(len(bl.samples)), key=_mean_sim) if len(bl.samples) > 1 else 0
    bl.rep_shingles = bl.samples[medoid_idx].shingles
    bl.rep_len = int(sum(s.length for s in bl.samples) / len(bl.samples))

    # Catch-all-Kriterium:
    #  (a) Zufallspfade überwiegend "erfolgreich" (200) oder Redirect (301/302),
    #      also NICHT sauber 404/403 für nicht existierende Pfade, UND
    #  (b) hohe gegenseitige Body-Ähnlichkeit (Median paarweise >= threshold*0.95).
    success_like = sum(1 for st in statuses if st == 200 or st in _REDIRECT_STATUSES)
    majority_success = success_like >= (len(statuses) + 1) // 2 and success_like >= 1
    # Paarweise Ähnlichkeiten
    pair_sims = []
    for i in range(len(bl.samples)):
        for j in range(i + 1, len(bl.samples)):
            pair_sims.append(_jaccard(bl.samples[i].shingles, bl.samples[j].shingles))
    if pair_sims:
        pair_sims.sort()
        median_sim = pair_sims[len(pair_sims) // 2]
    else:
        median_sim = 1.0  # nur 1 Sample: Ähnlichkeit zu sich selbst
    mutual_high = median_sim >= (threshold * 0.95)
    # Reine 404/403-Baseline (sauberer Server) → KEIN Catch-all.
    all_notfound = all(st in (404, 403, 410) for st in statuses)
    bl.is_catch_all = bool(majority_success and mutual_high and not all_notfound)
    bl.reason = (f"{success_like}/{len(statuses)} erfolgreich/redirect, "
                 f"median-ähnlichkeit {median_sim:.2f}")
    return bl
