"""Threat-Feed für die Startseiten-Laufschrift ("Neueste Schwachstellen").

Führt ECHTE, öffentliche Quellen zu aktuellen Schwachstellen-Meldungen zusammen:

  1. NVD (services.nvd.nist.gov, dieselbe Anbindung wie der threat-intel-Soldat):
     die zuletzt veröffentlichten CVEs mit ID, Kurzbeschreibung, CVSS/Severity
     und Datum. CVSS-Werte werden von NVD ÜBERNOMMEN, nie erfunden.
  2. Mastodon (öffentliche Hashtag-Timeline, z.B. infosec.exchange) – KEIN Login,
     KEIN Token, nur öffentliche Endpoints. HTML wird gestrippt.

Beide Quellen werden server-seitig gecacht (TTL, konfigurierbar), mit Timeout und
höflichem User-Agent abgefragt. Fällt eine Quelle aus, wird die andere genutzt;
fallen beide aus, liefert der Endpoint ``ok=False`` und das Frontend zeigt die
statischen Infosec-Fakten als Fallback (nie dauerhaft „Lädt …").

Es werden KEINE Daten erfunden: Was hier erscheint, stammt 1:1 aus NVD bzw. den
öffentlichen Mastodon-Statuses.
"""
from __future__ import annotations

import html
import os
import re
import threading
import time
from typing import Any

from .config import _CONFIG_PATH

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "antbb/1.0 (+local authorized security tool; feed reader)"

# ---- Server-seitiger Cache (prozessweit, thread-sicher) -----------------------
_CACHE: dict[str, Any] = {"ts": 0.0, "payload": None}
_CACHE_LOCK = threading.Lock()

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _defaults() -> dict:
    return {
        "enabled": True,
        "cache_ttl_seconds": 10800,   # 3h – respektiert NVD-/Instanz-Rate-Limits
        "http_timeout": 8.0,
        "max_items": 30,
        "nvd": {
            "enabled": True,
            "lookback_days": 7,
            "results_per_page": 15,
        },
        "mastodon": {
            "enabled": True,
            # Hashtag-Timelines (oeffentlich, ohne Login). Instanz konfigurierbar.
            "instance": "mastodon.social",
            "tags": ["cve", "vulnerability", "infosec"],
            "limit_per_tag": 10,
            # Oeffentliche Infosec-/CVE-Konten (user@instanz). Account-Timelines
            # sind oeffentlich abrufbar (ohne Token). Defaults = von der Nutzerin
            # genannte, bewaehrte Quellen.
            "accounts": [
                "cvedatabase@infosec.exchange",
                "EUVD_Bot@mastodon.social",
                "shodansafari@infosec.exchange",
                "urldna@infosec.exchange",
                "securityfeed@infosec.exchange",
            ],
            "limit_per_account": 6,
        },
    }


def _config() -> dict:
    cfg = _defaults()
    raw = {}
    try:
        import yaml
        if _CONFIG_PATH.is_file():
            with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
                raw = (yaml.safe_load(fh) or {}).get("threatfeed", {}) or {}
    except Exception:
        raw = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update({kk: vv for kk, vv in v.items() if vv is not None})
            elif v is not None:
                cfg[k] = v
    # Env-Overrides (optional)
    env_ttl = os.environ.get("ANTBB_FEED_TTL")
    if env_ttl and env_ttl.strip().isdigit():
        cfg["cache_ttl_seconds"] = int(env_ttl.strip())
    return cfg


def strip_html(raw: str) -> str:
    """Entfernt HTML-Tags aus einem Mastodon-Status und normalisiert Whitespace."""
    if not raw:
        return ""
    txt = raw.replace("</p>", " ").replace("<br>", " ").replace("<br/>", " ")
    txt = _TAG_RE.sub(" ", txt)
    txt = html.unescape(txt)
    txt = _WS_RE.sub(" ", txt).strip()
    return txt


def _shorten(text: str, limit: int = 180) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _sort_key(item: dict) -> str:
    # ISO-8601-Strings sind lexikographisch sortierbar (neueste zuerst → reverse).
    return str(item.get("date") or "")


def merge_and_sort(cves: list[dict], posts: list[dict], max_items: int) -> list[dict]:
    """Führt CVE- und Mastodon-Items zusammen, neueste zuerst (rein, testbar)."""
    n = max(1, int(max_items))
    cves = sorted([i for i in cves if i and i.get("text")], key=_sort_key, reverse=True)
    posts = sorted([i for i in posts if i and i.get("text")], key=_sort_key, reverse=True)
    # Beide Quellen sichtbar halten: bis zur Haelfte fuer NVD reservieren.
    take_c = min(len(cves), max(n // 2, n - len(posts)))
    picked = cves[:take_c] + posts[: n - take_c]
    picked.sort(key=_sort_key, reverse=True)
    return picked


def _fetch_nvd(cfg: dict) -> list[dict]:
    nvd = cfg.get("nvd", {}) or {}
    if not nvd.get("enabled", True):
        return []
    import datetime as _dt
    import httpx
    days = int(nvd.get("lookback_days", 7) or 7)
    rpp = int(nvd.get("results_per_page", 15) or 15)
    now = _dt.datetime.now(_dt.timezone.utc)
    start = now - _dt.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": now.strftime(fmt),
        "resultsPerPage": rpp,
    }
    headers = {"User-Agent": _USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")  # optional, nicht erforderlich
    if api_key:
        headers["apiKey"] = api_key
    out: list[dict] = []
    try:
        with httpx.Client(timeout=float(cfg.get("http_timeout", 8.0)), headers=headers) as c:
            r = c.get(_NVD_URL, params=params)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        descs = cve.get("descriptions", [])
        text = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
        score, vec, sev = _extract_cvss(cve)
        out.append({
            "kind": "cve",
            "id": cid,
            "text": _shorten(text or cid),
            "severity": (sev or "").upper() or None,
            "cvss": score,
            "date": cve.get("published") or "",
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "source": "NVD",
        })
    return out


def _extract_cvss(cve: dict):
    metrics = cve.get("metrics", {}) if isinstance(cve, dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr and isinstance(arr, list):
            d = arr[0].get("cvssData", {})
            return (d.get("baseScore"), d.get("vectorString"),
                    d.get("baseSeverity") or arr[0].get("baseSeverity"))
    return (None, "", "")


_CVE_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|EUVD-\d{4}-\d{3,7})\b", re.I)
_SCORE_RE = re.compile(r"(?:Score|CVSS)[^0-9]{0,12}(\d{1,2}(?:\.\d)?)\s*/?\s*10", re.I)


def _severity_from_score(score):
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    if v >= 9.0:
        return "CRITICAL"
    if v >= 7.0:
        return "HIGH"
    if v >= 4.0:
        return "MEDIUM"
    if v > 0:
        return "LOW"
    return None


def _extract_post_meta(text: str):
    """Best-effort: CVE/EUVD-ID + CVSS-Score aus dem Post-Text (nichts erfinden)."""
    cve_id = None
    m = _CVE_ID_RE.search(text or "")
    if m:
        cve_id = m.group(1).upper()
    sev = None
    ms = _SCORE_RE.search(text or "")
    if ms:
        sev = _severity_from_score(ms.group(1))
    return cve_id, sev


def _mastodon_status_item(s: dict, instance: str, source_label: str) -> dict | None:
    if not isinstance(s, dict):
        return None
    text = strip_html(s.get("content", ""))
    if not text:
        return None
    acct = (s.get("account") or {}).get("acct") or "infosec"
    if "@" not in acct:
        acct = f"{acct}@{instance}"
    cve_id, sev = _extract_post_meta(text)
    return {
        "kind": "mastodon",
        "id": cve_id,
        "text": _shorten(text),
        "author": f"@{acct}",
        "severity": sev,
        "date": s.get("created_at") or "",
        "url": s.get("url") or s.get("uri") or f"https://{instance}/",
        "source": source_label,
    }


def _fetch_mastodon_accounts(cfg: dict, client, headers) -> list[dict]:
    """Oeffentliche Account-Timelines genannter Infosec-/CVE-Konten."""
    mcfg = cfg.get("mastodon", {}) or {}
    accounts = mcfg.get("accounts") or []
    limit = int(mcfg.get("limit_per_account", 6) or 6)
    out: list[dict] = []
    for raw in accounts[:12]:
        raw = str(raw).lstrip("@").strip()
        if "@" not in raw:
            continue
        user, _, inst = raw.partition("@")
        inst = inst.strip().strip("/")
        if not user or not inst:
            continue
        try:
            rl = client.get(f"https://{inst}/api/v1/accounts/lookup",
                            params={"acct": user}, headers=headers)
            if rl.status_code != 200:
                continue
            acc_id = (rl.json() or {}).get("id")
            if not acc_id:
                continue
            rs = client.get(f"https://{inst}/api/v1/accounts/{acc_id}/statuses",
                            params={"limit": limit, "exclude_replies": "true",
                                    "exclude_reblogs": "true"},
                            headers=headers)
            if rs.status_code != 200:
                continue
            statuses = rs.json()
        except Exception:
            continue
        if not isinstance(statuses, list):
            continue
        for st in statuses:
            item = _mastodon_status_item(st, inst, f"Mastodon @{user}")
            if item:
                out.append(item)
    return out


def _fetch_mastodon(cfg: dict) -> list[dict]:
    """Oeffentliche Mastodon-Quellen: Hashtag-Timelines + genannte Infosec-Konten.

    Kein Login/Token. Jede Quelle einzeln abgesichert (Fehler -> uebersprungen).
    """
    mcfg = cfg.get("mastodon", {}) or {}
    if not mcfg.get("enabled", True):
        return []
    import httpx
    instance = str(mcfg.get("instance", "mastodon.social")).strip().strip("/")
    instance = re.sub(r"^https?://", "", instance)
    tags = mcfg.get("tags") or []
    limit = int(mcfg.get("limit_per_tag", 10) or 10)
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    out: list[dict] = []
    try:
        client = httpx.Client(timeout=float(cfg.get("http_timeout", 8.0)), headers=headers)
    except Exception:
        return []
    try:
        # a) Hashtag-Timelines
        for tag in tags[:5]:
            tag = str(tag).lstrip("#").strip()
            if not tag:
                continue
            try:
                r = client.get(f"https://{instance}/api/v1/timelines/tag/{tag}",
                               params={"limit": limit})
                if r.status_code != 200:
                    continue
                statuses = r.json()
            except Exception:
                continue
            if not isinstance(statuses, list):
                continue
            for st in statuses:
                item = _mastodon_status_item(st, instance, f"Mastodon #{tag}")
                if item:
                    out.append(item)
        # b) Genannte oeffentliche Infosec-/CVE-Konten
        out += _fetch_mastodon_accounts(cfg, client, headers)
    finally:
        try:
            client.close()
        except Exception:
            pass
    # Dedupe ueber URL (gleicher Post via Tag + Konto)
    seen: set[str] = set()
    uniq: list[dict] = []
    for it in out:
        key = it.get("url") or it.get("text")
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)
    return uniq


def get_feed(force: bool = False) -> dict:
    """Liefert den zusammengeführten Feed (gecacht). Nie Exceptions nach außen.

    Rückgabe: {"ok": bool, "items": [...], "sources": [...], "cached_at": ts}
    ok=False -> keine Quelle erreichbar; Frontend nutzt statische Fallback-Fakten.
    """
    cfg = _config()
    if not cfg.get("enabled", True):
        return {"ok": False, "items": [], "sources": [], "reason": "disabled"}
    ttl = float(cfg.get("cache_ttl_seconds", 10800))
    now = time.time()
    with _CACHE_LOCK:
        if (not force and _CACHE["payload"] is not None
                and (now - _CACHE["ts"]) < ttl):
            return _CACHE["payload"]
    # außerhalb des Locks abfragen (Netzwerk), damit Requests sich nicht blockieren
    cves = _fetch_nvd(cfg)
    posts = _fetch_mastodon(cfg)
    items = merge_and_sort(cves, posts, cfg.get("max_items", 20))
    sources = []
    if cves:
        sources.append("NVD")
    if posts:
        sources.append("Mastodon")
    payload = {
        "ok": bool(items),
        "items": items,
        "sources": sources,
        "cached_at": now,
    }
    # Nur erfolgreiche Antworten cachen; Fehlschlag soll beim nächsten Mal neu versuchen.
    if payload["ok"]:
        with _CACHE_LOCK:
            _CACHE["ts"] = now
            _CACHE["payload"] = payload
    return payload
