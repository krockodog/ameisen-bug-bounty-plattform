"""Smoke-Test für die Startseiten-Laufschrift "Neueste Schwachstellen".

Prüft rein offline (ohne echte Netzabfragen):
  * strip_html entfernt HTML-Tags und normalisiert Whitespace.
  * merge_and_sort führt CVE- und Mastodon-Items zusammen, neueste zuerst.
  * _extract_post_meta erkennt CVE/EUVD-IDs + Severity aus Score-Text.
  * get_feed stürzt bei Netzausfall NICHT ab, sondern liefert eine saubere
    Struktur mit ok-Flag (Fallback-Pfad des Frontends).
  * /api/dyk liefert valides JSON mit dem erwarteten Schema.
"""
from __future__ import annotations

import os
import sys


def test_strip_html():
    from antbb import threatfeed
    raw = '<p>Neue <b>CVE</b>&nbsp;entdeckt</p><br>Details <a href="x">hier</a>'
    out = threatfeed.strip_html(raw)
    assert "<" not in out and ">" not in out, out
    assert "CVE" in out and "entdeckt" in out, out
    assert "  " not in out, out
    print("[ok] strip_html")


def test_merge_and_sort():
    from antbb import threatfeed
    cves = [{"kind": "cve", "id": "CVE-2026-1", "text": "alt", "date": "2026-10-01T00:00:00.000"}]
    posts = [{"kind": "mastodon", "text": "neu", "date": "2026-10-20T00:00:00.000Z"},
             {"kind": "mastodon", "text": "", "date": "2026-10-22T00:00:00.000Z"}]
    merged = threatfeed.merge_and_sort(cves, posts, max_items=10)
    assert len(merged) == 2, merged
    assert merged[0]["text"] == "neu", merged
    print("[ok] merge_and_sort (sort + empty-filter)")


def test_post_meta():
    from antbb import threatfeed
    cid, sev = threatfeed._extract_post_meta(
        "🚨 EUVD-2026-107808 📊 Score: 8.5/10 (CVSS v3.1)")
    assert cid == "EUVD-2026-107808" and sev == "HIGH", (cid, sev)
    cid, sev = threatfeed._extract_post_meta("nur text")
    assert cid is None and sev is None
    print("[ok] post-meta (CVE/EUVD-ID + Severity aus Score)")


def test_get_feed_no_crash():
    from antbb import threatfeed
    os.environ["ANTBB_FEED_TTL"] = "1"
    threatfeed._CACHE["payload"] = None
    threatfeed._CACHE["ts"] = 0.0
    threatfeed._fetch_nvd = lambda cfg: []
    threatfeed._fetch_mastodon = lambda cfg: []
    res = threatfeed.get_feed(force=True)
    assert isinstance(res, dict), res
    assert res["ok"] is False, res
    assert res["items"] == [], res
    print("[ok] get_feed graceful (ok=False, kein Crash)")


def test_get_feed_with_data():
    from antbb import threatfeed
    threatfeed._CACHE["payload"] = None
    threatfeed._CACHE["ts"] = 0.0
    threatfeed._fetch_nvd = lambda cfg: [
        {"kind": "cve", "id": "CVE-2026-9", "text": "RCE", "severity": "CRITICAL",
         "date": "2026-10-22T10:00:00.000",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9"}]
    threatfeed._fetch_mastodon = lambda cfg: [
        {"kind": "mastodon", "text": "neuer exploit", "author": "@a",
         "date": "2026-10-21T10:00:00.000Z", "url": "https://mastodon.social/x"}]
    res = threatfeed.get_feed(force=True)
    assert res["ok"] is True, res
    assert len(res["items"]) == 2, res
    assert res["items"][0]["id"] == "CVE-2026-9", res
    print("[ok] get_feed merge (ok=True, sortiert)")


def test_endpoint():
    from fastapi.testclient import TestClient
    from antbb import threatfeed
    threatfeed._fetch_nvd = lambda cfg: []
    threatfeed._fetch_mastodon = lambda cfg: []
    threatfeed._CACHE["payload"] = None
    from antbb.web.app import app
    client = TestClient(app)
    r = client.get("/api/dyk?force=true")
    assert r.status_code == 200, r.status_code
    data = r.json()
    assert "ok" in data and "items" in data and "sources" in data, data
    print("[ok] /api/dyk antwortet mit valider Struktur")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    test_strip_html()
    test_merge_and_sort()
    test_post_meta()
    test_get_feed_no_crash()
    test_get_feed_with_data()
    test_endpoint()
    print("\nAlle DYK-Tests GRÜN.")
