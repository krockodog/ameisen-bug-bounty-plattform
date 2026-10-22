"""Integrations-Smoke-Test der optionalen Auth (ANTBB_AUTH=1) via TestClient.

Prueft: unauth -> Redirect/401; Login mit Bootstrap-Admin; Session-Zugriff;
Rollen-Gate (viewer darf keine human-only brain-Aktion).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANTBB_NO_LLM"] = "1"
os.environ["ANTBB_AUTH"] = "1"
os.environ["ANTBB_ADMIN_USER"] = "rootadmin"
os.environ["ANTBB_ADMIN_PASSWORD"] = "AdminPass!234"
os.environ["ANTBB_DB"] = "/tmp/antbb_test_webauth_mw.db"
if os.path.exists("/tmp/antbb_test_webauth_mw.db"):
    os.remove("/tmp/antbb_test_webauth_mw.db")

from fastapi.testclient import TestClient
from antbb.web.app import app, svc
from antbb import webauth


def run():
    with TestClient(app) as client:
        client.follow_redirects = False
        # unauth -> HTML redirect, API 401, aber /login + static frei
        assert client.get("/").status_code in (302, 303, 307)
        assert client.get("/api/targets").status_code == 401
        assert client.get("/login").status_code == 200

        # Bootstrap-Admin wurde beim Startup angelegt
        assert svc.store.get_user("rootadmin") is not None

        # Login
        r = client.post("/login", data={"username": "rootadmin",
                                         "password": "AdminPass!234", "next": "/"})
        assert r.status_code in (302, 303)
        cookie = r.cookies.get(webauth.COOKIE_NAME)
        assert cookie, "Session-Cookie fehlt"
        hdr = {"Cookie": f"{webauth.COOKIE_NAME}={cookie}"}
        assert client.get("/", headers=hdr).status_code == 200
        assert client.get("/api/targets", headers=hdr).status_code == 200

        # viewer anlegen + Rollen-Gate testen
        webauth.create_user(svc.store, "viewuser", "ViewPass!234", role="viewer")
        rv = client.post("/login", data={"username": "viewuser",
                                         "password": "ViewPass!234", "next": "/"})
        vcookie = rv.cookies.get(webauth.COOKIE_NAME)
        vhdr = {"Cookie": f"{webauth.COOKIE_NAME}={vcookie}"}
        # human-only brain-Aktion: viewer -> 403
        assert client.request("DELETE", "/api/brain/all", headers=vhdr).status_code == 403
        # normaler Lesezugriff: viewer -> 200
        assert client.get("/api/targets", headers=vhdr).status_code == 200

    # Aufraeumen der Test-Env, damit andere Tests im selben Prozess nicht erben
    os.environ.pop("ANTBB_AUTH", None)
    print("[test_web_auth] OK — Redirect/401, Login, Session, Rollen-Gate.")


if __name__ == "__main__":
    run()
