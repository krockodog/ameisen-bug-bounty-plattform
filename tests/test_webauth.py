"""Smoke-/Unit-Test fuer die optionale Auth-Schicht (antbb/webauth.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANTBB_DB"] = "/tmp/antbb_test_webauth.db"
if os.path.exists("/tmp/antbb_test_webauth.db"):
    os.remove("/tmp/antbb_test_webauth.db")

from antbb.store import Store
from antbb import webauth


def test_hash_roundtrip():
    h, salt, it = webauth.hash_password("GeheimesPasswort!")
    assert len(h) == 64 and len(salt) == 32
    assert webauth.verify_password("GeheimesPasswort!", h, salt, it)
    assert not webauth.verify_password("falsch", h, salt, it)
    # Klartext darf nirgends im Hash auftauchen
    assert "GeheimesPasswort" not in h


def test_user_lifecycle_and_roles():
    st = Store("/tmp/antbb_test_webauth.db")
    try:
        webauth.create_user(st, "admin1", "pw-admin-123", role="admin")
        webauth.create_user(st, "view1", "pw-view-123", role="viewer")
        assert st.count_users() == 2
        row = webauth.authenticate(st, "admin1", "pw-admin-123")
        assert row is not None and row["role"] == "admin"
        assert webauth.authenticate(st, "admin1", "wrong") is None
        # Session
        tok = webauth.start_session(st, row)
        sess = webauth.session_user(st, tok)
        assert sess is not None and sess["username"] == "admin1"
        st.delete_session(tok)
        assert webauth.session_user(st, tok) is None
    finally:
        st.close()


def test_auth_disabled_by_default():
    os.environ.pop("ANTBB_AUTH", None)
    assert webauth.auth_enabled() is False
    os.environ["ANTBB_AUTH"] = "1"
    assert webauth.auth_enabled() is True
    os.environ["ANTBB_AUTH"] = "0"
    assert webauth.auth_enabled() is False
    os.environ.pop("ANTBB_AUTH", None)


if __name__ == "__main__":
    test_hash_roundtrip()
    test_user_lifecycle_and_roles()
    test_auth_disabled_by_default()
    print("[test_webauth] OK — Hashing, Benutzer/Rollen, Sessions, Flag.")
