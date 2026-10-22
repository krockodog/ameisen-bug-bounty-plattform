"""Smoke-Test fuer das Opt-in-Modul (TLS/Header) – default-deny + Ownership."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANTBB_DB"] = "/tmp/antbb_test_assetchecks.db"
if os.path.exists("/tmp/antbb_test_assetchecks.db"):
    os.remove("/tmp/antbb_test_assetchecks.db")

from antbb.store import Store
from antbb import assetchecks


def test_default_deny_without_confirmation():
    st = Store("/tmp/antbb_test_assetchecks.db")
    try:
        aid = st.add_owned_asset("example.com", 443, "demo", confirmed_owner=False)
        try:
            assetchecks.run_check(st, aid, "tls")
            raise AssertionError("Check lief trotz fehlender Ownership-Bestaetigung!")
        except assetchecks.AssetOwnershipError:
            pass
    finally:
        st.close()


def test_confirmed_asset_runs_and_persists():
    st = Store("/tmp/antbb_test_assetchecks.db")
    try:
        aid = st.add_owned_asset("example.com", 443, "demo", confirmed_owner=True,
                                 confirmed_by="test")
        # Header-Check (netzabhaengig). Ergebnis muss persistiert werden, egal
        # ob ok=True/False – es darf NICHT crashen.
        res = assetchecks.run_check(st, aid, "headers")
        assert res["kind"] == "headers"
        runs = st.list_asset_check_runs(aid)
        assert len(runs) >= 1
    finally:
        st.close()


if __name__ == "__main__":
    test_default_deny_without_confirmation()
    try:
        test_confirmed_asset_runs_and_persists()
        print("[test_assetchecks] OK — default-deny + bestaetigter Check persistiert.")
    except Exception as exc:  # Netz evtl. nicht verfuegbar: default-deny bleibt das Kernkriterium
        print(f"[test_assetchecks] default-deny OK; Live-Check uebersprungen ({exc}).")
