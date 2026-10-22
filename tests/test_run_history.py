"""Smoke-Test fuer die persistente Run-Historie (store.run_history)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANTBB_DB"] = "/tmp/antbb_test_runhist.db"
if os.path.exists("/tmp/antbb_test_runhist.db"):
    os.remove("/tmp/antbb_test_runhist.db")

from antbb.store import Store


def test_add_and_list_run_history():
    st = Store("/tmp/antbb_test_runhist.db")
    try:
        tid = st.add_target("hist-target", "demo")
        st.add_run_history(run_id="r1", target_id=tid, target_name="hist-target",
                           mode="defensive", finding_count=3,
                           severity={"low": 3}, status="done", duration=1.5)
        st.add_run_history(run_id="r2", target_id=tid, target_name="hist-target",
                           mode="offensive", active=True, finding_count=0,
                           status="error", error="boom")
        rows = st.list_run_history()
        assert len(rows) == 2
        rows_t = st.list_run_history(target_id=tid)
        assert len(rows_t) == 2
        assert rows[0]["run_id"] in ("r1", "r2")
        statuses = {r["status"] for r in rows}
        assert statuses == {"done", "error"}
    finally:
        st.close()


if __name__ == "__main__":
    test_add_and_list_run_history()
    print("[test_run_history] OK — Historie persistiert und listet.")
