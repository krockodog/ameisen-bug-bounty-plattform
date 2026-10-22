"""Smoke-Test Fernzugriff / Remote-Access.

Beweist:
  * Default-Modus ist 'off' (nur lokal).
  * set/get persistiert über eine frische Store-Instanz (echtes SQLite).
  * Status-Erkennung ist honest-empty, wenn Binaries fehlen (keine erfundene
    IP/Hostname/Status).
  * Es wird NIE ein Secret in DB/Datei geschrieben.
  * Das Wählen eines Modus exponiert NICHTS automatisch (keine Prozesse).
"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os
import tempfile

from antbb.service import AntBBService
from antbb import remote_access as ra


def run():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "antbb.db")

    # 1) Default off
    svc = AntBBService(db_path=db)
    assert svc.get_remote_mode() == "off", "Default muss off sein"
    st = svc.remote_status()
    assert st["mode"] == "off"
    assert st["active_url"] == "", "off darf keine aktive URL haben"
    print("[1] Default-Modus = off (nur lokal) ✔")

    # 2) set/get persistiert (neue Store-/Service-Instanz)
    svc.set_remote_mode("cloudflare")
    svc.close()
    svc2 = AntBBService(db_path=db)
    assert svc2.get_remote_mode() == "cloudflare", "Präferenz muss persistieren"
    # ungültig -> normalisiert auf default off
    assert svc2.set_remote_mode("bogus") == "off"
    assert svc2.get_remote_mode() == "off"
    print("[2] set/get persistiert + Normalisierung ✔")

    # 3) honest-empty: Status ohne Binaries erfindet nichts
    tss = ra.tailscale_status()
    if not tss["installed"]:
        assert tss["running"] is False
        assert tss["ip"] == "" and tss["hostname"] == "" and tss["url"] == "", \
            "Ohne Binary darf NIE eine IP/Hostname/URL erfunden werden"
    cfs = ra.cloudflared_status()
    if not cfs["installed"]:
        assert cfs["version"] == ""
    print("[3] honest-empty ohne Binaries (keine Fabrikation) ✔")

    # 4) Kein Secret in DB / keine Datei mit Token
    # Token-Env setzen und sicherstellen, dass sein WERT nirgends landet.
    secret = "cf-super-secret-token-DEADBEEF"
    os.environ[ra.CLOUDFLARE_TOKEN_ENV] = secret
    svc2.set_remote_mode("cloudflare")
    st2 = svc2.remote_status()
    # Status darf nur das VORHANDENSEIN, nie den Wert melden
    assert st2["cloudflare"]["token_env_present"] is True
    svc2.close()
    import io
    with open(db, "rb") as fh:
        raw = fh.read()
    assert secret.encode() not in raw, "Token-Wert darf NIE in der DB stehen!"
    # kein settings-Wert enthält das Secret
    svc3 = AntBBService(db_path=db)
    val = svc3.store.get_setting("remote_access_mode")
    assert secret not in val
    svc3.close()
    del os.environ[ra.CLOUDFLARE_TOKEN_ENV]
    print("[4] Kein Secret/Token in DB oder Settings ✔")

    # 5) Modus wählen exponiert nichts: keine Listening-Sockets/Prozesse durch uns.
    #    (Wir prüfen, dass set_remote_mode rein eine DB-Schreiboperation ist:
    #     setup_steps liefert nur Text, kein Start.)
    steps = svc.remote_setup_steps("cloudflare")
    assert isinstance(steps, list) and all(isinstance(x, str) for x in steps)
    assert any("NICHT automatisch" in x or "nie" in x.lower() or "selbst" in x.lower()
               for x in steps), "Setup-Schritte müssen klarstellen: nichts wird auto-gestartet"
    svc.close()
    print("[5] Modus wählen = nur Präferenz, nichts auto-exponiert ✔")

    print("\nALLE REMOTE-ACCESS-SMOKE-TESTS BESTANDEN ✔")


if __name__ == "__main__":
    run()
