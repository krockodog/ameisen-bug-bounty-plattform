"""Smoke test: Cloudflare-Tunnel-Steuerung in remote_access (ohne echtes cloudflared)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os, tempfile, importlib
import antbb.remote_access as ra

ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1; print(f"  OK  {name}")
    else: fail += 1; print(f"  XX  {name}")

# 1) Oversight-Gate: Start ohne Oversight startet NICHTS.
r = ra.start_cloudflare_tunnel(oversight=False)
check("Start ohne Oversight blockiert", r["ok"] is False and r["running"] is False and "Oversight" in r["reason"])

# 2) honest runtime ohne laufenden Tunnel.
rt = ra.cloudflare_tunnel_runtime()
check("Runtime honest-empty", rt["running"] is False and rt["url"] == "")

# 3) status_for('cloudflare') enthält tunnel-Block + keine Exception.
st = ra.status_for("cloudflare")
check("status_for liefert cloudflare.tunnel", "tunnel" in st["cloudflare"])
check("status_for modes korrekt", set(st["modes"]) == {"off","tailscale","cloudflare"})

# 4) resolve_binary findet ein Binary im lokalen bin via ANTBB_BIN.
with tempfile.TemporaryDirectory() as d:
    fake = os.path.join(d, "cloudflared")
    open(fake, "w").write("#!/bin/sh\necho x\n"); os.chmod(fake, 0o755)
    os.environ["ANTBB_BIN"] = d
    importlib.reload(ra)
    check("resolve_binary findet lokales cloudflared", ra.resolve_binary("cloudflared") == fake)
    os.environ.pop("ANTBB_BIN", None)
    importlib.reload(ra)

# 5) Named-Tunnel ohne Token wird ehrlich abgelehnt (mit Oversight, aber kein Token).
os.environ.pop("CLOUDFLARE_TUNNEL_TOKEN", None)
# cloudflared evtl. nicht vorhanden -> dann greift zuerst die binary-Meldung; beide sind ehrlich-negativ
r2 = ra.start_cloudflare_tunnel(oversight=True, named=True)
check("Named-Tunnel ohne Token/Binary startet nichts", r2["ok"] is False and r2["running"] is False)

# 6) Secret-Disziplin: Zustandsdatei enthält NIE ein Token.
import json
sp = ra._state_path()
if os.path.exists(sp):
    txt = open(sp).read()
    check("State-Datei ohne Token", "CLOUDFLARE_TUNNEL_TOKEN" not in txt and "token" not in txt.lower())
else:
    check("State-Datei ohne Token (keine Datei)", True)

print("="*60)
print(f"ERGEBNIS: {ok}/{ok+fail} Checks OK")
raise SystemExit(1 if fail else 0)
