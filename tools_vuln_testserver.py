"""BEWUSST verwundbarer, rein LOKALER Mini-Testserver (nur 127.0.0.1).

NUR für den antbb-Verifikations-/Fuzz-Smoke-Test. Keine echten Daten, keine Secrets.
Baut absichtlich ein paar harmlose, lokale Schwachstellen ein, damit die
aktiven Verifikations-Checks und das Fuzzing nachweisbar anschlagen:
  * Reflected XSS  : /?q=<marker>        (reflektiert UNESCAPED)
  * SQLi error     : /?q=1'              (liefert MySQL-Fehlersignatur)
  * Open Redirect  : /?next=<url>         (302 Location = <url>)
  * Path Traversal : /?file=../etc/passwd (liefert root:...:0:0:)
  * Exposed Git    : /.git/HEAD           (ref: refs/heads/main)
  * CORS           : reflektiert Origin in Access-Control-Allow-Origin
  * Missing-Auth   : /admin               (200 + "admin dashboard"/"logout")
  * Fuzz-Targets   : /login, /backup/, /api  (andere Signatur als Catch-all-Normal)

Zusätzlich: CatchAllH – simuliert einen WAF-/SPA-Catch-all (jeder Pfad →
dieselbe 200-HTML-Seite). Für den Nachweis, dass die Fuzz-Baseline greift.
"""
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

NORMAL = b"<html><head><title>antbb testbed</title></head><body><h1>antbb testbed</h1><p>ok</p></body></html>"
CATCHALL = "<html><head><title>Please wait</title></head><body><h1>Einen Moment bitte...</h1><p>anti-bot</p></body></html>".encode("utf-8")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # ruhig bleiben
        pass

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        origin = self.headers.get("Origin")
        if origin:  # CORS-Fehlkonfiguration: Origin reflektieren
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        vals = [v for lst in q.values() for v in lst]

        # --- SSRF-Testbed: in-scope Canary-Endpunkt (reflektiert eindeutigen Marker) ---
        if path.startswith("/antbb-ssrf-canary-"):
            m = q.get("m", [""])[0]
            return self._send(200, ("canary " + m).encode(), "text/plain")
        # --- SSRF-Testbed: serverseitiger Fetch eines url-ähnlichen Parameters ---
        SSRF_PARAMS = ("url", "uri", "u", "fetch", "image", "img", "imageurl",
                       "image_url", "webhook", "callback", "src", "source",
                       "load", "feed", "link", "proxy", "data")
        fetchable = None
        for k in SSRF_PARAMS:
            if k in q and q[k] and q[k][0].startswith(("http://", "https://")):
                fetchable = q[k][0]
                break
        if fetchable is not None:
            import urllib.request
            try:
                with urllib.request.urlopen(fetchable, timeout=2) as resp:
                    fetched = resp.read(2048).decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                fetched = f"fetch-error {type(e).__name__}"
            body = ("<html><body><p>server-side fetch result: " + fetched +
                    "</p></body></html>").encode()
            return self._send(200, body)

        if path == "/.git/HEAD":
            return self._send(200, b"ref: refs/heads/main\n", "text/plain")
        if path == "/.git/config":
            return self._send(200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain")
        if path == "/.env":
            return self._send(200, b"APP_ENV=production\nDEBUG=false\n", "text/plain")
        if path in ("/admin", "/admin/"):
            return self._send(200, b"<html><body><h1>Admin Dashboard</h1><a>logout</a></body></html>")
        if path in ("/login", "/login/"):
            return self._send(200, b"<html><head><title>Login</title></head><body><h1>Login</h1><form>user</form></body></html>")
        if path in ("/backup", "/backup/"):
            return self._send(200, b"<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><a>dump.sql</a></body></html>")
        if path in ("/api", "/api/v1"):
            return self._send(200, b'{"ok":true,"service":"antbb-testbed","version":1}\n', "application/json")

        # Open Redirect
        if "next" in q:
            return self._send(302, b"", extra={"Location": q["next"][0]})
        # Path Traversal / LFI
        if "file" in q and "etc/passwd" in q["file"][0]:
            return self._send(200, b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", "text/plain")
        # Reflected XSS (unescaped) – Marker zuerst prüfen (enthält auch ')
        for v in vals:
            if "<antbb>" in v:
                body = ("<html><body><p>Suche: " + v + "</p></body></html>").encode()
                return self._send(200, body)
        # SQLi error-based: einzelnes Hochkomma
        for v in vals:
            if "'" in v and "AND '1'='" not in v:
                body = b"<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>"
                return self._send(200, body)
        # SQLi boolean-based
        for v in vals:
            if "AND '1'='1" in v:
                return self._send(200, NORMAL + b"<!-- extra content for TRUE branch " + b"x"*200 + b" -->")
            if "AND '1'='2" in v:
                return self._send(200, NORMAL)
        # Marker-Reflexion für Fuzz-Parameter (escaped-artig, aber sichtbar)
        for v in vals:
            if "antbbFUZZ" in v or "antbb" in v:
                esc = html.escape(v)
                body = (f"<html><body><p>Suche: {esc}</p></body></html>").encode()
                return self._send(200, body)
        return self._send(200, NORMAL)


class CatchAllH(BaseHTTPRequestHandler):
    """Simuliert einen JITTERNDEN SPA-/Anti-Bot-Catch-all.

    JEDER Pfad → dieselbe Platzhalterseite, aber mit schwankender Content-Length
    (>100 Byte Jitter durch wechselnde Füll-Kommentare mit Zufallszahlen) und
    gelegentlich einem 301. Genau dieser Jitter liess früher längenbasierte
    Treffer durchrutschen; die Ähnlichkeits-Baseline muss ihn tolerieren.
    """
    _n = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        import random
        CatchAllH._n += 1
        # Gelegentlich 301 (wie reale Anti-Bot-Seiten) – ohne Marker-Location.
        if CatchAllH._n % 5 == 0:
            self.send_response(301)
            self.send_header("Location", "/")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return
        # Jitter: Füll-Kommentar mit Zufallszahlen variabler Länge (>100 Byte).
        pad = "".join(str(random.randint(0, 9)) for _ in range(random.randint(120, 500)))
        body = CATCHALL + (f"<!-- req {CatchAllH._n} nonce {pad} -->").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8911
    mode = sys.argv[2] if len(sys.argv) > 2 else "vuln"
    handler = CatchAllH if mode == "catchall" else H
    print(f"serving 127.0.0.1:{port} mode={mode}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
