"""Built-in vulnerable localhost lab for engine validation.

All vulnerabilities are intentionally planted. Runs on 127.0.0.1:0 (ephemeral port)
by default. No false-positive sources: clean endpoints return deterministic safe output.
"""

import hashlib
import http.server
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.parse
from io import BytesIO
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(tempfile.gettempdir(), "webbreach_lab.db")
SECRET_PATH = os.path.join(tempfile.gettempdir(), "lab_secret.txt")
SMTP_MARKER = "WB-SMTP-MARKER-7f3a"

_planted_secret = "TOP_SECRET_F4G_a1b2c3d4"
_planted_sqli_row = {"id": 1, "name": "admin", "secret": _planted_secret}


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (name, secret) VALUES (?, ?)", ("admin", _planted_secret))
        conn.commit()
    return conn


def _write_secret():
    with open(SECRET_PATH, "w") as f:
        f.write(_planted_secret)


class LabHandler(http.server.BaseHTTPRequestHandler):
    """Handler with planted vulns + clean endpoints."""

    _store = []  # stored XSS payloads
    _csrf_tokens = set()

    def log_message(self, format, *args):
        pass  # silence logs during tests

    def _send(self, code, body, content_type="text/html", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # ------------------------------------------------------------------
    # Clean endpoints (no false positives)
    # ------------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # --- clean landing ---
        if path == "/":
            self._send(200, "<html><body><h1>WebBreach Lab</h1><p>OK</p></body></html>")
            return

        # --- clean JSON endpoint ---
        if path == "/api/health":
            self._json(200, {"status": "ok", "version": "1.0.0"})
            return

        # --- SQL Injection (error-based + time-based blind) ---
        if path == "/sqli":
            param = qs.get("id", ["1"])[0]
            # time-based blind: single-quote triggers sleep when t param present
            if "sleep" in param.lower() or (param.endswith("'") and "t" in qs):
                time.sleep(0.3)
                self._json(200, {"data": []})
                return
            conn = _get_db()
            try:
                row = conn.execute(f"SELECT * FROM users WHERE id={param}").fetchone()
                if row:
                    self._json(200, {"data": [dict(row)]})
                else:
                    self._json(200, {"data": []})
            except Exception as e:
                self._json(200, {"error": str(e)})
            finally:
                conn.close()
            return

        # --- POST sqli ---
        if path == "/sqli_post":
            body = self._read_body()
            try:
                data = json.loads(body)
            except Exception:
                data = urllib.parse.parse_qs(body.decode())
                data = {k: v[0] for k, v in data.items()}
            name = data.get("name", "")
            conn = _get_db()
            try:
                row = conn.execute(f"SELECT * FROM users WHERE name='{name}'").fetchone()
                if row:
                    self._json(200, {"data": [dict(row)]})
                else:
                    self._json(200, {"data": []})
            except Exception as e:
                self._json(200, {"error": str(e)})
            finally:
                conn.close()
            return

        # --- Reflected XSS ---
        if path == "/xss":
            q = qs.get("q", ["hello"])[0]
            self._send(200, f"<html><body><p>Search results for: {q}</p></body></html>")
            return

        # --- Stored XSS ---
        if path == "/xss/stored":
            html = "<html><body><h2>Guestbook</h2><ul>"
            for p in LabHandler._store:
                html += f"<li>{p}</li>"
            html += '</ul><form method="GET" action="/xss/stored"><input name="msg"><button>Post</button></form></body></html>'
            self._send(200, html)
            return

        if path == "/xss/stored/add":
            msg = qs.get("msg", [""])[0]
            if msg:
                LabHandler._store.append(msg)
            self._send(302, "", extra_headers={"Location": "/xss/stored"})
            return

        # --- CSRF (no token, no same-site) ---
        if path == "/csrf":
            self._send(200,
                '<html><body>'
                '<form method="POST" action="/csrf/transfer">'
                '<input name="to" value="attacker"><input name="amount" value="1000">'
                '<button>Transfer</button></form>'
                '</body></html>',
                extra_headers={"Set-Cookie": "session=abc123"})
            return

        # --- SSRF (fetches URL param) ---
        if path == "/ssrf":
            url = qs.get("url", [""])[0]
            if not url:
                self._send(200, "<p>Provide ?url=</p>")
                return
            try:
                if url.startswith("/") or url.startswith("file://"):
                    fp = url.replace("file://", "") or "/etc/hostname"
                    with open(fp, "r") as f:
                        body = f.read(256)
                    self._send(200, f"<pre>{body}</pre>")
                else:
                    import urllib.request as ur
                    with ur.urlopen(url, timeout=2) as r:
                        body = r.read(256).decode(errors="replace")
                    self._send(200, f"<pre>{body}</pre>")
            except Exception as e:
                self._send(200, f"<pre>Error: {e}</pre>")
            return

        # --- SSTI ---
        if path == "/ssti":
            tpl = qs.get("name", ["World"])[0]
            # simplistic Jinja2-style rendering
            result = re.sub(r"\{\{(.+?)\}\}", lambda m: str(eval(m.group(1))), tpl)
            self._send(200, f"<p>Hello, {result}!</p>")
            return

        # --- XXE ---
        if path == "/xxe":
            self._send(200, '<p>POST XML to /xxe</p>')
            return

        # --- Open Redirect ---
        if path == "/redirect":
            dest = qs.get("next", ["/"])[0]
            self._send(302, "", extra_headers={"Location": dest})
            return

        # --- Header Injection ---
        if path == "/header_inject":
            val = qs.get("val", ["safe"])[0]
            # Simulate vulnerable header reflection — pass value as-is
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # Intentionally unsanitized: allows CRLF injection in real HTTP servers
            raw_header = f"X-Custom: {val}\r\n"
            self.send_header("X-Custom", val)
            self.end_headers()
            self.wfile.write(b"<p>OK</p>")
            return

        # --- Path Traversal ---
        if path == "/traversal":
            self._send(200, '<p>POST filename to /traversal</p>')
            return

        # --- Command Injection (reflected + simulated exec) ---
        if path == "/cmd":
            host = qs.get("host", ["localhost"])[0]
            output = f"Pinging {host}..."
            # Simulate: if shell metacharacters present, "execute" injected command
            import re as _re
            m = _re.search(r'(?:;\s*|`\s*)echo\s+(WBCMD_\w+)', host)
            if m:
                output += f"\n{m.group(1)}"
            self._send(200, f"<pre>{output}</pre>")
            return

        # --- NoSQL injection ---
        if path == "/nosql":
            self._send(200, '<p>POST JSON to /nosql</p>')
            return

        # --- Cookie (insecure) ---
        if path == "/cookie":
            self._send(200, "<p>Logged in</p>",
                       extra_headers={"Set-Cookie": "token=secret123; Path=/"})
            return

        # --- HTTP Request Smuggling (CL/TE) — server responds normally ---
        if path == "/smuggle":
            self._send(200, "<p>Smuggle target alive</p>")
            return

        self._send(404, "<p>Not found</p>")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/sqli_post":
            body = self._read_body()
            try:
                data = json.loads(body)
            except Exception:
                data = urllib.parse.parse_qs(body.decode())
                data = {k: v[0] for k, v in data.items()}
            name = data.get("name", "")
            conn = _get_db()
            try:
                row = conn.execute(f"SELECT * FROM users WHERE name='{name}'").fetchone()
                if row:
                    self._json(200, {"data": [dict(row)]})
                else:
                    self._json(200, {"data": []})
            except Exception as e:
                self._json(200, {"error": str(e)})
            finally:
                conn.close()
            return

        if path == "/xxe":
            body = self._read_body()
            try:
                root = ET.fromstring(body)
                # intentionally extract DOCTYPE entities
                items = [child.text or "" for child in root]
                self._json(200, {"entities": items})
            except Exception as e:
                self._json(200, {"error": str(e)})
            return

        if path == "/traversal":
            body = self._read_body()
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            fname = data.get("file", "index.html")
            # path traversal — no sanitization
            base = tempfile.gettempdir()
            target = os.path.join(base, fname)
            try:
                with open(target, "r") as f:
                    content = f.read(256)
                self._json(200, {"content": content})
            except Exception as e:
                self._json(200, {"error": str(e)})
            return

        if path == "/nosql":
            body = self._read_body()
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            # NoSQL-style $where injection: if query contains $where, dump all
            query = data.get("query", {})
            if isinstance(query, dict) and "$where" in query:
                conn = _get_db()
                rows = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
                conn.close()
                self._json(200, {"data": rows})
            else:
                self._json(200, {"data": []})
            return

        self._send(404, "<p>Not found</p>")

    do_PUT = do_POST


class LabServer:
    """Threaded HTTP server wrapper for the vulnerable lab."""

    def __init__(self, host="127.0.0.1", port=0):
        _write_secret()
        _get_db().close()
        self.server = http.server.HTTPServer((host, port), LabHandler)
        self.port = self.server.server_address[1]
        self.host = host
        self._thread = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def start(self):
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        time.sleep(0.1)  # let server bind

    def stop(self):
        self.server.shutdown()
        if self._thread:
            self._thread.join(timeout=2)
        # cleanup
        for p in (DB_PATH, SECRET_PATH):
            try:
                os.unlink(p)
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *a):
        self.stop()
