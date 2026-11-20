#!/usr/bin/env python3
"""
Decoy Fabric v2 — HTTP honeypot (fake admin login, Python stdlib).

A second decoy surface alongside SSH: a fake admin login page on
port 8080. It looks like a generic admin panel, logs every
credential submitted to it, then shows a fake dashboard. Canary
tokens are planted in HTML comments — invisible in the browser,
visible to anyone viewing source, which is what an attacker does.

Safety contract:
* Bind is 127.0.0.1 by default, port 8080. Lab only.
* Credentials are logged, never checked against anything real.
* No template rendering, no database, no file serving beyond the
  two canned pages. User input is HTML-escaped on echo and never
  executed, never passed to a shell, never used in a query.

Usage::

    python3 http_honeypot.py                  # 127.0.0.1:8080
    python3 http_honeypot.py --port 8080 --log logs/honeypot.jsonl
    # then: curl http://127.0.0.1:8080/  (or open in a browser)
"""

from __future__ import annotations

import argparse
import html
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src.canary import html_comment_canaries
from src.logger import HoneypotLogger, make_event

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Admin Panel — Sign in</title>
<style>body{font-family:system-ui,Arial,sans-serif;max-width:420px;
margin:4em auto}input{display:block;width:100%;padding:8px;margin:6px 0}
button{padding:8px 16px;background:#1d4ed8;color:#fff;border:0}</style>
</head><body>
<h1>Admin Panel</h1>
<p>Sign in to continue.</p>
<form method="post" action="/login">
<label>Username <input name="username" autocomplete="off"></label>
<label>Password <input type="password" name="password"></label>
<button type="submit">Sign in</button>
</form>
<p><small>Internal system — authorised users only.</small></p>
{canaries}
</body></html>
"""

DASHBOARD_PAGE = """<!DOCTYPE html>
<html><head><title>Admin Dashboard</title></head><body>
<h1>Dashboard</h1>
<p>Welcome, {user}. System status: <b>OK</b></p>
<ul><li>Users: 42</li><li>Uptime: 12 days</li><li>Alerts: 0</li></ul>
<p><a href="/">Sign out</a></p>
{canaries}
</body></html>
"""


def make_handler(logger: HoneypotLogger):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep stdout clean
            pass

        def _log_http(self, event, path, **fields):
            session_id = uuid.uuid4().hex[:8]
            ip = self.client_address[0]
            logger.log(make_event(event, session_id, ip,
                                  self.client_address[1],
                                  http_path=path, **fields))

        def _send(self, body: str, status: int = 200):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlparse(self.path).path
            self._log_http("http_request", path, http_method="GET")
            if path in ("/", "/login", "/admin", "/wp-admin", "/wp-login.php"):
                # .replace, not .format: the CSS braces would break .format.
                self._send(LOGIN_PAGE.replace(
                    "{canaries}", html_comment_canaries()))
            elif path == "/dashboard":
                self._send(DASHBOARD_PAGE.replace(
                    "{user}", "admin").replace(
                    "{canaries}", html_comment_canaries()))
            else:
                self._send("<h1>404 Not Found</h1>", status=404)

        def do_POST(self):
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            fields = parse_qs(raw)
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]
            if path == "/login":
                self._log_http("http_login_attempt", path,
                               http_method="POST",
                               username=username, password=password)
                self._send(DASHBOARD_PAGE.replace(
                    "{user}", html.escape(username or "admin")).replace(
                    "{canaries}", html_comment_canaries()))
            else:
                self._send("<h1>404 Not Found</h1>", status=404)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decoy Fabric v2 — HTTP honeypot (fake admin login).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", default="logs/honeypot.jsonl")
    parser.add_argument("--db", default="logs/honeypot.db")
    args = parser.parse_args()
    logger = HoneypotLogger(args.log, args.db)
    server = ThreadingHTTPServer((args.host, args.port),
                                 make_handler(logger))
    print(f"[+] HTTP honeypot listening on {args.host}:{args.port} "
          f"(fake admin login)", flush=True)
    print("[+] Credentials are logged, never verified. Lab only.",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down HTTP honeypot.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
