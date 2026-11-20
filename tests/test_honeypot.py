"""Tests for the Decoy Honeypot Lab.

Run from the repo root::

    python3 -m unittest discover -s tests -v
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import honeypot  # noqa: E402
from analyze import build_summary, load_events, render_html  # noqa: E402
from src.logger import HoneypotLogger, make_event  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _recv_until(sock, marker, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


class TestFakeShell(unittest.TestCase):
    def test_known_commands_return_canned_output(self):
        self.assertIn("/home/user", honeypot.fake_shell_response("pwd"))
        self.assertIn("user", honeypot.fake_shell_response("whoami"))
        self.assertIn("Desktop", honeypot.fake_shell_response("ls"))

    def test_unknown_command_is_rejected_not_executed(self):
        out = honeypot.fake_shell_response("rm -rf /")
        self.assertIn("command not found", out)
        # The host must be untouched: no file was created, nothing ran.
        self.assertFalse(os.path.exists("/tmp/honeypot_pwned_marker"))

    def test_no_shell_escape_via_injection(self):
        # Classic injection strings must be treated as plain unknown
        # commands — never executed, never echoed as a shell would.
        for evil in ("ls; id", "pwd && cat /etc/passwd", "$(whoami)",
                     "`id`", "ls | cat", "whoami > /tmp/x"):
            out = honeypot.fake_shell_response(evil)
            self.assertIn("command not found", out, evil)
            self.assertNotIn("uid=", out)


class TestLogger(unittest.TestCase):
    def test_jsonl_and_sqlite_both_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = HoneypotLogger(f"{tmp}/h.jsonl", f"{tmp}/h.db")
            logger.log(make_event("login_attempt", "s1", "203.0.113.1",
                                  40000, username="root",
                                  password="123456"))
            with open(f"{tmp}/h.jsonl") as fh:
                lines = fh.read().strip().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["username"], "root")
            import sqlite3
            with sqlite3.connect(f"{tmp}/h.db") as conn:
                rows = conn.execute(
                    "SELECT username, password FROM events").fetchall()
            self.assertEqual(rows, [("root", "123456")])

    def test_stats_counts_top_passwords_and_per_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = HoneypotLogger(f"{tmp}/h.jsonl", f"{tmp}/h.db")
            for i, pw in enumerate(["123456", "123456", "password"]):
                logger.log(make_event("login_attempt", f"s{i}",
                                      "203.0.113.1", 40000 + i,
                                      username="root", password=pw))
                logger.log(make_event("command", f"s{i}", "203.0.113.1",
                                      40000 + i, command="ls"))
            stats = logger.stats()
            self.assertEqual(stats["total_login_attempts"], 3)
            self.assertEqual(stats["total_commands"], 3)
            self.assertEqual(stats["top_passwords"][0], ("123456", 2))
            self.assertEqual(
                stats["per_ip"]["203.0.113.1"]["login_attempts"], 3)
            self.assertIn("T1110.001", stats["mitre"])


class TestLiveHoneypot(unittest.TestCase):
    """Spin up the real listener on a random localhost port."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logger = HoneypotLogger(f"{self.tmp.name}/h.jsonl",
                                     f"{self.tmp.name}/h.db")
        self.port = _free_port()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen(5)
        self.stop = threading.Event()

        def serve():
            while not self.stop.is_set():
                try:
                    self.server.settimeout(0.5)
                    conn, addr = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=honeypot.handle_client,
                                 args=(conn, addr, self.logger),
                                 daemon=True).start()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.stop.set()
        self.server.close()
        # Give in-flight handler threads a moment to finish logging
        # before the temp log directory is removed.
        time.sleep(0.5)
        self.tmp.cleanup()

    def test_banner_is_fake_ssh(self):
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=5) as sock:
            banner = _recv_until(sock, b"\n")
        self.assertTrue(banner.startswith(b"SSH-2.0-OpenSSH_"),
                        banner)

    def test_full_session_is_logged_and_shell_is_fake(self):
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=5) as sock:
            _recv_until(sock, b"\n")
            sock.sendall(b"SSH-2.0-OpenSSH_8.2\r\n")
            _recv_until(sock, b"login as: ")
            sock.sendall(b"root\r\n")
            _recv_until(sock, b"password: ")
            sock.sendall(b"123456\r\n")
            prompt = _recv_until(sock, b"$ ")
            self.assertIn(b"Welcome", prompt)
            sock.sendall(b"pwd\r\n")
            out = _recv_until(sock, b"$ ")
            self.assertIn(b"/home/user", out)
            sock.sendall(b"exit\r\n")
            _recv_until(sock, b"logout")
        events = self.logger.load_events()
        attempts = [e for e in events if e["event"] == "login_attempt"]
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["username"], "root")
        self.assertEqual(attempts[0]["password"], "123456")
        commands = [e["command"] for e in events
                    if e["event"] == "command"]
        self.assertIn("pwd", commands)
        self.assertIn("exit", commands)


class TestAnalyzer(unittest.TestCase):
    def test_analyzer_counts_and_renders_report(self):
        events = [
            make_event("login_attempt", "s1", "203.0.113.1", 40001,
                       username="root", password="123456"),
            make_event("login_attempt", "s2", "203.0.113.2", 40002,
                       username="admin", password="admin"),
            make_event("command", "s1", "203.0.113.1", 40001,
                       command="ls"),
        ]
        summary = build_summary(events)
        self.assertEqual(summary["total_login_attempts"], 2)
        self.assertEqual(summary["unique_ips"], 2)
        self.assertEqual(summary["top_passwords"][0], ["123456", 1])
        html_report = render_html(summary)
        self.assertIn("Attacker Report", html_report)
        self.assertIn("T1110.001", html_report)
        self.assertIn("203.0.113.1", html_report)
        # No external JS: the report must be self-contained.
        self.assertNotIn("<script", html_report)

    def test_load_events_skips_bad_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as fh:
            fh.write('{"event": "login_attempt"}\nnot json\n\n')
            path = fh.name
        try:
            self.assertEqual(len(load_events(path)), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
