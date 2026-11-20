"""Tests for Decoy Fabric v2 — adaptive deception, fingerprinting,
canaries, clustering, HTTP honeypot.

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
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyze_v2 import build_campaign_report  # noqa: E402
from src.adaptive import get_policy, load_policies  # noqa: E402
from src.canary import (  # noqa: E402
    canary_for_command, find_canary, is_canary_access, list_canaries,
    make_canary_event)
from src.clustering import (  # noqa: E402
    cluster_sessions, jaccard, session_similarity)
from src.fingerprint import (  # noqa: E402
    build_session_features, classify_session, fingerprint_sessions)
from src.logger import make_event  # noqa: E402
import honeypot_v2  # noqa: E402
from http_honeypot import make_handler  # noqa: E402
from src.logger import HoneypotLogger  # noqa: E402

BASE = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)


def _ev(t, event, sid, ip, **kw):
    d = {"timestamp": (BASE + timedelta(seconds=t)).isoformat(),
         "event": event, "session_id": sid, "src_ip": ip,
         "src_port": 40000}
    d.update(kw)
    return d


def _hydra_session(sid="h1", ip="203.0.113.11", t0=0):
    evs = [_ev(t0, "session_start", sid, ip,
               client_banner="SSH-2.0-libssh_0.9.6")]
    for i, pw in enumerate(["123456", "password", "admin", "root", "qwerty"]):
        evs.append(_ev(t0 + 1 + i, "login_attempt", sid, ip,
                       username="root", password=pw))
    evs.append(_ev(t0 + 6, "session_end", sid, ip, username="root",
                   duration_seconds=6.0))
    return evs


def _manual_session(sid="m1", ip="198.51.100.77", t0=1000):
    cmds = ["ls", "pwd", "whoami", "lss", "cat notes.txt"]
    evs = [_ev(t0, "session_start", sid, ip,
               client_banner="SSH-2.0-OpenSSH_8.2"),
           _ev(t0 + 5, "login_attempt", sid, ip,
               username="alice", password="Winter2026!")]
    for i, c in enumerate(cmds):
        evs.append(_ev(t0 + 12 + i * 7, "command", sid, ip, command=c))
    evs.append(_ev(t0 + 50, "session_end", sid, ip, username="alice",
                   duration_seconds=50.0))
    return evs


class TestFingerprint(unittest.TestCase):
    def test_hydra_fast_sequential_no_commands(self):
        fps = fingerprint_sessions(_hydra_session())
        self.assertEqual(fps["h1"]["label"], "hydra")
        self.assertGreaterEqual(fps["h1"]["confidence"], 0.7)

    def test_manual_slow_exploratory_with_typo(self):
        fps = fingerprint_sessions(_manual_session())
        self.assertEqual(fps["m1"]["label"], "manual")
        self.assertTrue(fps["m1"]["has_typo"])

    def test_scanner_no_login(self):
        evs = [_ev(0, "session_start", "s1", "203.0.113.9",
                   client_banner="SSH-2.0-Nmap"),
               _ev(1, "session_end", "s1", "203.0.113.9",
                   duration_seconds=1.0)]
        fps = fingerprint_sessions(evs)
        self.assertEqual(fps["s1"]["label"], "scanner")

    def test_sqlmap_sql_in_command(self):
        evs = _manual_session()
        evs.insert(3, _ev(1015, "command", "m1", "198.51.100.77",
                          command="curl http://x/?id=1' OR 1=1 --"))
        fps = fingerprint_sessions(evs)
        self.assertEqual(fps["m1"]["label"], "sqlmap")

    def test_hydra_vs_manual_features_differ(self):
        h = build_session_features(_hydra_session())["h1"]
        m = build_session_features(_manual_session())["m1"]
        self.assertLess(h["mean_attempt_gap_s"], m["mean_command_gap_s"])
        self.assertEqual(h["n_commands"], 0)
        self.assertGreater(m["exploratory_commands"], 2)


class TestAdaptive(unittest.TestCase):
    def test_policy_changes_banner_and_delay(self):
        hydra = get_policy("hydra")
        manual = get_policy("manual")
        self.assertNotEqual(hydra.banner, manual.banner)
        self.assertGreater(hydra.response_delay_s, manual.response_delay_s)
        self.assertEqual(hydra.response_delay_s, 2.0)

    def test_hydra_lockout_manual_no_lockout(self):
        self.assertTrue(get_policy("hydra").should_lockout(3))
        self.assertFalse(get_policy("hydra").should_lockout(2))
        self.assertFalse(get_policy("manual").should_lockout(100))

    def test_scanner_fake_ports_and_rich_filesystem(self):
        self.assertIn(3306, get_policy("scanner").fake_open_ports)
        manual = get_policy("manual")
        self.assertIn(".aws", manual.ls_output("ls"))
        self.assertNotIn(".aws", get_policy("hydra").ls_output("ls"))

    def test_unknown_label_falls_back_to_default(self):
        self.assertEqual(get_policy("no-such-label").label, "default")

    def test_adaptive_state_fingerprints_ip_after_fast_attempts(self):
        state = honeypot_v2.AdaptiveState(load_policies())
        for i in range(3):
            state.record_attempt("203.0.113.11", "123456", 1000.0 + i)
        rec = state.by_ip["203.0.113.11"]
        self.assertEqual(rec["label"], "hydra")
        self.assertTrue(state.policy_for_ip("203.0.113.11").should_lockout(3))


class TestCanary(unittest.TestCase):
    def test_canary_list_and_lookup(self):
        self.assertGreaterEqual(len(list_canaries()), 6)
        self.assertEqual(find_canary("/home/user/.aws/credentials")["id"],
                         "CANARY-AWS-01")
        self.assertIsNone(find_canary("/home/user/notes.txt"))

    def test_canary_access_via_cat(self):
        self.assertTrue(is_canary_access("cat /home/user/.aws/credentials"))
        self.assertTrue(is_canary_access("cat ~/.aws/credentials"))
        self.assertFalse(is_canary_access("cat notes.txt"))
        self.assertFalse(is_canary_access("ls .aws"))

    def test_canary_event_is_high_severity(self):
        canary = canary_for_command("cat /home/user/.aws/credentials")
        ev = make_canary_event("s1", "198.51.100.77", 40000, canary,
                               "cat /home/user/.aws/credentials")
        self.assertEqual(ev["event"], "canary_accessed")
        self.assertEqual(ev["canary_id"], "CANARY-AWS-01")
        self.assertEqual(ev["severity"], "high")

    def test_v2_shell_returns_canary_content(self):
        policy = get_policy("manual")
        out = honeypot_v2.fake_shell_response_v2(
            "cat /home/user/.aws/credentials", policy)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", out)


class TestClustering(unittest.TestCase):
    def test_jaccard_and_similarity(self):
        self.assertEqual(jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertEqual(jaccard({"a"}, {"b"}), 0.0)
        self.assertEqual(jaccard(set(), set()), 1.0)
        fa = {"password_set": {"123456", "password"}, "command_set": set(),
              "label": "hydra"}
        fb = dict(fa)
        self.assertAlmostEqual(session_similarity(fa, fb), 1.0)

    def test_sample_campaign_separates_into_two(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "logs", "sample_campaign.jsonl")
        events = []
        with open(path) as fh:
            for line in fh:
                events.append(json.loads(line))
        campaigns = cluster_sessions(events)
        self.assertEqual(len(campaigns), 2)
        by_type = {c["likely_type"]: c for c in campaigns}
        self.assertIn("botnet", by_type)
        self.assertIn("manual", by_type)
        self.assertEqual(by_type["botnet"]["size_sessions"], 10)
        self.assertEqual(by_type["botnet"]["n_ips"], 5)
        self.assertEqual(by_type["manual"]["size_sessions"], 2)
        self.assertEqual(by_type["manual"]["n_ips"], 1)

    def test_analyze_v2_report_has_campaigns_and_canaries(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "logs", "sample_campaign.jsonl")
        with open(path) as fh:
            events = [json.loads(l) for l in fh]
        report = build_campaign_report(events)
        self.assertEqual(report["campaign_summary"]["n_campaigns"], 2)
        self.assertEqual(report["n_canary_events"], 2)
        self.assertEqual(report["total_sessions"], 12)


class TestHttpHoneypot(unittest.TestCase):
    def test_http_login_logs_credential_and_canary_in_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = HoneypotLogger(f"{tmp}/h.jsonl", f"{tmp}/h.db")
            from http.server import ThreadingHTTPServer
            server = ThreadingHTTPServer(("127.0.0.1", 0),
                                         make_handler(logger))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                    body = r.read().decode()
                self.assertIn("Admin Panel", body)
                self.assertIn("AKIAIOSFODNN7EXAMPLE", body)
                req = Request(f"http://127.0.0.1:{port}/login",
                              data=urlencode({"username": "admin",
                                            "password": "admin123"}).encode(),
                              method="POST")
                with urlopen(req, timeout=5) as r:
                    self.assertIn("Dashboard", r.read().decode())
            finally:
                server.shutdown()
                server.server_close()
            events = logger.load_events()
            attempts = [e for e in events
                        if e["event"] == "http_login_attempt"]
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["username"], "admin")
            self.assertEqual(attempts[0]["password"], "admin123")


if __name__ == "__main__":
    unittest.main()
