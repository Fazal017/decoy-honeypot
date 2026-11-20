"""
Structured logging for the Decoy Honeypot Lab.

Every event is written twice, in two independent stores:

* JSON Lines (``logs/honeypot.jsonl``) — human-readable, append-only,
  easy to grep / ship to a SIEM.
* SQLite (``logs/honeypot.db``) — queryable, survives restarts, powers
  the per-IP statistics used by ``analyze.py``.

Event schema (one JSON object per line)::

    {
      "timestamp":   "2026-11-21T02:30:00+00:00",   # ISO-8601, UTC
      "event":       "login_attempt",               # session_start |
                                                   # login_attempt | command |
                                                   # session_end
      "session_id":  "a1b2c3d4",
      "src_ip":      "203.0.113.42",
      "src_port":    51234,
      "username":    "root",        # login_attempt only
      "password":    "123456",      # login_attempt only
      "command":     "ls",          # command only
      "client_banner": "SSH-2.0-OpenSSH_8.2",  # session_start only
      "duration_seconds": 4.2       # session_end only
    }

MITRE ATT&CK mapping used by the analyzer
-------------------------------------------
* ``T1110 — Brute Force`` (specifically T1110.001 Password Guessing):
  repeated ``login_attempt`` events from one source IP.
* ``T1078 — Valid Accounts``: any attempt that *would* have succeeded
  against a real host — here every attempt is logged, none succeeds,
  because there is no real account and no real shell.
* ``T1059 — Command and Scripting Interpreter``: ``command`` events
  show what an attacker tries to run after (fake) login.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_event(event: str, session_id: str, src_ip: str, src_port: int,
               **fields) -> dict:
    """Build one log event dict with the standard fields."""
    record = {
        "timestamp": utc_now(),
        "event": event,
        "session_id": session_id,
        "src_ip": src_ip,
        "src_port": src_port,
    }
    record.update(fields)
    return record


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class HoneypotLogger:
    """Thread-safe JSONL + SQLite logger for honeypot events."""

    def __init__(self, jsonl_path: str = "logs/honeypot.jsonl",
                 db_path: str = "logs/honeypot.db"):
        self.jsonl_path = jsonl_path
        self.db_path = db_path
        self._lock = threading.Lock()
        for path in (jsonl_path, db_path):
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    # -- SQLite ------------------------------------------------------------
    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS events (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       timestamp TEXT NOT NULL,
                       event TEXT NOT NULL,
                       session_id TEXT NOT NULL,
                       src_ip TEXT NOT NULL,
                       src_port INTEGER,
                       username TEXT,
                       password TEXT,
                       command TEXT,
                       client_banner TEXT,
                       duration_seconds REAL
                   )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_ip "
                "ON events (src_ip)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_event "
                "ON events (event)"
            )

    # -- Writing -----------------------------------------------------------
    def log(self, event: dict) -> None:
        """Append one event to the JSONL file and insert it into SQLite."""
        with self._lock:
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT INTO events
                       (timestamp, event, session_id, src_ip, src_port,
                        username, password, command, client_banner,
                        duration_seconds)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (event.get("timestamp"), event.get("event"),
                     event.get("session_id"), event.get("src_ip"),
                     event.get("src_port"), event.get("username"),
                     event.get("password"), event.get("command"),
                     event.get("client_banner"),
                     event.get("duration_seconds")),
                )

    # -- Reading / statistics ----------------------------------------------
    def load_events(self) -> list[dict]:
        """Return all events from the JSONL file (empty list if none)."""
        if not os.path.exists(self.jsonl_path):
            return []
        events = []
        with open(self.jsonl_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def stats(self) -> dict:
        """Per-IP / credential / command statistics for the analyzer.

        Returns a dict with totals, top-10 lists, and first/last seen
        timestamps per source IP. Computed from the JSONL log so the
        analyzer works even on a log file copied from another host.
        """
        events = self.load_events()
        sessions = {e["session_id"] for e in events}
        attempts = [e for e in events if e["event"] == "login_attempt"]
        commands = [e for e in events if e["event"] == "command"]

        per_ip: dict[str, dict] = {}
        for e in events:
            ip = e["src_ip"]
            entry = per_ip.setdefault(ip, {
                "sessions": set(), "attempts": 0, "commands": 0,
                "first_seen": e["timestamp"], "last_seen": e["timestamp"],
            })
            entry["sessions"].add(e["session_id"])
            if e["event"] == "login_attempt":
                entry["attempts"] += 1
            if e["event"] == "command":
                entry["commands"] += 1
            entry["first_seen"] = min(entry["first_seen"], e["timestamp"])
            entry["last_seen"] = max(entry["last_seen"], e["timestamp"])

        per_ip_out = {
            ip: {
                "sessions": len(v["sessions"]),
                "login_attempts": v["attempts"],
                "commands": v["commands"],
                "first_seen": v["first_seen"],
                "last_seen": v["last_seen"],
            }
            for ip, v in sorted(
                per_ip.items(),
                key=lambda kv: kv[1]["attempts"], reverse=True)
        }

        return {
            "total_events": len(events),
            "total_sessions": len(sessions),
            "total_login_attempts": len(attempts),
            "total_commands": len(commands),
            "unique_ips": len(per_ip),
            "top_usernames": Counter(
                e.get("username") for e in attempts).most_common(10),
            "top_passwords": Counter(
                e.get("password") for e in attempts).most_common(10),
            "top_commands": Counter(
                e.get("command") for e in commands).most_common(10),
            "top_ips": Counter(
                e["src_ip"] for e in attempts).most_common(10),
            "per_ip": per_ip_out,
            # MITRE ATT&CK: every login attempt is T1110.001 (Password
            # Guessing); every post-login command is T1059.
            "mitre": {
                "T1110.001": "Brute Force: Password Guessing "
                             f"({len(attempts)} login attempts)",
                "T1059": "Command and Scripting Interpreter "
                         f"({len(commands)} commands attempted)",
                "T1078": "Valid Accounts — no real account exists; "
                         "0 logins ever succeeded",
            },
        }
