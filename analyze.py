#!/usr/bin/env python3
"""
Decoy Honeypot Lab — analyzer.

Reads ``logs/honeypot.jsonl`` and produces:

* ``summary.json`` — machine-readable attacker statistics
  (totals, top usernames / passwords / commands / IPs, per-IP
  first-seen / last-seen, MITRE ATT&CK mapping).
* ``report.html`` — a self-contained SOC-style attacker report with
  simple HTML/CSS bar charts. No JavaScript, no external resources,
  so the report can be opened offline or archived as evidence.

Usage::

    python3 analyze.py
    python3 analyze.py --log logs/honeypot.jsonl \\
        --output report.html --json summary.json
"""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from pathlib import Path

from src.logger import HoneypotLogger


def load_events(log_path: str) -> list[dict]:
    """Read a JSONL log file, skipping blank / malformed lines."""
    events = []
    path = Path(log_path)
    if not path.exists():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def build_summary(events: list[dict]) -> dict:
    """Compute attacker statistics from raw events."""
    # Reuse the shared stats implementation (src/logger.py) by writing
    # the events to a temporary JSONL file and letting HoneypotLogger
    # compute totals, top-10 lists and per-IP profiles from it.
    import tempfile, os
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
    try:
        for e in events:
            tmp.write(json.dumps(e) + "\n")
        tmp.close()
        stats_logger = HoneypotLogger(tmp.name, tmp.name + ".db")
        summary = stats_logger.stats()
    finally:
        os.unlink(tmp.name)
        db = tmp.name + ".db"
        if os.path.exists(db):
            os.unlink(db)

    attempts = [e for e in events if e["event"] == "login_attempt"]
    # Timeline: login attempts per calendar day.
    timeline = Counter(
        e["timestamp"][:10] for e in attempts if e.get("timestamp"))
    summary["timeline_by_day"] = dict(sorted(timeline.items()))
    if events:
        summary["first_seen"] = min(e["timestamp"] for e in events)
        summary["last_seen"] = max(e["timestamp"] for e in events)
    else:
        summary["first_seen"] = summary["last_seen"] = None
    # Top-10 lists are tuples after Counter.most_common(); make them JSON
    # friendly as [value, count] pairs.
    for key in ("top_usernames", "top_passwords", "top_commands", "top_ips"):
        summary[key] = [[v, c] for v, c in summary[key]]
    return summary


def _bar_rows(items: list, max_value: int) -> str:
    """Render a list of [label, count] as HTML/CSS bars (no JS)."""
    rows = []
    for label, count in items:
        pct = (count / max_value * 100) if max_value else 0
        rows.append(
            "<tr><td>{label}</td>"
            "<td><div class='bar' style='width:{pct:.1f}%'></div></td>"
            "<td>{count}</td></tr>".format(
                label=html.escape(str(label)), pct=pct, count=count))
    return "\n".join(rows)


def render_html(summary: dict) -> str:
    """Render the SOC-style attacker report as self-contained HTML."""
    def top(key):
        return summary.get(key) or []

    def bar_section(title, items):
        if not items:
            return f"<h2>{title}</h2><p>No data yet.</p>"
        max_v = max(c for _, c in items)
        return (f"<h2>{title}</h2>"
                "<table class='bars'>" + _bar_rows(items, max_v) + "</table>")

    timeline_rows = "".join(
        f"<tr><td>{html.escape(day)}</td><td>{count}</td></tr>"
        for day, count in summary.get("timeline_by_day", {}).items())
    per_ip_rows = "".join(
        "<tr><td>{ip}</td><td>{s}</td><td>{a}</td><td>{c}</td>"
        "<td>{first}</td><td>{last}</td></tr>".format(
            ip=html.escape(ip), s=v["sessions"], a=v["login_attempts"],
            c=v["commands"], first=html.escape(v["first_seen"]),
            last=html.escape(v["last_seen"]))
        for ip, v in summary.get("per_ip", {}).items())

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Decoy Honeypot Lab — Attacker Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2em auto;
padding:0 1em;color:#1a1a1a;background:#fff}}
h1{{border-bottom:3px solid #b91c1c;padding-bottom:.3em}}
h2{{margin-top:1.5em;color:#b91c1c}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#f3f4f6}}
.bars td:first-child{{width:180px}}
.bar{{background:#b91c1c;height:16px;min-width:2px}}
.kpi{{display:flex;gap:1em;flex-wrap:wrap}}
.kpi div{{background:#f3f4f6;padding:1em;min-width:140px;border-radius:8px}}
.kpi b{{font-size:1.6em;display:block}}
.mitre{{background:#fff7ed;border:1px solid #fdba74;padding:1em;border-radius:8px}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:4px}}
</style></head><body>
<h1>Decoy Honeypot Lab — Attacker Report</h1>
<p>Low-interaction SSH honeypot &middot; generated from
<code>logs/honeypot.jsonl</code>. No real shell, no real login —
every credential and command below was captured by the decoy.</p>
<p>Window: <b>{html.escape(str(summary.get('first_seen')))}</b> to
<b>{html.escape(str(summary.get('last_seen')))}</b></p>
<div class="kpi">
<div><b>{summary['total_sessions']}</b>Sessions</div>
<div><b>{summary['total_login_attempts']}</b>Login attempts</div>
<div><b>{summary['total_commands']}</b>Commands tried</div>
<div><b>{summary['unique_ips']}</b>Unique source IPs</div>
</div>
{bar_section("Top 10 usernames tried", top("top_usernames"))}
{bar_section("Top 10 passwords tried", top("top_passwords"))}
{bar_section("Top 10 commands tried", top("top_commands"))}
{bar_section("Top 10 source IPs (login attempts)", top("top_ips"))}
<h2>Timeline — login attempts per day</h2>
<table><tr><th>Date</th><th>Attempts</th></tr>{timeline_rows or '<tr><td colspan="2">No data yet.</td></tr>'}</table>
<h2>Per-IP profile</h2>
<table><tr><th>Source IP</th><th>Sessions</th><th>Attempts</th><th>Commands</th>
<th>First seen</th><th>Last seen</th></tr>{per_ip_rows or '<tr><td colspan="6">No data yet.</td></tr>'}</table>
<h2>MITRE ATT&amp;CK mapping</h2>
<div class="mitre">
<p><b>T1110.001 — Brute Force: Password Guessing:</b>
{html.escape(summary['mitre']['T1110.001'])}</p>
<p><b>T1059 — Command and Scripting Interpreter:</b>
{html.escape(summary['mitre']['T1059'])}</p>
<p><b>T1078 — Valid Accounts:</b>
{html.escape(summary['mitre']['T1078'])}</p>
</div>
<p><small>Decoy Honeypot Lab &middot; for lab / blue-team training only.
Never expose a honeypot to the internet without understanding the risk.</small></p>
</body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze honeypot logs into a SOC-style report.")
    parser.add_argument("--log", default="logs/honeypot.jsonl",
                        help="JSON Lines log to read")
    parser.add_argument("--output", default="report.html",
                        help="HTML report to write (default: report.html)")
    parser.add_argument("--json", default="summary.json",
                        help="JSON summary to write (default: summary.json)")
    args = parser.parse_args()

    events = load_events(args.log)
    summary = build_summary(events)
    Path(args.json).write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    Path(args.output).write_text(render_html(summary), encoding="utf-8")
    print(f"[+] Read {len(events)} events from {args.log}")
    print(f"[+] Sessions: {summary['total_sessions']} | "
          f"Login attempts: {summary['total_login_attempts']} | "
          f"Commands: {summary['total_commands']} | "
          f"Unique IPs: {summary['unique_ips']}")
    print(f"[+] Wrote {args.output} and {args.json}")


if __name__ == "__main__":
    main()
