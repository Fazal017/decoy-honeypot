#!/usr/bin/env python3
"""
Decoy Fabric v2 — campaign analyzer.

Reads a honeypot JSONL log and produces a *campaign* report,
not just a top-10 list:

* ``campaigns.json`` — fingerprints per session, campaigns from
  ``src/clustering.py`` (id, IPs, shared passwords/commands,
  first/last seen, likely type + confidence), canary events.
* ``campaign_report.html`` — self-contained HTML report (CSS
  bars, no JavaScript, no external resources).

Usage::

    python3 analyze_v2.py --log logs/sample_campaign.jsonl \\
        --output campaign_report.html --json campaigns.json
    python3 analyze_v2.py --log logs/honeypot.jsonl
"""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from pathlib import Path

from analyze import load_events
from src.clustering import campaign_summary, cluster_sessions
from src.fingerprint import fingerprint_sessions, fingerprint_summary


def build_campaign_report(events: list[dict]) -> dict:
    fps = fingerprint_sessions(events)
    campaigns = cluster_sessions(events)
    canaries = [e for e in events if e["event"] == "canary_accessed"]
    lockouts = [e for e in events if e["event"] == "lockout"]
    http_attempts = [e for e in events
                     if e["event"] == "http_login_attempt"]
    sessions = sorted(fps.values(), key=lambda f: f["first_seen"] or "")
    return {
        "total_events": len(events),
        "total_sessions": len(fps),
        "unique_ips": len({f["src_ip"] for f in fps.values()}),
        "fingerprints": fingerprint_summary(fps),
        "sessions": [
            {"session_id": f["session_id"], "src_ip": f["src_ip"],
             "label": f["label"], "confidence": f["confidence"],
             "reasons": f["reasons"], "n_attempts": f["n_attempts"],
             "n_commands": f["n_commands"],
             "passwords": f["passwords"], "commands": f["commands"],
             "duration_seconds": f["duration_seconds"],
             "first_seen": f["first_seen"], "last_seen": f["last_seen"]}
            for f in sessions],
        "campaigns": campaigns,
        "campaign_summary": campaign_summary(campaigns),
        "canary_events": [
            {"timestamp": e.get("timestamp"), "session_id": e.get("session_id"),
             "src_ip": e.get("src_ip"), "canary_id": e.get("canary_id"),
             "canary_type": e.get("canary_type"),
             "canary_path": e.get("canary_path"),
             "command": e.get("command")}
            for e in canaries],
        "n_canary_events": len(canaries),
        "n_lockouts": len(lockouts),
        "n_http_login_attempts": len(http_attempts),
        "top_passwords": Counter(
            p for f in fps.values() for p in f["passwords"]).most_common(10),
        "top_commands": Counter(
            c for f in fps.values() for c in f["commands"]).most_common(10),
    }


def render_html(report: dict) -> str:
    def esc(x):
        return html.escape(str(x))

    camp_rows = "".join(
        "<tr><td>{cid}</td><td>{typ}</td><td>{conf:.2f}</td>"
        "<td>{n}</td><td>{ips}</td><td>{pw}</td><td>{first}</td>"
        "<td>{last}</td></tr>".format(
            cid=esc(c["campaign_id"]), typ=esc(c["likely_type"]),
            conf=c["confidence"], n=c["size_sessions"],
            ips=esc(", ".join(c["ips"])),
            pw=esc(", ".join(c["passwords"][:6])),
            first=esc(c["first_seen"]), last=esc(c["last_seen"]))
        for c in report["campaigns"]) or \
        '<tr><td colspan="8">No campaigns found.</td></tr>'

    sess_rows = "".join(
        "<tr><td>{sid}</td><td>{ip}</td><td>{lab}</td><td>{conf:.2f}</td>"
        "<td>{a}</td><td>{c}</td><td>{why}</td></tr>".format(
            sid=esc(s["session_id"][:8]), ip=esc(s["src_ip"]),
            lab=esc(s["label"]), conf=s["confidence"],
            a=s["n_attempts"], c=s["n_commands"],
            why=esc("; ".join(s["reasons"][:2])))
        for s in report["sessions"])

    canary_rows = "".join(
        "<tr><td>{ts}</td><td>{ip}</td><td>{cid}</td><td>{typ}</td>"
        "<td>{path}</td><td>{cmd}</td></tr>".format(
            ts=esc(e["timestamp"]), ip=esc(e["src_ip"]),
            cid=esc(e["canary_id"]), typ=esc(e["canary_type"]),
            path=esc(e["canary_path"]), cmd=esc(e["command"]))
        for e in report["canary_events"]) or \
        '<tr><td colspan="6">No canary was accessed.</td></tr>'

    label_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{v}</td></tr>"
        for k, v in report["fingerprints"]["by_label"].items())

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Decoy Fabric v2 — Campaign Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:2em auto;
padding:0 1em;color:#1a1a1a;background:#fff}}
h1{{border-bottom:3px solid #7c3aed;padding-bottom:.3em}}
h2{{margin-top:1.5em;color:#7c3aed}}
table{{border-collapse:collapse;width:100%;font-size:.9em}}
td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}}
.kpi{{display:flex;gap:1em;flex-wrap:wrap}}
.kpi div{{background:#f3f4f6;padding:1em;min-width:130px;border-radius:8px}}
.kpi b{{font-size:1.6em;display:block}}
.canary{{background:#fef2f2;border:1px solid #fca5a5;padding:1em;border-radius:8px}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:4px}}
</style></head><body>
<h1>Decoy Fabric v2 — Campaign Report</h1>
<p>Adaptive Deception + Actor Profiling &amp; Campaign Clustering.
Sessions are grouped by password-list overlap, command similarity
and fingerprint — not by IP alone — so one botnet across five IPs
shows up as <b>one campaign</b>.</p>
<div class="kpi">
<div><b>{report['total_sessions']}</b>Sessions</div>
<div><b>{report['campaign_summary']['n_campaigns']}</b>Campaigns</div>
<div><b>{report['unique_ips']}</b>Unique IPs</div>
<div><b>{report['n_canary_events']}</b>Canary accesses</div>
<div><b>{report['n_lockouts']}</b>Adaptive lockouts</div>
<div><b>{report['n_http_login_attempts']}</b>HTTP login attempts</div>
</div>
<h2>Campaigns</h2>
<table><tr><th>ID</th><th>Likely type</th><th>Conf.</th><th>Sessions</th>
<th>IPs</th><th>Shared passwords</th><th>First seen</th><th>Last seen</th></tr>
{camp_rows}</table>
<h2>Fingerprints by label</h2>
<table><tr><th>Label</th><th>Sessions</th></tr>{label_rows}</table>
<h2>Sessions — fingerprint detail</h2>
<table><tr><th>Session</th><th>IP</th><th>Label</th><th>Conf.</th>
<th>Attempts</th><th>Commands</th><th>Why</th></tr>{sess_rows}</table>
<h2>Canary accesses (HIGH severity)</h2>
<div class="canary"><table><tr><th>Time</th><th>IP</th><th>Canary</th>
<th>Type</th><th>Path</th><th>Command</th></tr>{canary_rows}</table>
<p>Each access means an attacker read a planted fake secret —
treat as an exfiltration attempt (MITRE T1552 / T1005).</p></div>
<p><small>Decoy Fabric v2 &middot; lab / blue-team training only.
No real credentials were ever planted; all canary values are fake.</small></p>
</body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decoy Fabric v2 — campaign analyzer.")
    parser.add_argument("--log", default="logs/sample_campaign.jsonl")
    parser.add_argument("--output", default="campaign_report.html")
    parser.add_argument("--json", default="campaigns.json")
    args = parser.parse_args()
    events = load_events(args.log)
    report = build_campaign_report(events)
    # JSON-friendly: top lists are already [value, count] pairs via Counter.
    report["top_passwords"] = [[v, c] for v, c in report["top_passwords"]]
    report["top_commands"] = [[v, c] for v, c in report["top_commands"]]
    Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    Path(args.output).write_text(render_html(report), encoding="utf-8")
    print(f"[+] Read {len(events)} events from {args.log}")
    print(f"[+] Sessions: {report['total_sessions']} | "
          f"Campaigns: {report['campaign_summary']['n_campaigns']} "
          f"({report['campaign_summary']['by_type']}) | "
          f"Canary accesses: {report['n_canary_events']}")
    for c in report["campaigns"]:
        print(f"    {c['campaign_id']}: {c['likely_type']} "
              f"(conf {c['confidence']:.2f}) — {c['size_sessions']} sessions, "
              f"{c['n_ips']} IPs: {', '.join(c['ips'])}")
    print(f"[+] Wrote {args.output} and {args.json}")


if __name__ == "__main__":
    main()
