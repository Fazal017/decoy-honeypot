"""
Decoy Fabric v2 — deception tokens (canaries).

Idea: a honeypot that only *logs* logins tells you an attacker
arrived. A honeypot that plants fake secrets tells you what they
*wanted* — and, in a real deployment, when a planted secret is used
elsewhere, it proves exfiltration.

A canary is a fake credential / document that looks valuable, is
planted in the fake filesystem (and in HTTP HTML comments), and is
worthless by construction:

* AWS keys use the ``AKIA…EXAMPLE`` pattern — the format is real,
  the key is not. AWS documents ``AKIAIOSFODNN7EXAMPLE`` as the
  canonical example key; ours follow the same shape.
* Passwords / tokens are random-looking strings that were never
  issued anywhere. No canary value is a real credential, and none
  is ever sent to a real service.

When an attacker ``cat``s a canary file, the honeypot logs a
``canary_accessed`` event at HIGH severity with the token id.
In a production deployment that event would fire an alert and the
token would be watched for reuse — here it is recorded in the log
and surfaced in ``analyze_v2.py``.
"""

from __future__ import annotations

import re

# Fake filesystem paths -> canary. `content` is what `cat` returns.
CANARIES = [
    {
        "id": "CANARY-AWS-01",
        "type": "aws_access_key",
        "path": "/home/user/.aws/credentials",
        "content": ("[default]\n"
                    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                    "aws_secret_access_key = "
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
        "note": "Fake AWS key — EXAMPLE pattern, never issued.",
    },
    {
        "id": "CANARY-AWS-02",
        "type": "aws_secret",
        "path": "/home/user/.aws/config",
        "content": ("[default]\nregion = us-east-1\n"
                    "output = json\n# backup key: AKIAIOSFODNN7EXAMPLE\n"),
        "note": "Fake AWS config with a planted key.",
    },
    {
        "id": "CANARY-DB-01",
        "type": "database_password",
        "path": "/home/user/documents/db_passwords.txt",
        "content": ("prod-db: postgres / Hunter2-EXAMPLE-not-real\n"
                    "staging: mysql / changeme-EXAMPLE\n"),
        "note": "Fake database passwords.",
    },
    {
        "id": "CANARY-KEY-01",
        "type": "private_key",
        "path": "/home/user/.ssh/id_rsa",
        "content": ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                    "QyNTUxOQAAACDkZXhhbXBsZS1mYWtlLWtleS1ub3QtcmVhbC1kby1ub3QtdXNlCg==\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"),
        "note": "Fake private key — base64 decodes to 'example-fake-key'.",
    },
    {
        "id": "CANARY-DOC-01",
        "type": "document",
        "path": "/home/user/documents/salary-2026.xlsx",
        "content": ("[binary spreadsheet — fake]\n"
                    "NOTE: this is a planted decoy document, not real data.\n"),
        "note": "Fake document — a classic exfiltration target.",
    },
    {
        "id": "CANARY-TOKEN-01",
        "type": "api_token",
        "path": "/home/user/.config/app/token.txt",
        "content": "ghp_EXAMPLEFAKETOKEN00000000000000000000\n",
        "note": "Fake API token — EXAMPLE pattern.",
    },
]

# Commands that read a file: cat / less / head / tail / more / strings.
_READ_RE = re.compile(
    r"^\s*(?:cat|less|more|head|tail|strings|grep\s+.*?\s+|sed\s+-n.*?p\s+)"
    r"(.+)$"
)
# Also catch `cat file`, `cat < file`, `cp file /tmp`, `scp file …`.
# `~` paths too: `cat ~/.aws/credentials`.
_PATH_RE = re.compile(r"((?:~)?/[^\s;|&<>]+)")


def list_canaries() -> list[dict]:
    """All planted canaries (id, type, path)."""
    return [{"id": c["id"], "type": c["type"], "path": c["path"],
             "note": c["note"]} for c in CANARIES]


def find_canary(path: str) -> dict | None:
    """Return the canary planted at `path`, or None."""
    path = path.strip().strip("'\"")
    for c in CANARIES:
        if c["path"] == path:
            return c
    return None


def canary_for_command(command: str) -> dict | None:
    """If `command` reads a canary file, return that canary.

    Parses only the command string — nothing is executed, nothing
    is read from disk. ``cat ~/.aws/credentials`` and
    ``cat /home/user/.aws/credentials`` both match.
    """
    m = _READ_RE.match(command.strip())
    if not m:
        return None
    for path in _PATH_RE.findall(m.group(1)):
        # Expand a leading ~/ to the fake home.
        expanded = path.replace("~", "/home/user", 1) \
            if path.startswith("~") else path
        canary = find_canary(expanded)
        if canary:
            return canary
    # Direct path mention without a read verb, e.g. `ls .aws` — no.
    return None


def is_canary_access(command: str) -> bool:
    return canary_for_command(command) is not None


def make_canary_event(session_id: str, src_ip: str, src_port: int,
                      canary: dict, command: str) -> dict:
    """Build a HIGH-severity ``canary_accessed`` log event."""
    from src.logger import make_event
    return make_event(
        "canary_accessed", session_id, src_ip, src_port,
        command=command, canary_id=canary["id"],
        canary_type=canary["type"], canary_path=canary["path"],
        severity="high",
        note="Attacker read a planted deception token — "
             "treat as exfiltration attempt (T1552 / T1005).",
    )


def html_comment_canaries() -> str:
    """Canary tokens as HTML comments, for the HTTP honeypot.

    Hidden from a normal browser view, visible to anyone who
    views source — which is exactly what an attacker does.
    """
    lines = ["<!-- internal notes — do not share -->"]
    for c in CANARIES[:3]:
        if c["type"] == "aws_access_key":
            lines.append("<!-- backup aws key: AKIAIOSFODNN7EXAMPLE -->")
        elif c["type"] == "database_password":
            lines.append("<!-- db backup: Hunter2-EXAMPLE-not-real -->")
        elif c["type"] == "api_token":
            lines.append("<!-- api token: ghp_EXAMPLEFAKETOKEN00000000000000000000 -->")
    return "\n".join(lines)
