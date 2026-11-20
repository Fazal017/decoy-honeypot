"""
Decoy Fabric v2 — adaptive deception.

A static honeypot always looks the same, so a bot that has seen
one Decoy host has seen them all. An adaptive honeypot changes
what it *pretends to be* based on who is knocking:

* **Hydra / botnet** — old Debian banner, 2-3 s tarpitting delay
  per attempt, fake account lockout after 3 attempts. The bot
  wastes time and its dictionary is slowed, not the defender.
* **Manual actor** — rich Ubuntu filesystem with canary files,
  a plausible ``ls`` and extra directories. A human who finds
  ``.aws/credentials`` stays longer — and trips a canary.
* **Scanner** — no shell at all; instead the banner phase hints
  at fake open ports (22, 80, 443, 3306, 8080) so the scanner
  wastes its next pass on decoy services.
* **SQL tool** — a smaller shell, slower replies, database ports
  in the fake surface.

Policy is config-driven: ``config/adaptive_policy.json`` maps a
fingerprint label to {banner, response_delay_s, lockout_after,
max_commands, filesystem, fake_open_ports, welcome}. Edit the
JSON, restart, no code change. Unknown labels fall back to
``default``. Nothing here executes attacker input — the policy
only selects which *canned* strings are shown.
"""

from __future__ import annotations

import json
import os

DEFAULT_CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "adaptive_policy.json")

# Fake filesystems, by richness. Canary paths are listed only in
# the "rich" profile — a bot gets a bare box, a human gets bait.
FILESYSTEMS = {
    "minimal": {
        "ls": "notes.txt\n",
        "ls -la": "total 8\ndrwxr-xr-x 2 user user 4096 Nov 21 02:00 .\n"
                  "-rw-r--r-- 1 user user  220 Nov 21 02:00 notes.txt\n",
    },
    "standard": {
        "ls": "Desktop  Documents  Downloads  notes.txt  public_html\n",
        "ls -la": "total 32\ndrwxr-xr-x 5 user user 4096 Nov 21 02:00 .\n"
                  "drwxr-xr-x 3 root root 4096 Nov 21 01:00 ..\n"
                  "-rw-r--r-- 1 user user  220 Nov 21 02:00 notes.txt\n",
    },
    "rich": {
        "ls": ("Desktop  Documents  Downloads  notes.txt  public_html\n"
               ".aws  .ssh  .config\n"),
        "ls -la": ("total 48\ndrwxr-xr-x 6 user user 4096 Nov 21 02:00 .\n"
                   "drwxr-xr-x 3 root root 4096 Nov 21 01:00 ..\n"
                   "drwx------ 2 user user 4096 Nov 21 02:00 .aws\n"
                   "drwx------ 2 user user 4096 Nov 21 02:00 .ssh\n"
                   "-rw-r--r-- 1 user user  220 Nov 21 02:00 notes.txt\n"),
        "ls .aws": "config  credentials\n",
        "ls .ssh": "id_rsa  id_rsa.pub  known_hosts\n",
        "ls Documents": "db_passwords.txt  salary-2026.xlsx  project-plan.md\n",
        "ls documents": "db_passwords.txt  salary-2026.xlsx  project-plan.md\n",
    },
}


class AdaptivePolicy:
    """One deception profile, loaded from config JSON."""

    def __init__(self, label: str, data: dict):
        self.label = label
        self.banner = data.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.response_delay_s = float(data.get("response_delay_s", 0.2))
        self.lockout_after_attempts = data.get("lockout_after_attempts")
        self.max_commands = int(data.get("max_commands", 10))
        self.filesystem = data.get("filesystem", "standard")
        self.fake_open_ports = list(data.get("fake_open_ports", []))
        self.welcome = data.get("welcome", "")

    def should_lockout(self, attempts_from_ip: int) -> bool:
        if self.lockout_after_attempts is None:
            return False
        return attempts_from_ip >= self.lockout_after_attempts

    def ls_output(self, command: str = "ls") -> str | None:
        return FILESYSTEMS.get(self.filesystem, {}).get(command)

    def to_dict(self) -> dict:
        return {"label": self.label, "banner": self.banner,
                "response_delay_s": self.response_delay_s,
                "lockout_after_attempts": self.lockout_after_attempts,
                "max_commands": self.max_commands,
                "filesystem": self.filesystem,
                "fake_open_ports": self.fake_open_ports}


def load_policies(config_path: str = DEFAULT_CONFIG) -> dict[str, AdaptivePolicy]:
    """Load all policies from JSON; fall back to a built-in default."""
    try:
        with open(config_path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        raw = {}
    policies = {}
    for label, data in raw.items():
        if label.startswith("_"):
            continue
        policies[label] = AdaptivePolicy(label, data)
    if "default" not in policies:
        policies["default"] = AdaptivePolicy("default", {})
    return policies


def get_policy(label: str, policies: dict | None = None,
               config_path: str = DEFAULT_CONFIG) -> AdaptivePolicy:
    """Policy for a fingerprint label; unknown labels get `default`."""
    if policies is None:
        policies = load_policies(config_path)
    return policies.get(label) or policies["default"]


def banner_for(label: str, policies: dict | None = None) -> str:
    return get_policy(label, policies).banner


def delay_for(label: str, policies: dict | None = None) -> float:
    return get_policy(label, policies).response_delay_s
