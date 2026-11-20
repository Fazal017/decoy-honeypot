"""
Decoy Fabric v2 — attacker tool fingerprinting.

A normal honeypot logs *what* an attacker tried. Decoy Fabric asks
*how* they tried it, and answers that question from behaviour alone —
no IP reputation list, no external lookup, no payload.

The fingerprint is built from four signals that are hard for an
attacker to fake all at once:

* **Tempo** — inter-attempt / inter-command gaps. Hydra fires every
  ~0.3-1.5 s; a human pauses 3-30 s, and pauses longer before a
  destructive command.
* **Password order** — automated tools walk a fixed dictionary in
  order (``123456, password, admin, root, qwerty, …``). Humans try
  one or two guesses, usually related to the target.
* **Command sequence** — bots run a fixed recon script
  (``uname -a; id; wget …``); humans explore (``ls``, ``cat``,
  ``cd``, typos, backtracking). SQL tools leave SQL in the stream.
* **Breadth** — the same password list appearing from many IPs is
  not many attackers, it is one botnet.

Labels
------
``hydra``   — fast, sequential dictionary, no post-login commands.
``botnet``  — hydra-like behaviour *shared* across >=3 IPs
             (same password list, Jaccard >= 0.6). Assigned by
             :func:`fingerprint_sessions` when global context is
             available; a lone session is ``hydra``.
``manual``  — slow, exploratory, typos, few guesses.
``scanner`` — port scan: connects, sends a banner (or nothing),
             never attempts a login.
``sqlmap``  — SQL fragments in commands / passwords.
``unknown`` — not enough evidence to classify confidently.

All thresholds are explicit constants below so a reviewer can
audit — and tune — the classifier without reading the code.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import re

# --- Tunable thresholds ---------------------------------------------------
HYDRA_MAX_INTERVAL_S = 2.0      # mean gap between attempts, Hydra-like
HYDRA_MIN_ATTEMPTS = 3          # attempts in one session to call it Hydra
MANUAL_MIN_INTERVAL_S = 3.0     # mean gap between commands, human-like
MANUAL_MIN_DURATION_S = 15.0    # a human session lasts a while
BOTNET_MIN_IPS = 3              # IPs sharing a password list
BOTNET_MIN_JACCARD = 0.6        # password-list overlap for "same list"
SCANNER_MAX_DURATION_S = 5.0

# The dictionary Hydra / common wordlists walk, in order. A session
# whose passwords are a prefix / subsequence of this list, in order,
# is almost certainly automated.
KNOWN_DICTIONARY = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "admin", "root",
    "letmein", "welcome", "monkey", "password1", "123qwe", "admin123",
    "oracle", "test", "guest", "user", "ubuntu", "pi", "raspberry",
]

SQL_TOKENS = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop\s+table|or\s+1\s*=\s*1"
    r"|'\s*or\s*'|--|/\*|information_schema|@@version)\b"
)

EXPLORATORY_COMMANDS = {
    "ls", "ls -la", "pwd", "whoami", "cat", "cd", "hostname",
    "uname", "uname -a", "id", "env", "history", "ps", "ps aux",
}

# A command that is one edit away from a known command, or contains
# a doubled letter / transposition, is a human typo — bots do not typo.
TYPO_RE = re.compile(r"^(lss|lls|pwdx|whoam[i]?|catt|ct|unnam|hisotry|exitt)\b")


def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _mean_gap(timestamps: list) -> float | None:
    if len(timestamps) < 2:
        return None
    gaps = [
        (b - a).total_seconds()
        for a, b in zip(timestamps, timestamps[1:])
        if b is not None and a is not None
    ]
    return sum(gaps) / len(gaps) if gaps else None


def build_session_features(events: list[dict]) -> dict:
    """Group events by session and compute behavioural features.

    Returns ``{session_id: features}`` where features is a dict with
    src_ip, passwords (in order), commands (in order), timestamps,
    duration, attempt/command counts, mean gaps, typo and SQL flags.
    """
    by_session: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_session[e.get("session_id", "?")].append(e)

    out = {}
    for sid, evs in by_session.items():
        evs = sorted(evs, key=lambda e: e.get("timestamp", ""))
        attempts = [e for e in evs if e["event"] == "login_attempt"]
        commands = [e for e in evs if e["event"] == "command"]
        starts = [e for e in evs if e["event"] == "session_start"]
        ends = [e for e in evs if e["event"] == "session_end"]
        ts = [_parse_ts(e["timestamp"]) for e in evs if e.get("timestamp")]
        ts = [t for t in ts if t is not None]
        attempt_ts = [
            _parse_ts(e["timestamp"]) for e in attempts if e.get("timestamp")
        ]
        cmd_ts = [
            _parse_ts(e["timestamp"]) for e in commands if e.get("timestamp")
        ]
        cmd_strs = [str(e.get("command", "")) for e in commands]
        passwords = [str(e.get("password", "")) for e in attempts]
        duration = None
        if ends and ends[0].get("duration_seconds") is not None:
            duration = float(ends[0]["duration_seconds"])
        elif len(ts) >= 2:
            duration = (max(ts) - min(ts)).total_seconds()
        banner = starts[0].get("client_banner", "") if starts else ""
        out[sid] = {
            "session_id": sid,
            "src_ip": evs[0].get("src_ip", ""),
            "username": attempts[0].get("username", "") if attempts else "",
            "passwords": passwords,
            "password_set": set(passwords),
            "commands": cmd_strs,
            "command_set": set(cmd_strs),
            "n_attempts": len(attempts),
            "n_commands": len(commands),
            "duration_seconds": duration,
            "mean_attempt_gap_s": _mean_gap(attempt_ts),
            "mean_command_gap_s": _mean_gap(cmd_ts),
            "client_banner": banner,
            "has_sql": any(SQL_TOKENS.search(c) or SQL_TOKENS.search(p)
                           for c in cmd_strs for p in [c] + passwords),
            "has_typo": any(TYPO_RE.search(c) for c in cmd_strs),
            "exploratory_commands": sum(
                1 for c in cmd_strs
                if c.split()[0] in EXPLORATORY_COMMANDS
                if c.split()),
            "first_seen": evs[0].get("timestamp"),
            "last_seen": evs[-1].get("timestamp"),
        }
    return out


def _dictionary_order_score(passwords: list[str]) -> float:
    """Fraction of passwords that appear in KNOWN_DICTIONARY order.

    1.0 = the session walked the dictionary in order (Hydra-like);
    0.0 = passwords are unrelated to the dictionary.
    """
    if not passwords:
        return 0.0
    idx = [KNOWN_DICTIONARY.index(p) for p in passwords
           if p in KNOWN_DICTIONARY]
    if not idx:
        return 0.0
    ordered = sum(1 for a, b in zip(idx, idx[1:]) if b > a)
    # Score = share in dictionary * share in increasing order.
    return (len(idx) / len(passwords)) * (
        ordered / max(1, len(idx) - 1) if len(idx) > 1 else 1.0)


def classify_session(features: dict,
                     shared_password_ips: int = 0,
                     shared_password_jaccard: float = 0.0) -> dict:
    """Classify one session. Returns {label, confidence, reasons}."""
    reasons: list[str] = []
    n_att = features["n_attempts"]
    n_cmd = features["n_commands"]
    gap = features["mean_attempt_gap_s"]
    cmd_gap = features["mean_command_gap_s"]
    dur = features["duration_seconds"] or 0.0
    banner = str(features.get("client_banner", "")).lower()

    # 1. Scanner: no login at all.
    if n_att == 0:
        if "nmap" in banner or "masscan" in banner or "zmap" in banner:
            return {"label": "scanner", "confidence": 0.95,
                    "reasons": [f"scanner banner: {banner}"]}
        return {"label": "scanner", "confidence": 0.75,
                "reasons": ["connected but never attempted a login",
                            f"duration {dur:.1f}s"]}

    # 2. SQL tool: SQL fragments anywhere in the stream.
    if features["has_sql"]:
        return {"label": "sqlmap", "confidence": 0.9,
                "reasons": ["SQL fragment in command/password stream"]}

    # 3. Botnet: hydra-like AND the password list is shared.
    dict_score = _dictionary_order_score(features["passwords"])
    fast = gap is not None and gap <= HYDRA_MAX_INTERVAL_S
    if (shared_password_ips >= BOTNET_MIN_IPS
            and shared_password_jaccard >= BOTNET_MIN_JACCARD):
        return {"label": "botnet", "confidence": 0.9,
                "reasons": [
                    f"password list shared by {shared_password_ips} IPs",
                    f"password-list Jaccard {shared_password_jaccard:.2f}",
                    "hydra-like tempo" if fast else "dictionary order",
                ]}

    # 4. Hydra: several fast, in-order dictionary attempts, no commands.
    if n_att >= HYDRA_MIN_ATTEMPTS and fast and n_cmd == 0:
        reasons.append(f"{n_att} attempts, mean gap {gap:.2f}s")
        reasons.append(f"dictionary-order score {dict_score:.2f}")
        reasons.append("no post-login commands")
        conf = 0.85 if dict_score >= 0.5 else 0.7
        return {"label": "hydra", "confidence": conf, "reasons": reasons}
    if n_att >= HYDRA_MIN_ATTEMPTS and dict_score >= 0.8 and n_cmd == 0:
        return {"label": "hydra", "confidence": 0.8,
                "reasons": [f"dictionary-order score {dict_score:.2f}",
                            f"{n_att} attempts, no commands"]}

    # 5. Manual: slow, exploratory, typos, few guesses, long session.
    if features["exploratory_commands"] >= 2:
        reasons.append(
            f"{features['exploratory_commands']} exploratory commands")
    if features["has_typo"]:
        reasons.append("typo in command stream (human error)")
    if cmd_gap is not None and cmd_gap >= MANUAL_MIN_INTERVAL_S:
        reasons.append(f"slow command tempo ({cmd_gap:.1f}s mean gap)")
    if dur >= MANUAL_MIN_DURATION_S:
        reasons.append(f"long session ({dur:.0f}s)")
    if reasons and n_att <= 2:
        conf = 0.85 if features["has_typo"] or len(reasons) >= 3 else 0.7
        return {"label": "manual", "confidence": conf, "reasons": reasons}
    if features["has_typo"] and n_cmd >= 1:
        return {"label": "manual", "confidence": 0.75,
                "reasons": ["typo in command stream (human error)"]}

    # 6. Not enough evidence.
    return {"label": "unknown", "confidence": 0.4,
            "reasons": [f"{n_att} attempt(s), {n_cmd} command(s), "
                        f"gap={gap}, duration={dur:.1f}s"]}


def fingerprint_sessions(events: list[dict]) -> dict:
    """Fingerprint every session in a log, with botnet context.

    Two passes: first classify each session alone, then re-check
    hydra-like sessions for a password list shared across IPs —
    that is what turns ``hydra`` into ``botnet``.
    """
    features = build_session_features(events)
    # Password-list -> set of IPs that used it (per-session sets).
    pw_to_ips: dict[frozenset, set] = defaultdict(set)
    for f in features.values():
        if f["password_set"]:
            pw_to_ips[frozenset(f["password_set"])].add(f["src_ip"])
    result = {}
    for sid, f in features.items():
        # Best shared-list overlap for this session's password set.
        best_j, best_n = 0.0, 0
        for pw_set, ips in pw_to_ips.items():
            if not f["password_set"]:
                continue
            inter = len(f["password_set"] & set(pw_set))
            union = len(f["password_set"] | set(pw_set))
            j = inter / union if union else 0.0
            if j > best_j:
                best_j, best_n = j, len(ips)
        cls = classify_session(f, shared_password_ips=best_n,
                               shared_password_jaccard=best_j)
        result[sid] = {**f, **cls,
                       "shared_password_ips": best_n,
                       "shared_password_jaccard": round(best_j, 3)}
    return result


def fingerprint_summary(fingerprints: dict) -> dict:
    """Counts by label, for reports."""
    counts = Counter(v["label"] for v in fingerprints.values())
    return {"by_label": dict(counts),
            "total_sessions": len(fingerprints)}
