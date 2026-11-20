#!/usr/bin/env python3
"""
Decoy Fabric v2 — adaptive SSH honeypot (Python stdlib only).

v1 pretended to be one fixed Ubuntu box. v2 watches *how* an
attacker behaves, fingerprints the tool, and changes the decoy
to match — the Decoy Fabric concept:

1. Per-IP memory: every login attempt is recorded (passwords,
   timestamps). After a few attempts the IP is fingerprinted
   (see ``src/fingerprint.py``) and an adaptive policy is chosen
   (see ``src/adaptive.py`` / ``config/adaptive_policy.json``).
2. The *next* connection from that IP gets the policy's banner,
   delay and filesystem. Hydra gets tarpitted + fake-locked out;
   a manual actor gets a rich filesystem full of canary files.
3. Reading a canary file logs a HIGH-severity ``canary_accessed``
   event — the attacker just told you what they want to steal.

Safety contract (same as v1, unchanged):
* Bind is 127.0.0.1 by default; ports 2222 (SSH) only here.
* Attacker input is NEVER executed — commands are answered by
  canned lookup tables, canary reads by a string match.
* No real shell, no real login, no outbound connections.

Usage::

    python3 honeypot_v2.py                    # 127.0.0.1:2222, adaptive on
    python3 honeypot_v2.py --no-adaptive      # behave like v1
    python3 honeypot_v2.py --port 2222 --log logs/honeypot.jsonl
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
import uuid

import honeypot as v1
from src.adaptive import get_policy, load_policies
from src.canary import canary_for_command, make_canary_event
from src.fingerprint import build_session_features, classify_session
from src.logger import HoneypotLogger, make_event, utc_now

# Rich-filesystem canary contents, served by `cat` on the fake shell.
from src.canary import CANARIES

CANARY_CONTENT = {c["path"]: c["content"] for c in CANARIES}


class AdaptiveState:
    """Per-IP memory: attempts, passwords, timestamps, policy."""

    def __init__(self, policies):
        self.policies = policies
        self.lock = threading.Lock()
        self.by_ip: dict[str, dict] = {}

    def record_attempt(self, ip: str, password: str, ts: float) -> dict:
        """Record one attempt; return the IP's current fingerprint."""
        with self.lock:
            rec = self.by_ip.setdefault(ip, {
                "passwords": [], "timestamps": [], "label": "unknown",
                "policy_label": "default", "attempts": 0})
            rec["passwords"].append(password)
            rec["timestamps"].append(ts)
            rec["attempts"] += 1
            # Fingerprint from this IP's history so far.
            feats = {
                "n_attempts": rec["attempts"],
                "n_commands": 0,
                "mean_attempt_gap_s": (
                    (rec["timestamps"][-1] - rec["timestamps"][0])
                    / max(1, len(rec["timestamps"]) - 1)
                    if len(rec["timestamps"]) > 1 else None),
                "mean_command_gap_s": None,
                "duration_seconds": (
                    rec["timestamps"][-1] - rec["timestamps"][0]
                    if len(rec["timestamps"]) > 1 else 0.0),
                "passwords": rec["passwords"],
                "has_sql": False,
                "has_typo": False,
                "exploratory_commands": 0,
                "client_banner": "",
            }
            cls = classify_session(feats)
            rec["label"] = cls["label"]
            rec["policy_label"] = cls["label"]
            return dict(rec)

    def policy_for_ip(self, ip: str):
        label = self.by_ip.get(ip, {}).get("policy_label", "default")
        return get_policy(label, self.policies)

    def attempts_from_ip(self, ip: str) -> int:
        return self.by_ip.get(ip, {}).get("attempts", 0)


def fake_shell_response_v2(command: str, policy) -> str:
    """Canned shell output under an adaptive policy.

    Policy filesystem overrides `ls` variants; canary files return
    their fake content; everything else falls back to v1's table.
    Never executes anything.
    """
    cmd = command.strip()
    # Canary read: return the fake secret, the caller logs the event.
    canary = canary_for_command(cmd)
    if canary:
        return CANARY_CONTENT.get(canary["path"], "")
    # Policy filesystem (rich/minimal ls).
    out = policy.ls_output(cmd)
    if out is not None:
        return out
    if cmd in ("ls .aws", "ls .ssh", "ls Documents", "ls documents"):
        # Rich profile covers these; other profiles: not found.
        return f"ls: cannot access '{cmd[3:]}': No such file or directory\n"
    if cmd.startswith("cat "):
        # A non-canary cat: only notes.txt exists in every profile.
        if cmd == "cat notes.txt":
            return "TODO: change the default password (reminder).\n"
        return f"cat: {cmd[4:]}: No such file or directory\n"
    return v1.fake_shell_response(cmd)


def handle_client_v2(conn: socket.socket, addr, logger: HoneypotLogger,
                     state: AdaptiveState, adaptive: bool = True) -> None:
    src_ip, src_port = addr[0], addr[1]
    session_id = uuid.uuid4().hex[:8]
    started = time.time()
    username = ""
    policy = state.policy_for_ip(src_ip) if adaptive else get_policy("default", state.policies)
    try:
        conn.settimeout(10)
        conn.sendall((policy.banner + "\r\n").encode())
        client_banner = v1.recv_line(conn)
        if not client_banner:
            # Port scan: log it so fingerprinting can call it `scanner`.
            logger.log(make_event("session_start", session_id, src_ip,
                                  src_port, client_banner=""))
            logger.log(make_event("session_end", session_id, src_ip,
                                  src_port, username="",
                                  duration_seconds=0.0))
            return
        logger.log(make_event("session_start", session_id, src_ip, src_port,
                              client_banner=client_banner))
        conn.sendall(b"login as: ")
        username = v1.recv_line(conn)
        if not username:
            return
        conn.sendall(f"{username or 'user'}@honeypot's password: ".encode())
        password = v1.recv_line(conn)
        logger.log(make_event("login_attempt", session_id, src_ip, src_port,
                              username=username, password=password))
        # Adaptive step: record, fingerprint, pick policy, tarpit/lockout.
        if adaptive:
            rec = state.record_attempt(src_ip, password, time.time())
            policy = state.policy_for_ip(src_ip)
            if policy.response_delay_s:
                time.sleep(policy.response_delay_s)
            if policy.should_lockout(state.attempts_from_ip(src_ip)):
                conn.sendall(
                    b"Account locked due to too many failed login "
                    b"attempts. Try again later.\n")
                logger.log(make_event(
                    "lockout", session_id, src_ip, src_port,
                    username=username,
                    note=f"Adaptive lockout: {rec['label']} policy after "
                         f"{state.attempts_from_ip(src_ip)} attempts"))
                return
        # Fake shell under the (possibly new) policy.
        welcome = policy.welcome or (
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)")
        conn.sendall(f"\n{welcome}\n\nLast login: {utc_now()} from {src_ip}\n".encode())
        if policy.fake_open_ports:
            conn.sendall(
                ("[system] listening services: " +
                 ", ".join(str(p) for p in policy.fake_open_ports) + "\n").encode())
        conn.settimeout(60)
        for _ in range(policy.max_commands):
            conn.sendall(f"{username or 'user'}@honeypot:~$ ".encode())
            try:
                command = v1.recv_line(conn)
            except socket.timeout:
                break
            if not command:
                break
            logger.log(make_event("command", session_id, src_ip, src_port,
                                  command=command))
            if command.lower() in ("exit", "quit", "logout"):
                conn.sendall(b"logout\n")
                break
            canary = canary_for_command(command)
            if canary:
                logger.log(make_canary_event(session_id, src_ip, src_port,
                                             canary, command))
            conn.sendall(fake_shell_response_v2(command, policy).encode())
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        logger.log(make_event("session_end", session_id, src_ip, src_port,
                              username=username,
                              duration_seconds=round(time.time() - started, 2)))
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decoy Fabric v2 — adaptive SSH honeypot.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--log", default="logs/honeypot.jsonl")
    parser.add_argument("--db", default="logs/honeypot.db")
    parser.add_argument("--adaptive", action="store_true", default=True,
                        help="enable adaptive deception (default: on)")
    parser.add_argument("--no-adaptive", dest="adaptive",
                        action="store_false",
                        help="disable adaptive deception (v1 behaviour)")
    parser.add_argument("--policy", default=None,
                        help="path to adaptive_policy.json")
    args = parser.parse_args()
    policies = load_policies(args.policy) if args.policy else load_policies()
    logger = HoneypotLogger(args.log, args.db)
    state = AdaptiveState(policies)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(50)
    print(f"[+] Decoy Fabric v2 listening on {args.host}:{args.port} "
          f"(adaptive={'on' if args.adaptive else 'off'})", flush=True)
    print("[+] Policies: " + ", ".join(sorted(policies)), flush=True)
    print("[+] No real shell. No real login. Attacker input is never executed.",
          flush=True)
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Connection from {addr[0]}:{addr[1]}", flush=True)
            threading.Thread(target=handle_client_v2,
                             args=(conn, addr, logger, state, args.adaptive),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[+] Shutting down honeypot v2.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
