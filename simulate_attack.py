#!/usr/bin/env python3
"""
Decoy Honeypot Lab — attack simulator (safe, localhost only).

Generates realistic honeypot traffic WITHOUT the internet: it connects
to the honeypot running on localhost, tries common brute-force
credentials (``root/123456``, ``admin/admin`` …) and runs a few
harmless commands (``ls``, ``pwd``, ``whoami``), exactly like the
automated bots a real SSH honeypot sees.

This is how reviewers demo the project: start the honeypot in one
terminal, run this script in another, then run ``analyze.py`` to see
the attacker report it produces.

Safety: the target is hard-coded to 127.0.0.1 and the port defaults to
2222. It never touches a real host, never scans anything, and the
commands it sends are the honeypot's own canned commands.

Usage::

    # Terminal 1
    python3 honeypot.py
    # Terminal 2
    python3 simulate_attack.py
    python3 simulate_attack.py --port 2222 --rounds 2
"""

from __future__ import annotations

import argparse
import socket
import time

# Credentials automated SSH bots actually try (from public honeypot
# research). One pair per connection, like a real brute-forcer.
CREDENTIALS = [
    ("root", "123456"),
    ("root", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "user"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("pi", "raspberry"),
    ("root", "12345678"),
    ("admin", "123456"),
    ("root", "qwerty"),
    ("guest", "guest"),
]

# Harmless commands bots run after (fake) login to fingerprint a host.
COMMANDS = ["ls", "pwd", "whoami", "uname -a", "id", "exit"]


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 5.0):
    """Read from the socket until `marker` appears (or timeout)."""
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def one_attempt(host: str, port: int, username: str, password: str,
                commands: list[str]) -> bool:
    """One brute-force attempt: connect, log in, run commands, exit."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            recv_until(sock, b"\n")                    # fake SSH banner
            sock.sendall(b"SSH-2.0-OpenSSH_8.2\r\n")  # our client banner
            recv_until(sock, b"login as: ")
            sock.sendall((username + "\r\n").encode())
            recv_until(sock, b"password: ")
            sock.sendall((password + "\r\n").encode())
            recv_until(sock, b"$ ")                    # fake shell prompt
            for cmd in commands:
                sock.sendall((cmd + "\r\n").encode())
                if cmd in ("exit", "quit"):
                    break
                recv_until(sock, b"$ ")
        print(f"  [attempt] {username}:{password}  -> logged")
        return True
    except OSError as exc:
        print(f"  [failed]  {username}:{password}  -> {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate SSH brute-force attacks against the "
                    "local honeypot (localhost only).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="honeypot host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2222,
                        help="honeypot port (default: 2222)")
    parser.add_argument("--rounds", type=int, default=1,
                        help="how many times to replay the credential "
                             "list (default: 1)")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            "Refusing to simulate attacks against a non-localhost host. "
            "This simulator is for the local lab only.")
    print(f"[+] Simulating {len(CREDENTIALS) * args.rounds} login attempts "
          f"against {args.host}:{args.port}")
    ok = 0
    for round_no in range(1, args.rounds + 1):
        print(f"[+] Round {round_no}/{args.rounds}")
        for username, password in CREDENTIALS:
            if one_attempt(args.host, args.port, username, password,
                           COMMANDS):
                ok += 1
            time.sleep(0.05)
    print(f"[+] Done: {ok} attempts sent. Now run: "
          f"python3 analyze.py --log logs/honeypot.jsonl "
          f"--output report.html --json summary.json")


if __name__ == "__main__":
    main()
