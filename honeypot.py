#!/usr/bin/env python3
"""
Decoy Honeypot Lab — low-interaction SSH honeypot (Python stdlib only).

What it does
------------
Listens on a configurable TCP port (default **2222**, deliberately NOT
port 22) and pretends to be an OpenSSH server:

1. Sends a fake SSH banner (``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``).
2. Reads the client's banner, then asks for a username and a password
   — exactly like a login prompt — and **logs both**.
3. "Accepts" the login and presents a fake shell prompt. A small set of
   harmless commands (``ls``, ``pwd``, ``whoami``, ``help``, ``exit`` …)
   returns canned, hard-coded output. Anything else gets
   ``command not found``. Every command is logged.

What it NEVER does (the safety contract)
----------------------------------------
* No real shell. Attacker input is **never** passed to ``os.system``,
  ``subprocess``, ``eval`` or ``exec`` — commands are answered by a
  dictionary lookup only.
* No real login. There is no account, no password file, no SSH daemon.
  Every credential is accepted *by the decoy* and logged; nothing on
  the host is ever authenticated against.
* No outbound connections, no file writes outside the log directory.

Run it only in an isolated lab / VM, on a private network, behind a
firewall. Never point it at the internet unless you understand the
risk — a honeypot *invites* attention by design.

Usage::

    python3 honeypot.py                       # 127.0.0.1:2222
    python3 honeypot.py --host 0.0.0.0 --port 2222
    python3 honeypot.py --log logs/honeypot.jsonl --db logs/honeypot.db
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
import uuid

from src.logger import HoneypotLogger, make_event, utc_now

# ---------------------------------------------------------------------------
# Decoy identity — the "server" attackers think they are talking to.
# ---------------------------------------------------------------------------
FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
FAKE_HOSTNAME = "honeypot"
MAX_COMMANDS_PER_SESSION = 10
SESSION_TIMEOUT = 60          # seconds of inactivity before we hang up
RECV_TIMEOUT = 10             # seconds to wait for banner / credentials

# Canned, hard-coded replies. The key is the *exact* command string;
# anything not in this table is answered "command not found".
# NOTHING here is executed — it is a lookup table, by design.
CANNED_OUTPUTS = {
    "ls": "Desktop  Documents  Downloads  notes.txt  public_html\n",
    "ls -la": "total 32\ndrwxr-xr-x 5 user user 4096 Nov 21 02:00 .\n"
              "drwxr-xr-x 3 root root 4096 Nov 21 01:00 ..\n"
              "-rw-r--r-- 1 user user  220 Nov 21 02:00 notes.txt\n",
    "pwd": "/home/user\n",
    "whoami": "user\n",
    "id": "uid=1000(user) gid=1000(user) groups=1000(user)\n",
    "uname": "Linux honeypot 5.15.0-91-generic x86_64 GNU/Linux\n",
    "uname -a": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP "
                "x86_64 GNU/Linux\n",
    "hostname": "honeypot\n",
    "date": "Sat Nov 21 02:00:00 UTC 2026\n",
    "cat notes.txt": "TODO: change the default password (reminder).\n",
    "help": "Available commands: ls, pwd, whoami, id, uname, hostname, "
            "date, cat notes.txt, help, exit\n",
}


def fake_shell_response(command: str) -> str:
    """Return canned output for a command. Never executes anything."""
    cmd = command.strip()
    if cmd in CANNED_OUTPUTS:
        return CANNED_OUTPUTS[cmd]
    if cmd.startswith("cd "):
        return ""  # pretend the directory change worked; stay put
    if cmd == "":
        return ""
    return f"bash: {cmd.split()[0]}: command not found\n"


def recv_line(conn: socket.socket, limit: int = 1024) -> str:
    """Read one CRLF/LF-terminated line from the socket, as text."""
    data = b""
    while len(data) < limit:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\n"):
            break
    return data.decode("utf-8", errors="replace").strip()


def handle_client(conn: socket.socket, addr, logger: HoneypotLogger) -> None:
    """Serve one attacker connection: banner, fake login, fake shell."""
    src_ip, src_port = addr[0], addr[1]
    session_id = uuid.uuid4().hex[:8]
    started = time.time()
    username = ""
    try:
        conn.settimeout(RECV_TIMEOUT)
        # 1. Fake SSH banner.
        conn.sendall((FAKE_BANNER + "\r\n").encode())

        # 2. Read the client's banner (scanners / paramiko send one).
        #    An empty read means the peer hung up after the banner
        #    (a plain port scan) — nothing more to log, just close.
        try:
            client_banner = recv_line(conn)
        except socket.timeout:
            client_banner = ""
        if not client_banner:
            return
        logger.log(make_event("session_start", session_id, src_ip, src_port,
                              client_banner=client_banner))

        # 3. Fake login prompt — one username, one password per session.
        conn.sendall(b"login as: ")
        username = recv_line(conn)
        if not username:
            return  # peer disconnected instead of logging in
        conn.sendall(
            f"{username or 'user'}@{FAKE_HOSTNAME}'s password: ".encode())
        password = recv_line(conn)
        logger.log(make_event("login_attempt", session_id, src_ip, src_port,
                              username=username, password=password))

        # 4. Fake shell. Every command is logged and answered from the
        #    canned-output table only. `exit` / `quit` / Ctrl-D ends it.
        conn.sendall(
            f"\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic "
            f"x86_64)\n\nLast login: {utc_now()} from {src_ip}\n".encode())
        conn.settimeout(SESSION_TIMEOUT)
        for _ in range(MAX_COMMANDS_PER_SESSION):
            conn.sendall(f"{username or 'user'}@{FAKE_HOSTNAME}:~$ ".encode())
            try:
                command = recv_line(conn)
            except socket.timeout:
                break
            if not command:
                break
            if command.lower() in ("exit", "quit", "logout"):
                logger.log(make_event("command", session_id, src_ip,
                                      src_port, command=command))
                conn.sendall(b"logout\n")
                break
            logger.log(make_event("command", session_id, src_ip, src_port,
                                  command=command))
            conn.sendall(fake_shell_response(command).encode())
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass  # attacker hung up — that is normal for a honeypot
    finally:
        duration = round(time.time() - started, 2)
        logger.log(make_event("session_end", session_id, src_ip, src_port,
                              username=username,
                              duration_seconds=duration))
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decoy Honeypot Lab — low-interaction SSH honeypot.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind (default: 127.0.0.1 — "
                             "use 0.0.0.0 only in an isolated lab)")
    parser.add_argument("--port", type=int, default=2222,
                        help="TCP port to listen on (default: 2222, "
                             "deliberately NOT 22)")
    parser.add_argument("--log", default="logs/honeypot.jsonl",
                        help="JSON Lines log path")
    parser.add_argument("--db", default="logs/honeypot.db",
                        help="SQLite database path")
    args = parser.parse_args()

    logger = HoneypotLogger(args.log, args.db)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(50)
    print(f"[+] Decoy Honeypot Lab listening on {args.host}:{args.port}", flush=True)
    print(f"[+] Banner: {FAKE_BANNER}", flush=True)
    print(f"[+] Logs: {args.log}  |  SQLite: {args.db}", flush=True)
    print("[+] No real shell. No real login. Attacker input is never "
          "executed.", flush=True)
    print("[+] Press Ctrl-C to stop.", flush=True)
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Connection from {addr[0]}:{addr[1]}", flush=True)
            threading.Thread(target=handle_client, args=(conn, addr, logger),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[+] Shutting down honeypot.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
