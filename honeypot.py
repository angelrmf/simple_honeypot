
import argparse
import json
import logging
import random
import socket
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

import paramiko

# Pretend to be a normal, slightly outdated Ubuntu server
DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

# Usernames that "exist" on our fake server. Like real sshd, every other
# username gets an extra "Invalid user" line in the log.
VALID_USERS = {"root"}

MAX_SESSION_SECONDS = 120   # hang up on anyone who stays longer than this

# Paramiko prints a scary traceback whenever a port scanner connects and
# doesn't speak SSH. We handle those cases ourselves, so silence it.
logging.getLogger("paramiko").addHandler(logging.NullHandler())
logging.getLogger("paramiko").propagate = False


# ---------------------------------------------------------------------------
# Logging: one place that writes both log files (thread-safe)
# ---------------------------------------------------------------------------

class EventLog:
    def __init__(self, auth_path, json_path, hostname):
        self.auth_path = auth_path
        self.json_path = json_path
        self.hostname = hostname
        self.lock = threading.Lock()   # many connections write at the same time
        self.stats = {"connections": 0, "attempts": 0,
                      "ips": Counter(), "usernames": Counter(), "passwords": Counter()}

    def auth_line(self, pid, message):
        """Write one sshd-style line, e.g.
        'Oct 26 22:15:03 honeypot sshd[4242]: Failed password for root from ...'"""
        now = datetime.now()
        stamp = f"{now:%b} {now.day:2d} {now:%H:%M:%S}"
        with self.lock, open(self.auth_path, "a") as f:
            f.write(f"{stamp} {self.hostname} sshd[{pid}]: {message}\n")

    def event(self, **fields):
        """Write one JSON event and print a short line to the screen."""
        record = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  **fields}
        with self.lock:
            with open(self.json_path, "a") as f:
                f.write(json.dumps(record) + "\n")
            self._count(record)
            print(self._describe(record), flush=True)

    def _count(self, r):
        if r["event"] == "connect":
            self.stats["connections"] += 1
            self.stats["ips"][r["src_ip"]] += 1
        elif r["event"] == "login_attempt" and r["method"] == "password":
            self.stats["attempts"] += 1
            self.stats["usernames"][r["username"]] += 1
            self.stats["passwords"][r["password"]] += 1

    @staticmethod
    def _describe(r):
        clock = datetime.now().strftime("%H:%M:%S")
        who = f"{r['src_ip']}:{r['src_port']}"
        if r["event"] == "connect":
            return f"[{clock}] + connection from {who}"
        if r["event"] == "login_attempt":
            if r["method"] == "password":
                return f"[{clock}]   {who}  tried  {r['username']!r} / {r['password']!r}"
            return f"[{clock}]   {who}  offered a {r['key_type']} key for {r['username']!r}"
        if r["event"] == "disconnect":
            extra = f", {r['note']}" if r.get("note") else ""
            return (f"[{clock}] - {who} left after {r['duration_s']}s, "
                    f"{r['password_attempts']} password attempt(s){extra}")
        return f"[{clock}] {r}"


# ---------------------------------------------------------------------------
# The fake SSH server: paramiko asks this class "is this login OK?"
# and we always say no, after writing everything down.
# ---------------------------------------------------------------------------

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, session, log):
        self.session = session
        self.log = log
        self.password_attempts = 0
        self.flagged_invalid = set()   # usernames we already logged "Invalid user" for

    def get_allowed_auths(self, username):
        return "password,publickey"   # what a normal server offers

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        s = self.session
        self.password_attempts += 1

        prefix = ""
        if username not in VALID_USERS:
            prefix = "invalid user "
            if username not in self.flagged_invalid:
                self.flagged_invalid.add(username)
                self.log.auth_line(s["pid"], f"Invalid user {username} from {s['ip']} port {s['port']}")
        self.log.auth_line(
            s["pid"], f"Failed password for {prefix}{username} from {s['ip']} port {s['port']} ssh2")

        self.log.event(event="login_attempt", session=s["id"], src_ip=s["ip"],
                       src_port=s["port"], method="password",
                       username=username, password=password,
                       attempt=self.password_attempts)

        time.sleep(1)   # slow guessing down a little, like a real server does
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Normal SSH clients offer their keys first, so this isn't necessarily
        # an attack. Record it in the JSON log only.
        s = self.session
        self.log.event(event="login_attempt", session=s["id"], src_ip=s["ip"],
                       src_port=s["port"], method="publickey", username=username,
                       key_type=key.get_name(),
                       key_fingerprint=getattr(key, "fingerprint", None))
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        # Only reachable after a successful login, which never happens.
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


# ---------------------------------------------------------------------------
# Handling one connection (each runs in its own thread)
# ---------------------------------------------------------------------------

def handle_connection(client, addr, host_key, log, banner, slots):
    session = {"id": uuid.uuid4().hex[:12], "ip": addr[0], "port": addr[1],
               "pid": random.randint(1000, 65000)}   # fake sshd process id
    started = time.monotonic()
    server = FakeSSHServer(session, log)
    transport = None
    note = ""

    log.event(event="connect", session=session["id"], src_ip=addr[0], src_port=addr[1])
    try:
        transport = paramiko.Transport(client)
        transport.local_version = banner
        transport.banner_timeout = 15     # seconds to wait for the client's hello
        transport.handshake_timeout = 15
        transport.auth_timeout = 60
        transport.add_server_key(host_key)
        transport.start_server(server=server)   # raises if it isn't really SSH

        # Wait until the client gives up, or we hang up on them
        while transport.is_active() and time.monotonic() - started < MAX_SESSION_SECONDS:
            time.sleep(0.5)
        if transport.is_active():
            note = "timed out"
    except (paramiko.SSHException, EOFError, OSError):
        note = "didn't complete an SSH handshake (port scanner?)"
    except Exception as err:          # never let one bad client crash the honeypot
        note = f"error: {type(err).__name__}"
    finally:
        client_version = transport.remote_version if transport else ""
        if transport:
            transport.close()
        client.close()
        slots.release()

        log.auth_line(session["pid"],
                      f"Connection closed by {session['ip']} port {session['port']} [preauth]")
        log.event(event="disconnect", session=session["id"], src_ip=session["ip"],
                  src_port=session["port"], client_version=client_version,
                  password_attempts=server.password_attempts,
                  duration_s=round(time.monotonic() - started, 1), note=note)


# ---------------------------------------------------------------------------
# Setup and main loop
# ---------------------------------------------------------------------------

def load_host_key(path):
    """Reuse the same server key every run, so the fingerprint doesn't change
    (a changing fingerprint makes SSH clients show a big warning)."""
    try:
        return paramiko.RSAKey(filename=path)
    except FileNotFoundError:
        print(f"Creating a new host key in {path} (one time only)...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(path)
        return key


def print_summary(stats):
    print("\nHoneypot stopped. Summary:")
    print(f"  connections: {stats['connections']}   password attempts: {stats['attempts']}")
    for title, counter in [("Top IPs", stats["ips"]), ("Top usernames", stats["usernames"]),
                           ("Top passwords", stats["passwords"])]:
        if counter:
            top = ", ".join(f"{k} ({v})" for k, v in counter.most_common(5))
            print(f"  {title}: {top}")


def main():
    parser = argparse.ArgumentParser(description="A small low-interaction SSH honeypot.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="address to listen on (default: 127.0.0.1, only this computer)")
    parser.add_argument("--port", type=int, default=2222,
                        help="port to listen on (default: 2222)")
    parser.add_argument("--auth-log", default="honeypot_auth.log",
                        help="sshd-style log file (default: honeypot_auth.log)")
    parser.add_argument("--json-log", default="honeypot.jsonl",
                        help="detailed JSON-lines log (default: honeypot.jsonl)")
    parser.add_argument("--hostname", default="honeypot",
                        help="server name written in the auth log (default: honeypot)")
    parser.add_argument("--banner", default=DEFAULT_BANNER,
                        help="SSH version string to show clients")
    parser.add_argument("--host-key", default="honeypot_host_key",
                        help="file for the server's SSH key (created if missing)")
    parser.add_argument("--max-connections", type=int, default=50,
                        help="most connections handled at once (default: 50)")
    args = parser.parse_args()

    host_key = load_host_key(args.host_key)
    log = EventLog(args.auth_log, args.json_log, args.hostname)
    slots = threading.BoundedSemaphore(args.max_connections)

    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((args.host, args.port))
    except OSError as err:
        raise SystemExit(f"Can't listen on {args.host}:{args.port}: {err}")
    listener.listen(100)
    listener.settimeout(1.0)   # wake up every second so Ctrl+C works on Windows too

    print(f"Honeypot listening on {args.host}:{args.port}  (Ctrl+C to stop)")
    print(f"Logging to {args.auth_log} and {args.json_log}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: reachable from other machines. Keep this inside a lab network or VM.")
    print(f"Try it from another terminal:  ssh -p {args.port} root@127.0.0.1\n")

    try:
        while True:
            try:
                client, addr = listener.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                client.close()   # too busy: drop the connection instead of falling over
                continue
            threading.Thread(target=handle_connection, daemon=True,
                             args=(client, addr, host_key, log, args.banner, slots)).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        print_summary(log.stats)


if __name__ == "__main__":
    main()
