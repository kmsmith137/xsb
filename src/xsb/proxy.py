"""The egress proxy (plan §7.1) and the net-* verbs.

One proxy per user serves every sandbox. It filters HTTPS by the CONNECT
hostname (no TLS interception) and plain HTTP by the request's host. It
re-reads the allow and deny lists on every request, so `xsb net-allow` takes
effect at once. An entry matches the domain and its subdomains, and deny wins
over allow. A blocked request gets a 403 whose body names the domain and the
command that approves it.

Listeners, all in the runtime dir (see Context.runtime_dir):

  sock/proxy.sock   HTTP proxy (Linux; reached through the in-sandbox relay)
  sock/dns.sock     DNS forwarder (Linux, enforced mode): each connection
                    carries DNS messages with the 2-byte length prefix of DNS
                    over TCP; each query goes, unmodified and unfiltered, to
                    the host's resolver
  127.0.0.1:PORT    HTTP proxy over TCP (macOS; the port is in proxy.port)

Sandboxes bind-mount the sock/ *directory*, never the socket files, so a
restarted proxy's new sockets are seen by sandboxes that are already running.

Run `python -m xsb.proxy` to keep a proxy in the foreground, for debugging.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

from . import __version__, agents
from .context import Context, os_name

MAX_UNIX_PATH = 104          # macOS's limit (Linux allows 108)
LOG_ROTATE_BYTES = 10 << 20


# --------------------------------------------------------------------------
# Runtime dir
# --------------------------------------------------------------------------

class Runtime:
    """Paths of the proxy's files in the runtime dir."""

    def __init__(self, path: str):
        self.dir = path
        self.sock_dir = os.path.join(path, "sock")
        self.proxy_sock = os.path.join(self.sock_dir, "proxy.sock")
        self.dns_sock = os.path.join(self.sock_dir, "dns.sock")
        self.pidfile = os.path.join(path, "proxy.pid")
        self.versionfile = os.path.join(path, "proxy.version")
        self.portfile = os.path.join(path, "proxy.port")
        self.lockfile = os.path.join(path, "proxy.lock")
        self.logfile = os.path.join(path, "proxy.log")

    def make(self):
        for d in (self.dir, self.sock_dir):
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
        for s in (self.proxy_sock, self.dns_sock):
            if len(s.encode()) >= MAX_UNIX_PATH:
                raise ProxyError(f"socket path too long for a Unix socket ({len(s)} bytes): {s}")


class ProxyError(Exception):
    pass


# --------------------------------------------------------------------------
# Domain lists and the allow/deny decision
# --------------------------------------------------------------------------

def load_list(path: str) -> list[str]:
    """Entries of a domain list: "#" comments and blank lines dropped, lowercased."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    out.append(line)
    except FileNotFoundError:
        pass
    return out


def host_matches(host: str, entry: str) -> bool:
    """An entry matches its own domain and any subdomain; "*.foo.com" == "foo.com"."""
    host = host.lower().rstrip(".")
    entry = entry.lstrip("*").lstrip(".").rstrip(".")
    return bool(entry) and (host == entry or host.endswith("." + entry))


def decide(host: str, allow_path: str, deny_path: str, builtin=None) -> str:
    """"deny", "allow" or "block" (not on any list). Deny wins over allow."""
    builtin = agents.all_domains() if builtin is None else builtin
    if any(host_matches(host, e) for e in load_list(deny_path)):
        return "deny"
    if any(host_matches(host, e) for e in list(builtin) + load_list(allow_path)):
        return "allow"
    return "block"


# --------------------------------------------------------------------------
# The proxy server
# --------------------------------------------------------------------------

def pipe(a: socket.socket, b: socket.socket):
    """Copy between two sockets in both directions until either side closes."""
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [])
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def recv_until(sock: socket.socket, data: bytes, marker: bytes, cap: int = 65536) -> bytes:
    while marker not in data and len(data) < cap:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr == "::1" or addr.startswith("::ffff:127.")


class Proxy:
    def __init__(self, runtime: Runtime, allow_path: str, deny_path: str,
                 unix: bool = True, tcp: bool = False, dns: bool = True,
                 resolver: tuple | None = None, builtin=None):
        self.rt = runtime
        self.allow_path = allow_path
        self.deny_path = deny_path
        self.unix, self.tcp, self.dns = unix, tcp, dns
        self.resolver = resolver          # (host, port); None: the host's resolv.conf
        self.builtin = builtin
        self.listeners = []
        self.port = None
        self.allow_loopback = False       # tests only: let allowed names reach loopback servers

    # -- logging --

    def log(self, msg: str):
        try:
            with open(self.rt.logfile, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except OSError:
            pass

    # -- HTTP --

    def decide(self, host: str) -> str:
        return decide(host, self.allow_path, self.deny_path, self.builtin)

    def send_block(self, client, host: str, d: str):
        if d == "deny":
            self.log(f"DENIED   {host}")
            body = f'xsb: egress to "{host}" is denied (listed in net-deny.txt).\n'
        else:
            self.log(f"BLOCKED  {host}   -> approve: xsb net-allow {host}")
            body = (f'xsb: egress to "{host}" is not on the allowlist.\n'
                    f"Approve it on the host with:  xsb net-allow {host}\n"
                    f"(or block it for good with:   xsb net-deny {host})\n")
        self.send_status(client, "403 Forbidden", body)

    @staticmethod
    def send_status(client, status: str, body: str = ""):
        b = body.encode()
        client.sendall(f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                       f"Content-Length: {len(b)}\r\n\r\n".encode() + b)

    def open_upstream(self, client, host: str, port: int):
        """Apply the decision, then connect. On failure, answer the client and return None."""
        d = self.decide(host)
        if d != "allow":
            self.send_block(client, host, d)
            return None
        try:
            up = socket.create_connection((host, port), timeout=15)
        except OSError as e:
            self.send_status(client, "502 Bad Gateway", f"xsb: cannot connect to {host}:{port}: {e}\n")
            return None
        # The host's own loopback services are never a destination, even for an
        # allowed name that resolves there.
        if is_loopback(up.getpeername()[0]) and not self.allow_loopback:
            up.close()
            self.log(f"BLOCKED  {host}   (resolves to the host's loopback)")
            self.send_status(client, "403 Forbidden",
                             f'xsb: egress to "{host}" is refused: it resolves to a loopback address.\n')
            return None
        up.settimeout(None)
        client.settimeout(None)
        return up

    def handle_http(self, client):
        up = None
        try:
            client.settimeout(30)
            data = recv_until(client, b"", b"\r\n")
            if not data:
                return
            first, _, rest = data.partition(b"\r\n")
            parts = first.decode("latin1", "replace").split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":                        # HTTPS tunnel
                host, _, p = target.rpartition(":")
                host = (host or target).strip("[]")
                port = int(p) if p.isdigit() else 443
                recv_until(client, data, b"\r\n\r\n")        # discard the CONNECT headers
                up = self.open_upstream(client, host, port)
                if up is None:
                    return
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                pipe(client, up)
            elif "://" in target:                           # plain-HTTP proxy request
                u = urlsplit(target)
                host, port = (u.hostname or ""), (u.port or 80)
                up = self.open_upstream(client, host, port)
                if up is None:
                    return
                path = (u.path or "/") + (("?" + u.query) if u.query else "")
                up.sendall(f"{method} {path} HTTP/1.1\r\n".encode() + rest)
                pipe(client, up)
            else:
                self.send_status(client, "400 Bad Request", "xsb: not a proxy request\n")
        except (OSError, ValueError):
            pass
        finally:
            for s in (client, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    # -- DNS --

    def upstream_resolver(self) -> tuple:
        if self.resolver:
            return self.resolver
        return (host_nameserver(), 53)

    def handle_dns(self, client):
        try:
            client.settimeout(30)
            while True:
                head = recv_exact(client, 2)
                if head is None:
                    return
                query = recv_exact(client, struct.unpack("!H", head)[0])
                if query is None:
                    return
                reply = forward_dns(query, self.upstream_resolver())
                client.sendall(struct.pack("!H", len(reply)) + reply)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    # -- serving --

    def bind(self):
        self.rt.make()
        if self.unix:
            self.listeners.append((unix_listener(self.rt.proxy_sock), self.handle_http))
        if self.dns and self.unix:
            self.listeners.append((unix_listener(self.rt.dns_sock), self.handle_dns))
        if self.tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", self.port_to_reuse()))
            s.listen(128)
            self.port = s.getsockname()[1]
            self.listeners.append((s, self.handle_http))
            write_file(self.rt.portfile, f"{self.port}\n")

    def port_to_reuse(self) -> int:
        """The previous proxy's port if it's free, so running sandboxes keep working."""
        try:
            port = int(open(self.rt.portfile).read().strip())
        except (OSError, ValueError):
            return 0
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            return 0
        finally:
            s.close()

    def start_threads(self):
        for srv, handler in self.listeners:
            threading.Thread(target=self.accept_loop, args=(srv, handler), daemon=True).start()

    @staticmethod
    def accept_loop(srv, handler):
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                if srv.fileno() < 0:
                    return
                continue
            threading.Thread(target=handler, args=(client,), daemon=True).start()

    def close(self):
        for srv, _ in self.listeners:
            try:
                srv.close()
            except OSError:
                pass


def unix_listener(path: str) -> socket.socket:
    try:
        os.unlink(path)                 # a stale socket from an earlier proxy
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(128)
    return s


def write_file(path: str, text: str):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# DNS forwarding
# --------------------------------------------------------------------------

def host_nameserver(resolv_conf: str = "/etc/resolv.conf") -> str:
    """The first nameserver in the host's resolv.conf (read for every query)."""
    try:
        with open(resolv_conf) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1].split("%")[0]
    except OSError:
        pass
    return "127.0.0.1"


def _addr_family(host: str):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def forward_dns(query: bytes, resolver: tuple, timeout: float = 3.0) -> bytes:
    """Send a query to the resolver over UDP (retrying over TCP if the reply is
    truncated) and return the reply unchanged; SERVFAIL if nothing comes back."""
    host, port = resolver
    try:
        u = socket.socket(_addr_family(host), socket.SOCK_DGRAM)
        try:
            u.settimeout(timeout)
            u.connect((host, port))
            reply = None
            for _attempt in range(2):
                u.send(query)
                try:
                    while reply is None:
                        r = u.recv(65535)
                        if r[:2] == query[:2]:      # skip stray replies to other ids
                            reply = r
                except socket.timeout:
                    continue
                break
        finally:
            u.close()
        if reply is not None and len(reply) > 2 and reply[2] & 0x02:     # TC bit
            reply = dns_over_tcp(query, resolver, timeout) or reply
        if reply is not None:
            return reply
    except OSError:
        pass
    return servfail(query)


def dns_over_tcp(query: bytes, resolver: tuple, timeout: float) -> bytes | None:
    try:
        with socket.create_connection(resolver, timeout=timeout) as t:
            t.sendall(struct.pack("!H", len(query)) + query)
            head = recv_exact(t, 2)
            if head is None:
                return None
            return recv_exact(t, struct.unpack("!H", head)[0])
    except OSError:
        return None


def servfail(query: bytes) -> bytes:
    """A SERVFAIL reply echoing the query's id and question."""
    if len(query) < 12:
        return b""
    qid, flags, qdcount = struct.unpack("!HHH", query[:6])
    rd = flags & 0x0100
    opcode = flags & 0x7800
    end = 12
    try:
        for _ in range(qdcount):
            while True:
                n = query[end]
                if n & 0xC0:
                    end += 2
                    break
                end += 1 + n
                if n == 0:
                    break
            end += 4                   # qtype, qclass
    except IndexError:
        qdcount, end = 0, 12
    flags = 0x8000 | opcode | rd | 0x0080 | 2         # QR, RA, rcode=SERVFAIL
    return struct.pack("!HHHHHH", qid, flags, qdcount, 0, 0, 0) + query[12:end]


# --------------------------------------------------------------------------
# Lifecycle: start, stop, status
# --------------------------------------------------------------------------

def lock_held(rt: Runtime) -> bool:
    """True if a proxy holds the runtime dir's lock (i.e. is running)."""
    try:
        fd = os.open(rt.lockfile, os.O_RDWR)
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def running_pid(rt: Runtime) -> int | None:
    if not lock_held(rt):
        return None
    try:
        return int(open(rt.pidfile).read().strip())
    except (OSError, ValueError):
        return None


def running_version(rt: Runtime) -> str:
    try:
        return open(rt.versionfile).read().strip()
    except OSError:
        return ""


def ready(rt: Runtime, os_: str) -> bool:
    if running_pid(rt) is None:
        return False
    try:
        if os_ == "macos":
            port = int(open(rt.portfile).read().strip())
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        for path in (rt.proxy_sock, rt.dns_sock):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.settimeout(0.5)
                s.connect(path)
            finally:
                s.close()
        return True
    except (OSError, ValueError):
        return False


def running_port(ctx: Context) -> int | None:
    """macOS: the running proxy's TCP port."""
    try:
        return int(open(Runtime(ctx.runtime_dir).portfile).read().strip())
    except (OSError, ValueError):
        return None


def proxy_argv(ctx: Context) -> list[str]:
    return [sys.executable, "-m", "xsb.proxy", "--runtime-dir", ctx.runtime_dir,
            "--xsb-home", ctx.xsb_home]


def ensure_running(ctx: Context, quiet: bool = False) -> Runtime:
    """Start the proxy if it isn't running (the launch verbs call this)."""
    rt = Runtime(ctx.runtime_dir)
    if ready(rt, ctx.os):
        return rt
    rt.make()
    rotate_log(rt.logfile)
    env = dict(os.environ)
    # Make sure the child can import this xsb, even when it isn't installed.
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = pkg_parent + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with open(rt.logfile, "a") as logf:
        subprocess.Popen(proxy_argv(ctx), stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
                         start_new_session=True, close_fds=True, env=env, cwd="/")
    for _ in range(100):
        if ready(rt, ctx.os):
            if not quiet:
                print(f"xsb: started the egress proxy (log: {ctx.tilde(rt.logfile)})",
                      file=sys.stderr)
            return rt
        time.sleep(0.05)
    raise ProxyError(f"the egress proxy failed to start; see {rt.logfile}")


def stop(ctx: Context) -> int | None:
    """Stop the proxy; returns its pid, or None if it wasn't running."""
    rt = Runtime(ctx.runtime_dir)
    pid = running_pid(rt)
    if pid is None:
        return None
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return None
    for _ in range(100):
        if not lock_held(rt):
            break
        time.sleep(0.03)
    return pid


def rotate_log(path: str):
    try:
        if os.path.getsize(path) > LOG_ROTATE_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Status and the net-* verbs
# --------------------------------------------------------------------------

def list_files(ctx: Context) -> list[tuple[str, str]]:
    return [("allow", ctx.allow_list), ("deny", ctx.deny_list)]


def broken_link(path: str) -> bool:
    return os.path.islink(path) and not os.path.exists(path)


def list_problems(ctx: Context) -> list[str]:
    return [f"{ctx.tilde(p)} is a broken symlink (to {os.readlink(p)}); "
            "fix the link or the file it points to"
            for _, p in list_files(ctx) if broken_link(p)]


def version_problem(ctx: Context) -> str:
    rt = Runtime(ctx.runtime_dir)
    if running_pid(rt) is None:
        return ""
    v = running_version(rt)
    if v != __version__:
        return (f"the proxy runs xsb {v or '(unknown)'}, but xsb {__version__} is installed; "
                "fix: `xsb net-stop` (the next launch starts the new one)")
    return ""


def status_lines(ctx: Context) -> list[str]:
    rt = Runtime(ctx.runtime_dir)
    lines = ["Proxy"]
    pid = running_pid(rt)
    if pid is None:
        lines.append("  stopped (the next launch starts it)")
    else:
        v = running_version(rt)
        mark = "" if v == __version__ else f"  ⚠ older than the installed xsb {__version__}"
        lines.append(f"  running (pid {pid}, xsb {v or '?'}){mark}")
    lines.append(f"  {'runtime:':<11}{ctx.tilde(rt.dir)}")
    for label, p in list_files(ctx):
        if broken_link(p):
            state = "broken symlink"
        elif os.path.exists(p):
            state = f"{len(load_list(p))} entries"
        else:
            state = "missing"
        shown = ctx.tilde(p) + (f" -> {ctx.tilde(os.path.realpath(p))}" if os.path.islink(p) else "")
        lines.append(f"  {label + ':':<11}{shown}  ({state})")
    lines.append(f"  {'built in:':<11}{' '.join(agents.all_domains())}  "
                 f"({len(agents.all_domains())} entries: the agents' required domains)")
    return lines


DOMAIN = re.compile(r"(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?")


def add_to_list(ctx: Context, which: str, domains: list[str], header: str) -> list[str]:
    """Append domains to ~/.xsb/net-{which}.txt (through a symlink); returns messages."""
    if not os.path.isdir(ctx.xsb_home):
        raise ProxyError(f"{ctx.tilde(ctx.xsb_home)} does not exist; run `xsb init`")
    path = ctx.allow_list if which == "allow" else ctx.deny_list
    if broken_link(path):
        raise ProxyError(f"{ctx.tilde(path)} is a broken symlink (to {os.readlink(path)}); "
                         "fix it first (it is never replaced by a new file)")
    clean = []
    for d in domains:
        d = d.strip().lower()
        if not DOMAIN.fullmatch(d):
            raise ProxyError(f"not a domain name: {d!r} (give just the host, e.g. example.com)")
        if d not in clean:
            clean.append(d)
    existing = set(load_list(path))
    add = [d for d in clean if d not in existing]
    msgs = []
    shown = ctx.tilde(path) + (f" -> {ctx.tilde(os.path.realpath(path))}" if os.path.islink(path) else "")
    if add:
        new = not os.path.exists(path)
        need_nl = False
        if not new and os.path.getsize(path) > 0:
            with open(path, "rb") as f:
                f.seek(-1, os.SEEK_END)
                need_nl = f.read(1) != b"\n"
        with open(path, "a") as f:
            if new:
                f.write(header)
            if need_nl:
                f.write("\n")
            for d in add:
                f.write(d + "\n")
        verb = "allowed" if which == "allow" else "denied"
        msgs.append(f"{verb}: {', '.join(add)}  (added to {shown}; effective on the next request)")
    for d in clean:
        if d not in add:
            msgs.append(f"{d}: already in {shown}")
    if which == "allow":
        denied = load_list(ctx.deny_list)
        for d in clean:
            if any(host_matches(d.lstrip("*."), e) for e in denied):
                msgs.append(f"note: {d} is also matched by {ctx.tilde(ctx.deny_list)}, "
                            "and deny wins")
    return msgs


def log_lines(ctx: Context) -> list[str] | None:
    rt = Runtime(ctx.runtime_dir)
    lines = []
    found = False
    for path in (rt.logfile + ".1", rt.logfile):
        try:
            with open(path) as f:
                found = True
                lines += [l.rstrip("\n") for l in f if " BLOCKED " in l or " DENIED " in l]
        except FileNotFoundError:
            pass
    return lines if found else None


# --------------------------------------------------------------------------
# python -m xsb.proxy
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m xsb.proxy",
                                 description="Run xsb's egress proxy in the foreground.")
    ap.add_argument("--runtime-dir", help="default: the per-user runtime dir")
    ap.add_argument("--xsb-home", help="where net-allow.txt and net-deny.txt are (default ~/.xsb)")
    args = ap.parse_args(argv)
    ctx = Context.from_process()
    rt = Runtime(args.runtime_dir or ctx.runtime_dir)
    home = args.xsb_home or ctx.xsb_home
    rt.make()

    lock = os.open(rt.lockfile, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"xsb proxy: another proxy is already running in {rt.dir}", file=sys.stderr)
        return 0

    macos = os_name() == "macos"
    proxy = Proxy(rt, os.path.join(home, "net-allow.txt"), os.path.join(home, "net-deny.txt"),
                  unix=not macos, tcp=macos, dns=not macos)
    proxy.bind()
    write_file(rt.versionfile, __version__ + "\n")
    write_file(rt.pidfile, f"{os.getpid()}\n")
    where = f"127.0.0.1:{proxy.port}" if proxy.port else rt.sock_dir
    proxy.log(f"--- proxy up (pid {os.getpid()}, xsb {__version__}) on {where}; "
              f"lists in {home} ---")

    stopping = threading.Event()

    def on_signal(*_):
        stopping.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    proxy.start_threads()
    while not stopping.wait(3600):
        pass
    proxy.log(f"--- proxy stopped (pid {os.getpid()}) ---")
    try:
        os.unlink(rt.pidfile)
    except OSError:
        pass
    proxy.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
