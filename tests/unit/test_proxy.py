import os
import socket
import struct
import threading

import pytest

from conftest import write
from xsb import __version__, proxy
from xsb.proxy import Proxy, Runtime, decide, host_matches


# ---- matching ----

@pytest.mark.parametrize("host,entry,ok", [
    ("anthropic.com", "anthropic.com", True),
    ("api.anthropic.com", "anthropic.com", True),
    ("API.Anthropic.COM.", "anthropic.com", True),
    ("api.anthropic.com", "*.anthropic.com", True),
    ("anthropic.com", "*.anthropic.com", True),
    ("notanthropic.com", "anthropic.com", False),
    ("anthropic.com.evil.org", "anthropic.com", False),
    ("anything", "*", False),
])
def test_host_matches(host, entry, ok):
    assert host_matches(host, entry) == ok


def test_decide(tmp_path):
    allow = write(tmp_path / "allow.txt", "# comment\nexample.com   # inline\n\nPyPI.org\n")
    deny = write(tmp_path / "deny.txt", "bad.example.com\nclaude.ai\n")
    assert decide("www.example.com", allow, deny) == "allow"
    assert decide("pypi.org", allow, deny) == "allow"
    assert decide("bad.example.com", allow, deny) == "deny"          # deny wins over allow
    assert decide("x.bad.example.com", allow, deny) == "deny"
    assert decide("github.com", allow, deny) == "block"
    assert decide("api.anthropic.com", allow, deny) == "allow"       # built in (Claude)
    assert decide("chatgpt.com", allow, deny) == "allow"             # built in (Codex)
    assert decide("claude.ai", allow, deny) == "deny"                # deny wins over built in
    assert decide("x.com", str(tmp_path / "missing"), str(tmp_path / "missing")) == "block"


def test_lists_reread_every_time(tmp_path):
    allow = write(tmp_path / "allow.txt", "")
    deny = str(tmp_path / "deny.txt")
    assert decide("example.com", allow, deny) == "block"
    write(allow, "example.com\n")
    assert decide("example.com", allow, deny) == "allow"


# ---- symlinked lists and net-allow ----

def test_symlinked_list_reads_and_appends_reach_target(make_ctx, home, run):
    (home / ".xsb").mkdir()
    target = write(home / "repo" / "net" / "net-allow.txt", "# mine\nexample.com")
    os.symlink(target, home / ".xsb" / "net-allow.txt")
    ctx = make_ctx()
    assert decide("www.example.com", ctx.allow_list, ctx.deny_list) == "allow"
    rc, out, err = run(ctx, "net-allow", "GitHub.com", "example.com")
    assert rc == 0, err
    assert open(target).read() == "# mine\nexample.com\ngithub.com\n"   # newline fixed up
    assert os.path.islink(home / ".xsb" / "net-allow.txt")
    assert "allowed: github.com" in out and "example.com: already in" in out
    rc, out, _ = run(ctx, "net-deny", "evil.org")
    assert rc == 0 and "evil.org" in open(home / ".xsb" / "net-deny.txt").read()


def test_broken_list_symlink_is_error_and_never_replaced(make_ctx, home, run):
    (home / ".xsb").mkdir()
    link = home / ".xsb" / "net-allow.txt"
    os.symlink(home / "gone.txt", link)
    rc, _, err = run(make_ctx(), "net-allow", "example.com")
    assert rc == 1 and "broken symlink" in err
    assert os.path.islink(link) and not (home / "gone.txt").exists()


def test_net_allow_needs_xsb_home(make_ctx, run):
    rc, _, err = run(make_ctx(), "net-allow", "example.com")
    assert rc == 1 and "xsb init" in err


@pytest.mark.parametrize("bad", ["https://github.com", "github.com/foo", "a b", ""])
def test_net_allow_rejects_non_domains(make_ctx, home, run, bad):
    (home / ".xsb").mkdir()
    rc, _, err = run(make_ctx(), "net-allow", bad)
    assert rc == 1 and "not a domain" in err


def test_net_allow_warns_when_denied(make_ctx, home, run):
    (home / ".xsb").mkdir()
    write(home / ".xsb" / "net-deny.txt", "example.com\n")
    rc, out, _ = run(make_ctx(), "net-allow", "www.example.com")
    assert rc == 0 and "deny wins" in out


# ---- the server (in-process) ----

@pytest.fixture
def server(short_tmp, tmp_path):
    rt = Runtime(os.path.join(short_tmp, "rt"))
    allow = write(tmp_path / "allow.txt", "localhost\n")
    deny = write(tmp_path / "deny.txt", "denied.test\n")
    p = Proxy(rt, allow, deny, unix=True, tcp=True, dns=True)
    p.bind()
    p.start_threads()
    yield p
    p.close()


def unix_connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    return s


def recv_all(s):
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            return data
        data += chunk


def test_connect_blocked_gets_403_with_hint(server):
    s = unix_connect(server.rt.proxy_sock)
    s.sendall(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
    reply = recv_all(s).decode()
    assert reply.startswith("HTTP/1.1 403")
    assert 'xsb: egress to "github.com" is not on the allowlist' in reply
    assert "xsb net-allow github.com" in reply
    log = open(server.rt.logfile).read()
    assert "BLOCKED  github.com" in log


def test_denied_and_plain_http(server):
    s = unix_connect(server.rt.proxy_sock)
    s.sendall(b"GET http://denied.test/x HTTP/1.1\r\nHost: denied.test\r\n\r\n")
    reply = recv_all(s).decode()
    assert reply.startswith("HTTP/1.1 403") and "denied" in reply
    assert "DENIED   denied.test" in open(server.rt.logfile).read()


def echo_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = c.recv(65536)
            c.sendall(b"echo:" + data)
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv


def test_allowed_name_resolving_to_loopback_is_refused(server):
    srv = echo_server()
    port = srv.getsockname()[1]
    s = unix_connect(server.rt.proxy_sock)
    s.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
    reply = recv_all(s).decode()
    assert reply.startswith("HTTP/1.1 403") and "loopback" in reply
    srv.close()


@pytest.mark.parametrize("via", ["unix", "tcp"])
def test_connect_allowed_tunnels(server, via):
    server.allow_loopback = True
    srv = echo_server()
    port = srv.getsockname()[1]
    if via == "unix":
        s = unix_connect(server.rt.proxy_sock)
    else:
        s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    s.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    assert head.startswith(b"HTTP/1.1 200")
    s.sendall(b"hello")
    assert recv_all(s) == b"echo:hello"
    srv.close()


def test_port_file_written(server):
    assert int(open(server.rt.portfile).read()) == server.port


# ---- DNS forwarding ----

def make_query(qid=0x1234, name="example.com"):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


class FakeResolver:
    """UDP + TCP DNS server on one port; records queries; can truncate over UDP."""

    def __init__(self, truncate=False, pad=0):
        self.truncate = truncate
        self.pad = pad                    # extra answer bytes (to make big replies)
        self.udp_queries, self.tcp_queries = [], []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket()
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(5)
        threading.Thread(target=self.udp_loop, daemon=True).start()
        threading.Thread(target=self.tcp_loop, daemon=True).start()

    @staticmethod
    def answer(q, tc=False):
        flags = 0x8180 | (0x0200 if tc else 0)
        return q[:2] + struct.pack("!H", flags) + q[4:] + b"ANSWER-BYTES" + (b"-TCP" if not tc else b"")

    def udp_loop(self):
        while True:
            try:
                q, addr = self.udp.recvfrom(65535)
            except OSError:
                return
            self.udp_queries.append(q)
            self.udp.sendto(self.answer(q, tc=self.truncate) if self.truncate else
                            q[:2] + struct.pack("!H", 0x8180) + q[4:] + b"UDP-ANSWER"
                            + b"x" * self.pad, addr)

    def tcp_loop(self):
        while True:
            try:
                c, _ = self.tcp.accept()
            except OSError:
                return
            n = struct.unpack("!H", c.recv(2))[0]
            q = c.recv(n)
            self.tcp_queries.append(q)
            r = self.answer(q)
            c.sendall(struct.pack("!H", len(r)) + r)
            c.close()

    def close(self):
        self.udp.close()
        self.tcp.close()


def dns_roundtrip(sock_path, query):
    s = unix_connect(sock_path)
    s.sendall(struct.pack("!H", len(query)) + query)
    n = struct.unpack("!H", s.recv(2))[0]
    reply = b""
    while len(reply) < n:
        reply += s.recv(n - len(reply))
    s.close()
    return reply


def test_dns_forwarded_unchanged(server):
    fake = FakeResolver()
    server.resolver = ("127.0.0.1", fake.port)
    q = make_query()
    reply = dns_roundtrip(server.rt.dns_sock, q)
    assert fake.udp_queries == [q]
    assert reply == q[:2] + struct.pack("!H", 0x8180) + q[4:] + b"UDP-ANSWER"
    fake.close()


def test_dns_truncated_retried_over_tcp(server):
    fake = FakeResolver(truncate=True)
    server.resolver = ("127.0.0.1", fake.port)
    q = make_query(qid=0x4242)
    reply = dns_roundtrip(server.rt.dns_sock, q)
    assert fake.udp_queries == [q] and fake.tcp_queries == [q]
    assert reply == FakeResolver.answer(q)
    fake.close()


def test_dns_servfail_when_resolver_silent(server):
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    server.resolver = ("127.0.0.1", silent.getsockname()[1])
    q = make_query(qid=0x0707)
    import xsb.proxy as px
    orig = px.forward_dns
    px.forward_dns = lambda query, resolver: orig(query, resolver, timeout=0.2)
    try:
        reply = dns_roundtrip(server.rt.dns_sock, q)
    finally:
        px.forward_dns = orig
    qid, flags = struct.unpack("!HH", reply[:4])
    assert qid == 0x0707 and flags & 0x8000 and flags & 0x000F == 2
    assert reply[12:] == q[12:]             # the question is echoed
    silent.close()


def test_host_nameserver(tmp_path):
    p = write(tmp_path / "resolv.conf", "# x\nsearch a.b\nnameserver 127.0.0.53\nnameserver 1.1.1.1\n")
    assert proxy.host_nameserver(p) == "127.0.0.53"
    p = write(tmp_path / "r2", "nameserver fe80::1%eth0\n")
    assert proxy.host_nameserver(p) == "fe80::1"


# ---- lifecycle (a real proxy process) ----

def test_start_status_stop(make_ctx, home, run):
    (home / ".xsb").mkdir()
    ctx = make_ctx()
    rt = proxy.ensure_running(ctx, quiet=True)
    try:
        pid = proxy.running_pid(rt)
        assert pid and os.path.exists(rt.proxy_sock) and os.path.exists(rt.dns_sock)
        assert proxy.running_version(rt) == __version__
        assert proxy.ensure_running(ctx, quiet=True) and proxy.running_pid(rt) == pid   # idempotent
        assert any(f"running (pid {pid}" in l for l in proxy.status_lines(ctx))
        assert proxy.version_problem(ctx) == ""
        # A blocked request shows up in net-log.
        s = unix_connect(rt.proxy_sock)
        s.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\n\r\n")
        assert recv_all(s).startswith(b"HTTP/1.1 403")
        rc, out, _ = run(ctx, "net-log")
        assert rc == 0 and "BLOCKED  blocked.example" in out
        # The runtime dir is private.
        assert os.stat(rt.dir).st_mode & 0o077 == 0
    finally:
        rc, out, _ = run(ctx, "net-stop")
    assert rc == 0 and "stopped" in out
    assert proxy.running_pid(rt) is None
    rc, out, _ = run(ctx, "net-stop")
    assert "not running" in out


def test_version_mismatch_reported(make_ctx, home, run):
    (home / ".xsb").mkdir()
    ctx = make_ctx()
    rt = proxy.ensure_running(ctx, quiet=True)
    try:
        write(rt.versionfile, "0.0.1\n")
        assert "xsb net-stop" in proxy.version_problem(ctx)
    finally:
        proxy.stop(ctx)


def test_invalid_hostname_refused_and_escaped(server):
    s = unix_connect(server.rt.proxy_sock)
    s.sendall(b"CONNECT evil\x1b]52;c;aGk=\x07.com:443 HTTP/1.1\r\n\r\n")
    reply = recv_all(s)
    assert reply.startswith(b"HTTP/1.1 400") and b"\x1b" not in reply
    log = open(server.rt.logfile).read()
    assert "\x1b" not in log and "\x07" not in log and "BADHOST" in log


@pytest.mark.parametrize("host,ok", [("example.com", True), ("a_b.example.com", True),
                                     ("10.0.0.1", True), ("::1", True), ("fe80::1", True),
                                     ("evil\x1b.com", False), ("a b", False), ("", False),
                                     ("-x.com", False)])
def test_valid_host(host, ok):
    assert proxy.valid_host(host) == ok


def test_connect_forwards_early_bytes(server):
    server.allow_loopback = True
    srv = echo_server()
    port = srv.getsockname()[1]
    s = unix_connect(server.rt.proxy_sock)
    s.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode() + b"early")
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    assert recv_all(s) == b"echo:early"
    srv.close()
