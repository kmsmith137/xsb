import os
import signal
import socket
import struct
import subprocess
import sys

import pytest

from conftest import write
from test_proxy import FakeResolver, make_query
from xsb.backends.podman import relay_path
from xsb.proxy import Proxy, Runtime

RELAY = relay_path()


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def chain(short_tmp, tmp_path):
    """proxy (in-process, Unix sockets) + relay.py (subprocess) + a fake resolver."""
    rt = Runtime(os.path.join(short_tmp, "rt"))
    allow = write(tmp_path / "allow.txt", "")
    p = Proxy(rt, allow, str(tmp_path / "deny.txt"))
    p.bind()
    p.start_threads()
    http, dns = free_port(), free_port()
    relay = subprocess.Popen([sys.executable, "-I", RELAY, "--foreground", "--sock-dir",
                              rt.sock_dir, "--http-port", str(http), "--dns-port", str(dns)],
                             stdout=subprocess.PIPE, text=True)
    assert relay.stdout.readline() == "ready\n"
    yield p, http, dns
    relay.kill()
    relay.wait()
    p.close()


def udp_ask(port, query):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(10)
    u.sendto(query, ("127.0.0.1", port))
    reply, _ = u.recvfrom(65535)
    u.close()
    return reply


def tcp_ask(port, query):
    t = socket.create_connection(("127.0.0.1", port), timeout=10)
    t.sendall(struct.pack("!H", len(query)) + query)
    n = struct.unpack("!H", t.recv(2))[0]
    reply = b""
    while len(reply) < n:
        reply += t.recv(n - len(reply))
    t.close()
    return reply


def test_udp_query_reaches_resolver_unchanged(chain):
    proxy, http, dns = chain
    fake = FakeResolver()
    proxy.resolver = ("127.0.0.1", fake.port)
    q = make_query(qid=0x1111)
    reply = udp_ask(dns, q)
    assert fake.udp_queries == [q]
    assert reply == q[:2] + struct.pack("!H", 0x8180) + q[4:] + b"UDP-ANSWER"
    fake.close()


def test_truncated_udp_reply_retried_over_tcp(chain):
    proxy, http, dns = chain
    fake = FakeResolver(truncate=True)
    proxy.resolver = ("127.0.0.1", fake.port)
    q = make_query(qid=0x2222)
    reply = udp_ask(dns, q)
    assert fake.udp_queries == [q] and fake.tcp_queries == [q]
    assert reply == FakeResolver.answer(q)          # the full TCP answer, unchanged
    fake.close()


def test_tcp_dns_through_relay(chain):
    proxy, http, dns = chain
    fake = FakeResolver()
    proxy.resolver = ("127.0.0.1", fake.port)
    q = make_query(qid=0x3333)
    assert tcp_ask(dns, q) == q[:2] + struct.pack("!H", 0x8180) + q[4:] + b"UDP-ANSWER"
    fake.close()


def test_big_reply_truncated_for_udp_client_then_tcp(chain):
    proxy, http, dns = chain
    fake = FakeResolver(pad=1000)
    proxy.resolver = ("127.0.0.1", fake.port)
    q = make_query(qid=0x4444)                      # no EDNS: 512-byte limit
    reply = udp_ask(dns, q)
    flags = struct.unpack("!H", reply[2:4])[0]
    assert flags & 0x0200 and reply[12:] == q[12:]  # TC set, question only
    full = tcp_ask(dns, q)
    assert len(full) > 1000


def test_max_udp_size_reads_edns(monkeypatch):
    import importlib.util
    monkeypatch.setattr(sys, "dont_write_bytecode", True)   # no __pycache__ in the package
    spec = importlib.util.spec_from_file_location("xsb_relay", RELAY)
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)
    q = make_query()
    assert relay.max_udp_size(q) == 512
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    q2 = q[:10] + struct.pack("!H", 1) + q[12:] + opt
    assert relay.max_udp_size(q2) == 1232


def test_http_through_relay(chain):
    proxy, http, dns = chain
    s = socket.create_connection(("127.0.0.1", http), timeout=10)
    s.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\n\r\n")
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    assert data.startswith(b"HTTP/1.1 403") and b"xsb net-allow blocked.example" in data


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc")
def test_background_mode_listens_before_parent_exits(short_tmp):
    http, dns = free_port(), free_port()
    sock_dir = os.path.join(short_tmp, "relay-bg-sock")
    r = subprocess.run([sys.executable, "-I", RELAY, "--sock-dir", sock_dir,
                        "--http-port", str(http), "--dns-port", str(dns)], timeout=30)
    try:
        assert r.returncode == 0
        # The parent has exited: the ports must already be accepting.
        socket.create_connection(("127.0.0.1", http), timeout=2).close()
        socket.create_connection(("127.0.0.1", dns), timeout=2).close()
    finally:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    if sock_dir.encode() in open(f"/proc/{pid}/cmdline", "rb").read():
                        os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass


def test_bind_failure_exits_nonzero():
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    port = busy.getsockname()[1]
    r = subprocess.run([sys.executable, "-I", RELAY, "--http-port", str(port),
                        "--dns-port", str(free_port())], capture_output=True, text=True, timeout=30)
    busy.close()
    assert r.returncode != 0 and "cannot listen" in r.stderr
