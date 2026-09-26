"""xsb's in-sandbox network relay (Linux, enforced mode).

Runs inside the container as `/usr/bin/python3 -I /run/xsb/relay.py`, using the
host's Python, so it uses only the standard library and stays compatible with
old Python 3 versions. The container has no network except its own loopback
(podman --network none); the proxy's Unix sockets are bind-mounted (as a
directory) at /run/xsb/sock. The relay serves:

  127.0.0.1:3128 (TCP)       -> sock/proxy.sock   the HTTP proxy (HTTPS_PROXY)
  127.0.0.1:53 (UDP and TCP) -> sock/dns.sock     DNS; each UDP datagram is sent
                                                  with the 2-byte length prefix
                                                  of DNS over TCP

It binds every port first and only then goes into the background (the parent
exits 0), so `relay.py && exec <agent>` never starts the agent before the relay
is listening. If binding fails it exits non-zero and the launch fails.
"""

import argparse
import os
import select
import socket
import struct
import sys
import threading


def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [])
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


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def skip_name(msg, i):
    while True:
        n = msg[i]
        if n & 0xC0:                 # compression pointer
            return i + 2
        i += 1 + n
        if n == 0:
            return i


def question_end(msg):
    """Offset just past the question section."""
    i = 12
    for _ in range(struct.unpack("!H", msg[4:6])[0]):
        i = skip_name(msg, i) + 4
    return i


def max_udp_size(query):
    """The largest UDP reply the client accepts: 512, or its EDNS (OPT) size."""
    try:
        an, ns, ar = struct.unpack("!HHH", query[6:12])
        i = question_end(query)
        for n in range(an + ns + ar):
            i = skip_name(query, i)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", query[i:i + 10])
            if rtype == 41 and n >= an + ns:
                return max(512, rclass)
            i += 10 + rdlen
    except (IndexError, struct.error):
        pass
    return 512


def truncated(query, reply):
    """A reply too big for UDP becomes header + question with the TC bit set,
    so the client retries over TCP (which the relay also serves)."""
    try:
        end = question_end(reply)
    except (IndexError, struct.error):
        return reply[:12]
    flags = struct.unpack("!H", reply[2:4])[0] | 0x0200
    qd = struct.unpack("!H", reply[4:6])[0]
    return reply[:2] + struct.pack("!HHHHH", flags, qd, 0, 0, 0) + reply[12:end]


class Relay:
    def __init__(self, sock_dir, host, http_port, dns_port):
        self.sock_dir = sock_dir
        self.http = self.tcp_listener(host, http_port)
        self.dns_tcp = self.tcp_listener(host, dns_port)
        self.dns_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_udp.bind((host, dns_port))

    @staticmethod
    def tcp_listener(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(128)
        return s

    def unix(self, name):
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        u.connect(os.path.join(self.sock_dir, name))
        return u

    def stream_loop(self, srv, name):
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                continue
            try:
                upstream = self.unix(name)
            except OSError:          # the proxy is down; the client sees a reset
                client.close()
                continue
            threading.Thread(target=pipe, args=(client, upstream)).start()

    def udp_query(self, query, addr):
        try:
            u = self.unix("dns.sock")
            try:
                u.settimeout(15)
                u.sendall(struct.pack("!H", len(query)) + query)
                head = recv_exact(u, 2)
                if head is None:
                    return
                reply = recv_exact(u, struct.unpack("!H", head)[0])
            finally:
                u.close()
            if reply:
                if len(reply) > max_udp_size(query):
                    reply = truncated(query, reply)
                self.dns_udp.sendto(reply, addr)
        except OSError:
            pass

    def udp_loop(self):
        while True:
            try:
                query, addr = self.dns_udp.recvfrom(65535)
            except OSError:
                continue
            threading.Thread(target=self.udp_query, args=(query, addr)).start()

    def serve(self):
        for srv, name in ((self.http, "proxy.sock"), (self.dns_tcp, "dns.sock")):
            t = threading.Thread(target=self.stream_loop, args=(srv, name))
            t.daemon = True
            t.start()
        self.udp_loop()


def main():
    ap = argparse.ArgumentParser(description="xsb in-sandbox network relay")
    ap.add_argument("--sock-dir", default="/run/xsb/sock")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=3128)
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--foreground", action="store_true",
                    help="stay in the foreground and print 'ready' once listening (tests)")
    args = ap.parse_args()
    try:
        relay = Relay(args.sock_dir, args.host, args.http_port, args.dns_port)
    except OSError as e:
        sys.stderr.write("xsb relay: cannot listen: %s\n" % e)
        return 1
    if args.foreground:
        sys.stdout.write("ready\n")
        sys.stdout.flush()
    else:
        if os.fork():
            os._exit(0)                  # the parent returns once every port is bound
        os.setsid()
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
    relay.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
