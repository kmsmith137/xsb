"""Network modes (plan §7.2). These need internet access from the host."""

import time

import pytest


def test_allowed_domain_through_proxy_unlisted_gets_403(sb):
    r = sb.xsb("net-allow", "example.com")
    assert r.returncode == 0, r.stderr
    r = sb.run("""
        curl -sS -m 20 -o /dev/null -w 'allowed=%{http_code}\\n' https://example.com
        curl -sS -m 20 https://www.iana.org 2>&1 | head -2
        curl -sS -m 20 -o /dev/null -w 'plain=%{http_code}\\n' http://example.com
        curl -sS -m 20 -x "$HTTPS_PROXY" http://www.iana.org/ 2>&1 | head -3
    """, network="enforced")
    assert r.returncode == 0, r.stderr
    assert "allowed=200" in r.stdout
    assert "CONNECT tunnel failed, response 403" in r.stdout
    assert "plain=200" in r.stdout
    assert 'xsb: egress to "www.iana.org" is not on the allowlist' in r.stdout
    assert "xsb net-allow www.iana.org" in r.stdout
    r = sb.xsb("net-log")
    assert "BLOCKED  www.iana.org" in r.stdout


def test_enforced_no_direct_route(sb):
    r = sb.run("""
        getent hosts example.com > /dev/null && echo name-resolves
        curl -sS -m 10 --noproxy '*' https://example.com -o /dev/null 2>/dev/null \\
            && echo DIRECT-OK || echo direct-blocked
        /usr/bin/python3 - <<'EOF'
import socket
for addr in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
    try:
        socket.create_connection(addr, timeout=5).close()
        print("RAW-TCP-OK", addr)
    except OSError:
        print("raw-tcp-blocked")
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b"x", ("1.1.1.1", 9999))
    print("UDP-SENT")
except OSError:
    print("udp-blocked")
EOF
    """, network="enforced")
    assert r.returncode == 0, r.stderr
    assert "name-resolves" in r.stdout
    assert "direct-blocked" in r.stdout and "DIRECT-OK" not in r.stdout
    assert "RAW-TCP-OK" not in r.stdout and r.stdout.count("raw-tcp-blocked") == 2
    assert "udp-blocked" in r.stdout and "UDP-SENT" not in r.stdout


@pytest.mark.parametrize("network", ["enforced", "open"])
def test_dns_every_mode(sb, network):
    r = sb.run("""
        getent hosts example.com > /dev/null && echo example-ok
        getent hosts localhost > /dev/null && echo localhost-ok
        dig +short +tries=1 +time=5 example.com | grep -q . && echo dig-udp-ok
        dig +tcp +short +tries=1 +time=5 example.com | grep -q . && echo dig-tcp-ok
        dig +short +tries=1 +time=3 @1.1.1.1 example.com > /dev/null 2>&1 \\
            && echo OUTSIDE-RESOLVER-OK || echo outside-resolver-blocked
    """, network=network)
    assert r.returncode == 0, r.stderr
    for word in ("example-ok", "localhost-ok", "dig-udp-ok", "dig-tcp-ok"):
        assert word in r.stdout, (word, r.stdout)
    if network == "enforced":
        assert "outside-resolver-blocked" in r.stdout


def test_command_starts_after_relay_listens(sb):
    # First thing the command does: connect to the relay's ports, no retries.
    r = sb.xsb("run", "--network", "enforced", "--", "/usr/bin/python3", "-c",
               "import socket; socket.create_connection(('127.0.0.1', 3128), 1).close(); "
               "socket.create_connection(('127.0.0.1', 53), 1).close(); print('relay-ready')")
    assert r.returncode == 0 and "relay-ready" in r.stdout, r.stderr


def test_sandbox_survives_proxy_restart(sb):
    sb.xsb("net-allow", "example.com")
    script = ("for i in $(seq 1 14); do "
              "echo t=$i $(curl -s -m 3 -o /dev/null -w %{http_code} https://example.com); "
              "sleep 1; done")
    p = sb.popen("run", "--network", "enforced", "--", "bash", "-c", script)
    time.sleep(5)
    r = sb.xsb("net-stop")
    assert "stopped" in r.stdout
    time.sleep(2)
    r = sb.xsb("run", "--network", "enforced", "--", "true")   # restarts the proxy
    assert r.returncode == 0, r.stderr
    out, err = p.communicate(timeout=120)
    assert p.returncode == 0, err
    codes = [line.split()[1] if len(line.split()) > 1 else "" for line in out.splitlines()]
    assert codes[0] == "200"
    assert any(c != "200" for c in codes[1:-1]), out   # down while stopped
    assert codes[-1] == "200", out          # works again after the restart


def test_relay_runs_with_hosts_python(sb):
    r = sb.run("cat /etc/resolv.conf; echo; env | grep -i _proxy | sort", network="enforced")
    assert r.returncode == 0, r.stderr
    assert "nameserver 127.0.0.1" in r.stdout
    assert "HTTPS_PROXY=http://127.0.0.1:3128" in r.stdout
    assert "NO_PROXY=localhost,127.0.0.1,::1" in r.stdout
