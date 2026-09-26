import os
import time

import pytest


def test_unlisted_absent_ro_readonly_root_writable(sb, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cret")
    data = tmp_path / "data"
    data.mkdir()
    (data / "f").write_text("x")
    sb.append_user_config(f'[[mount]]\npath = "{data}"\nmode = "ro"\n')
    r = sb.run(f"""
        set -u
        test ! -e {secret} && echo secret-absent
        test ! -e {sb.xsb_home}/config.toml && echo xsb-config-absent
        test ! -e {sb.xsb_home}/net-allow.txt && echo xsb-list-absent
        cat {data}/f && echo ro-readable
        touch {data}/g 2>/dev/null || echo ro-not-writable
        touch /usr/xsb-test 2>/dev/null || echo usr-not-writable
        touch {sb.root}/written && echo root-writable
        touch xsb.toml 2>/dev/null || echo config-not-writable
    """)
    assert r.returncode == 0, r.stderr
    for word in ("secret-absent", "xsb-config-absent", "xsb-list-absent", "ro-readable",
                 "ro-not-writable", "usr-not-writable", "root-writable", "config-not-writable"):
        assert word in r.stdout, (word, r.stdout, r.stderr)
    assert os.path.exists(os.path.join(sb.root, "written"))


def test_env_contains_only_expected_names(sb):
    r = sb.run("env -0", env={"MY_SECRET_TOKEN": "abc", "TERM": "xterm"})
    assert r.returncode == 0, r.stderr
    names = {kv.split("=", 1)[0] for kv in r.stdout.split("\0") if kv}
    assert "MY_SECRET_TOKEN" not in names
    reserved = {"HOME", "USER", "PATH", "XDG_CACHE_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
                "IS_SANDBOX", "DISABLE_AUTOUPDATER", "XSB_ROOT", "XSB_BACKEND", "XSB_NETWORK"}
    assert reserved <= names
    forwarded = {"TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SHELL", "EDITOR",
                 "VISUAL", "GIT_EDITOR", "PAGER", "GIT_PAGER", "SSH_TTY", "SSH_CONNECTION",
                 "SSH_CLIENT", "TMUX", "TMUX_PANE", "CONDA_PREFIX", "LD_LIBRARY_PATH",
                 "CUPY_CACHE_DIR"}
    from_runtime = {"container", "HOSTNAME", "PWD", "SHLVL", "_", "OLDPWD"}
    assert names <= reserved | forwarded | from_runtime, names - reserved - forwarded - from_runtime


def test_planted_second_config_refused(sb):
    sb.write("sub/xsb.toml", '[[mount]]\npath = "/"\nmode = "rw"\n')
    r = sb.xsb("run", "--", "true", cwd=os.path.join(sb.root, "sub"))
    assert r.returncode == 1 and "more than one xsb.toml" in r.stderr


def test_orphans_are_reaped(sb):
    r = sb.run("""
        for i in $(seq 30); do ( sleep 0.2 & ) ; done
        sleep 1.5
        ps -eo stat= | grep -c '^Z' || true
    """)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "0"


@pytest.mark.skipif(not os.path.exists("/dev/nvidia0"), reason="no NVIDIA GPU")
def test_gpu_visible(sb):
    r = sb.run("test -c /dev/nvidia0 && test -c /dev/nvidiactl && echo gpu-ok")
    assert r.returncode == 0 and "gpu-ok" in r.stdout, r.stderr


@pytest.mark.parametrize("network", ["open", "enforced"])
def test_concurrent_sandboxes_bind_same_port(sb, network):
    script = ("import socket, time; s = socket.socket(); "
              "s.bind(('127.0.0.1', 5000)); s.listen(); print('bound', flush=True); time.sleep(4)")
    net = ["--network", network]
    procs = [sb.popen("run", *net, "--", "/usr/bin/python3", "-c", script) for _ in range(2)]
    outs = [p.communicate(timeout=300) for p in procs]
    for p, (o, e) in zip(procs, outs):
        assert p.returncode == 0 and "bound" in o, e


def test_supplementary_groups_kept(sb):
    """--group-add keep-groups (needs crun): the host's supplementary groups stay
    attached (shown unmapped, as 65534, but they still grant access)."""
    host = len(set(os.getgroups()))
    r = sb.run("grep '^Groups:' /proc/self/status")
    assert r.returncode == 0, r.stderr
    inside = r.stdout.split(":", 1)[1].split()
    assert len(inside) >= host - 1, (host, inside)


@pytest.mark.skipif(not os.environ.get("XSB_TEST_GROUP_FILE"),
                    reason="set XSB_TEST_GROUP_FILE to a file owned by someone else and "
                           "readable only through one of your groups")
def test_group_only_file_readable(sb):
    f = os.environ["XSB_TEST_GROUP_FILE"]
    sb.append_user_config(f'[[mount]]\npath = "{os.path.dirname(f)}"\nmode = "ro"\n')
    r = sb.run(f"head -c 1 {f} > /dev/null && echo group-read-ok")
    assert r.returncode == 0 and "group-read-ok" in r.stdout, r.stderr
