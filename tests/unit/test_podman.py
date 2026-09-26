import os

import pytest

from xsb.backends.podman import PodmanBackend, format_argv, relay_path
from xsb.cli import parse_launch, UserError
from xsb.policy import Mount, Policy

GOLDEN = os.path.join(os.path.dirname(__file__), "golden")


def check_golden(name: str, text: str):
    path = os.path.join(GOLDEN, name)
    if os.environ.get("XSB_UPDATE_GOLDEN"):
        os.makedirs(GOLDEN, exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    with open(path) as f:
        assert text == f.read(), f"{name} differs; rerun with XSB_UPDATE_GOLDEN=1 if intended"


def sample_policy(network="enforced", tty=True) -> Policy:
    return Policy(
        os="linux", backend="podman", verb="claude", root="/home/u/proj", cwd="/home/u/proj/wt",
        command=["/opt/claude/claude-2.1", "--dangerously-skip-permissions", "--resume"],
        env={"TERM": "xterm-256color", "HOME": "/home/u", "USER": "u", "PATH": "/usr/bin:/bin",
             "CLAUDE_CONFIG_DIR": "/home/u/.xsb/claude", "IS_SANDBOX": "1",
             "HTTPS_PROXY": "http://127.0.0.1:3128", "XSB_ROOT": "/home/u/proj",
             "SSH_CONNECTION": "10.0.0.1 5000 10.0.0.2 22"},
        mounts=[Mount("/usr", "ro", "built-in"), Mount("/etc", "ro", "built-in"),
                Mount("/home/u/proj", "rw", "root"),
                Mount("/home/u/.xsb/claude", "rw", "claude config dir"),
                Mount("/home/u/proj/top", "ro", "protected: top"),
                Mount("/home/u/proj/top/.git", "rw", "git common dir"),
                Mount("/home/u/proj/top/.git/config", "ro", "git config"),
                Mount("/home/u/proj/top/.git/hooks", "ro", "git hooks"),
                Mount("/opt/claude/claude-2.1", "ro", "claude program")],
        network=network, devices=["/dev/nvidia0", "/dev/nvidiactl"],
        image="docker.io/library/ubuntu:24.04", extra_args=["--ipc", "host"], tty=tty,
        runtime_dir="/run/user/1000/xsb", resolv_extra=["search example.org"])


def test_podman_argv_golden():
    spec = PodmanBackend().command(sample_policy())
    text = format_argv(spec.argv, spec.image).replace(relay_path(), "<relay.py>") + "\n"
    check_golden("podman_argv.txt", text)
    assert spec.files == {"/run/user/1000/xsb/resolv.conf":
                          "nameserver 127.0.0.1\nsearch example.org\n"}
    assert spec.image == "docker.io/library/ubuntu:24.04"


def test_podman_argv_open_mode():
    argv = PodmanBackend().command(sample_policy(network="open", tty=False)).argv
    assert argv[argv.index("--network") + 1] == "pasta"
    assert "-it" not in argv
    assert not any("relay" in a for a in argv) and "/bin/sh" not in argv
    # The command follows the image directly.
    i = argv.index("docker.io/library/ubuntu:24.04")
    assert argv[i + 1:] == ["/opt/claude/claude-2.1", "--dangerously-skip-permissions", "--resume"]


def test_podman_argv_structure():
    argv = PodmanBackend().command(sample_policy()).argv
    assert argv[:4] == ["podman", "run", "--rm", "--init"]
    assert argv[argv.index("--network") + 1] == "none"
    for flag in ("--group-add", "-w", "--tmpfs"):
        assert flag in argv
    vols = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert vols[:3] == ["/usr:/usr:ro", "/etc:/etc:ro", "/home/u/proj:/home/u/proj:rw"]
    assert "/run/user/1000/xsb/sock:/run/xsb/sock:ro" in vols
    assert "/run/user/1000/xsb/resolv.conf:/etc/resolv.conf:ro" in vols
    i = argv.index("docker.io/library/ubuntu:24.04")
    assert argv[i + 1:i + 5] == ["/bin/sh", "-c",
                                 '/usr/bin/python3 -I /run/xsb/relay.py && exec "$@"', "xsb"]


# ---- launch option parsing ----

def test_parse_launch():
    assert parse_launch("claude", ["--dry-run", "-p", "hi"]) == (True, None, ["-p", "hi"])
    assert parse_launch("claude", ["--network", "open", "--resume"]) == (False, "open", ["--resume"])
    assert parse_launch("claude", ["--network=open"]) == (False, "open", [])
    assert parse_launch("claude", ["--help"]) == (False, None, ["--help"])     # claude's help
    assert parse_launch("claude", ["--", "--dry-run"]) == (False, None, ["--dry-run"])
    assert parse_launch("run", ["--", "ls", "-l"]) == (False, None, ["ls", "-l"])
    assert parse_launch("run", ["ls", "--dry-run"]) == (False, None, ["ls", "--dry-run"])
    assert parse_launch("run", ["-h"]) is None
    with pytest.raises(UserError):
        parse_launch("run", ["--network", "closed"])
    with pytest.raises(UserError):
        parse_launch("run", ["--network"])


def test_dry_run_cli(run, make_ctx, home):
    root = home / "proj"
    root.mkdir()
    rc, _, _ = run(make_ctx(cwd=root), "init")
    assert rc == 0
    rc, out, err = run(make_ctx(cwd=root), "run", "--dry-run", "--network", "open", "--",
                       "echo", "hi")
    assert rc == 0, err
    assert "# Resolved policy" in out and "# Backend command (podman)" in out
    assert f"rw  {root}    # root" in out
    assert "command:  echo hi" in out
    assert "podman run" in out
    assert not (home / ".xsb" / "claude" / "x").exists()


def test_launch_needs_xsb_home(run, make_ctx, home):
    root = home / "proj"
    root.mkdir()
    (root / "xsb.toml").write_text("")
    rc, _, err = run(make_ctx(cwd=root), "run", "--", "true")
    assert rc == 1 and "xsb init" in err


def test_shell_takes_no_args(run, make_ctx, home):
    rc, _, err = run(make_ctx(), "shell", "ls")
    assert rc == 1 and "takes no arguments" in err
