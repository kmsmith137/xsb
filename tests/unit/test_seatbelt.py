import os

from test_podman import check_golden
from xsb.backends.seatbelt import SeatbeltBackend, glob_regex, profile, sbpl_str
from xsb.policy import Mount, Policy


def fake_realpath(p):
    """macOS's symlinks: /tmp -> /private/tmp, /var -> /private/var."""
    for link in ("/tmp", "/var", "/etc"):
        if p == link or p.startswith(link + "/"):
            return "/private" + p
    return p


def sample_policy(network="enforced") -> Policy:
    return Policy(
        os="macos", backend="seatbelt", verb="claude", root="/Users/u/proj", cwd="/Users/u/proj",
        command=["/Users/u/.local/share/claude/versions/2.1", "--dangerously-skip-permissions"],
        env={"HOME": "/Users/u", "PATH": "/usr/bin:/bin", "TMPDIR": "/var/folders/x/T/xsb/tmp/42",
             "HTTPS_PROXY": "http://127.0.0.1:50123"},
        mounts=[Mount("/opt", "ro", "[[mount]] built-in"),
                Mount("/Users/u/.gitconfig", "ro", "[[mount]] built-in"),
                Mount("/Users/u/proj", "rw", "root"),
                Mount("/tmp/scratch", "rw", "[[mount]] xsb.toml"),
                Mount("/Users/u/.xsb/claude", "rw", "claude config dir (claude_dir)"),
                Mount("/Users/u/proj/top", "ro", "protected: top"),
                Mount("/var/folders/x/T/xsb/tmp/42", "rw", "per-launch TMPDIR"),
                Mount("/Users/u/proj/xsb.toml", "ro", "xsb config (read-only, I1)"),
                Mount("/Users/u/proj/top/.git", "rw", "git common dir"),
                Mount("/Users/u/proj/top/.git/config", "ro", "git config")],
        network=network, runtime_dir="/var/folders/x/T/xsb", agent="claude",
        agent_dirs={"claude": "/Users/u/.xsb/claude"}, xsb_home="/Users/u/.xsb",
        tmpdir="/var/folders/x/T/xsb/tmp/42",
        protect_globs=["/Users/u/proj/.claude/settings.json", "/Users/u/proj/*/.mcp.json",
                       "/Users/u/proj/top"])


def test_seatbelt_profile_golden():
    text = profile(sample_policy(), realpath=fake_realpath)
    check_golden("seatbelt_profile.sb", text)


def test_profile_structure():
    text = profile(sample_policy(), realpath=fake_realpath)
    lines = text.splitlines()
    assert lines[:2] == ["(version 1)", "(deny default)"]
    assert "UNVERIFIED" in text
    # /tmp and /var are resolved to /private/...
    assert '(allow file-read* file-write* (subpath "/private/tmp/scratch"))' in text
    assert '(subpath "/tmp/scratch")' not in text
    # ~/.xsb is denied, then the mounted agent dir re-allowed after it.
    deny = lines.index('(deny file-read* file-write* (subpath "/Users/u/.xsb"))')
    allow = lines.index('(allow file-read* file-write* (subpath "/Users/u/.xsb/claude"))')
    assert deny < allow
    # The runtime dir is denied, then this launch's TMPDIR re-allowed.
    assert lines.index('(deny file-read* file-write* (subpath "/private/var/folders/x/T/xsb"))') < \
        lines.index('(allow file-read* file-write* (subpath "/private/var/folders/x/T/xsb/tmp/42"))')
    # Deeper rules come later: top ro, then .git rw, then .git/config ro.
    def idx(s):
        return next(i for i, l in enumerate(lines) if s in l)
    assert idx('(deny file-write* (subpath "/Users/u/proj/top"))') < \
        idx('(allow file-read* file-write* (subpath "/Users/u/proj/top/.git"))') < \
        idx('(deny file-write* (subpath "/Users/u/proj/top/.git/config"))')
    # The protect regex for "top" comes before the deeper .git allow.
    assert idx(r'(regex #"^/Users/u/proj/top(/.*)?$")') < idx('(subpath "/Users/u/proj/top/.git"))')
    # Regex literals are raw: one backslash before a literal dot.
    assert r'(regex #"^/Users/u/proj/\.claude/settings\.json(/.*)?$")' in text
    # Metadata on ~/.xsb itself is re-allowed after the deny, for the agent dir.
    assert lines.index('(allow file-read-metadata (literal "/Users/u/.xsb"))') > deny
    # Enforced network: only localhost.
    assert "(deny network*)" in lines
    assert '(allow network-outbound (remote ip "localhost:*"))' in lines
    assert "(allow network*)" not in lines


def test_open_network():
    text = profile(sample_policy(network="open"), realpath=fake_realpath)
    assert "(allow network*)" in text and "(deny network*)" not in text


def test_glob_regex():
    assert glob_regex("/r/*/.mcp.json") == r"^/r/[^/]*/\.mcp\.json(/.*)?$"
    assert glob_regex("/r/a?b") == r"^/r/a[^/]b(/.*)?$"
    assert glob_regex("/r/[!x]y") == r"^/r/[^x]y(/.*)?$"
    assert glob_regex("/r/a+b (1)") == r"^/r/a\+b \(1\)(/.*)?$"
    import re
    assert re.match(glob_regex("/r/*/.mcp.json"), "/r/wt/.mcp.json")
    assert not re.match(glob_regex("/r/*/.mcp.json"), "/r/a/b/.mcp.json")


def test_sbpl_escaping():
    assert sbpl_str('a"b\\c') == '"a\\"b\\\\c"'


def test_command_and_cleanup():
    spec = SeatbeltBackend().command(sample_policy())
    assert spec.argv[:2] == ["sandbox-exec", "-f"]
    prof = spec.argv[2]
    assert prof.startswith("/var/folders/x/T/xsb/profile-") and prof in spec.files
    i = spec.argv.index("/usr/bin/env")
    assert spec.argv[i + 1] == "-i"
    assert "TMPDIR=/var/folders/x/T/xsb/tmp/42" in spec.argv
    assert spec.argv[-2:] == ["/Users/u/.local/share/claude/versions/2.1",
                              "--dangerously-skip-permissions"]
    assert "/var/folders/x/T/xsb/tmp/42" in spec.cleanup and prof in spec.cleanup
    assert spec.description.startswith("# Seatbelt profile")


def test_base_read_paths():
    paths = SeatbeltBackend().base_read_paths()
    assert {"/System", "/usr", "/bin", "/sbin", "/Library", "/private/etc"} <= set(paths)


def test_macos_policy_from_config(make_ctx, home):
    """On macOS: no /usr, /etc mounts, a per-launch TMPDIR, no IS_SANDBOX."""
    from test_policy import project
    from xsb.config import load_config
    from xsb.policy import LaunchRequest, build_policy
    root = project(home)
    ctx = make_ctx(cwd=root, os_="macos")
    p = build_policy(load_config(ctx), LaunchRequest(verb="run", args=["true"],
                                                     network="enforced", proxy_port=50123),
                     "seatbelt", code_paths=[])
    paths = {m.path for m in p.mounts}
    assert "/usr" not in paths and "/etc" not in paths
    assert p.tmpdir and p.tmpdir.startswith(ctx.runtime_dir) and p.env["TMPDIR"] == p.tmpdir
    assert p.env["XDG_CACHE_HOME"] == os.path.join(p.tmpdir, "cache")
    assert "IS_SANDBOX" not in p.env and p.env["DISABLE_AUTOUPDATER"] == "1"
    assert p.env["HTTPS_PROXY"] == "http://127.0.0.1:50123"
    assert p.devices == [] and p.image == ""
    text = SeatbeltBackend().command(p).files
    assert any("(deny default)" in t for t in text.values())
