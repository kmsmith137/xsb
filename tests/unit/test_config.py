import os
import tomllib

import pytest

from conftest import write
from xsb.config import (ConfigError, Expander, find_configs, find_root, load_config,
                        defaults_text, format_effective)
from xsb.policy import config_mounts


def proj(home, text="", name="proj"):
    root = home / name
    root.mkdir(exist_ok=True)
    write(root / "xsb.toml", text)
    return root


# ---- discovery (plan §5.2) ----

def test_discovery_none(make_ctx, home):
    ctx = make_ctx(cwd=home)
    assert find_configs(ctx.cwd, ctx.home) == []
    with pytest.raises(ConfigError, match="xsb init"):
        find_root(ctx)
    assert find_root(ctx, required=False) == (None, None)


def test_discovery_one(make_ctx, home):
    root = proj(home)
    sub = root / "a" / "b"
    sub.mkdir(parents=True)
    assert find_root(make_ctx(cwd=sub)) == (str(root), str(root / "xsb.toml"))


def test_discovery_two_refused(make_ctx, home):
    root = proj(home)
    sub = root / "sub"
    write(sub / "xsb.toml")
    with pytest.raises(ConfigError, match="more than one xsb.toml"):
        find_root(make_ctx(cwd=sub))
    # From the root itself only one is found.
    assert find_root(make_ctx(cwd=root))[0] == str(root)


def test_discovery_stops_at_home(make_ctx, home, tmp_path):
    write(tmp_path / "xsb.toml")          # above $HOME: never considered
    root = proj(home)
    assert find_root(make_ctx(cwd=root))[0] == str(root)


def test_discovery_includes_home(make_ctx, home):
    write(home / "xsb.toml")
    (home / "x").mkdir()
    assert find_root(make_ctx(cwd=home / "x"))[0] == str(home)


def test_discovery_outside_home_walks_to_root(make_ctx, tmp_path):
    root = tmp_path / "elsewhere"
    write(root / "xsb.toml")
    (root / "d").mkdir()
    assert find_root(make_ctx(cwd=root / "d"))[0] == str(root)


def test_broken_symlink_config_is_an_error(make_ctx, home):
    root = home / "proj"
    root.mkdir()
    os.symlink(home / "nowhere.toml", root / "xsb.toml")
    with pytest.raises(ConfigError, match="broken symlink"):
        load_config(make_ctx(cwd=root))


# ---- merge semantics (plan §5.3) ----

def test_scalar_list_replaces_across_files(make_ctx, home):
    write(home / ".xsb/config.toml", '[env]\nrequire = ["A", "B"]\n[linux]\nextra_args = ["--x"]\n')
    root = proj(home, '[env]\nrequire = ["C"]\n')
    m = load_config(make_ctx(cwd=root)).merged
    assert m.get("env", "require") == ["C"]
    assert m.source("env", "require") == "xsb.toml"
    assert m.get("linux", "extra_args") == ["--x"]
    assert m.source("linux", "extra_args") == "~/.xsb/config.toml"


def test_mounts_append_and_same_path_collapses(make_ctx, home):
    write(home / ".xsb/config.toml", '[[mount]]\npath = "/data"\nmode = "ro"\n')
    root = proj(home, '[[mount]]\npath = "/data"\nmode = "rw"\n[[mount]]\npath = "/other"\n')
    m = load_config(make_ctx(cwd=root)).merged
    paths = [e.fields["path"] for e in m.entries["mount"]]
    assert paths.count("/data") == 1
    data = next(e for e in m.entries["mount"] if e.fields["path"] == "/data")
    assert data.fields["mode"] == "rw" and data.source == "xsb.toml"
    other = next(e for e in m.entries["mount"] if e.fields["path"] == "/other")
    assert other.fields["mode"] == "ro"           # default mode
    assert "/opt" in paths                        # defaults are kept


def test_mount_keys_match_after_expansion(make_ctx, home):
    root = proj(home, '[[mount]]\npath = "$HOME/.condarc"\nenabled = false\n')
    m = load_config(make_ctx(cwd=root)).merged
    assert not any(e.key.endswith(".condarc") for e in m.active("mount"))


def test_env_forward_table_adds_and_removes(make_ctx, home):
    root = proj(home, "[env.forward]\nTMUX = false\nMY_VAR = true\n")
    m = load_config(make_ctx(cwd=root)).merged
    fwd = {k: v for k, (v, _) in m.table("env", "forward").items()}
    assert fwd["TMUX"] is False and fwd["MY_VAR"] is True and fwd["TERM"] is True


def test_protect_false_removes_default(make_ctx, home):
    root = proj(home, '[protect]\n"*/.mcp.json" = false\n"top" = true\n')
    m = load_config(make_ctx(cwd=root)).merged
    prot = {k: v for k, (v, _) in m.table("protect").items()}
    assert prot["*/.mcp.json"] is False and prot["top"] is True and prot[".mcp.json"] is True


def test_mixed_list_is_an_error(make_ctx, home):
    root = proj(home, 'mount = [{ path = "/a" }, "/b"]\n')
    with pytest.raises(ConfigError, match="mix"):
        load_config(make_ctx(cwd=root))


def test_enabled_false_removes_default_mount_and_device(make_ctx, home):
    root = proj(home, '[[mount]]\npath = "/opt"\nenabled = false\n'
                      '[[device]]\nglob = "/dev/nvidia*"\nenabled = false\n')
    m = load_config(make_ctx(cwd=root)).merged
    assert not any(e.fields["path"] == "/opt" for e in m.active("mount"))
    assert m.active("device") == []


def test_refuse_entries_keyed_by_dir(make_ctx, home):
    write(home / ".xsb/config.toml", 'refuse = [ { dir = "top", reason = "one" } ]\n')
    root = proj(home, 'refuse = [ { dir = "top", reason = "two" }, { dir = "x" } ]\n')
    m = load_config(make_ctx(cwd=root)).merged
    assert [(e.fields["dir"], e.fields["reason"]) for e in m.active("refuse")] == \
        [("top", "two"), ("x", "")]


# ---- [[match]] ----

MATCH = '''
[[match]]
os = "linux"
hosts = ["cf*", "cs*"]
[[match.mount]]
path = "/scratch"
mode = "rw"
[match.env.set]
FOO = "bar"

[[match]]
os = "macos"
[match.network]
mode = "open"
'''


@pytest.mark.parametrize("os_,host,scratch,foo,mode", [
    ("linux", "cf05", True, True, "enforced"),
    ("linux", "CS01", True, True, "enforced"),
    ("linux", "other", False, False, "enforced"),
    ("macos", "cf05", False, False, "open"),
])
def test_match_by_os_and_host(make_ctx, home, os_, host, scratch, foo, mode):
    root = proj(home, MATCH)
    m = load_config(make_ctx(cwd=root, os_=os_, hostname=host)).merged
    assert any(e.fields["path"] == "/scratch" for e in m.active("mount")) == scratch
    assert ("FOO" in m.table("env", "set")) == foo
    assert m.get("network", "mode") == mode
    if scratch:
        e = next(e for e in m.active("mount") if e.fields["path"] == "/scratch")
        assert e.source.startswith("xsb.toml [[match]] #1")


def test_builtin_linux_match_block(make_ctx, home):
    root = proj(home)
    lin = load_config(make_ctx(cwd=root, os_="linux")).merged
    mac = load_config(make_ctx(cwd=root, os_="macos")).merged
    assert {"/usr", "/etc"} <= {e.fields["path"] for e in lin.active("mount")}
    assert not {"/usr", "/etc"} & {e.fields["path"] for e in mac.active("mount")}


def test_nested_match_is_an_error(make_ctx, home):
    root = proj(home, '[[match]]\nos = "linux"\n[[match.match]]\nos = "linux"\n')
    with pytest.raises(ConfigError, match="nested"):
        load_config(make_ctx(cwd=root))


# ---- validation ----

@pytest.mark.parametrize("text,msg", [
    ("colour = 1\n", "unknown key 'colour'"),
    ("[network]\nmoed = \"open\"\n", "unknown key 'moed'"),
    ('[[mount]]\npath = "/a"\nmdoe = "rw"\n', "unknown key 'mdoe'"),
    ('[network]\nmode = "closed"\n', "expected"),
    ('[[mount]]\nmode = "rw"\n', "missing 'path'"),
    ('[mount]\npath = "/a"\n', r"\[\[mount\]\]"),
    ('[env.forward]\nTERM = "yes"\n', "true or false"),
    ('[env.forward]\n"BAD-NAME" = true\n', "invalid variable name"),
    ('[protect]\n"**/x" = true\n', "not supported"),
    ('[[match]]\nos = "windows"\n', "expected"),
    ('[[match]]\nfoo = 1\n', "unknown key 'match.foo'"),
])
def test_validation_errors(make_ctx, home, text, msg):
    root = proj(home, text)
    with pytest.raises(ConfigError, match=msg):
        load_config(make_ctx(cwd=root))


@pytest.mark.parametrize("text", [
    '[env.set]\nPATH = "/x"\n',
    '[env.forward]\nHTTPS_PROXY = true\n',
    '[env.forward]\nCLAUDE_CONFIG_DIR = true\n',
    '[env]\nrequire = ["HOME"]\n',
    '[[match]]\nos = "linux"\n[match.env.set]\nXSB_ROOT = "x"\n',
])
def test_reserved_env_is_an_error(make_ctx, home, text):
    root = proj(home, text)
    with pytest.raises(ConfigError, match="set by xsb itself"):
        load_config(make_ctx(cwd=root))


def test_invalid_toml(make_ctx, home):
    root = proj(home, "this is not toml\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(make_ctx(cwd=root))


# ---- expansion (plan §5.3) ----

def test_variable_expansion(make_ctx, home):
    root = proj(home)
    ctx = make_ctx(cwd=root / "", env={"DATA": "/data", "USER": "someone-else"})
    x = Expander(ctx, str(root))
    assert x.expand("~/a", "t") == f"{home}/a"
    assert x.expand("~", "t") == str(home)
    assert x.expand("$HOME/a/${USER}", "t") == f"{home}/a/tester"
    assert x.expand("$HOSTNAME-$ROOT-$CWD", "t") == f"testhost-{root}-{ctx.cwd}"
    assert x.expand("$DATA/x", "t") == "/data/x"
    assert x.expand("cost$$", "t") == "cost$"


@pytest.mark.parametrize("s,msg", [
    ("$NOPE/x", r"\$NOPE is not defined"),
    ("${NOPE}", r"\$NOPE is not defined"),
    ("a $ b", "stray"),
    ("~bob/x", "only ~ and ~/"),
])
def test_expansion_errors(make_ctx, home, s, msg):
    x = Expander(make_ctx(), str(home))
    with pytest.raises(ConfigError, match=msg):
        x.expand(s, "t")


def test_undefined_variable_in_mount_fails_at_use(make_ctx, home):
    root = proj(home, '[[mount]]\npath = "/data/$NO_SUCH_VAR"\n')
    cfg = load_config(make_ctx(cwd=root))
    with pytest.raises(ConfigError, match="NO_SUCH_VAR"):
        config_mounts(cfg)


def test_root_undefined_outside_project(make_ctx, home):
    x = Expander(make_ctx(), None)
    with pytest.raises(ConfigError, match="not in a project"):
        x.expand("$ROOT/x", "t")
    with pytest.raises(ConfigError, match="needs a project root"):
        x.path("rel/x", "t")


def test_relative_paths_resolve_against_root(make_ctx, home):
    write(home / ".xsb/config.toml", 'claude_dir = "agent/claude"\n')
    root = proj(home, '[[mount]]\npath = "data"\nmode = "rw"\n')
    (root / "data").mkdir()
    cfg = load_config(make_ctx(cwd=root))
    assert cfg.agent_dir(__import__("xsb.agents").agents.AGENTS["claude"]) == f"{root}/agent/claude"
    mounts, _ = config_mounts(cfg)
    assert any(m.path == f"{root}/data" and m.mode == "rw" for m in mounts)


def test_symlinked_config_root_is_symlink_dir(make_ctx, home):
    shared = home / "repo" / "policy.toml"
    write(shared, '[[mount]]\npath = "data"\nmode = "rw"\n')
    root = home / "proj"
    (root / "data").mkdir(parents=True)
    os.symlink(shared, root / "xsb.toml")
    cfg = load_config(make_ctx(cwd=root))
    assert cfg.root == str(root)
    assert cfg.files_read == [str(shared)]
    mounts, _ = config_mounts(cfg)
    assert any(m.path == f"{root}/data" for m in mounts)


def test_globs_expand_after_variables(make_ctx, home):
    for n in ("d1", "d2"):
        (home / "g" / n).mkdir(parents=True)
    root = proj(home, '[[mount]]\npath = "$HOME/g/d*"\n')
    mounts, _ = config_mounts(load_config(make_ctx(cwd=root)))
    assert {f"{home}/g/d1", f"{home}/g/d2"} <= {m.path for m in mounts}


# ---- create = true ----

def test_create_true(make_ctx, home):
    (home / "parent").mkdir()
    root = proj(home, '[[mount]]\npath = "~/parent/new"\nmode = "rw"\ncreate = true\n'
                      '[[mount]]\npath = "~/missing/new"\nmode = "rw"\ncreate = true\n'
                      '[[mount]]\npath = "~/parent/nocreate"\n')
    mounts, skipped = config_mounts(load_config(make_ctx(cwd=root)))
    new = [m for m in mounts if m.path == f"{home}/parent/new"]
    assert len(new) == 1 and new[0].create
    assert f"{home}/missing/new" in skipped
    assert f"{home}/parent/nocreate" in skipped
    assert not (home / "parent" / "new").exists()      # created at launch, not here


# ---- `xsb config` and `--defaults` ----

def test_defaults_output_parses_and_equals_builtin(run, make_ctx):
    rc, out, _ = run(make_ctx(), "config", "--defaults")
    assert rc == 0
    assert tomllib.loads(out) == tomllib.loads(defaults_text())
    assert out == defaults_text()
    d = tomllib.loads(out)
    assert d["match"][0]["os"] == "linux"
    assert {m["path"] for m in d["match"][0]["mount"]} == {"/usr", "/etc"}
    # Every list of scalars has an empty default (plan §5.3 design rule).
    assert d["env"]["require"] == [] and d["linux"]["extra_args"] == []


def test_config_tags_sources(run, make_ctx, home):
    write(home / ".xsb/config.toml", 'codex_dir = "~/codex"\n'
          '[[match]]\nos = "linux"\n[match.linux]\nextra_args = ["--ipc", "host"]\n')
    root = proj(home, '[network]\nmode = "open"\n[[mount]]\npath = "/data"\nmode = "rw"\n'
                      '[env.forward]\nTMUX = false\n')
    rc, out, _ = run(make_ctx(cwd=root), "config")
    assert rc == 0
    lines = out.splitlines()

    def tag(prefix):
        line = next(l for l in lines if l.startswith(prefix))
        return line.split("#", 1)[1].strip()

    assert tag("claude_dir =") == "built-in"
    assert tag("codex_dir =") == "~/.xsb/config.toml"
    assert tag("mode = \"open\"") == "xsb.toml"
    assert tag("TMUX =") == "xsb.toml"
    assert tag("TERM =") == "built-in"
    assert tag("extra_args =") == '~/.xsb/config.toml [[match]] #1 (os = "linux")'
    i = lines.index('path = "/data"')
    assert lines[i - 1] == "[[mount]]   # xsb.toml"
    i = lines.index('path = "/usr"')
    assert lines[i - 1] == '[[mount]]   # built-in [[match]] #1 (os = "linux")'
    # The output is itself valid TOML and matches the merged values.
    d = tomllib.loads(out)
    assert d["network"]["mode"] == "open" and d["env"]["forward"]["TMUX"] is False


def test_config_outside_project(run, make_ctx):
    rc, out, _ = run(make_ctx(), "config")
    assert rc == 0 and "Not in a project" in out
    tomllib.loads(out)


def test_broken_symlink_mount_skipped(make_ctx, home):
    os.symlink(home / "gone", home / "dangling")
    root = proj(home, '[[mount]]\npath = "~/dangling"\n[[mount]]\npath = "~/dang*"\n')
    mounts, skipped = config_mounts(load_config(make_ctx(cwd=root)))
    assert not any("dangling" in m.path for m in mounts)
    assert f"{home}/dangling" in skipped
