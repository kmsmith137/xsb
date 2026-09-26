import os
import shutil
import subprocess

import pytest

from conftest import write
from xsb.config import load_config
from xsb.policy import (LaunchRequest, Mount, MountTable, PolicyError, build_policy,
                        git_common_dirs)

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 57

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def project(home, text="", name="proj", user=""):
    root = home / name
    root.mkdir(exist_ok=True)
    write(root / "xsb.toml", text + '\n[linux]\nimage = "img:1"\n[[device]]\n'
          'glob = "/dev/nvidia*"\nenabled = false\n')
    x = home / ".xsb"
    x.mkdir(exist_ok=True)
    if user:
        write(x / "config.toml", user)
    return root


def policy(ctx, verb="run", args=("true",), network="open", code_paths=(), **kw):
    cfg = load_config(ctx)
    return build_policy(cfg, LaunchRequest(verb=verb, args=list(args), network=network, **kw),
                        "podman", code_paths=list(code_paths))


def modes(p):
    return {m.path: m.mode for m in p.mounts}


# ---- mount ordering (plan §6.2) ----

def test_mount_table_order_and_dedupe():
    ms = [Mount("/a/b/c", "ro", "1"), Mount("/a", "rw", "2"), Mount("/x", "ro", "3"),
          Mount("/a/b", "ro", "4"), Mount("/x", "rw", "5")]
    t = MountTable(ms)
    assert [(m.path, m.why) for m in t.mounts] == \
        [("/a", "2"), ("/x", "5"), ("/a/b", "4"), ("/a/b/c", "1")]
    assert t.covering("/a/b/c/d").why == "1"
    assert t.covering("/a/bc").why == "2"
    assert t.covering("/y") is None


def test_mount_table_visibility_and_writability(tmp_path):
    d = tmp_path / "d"
    (d / "sub").mkdir(parents=True)
    write(d / "sub" / "f", "x")
    t = MountTable([Mount(str(d), "rw", "root"), Mount(str(d / "sub"), "ro", "pin")])
    assert t.visible(str(d / "sub" / "f"))
    assert not t.writable(str(d / "sub" / "f"))
    assert t.writable(str(d))                       # partly writable counts
    assert not t.visible(str(tmp_path))
    # A symlink is resolved to where its target is visible.
    os.symlink(d / "sub" / "f", tmp_path / "link")
    assert t.sandbox_paths(str(tmp_path / "link")) == [str(d / "sub" / "f")]


def test_policy_mount_order_deeper_wins(make_ctx, home):
    root = project(home, '[protect]\n"top" = true\n[[mount]]\npath = "top/data"\nmode = "rw"\n')
    (root / "top" / "data").mkdir(parents=True)
    p = policy(make_ctx(cwd=root))
    paths = [m.path for m in p.mounts]
    depths = [len(x.strip("/").split("/")) for x in paths]
    assert depths == sorted(depths)
    mm = modes(p)
    assert mm[str(root)] == "rw" and mm[str(root / "top")] == "ro"
    assert mm[str(root / "top" / "data")] == "rw"      # deeper wins
    assert len(paths) == len(set(paths))


def test_same_path_later_rule_wins(make_ctx, home):
    # A read-write config mount of a protected path: step 5 (protect) comes later.
    root = project(home, '[protect]\n"keep" = true\n[[mount]]\npath = "keep"\nmode = "rw"\n')
    (root / "keep").mkdir()
    assert modes(policy(make_ctx(cwd=root)))[str(root / "keep")] == "ro"


# ---- basic policy ----

def test_root_rw_config_ro_and_missing_skipped(make_ctx, home):
    root = project(home, '[[mount]]\npath = "/definitely/not/here"\n')
    p = policy(make_ctx(cwd=root))
    mm = modes(p)
    assert mm[str(root)] == "rw"
    assert mm[str(root / "xsb.toml")] == "ro"        # I1
    assert mm["/usr"] == "ro" and mm["/etc"] == "ro"
    assert "/definitely/not/here" in p.skipped
    assert p.image == "img:1" and p.devices == []


def test_symlinked_config_pinned_at_real_path(make_ctx, home):
    real = write(home / "proj" / "policies" / "p.toml",
                 '[linux]\nimage = "img:1"\n[[device]]\nglob = "/dev/nvidia*"\nenabled = false\n')
    root = home / "proj"
    os.symlink("policies/p.toml", root / "xsb.toml")
    (home / ".xsb").mkdir()
    p = policy(make_ctx(cwd=root))
    assert modes(p)[real] == "ro"


def test_lists_pinned_when_visible(make_ctx, home):
    root = project(home)
    lists = root / "netlists"
    write(lists / "allow.txt", "example.com\n")
    os.symlink(lists / "allow.txt", home / ".xsb" / "net-allow.txt")
    p = policy(make_ctx(cwd=root))
    assert modes(p)[str(lists / "allow.txt")] == "ro"
    # A list that isn't visible is never mounted.
    write(home / "elsewhere" / "deny.txt", "")
    os.symlink(home / "elsewhere" / "deny.txt", home / ".xsb" / "net-deny.txt")
    p = policy(make_ctx(cwd=root))
    assert str(home / "elsewhere" / "deny.txt") not in modes(p)


def test_refuse(make_ctx, home):
    root = project(home, 'refuse = [ { dir = "top", reason = "run from a worktree" } ]\n')
    (root / "top" / "sub").mkdir(parents=True)
    with pytest.raises(PolicyError, match="run from a worktree"):
        policy(make_ctx(cwd=root / "top" / "sub"))
    policy(make_ctx(cwd=root))       # fine elsewhere


def test_env_require(make_ctx, home):
    root = project(home, '[env]\nrequire = ["NEEDED"]\n')
    with pytest.raises(PolicyError, match="NEEDED not set"):
        policy(make_ctx(cwd=root))
    p = policy(make_ctx(cwd=root, env={"NEEDED": "yes"}))
    assert p.env["NEEDED"] == "yes"


def test_env_contains_only_expected(make_ctx, home):
    root = project(home, '[env.forward]\nTMUX = false\nMINE = true\n[env.set]\nVENV = "$CWD/.venv"\n')
    env = {"TERM": "xterm", "TMUX": "/tmp/tmux", "MINE": "1", "SECRET_TOKEN": "s3cret",
           "PATH": "/usr/bin:/bin"}
    p = policy(make_ctx(cwd=root, env=env), network="enforced")
    assert "SECRET_TOKEN" not in p.env and "TMUX" not in p.env
    assert p.env["TERM"] == "xterm" and p.env["MINE"] == "1"
    assert p.env["VENV"] == f"{root}/.venv"
    assert p.env["PATH"] == "/usr/bin:/bin"
    assert p.env["HTTPS_PROXY"] == "http://127.0.0.1:3128" == p.env["http_proxy"]
    assert p.env["NO_PROXY"] == "localhost,127.0.0.1,::1"
    assert p.env["XSB_ROOT"] == str(root) and p.env["XSB_NETWORK"] == "enforced"
    assert p.env["CUPY_CACHE_DIR"] == "/tmp/cupy_cache"
    expected = {"TERM", "MINE", "VENV", "CUPY_CACHE_DIR", "HOME", "USER", "PATH", "XDG_CACHE_HOME",
                "CLAUDE_CONFIG_DIR", "CODEX_HOME", "IS_SANDBOX", "DISABLE_AUTOUPDATER",
                "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy",
                "XSB_ROOT", "XSB_BACKEND", "XSB_NETWORK"}
    assert set(p.env) == expected


def test_open_mode_has_no_proxy_vars(make_ctx, home):
    root = project(home)
    p = policy(make_ctx(cwd=root), network="open")
    assert not any("proxy" in k.lower() for k in p.env)


# ---- agents (plan §8) ----

def fake_agent(home, name, elf=True, codex_layout=False):
    if codex_layout:
        rel = home / ".codex" / "packages" / "standalone" / "releases" / "1.0"
        write(rel / "codex-package.json", "{}")
        write(rel / "codex-path" / "rg", "")
        real = rel / "bin" / name
        write(home / ".codex" / "auth.json", "{}")
    else:
        real = home / "store" / "versions" / f"{name}-1.0"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_bytes(ELF if elf else b"#!/bin/sh\necho hi\n")
    real.chmod(0o755)
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    mid = home / "store" / f"{name}-link"
    mid.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(real, mid)
    os.symlink(mid, bindir / name)          # a chain of two symlinks
    return str(bindir), str(real)


def test_agent_program_resolved_and_mounted(make_ctx, home):
    root = project(home)
    bindir, real = fake_agent(home, "claude")
    ctx = make_ctx(cwd=root, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    p = policy(ctx, verb="claude", args=["--resume"])
    assert p.command[0] == real
    assert p.command[1:] == ["--dangerously-skip-permissions", "--resume"]
    assert modes(p)[real] == "ro"
    assert p.env["CLAUDE_CONFIG_DIR"] == str(home / ".xsb" / "claude")
    assert "CODEX_HOME" not in p.env
    assert modes(p)[str(home / ".xsb" / "claude")] == "rw"
    assert str(home / ".xsb" / "codex") not in modes(p)


def test_codex_release_dir_mounted_not_codex_home(make_ctx, home):
    root = project(home)
    bindir, real = fake_agent(home, "codex", codex_layout=True)
    ctx = make_ctx(cwd=root, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    p = policy(ctx, verb="codex")
    rel = str(home / ".codex" / "packages" / "standalone" / "releases" / "1.0")
    assert p.command[:2] == [real, "--dangerously-bypass-approvals-and-sandbox"]
    assert modes(p)[rel] == "ro"
    assert not any(m.path in (str(home / ".codex"), str(home / ".codex" / "auth.json"))
                   for m in p.mounts)
    assert not p.table().visible(str(home / ".codex" / "auth.json"))


def test_missing_agent_refused(make_ctx, home):
    root = project(home)
    with pytest.raises(PolicyError, match="not found on PATH"):
        policy(make_ctx(cwd=root), verb="claude")


def test_shell_and_run_mount_all_agent_dirs(make_ctx, home):
    root = project(home)
    bindir, real = fake_agent(home, "claude")
    ctx = make_ctx(cwd=root, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    for verb, args in (("shell", []), ("run", ["ls"])):
        p = policy(ctx, verb=verb, args=args)
        mm = modes(p)
        assert mm[str(home / ".xsb" / "claude")] == "rw"
        assert mm[str(home / ".xsb" / "codex")] == "rw"
        assert p.env["CLAUDE_CONFIG_DIR"] and p.env["CODEX_HOME"]
        assert mm[real] == "ro"                  # claude runnable by hand; codex absent
    assert policy(ctx, verb="shell", args=[]).command == ["bash"]


def test_agent_dir_created_later(make_ctx, home):
    root = project(home)
    p = policy(make_ctx(cwd=root), verb="run")
    assert str(home / ".xsb" / "claude") in p.create_dirs
    assert not (home / ".xsb" / "claude").exists()


# ---- git (plan §6.2 step 4) ----

def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"})


@pytest.fixture
def worktree_layout(home):
    """<root>/top: main checkout (protected); <root>/dev: its worktree;
    <root>/dev/sub: a nested repo's worktree (like ch_top's layout)."""
    root = project(home, '[protect]\n"top" = true\n')
    top = root / "top"
    top.mkdir()
    git("init", "-q", "-b", "main", cwd=top)
    git("commit", "-q", "--allow-empty", "-m", "x", cwd=top)
    (top / "sub").mkdir()
    git("init", "-q", "-b", "main", cwd=top / "sub")
    git("commit", "-q", "--allow-empty", "-m", "x", cwd=top / "sub")
    shutil.rmtree(top / ".git" / "hooks", ignore_errors=True)
    git("worktree", "add", "-q", str(root / "dev"), "-b", "dev", cwd=top)
    git("worktree", "add", "-q", str(root / "dev" / "sub"), "-b", "dev", cwd=top / "sub")
    return root


@needs_git
def test_git_common_dirs(worktree_layout):
    root = worktree_layout
    dev = root / "dev"
    gits = git_common_dirs(str(dev), str(root))
    assert gits == [str(root / "top" / ".git"), str(root / "top" / "sub" / ".git")]
    # From inside the nested repo, the enclosing worktree's repo is found too.
    gits = git_common_dirs(str(dev / "sub"), str(root))
    assert set(gits) == {str(root / "top" / ".git"), str(root / "top" / "sub" / ".git")}


@needs_git
def test_git_pins(make_ctx, worktree_layout):
    root = worktree_layout
    p = policy(make_ctx(cwd=root / "dev"))
    mm = modes(p)
    g = root / "top" / ".git"
    assert mm[str(root / "top")] == "ro"             # protected
    assert mm[str(g)] == "rw"                        # re-opened for commits
    assert mm[str(g / "config")] == "ro"
    assert mm[str(g / "hooks")] == "ro"
    assert str(g / "hooks") in p.create_dirs         # was missing: created, then pinned
    assert mm[str(root / "dev" / ".git")] == "ro"    # worktree pointer file
    assert mm[str(g / "worktrees" / "dev" / "commondir")] == "ro"
    assert mm[str(root / "top" / "sub" / ".git" / "config")] == "ro"
    assert mm[str(root / "dev" / "sub" / ".git")] == "ro"


# ---- invariants ----

@pytest.mark.parametrize("text", [
    '[[mount]]\npath = "~"\nmode = "ro"\n',
    '[[mount]]\npath = "~/.xsb/config.toml"\n',
    'claude_dir = "~/.xsb"\n',
])
def test_i3_xsb_home_exposure_refused(make_ctx, home, text):
    root = project(home, text)
    write(home / ".xsb" / "config.toml", "")
    with pytest.raises(PolicyError, match="I3"):
        policy(make_ctx(cwd=root))


def test_i3_agent_dir_inside_xsb_home_allowed(make_ctx, home):
    root = project(home)
    p = policy(make_ctx(cwd=root), verb="run")
    assert not p.table().visible(str(home / ".xsb" / "config.toml"))


def test_i4_code_under_writable_root_refused(make_ctx, home):
    root = project(home)
    code = root / "clone" / "src" / "xsb"
    code.mkdir(parents=True)
    with pytest.raises(PolicyError, match="I4"):
        policy(make_ctx(cwd=root), code_paths=[str(code)])
    # Protected: allowed (an editable install from a clone the sandbox can't write).
    root2 = project(home, '[protect]\n"clone" = true\n', name="proj2")
    code2 = root2 / "clone" / "src" / "xsb"
    code2.mkdir(parents=True)
    policy(make_ctx(cwd=root2), code_paths=[str(code2)])
    # Outside the root: allowed.
    policy(make_ctx(cwd=root), code_paths=[str(home / "elsewhere")])


def test_i4_real_install_is_fine(make_ctx, home):
    root = project(home)
    cfg = load_config(make_ctx(cwd=root))
    build_policy(cfg, LaunchRequest(verb="run", args=["true"]), "podman")   # default code paths


def test_i5_runtime_dir_visible_refused(make_ctx, home, short_tmp):
    root = project(home, f'[[mount]]\npath = "{short_tmp}"\n')
    os.makedirs(os.path.join(short_tmp, "rt"), exist_ok=True)
    with pytest.raises(PolicyError, match="I5"):
        policy(make_ctx(cwd=root))


def test_colon_in_path_refused(make_ctx, home):
    root = project(home, '[[mount]]\npath = "~/a:b"\n')
    (home / "a:b").mkdir()
    with pytest.raises(PolicyError, match="':'"):
        policy(make_ctx(cwd=root))
