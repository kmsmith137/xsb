import os
import stat
import tomllib

from conftest import write


def test_init_creates_machine_and_project(run, make_ctx, home):
    root = home / "proj"
    root.mkdir()
    rc, out, err = run(make_ctx(cwd=root), "init")
    assert rc == 0, err
    x = home / ".xsb"
    assert stat.S_IMODE(os.stat(x).st_mode) == 0o700
    for p in ("claude", "codex"):
        assert (x / p).is_dir()
    for p in ("net-allow.txt", "net-deny.txt", "config.toml"):
        assert (x / p).is_file()
    assert "xsb net-allow" in (x / "net-allow.txt").read_text()
    text = (root / "xsb.toml").read_text()
    assert f"marks {root} as an xsb root" in text
    assert tomllib.loads(text) == {}                     # comments only
    assert tomllib.loads((x / "config.toml").read_text()) == {}
    assert "Created:" in out and "~/.xsb/config.toml" in out and "~/proj/xsb.toml" in out


def test_init_never_overwrites(run, make_ctx, home):
    x = home / ".xsb"
    x.mkdir()
    write(x / "config.toml", "# mine\n")
    target = write(home / "lists" / "allow.txt", "example.com\n")
    os.symlink(target, x / "net-allow.txt")
    os.symlink(home / "missing.txt", x / "net-deny.txt")     # broken symlink: kept as is
    root = home / "proj"
    root.mkdir()
    rc, out, err = run(make_ctx(cwd=root), "init")
    assert rc == 0, err
    assert (x / "config.toml").read_text() == "# mine\n"
    assert os.readlink(x / "net-allow.txt") == target
    assert open(target).read() == "example.com\n"
    assert os.path.islink(x / "net-deny.txt") and not os.path.exists(x / "net-deny.txt")
    assert "config.toml" not in out and "net-allow" not in out


def test_init_inside_xsb_home_stops_after_machine_setup(run, make_ctx, home):
    x = home / ".xsb"
    rc, out, _ = run(make_ctx(cwd=home), "init")      # $HOME contains ~/.xsb: refused...
    assert rc == 1
    assert x.is_dir()                                  # ...but the machine setup happened
    (x / "claude" / "sub").mkdir()
    for cwd in (x, x / "claude" / "sub"):
        rc, out, _ = run(make_ctx(cwd=cwd), "init")
        assert rc == 0 and "is set up" in out
        assert not (cwd / "xsb.toml").exists()


def test_init_refuses_existing_config_here_or_above(run, make_ctx, home):
    root = home / "proj"
    write(root / "xsb.toml", "")
    rc, _, err = run(make_ctx(cwd=root), "init")
    assert rc == 1 and "already exists" in err
    (root / "sub").mkdir()
    rc, _, err = run(make_ctx(cwd=root / "sub"), "init")
    assert rc == 1 and "already exists" in err
    assert not (root / "sub" / "xsb.toml").exists()


def test_init_refuses_dir_containing_xsb_home(run, make_ctx, home):
    rc, _, err = run(make_ctx(cwd=home), "init")
    assert rc == 1 and "contains ~/.xsb" in err
    assert not (home / "xsb.toml").exists()


def test_init_config_has_detected_entries(run, make_ctx, home, tmp_path):
    bindir = home / "bin"
    bindir.mkdir()
    conda = tmp_path / "opt-elsewhere" / "conda"
    write(conda / "bin" / "conda", "")
    root = home / "proj"
    (root / ".venv" / "bin").mkdir(parents=True)
    path = f"{root}/.venv/bin:{bindir}:/usr/bin:/snap/bin:/nonexistent"
    ctx = make_ctx(cwd=root, env={"PATH": path, "CONDA_EXE": str(conda / "bin" / "conda")})
    rc, _, err = run(ctx, "init")
    assert rc == 0, err
    text = (home / ".xsb" / "config.toml").read_text()
    d = tomllib.loads(text)
    paths = [m["path"] for m in d["mount"]]
    assert paths == [str(conda), "~/bin"]
    assert all(m["mode"] == "ro" for m in d["mount"])
    assert "Added by `xsb init` for this machine" in text
    assert "~/bin is on your PATH, but the sandbox wouldn't see it." in text
