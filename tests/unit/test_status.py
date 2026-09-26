import os

from conftest import FakeBackend, write


def setup(run, make_ctx, home):
    root = home / "proj"
    root.mkdir()
    rc, _, err = run(make_ctx(cwd=root), "init")
    assert rc == 0, err
    return root


def test_status_ok_inside_and_outside_project(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    for cwd in (root, home):
        rc, out, _ = run(make_ctx(cwd=cwd), "status", backend=FakeBackend())
        assert rc == 0, out
        assert "Project" in out and "Proxy" in out and "Checks" in out
    rc, out, _ = run(make_ctx(cwd=root), "status", backend=FakeBackend())
    assert f"root:        {root}" in out
    rc, out, _ = run(make_ctx(cwd=home), "status", backend=FakeBackend())
    assert "not in a project" in out


def test_status_missing_prerequisite(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    rc, out, _ = run(make_ctx(cwd=root), "status", backend=FakeBackend(["podman not found"]))
    assert rc == 1 and "⚠ podman not found" in out


def test_status_broken_list_symlink(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    allow = home / ".xsb" / "net-allow.txt"
    allow.unlink()
    os.symlink(home / "gone.txt", allow)
    rc, out, _ = run(make_ctx(cwd=root), "status", backend=FakeBackend())
    assert rc == 1 and "broken symlink" in out


def test_status_without_xsb_home(run, make_ctx, home):
    rc, out, _ = run(make_ctx(cwd=home), "status", backend=FakeBackend())
    assert rc == 1 and "run `xsb init`" in out


def test_status_config_error(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    write(root / "xsb.toml", "bogus = 1\n")
    rc, out, _ = run(make_ctx(cwd=root), "status", backend=FakeBackend())
    assert rc == 1 and "unknown key 'bogus'" in out


def test_status_shows_detection_gap(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    (home / "bin").mkdir()
    ctx = make_ctx(cwd=root, env={"PATH": f"{home}/bin:/usr/bin"})
    rc, out, _ = run(ctx, "status", backend=FakeBackend())
    assert rc == 1
    assert "~/bin is on your PATH" in out and 'path = "~/bin"' in out


def test_status_permissive_xsb_home(run, make_ctx, home):
    root = setup(run, make_ctx, home)
    os.chmod(home / ".xsb", 0o755)
    rc, out, _ = run(make_ctx(cwd=root), "status", backend=FakeBackend())
    assert rc == 1 and "chmod 700" in out
