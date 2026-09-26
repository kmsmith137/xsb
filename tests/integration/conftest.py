"""Integration tests: real podman launches (Linux only).

Run them all with `pytest tests/integration`. They are skipped when podman
isn't available (e.g. inside a sandbox, where podman can't nest).
"""

import os
import shutil
import subprocess
import sys
import tempfile

import pytest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harness.py")


def podman_works() -> bool:
    if not sys.platform.startswith("linux") or not shutil.which("podman"):
        return False
    try:
        r = subprocess.run(["podman", "info"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


PODMAN = podman_works()


def pytest_collection_modifyitems(config, items):
    if PODMAN:
        return
    skip = pytest.mark.skip(reason="needs Linux with a working rootless podman")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)


class Sandbox:
    """A project root plus a throwaway ~/.xsb, and a way to run xsb there."""

    def __init__(self, base: str):
        self.base = base
        self.root = os.path.join(base, "proj")
        self.xsb_home = os.path.join(base, "xsb-home")
        rt_parent = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
        self.runtime_dir = tempfile.mkdtemp(prefix="xsbi", dir=rt_parent)
        os.makedirs(self.root)
        # `xsb init` sets up ~/.xsb and the project, like a user would.
        r = self.xsb("init", cwd=self.root)
        assert r.returncode == 0, r.stderr
        # Agent dirs inside the throwaway ~/.xsb, not the real one.
        self.prepend_user_keys(f'claude_dir = "{self.xsb_home}/claude"\n'
                               f'codex_dir = "{self.xsb_home}/codex"\n')

    @property
    def user_config(self) -> str:
        return os.path.join(self.xsb_home, "config.toml")

    def prepend_user_keys(self, text: str):
        """Top-level keys, which must precede any table."""
        with open(self.user_config) as f:
            old = f.read()
        with open(self.user_config, "w") as f:
            f.write(text + old)

    def append_user_config(self, text: str):
        with open(self.user_config, "a") as f:
            f.write("\n" + text)

    def write(self, rel: str, text: str = "") -> str:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def xsb(self, *args, cwd=None, env=None, timeout=300, input=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([sys.executable, HARNESS, self.xsb_home, self.runtime_dir, *args],
                              cwd=cwd or self.root, env=e, capture_output=True, text=True,
                              timeout=timeout, input=input)

    def run(self, script: str, *opts, cwd=None, env=None, network="open", timeout=300):
        """`xsb run` a bash script in the sandbox."""
        net = ["--network", network] if network else []
        return self.xsb("run", *net, *opts, "--", "bash", "-c", script, cwd=cwd, env=env,
                        timeout=timeout)

    def popen(self, *args, cwd=None):
        return subprocess.Popen([sys.executable, HARNESS, self.xsb_home, self.runtime_dir, *args],
                                cwd=cwd or self.root, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    def close(self):
        self.xsb("net-stop")
        shutil.rmtree(self.runtime_dir, ignore_errors=True)


@pytest.fixture
def sb(tmp_path):
    s = Sandbox(str(tmp_path))
    yield s
    s.close()
