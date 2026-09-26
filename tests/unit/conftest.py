import os
import tempfile

import pytest

from xsb import cli
from xsb.context import Context


class FakeBackend:
    name = "fake"

    def __init__(self, problems=()):
        self.problems = list(problems)

    def check(self):
        return list(self.problems)

    def base_read_paths(self):
        return []


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture
def short_tmp():
    # Unix socket paths are limited to ~104-108 bytes; pytest's tmp_path can be longer.
    d = tempfile.mkdtemp(prefix="xsbu")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def make_ctx(home, short_tmp):
    def make(cwd=None, os_="linux", hostname="testhost", env=None, **kw):
        environ = {"PATH": "/usr/bin:/bin", "HOME": str(home), "USER": "tester"}
        environ.update(env or {})
        return Context(os=os_, home=str(home), user="tester", hostname=hostname,
                       cwd=str(cwd or home), environ=environ,
                       runtime_dir=os.path.join(short_tmp, "rt"), uid=os.getuid(), **kw)
    return make


@pytest.fixture
def run(capsys, monkeypatch):
    """Run the CLI in-process: returns (exit code, stdout, stderr)."""
    def run_(ctx, *args, backend=None):
        if backend is not None:
            import xsb.backends
            monkeypatch.setattr(xsb.backends, "get_backend", lambda os_=None: backend)
        rc = cli.main(list(args), ctx=ctx)
        o = capsys.readouterr()
        return rc, o.out, o.err
    return run_


def write(path, text=""):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path
