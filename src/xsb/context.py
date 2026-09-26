"""Facts about the machine and the launching process that xsb depends on.

Everything that varies between machines or test runs (home dir, hostname, OS,
current directory, environment, where ~/.xsb and the proxy's runtime dir live)
is gathered here once, so the rest of xsb is a function of a Context. Unit
tests build Contexts directly; `Context.from_process()` is the real one.
"""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass, field


def os_name(platform: str = sys.platform) -> str:
    """xsb's name for the OS: "linux" or "macos" (the values [[match]] os takes)."""
    if platform.startswith("linux"):
        return "linux"
    if platform == "darwin":
        return "macos"
    return platform


def short_hostname() -> str:
    return socket.gethostname().split(".")[0]


def default_runtime_dir(os_: str, environ: dict, uid: int) -> str:
    """The per-user runtime dir for the proxy (plan §7.1).

    $XDG_RUNTIME_DIR/xsb, else /tmp/xsb-<uid> on Linux and $TMPDIR/xsb on macOS.
    Kept short on purpose: Unix socket paths are limited to ~104-108 bytes.
    """
    xdg = environ.get("XDG_RUNTIME_DIR")
    if xdg and os.path.isdir(xdg):
        return os.path.join(xdg, "xsb")
    if os_ == "macos":
        return os.path.join(environ.get("TMPDIR") or "/tmp", "xsb")
    return f"/tmp/xsb-{uid}"


@dataclass
class Context:
    os: str                      # "linux" | "macos"
    home: str                    # $HOME, absolute
    user: str
    hostname: str                # short hostname
    cwd: str                     # the launch directory (physical path)
    environ: dict = field(default_factory=dict)   # the launching environment
    xsb_home: str = ""           # ~/.xsb
    runtime_dir: str = ""        # proxy runtime dir
    uid: int = 0

    def __post_init__(self):
        if not self.xsb_home:
            self.xsb_home = os.path.join(self.home, ".xsb")
        if not self.runtime_dir:
            self.runtime_dir = default_runtime_dir(self.os, self.environ, self.uid)

    @classmethod
    def from_process(cls) -> "Context":
        environ = dict(os.environ)
        home = os.path.expanduser("~")
        user = environ.get("USER") or environ.get("LOGNAME")
        if not user:
            import pwd
            user = pwd.getpwuid(os.getuid()).pw_name
        return cls(os=os_name(), home=home, user=user, hostname=short_hostname(),
                   cwd=os.getcwd(), environ=environ, uid=os.getuid())

    # Paths inside ~/.xsb (plan §5.1).
    @property
    def user_config(self) -> str:
        return os.path.join(self.xsb_home, "config.toml")

    @property
    def allow_list(self) -> str:
        return os.path.join(self.xsb_home, "net-allow.txt")

    @property
    def deny_list(self) -> str:
        return os.path.join(self.xsb_home, "net-deny.txt")

    def tilde(self, path: str) -> str:
        """Abbreviate $HOME as ~ for display."""
        if path == self.home:
            return "~"
        if path.startswith(self.home.rstrip("/") + "/"):
            return "~" + path[len(self.home.rstrip("/")):]
        return path
