"""OS-specific sandbox implementations (plan §10).

A backend turns a Policy into a process launch. `command()` is pure, so
`--dry-run` and the unit tests exercise it without launching anything.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Protocol


class BackendError(Exception):
    """The backend can't launch (e.g. a missing program); reported in one line."""


@dataclass
class LaunchSpec:
    argv: list[str]
    files: dict = field(default_factory=dict)     # path -> content, written before launching
    description: str = ""                        # extra text for --dry-run (e.g. a Seatbelt profile)
    cleanup: list = field(default_factory=list)  # paths removed after the launch
    image: str = ""                              # podman: the base image (pulled if missing)
    env: dict | None = None                      # the launched process's environment (seatbelt)


class Backend(Protocol):
    name: str

    def check(self) -> list[str]: ...                      # prerequisite problems, for `xsb status`
    def command(self, policy) -> LaunchSpec: ...           # argv + files to write; pure
    def launch(self, spec: LaunchSpec) -> int: ...         # run it, return the exit status
    def base_read_paths(self) -> list[str]: ...            # visible without a mount (macOS system paths)


def backend_name(os_: str) -> str:
    return {"linux": "podman", "macos": "seatbelt"}.get(os_, "")


def get_backend(os_: str | None = None) -> Backend:
    from ..context import os_name
    os_ = os_ or os_name(sys.platform)
    if os_ == "linux":
        from .podman import PodmanBackend
        return PodmanBackend()
    if os_ == "macos":
        from .seatbelt import SeatbeltBackend
        return SeatbeltBackend()
    raise RuntimeError(f"xsb does not support this OS ({sys.platform})")
