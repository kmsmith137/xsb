"""The Policy: the fully resolved, OS-neutral description of one launch.

Built from the merged config (config.py) and consumed by a backend. This
module also enforces the security invariants (plan §6.1).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .config import Config, ConfigError, is_under


class PolicyError(Exception):
    """The launch is refused (an invariant would be violated, I7)."""


@dataclass
class Mount:
    path: str                 # where it appears in the sandbox (the host path, except xsb-internal mounts)
    mode: str                 # "ro" | "rw"
    why: str                  # what added it, for --dry-run
    src: str | None = None    # host path, when it differs from `path`
    create: bool = False      # create the directory before launching

    @property
    def source(self) -> str:
        return self.src or self.path

    @property
    def depth(self) -> int:
        return len([p for p in self.path.split("/") if p])


class MountTable:
    """A set of mounts, with the questions the invariants ask about them.

    Rules (plan §6.2): when two mounts cover the same path the deeper one wins;
    for identical paths the later one wins.
    """

    def __init__(self, mounts: list[Mount]):
        last = {}
        for i, m in enumerate(mounts):
            last[m.path] = i
        kept = [m for i, m in enumerate(mounts) if last[m.path] == i]
        # Stable sort: shallower first, and the order given for ties.
        self.mounts = sorted(kept, key=lambda m: m.depth)
        self._real = {id(m): os.path.realpath(m.source) for m in self.mounts}

    def covering(self, path: str) -> Mount | None:
        """The mount that decides what `path` (a sandbox path) is."""
        best = None
        for m in self.mounts:
            if is_under(path, m.path) and (best is None or m.depth >= best.depth):
                best = m
        return best

    def sandbox_paths(self, host_path: str) -> list[str]:
        """Sandbox paths at which the host file or dir `host_path` is visible."""
        real = os.path.realpath(host_path)
        out = []
        for m in self.mounts:
            msrc = self._real[id(m)]
            if not is_under(real, msrc):
                continue
            rel = os.path.relpath(real, msrc)
            p = m.path if rel == "." else os.path.join(m.path, rel)
            if self.covering(p) is m and p not in out:
                out.append(p)
        return out

    def visible(self, host_path: str) -> bool:
        return bool(self.sandbox_paths(host_path))

    def writable(self, host_path: str) -> bool:
        """True if the sandbox could write host_path, or anything inside it."""
        for p in self.sandbox_paths(host_path):
            if self.covering(p).mode == "rw":
                return True
            if any(m.mode == "rw" and m.path != p and is_under(m.path, p) for m in self.mounts):
                return True
        return False


def config_mounts(cfg: Config) -> tuple[list[Mount], list[str]]:
    """Mounts from the [[mount]] entries: globs expanded, missing paths skipped.

    Returns (mounts, skipped). A `create = true` entry whose path is missing but
    whose parent exists is kept, marked for creation at launch.
    """
    exp = cfg.expander
    mounts, skipped = [], []
    for e in cfg.merged.active("mount"):
        raw = e.fields["path"]
        what = f"mount {raw!r} ({e.source})"
        matches = exp.glob(raw, what)
        if matches:
            mounts += [Mount(p, e.fields["mode"], f"[[mount]] {e.source}") for p in matches]
            continue
        p = exp.path(raw, what)
        if e.fields["create"] and not glob_magic(p) and os.path.isdir(os.path.dirname(p)):
            mounts.append(Mount(p, e.fields["mode"], f"[[mount]] {e.source}, created", create=True))
        else:
            skipped.append(p)
    return mounts, skipped


def glob_magic(p: str) -> bool:
    import glob
    return glob.has_magic(p)
