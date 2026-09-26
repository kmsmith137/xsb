"""Detection checks (plan §5.6): what the built-in defaults miss on this machine.

Each check returns Findings: a comment saying why, and the TOML to add to
~/.xsb/config.toml. `xsb init` writes them into a new config.toml, and
`xsb status` runs them again later and shows them as warnings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .config import is_under
from .context import Context
from .policy import MountTable
from .tomlw import toml_value


@dataclass
class Finding:
    comment: str
    path: str        # the host path to mount read-only

    def toml(self, ctx: Context) -> str:
        return (f"# {self.comment}\n[[mount]]\npath = {toml_value(ctx.tilde(self.path))}\n"
                f'mode = "ro"\n')


# PATH entries never worth mounting: snap packages need snapd and its mounts,
# so they can't run in the sandbox anyway.
IGNORED_PATH_PREFIXES = ("/snap",)


def check_conda(ctx: Context, table: MountTable) -> list[Finding]:
    """A conda install outside the default locations (found via $CONDA_EXE)."""
    exe = ctx.environ.get("CONDA_EXE")
    if not exe or not os.path.isabs(exe) or not os.path.exists(exe):
        return []
    root = os.path.dirname(os.path.dirname(os.path.realpath(exe)))
    if table.visible(root):
        return []
    return [Finding(f"conda is installed in {ctx.tilde(root)} ($CONDA_EXE), "
                    "which the sandbox wouldn't see.", root)]


def check_path(ctx: Context, table: MountTable, root: str | None,
               already: list[Finding] = ()) -> list[Finding]:
    """Directories on the launching shell's PATH that the sandbox wouldn't see."""
    out = []
    seen = set()
    for d in ctx.environ.get("PATH", "").split(":"):
        if not d or not os.path.isabs(d) or d in seen:
            continue
        seen.add(d)
        d = os.path.normpath(d)
        if not os.path.isdir(d):
            continue                      # missing on the host too
        if root and is_under(os.path.realpath(d), os.path.realpath(root)):
            continue                      # inside the project, which is always mounted
        if any(is_under(d, p) for p in IGNORED_PATH_PREFIXES):
            continue
        if any(is_under(os.path.realpath(d), os.path.realpath(f.path)) for f in (*already, *out)):
            continue
        if table.visible(d):
            continue
        out.append(Finding(f"{ctx.tilde(d)} is on your PATH, but the sandbox wouldn't see it.", d))
    return out


def run_checks(ctx: Context, table: MountTable, root: str | None) -> list[Finding]:
    found = check_conda(ctx, table)
    found += check_path(ctx, table, root, found)
    return found
