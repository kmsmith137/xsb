"""`xsb status` (plan §4.1): project state, proxy state, and health checks."""

from __future__ import annotations

import os

from . import agents
from .config import ConfigError, load_config
from .context import Context


class Checks:
    def __init__(self):
        self.items = []     # (ok, text, fix)

    def add(self, ok: bool, text: str, fix: str = ""):
        self.items.append((ok, text, fix))

    @property
    def failed(self) -> bool:
        return any(not ok for ok, _, _ in self.items)

    def render(self) -> list[str]:
        lines = []
        for ok, text, fix in self.items:
            lines.append(f"  {'✓' if ok else '⚠'} {text}")
            for fl in fix.splitlines():
                lines.append(f"      {fl}")
        return lines


def describe_file(ctx: Context, path: str) -> str:
    s = ctx.tilde(path)
    if os.path.islink(path):
        s += " -> " + ctx.tilde(os.path.realpath(path))
    return s


def gather(ctx: Context, backend=None) -> tuple[list[str], Checks]:
    from .backends import get_backend
    backend = backend or get_backend(ctx.os)
    lines, checks = [], Checks()

    # 1. Project
    lines.append("Project")
    cfg = None
    try:
        cfg = load_config(ctx, require_root=False)
    except ConfigError as e:
        lines.append("  (config error, see checks)")
        checks.add(False, f"config: {e}", "fix the file named above")
    if cfg is not None:
        if cfg.root:
            lines.append(f"  root:        {cfg.root}")
            lines.append(f"  config:      {describe_file(ctx, cfg.config_path)}")
        else:
            lines.append("  not in a project (no xsb.toml here or above; `xsb init` makes one)")
        for a in agents.AGENTS.values():
            try:
                d = cfg.agent_dir(a)
                state = "" if os.path.isdir(d) else "   (created at first launch)"
                lines.append(f"  {a.name + ' dir:':<13}{ctx.tilde(d)}{state}")
            except ConfigError as e:
                checks.add(False, f"{a.config_key}: {e}")
        lines.append(f"  network:     {cfg.network_mode}")
    lines.append("")

    # 2. Proxy
    from . import proxy
    lines += proxy.status_lines(ctx)
    lines.append("")

    # 3. Checks
    problems = backend.check()
    for problem in problems:
        checks.add(False, problem)
    if not problems:
        checks.add(True, f"{backend.name} prerequisites are installed")
    if os.path.isdir(ctx.xsb_home):
        checks.add(True, f"{ctx.tilde(ctx.xsb_home)} exists")
        mode = os.stat(ctx.xsb_home).st_mode & 0o777
        if mode & 0o077:
            checks.add(False, f"{ctx.tilde(ctx.xsb_home)} is accessible to other users "
                       f"(mode {mode:o}); it holds agent logins",
                       f"fix: chmod 700 {ctx.tilde(ctx.xsb_home)}")
    else:
        checks.add(False, f"{ctx.tilde(ctx.xsb_home)} does not exist", "fix: run `xsb init`")
    for problem in proxy.list_problems(ctx):
        checks.add(False, problem)
    vp = proxy.version_problem(ctx)
    if vp:
        checks.add(False, vp)
    if cfg is not None:
        _config_checks(ctx, cfg, backend, checks)
    return lines, checks


def _config_checks(ctx: Context, cfg, backend, checks: Checks):
    from .detect import run_checks
    from .policy import Mount, MountTable, config_mounts
    try:
        mounts, _ = config_mounts(cfg)
    except ConfigError as e:
        checks.add(False, f"config: {e}")
        return
    base = [Mount(p, "ro", "base") for p in backend.base_read_paths()]
    extra = [Mount(cfg.root, "rw", "root")] if cfg.root else []
    table = MountTable(base + mounts + extra)
    findings = run_checks(ctx, table, cfg.root)
    for f in findings:
        checks.add(False, f.comment, f"fix: add to {ctx.tilde(ctx.user_config)}:\n" + f.toml(ctx).split("\n", 1)[1].rstrip())
    if not findings:
        checks.add(True, "PATH and conda are visible in the sandbox")
