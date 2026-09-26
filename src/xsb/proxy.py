"""The egress proxy (plan §7.1) and the net-* verbs.

One proxy per user serves every sandbox. It filters HTTPS by CONNECT hostname
(no TLS interception) and plain HTTP by the request's host, re-reading the
allow and deny lists on every request.
"""

from __future__ import annotations

import os

from . import agents
from .context import Context


# --------------------------------------------------------------------------
# Domain lists
# --------------------------------------------------------------------------

def load_list(path: str) -> list[str]:
    """Entries of a domain list: "#" comments and blank lines dropped, lowercased."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    out.append(line)
    except FileNotFoundError:
        pass
    return out


def list_files(ctx: Context) -> list[tuple[str, str]]:
    return [("allow", ctx.allow_list), ("deny", ctx.deny_list)]


def broken_link(path: str) -> bool:
    return os.path.islink(path) and not os.path.exists(path)


def list_problems(ctx: Context) -> list[str]:
    return [f"{ctx.tilde(p)} is a broken symlink (to {os.readlink(p)}); "
            "fix the link or the file it points to"
            for _, p in list_files(ctx) if broken_link(p)]


def status_lines(ctx: Context) -> list[str]:
    lines = ["Proxy"]
    lines.append("  " + running_description(ctx))
    for label, p in list_files(ctx):
        if broken_link(p):
            state = "broken symlink"
        elif os.path.exists(p):
            state = f"{len(load_list(p))} entries"
        else:
            state = "missing"
        shown = ctx.tilde(p) + (f" -> {ctx.tilde(os.path.realpath(p))}" if os.path.islink(p) else "")
        lines.append(f"  {label + ':':<11}{shown}  ({state})")
    lines.append(f"  {'built in:':<11}{' '.join(agents.all_domains())}  "
                 f"({len(agents.all_domains())} entries, the agents' required domains)")
    return lines


def running_description(ctx: Context) -> str:
    return "stopped"
