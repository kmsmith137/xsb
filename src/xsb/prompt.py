"""The system-prompt text xsb adds for agents (plan §9).

It describes the sandbox as actually configured for this launch, so the agent
knows what it may write, why some paths are read-only, and what to do when
the network proxy blocks a domain. `xsb prompt` prints it.
"""

from __future__ import annotations

import os

from .config import is_under
from .policy import Policy

BLOCK_MESSAGE = 'xsb: egress to "..." is not on the allowlist'


def _protected_summary(policy: Policy) -> str:
    globs, git = [], False
    for _path, why in policy.protected:
        if why.startswith("protected: "):
            g = why[len("protected: "):]
            if g not in globs:
                globs.append(g)
        elif why.startswith("git"):
            git = True
    parts = []
    if globs:
        parts.append("these paths relative to the root: " + ", ".join(globs))
    if git:
        parts.append("each git repository's config, hooks/ and worktree pointer files "
                     "(the rest of .git stays writable, so commits work)")
    parts.append("xsb's own config (xsb.toml) and network lists")
    return "; ".join(parts)


def generate(policy: Policy) -> str:
    root = policy.root
    writable = []
    for m in policy.mounts:
        if m.mode == "rw" and not is_under(m.path, root) and m.path not in writable:
            if policy.tmpdir and m.path == policy.tmpdir:
                continue
            writable.append(m.path)
    lines = [
        f"You are running inside an xsb sandbox ({policy.backend}). Permission prompts are "
        "turned off because the sandbox is the security boundary.",
        "",
        f"- Files: the project root, {root}, is read-write."
        + (" Also writable: " + ", ".join(writable) + "." if writable else "")
        + " Every other path you can see is read-only, and host paths that aren't "
        "configured for the sandbox are absent. Scratch space: /tmp"
        + (f" (TMPDIR={policy.tmpdir})" if policy.tmpdir else "") + ".",
        f"- Protected paths are read-only on purpose, even inside the root: "
        f"{_protected_summary(policy)}. Do not try to work around that.",
    ]
    if policy.network == "enforced":
        lines.append(
            "- Network: all HTTP(S) traffic goes through an allowlisting proxy (HTTPS_PROXY "
            "is set), and it is the only way out of the sandbox. A request to a domain that "
            "is not on the allowlist fails with a 403 or \"CONNECT tunnel failed\", or a "
            f"response body starting `{BLOCK_MESSAGE}`. When that happens, stop and tell the "
            "user the exact domain and why you need it. The user approves it with "
            "`xsb net-allow <domain>`, and then you retry. Never route around a block: do "
            "not switch to a mirror or another domain, unset or change the proxy variables, "
            "or use raw sockets or other tools.")
    else:
        lines.append("- Network: open (no proxy) for this launch.")
    lines.append(
        f"- If you need a path that is not visible, ask the user to add a mount to "
        f"{os.path.join(root, 'xsb.toml')}.")
    return "\n".join(lines) + "\n"


def add_to_command(policy: Policy, text: str):
    """Insert the agent's system-prompt arguments after its no-prompt flags."""
    from .agents import AGENTS
    a = AGENTS[policy.agent]
    i = 1 + len(a.no_prompt_flags)
    policy.command[i:i] = a.prompt_args(text)
