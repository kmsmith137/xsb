"""Agent profiles (plan §8): one row per program xsb can launch.

`xsb claude` and `xsb codex` are the same launcher reading different rows.
Adding an agent means adding a row here.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Agent:
    name: str
    command: str                     # looked up on the launching shell's PATH
    dir_env: str                     # env var naming the agent's config dir
    config_key: str                  # config key for that dir (default ~/.xsb/<name>)
    no_prompt_flags: tuple = ()      # turn off the agent's own permission prompts
    env: tuple = ()                  # (name, value, os or None): extra env for this agent
    domains: tuple = ()              # always allowed by the proxy
    prompt_style: str = ""           # how the system-prompt text is passed (see prompt_args)
    login_hint: str = ""             # how to log in, for messages
    package_marker: str = ""         # file marking a release dir that holds the program's helpers

    def env_for(self, os_: str) -> dict:
        return {k: v for k, v, only in self.env if only in (None, os_)}

    def prompt_args(self, text: str) -> list[str]:
        """Arguments that append xsb's system-prompt text (plan §9)."""
        if self.prompt_style == "claude":
            return ["--append-system-prompt", text]
        if self.prompt_style == "codex":
            # `-c key=value` parses the value as TOML; pass a TOML string.
            from .tomlw import toml_value
            return ["-c", "developer_instructions=" + toml_value(text)]
        return []


AGENTS: dict[str, Agent] = {
    "claude": Agent(
        name="claude",
        command="claude",
        dir_env="CLAUDE_CONFIG_DIR",
        config_key="claude_dir",
        no_prompt_flags=("--dangerously-skip-permissions",),
        env=(
            # Container uid 0 is the host user (single-id user namespace); this
            # undocumented variable lets claude accept
            # --dangerously-skip-permissions as uid 0. Re-check after upgrades.
            ("IS_SANDBOX", "1", "linux"),
            # The program is mounted read-only; update it outside the sandbox.
            ("DISABLE_AUTOUPDATER", "1", None),
        ),
        domains=("anthropic.com", "claude.com", "claude.ai"),
        prompt_style="claude",
        login_hint="run /login inside `xsb claude`",
    ),
    "codex": Agent(
        name="codex",
        command="codex",
        dir_env="CODEX_HOME",
        config_key="codex_dir",
        # Disables both approvals and Codex's own sandbox: Seatbelt can't be
        # nested, and on Linux it would conflict with the container.
        no_prompt_flags=("--dangerously-bypass-approvals-and-sandbox",),
        domains=("openai.com", "chatgpt.com"),
        prompt_style="codex",
        login_hint="sign in outside the sandbox: CODEX_HOME=<codex_dir> codex login --device-auth",
        # Codex installs as a release dir: bin/codex plus helpers (codex-path/rg,
        # codex-resources/...). The whole release dir is mounted, never ~/.codex
        # itself, which holds the user's personal login (auth.json).
        package_marker="codex-package.json",
    ),
}


def all_domains() -> list[str]:
    """Every agent's required domains (one proxy serves all sandboxes)."""
    out = []
    for a in AGENTS.values():
        for d in a.domains:
            if d not in out:
                out.append(d)
    return out


def reserved_env_names() -> set[str]:
    """Agent-related variable names that config may not forward or set."""
    names = set()
    for a in AGENTS.values():
        names.add(a.dir_env)
        names.update(k for k, _, _ in a.env)
    return names


# ---- locating the agent's program (plan §8) ----

EXEC_MAGIC = (
    b"\x7fELF",                                  # ELF
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",    # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",    # Mach-O 64-bit
    b"\xca\xfe\xba\xbe",                         # Mach-O universal
)


@dataclass
class Program:
    """The agent's program, resolved on the host."""
    found: str | None = None         # what PATH lookup found (maybe a symlink)
    real: str | None = None          # the real file, run by absolute path
    mount: str | None = None         # what is mounted read-only: `real`, or its release dir
    problem: str = ""                # why it isn't a single self-contained executable

    @property
    def ok(self) -> bool:
        return self.real is not None and not self.problem


def resolve_program(command: str, path_env: str | None, package_marker: str = "") -> Program:
    found = shutil.which(command, path=path_env)
    if not found:
        return Program(problem=f"`{command}` not found on PATH")
    real = os.path.realpath(found)
    prog = Program(found=found, real=real, mount=real)
    if package_marker:
        d = os.path.dirname(real)
        for _ in range(2):                          # bin/<program> -> the release dir
            if os.path.isfile(os.path.join(d, package_marker)):
                prog.mount = d
                break
            d = os.path.dirname(d)
    try:
        with open(real, "rb") as f:
            head = f.read(4)
    except OSError as e:
        prog.problem = f"cannot read {real}: {e.strerror}"
        return prog
    if head[:2] == b"#!":
        prog.problem = (f"{real} is a script, not a self-contained executable; "
                        "its interpreter and libraries need mounts of their own")
    elif head not in EXEC_MAGIC:
        prog.problem = f"{real} is not an ELF or Mach-O executable"
    return prog
