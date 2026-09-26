"""Command-line interface: flat verbs (plan §4)."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, agents
from .config import (ConfigError, find_configs, format_effective, defaults_text,
                     is_under, load_config)
from .context import Context
from .policy import PolicyError
from .backends import BackendError
from .proxy import ProxyError

USAGE = """\
usage: xsb VERB [options] [args...]

Launch (options: --dry-run, --network {enforced,open}):
  xsb claude [args...]       Claude Code in the sandbox; args pass through
  xsb codex [args...]        Codex in the sandbox; args pass through
  xsb shell                  interactive bash in the same sandbox
  xsb run -- CMD [args...]   run a command in the sandbox

Setup and inspection:
  xsb init                   set up ~/.xsb if missing, then make this directory a project root
  xsb config [--defaults]    the merged config here, each value tagged with its source
                             (--defaults: the built-in defaults, as TOML)
  xsb status                 project, proxy and health checks (non-zero exit if a check fails)
  xsb prompt [AGENT]         the system-prompt text a launch here would add

Network:
  xsb net-allow DOMAIN...    allow domains (appends to ~/.xsb/net-allow.txt)
  xsb net-deny DOMAIN...     deny domains (appends to ~/.xsb/net-deny.txt)
  xsb net-log                show blocked and denied requests
  xsb net-stop               stop the proxy (the next launch restarts it)
"""


class UserError(Exception):
    """A problem to report in one line, without a traceback."""


def out(msg: str = ""):
    print(msg)


def err(msg: str):
    print(f"xsb: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------
# xsb init (plan §5.6)
# --------------------------------------------------------------------------

ALLOW_HEADER = """\
# Domains the sandboxed agents may reach over HTTP(S), one per line.
# An entry matches the domain and its subdomains ("example.com" covers
# www.example.com; "*.example.com" means the same). "#" starts a comment.
# Deny (net-deny.txt) wins over allow.
#
# xsb's proxy re-reads this file on every request, so a change applies at
# once, to every sandbox. `xsb net-allow DOMAIN` appends here. The agents'
# own required domains (e.g. anthropic.com for Claude) are built in and
# needn't be listed.
"""

DENY_HEADER = """\
# Domains the sandboxed agents may never reach, one per line (same syntax as
# net-allow.txt). Deny wins over allow, including over the agents' built-in
# domains. `xsb net-deny DOMAIN` appends here.
"""

USER_CONFIG_HEADER = """\
# User-level xsb config. Optional: every setting has a built-in default.
# Settings here apply to every project; a project's xsb.toml overrides them.
#
#   xsb config --defaults   # print the built-in defaults (copy blocks from here)
#   xsb config              # print the merged config for the current directory
"""

PROJECT_CONFIG_TEMPLATE = """\
# This file marks {root} as an xsb root: agents launched with
# `xsb claude` / `xsb codex` from here or below can write in this directory.
# Every setting is optional; with none, the built-in defaults apply.
#
#   xsb config --defaults   # all settings and their defaults (copy blocks from here)
#   xsb config              # the merged config for this directory
"""


def machine_findings(ctx: Context):
    """Detection checks for a new ~/.xsb/config.toml: built-in defaults only."""
    from .backends import get_backend
    from .detect import run_checks
    from .policy import Mount, MountTable, config_mounts
    cfg = load_config(ctx, require_root=False, builtin_only=True)
    mounts, _ = config_mounts(cfg)
    base = [Mount(p, "ro", "base") for p in get_backend(ctx.os).base_read_paths()]
    table = MountTable(base + mounts + [Mount(ctx.cwd, "rw", "root")])
    return run_checks(ctx, table, ctx.cwd)


def cmd_init(ctx: Context, args) -> int:
    created = []

    def note(path):
        created.append(ctx.tilde(path))

    # 1. ~/.xsb and its files; existing entries (including symlinks) are kept.
    if not os.path.lexists(ctx.xsb_home):
        os.mkdir(ctx.xsb_home, 0o700)
        os.chmod(ctx.xsb_home, 0o700)
        note(ctx.xsb_home + "/")
    elif not os.path.isdir(ctx.xsb_home):
        raise UserError(f"{ctx.xsb_home} exists but is not a directory")
    for a in agents.AGENTS.values():
        d = os.path.join(ctx.xsb_home, a.name)
        if not os.path.lexists(d):
            os.mkdir(d, 0o700)
            note(d + "/")
    for path, header in ((ctx.allow_list, ALLOW_HEADER), (ctx.deny_list, DENY_HEADER)):
        if not os.path.lexists(path):
            write_new(path, header)
            note(path)
    if not os.path.lexists(ctx.user_config):
        text = USER_CONFIG_HEADER
        findings = machine_findings(ctx)
        if findings:
            text += "#\n# Added by `xsb init` for this machine:\n"
            for f in findings:
                text += "\n" + f.toml(ctx)
        write_new(ctx.user_config, text)
        note(ctx.user_config)

    def report():
        if created:
            out("Created:")
            for c in created:
                out(f"  {c}")

    # 2. Inside ~/.xsb: only the machine setup.
    cwd_r, xsb_r = os.path.realpath(ctx.cwd), os.path.realpath(ctx.xsb_home)
    if is_under(cwd_r, xsb_r):
        report()
        out(f"{ctx.tilde(ctx.xsb_home)} is set up. Run `xsb init` in a project directory "
            "to make it a root.")
        return 0

    # 3. Refuse nested configs, and roots that would expose ~/.xsb.
    found = find_configs(ctx.cwd, ctx.home)
    if found or is_under(xsb_r, cwd_r):
        report()
        if found:
            raise UserError(f"{found[0]} already exists; not creating another "
                            "(nested xsb.toml files are refused at launch)")
        raise UserError(f"{ctx.cwd} contains {ctx.tilde(ctx.xsb_home)}; a project root here "
                        "would expose it to the sandbox")

    # 4. The project's xsb.toml, comments only.
    path = os.path.join(ctx.cwd, "xsb.toml")
    write_new(path, PROJECT_CONFIG_TEMPLATE.format(root=ctx.cwd))
    note(path)
    report()
    return 0


def write_new(path: str, text: str):
    with open(path, "x") as f:
        f.write(text)


# --------------------------------------------------------------------------
# xsb config
# --------------------------------------------------------------------------

def cmd_config(ctx: Context, args) -> int:
    if args.defaults:
        sys.stdout.write(defaults_text())
        return 0
    cfg = load_config(ctx, require_root=False)
    sys.stdout.write(format_effective(cfg))
    return 0


# --------------------------------------------------------------------------
# xsb status (plan §4.1)
# --------------------------------------------------------------------------

def cmd_status(ctx: Context, args) -> int:
    from . import status
    lines, checks = status.gather(ctx)
    for line in lines:
        out(line)
    out("Checks")
    for line in checks.render():
        out(line)
    return 1 if checks.failed else 0


# --------------------------------------------------------------------------
# Launch verbs: claude, codex, shell, run (plan §4)
# --------------------------------------------------------------------------

LAUNCH_VERBS = ("claude", "codex", "shell", "run")

LAUNCH_HELP = """\
usage: xsb {verb} [--dry-run] [--network {{enforced,open}}] {rest}

  --dry-run              print the resolved policy and the exact backend command;
                         launch nothing
  --network MODE         override the configured network mode for this launch
"""


def parse_launch(verb: str, rest: list[str]):
    """xsb's options come first; everything from the first other argument (or
    after `--`) belongs to the agent or command."""
    dry, network, i = False, None, 0
    while i < len(rest):
        a = rest[i]
        if a == "--dry-run":
            dry = True
        elif a == "--network" or a.startswith("--network="):
            if "=" in a:
                network = a.split("=", 1)[1]
            else:
                i += 1
                if i == len(rest):
                    raise UserError("--network needs a value: enforced or open")
                network = rest[i]
            if network not in ("enforced", "open"):
                raise UserError(f"--network must be enforced or open, not {network!r}")
        elif a in ("-h", "--help") and verb in ("shell", "run"):
            return None
        elif a == "--":
            i += 1
            break
        else:
            break
        i += 1
    return dry, network, rest[i:]


def cmd_launch(ctx: Context, verb: str, rest: list[str]) -> int:
    from . import proxy
    from .backends import get_backend
    from .policy import LaunchRequest, build_policy
    parsed = parse_launch(verb, rest)
    if parsed is None:
        tail = {"shell": "", "run": "-- CMD [args...]"}[verb]
        sys.stdout.write(LAUNCH_HELP.format(verb=verb, rest=tail))
        return 0
    dry, network, args = parsed
    if verb == "shell" and args:
        raise UserError("xsb shell takes no arguments; use `xsb run -- CMD [args...]`")
    if not os.path.isdir(ctx.xsb_home):
        raise UserError(f"{ctx.tilde(ctx.xsb_home)} does not exist; run `xsb init`")
    cfg = load_config(ctx)
    backend = get_backend(ctx.os)
    enforced = (network or cfg.network_mode) == "enforced"
    port = None
    if enforced and ctx.os == "macos":
        # The sandbox reaches the proxy's TCP port directly, so it must be known first.
        if not dry:
            proxy.ensure_running(ctx)
        port = proxy.running_port(ctx)
    req = LaunchRequest(verb=verb, args=args, network=network, tty=sys.stdin.isatty(),
                        proxy_port=port)
    policy = build_policy(cfg, req, backend.name)
    if enforced and not dry and ctx.os != "macos":
        proxy.ensure_running(ctx)
    if policy.agent:
        from . import prompt
        prompt.add_to_command(policy, prompt.generate(policy))
    spec = backend.command(policy)
    if dry:
        out("# Resolved policy")
        out(policy.describe(ctx.tilde))
        out("")
        if spec.description:
            out(spec.description)
            out("")
        out(f"# Backend command ({backend.name})")
        from .backends.podman import format_argv
        out(format_argv(spec.argv, spec.image))
        return 0
    agent_dirs = {os.path.realpath(d) for d in policy.agent_dirs.values()}
    for d in policy.create_dirs:
        os.makedirs(d, exist_ok=True)
        if os.path.realpath(d) in agent_dirs:
            os.chmod(d, 0o700)
    for f in policy.create_files:
        open(f, "a").close()
    return backend.launch(spec)


# --------------------------------------------------------------------------
# xsb prompt (plan §9)
# --------------------------------------------------------------------------

def cmd_prompt(ctx: Context, args) -> int:
    from . import prompt
    from .backends import backend_name
    from .policy import LaunchRequest, build_policy
    cfg = load_config(ctx)
    policy = build_policy(cfg, LaunchRequest(verb=args.agent, need_program=False),
                          backend_name(ctx.os), check_only=True)
    sys.stdout.write(prompt.generate(policy))
    return 0


# --------------------------------------------------------------------------
# net-* verbs (plan §7.1)
# --------------------------------------------------------------------------

def cmd_net_allow(ctx: Context, args) -> int:
    from . import proxy
    for m in proxy.add_to_list(ctx, "allow", args.domains, ALLOW_HEADER):
        out(m)
    return 0


def cmd_net_deny(ctx: Context, args) -> int:
    from . import proxy
    for m in proxy.add_to_list(ctx, "deny", args.domains, DENY_HEADER):
        out(m)
    return 0


def cmd_net_log(ctx: Context, args) -> int:
    from . import proxy
    lines = proxy.log_lines(ctx)
    if lines is None:
        out("no proxy log yet")
    elif not lines:
        out("nothing blocked or denied yet")
    for line in lines or []:
        out(line)
    return 0


def cmd_net_stop(ctx: Context, args) -> int:
    from . import proxy
    pid = proxy.stop(ctx)
    out(f"stopped the proxy (pid {pid}); the next launch starts it again" if pid
        else "the proxy is not running")
    return 0


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

def build_parsers() -> dict:
    p = {}
    ap = argparse.ArgumentParser(prog="xsb init", description="Set up ~/.xsb if it's missing, "
                                 "then create a comments-only xsb.toml here.")
    p["init"] = (ap, cmd_init)
    ap = argparse.ArgumentParser(prog="xsb config", description="Print the merged config "
                                 "for the current directory, each value tagged with its source.")
    ap.add_argument("-d", "--defaults", action="store_true",
                    help="print the built-in defaults as TOML")
    p["config"] = (ap, cmd_config)
    ap = argparse.ArgumentParser(prog="xsb status", description="Project, proxy and health "
                                 "checks; exits non-zero if any check fails.")
    p["status"] = (ap, cmd_status)
    ap = argparse.ArgumentParser(prog="xsb prompt", description="Print the system-prompt text "
                                 "a launch here would add for the agent.")
    ap.add_argument("agent", nargs="?", default="claude", choices=sorted(agents.AGENTS))
    p["prompt"] = (ap, cmd_prompt)
    for verb, fn, which in (("net-allow", cmd_net_allow, "allow"), ("net-deny", cmd_net_deny, "deny")):
        ap = argparse.ArgumentParser(prog=f"xsb {verb}", description=f"Append domains to "
                                     f"~/.xsb/net-{which}.txt (through a symlink, if it is one).")
        ap.add_argument("domains", nargs="+", metavar="DOMAIN")
        p[verb] = (ap, fn)
    p["net-log"] = (argparse.ArgumentParser(prog="xsb net-log",
                                            description="Show blocked and denied requests."),
                    cmd_net_log)
    p["net-stop"] = (argparse.ArgumentParser(prog="xsb net-stop", description="Stop the proxy "
                                             "(the next launch restarts it)."), cmd_net_stop)
    return p


def main(argv: list[str] | None = None, ctx: Context | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return 0 if argv else 2
    if argv[0] == "--version":
        out(f"xsb {__version__}")
        return 0
    verb, rest = argv[0], argv[1:]
    if verb in LAUNCH_VERBS:
        try:
            ctx = ctx or Context.from_process()
            return cmd_launch(ctx, verb, rest)
        except (UserError, ConfigError, PolicyError, ProxyError, BackendError) as e:
            err(str(e))
            return 1
    parsers = build_parsers()
    if verb not in parsers:
        err(f"unknown verb '{verb}' (see `xsb --help`)")
        return 2
    ap, handler = parsers[verb]
    args = ap.parse_args(rest)
    try:
        ctx = ctx or Context.from_process()
        return handler(ctx, args)
    except (UserError, ConfigError, PolicyError, ProxyError, BackendError) as e:
        err(str(e))
        return 1
