"""The Policy: the fully resolved, OS-neutral description of one launch.

Built from the merged config (config.py) and consumed by a backend. This
module also enforces the security invariants (plan §6.1).
"""

from __future__ import annotations

import glob
import os
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass, field

from . import agents
from .agents import Program, resolve_program
from .config import Config, ConfigError, is_under
from .tomlw import toml_value

LINUX_PROXY_PORT = 3128                  # the in-sandbox relay's port (Linux, enforced)
NO_PROXY = "localhost,127.0.0.1,::1"
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"


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
    return glob.has_magic(p)


# --------------------------------------------------------------------------
# The Policy
# --------------------------------------------------------------------------

@dataclass
class Policy:
    os: str                   # "linux" | "macos"
    backend: str              # "podman" | "seatbelt"
    verb: str                 # "claude" | "codex" | "shell" | "run"
    root: str
    cwd: str
    command: list             # argv run inside the sandbox
    env: dict                 # the sandbox's whole environment
    mounts: list              # ordered: by depth, then rule order (plan §6.2)
    network: str = "enforced"
    devices: list = field(default_factory=list)
    image: str = ""
    extra_args: list = field(default_factory=list)
    tty: bool = False
    runtime_dir: str = ""
    agent: str | None = None                          # the launched agent, if any
    agent_dirs: dict = field(default_factory=dict)    # agent name -> config dir
    programs: dict = field(default_factory=dict)      # agent name -> Program
    protected: list = field(default_factory=list)     # (sandbox path, why) pinned read-only
    skipped: list = field(default_factory=list)       # configured paths missing here
    resolv_extra: list = field(default_factory=list)  # host resolv.conf search/options lines
    tmpdir: str | None = None                         # macOS: per-launch TMPDIR
    proxy_port: int | None = None                     # the port HTTP(S)_PROXY points at

    @property
    def create_dirs(self) -> list[str]:
        return [m.source for m in self.mounts if m.create and not os.path.exists(m.source)]

    def table(self) -> MountTable:
        return MountTable(self.mounts)

    def writable_paths(self) -> list[str]:
        return [m.path for m in self.mounts if m.mode == "rw"]

    def describe(self, tilde=lambda p: p) -> str:
        lines = [f"root:     {self.root}", f"cwd:      {self.cwd}",
                 f"backend:  {self.backend}", f"network:  {self.network}"]
        if self.image:
            lines.append(f"image:    {self.image}")
        for name, d in self.agent_dirs.items():
            prog = self.programs.get(name)
            p = f", program {prog.real}" + (f" (mounts {prog.mount})" if prog and prog.mount != prog.real else "") \
                if prog else ""
            lines.append(f"agent:    {name}: config dir {tilde(d)}{p}")
        lines.append("mounts, in order (deeper paths win; later ones win for the same path):")
        for m in self.mounts:
            src = f" (from {m.src})" if m.src else ""
            new = " (created)" if m.create and not os.path.exists(m.source) else ""
            lines.append(f"  {m.mode}  {m.path}{src}{new}    # {m.why}")
        if self.skipped:
            lines.append("skipped (missing on this machine): " + " ".join(tilde(p) for p in self.skipped))
        if self.devices:
            lines.append("devices:  " + " ".join(self.devices))
        lines.append("env:")
        for k, v in self.env.items():
            lines.append(f"  {k}={v}")
        lines.append("command:  " + shlex.join(self.command))
        return "\n".join(lines)


@dataclass
class LaunchRequest:
    verb: str                        # "claude" | "codex" | "shell" | "run"
    args: list = field(default_factory=list)   # agent args, or the command for `run`
    network: str | None = None       # --network override
    tty: bool = False
    proxy_port: int | None = None    # macOS: the running proxy's TCP port


def launched_agents(verb: str) -> list[agents.Agent]:
    """The agents whose config dirs a launch mounts: the launched agent, or all
    of them for `xsb shell` / `xsb run` (so agents run there by hand work)."""
    if verb in agents.AGENTS:
        return [agents.AGENTS[verb]]
    return list(agents.AGENTS.values())


def xsb_code_paths() -> list[str]:
    """xsb's own code, which no sandbox may write (I4)."""
    import xsb
    out = []
    for p in (os.path.dirname(os.path.abspath(xsb.__file__)), sys.prefix, sys.base_prefix):
        r = os.path.realpath(p)
        if r not in out:
            out.append(r)
    return out


def build_policy(cfg: Config, req: LaunchRequest, backend: str,
                 code_paths: list[str] | None = None) -> Policy:
    """Resolve the config into a Policy, enforcing the invariants (plan §6)."""
    ctx, exp = cfg.ctx, cfg.expander
    if cfg.root is None:
        raise PolicyError("not in a project (no xsb.toml here or above); run `xsb init`")
    root, cwd = cfg.root, ctx.cwd
    network = req.network or cfg.network_mode
    if network not in ("enforced", "open"):
        raise PolicyError(f"unknown network mode {network!r}")

    check_refuse(cfg)
    require = cfg.merged.get("env", "require") or []
    missing = [n for n in require if n not in ctx.environ]
    if missing:
        raise PolicyError(f"env.require: {', '.join(missing)} not set in this shell "
                          f"(required by {cfg.merged.source('env', 'require')})")

    # Agents: programs and config dirs.
    launched = launched_agents(req.verb)
    programs: dict[str, Program] = {}
    for a in launched:
        prog = resolve_program(a.command, ctx.environ.get("PATH"), a.package_marker)
        if prog.real is None:
            if req.verb == a.name:
                raise PolicyError(f"`{a.command}` not found on PATH; install it first")
            continue
        programs[a.name] = prog

    rules: list[Mount] = []
    # 1. Built-in and config mounts, and the agents' programs.
    cm, skipped = config_mounts(cfg)
    rules += cm
    for name, prog in programs.items():
        rules.append(Mount(prog.mount, "ro", f"{name} program"))
    tmpdir = None
    if ctx.os == "macos":
        tmpdir = os.path.join(ctx.runtime_dir, "tmp", str(os.getpid()))
        rules.append(Mount(tmpdir, "rw", "per-launch TMPDIR", create=True))
    # 2. The root.
    rules.append(Mount(root, "rw", "root"))
    # 3. The agents' config dirs.
    agent_dirs = {}
    for a in launched:
        d = cfg.agent_dir(a)
        agent_dirs[a.name] = d
        rules.append(Mount(d, "rw", f"{a.name} config dir ({a.config_key})",
                           create=not os.path.isdir(d)))
    # 4. Git: the shared stores read-write, their config and hooks read-only.
    protected = []
    gits = git_common_dirs(cwd, root)
    rules += [Mount(g, "rw", "git common dir") for g in gits]
    table = MountTable(rules)
    for g in gits:
        for p, why, create in git_pins(g):
            for sp, real in pin_points(table, p):
                rules.append(Mount(sp, "ro", why, src=None if sp == real else real, create=create))
                protected.append((sp, why))
    # 5. Protected paths.
    table = MountTable(rules)
    for key, (on, _src) in cfg.merged.table("protect").items():
        if not on:
            continue
        for host in exp.glob(key, f"protect {toml_value(key)}"):
            for sp, real in pin_points(table, host):
                rules.append(Mount(sp, "ro", f"protected: {key}", src=None if sp == real else real))
                protected.append((sp, f"protected: {key}"))
    # 6. xsb's own config and the network lists (I1), at their real paths.
    table = MountTable(rules)
    for f in xsb_config_files(cfg):
        for sp, real in pin_points(table, f):
            rules.append(Mount(sp, "ro", "xsb config (read-only, I1)",
                               src=None if sp == real else real))
            protected.append((sp, "xsb config"))

    table = MountTable(rules)
    check_invariants(cfg, table, agent_dirs, code_paths)
    for m in table.mounts:
        for p in (m.path, m.source):
            if ":" in p:
                raise PolicyError(f"cannot mount a path containing ':': {p}")

    # Environment (plan §6.4).
    env = build_env(cfg, launched, agent_dirs, network, backend, tmpdir, req.proxy_port)

    # Command.
    if req.verb in agents.AGENTS:
        a = agents.AGENTS[req.verb]
        command = [programs[a.name].real, *a.no_prompt_flags, *req.args]
    elif req.verb == "shell":
        command = ["bash"]
    elif req.verb == "run":
        if not req.args:
            raise PolicyError("xsb run needs a command: xsb run -- CMD [args...]")
        command = list(req.args)
    else:
        raise PolicyError(f"unknown launch verb {req.verb!r}")

    policy = Policy(os=ctx.os, backend=backend, verb=req.verb, root=root, cwd=cwd,
                    command=command, env=env, mounts=table.mounts, network=network,
                    tty=req.tty, runtime_dir=ctx.runtime_dir,
                    agent=req.verb if req.verb in agents.AGENTS else None,
                    agent_dirs=agent_dirs, programs=programs, protected=protected,
                    skipped=skipped, tmpdir=tmpdir,
                    proxy_port=env_port(env))
    if ctx.os == "linux":
        for p in ("/usr", "/etc"):
            if not os.path.isdir(p):
                raise PolicyError(f"{p} does not exist on this host; the Linux backend needs it")
        policy.devices = linux_devices(cfg)
        policy.image = linux_image(cfg)
        policy.extra_args = list(cfg.merged.get("linux", "extra_args") or [])
        if network == "enforced":
            policy.resolv_extra = host_resolv_extra()
    return policy


def env_port(env: dict) -> int | None:
    url = env.get("HTTPS_PROXY", "")
    tail = url.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else None


def check_refuse(cfg: Config):
    cwd_r = os.path.realpath(cfg.ctx.cwd)
    for e in cfg.merged.active("refuse"):
        d = cfg.expander.path(e.fields["dir"], f"refuse dir {toml_value(e.fields['dir'])}")
        if is_under(cwd_r, os.path.realpath(d)):
            why = e.fields.get("reason") or "it is listed in `refuse`"
            raise PolicyError(f"refusing to launch in {d}: {why}")


def pin_points(table: MountTable, host_path: str) -> list[tuple[str, str]]:
    """Where to pin host_path read-only: each sandbox path at which it is
    visible and writable. Invisible paths are never mounted (that would expose
    them), and read-only ones need nothing."""
    real = os.path.realpath(host_path)
    return [(sp, real) for sp in table.sandbox_paths(real) if table.covering(sp).mode == "rw"]


def xsb_config_files(cfg: Config) -> list[str]:
    ctx = cfg.ctx
    files = list(cfg.files_read)
    for p in (ctx.allow_list, ctx.deny_list):
        if os.path.exists(p):
            files.append(os.path.realpath(p))
    return files


# ---- git (plan §6.2 step 4) ----

def git_common_dirs(cwd: str, root: str) -> list[str]:
    """Shared .git stores of the repos around cwd: the repo containing cwd, each
    directory from cwd up to the root that has a .git, and each immediate
    subdirectory of cwd that has one."""
    cands = [cwd]
    d = cwd
    while d != root and d != "/":
        d = os.path.dirname(d)
        if os.path.lexists(os.path.join(d, ".git")):
            cands.append(d)
    try:
        names = sorted(os.listdir(cwd))
    except OSError:
        names = []
    for n in names:
        p = os.path.join(cwd, n)
        if os.path.isdir(p) and os.path.lexists(os.path.join(p, ".git")):
            cands.append(p)
    out = []
    for c in cands:
        g = git_common_dir(c)
        if g and g not in out:
            out.append(g)
    return out


def git_common_dir(path: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", path, "rev-parse", "--git-common-dir"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    g = r.stdout.strip()
    if not os.path.isabs(g):
        g = os.path.join(path, g)
    g = os.path.realpath(g)
    return g if os.path.isdir(g) else None


def git_pins(g: str) -> list[tuple[str, str, bool]]:
    """Files in a shared .git store that git on the host loads or runs, pinned
    read-only: (path, why, create). The rest of the store stays writable so
    commits work.

    Beyond config and hooks/ (a missing hooks/ is created, so no hook can be
    planted in it), this pins the pointers that could redirect git on the host
    to a config the agent wrote: each linked worktree's .git file and
    worktrees/*/commondir. Submodules' config and hooks/ are pinned too.
    """
    pins = [(os.path.join(g, "config"), "git config", False),
            (os.path.join(g, "hooks"), "git hooks", not os.path.exists(os.path.join(g, "hooks")))]
    for wt in sorted(glob.glob(os.path.join(g, "worktrees", "*"))):
        cd = os.path.join(wt, "commondir")
        if os.path.isfile(cd):
            pins.append((cd, "git worktree commondir", False))
        try:
            dotgit = open(os.path.join(wt, "gitdir")).read().strip()
        except OSError:
            dotgit = ""
        if dotgit and os.path.isfile(dotgit) and not os.path.islink(dotgit):
            pins.append((os.path.realpath(dotgit), "git worktree .git file", False))
    for sub in sorted(glob.glob(os.path.join(g, "modules", "*"))):
        for name, why in (("config", "git submodule config"), ("hooks", "git submodule hooks")):
            p = os.path.join(sub, name)
            if os.path.exists(p):
                pins.append((p, why, False))
    return [(p, why, create) for p, why, create in pins if create or os.path.exists(p)]


# ---- invariants (plan §6.1) ----

def check_invariants(cfg: Config, table: MountTable, agent_dirs: dict,
                     code_paths: list[str] | None):
    ctx = cfg.ctx
    # I1: config files and lists are read-only wherever they are visible.
    for f in xsb_config_files(cfg):
        if table.writable(f):
            raise PolicyError(f"{f} would be writable in the sandbox (I1)")
    # I3: ~/.xsb is invisible, except for the agent dirs this launch mounts.
    xr = os.path.realpath(ctx.xsb_home)
    allowed = [os.path.realpath(d) for d in agent_dirs.values()]
    for m in table.mounts:
        src = os.path.realpath(m.source)
        if is_under(xr, src):
            raise PolicyError(f"mounting {m.path} ({m.why}) would expose {ctx.tilde(ctx.xsb_home)} "
                              "to the sandbox (I3); mount something narrower")
        if is_under(src, xr) and not any(is_under(src, a) for a in allowed):
            raise PolicyError(f"mounting {m.path} ({m.why}) would expose part of "
                              f"{ctx.tilde(ctx.xsb_home)} to the sandbox (I3)")
    # I4: xsb's own code is not writable.
    for p in (xsb_code_paths() if code_paths is None else code_paths):
        if table.writable(p):
            raise PolicyError(
                f"xsb's own code ({p}) would be writable in this sandbox (I4), so an agent "
                "could change the launcher you run on the host. Use a clone or install "
                "outside this project's root (e.g. `pipx install`), or protect it.")
    # I5: the proxy's runtime dir is invisible.
    if table.visible(ctx.runtime_dir):
        raise PolicyError(f"the proxy's runtime dir {ctx.runtime_dir} would be visible in the "
                          "sandbox (I5)")


# ---- environment (plan §6.4) ----

def build_env(cfg: Config, launched, agent_dirs: dict, network: str, backend: str,
              tmpdir: str | None, proxy_port: int | None) -> dict:
    ctx, m, exp = cfg.ctx, cfg.merged, cfg.expander
    env = {}
    names = [k for k, (v, _) in m.table("env", "forward").items() if v]
    names += [n for n in (m.get("env", "require") or []) if n not in names]
    for n in names:
        if n in ctx.environ:
            env[n] = ctx.environ[n]
    for k, (v, src) in m.table("env", "set").items():
        env[k] = exp.expand(v, f"env.set {k} ({src})")
    # Reserved: set by xsb, never by config.
    env["HOME"] = ctx.home
    env["USER"] = ctx.user
    env["PATH"] = ctx.environ.get("PATH") or DEFAULT_PATH
    if tmpdir:
        env["TMPDIR"] = tmpdir
    env["XDG_CACHE_HOME"] = os.path.join(tmpdir, "cache") if tmpdir else "/tmp/cache"
    for a in launched:
        env[a.dir_env] = agent_dirs[a.name]
        env.update(a.env_for(ctx.os))
    if network == "enforced":
        port = LINUX_PROXY_PORT if ctx.os == "linux" else proxy_port
        url = f"http://127.0.0.1:{port if port else 'PORT'}"
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            env[k] = url
        env["NO_PROXY"] = env["no_proxy"] = NO_PROXY
    env["XSB_ROOT"] = cfg.root
    env["XSB_BACKEND"] = backend
    env["XSB_NETWORK"] = network
    return env


# ---- Linux specifics ----

def linux_devices(cfg: Config) -> list[str]:
    out = []
    for e in cfg.merged.active("device"):
        for p in cfg.expander.glob(e.fields["glob"], f"device {toml_value(e.fields['glob'])}"):
            try:
                if stat.S_ISCHR(os.stat(p).st_mode) and p not in out:
                    out.append(p)
            except OSError:
                pass
    return out


def linux_image(cfg: Config, os_release: str = "/etc/os-release") -> str:
    image = cfg.merged.get("linux", "image")
    if image != "auto":
        return image
    info = {}
    try:
        with open(os_release) as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep:
                    info[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    if not info.get("ID") or not info.get("VERSION_ID"):
        raise PolicyError(f"cannot pick a base image from {os_release}; set linux.image "
                          "(e.g. \"docker.io/library/ubuntu:24.04\")")
    return f"docker.io/library/{info['ID']}:{info['VERSION_ID']}"


def host_resolv_extra(resolv_conf: str = "/etc/resolv.conf") -> list[str]:
    """The host's search and options lines, so short names resolve as on the host."""
    out = []
    try:
        with open(resolv_conf) as f:
            for line in f:
                if line.split()[:1] and line.split()[0] in ("search", "domain", "options"):
                    out.append(line.strip())
    except OSError:
        pass
    return out
