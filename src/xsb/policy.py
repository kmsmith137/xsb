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
from .config import Config, is_under
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
    create: str = ""          # "dir" or "file": create it (if missing) before launching

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
            mounts.append(Mount(p, e.fields["mode"], f"[[mount]] {e.source}, created", create="dir"))
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
    xsb_home: str = ""                                # ~/.xsb (denied outright by Seatbelt)
    protect_globs: list = field(default_factory=list) # [protect] patterns, absolute (Seatbelt
                                                      # turns them into regexes, which also
                                                      # cover files that don't exist yet)

    @property
    def create_dirs(self) -> list[str]:
        return [m.source for m in self.mounts if m.create == "dir" and not os.path.exists(m.source)]

    @property
    def create_files(self) -> list[str]:
        return [m.source for m in self.mounts if m.create == "file" and not os.path.exists(m.source)]

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
            line = f"agent:    {name}: config dir {tilde(d)}"
            prog = self.programs.get(name)
            if prog:
                line += f", program {prog.real}"
                if prog.mount != prog.real:
                    line += f" (mounts {prog.mount})"
            lines.append(line)
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
    need_program: bool = True        # False for `xsb prompt`: a missing agent is fine


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
                 code_paths: list[str] | None = None, check_only: bool = False) -> Policy:
    """Resolve the config into a Policy, enforcing the invariants (plan §6).
    `check_only` (for `xsb status`) skips the backend details (image, devices)."""
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
        prog = resolve_program(a.command, ctx.environ.get("PATH"), a.package_marker,
                               writable=(root,))
        if prog.real is None:
            if req.verb == a.name and req.need_program:
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
        rules.append(Mount(tmpdir, "rw", "per-launch TMPDIR", create="dir"))
    # 2. The root.
    rules.append(Mount(root, "rw", "root"))
    # 3. The agents' config dirs.
    agent_dirs = {}
    for a in launched:
        d = cfg.agent_dir(a)
        agent_dirs[a.name] = d
        rules.append(Mount(d, "rw", f"{a.name} config dir ({a.config_key})",
                           create="" if os.path.isdir(d) else "dir"))
    # 4. Git: the shared stores read-write, their config and hooks read-only.
    protected = []
    repos = git_repos(cwd, root)
    gits = []
    for r in repos:
        if r.common_dir not in gits:
            gits.append(r.common_dir)
    rules += [Mount(g, "rw", "git common dir") for g in gits]
    table = MountTable(rules)
    for g in gits:
        for p, why, create in git_pins(g, repos):
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

    if ctx.os == "linux":
        rules += self_binds(rules)
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
        prog = programs.get(a.name)
        command = [prog.real if prog else a.command, *a.no_prompt_flags, *req.args]
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
                    proxy_port=env_port(env), xsb_home=ctx.xsb_home,
                    protect_globs=[exp.pattern(k, f"protect {toml_value(k)}")
                                   for k, (on, _) in cfg.merged.table("protect").items() if on])
    if ctx.os == "linux" and not check_only:
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

@dataclass
class GitRepo:
    common_dir: str          # the shared store (real path)
    toplevel: str            # the work tree's top (real path)
    dotgit_file: str | None  # <toplevel>/.git when it is a file (linked worktree, submodule)


def git_repos(cwd: str, root: str) -> list[GitRepo]:
    """The repos around cwd whose shared .git stores the sandbox needs: the repo
    containing cwd, each directory from cwd up to the root that has a .git, and
    each immediate subdirectory of cwd that has one.

    Everything inside the root is writable by the agent, including .git files
    and symlinks, so a store is only accepted when the agent couldn't have
    pointed xsb at it: it is inside the root; or its .git lies above the root
    (the root is inside its work tree); or the store itself registers this
    work tree as a linked worktree (its worktrees/*/gitdir names our .git file).
    """
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
    root_r = os.path.realpath(root)
    out, seen = [], set()
    for c in cands:
        repo = git_repo(c)
        if repo is None or (repo.common_dir, repo.toplevel) in seen:
            continue
        seen.add((repo.common_dir, repo.toplevel))
        if trusted_repo(repo, root_r):
            out.append(repo)
    return out


def git_repo(path: str) -> GitRepo | None:
    try:
        r = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel",
                            "--git-common-dir"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = r.stdout.strip().splitlines()
    if r.returncode != 0 or len(lines) != 2:
        return None                   # not a repo, or a bare one
    top, g = lines
    if not os.path.isabs(g):
        g = os.path.join(path, g)
    top, g = os.path.realpath(top), os.path.realpath(g)
    if not os.path.isdir(g):
        return None
    dotgit = os.path.join(top, ".git")
    return GitRepo(g, top, dotgit if os.path.isfile(dotgit) else None)


def trusted_repo(repo: GitRepo, root_r: str) -> bool:
    if is_under(repo.common_dir, root_r):
        return True
    if is_under(root_r, repo.toplevel):
        return True                   # .git above the root: not writable by the agent
    if repo.dotgit_file:
        for gd in glob.glob(os.path.join(glob.escape(repo.common_dir), "worktrees", "*", "gitdir")):
            try:
                target = open(gd).read().strip()
            except OSError:
                continue
            if os.path.realpath(target) == os.path.realpath(repo.dotgit_file):
                return True
    return False


def git_common_dirs(cwd: str, root: str) -> list[str]:
    out = []
    for r in git_repos(cwd, root):
        if r.common_dir not in out:
            out.append(r.common_dir)
    return out


def git_config_get(args: list[str]) -> str:
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def gitdirs_under(d: str) -> list[str]:
    """Git dirs nested under a store's modules/ (submodules, any name depth)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(d):
        if "HEAD" in filenames and "config" in filenames:
            out.append(dirpath)
            dirnames[:] = [n for n in dirnames if n == "modules"]   # nested submodules
    return sorted(out)


def git_pins(g: str, repos: list[GitRepo] = ()) -> list[tuple[str, str, str]]:
    """Files in and around a shared .git store that git on the host loads or
    runs, to pin read-only: (path, why, create), create being "", "dir" or "file"
    for a missing path that is created first so it can be pinned. The rest of
    the store stays writable so commits work.

    Beyond config and hooks/, this pins what could redirect git on the host to a
    config the agent wrote: every linked worktree's and submodule's .git file,
    and worktrees/*/commondir; submodules' config and hooks/ at any depth;
    config.worktree when extensions.worktreeConfig is on; and a core.hooksPath
    directory.
    """
    ge = glob.escape(g)
    pins = [(os.path.join(g, "config"), "git config", ""),
            (os.path.join(g, "hooks"), "git hooks",
             "" if os.path.exists(os.path.join(g, "hooks")) else "dir")]
    worktree_cfg = git_config_get(["config", "-f", os.path.join(g, "config"), "--type=bool",
                                   "--get", "extensions.worktreeConfig"]) == "true"
    if worktree_cfg:
        p = os.path.join(g, "config.worktree")
        pins.append((p, "git config.worktree", "" if os.path.exists(p) else "file"))
    for wt in sorted(glob.glob(os.path.join(ge, "worktrees", "*"))):
        cd = os.path.join(wt, "commondir")
        if os.path.isfile(cd):
            pins.append((cd, "git worktree commondir", ""))
        if worktree_cfg:
            p = os.path.join(wt, "config.worktree")
            pins.append((p, "git config.worktree", "" if os.path.exists(p) else "file"))
        try:
            dotgit = open(os.path.join(wt, "gitdir")).read().strip()
        except OSError:
            dotgit = ""
        if dotgit and os.path.isfile(dotgit) and not os.path.islink(dotgit):
            pins.append((os.path.realpath(dotgit), "git worktree .git file", ""))
    for m in gitdirs_under(os.path.join(g, "modules")):
        pins.append((os.path.join(m, "config"), "git submodule config", ""))
        pins.append((os.path.join(m, "hooks"), "git submodule hooks",
                     "" if os.path.exists(os.path.join(m, "hooks")) else "dir"))
        wt = git_config_get(["config", "-f", os.path.join(m, "config"), "--get", "core.worktree"])
        if wt:
            dotgit = os.path.join(os.path.normpath(os.path.join(m, wt)), ".git")
            if os.path.isfile(dotgit) and not os.path.islink(dotgit):
                pins.append((os.path.realpath(dotgit), "git submodule .git file", ""))
    for r in repos:
        if r.common_dir != g:
            continue
        if r.dotgit_file and not os.path.islink(os.path.join(r.toplevel, ".git")):
            pins.append((r.dotgit_file, "git .git file", ""))
        hp = git_config_get(["-C", r.toplevel, "config", "--get", "core.hooksPath"])
        if hp:
            hp = os.path.expanduser(hp)
            hp = hp if os.path.isabs(hp) else os.path.join(r.toplevel, hp)
            pins.append((os.path.normpath(hp), "git core.hooksPath",
                         "" if os.path.exists(hp) else "dir"))
    seen, out = set(), []
    for p, why, create in pins:
        if p not in seen and (create or os.path.exists(p)):
            seen.add(p)
            out.append((p, why, create))
    return out


def self_binds(mounts: list[Mount]) -> list[Mount]:
    """Bind each directory between a mount and its nearest writable parent
    mount onto itself (Linux).

    rename(2) refuses to move a mount point (EBUSY), but a directory that
    merely *contains* one can be renamed, and the mount moves with it: the
    agent could `mv .claude .x; mkdir .claude` and write a fresh
    settings.json where the pinned one used to be. Once every directory in
    between is a mount point, none of them can be renamed or removed.
    """
    table = MountTable(mounts)
    have = {m.path for m in table.mounts}
    extra = []
    for m in table.mounts:
        parent = os.path.dirname(m.path)
        c = table.covering(parent) if parent != m.path else None
        if c is None or c.mode != "rw" or c.path == m.path:
            continue
        d = parent
        while d != c.path and is_under(d, c.path) and d not in have:
            rel = os.path.relpath(d, c.path)
            src = None if not c.src else os.path.join(c.src, rel)
            extra.append(Mount(d, "rw", f"keeps {m.path} in place (a parent rename can't move it)",
                               src=src, create="dir"))
            have.add(d)
            d = os.path.dirname(d)
    return extra


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
