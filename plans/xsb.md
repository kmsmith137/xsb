# Plan: `xsb`, a standalone sandbox launcher for coding agents

Handoff plan for an implementation agent with no prior context. It describes a
new Python package, `xsb`, that replaces the `sbox-*` scripts in the `ch_top`
repo and can be used by any project, not just ch_top.

The last section lists the design decisions already made, things to check
during implementation, and deferred work. Read it before starting.

**Getting started.**

- **The repo** is `~/git/xsb`, a standalone git repo (no commits yet); this plan
  is `plans/xsb.md` in it. Build the package there.
- **Run unsandboxed.** The integration tests need podman, which can't run inside
  an `sbox-claude` sandbox.
- **Python:** the conda `dev` env (`~/miniforge3/envs/dev`, Python 3.13) has
  pytest. Don't install software yourself; ask the user if something is
  missing.
- **Start with phase 0** (§12), a throwaway prototype of the riskiest part. If it
  contradicts §7, stop and report rather than redesigning.
- **Commits:** this is a large task, so commit checkpoints as you go: at least
  one per completed phase, with its tests passing, and the message naming the
  phase. The first commit can include this plan. Don't commit phase 0's
  throwaway prototype code, and never push.
- **At the end,** write `plans/xsb_report.md`: what was built, what was verified
  (and what couldn't be, e.g. macOS), and any departures from this plan, with
  reasons.

## 1. Goal

Run coding agents (Claude Code, Codex) with all permission prompts turned off,
inside an OS-level sandbox that is the real security boundary. The sandbox:

- shows the agent only an allowlist of host paths (everything else is absent);
- lets it write only inside one project directory (the **root**), plus a few
  explicitly listed paths;
- protects files that the host later runs or loads *outside* the sandbox
  (git hooks, Claude settings) even when they sit inside the root;
- sends all network traffic through a domain-allowlisting proxy, and on the
  default setting makes that the *only* way out;
- keeps the agent's login and transcripts in a dedicated config dir, separate
  from the user's personal `~/.claude`.

The main threat is **prompt injection**: an agent that reads hostile text and
then tries to act on it. It should not be able to read secrets, widen its own
sandbox, plant code that the user later runs unsandboxed, or send data to
arbitrary hosts.

Platforms: Linux (rootless Podman) and macOS (Seatbelt / `sandbox-exec`).
Windows is out of scope.

## 2. Background: what exists today

In `ch_top` (the container repo at `~/ch/top`), at the time of writing:

| File | Role |
|---|---|
| `sbox-common.sh` | sourced by the launchers; locates the worktree and the policy, starts the proxy, builds the `podman run` argument list |
| `sbox-claude` | runs `claude --dangerously-skip-permissions` in the container |
| `sbox-shell` | same container, interactive `bash` instead |
| `sbox-net` | Python egress proxy + CLI (`start/stop/status/url/log/allow/deny/proxy`) |
| `sandbox/fs-allow.txt` | `ro`/`rw <path>` allowlist |
| `sandbox/devices.txt` | device globs (default `/dev/nvidia*`) |
| `sandbox/env-allow.txt` | env var names forwarded from the launching shell |
| `sandbox/net-allow.txt`, `net-deny.txt` | domain lists for the proxy |

`README.md` in ch_top ("Sandbox and GPU", "Egress proxy", Appendices C to F)
explains the rationale. Read `sbox-common.sh` and `sbox-net` in full before
starting. Most of their logic carries over, and their comments record hard-won
details.

### 2.1 Behaviors to preserve (with reasons)

- **`podman run --init`**: catatonit as PID 1 reaps orphaned children. Without
  it, zombies accumulated to 95% of the cgroup's 2048-PID limit over a 20-hour
  agent session and killed subagents.
- **`--rm`, `--tmpfs /tmp`, `--tmpfs /run`**: throwaway container; private `/tmp`
  and `/run`, which also hides host sockets (ssh-agent, tmux) that live there.
- **Same-path mounts**: every host path is mounted at the same path in the
  container, so paths in logs, configs and error messages mean the same thing
  inside and outside.
- **Host `/usr` and `/etc` mounted read-only over a base image** matching the host
  distro, so the host toolchain runs unchanged. The image only supplies the
  directory skeleton.
- **`--group-add keep-groups`**: meant to keep the user's supplementary group
  reads. It only works with podman's `crun` runtime; with `runc` it is silently
  ignored (see §14.2).
- **Single-id user namespace**: container uid 0 is the host user. This needs
  `IS_SANDBOX=1` so `claude` accepts `--dangerously-skip-permissions` as uid 0.
  (`IS_SANDBOX` is undocumented; re-check it after Claude upgrades, §14.2.)
- **Private network namespace per launch**, so each sandbox has its own
  `127.0.0.1` and agents in different worktrees can bind the same ports. (sbox
  uses pasta; xsb's default mode uses `--network none`, §7.2.)
- **`-it` only when stdin is a TTY.**
- **Env starts empty**, apart from a curated list forwarded *by name*. Never pass
  the whole host environment (secrets). Structural variables set by the
  launcher cannot be overridden from the list.
- **Forward `SSH_TTY`, `SSH_CONNECTION`, `SSH_CLIENT`, `TMUX`, `TMUX_PANE`** so that
  Claude's copy-to-clipboard uses OSC 52 escape sequences over ssh/tmux. Never
  mount the tmux *socket*: the tmux server runs unsandboxed, so the socket would
  be a sandbox escape (`send-keys`).
- **Each git repo's `config` and `hooks/` are read-only** inside the sandbox, while
  the rest of the shared `.git` store stays writable so `git commit` works from
  worktrees. For a worktree, `git rev-parse --git-common-dir` resolves the
  shared store, which lives in the main checkout.
- **Proxy**: filters HTTPS by `CONNECT` hostname (no TLS interception); re-reads
  the lists on every request, so `net-allow` takes effect immediately; an entry
  matches the domain and its subdomains; deny wins over allow; a blocked
  request gets a 403 whose body names the domain and the approval command.
- **Pull the base image on first use** if it is missing.

### 2.2 Known problems to fix

1. **The launcher and proxy live inside the writable root.** An agent can edit
   `sbox-common.sh` (which the user sources on the host at the next launch) and
   `sbox-net` (the host proxy process). Fixed by installing xsb as a package
   outside any root, plus invariant I4 below.
2. **Other files that run on the host are writable**, e.g.
   `~/ch/top/.claude/settings.json`: hooks placed there run when the user starts
   plain `claude` in the toplevel. Fixed by protected paths (§6.3).
3. **Egress filtering can be bypassed.** Under pasta the sandbox has direct
   internet access; only clients that honor `HTTPS_PROXY` are filtered. Fixed by
   enforced egress (§7.2).
4. **Everything is ch-specific**: conda, CUDA, `.venv`, the grouping-dir layout.
   All of that becomes config (§11).

## 3. Terminology

- **Root**: the directory containing `xsb.toml`. It is the sandbox's main
  read-write area and identifies the project.
- **Project**: a root. There is no registry of projects.
- **Agent**: a program xsb can launch (`claude`, `codex`), described by an
  *agent profile* (§8).
- **Backend**: OS-specific sandbox implementation (`podman` on Linux,
  `seatbelt` on macOS) that turns a resolved **Policy** into a process launch.
- **Policy**: the fully resolved, OS-neutral description of one launch: mounts,
  protected paths, env, devices, network settings, command. Built from config;
  consumed by a backend.

## 4. Command-line interface

One executable, `xsb`, with flat verbs (no nested subcommands):

| Command | Behavior |
|---|---|
| `xsb claude [args...]` | launch Claude Code in the sandbox; extra args pass through |
| `xsb codex [args...]` | same for Codex |
| `xsb shell` | interactive `bash` in an identical sandbox (for inspecting what the agent sees) |
| `xsb run -- CMD [args...]` | run an arbitrary command in the sandbox (used heavily by tests) |
| `xsb init` | set up `~/.xsb` if it's missing, then create a comments-only `xsb.toml` in the current directory (§5.6) |
| `xsb config` | print the effective merged config for the current directory, each value tagged with its source (built-in, `~/.xsb/config.toml`, `xsb.toml`, or a `[[match]]` block) |
| `xsb config -d, --defaults` | print the built-in defaults for every setting, as valid TOML with explanatory comments (keys not commented out). The same on every OS: Linux-only entries sit in a `[[match]] os = "linux"` block. Full output: Appendix A.2 |
| `xsb status` | the state of the current project and machine, plus health checks; exits non-zero if any check fails (§4.1) |
| `xsb prompt [agent]` | print the system-prompt text a launch here would inject |
| `xsb net-allow DOMAIN...` | append to the allow list, `~/.xsb/net-allow.txt` |
| `xsb net-deny DOMAIN...` | append to the deny list, `~/.xsb/net-deny.txt` |
| `xsb net-log` | show blocked / denied requests |
| `xsb net-stop` | stop the proxy (the next launch restarts it) |

Common options for the launch verbs (`claude`, `codex`, `shell`, `run`):

- `--dry-run`: print the resolved policy and the exact backend command (podman
  argv, or the Seatbelt profile plus argv), and launch nothing.
- `--network {enforced,open}`: override the configured network mode for
  this launch. `open` replaces today's `SBOX_NO_PROXY=1`.

There are no environment-variable overrides (sbox's `SBOX_*`): settings come
from config files and command-line flags only.

### 4.1 `xsb status`

Works anywhere; outside a project it says so and shows the rest. It prints three
parts:

1. **Project:** the root, its `xsb.toml` (and the real file, if it's a
   symlink), the agent config dirs, and the network mode.
2. **Proxy:** running or stopped (and ⚠ if it runs an older xsb version than
   the installed one; fix: `xsb net-stop`), and the allow and deny lists (with
   their real paths, if symlinks) and the agents' built-in domains, with entry
   counts.
3. **Checks**, each shown as ✓ or ⚠ with a one-line fix:
   - prerequisites: podman, pasta, catatonit and `/usr/bin/python3` on Linux;
     `sandbox-exec` on macOS (each backend's `check()`, §10.1);
   - Linux: podman's runtime is `crun` (`podman info --format
     '{{.Host.OCIRuntime.Name}}'`). With `runc`, `--group-add keep-groups` is
     silently ignored, so files readable only through a group are unreadable in
     the sandbox. The fix: install crun and set `runtime = "crun"` under
     `[engine]` in `~/.config/containers/containers.conf`;
   - each installed agent's program resolves to a single executable file (§8);
   - no broken network-list symlinks (§5.1);
   - xsb's own code is not writable from this project's sandbox (I4);
   - `~/.xsb` exists (otherwise: run `xsb init`);
   - gaps that config would fix, found by the same checks `xsb init` uses
     (§5.6), e.g. a folder on `PATH` that the sandbox can't see. The warning
     includes the TOML lines to add to `~/.xsb/config.toml`.

Exits non-zero if any check fails. Where other output lives: the merged settings
are `xsb config`, and the exact backend command (podman argv or Seatbelt
profile) is `--dry-run` on a launch verb.

## 5. Configuration

### 5.1 Files

```
~/.xsb/
    config.toml        # user-level defaults (optional)
    net-allow.txt      # domain lists, shared by all projects
    net-deny.txt
    claude/            # default shared CLAUDE_CONFIG_DIR
    codex/             # default shared CODEX_HOME
<root>/xsb.toml        # project config (may be a symlink); its presence defines the root
```

`~/.xsb` is the same on Linux and macOS (no XDG or `~/Library` split).
`system_prompt.md` layers are deferred (§9).

**Created by `xsb init`** (§5.6), so the user can always see which files there
are. Commands that need `~/.xsb` and find it missing (the launch verbs,
`net-allow`, `net-deny`) say "run `xsb init`"; `xsb config` and `xsb status`
work without it.

**The network lists may be symlinks.** To track the lists in git and share them
across machines, replace `~/.xsb/net-allow.txt` and `net-deny.txt`
with symlinks to files in a git repo (Appendix B.4). xsb follows the symlinks
for reading and for `xsb net-allow` / `net-deny`, and pins the *real* files
read-only in every sandbox (I1). `xsb init` treats any existing entry,
including a symlink, as present (`os.path.lexists`). A broken symlink is an
error for `net-allow` and is reported by `xsb status`; it is never replaced by a
new file.

### 5.2 Finding the root

Walk up from the current directory to `$HOME` (inclusive), or to `/` if the
current directory is not under `$HOME`, and collect every `xsb.toml` found.

- **None**: fail, suggesting `xsb init`.
- **More than one**: fail and list them. (An agent could otherwise plant
  `<root>/sub/xsb.toml` with a wider policy, and the next launch from `sub/`
  would pick it up.)
- **Exactly one**: its directory is the root.

### 5.3 Format and merge rules

TOML, parsed with the standard library's `tomllib` (so Python ≥ 3.11).

Load order, later layers overriding earlier ones:

1. built-in defaults (one set for every OS; Linux-only entries are in a
   `[[match]] os = "linux"` block);
2. `~/.xsb/config.toml`;
3. `xsb.toml`.

Within each file, `[[match]]` blocks are applied after the file's plain keys,
in file order, when their conditions hold.

Merge semantics are decided by the kind of value, since `tomllib` returns
`[[mount]]` blocks and `x = [...]` both as Python lists:

| Kind of value | Merge rule |
|---|---|
| scalar (`mode = "rw"`) | replaces |
| list of scalars (`require = [...]`, `extra_args = [...]`) | **replaces** |
| list of tables (`[[mount]]`, `[[device]]`, `[[match]]`, or the inline form `mount = [{...}]`) | **appends**; an entry with the same key as an earlier one replaces it, and `enabled = false` removes it. Keys: `path` for mounts, `glob` for devices, `dir` for `refuse`; `[[match]]` blocks never collapse |
| table (`[env.set]`, `[linux]`) | merges key by key |

Consequences:

- **Replacing applies across files.** A `require` list in `xsb.toml` replaces
  one in `~/.xsb/config.toml`. `xsb config` shows where each value came
  from.
- **Design rule:** every list of scalars has an empty built-in default, so
  replacing never silently drops a default. A setting whose default must be both
  extendable and trimmable is a table of `name = true|false`, not a list
  (`[env.forward]`, `[protect]`; §5.4).
- **Removing a default entry:** repeat its key with `enabled = false`, e.g.
  `[[mount]] path = "~/.condarc"` plus `enabled = false`. Every keyed entry
  (`[[mount]]`, `[[device]]`, `refuse`) accepts `enabled`, default `true`.
- **Mixed lists are an error.** A list containing both tables and scalars is
  rejected.

**Relative paths** always resolve against the root, whichever file they're in
(mount paths, agent dirs, `[protect]` globs, `refuse` dirs). The root is the
directory where `xsb.toml` was found, even if `xsb.toml` is a symlink to a file
elsewhere (Appendix B). `$ROOT` is available explicitly.

**Variables** expanded in paths and env values: `~`, `$HOME`, `$USER`,
`$HOSTNAME` (short name), `$ROOT`, `$CWD` (the launch directory), and any other
`$NAME` / `${NAME}` from the launching environment. An undefined variable is an
error, not an empty string. Globs expand after variables.

### 5.4 Schema

```toml
# Agent config dirs. Missing: ~/.xsb/<agent>. Relative: to the root.
claude_dir = "claude"
codex_dir  = "~/.xsb/codex"

refuse = [ { dir = "top", reason = "..." } ]   # refuse to launch when $CWD is (under) this dir

[protect]                       # read-only inside the sandbox (§6.3). Keys are globs relative to the
"top" = true                    # root. A table, so it merges with the built-in defaults: "true"
"*/.envrc" = true               # adds a path, "false" removes a default, e.g. to let
"*/.mcp.json" = false           # agents edit worktrees' MCP configs

[[mount]]
path = "/mnt/cs00/data/$USER"   # glob allowed
mode = "rw"                     # "ro" | "rw"
create = true                   # create the directory if missing, when its parent exists (default false)
enabled = true                  # false: remove an earlier entry with the same path (e.g. a default)

[[device]]                      # Linux only; character devices only, missing ones skipped
glob = "/dev/nvidia*"
enabled = true                  # false: remove an earlier entry with the same glob

[env]
require = ["CONDA_PREFIX"]      # refuse to launch if unset; also forwarded
[env.forward]                   # forwarded by name if set in the launching shell. A table, not
CONDA_PREFIX = true             # a list, so it merges key by key with the built-in defaults:
TMUX = false                    # "true" adds a name, "false" stops forwarding a default
[env.set]
VIRTUAL_ENV = "$CWD/.venv"

[network]
mode = "enforced"               # "enforced" (default) | "open"

[linux]
image = "docker.io/library/ubuntu:24.04"   # default "auto": docker.io/library/<ID>:<VERSION_ID> from /etc/os-release
extra_args = ["--ipc", "host", "--ulimit", "memlock=-1:-1"]

# Conditional settings. Each [[match]] block (an xsb convention, not TOML
# syntax) lists conditions; if all hold on the current machine, the settings
# nested under it are merged into the config as if written at top level,
# otherwise they are ignored. Nested settings use the "match." prefix and
# belong to the most recent [[match]] above them: [[match.mount]],
# [[match.device]], [match.env.set], etc. Here: on Linux machines named cf* or
# cs*, also mount /scratch read-write.
[[match]]
os = "linux"                    # "linux" | "macos"
hosts = ["cf*", "cs*"]          # fnmatch against the short hostname
[[match.mount]]
path = "/scratch"
mode = "rw"
```

Unknown keys are an error (catches typos in security-relevant config).

### 5.5 Built-in defaults

**Rule for what is a default:** defaults cover common development setups
(missing paths are skipped, so they cost nothing where absent). Anything that
shares host state or grants write access is opt-in (e.g. `--ipc host`). Any
default entry can be removed (`enabled = false`, `false` in a table; §5.3).

**Shell startup files are not mounted.** The sandbox inherits its environment
from the launching shell instead (§6.4): conda and direnv have already set up
`PATH`, `CONDA_PREFIX`, `VIRTUAL_ENV` there, and xsb passes them through.
Loading `~/.bashrc` again inside the sandbox would only redo that setup, and in
the wrong order (a `conda activate` in `.bashrc` puts conda's `bin` ahead of a
venv), and it would re-export any secrets kept there. So agents' shells run
without startup files: no aliases, prompt or `conda` shell function, none of
which agents need (`conda` still works as a program). A user who wants them can
add the mounts.

- **Mounts, Linux only** (in a `[[match]] os = "linux"` block): `ro /usr`,
  `ro /etc`. The Linux backend refuses to launch if either path doesn't exist
  on the host.
- **Mounts, both OSes** (read-only):
  - `/opt`: system software; on macOS this covers `/opt/homebrew`;
  - `~/.gitconfig`, `~/.config/git`: commit identity (credentials live in
    `~/.git-credentials`, which stays hidden);
  - `~/.local/bin`, `~/.local/lib`: per-user tools (direnv) and
    `pip install --user` packages. Not all of `~/.local`: `~/.local/share` holds
    desktop-app data (Trash, keyrings, chat history);
  - conda: `~/miniforge3`, `~/miniconda3`, `~/anaconda3` (`/opt/conda` is
    already under `/opt`), `~/.conda`, `~/.condarc`.
- **Devices** (Linux): `/dev/nvidia*`.
- **macOS system paths**: a base Seatbelt allowance block (§10.3), not mounts.
- **The agent's own program**: mounted automatically (§8), not a config entry.
- **`[env.forward]`**: `true` for `TERM COLORTERM LANG LC_ALL LC_CTYPE TZ SHELL
  EDITOR VISUAL GIT_EDITOR PAGER GIT_PAGER SSH_TTY SSH_CONNECTION SSH_CLIENT
  TMUX TMUX_PANE CONDA_PREFIX LD_LIBRARY_PATH`. `SHELL` matters on macOS: Claude
  runs its Bash tool with `$SHELL`, so there it picks zsh. `LD_LIBRARY_PATH` is
  forwarded rather than set, so the sandbox finds libraries the way the user's
  shell does. (sbox set it to `/usr/local/cuda/lib64`, but on our machines CUDA
  is found through `/etc/ld.so.conf.d/`, and a hardcoded path could shadow a
  conda env's own CUDA libraries.) Keep the reasons from ch_top's
  `env-allow.txt` as comments, both in the code and in `xsb config --defaults`
  output (Appendix A.2).
- **`[env.set]`**: `CUPY_CACHE_DIR=/tmp/cupy_cache` (home is read-only, so caches
  go to `/tmp`; only CuPy reads it).
- **Env set by xsb (reserved; config cannot override)**: `HOME`, `USER`, `PATH`
  (the launching shell's, unchanged), the agent's config-dir variable,
  `HTTP(S)_PROXY` / `http(s)_proxy` / `NO_PROXY` / `no_proxy`, `TMPDIR` (macOS),
  `XDG_CACHE_HOME=/tmp/cache`, `IS_SANDBOX` (Linux, Claude), and `XSB_ROOT`,
  `XSB_BACKEND`, `XSB_NETWORK` so tools can detect the sandbox.
- **Always read-write**: the root.

### 5.6 `xsb init`

One command sets up both the machine and a project:

1. **Create `~/.xsb`** (mode `0700`) if it's missing, and each of these that is
   missing; existing files, including symlinks, are never overwritten:
   - `claude/` and `codex/`, empty (whether or not that agent is installed);
   - `net-allow.txt` and `net-deny.txt`, with an explanatory header only
     (syntax, and that `xsb net-allow` appends here). The agents' required
     domains stay built in (§8);
   - `config.toml`: a header comment, plus any machine-specific settings the
     detection checks below find, each with a comment saying why (Appendix
     A.1). It never contains a copy of the defaults, so it doesn't go stale
     when xsb changes.
2. **If the current directory is `~/.xsb` or inside it, stop.** That's how to
   set up only the machine; a project root there would be a hidden directory.
3. **Refuse** if an `xsb.toml` exists in the current directory or any parent
   (nested configs are refused at launch, §5.2), or if the current directory
   contains `~/.xsb`, e.g. `$HOME` (it would expose `~/.xsb`, I3).
4. **Create `./xsb.toml`**, comments only (Appendix A.3).
5. **List what was created.**

**Detection checks** look for what the defaults miss on this machine. Initially:

- a conda install outside the default locations (found via `$CONDA_EXE`);
- directories on the launching shell's `PATH` that aren't visible in the
  sandbox (e.g. `~/bin`, `~/go/bin`), since commands found there on the host
  would be missing inside.

Each check is a small function returning proposed TOML entries with a comment.
`xsb init` writes them into a new `config.toml`; `xsb status` runs the same
checks later and shows the entries in its warnings (§4.1). The list is
expected to grow.

## 6. Filesystem policy

### 6.1 Security invariants

Each is enforced in code, not by convention, and each gets a test.

- **I1**: every config file and network list xsb reads is read-only inside the
  sandbox, if visible at all. Paths are resolved to real paths first, so a
  symlinked `xsb.toml` or list is pinned at its real location, e.g. inside a
  git checkout under a writable root. Together with I2 and I3, this means an
  agent can't change the policy that governs its next launch.
- **I2**: exactly one `xsb.toml` between `$CWD` and `$HOME` (§5.2).
- **I3**: `~/.xsb` is invisible in the sandbox, except for the agent dirs that
  this launch mounts. Refuse to launch if any mount would expose other parts of
  it, e.g. `ro ~`.
- **I4**: xsb's own code is not writable from any sandbox. At launch, resolve
  the real paths of the `xsb` package directory and of `sys.executable`'s
  prefix, and refuse if either would be writable in this sandbox (under a
  read-write mount and not protected). An editable install is fine when the
  clone is outside the sandbox's root (e.g. `~/git/xsb` while working in
  `~/ch`) or protected. Developing xsb with a sandboxed agent in the same clone
  that the host's editable install points to is refused; use a separate clone
  or worktree, or a non-editable install (`pipx install`).
- **I5**: the proxy's runtime dir (pid file, log, socket) is invisible.
- **I6**: protected paths (§6.3) are read-only.
- **I7**: fail closed. Invalid config, a missing `/usr` or `/etc` on Linux, the
  proxy failing to start, or the relay failing (unless mode is `open`) all
  refuse the launch.

### 6.2 Mount assembly

1. Built-in mounts, then config mounts. Globs expand; missing paths are
   skipped. `create = true` creates a missing directory whose parent
   exists; if the parent is missing too, the entry is skipped. (So one config
   can name `/mnt/cs00/data/$USER`, created on the production nodes and
   skipped elsewhere.)
2. The root, read-write.
3. The launched agent's config dir, read-write, created if missing.
4. Git: for `$CWD` and each immediate subdirectory that is a git checkout,
   resolve the common dir (`git rev-parse --git-common-dir`). Always mount it
   read-write explicitly, even if it's already under the root, so commits work
   even when it sits under a protected path (ch_top protects `top`, which holds
   the shared `.git` dirs). Then pin its `config` and `hooks/` read-only.
5. Protected paths, read-only.
6. `xsb.toml` and the network lists, read-only, at their real paths (symlinks
   resolved).

When two rules cover the same path, the **deeper path wins**; for identical
paths the later rule wins. Podman applies mounts in the order given, so emit
them sorted by path depth, keeping the order above for ties. The Seatbelt
generator emits rules in the same order, since later rules win in SBPL. For
example, `[protect] "top" = true` makes `~/ch/top` read-only, while step 4 re-opens
`~/ch/top/.git` read-write (deeper) and then pins `~/ch/top/.git/config`
read-only (deeper still).

### 6.3 Protected paths

Protected paths are read-only inside the sandbox even though they lie in a
writable area (usually the root). They are for files that the host loads or
runs *automatically*, outside the sandbox, where a planted edit would be a
sandbox escape.

The **built-in `[protect]` entries** (all `true`) are the files Claude Code loads
on its own when started in a directory, in the root and in each immediate
subdirectory (e.g. each worktree):

- `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks`,
  `.mcp.json`
- `*/.claude/settings.json`, `*/.claude/settings.local.json`, `*/.claude/hooks`,
  `*/.mcp.json`

That is the realistic escape: an agent adds a hook, and the next time the user
runs plain `claude` there, it runs on the host. Other files (shell startup
files, `.gitconfig`, editor settings) aren't protected by default, because
nothing on the host loads them from inside a project directory. Skills, agents
and commands aren't either: they only run when invoked, and agents
legitimately edit them.

Always protected, and not part of the table (they cannot be turned off):

- every git repo's `config` and `hooks/` (§6.2, step 4);
- `xsb.toml`, at its real path (I1).

Keys are globs relative to the root, expanded at launch with Python's `glob`
(`*` matches within one path component; `**` is not supported, so launch never
walks the whole tree). On Linux, a bind mount can only pin a path that
**exists**, so creating a *new* protected file isn't prevented there. That's
accepted: a project that needs it can protect a whole directory, as ch_top
does with `top`. Seatbelt uses regexes, so on macOS the same globs also cover
files that don't exist yet.

In config, `"<glob>" = true` adds an entry and `"<glob>" = false` removes a
built-in one. Keys match built-in entries by exact string.

### 6.4 Environment assembly

The sandbox's environment comes from the launching shell, filtered: `PATH` as
is, and forwarded variables by name. No shell startup
files run (§5.5), so nothing reorders `PATH` afterwards. (sbox sets
`CLAUDE_ENV_FILE` to re-add the venv to `PATH` before each command; xsb doesn't
need it.) Launch from a shell that is already set up (conda
env active, direnv loaded).

The environment starts empty. Then:

1. Forward each name whose merged `env.forward` value is `true`, only if it is
   set. Names in `env.require` are always forwarded (a required variable that
   didn't reach the sandbox would be pointless).
2. Apply `env.set` (expanded).
3. Apply the reserved variables (§5.5).

Names that fail `^[A-Za-z_][A-Za-z0-9_]*$` are an error, and so are values in
`env.forward` other than `true` / `false`. Listing a reserved name in `forward`
or `set` is also an error, not a warning, so that mistakes in
security-relevant config are caught early.

## 7. Network

### 7.1 The proxy

Port `sbox-net`'s proxy into `xsb/proxy.py`, keeping its behavior (§2.1).
Changes:

- **One proxy per user**, shared by all projects and sandboxes. Runtime dir:
  `$XDG_RUNTIME_DIR/xsb`, falling back to `/tmp/xsb-<uid>` on Linux and
  `$TMPDIR/xsb` on macOS. It holds the pid file, version file, log and port
  file, and a `sock/` subdirectory with the Unix sockets.
- **Listens on** a Unix socket `sock/proxy.sock` (Linux; reached through the
  in-container relay) and a TCP port on `127.0.0.1` (macOS, where Seatbelt
  allows loopback connections).
- **DNS forwarder** (enforced mode on Linux): a third listener, the Unix socket
  `sock/dns.sock`. Each connection carries DNS messages with the 2-byte length prefix
  used by DNS over TCP. The proxy sends each query, **unmodified and
  unfiltered**, to the host's resolver (the first `nameserver` in the host's
  `/etc/resolv.conf`, over UDP; retry over TCP if the reply is truncated), and
  returns the reply unchanged. See "DNS" in §7.2.
- **Port** (macOS): bind port 0, write the chosen port to the runtime dir, and
  reuse it while the proxy runs. (sbox-net derives a fixed port from a hash of
  the grouping dir, which can collide; don't port that.)
- **Lists read** per request: `~/.xsb/net-allow.txt` and `net-deny.txt`, plus the
  required domains of *all* agent profiles (built in, e.g. `anthropic.com` for
  Claude), since one proxy serves every sandbox.
  There are no per-project lists. `xsb status` shows both sources.
- **Block message**: the 403 body names `xsb net-allow <domain>`.
- **`xsb net-allow` writes** to `~/.xsb/net-allow.txt` (`net-deny` to
  `net-deny.txt`), through the symlink if it is one (§5.1).
- **Start**: launched on first use by any launch verb, as `sys.executable -m
  xsb.proxy`, detached (`start_new_session`); running that command directly
  keeps it in the foreground, for debugging. The proxy records its xsb version
  in the runtime dir, and `xsb status` warns when it differs from the installed
  one (after an upgrade, `xsb net-stop`; the next launch starts the new one).
- **Restart-safe sockets:** sandboxes bind-mount the `sock/` *directory*, not
  the socket files. A restarted proxy re-creates its sockets, and a bind-mounted
  socket file would keep pointing at the old, deleted one, cutting running
  sandboxes off.

### 7.2 Modes

| Mode | Linux | macOS |
|---|---|---|
| `enforced` (default) | `podman --network none` (own loopback only). An in-container relay (§10.2) listens on `127.0.0.1:3128` (TCP) and `127.0.0.1:53` (UDP and TCP), and forwards to the proxy's `proxy.sock` and `dns.sock`, whose directory is bind-mounted at `/run/xsb/sock/`. No other route out exists. | Seatbelt allows outbound TCP only to `localhost`, on any port (the proxy, and the agent's own local servers). This also reaches other services listening on the Mac's loopback; accepted (§14.1). DNS through mDNSResponder is allowed. |
| `open` | pasta, no proxy variables | no network rules, no proxy variables |

In `enforced` mode set `HTTPS_PROXY` / `HTTP_PROXY` (both cases) to
`http://127.0.0.1:PORT` (3128 on Linux; the proxy's actual port on macOS), and
`NO_PROXY` to `localhost,127.0.0.1,::1`. (sbox also has a mode where the proxy
variables are set but direct connections still work; xsb doesn't, since such
filtering is easy to bypass.)

**DNS works in every mode, unfiltered.** Proxy-aware
clients don't need it, since they send the hostname to the proxy, which resolves
it on the host. But many tools look names up on their own, and failing DNS
causes confusing errors. So:

- **Linux, enforced:** xsb writes a `resolv.conf` containing
  `nameserver 127.0.0.1` into the runtime dir and bind-mounts it read-only over
  `/etc/resolv.conf`. The relay passes queries to `sock/dns.sock` (§7.1). This is the
  only DNS path: queries sent straight to outside resolvers (`dig @1.1.1.1`)
  fail, like all other direct traffic.
- **Linux, open:** pasta's own DNS forwarding, as today.
- **macOS:** the base profile allows `mach-lookup` of `com.apple.dnssd.service`
  (mDNSResponder), which serves both DNS and `/etc/hosts`.

**Accepted risk: DNS exfiltration.** Code in the sandbox can leak data by
looking up names like `<data>.attacker.com`; the host's resolver forwards the
query to the attacker's nameserver. The bandwidth is low, but it is enough for a
token. Direct connections to the resolved IPs are still blocked in enforced
mode. If this risk is later judged too high, the designed fallback is a
**filtering** forwarder: answer only names on the allowlist, reply NXDOMAIN
otherwise, and log refusals like blocked requests. On Linux that changes only
the proxy's DNS handler. On macOS it is not possible (Seatbelt can only allow or
deny mDNSResponder as a whole).

Verify enforced mode against the existing production search in pirate (it runs
in-sandbox with data addresses rewritten to loopback) before making it the
default in ch_top (§14.2).

## 8. Agent profiles

A table in `xsb/agents.py`. `xsb claude` and `xsb codex` are the same launcher
reading different rows. Adding an agent means adding a row.

| Field | claude | codex |
|---|---|---|
| command | `claude` | `codex` |
| config-dir env var | `CLAUDE_CONFIG_DIR` | `CODEX_HOME` |
| default dir | `~/.xsb/claude` | `~/.xsb/codex` |
| config key | `claude_dir` | `codex_dir` |
| no-prompts flags | `--dangerously-skip-permissions` | the flag that disables both approvals and Codex's own sandbox (**verify the current name**; believed to be `--dangerously-bypass-approvals-and-sandbox`) |
| extra env | `IS_SANDBOX=1` (Linux only), `DISABLE_AUTOUPDATER=1` | none |
| required domains | `anthropic.com`, `claude.com`, `claude.ai` | `openai.com`, `chatgpt.com` |
| system-prompt text (§9) | `--append-system-prompt <text>` | **verify**: a `-c` config override for extra instructions |
| program | resolved automatically (below) | resolved automatically (below) |

Codex's own sandbox must be off: Seatbelt cannot be nested, and on Linux it
would conflict with the container's restrictions.

**The agent's program is mounted automatically.** At launch, xsb finds the
command on the host's `PATH` and resolves symlinks to the real file. It mounts
**that one file** read-only at its real path and runs it by absolute path. Both
agents currently install as single self-contained executables, e.g.:

- `~/.local/bin/claude` → `/var/lib/containers/$USER/claude/versions/2.1.282`
- `~/.local/bin/codex` → `~/.codex/packages/standalone/releases/<ver>/bin/codex`
  (a static musl binary)

This keeps agent installs out of the config and, importantly, never mounts
`~/.codex`, which also holds the user's **personal** Codex login
(`~/.codex/auth.json`). If the resolved file is not an ELF / Mach-O executable
(e.g. a script shim that needs an interpreter), `xsb status` warns and the user
adds mounts by hand. The mount shows up in `xsb config` and `--dry-run` like any
other. Inside the sandbox, `claude` / `codex` are also callable by name when
their symlink sits in a mounted directory on `PATH`, such as `~/.local/bin` (a
default mount).

**Codex login and updates.** Codex's ChatGPT sign-in waits for a browser
callback on `localhost:1455`, which can't reach a Linux sandbox's private
loopback (or a remote machine over ssh). Document signing in outside the
sandbox, `CODEX_HOME=<codex_dir> codex login`, or its device-code sign-in if
available (**verify**). Codex's self-update writes into `~/.codex/packages`,
which isn't writable in the sandbox, so update outside it. The same goes for
Claude, whose auto-updater xsb turns off in the sandbox
(`DISABLE_AUTOUPDATER=1`) so it doesn't try.

## 9. System prompt

`xsb claude` / `xsb codex` append a generated text (template in
`xsb/prompt.py`) describing the sandbox as actually configured for this launch.
It replaces the egress paragraph and the "never bypass the proxy" rule in
ch_top's `CLAUDE.md` (lines 42 to 50 and 96 to 99 at the time of writing).
Content:

- You are running in an xsb sandbox. Permissions are skipped; the sandbox is the
  security boundary. The root is `<root>`, read-write. Other visible paths are
  read-only unless listed as writable: `<list>`.
- Protected paths are read-only on purpose (`<summary>`); do not work around
  that.
- Network: all HTTP(S) goes through an allowlisting proxy (`<mode>`). A blocked
  domain fails with a 403 or "CONNECT tunnel failed", or a body starting
  `xsb: egress to ... is not on the allowlist`. When that happens, stop and tell
  the user the exact domain and why you need it. The user approves it with
  `xsb net-allow <domain>`, and then you retry. Never route around a block:
  do not switch to a mirror or another domain, unset or change the proxy
  variables, or use raw sockets or other tools.
- If you need a path that is not visible, ask the user to add a mount to
  `xsb.toml`.

`xsb prompt` prints this text. Deferred (do not implement yet): user and
project additions (`~/.xsb/system_prompt.md`, and a `system_prompt` key in
`xsb.toml`).

## 10. Backends

### 10.1 Interface

```python
class Backend(Protocol):
    name: str
    def check(self) -> list[str]: ...                      # prerequisite problems, for `xsb status`
    def command(self, policy: Policy) -> LaunchSpec: ...  # argv + files to write; pure, no side effects
    def launch(self, spec: LaunchSpec) -> int: ...        # run it, return the exit status
```

`command()` is pure so that `--dry-run` and the unit tests exercise it without
launching anything. Choose the backend by `sys.platform`.

### 10.2 Linux: `podman`

Build the argv the way `sbox-common.sh` does (§2.1), from the Policy:

- `run --rm --init`, the `--network` value from §7.2, `--tmpfs /tmp --tmpfs /run`,
  `-w $CWD`, `--group-add keep-groups` (always), `-it` if stdin is a
  TTY, `linux.extra_args`, then the `-e` values and `-v src:dst:mode` mounts in
  §6.2 order, `--device` entries, the image, and the command. In enforced mode,
  also mount (read-only) `relay.py` at `/run/xsb/relay.py`, the proxy's `sock/`
  directory at `/run/xsb/sock`, and the generated `resolv.conf` over
  `/etc/resolv.conf`.
- **Relay** (`enforced` mode): a small stdlib-only Python script,
  `xsb/data/relay.py`, run inside the container as
  `/usr/bin/python3 -I /run/xsb/relay.py ...`, using the host's `/usr`. (sbox
  uses socat; DNS needs a UDP-datagram to length-prefixed-stream conversion that
  socat can't do.) It serves:
  - `127.0.0.1:3128` TCP, piped to `/run/xsb/sock/proxy.sock` (a fixed port is
    fine, since nothing else shares the container's loopback);
  - `127.0.0.1:53` UDP and TCP, forwarded to `/run/xsb/sock/dns.sock`. Binding
    port 53 is fine: container root keeps `CAP_NET_BIND_SERVICE`.

  The relay binds all of its ports **before** it goes into the background
  (fork, then the parent exits 0). So the prelude is
  `/usr/bin/python3 -I /run/xsb/relay.py ... && exec <agent>`, and the agent
  never starts before the relay is listening. (sbox's `socat ... &` has that
  race.) If the relay fails, the launch fails (I7).
- **Image**: `linux.image = "auto"` (the default) means
  `docker.io/library/<ID>:<VERSION_ID>` from the host's `/etc/os-release`. Pull
  it if `podman image exists` fails.

This host (Ubuntu 24.04) has podman 4.9.3 using the `crun` runtime (set in
`~/.config/containers/containers.conf`), pasta, catatonit, socat, bwrap,
`/usr/bin/python3` (3.12, used by the relay) and `dig`, `curl`, `getent`.

### 10.3 macOS: `seatbelt`

Implement in this repo; testing and completion happen later on a Mac (§13).

- **`seatbelt.profile(policy) -> str`** (pure, unit-tested on Linux). Emits
  `(version 1)`, `(deny default)`, then the static base allowances from
  `xsb/data/seatbelt_base.sb`, then generated rules in §6.2 order:
  - `(allow file-read* (subpath "<p>"))` for read-only mounts;
  - `file-read*` plus `file-write*` for read-write mounts;
  - `(deny file-write* (subpath|literal|regex ...))` for protected paths;
  - `(deny file-read* file-write* (subpath "~/.xsb"))` followed by allows for
    the mounted agent dirs;
  - a deny on the runtime dir;
  - `(deny network*)`, then `(allow network-outbound (remote ip "localhost:*"))`
    and `(allow network-bind (local ip "localhost:*"))` in enforced mode.

  Resolve every path with `os.path.realpath` before emitting (`/tmp` is
  `/private/tmp`, `/var` is `/private/var`). Escape strings for SBPL.
- **`seatbelt_base.sb`**: a first guess at what a default-deny profile needs on
  macOS: `process-fork`, `process-exec`, `sysctl-read`,
  `(signal (target same-sandbox))`, `pseudo-tty`, and file reads for
  `/System`, `/usr`, `/bin`, `/sbin`, `/Library`, `/private/etc`,
  `/private/var/db/timezone`, `/dev/null`, `/dev/urandom` and `/dev/tty*`.
  (`/opt/homebrew` comes from the default `/opt` mount, not from this file.)
  Also `mach-lookup` for `com.apple.dnssd.service` (DNS and
  `/etc/hosts`; allowed on purpose, see "DNS" in §7.2), `trustd`, and `securityd`
  (Keychain). Mark the file **UNVERIFIED** at the top.
- **Launch**: write the profile to the runtime dir, then exec
  `sandbox-exec -f <profile> /usr/bin/env -i K=V... <command>`, with a per-launch
  `TMPDIR` under the runtime dir that is read-write in the profile and removed
  after the agent exits. No relay: the agent reaches the host proxy's TCP port directly. No devices.
  No `IS_SANDBOX`.
- **`MACOS.md`**: the handoff checklist from §13.

## 11. ch_top migration (follow-up; not part of this repo's work)

Listed so the xsb design can be checked against a real user. Do it in ch_top
after xsb works.

The config files ch_top needs are in Appendix B. Between them, they translate
`fs-allow.txt`, `devices.txt`, `env-allow.txt` and the hardcoded parts of
`sbox-common.sh`. Project settings go in ch_top's `sandbox/ch.toml` (B.1), which
`~/ch/xsb.toml` symlinks to (B.2); machine and toolchain settings are mostly
covered by the defaults (A.2), and anything left goes in the user's
`~/.xsb/config.toml` (B.3).

Other ch_top steps:

- Replace `sbox-claude`, `sbox-shell` and `sbox-net` with three-line wrappers
  that call `xsb` (delete them a few weeks later). Delete `sbox-common.sh` and
  the translated policy files (`fs-allow.txt`, `devices.txt`,
  `env-allow.txt`).
- **Network lists:** copy `sandbox/net-allow.txt` and `net-deny.txt` into the xsb
  repo's `net/`, create the `~/.xsb` symlinks (B.4), and delete them from
  ch_top.
- **Claude config dir:** move `~/ch/claude` to the default `~/.xsb/claude`. Do
  it at the switchover, with no `sbox-claude` sessions running (until then
  `sbox-claude` expects `~/ch/claude` and would create a fresh, logged-out
  one). Transcripts and memory are filed by working directory, which doesn't
  change, so history carries over. `~` and `~/ch` are the same NFS filesystem,
  so this is a rename. Two files contain the old absolute path:

  ```bash
  rmdir ~/.xsb/claude 2>/dev/null; mkdir -p ~/.xsb
  mv ~/ch/claude ~/.xsb/claude
  sed -i 's#/home/kmsmith/ch/claude#/home/kmsmith/.xsb/claude#g' \
      ~/.xsb/claude/settings.json ~/.xsb/claude/plugins/known_marketplaces.json
  ```

  The old `jobs/` and `daemon*` files are leftovers from past background
  sessions and can be deleted.
- **`CLAUDE_ENV_FILE`:** the sandbox no longer uses it (§6.4). The worktree's
  `.claude/env.sh` and the `.envrc` export stay, for running `claude` directly
  on the host; update the comment in `dotfile_templates/claude-env.sh.tmpl`,
  which describes the sbox path.
- `CLAUDE.md`: delete the egress paragraph and the "never bypass the proxy"
  bullet (now in the generated system prompt); delete the `claude/` line
  (README too).
- `.claude/skills/ch-research/SKILL.md`: replace the repeated proxy explanation
  (lines 81 to 82, 413 to 417) with a pointer to the system prompt, keeping
  "agents must not install software".
- README: replace "Sandbox and GPU", "Egress proxy" and Appendices C to F with a
  short section pointing to xsb.
- **xsb itself** lives at `~/git/xsb`, outside `~/ch`, and is not managed by
  ch_top (not in `git_repositories.toml`).

## 12. Package layout and phases

```
xsb/
  pyproject.toml         # setuptools; requires-python >= 3.11; no runtime dependencies
                         # [project.scripts] xsb = "xsb.cli:main"
  README.md              # user docs: install, xsb.toml reference, security model
  net/                   # the maintainer's own global allow/deny lists (Appendix B.4);
                         # not part of the package
  MACOS.md               # §13
  src/xsb/
    __init__.py
    __main__.py          # python -m xsb
    cli.py               # argument parsing, verb dispatch
    config.py            # discovery, TOML load, match/merge, expansion, validation
    policy.py            # Policy dataclass; config -> Policy; invariants I1-I7
    agents.py            # agent profile table
    prompt.py            # system-prompt template
    proxy.py             # proxy server + net-* verbs (python -m xsb.proxy)
    backends/__init__.py # Backend protocol, selection
    backends/podman.py
    backends/seatbelt.py
    data/seatbelt_base.sb
    data/relay.py        # in-container TCP + DNS relay (Linux), run by the container's python3
  tests/
    unit/                # no podman needed; run anywhere, including macOS
    integration/         # Linux + podman; skipped if podman is unavailable
```

Tests use pytest (a dev dependency only).

Phases, each ending with passing tests:

0. **Prototype enforced networking** (throwaway code, before phase 1), since it
   is the part most likely to force a design change. By hand or with a small
   script, check that: `podman run --network none` with the proxy's `sock/`
   directory bind-mounted works, and survives a proxy restart; a bind mount
   over `/etc/resolv.conf` is accepted; a relay inside the container reaches the
   proxy for HTTPS and DNS; and Claude's Bash tool in that container keeps the
   launching shell's `PATH` (§14.2). Report the results before building on
   them.
1. Skeleton, `config.py`; `xsb init/status/config` (including `--defaults`).
   `xsb status` starts with the project part and gains its proxy part and
   checks in later phases, as the things it reports are built.
2. `proxy.py` and the `net-*` verbs (port the existing proxy; add the Unix socket
   and dynamic port).
3. `policy.py` and `backends/podman.py` in `open` mode; `xsb run/shell/claude`;
   `--dry-run`.
4. Enforced network mode on Linux (relay, DNS).
5. Protected paths; invariants I3 and I4.
6. `prompt.py`, `xsb prompt`, `codex` profile.
7. `backends/seatbelt.py` (generator plus launch glue), `seatbelt_base.sb`,
   `MACOS.md`.

**Where to test.** A sandboxed agent (one started by `sbox-claude`) cannot run
podman, since there is no nesting. Unit tests run anywhere. Integration tests
must run on the host, either by the user or by an unsandboxed agent session.
Structure them so one command runs them all (`pytest tests/integration`), and
report which ones could not run.

### Test list

Unit tests:

- config discovery (0, 1, 2 files);
- merge semantics: a scalar list replaces; `[[mount]]` appends, and two mounts
  with the same path collapse to the later one; `[env.forward]` with `true` /
  `false` adds and removes; a mixed list is an error;
- `xsb init`: creates the `~/.xsb` files and never overwrites existing ones
  (including symlinks); stops after that step in or under `~/.xsb`; refuses
  when an `xsb.toml` exists here or in a parent, and in a directory containing
  `~/.xsb`; the `config.toml` it writes parses as TOML, with detected entries;
- `xsb config --defaults` output parses as TOML and equals the built-in
  defaults;
- `xsb config` tags each value with the right source;
- `xsb status` exits non-zero when a check fails (missing prerequisite, broken
  list symlink, agent program that isn't a single executable), and zero
  otherwise, both inside and outside a project;
- `[[match]]` by os and host;
- variable expansion, including the undefined-variable error;
- relative path resolution, including a symlinked `xsb.toml` (the root is the
  symlink's directory);
- `create = true`: a missing directory is created when its parent exists, and
  the entry is skipped when the parent is missing;
- unknown-key error;
- reserved-env error;
- mount ordering;
- invariant I3 (`ro ~` refused) and invariant I4;
- proxy `decide()` matching;
- agent program resolution: a symlink chain resolves to one file, that file is
  mounted read-only and run by absolute path, and `~/.codex` itself is never
  mounted; a script shim triggers the `xsb status` warning;
- removal: `enabled = false` on a default mount or device removes it; `false` in
  `[env.forward]` / `[protect]` removes a default;
- symlinked lists: reads and `net-allow` appends reach the target file;
  a broken symlink is an error and is never replaced;
- DNS forwarding: a query framed by `relay.py` reaches a fake resolver
  unchanged, and the reply comes back unchanged (including a truncated UDP
  reply retried over TCP);
- the podman argv for a sample policy (golden file);
- the Seatbelt profile for a sample policy (golden file), including `/tmp`
  resolution and the `~/.xsb` deny.

Integration tests (Linux):

- an unlisted host path is absent; a `ro` path is not writable; the root is
  writable;
- a protected file is not writable; `.git/config` and `.git/hooks` are not
  writable, while `git commit` in a worktree succeeds, including when the main
  checkout holding the shared `.git` is protected (the ch_top layout);
- `~/.xsb/config.toml` is invisible;
- env contains only the expected names;
- with no startup files mounted, `which python` in Claude's Bash tool finds the
  venv from the launching shell's `PATH` (§14.2);
- the real files behind a symlinked `xsb.toml` and list are read-only in the
  sandbox;
- an allowed domain succeeds through the proxy; an unlisted one gets a 403 with
  the `net-allow` hint;
- in enforced mode, a raw TCP connect to an outside IP fails and
  `curl --noproxy '*'` fails (even though the name resolves);
- DNS in every mode: `getent hosts example.com` succeeds and `localhost`
  resolves; in enforced mode, `dig @1.1.1.1 example.com` (straight to an outside
  resolver) fails, and UDP to any outside port fails;
- the agent command does not start until the relay is listening;
- a running sandbox keeps working across `xsb net-stop` and a proxy restart;
- two concurrent sandboxes both bind `127.0.0.1:5000`;
- orphaned children are reaped (`--init`);
- the GPU is visible if `/dev/nvidia0` exists;
- a planted second `xsb.toml` is refused.

## 13. macOS handoff (contents of `MACOS.md`)

The Mac agent must run **unsandboxed**: Claude Code's `/sandbox` (Bash
sandboxing) must be off, because `sandbox-exec` cannot start inside another
Seatbelt sandbox. It should run the unit tests first, then work through:

1. Grow `seatbelt_base.sb` until `claude`, `git`, `python` and `bash` run under
   `(deny default)`. Watch denials with
   `log stream --style compact --predicate 'sender == "Sandbox"'`.
2. **Keychain**: Claude on macOS stores its login in the Keychain. Check that
   login works with `CLAUDE_CONFIG_DIR` set, and whether the sandbox can read
   *other* Keychain items. Narrow `securityd` access if it can.
3. **TLS**: Go binaries (`gh`, `gcloud`) verify certificates (via `trustd`).
4. **Apple Events**: `open` and `osascript` must fail.
5. **Network**: a raw connect to an outside host fails; an allowed domain works
   through the proxy; an unlisted one gets a 403.
6. **DNS**: `dscacheutil -q host -a name example.com` and a Python
   `socket.getaddrinfo` both work, and `localhost` resolves. Check which
   mDNSResponder service names are needed (e.g. `com.apple.dnssd.service`).
7. Protected paths cannot be written, including files that do not exist yet.
   `~/.xsb/config.toml` cannot be read.
8. A planted `xsb.toml` is refused.
9. `xsb codex` runs with Codex's own sandbox off.
10. Record in `MACOS.md` everything added to `seatbelt_base.sb` and why.

## 14. Design decisions, checks and deferred work

### 14.1 Decisions made

- **Name** `xsb`, free on PyPI as of 2026-09-24 (unclaimed; a name can still be
  refused at upload). XSB is also a Prolog system whose binary is `xsb`;
  accepted.
- **Flat verbs** (`xsb net-allow`), not nested subcommands.
- **Independent repo.** xsb knows nothing about ch_top, worktrees, conda or
  CUDA. ch_top becomes an ordinary user (§11).
- **A project is a root**, defined by the single `xsb.toml` above the current
  directory. There is no project registry.
- **No approval step.** An agent can't change the policy for its next launch:
  config is read-only in the sandbox (I1), a second `xsb.toml` is refused (I2),
  and `~/.xsb` is invisible (I3). What's left is a policy change arriving
  through a git merge, which the diff shows, or a hostile `xsb.toml` in someone
  else's repo, which only matters once others use xsb.
- **`~/.xsb/` on both OSes.** Its policy parts are always hidden (I3).
- **Agent config dirs are chosen in `xsb.toml`**; the default is shared
  `~/.xsb/<agent>`. The trade-off is explained in the `claude_dir` comment in
  `xsb config --defaults`: a shared dir means every project's agent can read the
  others' transcripts and memory, and edit shared settings and hooks (which run
  inside sandboxes only).
- **One `xsb init` for machine and project** (§5.6): it creates `~/.xsb` if
  missing (with a `config.toml` holding only machine-specific detected
  settings), then a comments-only `xsb.toml` (Appendix A.3) that marks the root
  and points to `xsb config --defaults`. No settings are written into
  `xsb.toml`, matching the practice of leaving defaults unstated.
- **Enforced egress is the default**, with `open` as the only other mode.
- **The system prompt core is generated by xsb**; the user and project layers
  are deferred.
- **Linux backend is podman** (the existing, tested design); **macOS backend is
  Seatbelt**. macOS has no private loopback and no GPU.
- **Python ≥ 3.11, standard library only** at runtime.
- **Network lists stay plain text** (appendable with comments intact), and there
  is one pair, in `~/.xsb`, shared by all projects, with **one proxy per user**.
  No per-project lists.
- **A project whose policy is tracked in git symlinks `xsb.toml` to it**
  (Appendix B.2); there's no include mechanism. Relative paths always resolve
  against the root.
- **Merge rules** (§5.3): scalars and lists of scalars replace; lists of tables
  append. Settings that need add-and-remove against a default are tables
  of `name = true|false` (`[env.forward]`, `[protect]`).
- **One set of built-in defaults for every OS**, printed by `xsb config
  --defaults`; Linux-only entries are in a `[[match]]` block.
- **Few knobs:** `--group-add keep-groups` is always passed; missing mount paths
  are always skipped (the backend itself checks `/usr` and `/etc`); `PATH` comes
  unchanged from the launching shell; settings come only from config files and
  flags, not environment variables.
- **One `xsb status` command** for project state, proxy state and health checks
  (§4.1).
- **Built-in defaults cover common development setups** (§5.5): system dirs,
  `/opt`, git config, `~/.local/{bin,lib}`, conda, NVIDIA GPUs, and the agent's
  own program (mounted automatically). Only things that share host state or
  grant write access are opt-in. Every default can be removed. `xsb init` and `xsb status` detect what
  the defaults miss on a given machine.
- **Shell startup files are not loaded in the sandbox;** it inherits the
  launching shell's environment (§5.5, §6.4), so xsb doesn't need
  `CLAUDE_ENV_FILE`.
- **The network lists can be symlinks** from `~/.xsb` into a git repo (for
  Kendrick, the xsb repo; Appendix B.4). `~/.xsb` itself is not a git repo:
  `config.toml` differs per machine.
- **Project settings go in the project's config;** anything machine-specific the
  defaults don't cover goes in `~/.xsb/config.toml` (Appendix B).
- **Goal is "reasonably secure", not airtight.** Where a protection would make
  xsb awkward or fragile for a marginal gain, it's left out. Specifically:
  - **DNS works in every mode and is not filtered** (§7.2): on Linux enforced
    mode through the relay to the host's resolver, on macOS through
    mDNSResponder. Code in the sandbox could leak data through DNS lookups, but
    blocking or filtering DNS would cause confusing failures in ordinary tools.
  - **Protected paths by default cover only the files Claude Code loads on its
    own** (settings, hooks, `.mcp.json`), in the root and its immediate
    subdirectories (§6.3). No deep search of the tree. Creating a *new*
    protected file isn't prevented on Linux (bind mounts can't); projects that
    care protect a whole directory.
  - **macOS: all loopback ports are reachable** from the sandbox, so agents can
    run local servers. This also exposes other services listening on the Mac's
    loopback.
  - **`linux.extra_args` passes raw podman arguments.** It could weaken the
    sandbox (`--privileged`), but it's the user's own config.
  - **Residual risk, documented in the README:** the root holds files the user
    later runs on the host (a worktree's `.venv`, build outputs, test scripts),
    and an agent can modify them. xsb protects the common auto-run files, and
    ch_top protects its toplevel.
- **Claude's auto-updater is off in the sandbox** (`DISABLE_AUTOUPDATER=1`): the
  program is mounted read-only, so updates happen outside.
- **Invariant I4 considers protected paths**, so an editable install of xsb
  from a clone the sandbox can't write is allowed.
- **xsb is a standalone repo, not managed by ch_top**, and used for many
  ch_top-style projects. No clone location is assumed (Kendrick's is
  `~/git/xsb`).
- **`refuse` exists for ch_top's** "run from a feature worktree, not the
  toplevel" check. `[protect] "top"` would already stop an agent in the
  toplevel from changing anything, but `refuse` fails at once with a clear
  message instead of starting an agent that can't do its job.
- **Podman now; bubblewrap maybe later.** bwrap needs no image and is what
  Claude Code's own sandbox uses, but would need its own init process and
  network setup. The Backend interface keeps the option open.
- **Anthropic's `sandbox-runtime` (srt) is not used.** Past experience was poor,
  it is still 0.0.x, and it doesn't fit our model: allowlist reads, GPU, private
  loopback. Its protected-path list and Seatbelt approach were used as
  references.

### 14.2 Checks during implementation

No decision needed: verify each, and apply the stated fallback if it fails.

- **Enforced networking on Linux** (§7.2): the pirate production search runs
  in the sandbox (it uses loopback addresses); podman allows mounting over
  `/etc/resolv.conf` with `--network none`; the proxy process reaches the host's
  resolver (on Ubuntu, systemd-resolved at `127.0.0.53`). *Fallback:* ch_top
  sets `network.mode = "open"` until fixed.
- **Agents without shell startup files** (§6.4): in the sandbox, Claude's Bash
  tool keeps the launching shell's `PATH`, so `which python` finds the venv.
  Same for Codex. *Fallback:* xsb writes a small env file (re-exporting `PATH`
  and `env.set`) and points `CLAUDE_ENV_FILE` at it.
- **CUDA without `LD_LIBRARY_PATH`** (§5.5): the ksgpu and pirate GPU tests pass
  in the sandbox; CUDA should be found through `/etc/ld.so.conf.d/`. *Fallback:*
  ch_top sets `LD_LIBRARY_PATH` in `[env.set]`.
- **Codex** (§8): the flag that turns off approvals and Codex's own sandbox;
  how to pass extra instructions; whether device-code sign-in exists. Fix the
  agent-profile row to match.
- **Supplementary groups** (§2.1): podman on this machine now uses `crun`, and a
  test container with `--group-add keep-groups` shows the host groups
  (`Groups: 65534 65534 ...` in `/proc/self/status`; they appear unmapped but
  still grant access). Verify in xsb's sandbox that a file readable only
  through a group (e.g. `chord-dev`) can be read.
- **`IS_SANDBOX=1`** (§2.1): still accepted by the installed Claude version. It's
  undocumented, so re-check after Claude upgrades.
- **macOS items** are in §13 (Keychain, TLS, DNS, the base profile).

### 14.3 Deferred (not part of this plan)

- User and project additions to the system prompt (`~/.xsb/system_prompt.md`, a
  `system_prompt` key in `xsb.toml`).
- Richer ways to approve a blocked domain: a tmux prompt, holding the request
  until approved, a phone notification (ch_top README Appendix F).
- A filtering DNS forwarder, and a TLS-inspecting proxy.
- A bubblewrap backend for Linux.

## Appendix A: default config

### A.1 `~/.xsb/config.toml` as created by `xsb init`

The header, followed by whatever the detection checks (§5.6) found; if they
found nothing, just the header. Here, one detected entry:

```toml
# User-level xsb config. Optional: every setting has a built-in default.
# Settings here apply to every project; a project's xsb.toml overrides them.
#
#   xsb config --defaults   # print the built-in defaults (copy blocks from here)
#   xsb config              # print the merged config for the current directory
#
# Added by `xsb init` for this machine:

# ~/bin is on your PATH, but the sandbox wouldn't see it.
[[mount]]
path = "~/bin"
mode = "ro"
```

### A.2 Output of `xsb config --defaults`

This is the reference for every setting, and it is the same on every OS. The
`/usr` and `/etc` mounts are in a `[[match]] os = "linux"` block at the end:
macOS gets system paths from its Seatbelt base rules (`seatbelt_base.sb`)
instead. The `[linux]` table and `[[device]]` entries are ignored on macOS. The
agent's own program is not listed: it is mounted automatically (§8).

```toml
# Built-in xsb defaults. This is valid TOML: copy any block into
# ~/.xsb/config.toml or a project's xsb.toml and edit it.
#
# Merge rules: single values and lists of strings replace; [[...]] entries
# append (same path/glob/dir: the later one wins); tables merge key by key.

# Where each agent keeps its login, settings and transcripts. Relative paths
# resolve against the project root. A shared dir means
# every project's agent can read the others' transcripts and memory.
claude_dir = "~/.xsb/claude"
codex_dir  = "~/.xsb/codex"

# Refuse to launch when the current directory is (under) one of these dirs,
# relative to the root. None by default. Example:
#   refuse = [ { dir = "top", reason = "run from a feature worktree" } ]
refuse = []

# Read-only inside the sandbox even when inside the writable root: the files
# Claude Code loads on its own, where an agent's edit (e.g. a new hook) would
# run on the host the next time you start plain `claude` there. Globs
# relative to the root; `*` is one path level, so these cover the root and
# each immediate subdirectory. Set an entry to false to remove it. Always
# protected, whatever this table says: every git repo's config and hooks/,
# and xsb.toml.
[protect]
".claude/settings.json" = true
".claude/settings.local.json" = true
".claude/hooks" = true
".mcp.json" = true
"*/.claude/settings.json" = true
"*/.claude/settings.local.json" = true
"*/.claude/hooks" = true
"*/.mcp.json" = true

# Host paths visible in the sandbox, at the same path. Everything not
# listed is invisible. The root and the agent's dir are always added
# read-write. A missing path is skipped; create = true creates it first (if
# its parent exists); enabled = false removes an entry with the same path
# (including these defaults). The agent's own program is mounted
# automatically and isn't listed here. `xsb init` adds entries for things
# these defaults miss on your machine, and `xsb status` flags later gaps.

# System software outside /usr (CUDA alternatives, vendor tools; Homebrew
# on Apple-silicon Macs).
[[mount]]
path = "/opt"
mode = "ro"
create = false

# Git identity, so commits work. Credentials (~/.git-credentials) stay hidden.
[[mount]]
path = "~/.gitconfig"
mode = "ro"
create = false

[[mount]]
path = "~/.config/git"
mode = "ro"
create = false

# Per-user tools (e.g. direnv) and `pip install --user` packages. Not all of
# ~/.local: ~/.local/share holds desktop-app data (Trash, keyrings, chat
# history).
[[mount]]
path = "~/.local/bin"
mode = "ro"
create = false

[[mount]]
path = "~/.local/lib"
mode = "ro"
create = false

# Conda, at its common install locations; whichever exist are mounted
# (/opt/conda is already covered by /opt).
#
# Shell startup files (~/.bashrc, ~/.zshrc, ...) are deliberately not mounted:
# the sandbox inherits the launching shell's environment instead (§5.5).
[[mount]]
path = "~/miniforge3"
mode = "ro"
create = false

[[mount]]
path = "~/miniconda3"
mode = "ro"
create = false

[[mount]]
path = "~/anaconda3"
mode = "ro"
create = false

[[mount]]
path = "~/.conda"
mode = "ro"
create = false

[[mount]]
path = "~/.condarc"
mode = "ro"
create = false

# Device nodes (Linux only; ignored on macOS). All NVIDIA GPUs, skipped where
# absent. This exposes the GPU driver, a large kernel interface, to the
# sandbox; remove with:  [[device]] glob = "/dev/nvidia*"  enabled = false
[[device]]
glob = "/dev/nvidia*"

[env]
require = []         # names that must be set in the launching shell (also forwarded)

# Variables copied from the launching shell, by name, only if set. All
# others are dropped, since the host environment may contain secrets. Set
# an entry to false to stop forwarding it.
[env.forward]
# terminal and locale
TERM = true
COLORTERM = true
LANG = true
LC_ALL = true
LC_CTYPE = true
TZ = true
# the user's shell (Claude runs its Bash tool with $SHELL; zsh on macOS)
SHELL = true
# editor and pager (Claude's external editor, git commit messages)
EDITOR = true
VISUAL = true
GIT_EDITOR = true
PAGER = true
GIT_PAGER = true
# ssh and tmux markers: Claude checks these to choose OSC 52 escape
# sequences for copy-to-clipboard over ssh/tmux. Only the strings are
# forwarded. The tmux socket is never mounted: the tmux server runs
# outside the sandbox, so its socket would be an escape route.
SSH_TTY = true
SSH_CONNECTION = true
SSH_CLIENT = true
TMUX = true
TMUX_PANE = true
# toolchain: the active conda env, and the library search path as the
# launching shell has it (CUDA is normally found via /etc/ld.so.conf.d)
CONDA_PREFIX = true
LD_LIBRARY_PATH = true

# Extra variables set inside the sandbox, e.g.  VIRTUAL_ENV = "$CWD/.venv"
# Variables xsb sets itself (HOME, USER, PATH, the proxy variables, the
# agent's config-dir variable, XSB_*) cannot be set here.
[env.set]
CUPY_CACHE_DIR = "/tmp/cupy_cache"   # home is read-only, so caches go to /tmp

[network]
# "enforced": the proxy is the only way out of the sandbox.
# "open":     no proxy at all.
# The domain lists are ~/.xsb/net-allow.txt and ~/.xsb/net-deny.txt, shared by
# all projects; each agent's own required domains are always allowed.
mode = "enforced"

[linux]
# Base image. It must match the host's distro, since the host's /usr is
# mounted over it. "auto" means docker.io/library/<ID>:<VERSION_ID> from the
# host's /etc/os-release (e.g. ubuntu:24.04).
image = "auto"
extra_args = []      # extra `podman run` arguments

# Linux only: the host's /usr and /etc make the host's own programs run inside
# the container (the base image supplies only the skeleton). The backend
# refuses to launch if either doesn't exist on the host.
[[match]]
os = "linux"

[[match.mount]]
path = "/usr"
mode = "ro"
create = false

[[match.mount]]
path = "/etc"
mode = "ro"
create = false
```

### A.3 `xsb.toml` as written by `xsb init`

Comments only, so it is equivalent to an empty config. The path is the actual
root.

```toml
# This file marks /home/kmsmith/proj as an xsb root: agents launched with
# `xsb claude` / `xsb codex` from here or below can write in this directory.
# Every setting is optional; with none, the built-in defaults apply.
#
#   xsb config --defaults   # all settings and their defaults (copy blocks from here)
#   xsb config              # the merged config for this directory
```

## Appendix B: config files for ch_top

The ch policy is one file tracked in ch_top (B.1); `~/ch/xsb.toml` is a
symlink to it, which makes `~/ch` the root (B.2).
Machine and toolchain settings (conda, GPUs) are covered by the built-in
defaults (A.2). The only thing left for the user's `~/.xsb/config.toml` (B.3) is
what the defaults deliberately leave out. The network lists are global,
symlinked from `~/.xsb` into the xsb repo (B.4).

### B.1 `~/ch/top/sandbox/ch.toml` (tracked in ch_top)

```toml
# xsb policy for the ch_top layout (~/ch = grouping dir = xsb root).
# ~/ch/xsb.toml is a symlink to this file, so ~/ch is the root and relative
# paths resolve against it. Machine and toolchain settings (conda, GPUs)
# come from xsb's built-in defaults, and the network lists are global
# (~/.xsb/net-*.txt), so neither appears here.

refuse = [ { dir = "top", reason = "the toplevel is the unsandboxed management checkout; run from a feature worktree" } ]

# The toplevel's scripts (git-*, init-*), .claude/ and CLAUDE.md are run
# or loaded by unsandboxed tools, so agents must not be able to edit them.
# The shared .git dirs under top/ stay writable (xsb re-opens them, with
# config and hooks/ pinned read-only), so commits from worktrees still work.
[protect]
"top" = true

# Production storage, so the full-node FRB search can run in the sandbox.
# Skipped on machines where these paths don't exist.
[[mount]]
path = "/scratch2"
mode = "rw"
[[mount]]
path = "/scratch"
mode = "rw"
[[mount]]
path = "/mnt/cs00/data"          # shared NFS export: read-only...
mode = "ro"
[[mount]]
path = "/mnt/cs00/data/$USER"    # ...except this user's subdir (pirate's nfs_dir),
mode = "rw"                      # created if missing on nodes that have the export
create = true

# Launch from a worktree shell where the conda env is active and direnv has
# loaded the worktree's .envrc (venv first on PATH, VIRTUAL_ENV,
# PYTHONSAFEPATH). The sandbox inherits PATH, and these are forwarded, so it
# works from any subdirectory of the worktree.
[env]
require = ["CONDA_PREFIX", "VIRTUAL_ENV"]   # required names are also forwarded

[env.forward]
PYTHONSAFEPATH = true    # don't import from the cwd (source dirs shadow installed packages)
```

### B.2 `~/ch/xsb.toml`: a symlink

`init-toplevel` creates it; there is nothing machine-specific left to put in a
separate file. `claude_dir` and `codex_dir` are left at their defaults
(`~/.xsb/claude`, `~/.xsb/codex`); §11 has the steps for moving today's
`~/ch/claude` there.

```bash
ln -s top/sandbox/ch.toml ~/ch/xsb.toml
```

### B.3 `~/.xsb/config.toml` (the user's, not tracked in ch_top)

Kendrick's. Everything else from today's `fs-allow.txt`, `devices.txt` and
`env-allow.txt` is now a default or no longer needed: `/var` was only there for
the `claude` program (now mounted automatically, §8); `~/.local` is now just
`bin` and `lib`; `~/.bashrc` and `~/.profile` are no longer loaded (§5.5). This
block stays opt-in because it shares host state:

```toml
# Linux GPU machines
[[match]]
os = "linux"
[match.linux]
# CUDA pinned memory and RDMA. WARNING: --ipc host shares the host's IPC
# namespace, including /dev/shm, so other processes' shared memory is
# visible in the sandbox.
extra_args = ["--ipc", "host", "--ulimit", "memlock=-1:-1"]
```

### B.4 Network lists, symlinked into the xsb repo

Kendrick keeps his allow and deny lists in the xsb repo, under `net/`, so they
are tracked in git and shared across machines. That directory is the
maintainer's own policy, not part of the installed package (§12). On each
machine, after cloning xsb (wherever the clone lives; `~/git/xsb` here), and
once for all the CHORD machines, which share an NFS home dir:

```bash
ln -sfn ~/git/xsb/net/net-allow.txt ~/.xsb/net-allow.txt
ln -sfn ~/git/xsb/net/net-deny.txt  ~/.xsb/net-deny.txt
```

`xsb net-allow <domain>` then appends to `~/git/xsb/net/net-allow.txt`, to be
committed in the xsb repo. With the clone outside `~/ch`, ch sandboxes can't see
the lists at all. If a clone is inside some project's root (e.g. while
developing xsb with an agent), xsb pins the real files read-only there (I1). An
agent could still edit its own checkout's copy of the lists and commit it; that
takes effect only when the change is merged, and shows up in the diff.
