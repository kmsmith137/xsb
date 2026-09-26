# xsb

`xsb` runs coding agents (Claude Code, Codex) with their permission prompts
turned off, inside an OS-level sandbox that is the real security boundary:

- the agent sees only an allowlist of host paths; everything else is absent;
- it can write only inside one project directory (the **root**) and a few
  paths you list;
- files that the host later loads or runs *outside* the sandbox (git hooks and
  config, Claude settings and hooks) stay read-only, even inside the root;
- all network traffic goes through a domain-allowlisting proxy, and by default
  that proxy is the *only* way out;
- the agent's login and transcripts live in their own config dir
  (`~/.xsb/claude`, `~/.xsb/codex`), separate from your personal `~/.claude`.

The threat it is built for is **prompt injection**: an agent that reads hostile
text and tries to act on it should not be able to read your secrets, widen its
own sandbox, plant code that you later run unsandboxed, or send data to
arbitrary hosts. The goal is "reasonably secure", not airtight; the known gaps
are listed under [Security model](#security-model).

Platforms: Linux (rootless Podman) and macOS (Seatbelt, `sandbox-exec`; not yet
tested on a Mac, see [MACOS.md](MACOS.md)).

## Install

Python ≥ 3.11, no other Python dependencies.

```bash
pipx install /path/to/xsb      # or: pip install /path/to/xsb
```

An editable install (`pip install -e .`) works too, as long as the clone is
outside the root of any project you sandbox, or protected there: xsb refuses to
launch a sandbox that could write its own code (invariant I4, below).

**Linux** needs rootless `podman` with the `crun` runtime, `pasta` and
`catatonit` (on Ubuntu: `apt install podman crun passt catatonit`), and
`/usr/bin/python3` (the in-sandbox network relay runs on the host's Python).
If `podman info --format '{{.Host.OCIRuntime.Name}}'` says `runc`, install crun
and set `runtime = "crun"` under `[engine]` in
`~/.config/containers/containers.conf`: with runc, podman silently ignores
`--group-add keep-groups`, so files you can read only through a group are
unreadable in the sandbox. The first launch pulls a base image matching your
distro (e.g. `docker.io/library/ubuntu:24.04`); your host's `/usr` and `/etc`
are mounted over it, so your own toolchain runs unchanged.

`xsb status` checks all of this.

## Quick start

```bash
cd ~/myproject          # from a shell with your toolchain set up (conda env, venv, direnv)
xsb init                # creates ~/.xsb (first time) and ./xsb.toml, which marks the root
xsb claude              # Claude Code in the sandbox (run /login the first time)
```

When the agent hits a domain that isn't allowed, it stops and tells you; you
approve it on the host and it retries:

```bash
xsb net-allow docs.example.org
```

`xsb shell` opens a bash prompt in the same sandbox, to see what the agent
sees. `xsb claude --dry-run` prints the resolved policy and the exact podman
command (or Seatbelt profile) without launching anything.

## Commands

| Command | |
|---|---|
| `xsb claude [args...]` | Claude Code in the sandbox (`--dangerously-skip-permissions`); args pass through |
| `xsb codex [args...]` | Codex in the sandbox (`--dangerously-bypass-approvals-and-sandbox`); args pass through |
| `xsb shell` | interactive bash in the same sandbox |
| `xsb run -- CMD [args...]` | run a command in the sandbox |
| `xsb init` | set up `~/.xsb` if it's missing, then create a comments-only `xsb.toml` here |
| `xsb config` | the merged config for this directory, each value tagged with where it came from |
| `xsb config --defaults` | every setting's built-in default, as commented TOML you can copy from |
| `xsb status` | project, proxy and health checks; non-zero exit if any check fails |
| `xsb prompt [agent]` | the system-prompt text a launch here would add |
| `xsb net-allow DOMAIN...` | allow domains (appends to `~/.xsb/net-allow.txt`) |
| `xsb net-deny DOMAIN...` | deny domains (appends to `~/.xsb/net-deny.txt`) |
| `xsb net-log` | blocked and denied requests |
| `xsb net-stop` | stop the proxy; the next launch starts it again |

The launch verbs take `--dry-run` and `--network {enforced,open}` right after
the verb; anything after that (or after `--`) goes to the agent or command.
There are no environment-variable overrides: settings come from config files
and flags only.

`xsb shell` and `xsb run` see both agents' config dirs, with
`CLAUDE_CONFIG_DIR` / `CODEX_HOME` set, so `claude` or `codex` run by hand
there use the sandbox logins. `xsb claude` sees only Claude's, `xsb codex` only
Codex's.

## Configuration

### Files

```
~/.xsb/
    config.toml        user-level settings (optional)
    net-allow.txt      domain lists, shared by all projects
    net-deny.txt
    claude/            default CLAUDE_CONFIG_DIR for sandboxed Claude
    codex/             default CODEX_HOME for sandboxed Codex
<root>/xsb.toml        project settings; its presence defines the root
```

`~/.xsb` is the same on Linux and macOS, and is invisible inside every sandbox
except for the agent dirs a launch mounts.

**The root** is found by walking up from the current directory to `$HOME`
(or to `/` outside `$HOME`) and collecting every `xsb.toml`. There must be
exactly one: a nested `xsb.toml` is refused, since an agent could plant one
with a wider policy.

`xsb.toml` may be a symlink, e.g. to a file tracked in git. The root is still
the directory holding the symlink, and relative paths resolve against it. The
network lists can be symlinks too (to share them across machines through a git
repo); `xsb net-allow` writes through the symlink.

### Layers and merging

Later layers override earlier ones:

1. the built-in defaults (`xsb config --defaults`);
2. `~/.xsb/config.toml`;
3. `<root>/xsb.toml`.

Within a file, `[[match]]` blocks are applied after the file's plain keys, in
order, when their conditions hold. How a value merges depends on its kind:

| Kind | Rule |
|---|---|
| single value (`mode = "rw"`) | replaces |
| list of strings (`require = [...]`, `extra_args = [...]`) | replaces |
| list of tables (`[[mount]]`, `[[device]]`, `refuse`) | appends; an entry with the same key (`path`, `glob`, `dir`) replaces the earlier one, and `enabled = false` removes it |
| table (`[env.set]`, `[linux]`, `[protect]`, `[env.forward]`) | merges key by key |

Every list of strings has an empty default, so replacing one never drops a
default silently. Settings whose defaults must be both extendable and
trimmable are tables of `name = true|false` (`[protect]`, `[env.forward]`).
To remove a default `[[mount]]` or `[[device]]`, repeat its key with
`enabled = false`. Unknown keys are an error, to catch typos in
security-relevant config.

**Paths** are relative to the root, in whichever file they appear.
**Variables** are expanded in paths and in `[env.set]` values: `~`, `$HOME`,
`$USER`, `$HOSTNAME` (short name), `$ROOT`, `$CWD` (the launch directory), and
any other `$NAME` or `${NAME}` from the launching environment (`$$` is a
literal `$`). An undefined variable is an error. Globs expand after variables.

### Settings

`xsb config --defaults` prints every setting with its default and an
explanation; this is a summary.

```toml
claude_dir = "~/.xsb/claude"    # the agents' config dirs (login, settings, transcripts)
codex_dir  = "~/.xsb/codex"

# Refuse to launch when the current directory is (under) one of these dirs.
refuse = [ { dir = "top", reason = "run from a feature worktree" } ]

[protect]                       # read-only even inside the root; globs relative to the root,
"top" = true                    # `*` within one path component; false removes a default
"*/.mcp.json" = false

[[mount]]
path = "/data/$USER"            # visible at the same path in the sandbox; globs allowed
mode = "rw"                     # "ro" (default) | "rw"
create = true                   # create it if missing (when its parent exists)

[[device]]                      # Linux: character devices, e.g. GPUs (default /dev/nvidia*)
glob = "/dev/nvidia*"
enabled = false                 # removes the default entry

[env]
require = ["CONDA_PREFIX"]      # refuse to launch unless set; also forwarded
[env.forward]                   # copied from the launching shell by name, if set
PYTHONSAFEPATH = true
[env.set]                       # set in the sandbox
VIRTUAL_ENV = "$CWD/.venv"

[network]
mode = "enforced"               # "enforced" (default) | "open"

[linux]
image = "auto"                  # docker.io/library/<ID>:<VERSION_ID> from /etc/os-release
extra_args = ["--ipc", "host"]  # raw `podman run` arguments

[[match]]                       # conditional settings: all conditions must hold
os = "linux"                    # "linux" | "macos"
hosts = ["gpu*"]                # fnmatch on the short hostname
[[match.mount]]
path = "/scratch"
mode = "rw"
```

The **default mounts** (all read-only, skipped where missing) are `/usr` and
`/etc` (Linux), `/opt`, `~/.gitconfig` and `~/.config/git/{config,ignore,attributes}`
(not the credential store), `~/.local/bin`,
`~/.local/lib`, and conda at its usual places. The agent's own program is
mounted automatically. Shell startup files (`~/.bashrc` etc.) are deliberately
not mounted: the sandbox inherits the launching shell's environment instead.
Anything that shares host state or grants write access is opt-in.

`xsb init` and `xsb status` look for what the defaults miss on your machine,
such as a directory on your `PATH` that the sandbox can't see, and propose
the lines to add to `~/.xsb/config.toml`.

## How the sandbox is built

### Filesystem

Every host path appears at the same path in the sandbox, so paths in logs and
error messages mean the same inside and out. The mounts, in order (when two
cover the same path, the deeper one wins; for identical paths, the later one):

1. built-in and configured mounts (missing paths skipped), and the agent's program;
2. the root, read-write;
3. the agent's config dir, read-write (created if missing);
4. git: the shared `.git` store of the repo containing the current directory,
   of each repo in its parents up to the root, and of each repo in its
   immediate subdirectories, read-write (so commits work from worktrees, even
   when the main checkout is protected), with each store's `config`, `hooks/`,
   `worktrees/*/commondir`, submodule `config` and `hooks/`, and every linked
   worktree's `.git` file pinned read-only;
5. `[protect]` paths, read-only. The defaults are the files Claude Code loads by
   itself in the root and each immediate subdirectory: `.claude/settings.json`,
   `.claude/settings.local.json`, `.claude/hooks`, `.mcp.json`;
6. `xsb.toml` and the network lists, read-only at their real paths.

On Linux a bind mount can only pin a path that exists, so creating a *new*
protected file isn't prevented; protect the whole directory if that matters.
On macOS the protected globs are regexes and cover new files too.

### Environment

The sandbox's environment starts empty. It gets the launching shell's `PATH`
unchanged, the variables in `[env.forward]` (by name, if set), `[env.set]`, and
the variables xsb sets itself: `HOME`, `USER`, `PATH`, the agent's config-dir
variable, the proxy variables, `XDG_CACHE_HOME`, `TMPDIR` (macOS), `IS_SANDBOX`
(Linux, Claude), `DISABLE_AUTOUPDATER` (Claude), and `XSB_ROOT`, `XSB_BACKEND`,
`XSB_NETWORK`. Config can't set these. Launch from a shell that is already set
up (conda env active, direnv loaded); no startup files run in the sandbox.

### Network

One proxy per user serves all sandboxes. It filters HTTPS by the `CONNECT`
hostname (no TLS interception) and plain HTTP by host. It re-reads
`~/.xsb/net-allow.txt` and `net-deny.txt` on every request. An entry matches
the domain and its subdomains, deny wins over allow, and each agent's own
domains (`anthropic.com`, `claude.com`, `claude.ai`; `openai.com`,
`chatgpt.com`) are always allowed. A blocked request gets a 403 naming
`xsb net-allow <domain>`, and is logged (`xsb net-log`). The proxy never
connects to the host's own loopback addresses.

| Mode | Linux | macOS |
|---|---|---|
| `enforced` (default) | `podman --network none`: only the sandbox's own loopback. A relay inside listens on `127.0.0.1:3128` and `127.0.0.1:53` and forwards to the proxy's Unix sockets. No other route out. | Seatbelt allows outbound TCP only to `localhost` (the proxy's port, and local servers). |
| `open` | pasta, no proxy | no network rules, no proxy |

Each Linux sandbox has its own `127.0.0.1`, so agents in different projects can
bind the same ports. Sandboxes keep working across a proxy restart.

**DNS works in every mode and is not filtered**, since many tools look names up
themselves. On Linux in enforced mode, the relay passes queries to the proxy,
which asks the host's resolver; on macOS, mDNSResponder is reachable.

### Agents

The agent's program is found on your `PATH`, its symlinks resolved, and the real
file mounted read-only and run by absolute path. Codex ships as a release dir
(`bin/codex` plus helpers), which is mounted instead; `~/.codex`, which holds
your personal Codex login, is never mounted.

- **Claude:** run `/login` inside `xsb claude` the first time. The login lives
  in `claude_dir` (default `~/.xsb/claude`). Update Claude outside the sandbox;
  the auto-updater is off inside.
- **Codex:** its browser sign-in waits for a callback on `localhost:1455`,
  which can't reach the sandbox, so sign in outside:
  `CODEX_HOME=~/.xsb/codex codex login --device-auth`. Update Codex outside too.

The agents are told about the sandbox in an added system prompt (`xsb prompt`):
what is writable, what is protected and why, and to stop and ask for approval
when the proxy blocks a domain instead of routing around it.

A shared `claude_dir` (the default) means every project's agent can read the
others' transcripts and memory, and edit the shared settings and hooks (which
only run inside sandboxes). Set `claude_dir` per project to separate them.

## Security model

Invariants, each enforced in code and tested:

- **I1**: every config file and network list xsb reads is read-only in the
  sandbox, if visible at all (at its real path, so symlinks don't help).
- **I2**: exactly one `xsb.toml` between the current directory and `$HOME`.
- **I3**: `~/.xsb` is invisible in the sandbox, except the agent dirs of this
  launch; a mount that would expose more (e.g. `~`) is refused.
- **I4**: xsb's own code (its package and the Python running it) is not
  writable from the sandbox.
- **I5**: the proxy's runtime dir (pid file, log, sockets) is invisible.
- **I6**: protected paths are read-only.
- **I7**: fail closed: invalid config, a missing `/usr` or `/etc` on Linux, the
  proxy failing to start, or the relay failing all refuse the launch.

Together, I1 to I3 mean an agent can't change the policy for its next launch.
A policy change can still arrive through a git merge (the diff shows it), or
in someone else's repo's `xsb.toml`.

Known gaps, accepted:

- **The root holds files you later run on the host**: a `.venv`, build
  outputs, test scripts, `.envrc`. An agent can modify them. xsb protects only
  the files that run automatically (Claude settings and hooks, git config and
  hooks); protect more with `[protect]` (e.g. a whole management checkout).
- **Other repos in the root**: git metadata is protected for the repos around
  the current directory; a repo elsewhere in the root (not a parent, not an
  immediate subdirectory) needs `[protect]` entries such as
  `"vendor/*/.git/hooks"`.
- **Git history** in the shared stores is writable (commits need it): an agent
  can rewrite refs of other branches.
- **DNS exfiltration**: code in the sandbox can leak data by looking up names
  like `<data>.attacker.example`. The bandwidth is low. A filtering DNS
  forwarder is the designed fallback (Linux only).
- **Domain fronting**: the proxy sees only the `CONNECT` hostname; an allowed
  CDN-hosted domain can front for others.
- **macOS**: every loopback port is reachable from the sandbox, including other
  local services; there is no private loopback.
- **Creating new protected files** isn't prevented on Linux (see above).
- **Symlinked protected files**: the target is pinned, not the link itself, so
  an agent can replace the link with a file of its own. Don't symlink protected
  files, or protect the directory holding the link.
- **`linux.extra_args`** passes raw podman arguments and can weaken the
  sandbox; it's your own config.
- On Linux the sandbox's uid 0 is your own uid (single-id user namespace), and
  `IS_SANDBOX=1` (undocumented) lets Claude accept
  `--dangerously-skip-permissions` as uid 0; re-check after Claude upgrades.

## Development

```bash
pytest tests/unit             # anywhere, including macOS; no podman needed
pytest tests/integration      # Linux with rootless podman; skipped otherwise
```

The integration tests use a throwaway `~/.xsb` and their own proxy (see
`tests/integration/harness.py`), so they never touch your real setup. They
need internet access (example.com, 1.1.1.1). Two are opt-in:

- `XSB_TEST_REAL_CLAUDE=1` runs a real Claude session with your
  `~/.xsb/claude` login, to check that Claude's Bash tool keeps the launching
  shell's `PATH`;
- `XSB_TEST_GROUP_FILE=<path>` checks that a file readable only through one of
  your supplementary groups (owned by someone else) is readable in the sandbox.

Golden files (`tests/unit/golden/`) hold the podman argv and Seatbelt profile
for sample policies; regenerate with `XSB_UPDATE_GOLDEN=1 pytest tests/unit`.

`python -m xsb.proxy` runs the proxy in the foreground, for debugging.
