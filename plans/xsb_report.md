# xsb: implementation report

This reports on implementing `plans/xsb.md`: what was built, what was verified
(and what couldn't be), and where the implementation departs from the plan,
with reasons. Work was done on `cf05` (Ubuntu 24.04, podman 4.9.3 with crun,
pasta, catatonit; conda `dev` env with Python 3.13; host `/usr/bin/python3`
3.12), unsandboxed.

## What was built

The `xsb` package, as laid out in plan §12, committed one phase at a time:

| Commit | Phase |
|---|---|
| `613f849` | 1: skeleton, `config.py`, `xsb init/config/status` (includes the plan) |
| `ada1d7d` | 2: `proxy.py`, `net-allow/net-deny/net-log/net-stop` |
| `a0c55f3` | 3: `policy.py`, podman backend (open mode), `xsb run/shell/claude/codex`, `--dry-run` |
| `ed3c737` | 4: enforced network on Linux (`data/relay.py`, DNS) |
| `d250bb3` | 5: protected paths, I3/I4, end-to-end tests |
| `1d671fc` | 6: `prompt.py`, `xsb prompt`, Codex profile |
| `2188d94` | 7: `backends/seatbelt.py`, `seatbelt_base.sb`, `MACOS.md` |
| `c217102` | README, fixes from my own review pass |
| `ab1c4f2` | `~/.config/git` credential store kept hidden |
| `4f9addb` | fixes from an independent security review (below) |

Modules beyond the plan's list, all small: `context.py` (everything
machine-specific — home, hostname, OS, cwd, environment, `~/.xsb`, runtime
dir — in one object, so tests can build one), `detect.py` (the `xsb init` /
`xsb status` detection checks), `status.py`, `tomlw.py` (a tiny TOML writer;
the standard library only reads TOML).

The built-in defaults are a data file, `data/defaults.toml` (plan Appendix
A.2, with comments). It is both what `xsb config --defaults` prints and what
the code parses, so the two can't drift apart.

Phase 0 was a throwaway prototype in the session's scratch directory (not
committed), as the plan asked.

## What was verified

### Phase 0 (enforced networking prototype)

All checks passed, so §7 stood as designed:

- `podman run --network none` with the proxy's `sock/` directory bind-mounted:
  HTTPS through an in-container relay to the host proxy works; an unlisted
  domain gets a 403.
- A running container survives a proxy restart: requests fail only during the
  gap, then work again (the directory mount, not the socket file).
- A read-only bind mount over `/etc/resolv.conf` is accepted, also with the
  host's `/etc` mounted read-only (where it is a symlink into `/run`).
- DNS through the relay (UDP and TCP) to the proxy, which forwards to
  systemd-resolved (`127.0.0.53`): `getent`, `dig`, `dig +tcp` work;
  `dig @1.1.1.1` and `curl --noproxy '*'` fail.
- Claude's Bash tool keeps the launching shell's `PATH` with no startup files
  mounted (`which python` found the venv). The user ran this check: my
  session's permission classifier blocks me from running
  `claude --dangerously-skip-permissions` with a real login. So the
  `CLAUDE_ENV_FILE` fallback (§14.2) isn't needed.
- Found: AF_UNIX socket paths are limited to ~108 bytes; the runtime dir
  `/run/user/<uid>/xsb` fits, and xsb checks the length.

### Tests

`pytest tests` runs 172 unit tests and 25 integration tests. On `cf05`: all
pass except two opt-in integration tests, skipped (below).

The unit tests cover the plan's whole unit-test list (§12). The integration
tests cover its whole integration list, with the adjustments noted below:

- filesystem: unlisted paths absent, read-only mounts not writable, root
  writable, `~/.xsb` showing only the agent dirs, env limited to the expected
  names, a planted second `xsb.toml` refused, orphans reaped (`--init`), GPU
  device nodes visible, two concurrent sandboxes binding `127.0.0.1:5000`
  (both network modes), supplementary groups attached;
- protected paths: the default Claude files, and a protected main checkout
  whose worktree still commits while `.git/config`, `hooks/`, the worktree's
  `.git` file and `commondir` stay read-only; renaming a parent directory of a
  pin (or of a nested repo's `.git`) fails; symlinked `xsb.toml` and net list
  read-only at their real paths; I3 refusal;
- network: an allowed domain works (HTTPS and plain HTTP), an unlisted one gets
  the 403 with the `xsb net-allow` hint and shows in `xsb net-log`; in
  enforced mode no raw TCP, no UDP, no outside resolver, no `--noproxy`; DNS in
  both modes; the command starts only after the relay listens; a running
  sandbox recovers after `xsb net-stop` and a restart;
- agents: `claude --version` and `codex --version` run from their automatic
  mounts.

Opt-in (skipped by default):

- `XSB_TEST_REAL_CLAUDE=1`: Claude's Bash tool keeps `PATH` (a real Claude
  session with the `~/.xsb/claude` login). I can't run it myself (see phase
  0); the user did the equivalent check by hand.
- `XSB_TEST_GROUP_FILE=<path>`: a file readable only through a supplementary
  group is readable in the sandbox. No such file exists on `cf05`'s local
  filesystems. The test that always runs checks that the supplementary groups
  are attached in the sandbox.

The integration tests never touch the user's real `~/.xsb` or proxy: they run
xsb through `tests/integration/harness.py` with a throwaway `~/.xsb` and
runtime dir, keeping the real `HOME` so podman keeps its config.

### Plan §14.2 checks

| Check | Result |
|---|---|
| Enforced networking: `/etc/resolv.conf` mount, proxy reaches the host resolver | ✓ (phase 0 and integration tests) |
| Enforced networking with pirate's production search | **not done**: that belongs to the ch_top migration (§11), and xsb itself must stay independent of the ch workspace. Until it's done, ch_top can set `network.mode = "open"`. |
| Agents without shell startup files: Claude | ✓ (phase 0, run by the user) |
| Same for Codex | **not verified**: needs a Codex login in `~/.xsb/codex` |
| CUDA without `LD_LIBRARY_PATH` | ✓ by hand: with `LD_LIBRARY_PATH` unset, a CuPy reduction and an `nvcc`-compiled kernel give the right answers inside the sandbox (enforced mode). The ksgpu/pirate test suites weren't run (ch-specific). |
| Codex: no-prompts flag, extra instructions, device sign-in | ✓ against codex-cli 0.156.1: `--dangerously-bypass-approvals-and-sandbox`; `-c developer_instructions="..."` (confirmed with `codex debug prompt-input`: it becomes a developer message); `codex login --device-auth` exists; top-level flags parse before subcommands (`exec`, `resume`, `review`) |
| Supplementary groups (crun) | partly: the groups are attached in the sandbox; reading a group-only file is untested (none found) |
| `IS_SANDBOX=1` | ✓ with Claude 2.1.283 (phase 0: Claude accepted `--dangerously-skip-permissions` as container uid 0). Re-check after upgrades. |

### Not verified

- **macOS, entirely.** The Seatbelt backend and profile generator are
  unit-tested on Linux (golden file, `/tmp` → `/private/tmp`, the `~/.xsb`
  deny, rule ordering), but nothing has run on a Mac. `seatbelt_base.sb` is
  marked UNVERIFIED. `MACOS.md` has the §13 checklist, plus the assumptions the
  generator makes that only a Mac can confirm (later rules win in SBPL, raw
  regex literals, metadata on parent directories, localhost inbound, Unix
  sockets).
- The relay failing at launch (I7) is covered by a unit test (bind failure
  gives a non-zero exit, and the launch is `relay && exec command`), but a
  failing relay wasn't simulated in a real container.
- An interactive `xsb shell` / `xsb claude` session (with a TTY). Everything
  was exercised non-interactively; `-it` is added only when stdin is a TTY.

### Independent security review

After the phases were done, a separate agent reviewed the security-critical
code cold (read-only). Its findings, and what was done (commit `4f9addb`):

| Finding | Outcome |
|---|---|
| On Linux, a pin more than one level below a writable mount can be escaped by renaming a parent directory (the mount moves with it) and recreating the path, e.g. `mv .claude .x; mkdir .claude` then a new `settings.json`. **Confirmed in a container: the host got the agent's file.** | Fixed (approach approved by the user): every directory between a writable mount and a mount inside it is bind-mounted onto itself, so none can be renamed or removed. Tested with the rename attacks. |
| A symlinked `xsb.toml` (the plan's B.2 layout) can be replaced: the link is in the writable root. | Documented as a known gap, **the user's choice** (over refusing symlinks, or recording link targets in `~/.xsb`). |
| Git discovery followed `.git` files and symlinks the agent can write: a planted `sub/.git` could get another repo's store mounted read-write; discovery could also climb above the root. | Fixed: a store is used only if it is inside the root, its `.git` is above the root, or it registers this work tree as a linked worktree. |
| Git files host git runs were still unpinned: submodules with `/` in their names or nested, submodule `.git` files, `config.worktree`, `core.hooksPath` in the work tree. | Fixed (all pinned). An in-progress rebase's todo list (`exec` lines) can't be pinned: documented. |
| Glob characters in the root path (e.g. `proj[old]`) silently disabled protect pins, on both backends. | Fixed: literal parts are escaped before globbing. |
| Host names with control characters reached `proxy.log`, `xsb net-log` and the 403 body. | Fixed: invalid names get a 400; log output is made printable. |
| macOS open mode `(allow network*)` also allowed Unix sockets (e.g. the tmux server). | Fixed: open mode allows IP only. |
| Smaller: bytes sent right after `CONNECT` were dropped; an in-root PATH entry could make xsb mount any host executable as the agent's program; env values visible in `ps`; `*` skipped hidden dirs on Linux but not in the Seatbelt regexes; other projects' `xsb.toml` under read-write mounts. | Fixed, except the last (documented). The env now goes in a private `--env-file` (podman) or the process environment (Seatbelt). |

Found along the way, also fixed in `4f9addb`: podman copies its own
`HTTP(S)_PROXY` into containers by default (now `--http-proxy=false`), and
`xsb net-stop` could leave the proxy running when the kernel delivered SIGTERM
to a worker thread (the proxy now blocks the signals and `sigwait()`s for
them; `stop()` falls back to SIGKILL). I reproduced the second in a
start/stop loop (1 in ~30), and verified the fix over 40 cycles.

## Departures from the plan

Decided with the user during the work:

1. **Git dirs (§6.2 step 4)** cover the repo containing `$CWD`, every directory
   from `$CWD` up to the root that has a `.git`, and `$CWD`'s immediate
   subdirectories. The plan had only `$CWD` and its subdirectories; launching
   from a nested repo (e.g. `<worktree>/<subrepo>`) would then have missed the
   enclosing worktree's repo, whose `.git` may sit under a protected path.
2. **`xsb shell` and `xsb run` mount both agents' config dirs** and set
   `CLAUDE_CONFIG_DIR` / `CODEX_HOME`, so agents run by hand there use the
   sandbox logins (they also get both agents' programs and extra env).
   `xsb claude` / `xsb codex` mount only their own. The user: hiding them
   "would be confusing and doesn't serve a strong purpose".
3. **Codex's release dir is mounted, not just `bin/codex`** (§8). Codex 0.156.1
   is no longer one self-contained binary: its release dir holds `bin/codex`,
   `bin/codex-code-mode-host`, `codex-path/rg` and `codex-resources/`, marked by
   `codex-package.json`. xsb mounts that dir (found up to two levels above the
   binary) read-only. `~/.codex` itself (with `auth.json`) is still never
   mounted.
4. **More git metadata pinned read-only** than `config` and `hooks/`: every
   registered worktree's `.git` file (found through `worktrees/*/gitdir`),
   `worktrees/*/commondir`, and submodules' `config` and `hooks/`. The first
   two can redirect git on the host to a config the agent wrote (e.g.
   `core.fsmonitor`, which runs a command on the next `git status`). A missing
   `hooks/` is created before launch so it can be pinned (otherwise an agent
   could create it and plant a hook). Side effect: `git worktree
   move/remove/repair` of existing worktrees fails inside the sandbox.
5. The real-Claude integration test uses `~/.xsb/claude` and is skipped unless
   it's logged in; it is also opt-in (`XSB_TEST_REAL_CLAUDE=1`), so that I
   never run it by accident.

My own, each small:

6. **`~/.config/git` is not mounted whole**: only its `config`, `ignore` and
   `attributes`. `~/.config/git/credentials` is the git credential store's
   other default location, and the plan's intent was to keep credentials
   hidden.
7. **The proxy never connects to the host's own loopback**, even for an allowed
   name that resolves there: that would reach host services (the sandbox's own
   loopback is separate).
8. **The generated `resolv.conf`** (enforced mode) keeps the host's `search`,
   `domain` and `options` lines after `nameserver 127.0.0.1`, so short
   hostnames resolve as on the host.
9. **DNS replies too big for the client's UDP buffer** (512 bytes, or its EDNS
   size) are turned into truncated (TC) replies by the relay, so the client
   retries over TCP (which the relay also serves). Without this, the proxy's
   TCP retry (§7.1) could hand a UDP client a reply larger than it can take.
10. **Keys of list entries match after expansion**: `[[mount]] path =
    "$HOME/.condarc"` with `enabled = false` removes the default `~/.condarc`.
    (`[protect]` keys still match by exact string, as in the plan.) `$$` is a
    literal `$`.
11. **Pins only where visible and writable**: a protected path, git file,
    config file or list that the sandbox can't see is never mounted (mounting
    it read-only would expose it), and one that is already read-only needs
    nothing.
12. **macOS `XDG_CACHE_HOME` is `$TMPDIR/cache`**, not `/tmp/cache`: on macOS
    `/tmp` is the host's shared `/private/tmp`, not writable in the profile.
    The macOS launch runs `sandbox-exec` as a child rather than `exec`, so the
    per-launch `TMPDIR` and profile can be removed afterwards. The profile also
    allows metadata reads on the parent directories of visible paths.
13. **`xsb status` has two extra checks**: `~/.xsb` accessible to other users
    (it holds agent logins; fix `chmod 700`), and "a launch here would be
    refused" (it builds the policy for `xsb shell`, which is also how the I4
    check is done).
14. **Proxy liveness** uses a `flock` held by the proxy (robust against stale
    pid files and pid reuse); two launches racing to start it end up with one
    proxy. The proxy log rotates at 10 MB.
15. **On Linux the proxy starts only after the policy is accepted**, and
    `--dry-run` never starts it. (On macOS the port must be known first.)
16. **Listing a reserved name in `env.require`** is an error too, like
    `forward` and `set`. `DISABLE_AUTOUPDATER` is reserved (it's agent env).
17. `refuse` applies to every launch verb, including `shell` and `run`.
18. `xsb shell` takes no arguments (use `xsb run`). `xsb prompt` works without
    the agent installed.
19. The plan's `net/` directory (the maintainer's lists, Appendix B.4) isn't
    created: copying ch_top's lists in is a §11 migration step, and they need
    their `sbox-net` wording updated then.
20. From the security review (above): self-bind mounts above pins; git stores
    accepted only when the agent couldn't have planted the pointer to them;
    the extra git pins; escaped glob literals; `*` matching hidden names;
    proxy host-name validation; `--http-proxy=false`; the environment kept
    off command lines; macOS open mode without Unix sockets; agent programs
    not resolved through in-root PATH entries that point outside the root.

## Open issues and suggestions

- **Symlinked `xsb.toml`** (the plan's B.2 layout for ch_top): an agent can
  replace the link with its own `xsb.toml`, which applies at the next launch.
  Kept as a documented gap by the user's choice. If that changes: refuse
  symlinked configs, or record each root's link target in `~/.xsb` and refuse
  a launch when it changed.
- **Symlinked protected files** (README "Known gaps"): if, say,
  `.claude/settings.json` is a symlink, xsb pins the target, but the link sits
  in a writable directory, so an agent can replace it with a file of its own.
  Bind mounts can't pin a symlink itself. Options: refuse to launch when a
  protected path is a symlink, or pin its parent directory. Left as a
  documented gap.
- **The user's migrated `~/.xsb/claude`**: `settings.json` and
  `plugins/known_marketplaces.json` still contain `/home/kmsmith/ch/claude`
  (the §11 `sed` line fixes them), and `~/.xsb` is mode 0775 (`xsb status`
  flags it; `chmod 700 ~/.xsb`). `xsb init` will add the missing
  `codex/`, net lists and `config.toml` without touching `claude/`.
- **Installing**: `pip install -e ~/git/xsb` into the `dev` env (or `pipx`)
  gives the `xsb` command. With an editable install, xsb refuses to launch a
  sandbox whose root contains `~/git/xsb` (I4) unless that path is
  protected.
- **ch_top migration** (§11) is the next step. xsb stays independent of it.
