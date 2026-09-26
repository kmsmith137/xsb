# macOS handoff: finishing the Seatbelt backend

The macOS backend (`src/xsb/backends/seatbelt.py`) was written and unit-tested
on Linux; it has **not been run on a Mac**. This file is the checklist for the
agent (or person) who completes it there.

## Before you start

- **Run unsandboxed.** Claude Code's `/sandbox` (Bash sandboxing) must be off:
  `sandbox-exec` cannot start inside another Seatbelt sandbox.
- Python ≥ 3.11 with pytest. Install xsb from this clone
  (`pip install -e .`) or run with `PYTHONPATH=src`.
- Run the unit tests first: `pytest tests/unit`. They include the profile
  generator's golden file (`tests/unit/golden/seatbelt_profile.sb`).
- Watch sandbox denials while you work:

  ```bash
  log stream --style compact --predicate 'sender == "Sandbox"'
  ```

- `xsb claude --dry-run` (or `xsb shell --dry-run`) prints the exact profile
  and `sandbox-exec` command for a launch.

## How the backend works

- `profile(policy)` emits `(version 1)`, `(deny default)`, then
  `src/xsb/data/seatbelt_base.sb` (static, **UNVERIFIED**), then generated rules:
  - metadata access to the parent directories of every visible path;
  - one rule per Policy mount, shallower paths first (later rules win in SBPL):
    read-write mounts get `file-read* file-write*`, read-only ones
    `file-read*` plus `(deny file-write* ...)`;
  - `[protect]` globs as `(deny file-write* (regex ...))`, placed by depth, so
    they also cover files that don't exist yet;
  - `(deny file-read* file-write* (subpath "~/.xsb"))`, then the agent dirs of
    this launch re-allowed (I3); the same for the proxy's runtime dir and the
    per-launch `TMPDIR` (I5);
  - network: `enforced` denies `network*` and allows only `localhost` (the
    proxy's TCP port, and the agent's own local servers); `open` allows any IP
    address (but not Unix-domain sockets).
- Every path is resolved with `os.path.realpath` (`/tmp` → `/private/tmp`).
- Launch: the profile is written to the runtime dir (`$TMPDIR/xsb`, or
  `$XDG_RUNTIME_DIR/xsb`), then `/usr/bin/sandbox-exec -f <profile> <command>`
  runs with exactly the Policy's environment, and a per-launch `TMPDIR`
  (`<runtime>/tmp/<pid>`) that is removed, with the profile, after the command
  exits. `XDG_CACHE_HOME` is `$TMPDIR/cache`.
- The proxy listens on `127.0.0.1:<port>` (TCP; port 0 on first start, then
  reused, recorded in `<runtime>/proxy.port`). No relay and no DNS forwarder:
  DNS goes through mDNSResponder, allowed in the base profile.

## Assumptions to check (not verified on Linux)

- **Later rules win** in SBPL when several match the same operation. The whole
  ordering scheme depends on it (e.g. a protected dir with a writable `.git`
  inside, whose `config` is read-only again). Test that nesting directly.
- `#"..."` regex literals are raw strings (backslashes reach the regex engine as
  written), and the regex dialect accepts `[^/]*`, `(/.*)?`, `\.`.
- Whether path lookups need `file-read-metadata` on every parent directory, and
  whether the re-allowed metadata on `~/.xsb` and the runtime dir (after their
  denies) is enough for the agent dir and `TMPDIR` to resolve.
- `(allow network-inbound (local ip "localhost:*"))`: needed for local servers
  to accept connections?
- **Unix-domain sockets are denied in both modes** (open mode allows IP only),
  so the sandbox can't reach e.g. the tmux server's socket, whose path is
  forwarded in `$TMUX`. Tools that use Unix sockets inside allowed paths (a
  test server under the root) may need `(allow network* (local unix-socket
  (subpath ...)) (remote unix-socket (subpath ...)))` for the writable paths;
  check what fails.
- The environment is passed as `sandbox-exec`'s own process environment
  (exactly the Policy's env, not on the command line); check that
  `sandbox-exec` passes it through unchanged and finds a relative command
  (e.g. `bash` for `xsb shell`) through that `PATH`.
- Renaming a parent directory: on Linux, pins needed self-bind mounts so a
  parent rename can't move them. Seatbelt rules are path-based, so a renamed
  parent shouldn't help an agent there, but test it: `mv .claude .x; mkdir
  .claude` and then write `.claude/settings.json` must fail.

## Checklist (plan §13)

1. Grow `seatbelt_base.sb` until `claude`, `git`, `python` and `bash` run
   under `(deny default)`.
2. **Keychain:** Claude on macOS keeps its login in the Keychain. Check that
   login works with `CLAUDE_CONFIG_DIR` set, and whether the sandbox can read
   *other* Keychain items. Narrow the `securityd` access if it can.
3. **TLS:** Go binaries (`gh`, `gcloud`) verify certificates (via `trustd`).
4. **Apple Events:** `open` and `osascript` must fail.
5. **Network:** a raw connect to an outside host fails; an allowed domain works
   through the proxy; an unlisted one gets a 403 naming `xsb net-allow`.
6. **DNS:** `dscacheutil -q host -a name example.com` and a Python
   `socket.getaddrinfo` both work, and `localhost` resolves. Check which
   mDNSResponder service names are needed (e.g. `com.apple.dnssd.service`).
7. Protected paths cannot be written, **including files that do not exist
   yet** (e.g. create `.claude/settings.json` in the root from inside).
   `~/.xsb/config.toml` cannot be read.
8. A planted second `xsb.toml` is refused.
9. `xsb codex` runs with Codex's own sandbox off
   (`--dangerously-bypass-approvals-and-sandbox`).
10. Record here everything added to `seatbelt_base.sb`, and why.

Also worth checking: `xsb status` on a Mac (the prerequisite check looks for
`sandbox-exec`; the detection checks treat the base profile's `subpath`
entries as visible), and the integration-test equivalents: the tests under
`tests/integration` are Linux/podman-only today.

## Additions to `seatbelt_base.sb`

(None yet. Record each one: the rule, what failed without it, and why it is
safe.)
