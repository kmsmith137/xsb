"""Linux backend: rootless Podman (plan §10.2).

The host's /usr and /etc are mounted read-only over a base image of the same
distro, so the host's own programs run unchanged; every other host path is
mounted at its own path, so paths mean the same inside and outside.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from importlib import resources

from . import LaunchSpec

RELAY_IN_SANDBOX = "/run/xsb/relay.py"
SOCK_IN_SANDBOX = "/run/xsb/sock"
SANDBOX_PYTHON = "/usr/bin/python3"


def relay_path() -> str:
    return str(resources.files("xsb").joinpath("data/relay.py"))


class PodmanBackend:
    name = "podman"

    def check(self) -> list[str]:
        """Prerequisite problems, each with its fix, for `xsb status`."""
        problems = []
        for prog, why in (("podman", "runs the sandbox"),
                          ("pasta", "network for `open` mode"),
                          ("catatonit", "init process that reaps orphans (podman --init)")):
            if not shutil.which(prog):
                problems.append(f"{prog} not found ({why}); install it with your package manager")
        if not os.access(SANDBOX_PYTHON, os.X_OK):
            problems.append(f"{SANDBOX_PYTHON} not found (runs the in-sandbox network relay); "
                            "install python3")
        if shutil.which("podman"):
            rt = podman_runtime()
            if rt and rt != "crun":
                problems.append(
                    f"podman's runtime is {rt}, not crun: with it `--group-add keep-groups` is "
                    "silently ignored, so files readable only through a group are unreadable in "
                    'the sandbox. Fix: install crun and set runtime = "crun" under [engine] in '
                    "~/.config/containers/containers.conf")
        return problems

    def base_read_paths(self) -> list[str]:
        return []      # the host's /usr and /etc come from mounts (built-in defaults)

    def command(self, policy) -> LaunchSpec:
        """The podman argv for a policy. Pure: reads and writes nothing."""
        enforced = policy.network == "enforced"
        argv = ["podman", "run", "--rm", "--init",
                "--network", "none" if enforced else "pasta",
                "--tmpfs", "/tmp", "--tmpfs", "/run",
                "-w", policy.cwd, "--group-add", "keep-groups"]
        if policy.tty:
            argv.append("-it")
        argv += policy.extra_args
        for k, v in policy.env.items():
            argv += ["-e", f"{k}={v}"]
        for m in policy.mounts:
            argv += ["-v", f"{m.source}:{m.path}:{m.mode}"]
        files = {}
        if enforced:
            resolv = os.path.join(policy.runtime_dir, "resolv.conf")
            files[resolv] = "".join(line + "\n" for line in
                                    ["nameserver 127.0.0.1", *policy.resolv_extra])
            argv += ["-v", f"{relay_path()}:{RELAY_IN_SANDBOX}:ro",
                     "-v", f"{os.path.join(policy.runtime_dir, 'sock')}:{SOCK_IN_SANDBOX}:ro",
                     "-v", f"{resolv}:/etc/resolv.conf:ro"]
        for d in policy.devices:
            argv += ["--device", d]
        argv.append(policy.image)
        if enforced:
            # The relay binds its ports, then goes into the background, so the
            # command never starts before the relay is listening (I7).
            argv += ["/bin/sh", "-c", f'{SANDBOX_PYTHON} -I {RELAY_IN_SANDBOX} && exec "$@"',
                     "xsb"]
        argv += policy.command
        return LaunchSpec(argv=argv, files=files, image=policy.image)

    def launch(self, spec: LaunchSpec) -> int:
        for path, text in spec.files.items():
            tmp = path + f".{os.getpid()}.tmp"
            with open(tmp, "w") as f:
                f.write(text)
            os.replace(tmp, path)
        ensure_image(spec.image)
        return run_foreground(spec.argv)


def podman_runtime() -> str:
    try:
        r = subprocess.run(["podman", "info", "--format", "{{.Host.OCIRuntime.Name}}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def ensure_image(image: str):
    """Pull the base image on first use."""
    r = subprocess.run(["podman", "image", "exists", image], capture_output=True)
    if r.returncode != 0:
        print(f"xsb: pulling the base image {image} (first use)", file=sys.stderr)
        subprocess.run(["podman", "pull", image], check=True)


def run_foreground(argv: list[str]) -> int:
    proc = subprocess.Popen(argv)
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue          # the terminal delivers Ctrl-C to podman too


def format_argv(argv: list[str], image: str = "") -> str:
    """The argv as a shell command: one option per line, then the image, then
    the command run in the sandbox."""
    head, tail = argv, []
    if image and image in argv:
        i = argv.index(image)
        head, tail = argv[:i], argv[i:]
    out, line = [], []
    for a in head:
        if a.startswith("-") and line:
            out.append(" ".join(line))
            line = []
        line.append(shlex.quote(a))
    out.append(" ".join(line))
    if tail:
        out.append(shlex.quote(tail[0]))
        if tail[1:]:
            out.append(shlex.join(tail[1:]))
    return " \\\n    ".join(out)
