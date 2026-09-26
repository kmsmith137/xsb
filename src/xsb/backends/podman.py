"""Linux backend: rootless Podman (plan §10.2)."""

from __future__ import annotations

import shutil
import subprocess


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
        if not shutil.which("/usr/bin/python3"):
            problems.append("/usr/bin/python3 not found (runs the in-sandbox network relay); "
                            "install python3")
        if shutil.which("podman"):
            rt = podman_runtime()
            if rt and rt != "crun":
                problems.append(
                    f"podman's runtime is {rt}, not crun: with it `--group-add keep-groups` is "
                    "silently ignored, so files readable only through a group are unreadable in "
                    'the sandbox. Install crun and set runtime = "crun" under [engine] in '
                    "~/.config/containers/containers.conf")
        return problems

    def base_read_paths(self) -> list[str]:
        return []      # the host's /usr and /etc come from mounts (built-in defaults)


def podman_runtime() -> str:
    try:
        r = subprocess.run(["podman", "info", "--format", "{{.Host.OCIRuntime.Name}}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""
