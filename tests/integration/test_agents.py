"""Agents in the sandbox (plan §8, §14.2)."""

import os
import shutil

import pytest

REAL_CLAUDE_DIR = os.path.expanduser("~/.xsb/claude")


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_agent_program_runs_from_its_mount(sb, agent):
    """The agent's own program is mounted automatically and runs by path.
    (--version only: no session, no login; the config dirs are throwaway.)"""
    if not shutil.which(agent):
        pytest.skip(f"{agent} not installed")
    r = sb.xsb(agent, "--network", "open", "--version", timeout=120)
    assert r.returncode == 0, r.stderr
    assert any(ch.isdigit() for ch in r.stdout), r.stdout


@pytest.mark.skipif(os.environ.get("XSB_TEST_REAL_CLAUDE") != "1",
                    reason="runs a real Claude session with your ~/.xsb/claude login; "
                           "set XSB_TEST_REAL_CLAUDE=1 to run it")
def test_claude_bash_tool_keeps_launching_path(sb):
    """No shell startup files are mounted, so Claude's Bash tool must keep the
    launching shell's PATH: `which python` finds the venv (plan §14.2)."""
    if not os.path.exists(os.path.join(REAL_CLAUDE_DIR, ".credentials.json")):
        pytest.skip("~/.xsb/claude is not logged in")
    if not shutil.which("claude"):
        pytest.skip("claude not installed")
    # Use the real login instead of the throwaway claude_dir.
    with open(sb.user_config) as f:
        text = f.read()
    with open(sb.user_config, "w") as f:
        f.write(text.replace(f'claude_dir = "{sb.xsb_home}/claude"',
                             f'claude_dir = "{REAL_CLAUDE_DIR}"'))
    venv_bin = os.path.join(sb.root, ".venv", "bin")
    os.makedirs(venv_bin)
    os.symlink("/usr/bin/python3", os.path.join(venv_bin, "python"))
    path = venv_bin + os.pathsep + os.environ["PATH"]
    r = sb.xsb("claude", "-p", "Use your Bash tool to run exactly this command: which python. "
               "Then reply with its raw output only, nothing else.",
               env={"PATH": path}, timeout=600)
    assert r.returncode == 0, r.stderr
    assert os.path.join(venv_bin, "python") in r.stdout, r.stdout
