import os
import tomllib

from conftest import write
from test_policy import fake_agent, policy, project
from xsb import prompt


def test_prompt_describes_the_launch(make_ctx, home):
    root = project(home, '[protect]\n"top" = true\n[[mount]]\npath = "/opt"\nmode = "rw"\n')
    (root / "top").mkdir()
    bindir, real = fake_agent(home, "claude")
    ctx = make_ctx(cwd=root, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    p = policy(ctx, verb="claude", network="enforced")
    text = prompt.generate(p)
    assert f"the project root, {root}, is read-write" in text
    assert "Also writable: /opt, " in text and str(home / ".xsb" / "claude") in text
    assert "these paths relative to the root: top" in text
    assert "xsb net-allow <domain>" in text and "Never route around a block" in text
    assert 'xsb: egress to "..." is not on the allowlist' in text
    assert f"{root}/xsb.toml" in text
    p2 = policy(ctx, verb="claude", network="open")
    assert "Network: open" in prompt.generate(p2)


def test_prompt_args_per_agent(make_ctx, home):
    root = project(home)
    bindir, real = fake_agent(home, "claude")
    bindir2, real2 = fake_agent(home, "codex", codex_layout=True)
    ctx = make_ctx(cwd=root, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    p = policy(ctx, verb="claude", args=["-p", "hi"])
    prompt.add_to_command(p, "TEXT")
    assert p.command == [real, "--dangerously-skip-permissions", "--append-system-prompt", "TEXT",
                         "-p", "hi"]
    p = policy(ctx, verb="codex", args=["exec", "hi"])
    text = 'multi-line "quoted"\ntext\\with backslash'
    prompt.add_to_command(p, text)
    assert p.command[:3] == [real2, "--dangerously-bypass-approvals-and-sandbox", "-c"]
    assert p.command[4:] == ["exec", "hi"]
    # Codex parses the -c value as TOML: it must round-trip exactly.
    assert tomllib.loads(p.command[3])["developer_instructions"] == text


def test_prompt_cli_without_agent_installed(run, make_ctx, home):
    root = project(home)
    rc, out, err = run(make_ctx(cwd=root), "prompt", "codex")
    assert rc == 0, err
    assert "xsb sandbox" in out and str(home / ".xsb" / "codex") in out
    rc, out, _ = run(make_ctx(cwd=root), "prompt")
    assert str(home / ".xsb" / "claude") in out
