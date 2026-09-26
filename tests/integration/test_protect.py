"""Protected paths and the git layout (plan §6.2, §6.3)."""

import os
import subprocess

GIT = ["git", "-c", "user.name=xsb-test", "-c", "user.email=xsb-test@example.invalid",
       "-c", "init.defaultBranch=main"]


def git(*args, cwd):
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"})


def test_default_protected_files(sb):
    for rel in (".claude/settings.json", ".mcp.json", "wt/.claude/settings.local.json",
                ".claude/hooks/pre.sh"):
        sb.write(rel, "{}")
    r = sb.run("""
        for f in .claude/settings.json .mcp.json wt/.claude/settings.local.json; do
            echo x >> "$f" 2>/dev/null && echo "WROTE $f" || echo "protected $f"
        done
        touch .claude/hooks/new.sh 2>/dev/null && echo "WROTE hooks" || echo "protected hooks"
        touch .claude/other.json && echo "other-writable"
    """)
    assert r.returncode == 0, r.stderr
    assert "WROTE" not in r.stdout, r.stdout
    assert r.stdout.count("protected") == 4 and "other-writable" in r.stdout


def test_git_layout_commit_works_config_hooks_pinned(sb):
    """<root>/top: main checkout, protected (holds the shared .git);
    <root>/dev: its worktree. Commits from dev work; config, hooks and the
    worktree pointers can't be changed."""
    with open(os.path.join(sb.root, "xsb.toml"), "a") as f:
        f.write('\n[protect]\n"top" = true\n')
    top = os.path.join(sb.root, "top")
    os.makedirs(top)
    git("init", "-q", cwd=top)
    git("commit", "-q", "--allow-empty", "-m", "first", cwd=top)
    git("worktree", "add", "-q", os.path.join(sb.root, "dev"), "-b", "dev", cwd=top)
    dev = os.path.join(sb.root, "dev")
    r = sb.run(f"""
        {' '.join(GIT)} commit -q --allow-empty -m from-sandbox && echo commit-ok
        echo x >> ../top/.git/config 2>/dev/null && echo CONFIG-WRITTEN || echo config-pinned
        touch ../top/.git/hooks/post-commit 2>/dev/null && echo HOOK-PLANTED || echo hooks-pinned
        echo 'gitdir: /tmp/evil' > .git 2>/dev/null && echo DOTGIT-WRITTEN || echo dotgit-pinned
        echo /tmp/evil > ../top/.git/worktrees/dev/commondir 2>/dev/null \\
            && echo COMMONDIR-WRITTEN || echo commondir-pinned
        touch ../top/newfile 2>/dev/null && echo TOP-WRITTEN || echo top-protected
    """, cwd=dev)
    assert r.returncode == 0, r.stderr
    for word in ("commit-ok", "config-pinned", "hooks-pinned", "dotgit-pinned",
                 "commondir-pinned", "top-protected"):
        assert word in r.stdout, (word, r.stdout, r.stderr)
    log = subprocess.run(["git", "log", "--format=%s", "-1", "dev"], cwd=top,
                         capture_output=True, text=True).stdout.strip()
    assert log == "from-sandbox"


def test_symlinked_config_and_list_readonly(sb):
    # xsb.toml -> policies/p.toml inside the writable root.
    policies = os.path.join(sb.root, "policies")
    os.makedirs(policies)
    os.replace(os.path.join(sb.root, "xsb.toml"), os.path.join(policies, "p.toml"))
    os.symlink("policies/p.toml", os.path.join(sb.root, "xsb.toml"))
    # ~/.xsb/net-allow.txt -> <root>/netlists/allow.txt
    lists = os.path.join(sb.root, "netlists")
    os.makedirs(lists)
    allow = os.path.join(sb.xsb_home, "net-allow.txt")
    os.replace(allow, os.path.join(lists, "allow.txt"))
    os.symlink(os.path.join(lists, "allow.txt"), allow)
    r = sb.run("""
        echo x >> policies/p.toml 2>/dev/null && echo CONFIG-WRITTEN || echo config-ro
        echo x >> netlists/allow.txt 2>/dev/null && echo LIST-WRITTEN || echo list-ro
        touch netlists/other && echo dir-writable
    """)
    assert r.returncode == 0, r.stderr
    assert "config-ro" in r.stdout and "list-ro" in r.stdout and "dir-writable" in r.stdout
    # net-allow on the host still writes through the symlink.
    r = sb.xsb("net-allow", "example.org")
    assert r.returncode == 0 and "example.org" in open(os.path.join(lists, "allow.txt")).read()


def test_xsb_home_invisible_except_agent_dirs(sb):
    r = sb.run(f"ls -A {sb.xsb_home}")
    assert r.returncode == 0, r.stderr
    assert set(r.stdout.split()) == {"claude", "codex"}


def test_i3_refused(sb):
    with open(os.path.join(sb.root, "xsb.toml"), "a") as f:
        f.write(f'\n[[mount]]\npath = "{os.path.dirname(sb.xsb_home)}"\nmode = "ro"\n')
    r = sb.xsb("run", "--", "true")
    assert r.returncode == 1 and "(I3)" in r.stderr
