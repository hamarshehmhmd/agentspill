import json
import os

from conftest import GH, PW, git, write

import make_demo_repo
from agentspill.scan import scan_history, scan_staged, scan_tree


def rules(*r):
    return {"permissions": {"allow": list(r)}}


def test_tree_exposures(repo, tmp_path):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    git(repo, "add", ".mcp.json")
    git(repo, "commit", "-qm", "mcp")
    write(repo, ".claude/settings.local.json", rules(f"Bash(PGPASSWORD={PW} psql)"))
    fs, arts = scan_tree(str(repo))
    ex = {f.path: f.exposure for f in fs}
    assert ex == {".mcp.json": "committed", ".claude/settings.local.json": "unignored"}
    assert {a["path"] for a in arts} == {".mcp.json", ".claude/settings.local.json"}
    # committed shapeless secrets escalate high -> critical
    assert {f.severity for f in fs} == {"critical", "high"}


def test_global_ignore_only_vs_repo_ignore(repo, tmp_path):
    write(repo, ".claude/settings.local.json", rules(f"Bash(PGPASSWORD={PW} psql)"))
    gi = tmp_path / "global-ignore"
    gi.write_text("**/.claude/settings.local.json\n")
    git(repo, "config", "core.excludesFile", str(gi))
    fs, _ = scan_tree(str(repo))
    assert fs[0].exposure == "global-ignore-only"
    write(repo, ".gitignore", ".claude/settings.local.json\n")
    fs, _ = scan_tree(str(repo))
    assert fs[0].exposure == "ignored"


def test_pushed(repo, tmp_path):
    bare = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(bare))
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "m")
    git(repo, "remote", "add", "origin", str(bare))
    git(repo, "push", "-q", "origin", "main")
    fs, _ = scan_tree(str(repo))
    assert fs[0].exposure == "pushed"


def test_history_finds_deleted_secret_and_coauthor(repo):
    write(repo, ".claude/settings.local.json", rules(f"Bash(mysql -u root -p{PW} db)"))
    git(repo, "add", "-f", ".claude/settings.local.json")
    git(repo, "commit", "-qm", "wip\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
    git(repo, "rm", "-q", ".claude/settings.local.json")
    git(repo, "commit", "-qm", "rm")
    assert scan_tree(str(repo))[0] == []
    hist = scan_history(str(repo))
    assert len(hist) == 1
    f = hist[0]
    assert f.hit.secret == PW and f.exposure == "history" and f.extra["agent_coauthored"]
    assert f.extra["in_head"] is False and f.commit


def test_history_on_other_branch(repo):
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "CLAUDE.md", f"db: postgres://u:{PW}@h/db\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "notes")
    git(repo, "checkout", "-q", "main")
    hist = scan_history(str(repo))
    assert [(f.path, f.hit.kind) for f in hist] == [("CLAUDE.md", "dsn-password")]


def test_staged_blocks_local_only(repo):
    write(repo, ".claude/settings.local.json", rules("Bash(npm test)"))
    git(repo, "add", "-f", ".claude/settings.local.json")
    fs, blocked = scan_staged(str(repo))
    assert fs == [] and blocked[0]["path"] == ".claude/settings.local.json"


def test_staged_scans_index_not_worktree(repo):
    write(repo, ".mcp.json", {"mcpServers": {"x": {"env": {"API_KEY": "Live-Key-9876543"}}}})
    git(repo, "add", ".mcp.json")
    write(repo, ".mcp.json", {"mcpServers": {"x": {"env": {"API_KEY": "${API_KEY}"}}}})
    fs, blocked = scan_staged(str(repo))
    assert [f.hit.secret for f in fs] == ["Live-Key-9876543"] and not blocked


def test_demo_repo_end_to_end(tmp_path):
    root = tmp_path / "shop-api"
    s = make_demo_repo.main(str(root))
    fs, _ = scan_tree(str(root))
    hist = scan_history(str(root))
    found = {f.hit.secret for f in fs} | {f.hit.secret for f in hist}
    assert found == set(s.values())


def test_monorepo_subdir(repo):
    write(repo, "apps/web/.cursor/mcp.json", {"mcpServers": {"s": {"env": {"SECRET_TOKEN": "Abc-123456789"}}}})
    fs, _ = scan_tree(str(repo))
    assert fs[0].path == "apps/web/.cursor/mcp.json"
    fs, _ = scan_tree(str(repo / "apps"))
    assert fs[0].path == "web/.cursor/mcp.json" and fs[0].exposure == "unignored"


def test_skips_node_modules(repo):
    write(repo, "node_modules/pkg/.mcp.json", {"mcpServers": {"s": {"env": {"SECRET_TOKEN": "Abc-123456789"}}}})
    assert scan_tree(str(repo))[0] == []
