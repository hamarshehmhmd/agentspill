import json
import os
import stat

from conftest import GH, PW, git, write

from agentspill.fix import ENV_FILE, apply_plan, plan_repo_fix
from agentspill.scan import scan_tree


def test_fix_rewrites_mcp_and_permissions(repo):
    write(repo, ".mcp.json", {"mcpServers": {
        "db": {"args": ["pg", f"postgresql://app:{PW}@db/x"]},
        "gh": {"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH}},
        "web": {"url": "https://x", "headers": {"Authorization": "Bearer abcdefgh12345678"}}}})
    write(repo, ".cursor/mcp.json", {"mcpServers": {"s": {"env": {"SUPA_SECRET": "Sup-123456789"}}}})
    write(repo, ".claude/settings.local.json",
          {"permissions": {"allow": ["Bash(npm test)", f"Bash(PGPASSWORD={PW} psql)"], "deny": []}})
    git(repo, "add", ".mcp.json", ".cursor/mcp.json")
    git(repo, "add", "-f", ".claude/settings.local.json")
    git(repo, "commit", "-qm", "x")
    fs, _ = scan_tree(str(repo))
    plan = plan_repo_fix(str(repo), fs)
    # dry run touches nothing
    assert PW in (repo / ".mcp.json").read_text()
    apply_plan(str(repo), plan)
    mcp = json.loads((repo / ".mcp.json").read_text())
    assert mcp["mcpServers"]["db"]["args"][1] == "postgresql://app:${DB_PASSWORD}@db/x"
    assert mcp["mcpServers"]["gh"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"] == "${GITHUB_PERSONAL_ACCESS_TOKEN}"
    assert mcp["mcpServers"]["web"]["headers"]["Authorization"] == "Bearer ${WEB_TOKEN}"
    cur = json.loads((repo / ".cursor/mcp.json").read_text())
    assert cur["mcpServers"]["s"]["env"]["SUPA_SECRET"] == "${env:SUPA_SECRET}"
    perms = json.loads((repo / ".claude/settings.local.json").read_text())
    assert perms["permissions"]["allow"] == ["Bash(npm test)"]
    env = (repo / ENV_FILE).read_text()
    assert f"DB_PASSWORD='{PW}'" in env and f"GITHUB_PERSONAL_ACCESS_TOKEN='{GH}'" in env
    assert stat.S_IMODE(os.stat(repo / ENV_FILE).st_mode) == 0o600
    gi = (repo / ".gitignore").read_text().splitlines()
    assert ".claude/settings.local.json" in gi and ENV_FILE in gi
    tracked = git(repo, "ls-files").stdout.split()
    assert ".claude/settings.local.json" not in tracked
    # re-scan: clean
    fs2, _ = scan_tree(str(repo))
    assert fs2 == []


def test_env_var_name_collision(repo):
    write(repo, ".mcp.json", {"mcpServers": {
        "a": {"env": {"API_KEY": "Key-aaaaaaaa1"}}, "b": {"env": {"API_KEY": "Key-bbbbbbbb2"}}}})
    fs, _ = scan_tree(str(repo))
    plan = plan_repo_fix(str(repo), fs)
    assert set(plan.env_vars) == {"API_KEY", "API_KEY_2"}


def test_fix_manual_for_text_and_no_expansion(repo):
    write(repo, "CLAUDE.md", f"db postgres://u:{PW}@h/db\n")
    write(repo, "claude_desktop_config.json", {"mcpServers": {"x": {"env": {"API_TOKEN": "Tok-123456789"}}}})
    fs, _ = scan_tree(str(repo))
    plan = plan_repo_fix(str(repo), fs)
    assert not plan.edits and len(plan.manual) == 2


def test_fix_keeps_existing_env_file_entries(repo):
    (repo / ENV_FILE).write_text("OTHER='x'\n")
    write(repo, ".mcp.json", {"mcpServers": {"a": {"env": {"API_KEY": "Key-aaaaaaaa1"}}}})
    fs, _ = scan_tree(str(repo))
    apply_plan(str(repo), plan_repo_fix(str(repo), fs))
    body = (repo / ENV_FILE).read_text()
    assert "OTHER='x'" in body and "API_KEY='Key-aaaaaaaa1'" in body
