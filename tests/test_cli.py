import json
import os
import subprocess
import sys

from conftest import ANTHROPIC, GH, OPENAI, PW, ROOT, git, write

from agentspill.cli import main


def run(*a):
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"), NO_COLOR="1")
    return subprocess.run([sys.executable, "-m", "agentspill", *a], capture_output=True, text=True, env=env)


def test_version():
    p = run("--version")
    assert p.returncode == 0 and "0.1.0" in p.stdout


def test_scan_text_never_prints_secret(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    write(repo, ".claude/settings.local.json", {"permissions": {"allow": [f"Bash(PGPASSWORD={PW} psql)"]}})
    for fmt in ("text", "json", "sarif", "github", "checklist"):
        p = run("scan", str(repo), "--format", fmt)
        assert p.returncode == 1, (fmt, p.stderr)
        assert GH not in p.stdout and PW not in p.stdout, fmt


def test_scan_clean_repo_exit0(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}})
    p = run("scan", str(repo))
    assert p.returncode == 0 and "no secrets found" in p.stdout


def test_fail_on(repo):
    write(repo, ".mcp.json", {"mcpServers": {"db": {"env": {"DB_PASSWORD": PW}}}})
    assert run("scan", str(repo), "--fail-on", "none").returncode == 0
    assert run("scan", str(repo), "--fail-on", "critical").returncode == 0  # untracked shapeless -> high
    git(repo, "add", ".mcp.json")
    git(repo, "commit", "-qm", "x")
    assert run("scan", str(repo), "--fail-on", "critical").returncode == 1


def test_json_shape(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    d = json.loads(run("scan", str(repo), "--format", "json").stdout)
    f = d["findings"][0]
    assert f["kind"] == "github-token" and f["exposure"] == "unignored" and f["rotate"].startswith("https://github.com")
    assert d["artifacts"][0]["path"] == ".mcp.json"


def test_sarif_valid(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    d = json.loads(run("scan", str(repo), "--format", "sarif").stdout)
    r = d["runs"][0]["results"][0]
    assert r["ruleId"] == "github-token" and r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_history_flag_and_remote_url(repo, tmp_path):
    write(repo, ".claude/settings.local.json", {"permissions": {"allow": [f"Bash(mysql -p{PW} db)"]}})
    git(repo, "add", "-f", ".claude/settings.local.json")
    git(repo, "commit", "-qm", "x")
    git(repo, "rm", "-q", ".claude/settings.local.json")
    git(repo, "commit", "-qm", "rm")
    assert run("scan", str(repo)).returncode == 0
    p = run("scan", str(repo), "--history")
    assert p.returncode == 1 and "still in git history" in p.stdout
    bare = tmp_path / "pub.git"
    git(tmp_path, "clone", "-q", "--bare", str(repo), str(bare))
    d = json.loads(run("scan", "file://" + str(bare), "--format", "json").stdout)
    assert [f["exposure"] for f in d["findings"]] == ["pushed"]


def test_fix_cli_dry_run_then_write(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    p = run("fix", str(repo))
    assert "dry run" in p.stdout and GH in (repo / ".mcp.json").read_text()
    p = run("fix", str(repo), "--write")
    assert p.returncode == 0 and GH not in (repo / ".mcp.json").read_text()
    assert run("scan", str(repo)).returncode == 0


def test_home_scan_and_scrub(tmp_path):
    h = tmp_path / "home"
    write(h, ".claude/projects/p/s.jsonl",
          json.dumps({"message": {"content": f"key {OPENAI}"}}) + "\n" + json.dumps({"x": "ok"}) + "\n")
    write(h, ".claude.json", {"mcpServers": {"db": {"args": [f"postgres://u:{PW}@h/d"]}},
                              "projects": {"/p": {"history": [{"display": f"use {ANTHROPIC}"}]}}})
    p = run("home", "--home-dir", str(h))
    assert p.returncode == 1 and OPENAI not in p.stdout
    assert "~/.claude/projects/p/s.jsonl" in p.stdout and "~/.claude.json" in p.stdout
    p = run("home", "--home-dir", str(h), "--scrub")
    assert "would scrub 2" in p.stdout and OPENAI in (h / ".claude/projects/p/s.jsonl").read_text()
    p = run("home", "--home-dir", str(h), "--scrub", "--write")
    t = (h / ".claude/projects/p/s.jsonl").read_text()
    assert OPENAI not in t and "REDACTED" in t
    for ln in t.splitlines():
        json.loads(ln)
    cj = json.loads((h / ".claude.json").read_text())
    assert ANTHROPIC not in json.dumps(cj)
    assert PW in cj["mcpServers"]["db"]["args"][0]  # live config left alone


def test_install_hook_blocks_commit(repo):
    p = run("install-hook", str(repo))
    assert p.returncode == 0
    hook = repo / ".git/hooks/pre-commit"
    assert hook.exists() and os.access(hook, os.X_OK)
    assert run("install-hook", str(repo)).returncode == 1  # refuses to overwrite


def test_staged_cli(repo):
    write(repo, ".mcp.json", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}})
    git(repo, "add", ".mcp.json")
    p = run("scan", "--staged", str(repo))
    assert p.returncode == 1 and "commit blocked" in p.stderr


def test_not_a_directory(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2
