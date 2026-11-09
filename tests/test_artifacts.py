import json

from conftest import GH, PW

from agentspill.artifacts import classify, parse_text_blob, walk_home


def test_classify_repo_paths():
    assert classify(".claude/settings.local.json").local_only
    assert not classify(".claude/settings.json").local_only
    assert classify("packages/api/.mcp.json").agent == "claude-code"
    assert classify(".cursor/mcp.json").expand == "${env:VAR}"
    assert classify(".cursor/rules/db.mdc").agent == "cursor"
    assert classify(".specstory/history/2026-10-01.md").local_only
    assert classify("CLAUDE.local.md").local_only
    assert classify("src/app.py") is None
    assert classify("docs/settings.local.json") is None


def test_parse_mcp_json_contexts():
    raw = json.dumps({"mcpServers": {
        "db": {"command": "npx", "args": ["pg", f"postgres://a:{PW}@h/d"]},
        "gh": {"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH, "GITHUB_HOST": "github.com"}},
        "http": {"url": "https://x/mcp", "headers": {"Authorization": "Bearer abcdefgh12345678"}},
        "ok": {"headers": {"Authorization": "Bearer ${TOK}"}, "env": {"K_API_KEY": "${K}"}}}}, indent=2)
    spots = parse_text_blob(raw, "json")
    got = {(s.context, s.field, s.hit.kind) for s in spots}
    assert got == {("mcp-arg", "mcpServers.db.args", "dsn-password"),
                   ("mcp-env", "mcpServers.gh.env.GITHUB_PERSONAL_ACCESS_TOKEN", "github-token"),
                   ("mcp-header", "mcpServers.http.headers.Authorization", "auth-header")}
    assert all(s.line > 0 for s in spots)


def test_parse_vscode_servers_and_jsonc():
    raw = '{\n // comment\n "servers": {"x": {"env": {"API_TOKEN": "tok-12345678"},},},\n}'
    spots = parse_text_blob(raw, "json")
    assert [(s.context, s.hit.secret) for s in spots] == [("mcp-env", "tok-12345678")]


def test_parse_permissions():
    raw = json.dumps({"permissions": {"allow": ["Bash(npm test)", f"Bash(PGPASSWORD={PW} psql)"]}}, indent=2)
    spots = parse_text_blob(raw, "json")
    assert [(s.context, s.field, s.line) for s in spots] == [("permission-rule", "permissions.allow[1]", 5)]


def test_parse_codex_toml():
    raw = '[mcp_servers.db]\ncommand = "x"\nenv = { DB_PASSWORD = "Real-Pass-123", DB_HOST = "h" }\n'
    spots = parse_text_blob(raw, "toml")
    assert [(s.hit.secret, s.line) for s in spots] == [("Real-Pass-123", 3)]


def test_parse_jsonl_transcript():
    lines = [json.dumps({"message": {"content": f"run PGPASSWORD={PW} psql"}}),
             json.dumps({"toolUseResult": {"stdout": f"TOKEN={GH}\\nok"}})]
    spots = parse_text_blob("\n".join(lines), "jsonl")
    assert {(s.hit.secret, s.line) for s in spots} == {(PW, 1), (GH, 2)}


def test_walk_home(tmp_path):
    (tmp_path / ".claude/projects/p").mkdir(parents=True)
    (tmp_path / ".claude/projects/p/s.jsonl").write_text("{}\n")
    (tmp_path / ".claude.json").write_text("{}")
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text("")
    got = sorted(r for r, _ in walk_home(str(tmp_path)))
    assert got == [".claude.json", ".claude/projects/p/s.jsonl", ".codex/config.toml"]


def test_parse_codex_toml_without_tomllib(monkeypatch):
    import agentspill.artifacts as A
    monkeypatch.setattr(A, "tomllib", None)
    raw = '[mcp_servers.db]\ncommand = "x"\nenv = { DB_PASSWORD = "Real-Pass-123", DB_HOST = "h" }\n'
    spots = A.parse_text_blob(raw, "toml")
    assert [(s.hit.secret, s.line, s.context) for s in spots] == [("Real-Pass-123", 3, "mcp-env")]
