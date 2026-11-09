"""Build a throwaway demo repo full of agent-written secrets (all fake, generated at runtime).

    python examples/make_demo_repo.py /tmp/shop-api

The values are random and deterministic. They are generated instead of stored so this
repository itself never contains anything that looks like a live credential.
"""
import base64
import json
import os
import random
import string
import subprocess
import sys

R = random.Random(20261109)
ALNUM = string.ascii_letters + string.digits


def rnd(n, chars=ALNUM):
    return "".join(R.choice(chars) for _ in range(n))


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")


SECRETS = {
    "pg": "Tr0ub4dor-" + rnd(8),
    "mysql": "s3cret" + rnd(6),
    "bearer": rnd(40),
    "gh": "ghp" + "_" + rnd(36),
    "mcp_bearer": rnd(32),
    "service_role": ".".join([b64({"alg": "HS256", "typ": "JWT"}),
                              b64({"iss": "supabase", "ref": rnd(20).lower(), "role": "service_role",
                                   "iat": 1760000000, "exp": 2075000000}), rnd(43, ALNUM + "-_")]),
    "staging": "stg-" + rnd(12),
}


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)


def git(root, *a, **kw):
    env = dict(os.environ, GIT_AUTHOR_NAME="dev", GIT_AUTHOR_EMAIL="dev@example.com", GIT_COMMITTER_NAME="dev",
               GIT_COMMITTER_EMAIL="dev@example.com", GIT_AUTHOR_DATE=kw.get("date", "2026-10-02T10:00:00"),
               GIT_COMMITTER_DATE=kw.get("date", "2026-10-02T10:00:00"))
    subprocess.run(["git", "-C", root, *a], check=True, capture_output=True, env=env)


def settings_local(rules):
    return json.dumps({"permissions": {"allow": rules, "deny": []}}, indent=2) + "\n"


def main(root):
    S = SECRETS
    os.makedirs(root, exist_ok=True)
    git(root, "init", "-q", "-b", "main")
    # Claude Code's own default: the file is ignored only through a *global* excludes file.
    gexcl = os.path.join(root, "..", os.path.basename(root) + ".global-gitignore")
    with open(gexcl, "w") as fh:
        fh.write("**/.claude/settings.local.json\n")
    git(root, "config", "core.excludesFile", os.path.abspath(gexcl))
    git(root, "config", "user.name", "dev")
    git(root, "config", "user.email", "dev@example.com")
    write(root, "README.md", "# shop-api\n")
    write(root, "app.py", "print('hello')\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init", date="2026-10-01T09:00:00")

    # second laptop / CI checkout, no global ignore: the file gets committed by the agent's commit
    rules_old = ["Bash(npm run test:*)",
                 f"Bash(mysql -u root -p{S['mysql']} shop -e \"show tables\")"]
    write(root, ".claude/settings.local.json", settings_local(rules_old))
    git(root, "add", "-f", ".claude/settings.local.json")
    git(root, "commit", "-qm", "chore: add test scripts\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        date="2026-10-03T16:20:00")
    git(root, "rm", "-q", "--cached", ".claude/settings.local.json")
    git(root, "commit", "-qm", "remove local settings", date="2026-10-04T08:00:00")

    rules = rules_old + [
        f"Bash(PGPASSWORD={S['pg']} psql -h db.internal -U app shop -c \"select count(*) from orders\")",
        f"Bash(curl -s -H \"Authorization: Bearer {S['bearer']}\" https://api.internal.example/v1/health)",
        "Bash(git push:*)",
    ]
    write(root, ".claude/settings.local.json", settings_local(rules))

    mcp = {"mcpServers": {
        "postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
                                                f"postgresql://app:{S['pg']}@db.internal:5432/shop"]},
        "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
                                                 "ghcr.io/github/github-mcp-server"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": S["gh"]}},
        "internal-docs": {"type": "http", "url": "https://mcp.internal.example/mcp",
                          "headers": {"Authorization": f"Bearer {S['mcp_bearer']}"}},
        "linear": {"type": "http", "url": "https://mcp.linear.app/mcp",
                   "headers": {"Authorization": "Bearer ${LINEAR_API_KEY}"}},
    }}
    write(root, ".mcp.json", json.dumps(mcp, indent=2) + "\n")
    cursor = {"mcpServers": {"supabase": {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase"],
                                          "env": {"SUPABASE_URL": "https://abcdefghijklmnop.supabase.co",
                                                  "SUPABASE_SERVICE_ROLE_KEY": S["service_role"]}}}}
    write(root, ".cursor/mcp.json", json.dumps(cursor, indent=2) + "\n")
    write(root, "CLAUDE.md", "# Notes for Claude\n\n- run tests with `npm test`\n"
                             f"- staging DB for manual checks: postgres://admin:{S['staging']}@staging-db.internal/shop\n")
    git(root, "add", ".mcp.json", ".cursor/mcp.json", "CLAUDE.md")
    git(root, "commit", "-qm", "add MCP servers for the team\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        date="2026-10-20T11:00:00")
    return S


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/shop-api")
