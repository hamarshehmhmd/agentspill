"""Build a fake home directory with agent stores holding (fake, runtime-generated) secrets.

    python examples/make_demo_home.py /tmp/demo-home
"""
import json
import os
import random
import string
import sys

R = random.Random(42)


def rnd(n):
    return "".join(R.choice(string.ascii_letters + string.digits) for _ in range(n))


def main(h):
    pw = "Prod-" + rnd(12)
    openai = "sk-" + "proj-" + rnd(48)
    anthropic = "sk-" + "ant-api03-" + rnd(90)
    stripe = "sk_" + "live_" + rnd(24)
    os.makedirs(os.path.join(h, ".claude/projects/-home-dev-shop-api"), exist_ok=True)
    os.makedirs(os.path.join(h, ".codex"), exist_ok=True)
    with open(os.path.join(h, ".claude.json"), "w") as fh:
        json.dump({"projects": {"/home/dev/shop-api": {
            "mcpServers": {"prod-db": {"command": "npx", "args": ["-y", "pg-mcp", f"postgres://ro:{pw}@prod-db:5432/app"]}},
            "history": [{"display": f"why does ANTHROPIC_API_KEY={anthropic} return 401?"}]}}}, fh, indent=2)
    lines = [
        {"type": "user", "message": {"role": "user", "content": "check the orders table on prod"}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {
            "command": f"PGPASSWORD={pw} psql -h prod-db -U ro app -c 'select count(*) from orders'"}}]}},
        {"type": "user", "toolUseResult": {"stdout": f"cat .env\nOPENAI_API_KEY={openai}\nNODE_ENV=production"}},
    ]
    with open(os.path.join(h, ".claude/projects/-home-dev-shop-api/5f1c.jsonl"), "w") as fh:
        fh.write("\n".join(json.dumps(x) for x in lines) + "\n")
    with open(os.path.join(h, ".codex/config.toml"), "w") as fh:
        fh.write('[mcp_servers.stripe]\ncommand = "npx"\nargs = ["-y", "@stripe/mcp"]\n'
                 f'env = {{ STRIPE_SECRET_KEY = "{stripe}" }}\n')


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/demo-home")
