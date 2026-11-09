import json
import os
import random
import string
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "examples"))

_R = random.Random(7)


def rnd(n, chars=string.ascii_letters + string.digits):
    return "".join(_R.choice(chars) for _ in range(n))


# fake credentials assembled at runtime so the repo never stores token-shaped strings
GH = "gh" + "p_" + rnd(36)
AWS = "AK" + "IA" + rnd(16, string.ascii_uppercase + string.digits)
OPENAI = "sk-" + "proj-" + rnd(48)
ANTHROPIC = "sk-" + "ant-api03-" + rnd(90)
STRIPE = "sk_" + "live_" + rnd(24)
PW = "Pg-" + rnd(14)


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True, env=env)


@pytest.fixture(autouse=True)
def _isolate_git(monkeypatch, tmp_path_factory):
    # no user/global gitignore leaks into tests
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "t")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "t@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "t")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "t@example.com")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "README.md").write_text("x\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "init")
    return r


def write(root, rel, content):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content if isinstance(content, str) else json.dumps(content, indent=2))
    return p
