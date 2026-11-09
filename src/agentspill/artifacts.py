"""Where coding agents write things to disk, and how to read each file."""
from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass

try:  # Python 3.11+
    import tomllib  # type: ignore
except ImportError:  # pragma: no cover - exercised on 3.9/3.10 in CI
    tomllib = None

from .detect import Hit, dedupe, env_value_hit, header_value_hit, text_hits


@dataclass(frozen=True)
class Artifact:
    glob: str        # repo-relative glob (fnmatch on posix path, '**/' prefix allowed)
    agent: str
    what: str
    fmt: str         # json | toml | text | jsonl
    local_only: bool = False   # should never be committed
    expand: str = ""           # env reference syntax the agent supports: "${VAR}", "${env:VAR}", "{env:VAR}"


REPO_ARTIFACTS = [
    Artifact(".claude/settings.local.json", "claude-code", "permission rules (\"don't ask again\")", "json", True, ""),
    Artifact(".claude/settings.json", "claude-code", "shared settings / permission rules", "json", False, ""),
    Artifact(".mcp.json", "claude-code", "project MCP servers", "json", False, "${VAR}"),
    Artifact(".cursor/mcp.json", "cursor", "project MCP servers", "json", False, "${env:VAR}"),
    Artifact(".vscode/mcp.json", "vscode/copilot", "MCP servers", "json", False, "${env:VAR}"),
    Artifact(".gemini/settings.json", "gemini-cli", "settings / MCP servers", "json", False, "${VAR}"),
    Artifact(".codex/config.toml", "codex", "config / MCP servers", "toml", False, ""),
    Artifact(".roo/mcp.json", "roo-code", "MCP servers", "json", False, "${env:VAR}"),
    Artifact(".kilocode/mcp.json", "kilo-code", "MCP servers", "json", False, "${env:VAR}"),
    Artifact("opencode.json", "opencode", "config / MCP servers", "json", False, "{env:VAR}"),
    Artifact(".windsurf/mcp_config.json", "windsurf", "MCP servers", "json", False, "${env:VAR}"),
    Artifact("claude_desktop_config.json", "claude-desktop", "MCP servers (copied into repo)", "json", False, ""),
    Artifact("CLAUDE.local.md", "claude-code", "personal memory file", "text", True),
    Artifact("CLAUDE.md", "claude-code", "memory file", "text"),
    Artifact("AGENTS.md", "codex/agents", "memory / instructions file", "text"),
    Artifact("GEMINI.md", "gemini-cli", "memory file", "text"),
    Artifact(".cursorrules", "cursor", "rules file", "text"),
    Artifact(".cursor/rules/*", "cursor", "rules", "text"),
    Artifact(".claude/agents/*.md", "claude-code", "subagent definitions", "text"),
    Artifact(".claude/commands/*.md", "claude-code", "slash commands", "text"),
    Artifact(".specstory/history/*", "specstory", "saved agent chat history", "text", True),
    Artifact(".aider.chat.history.md", "aider", "chat history", "text", True),
    Artifact(".aider.input.history", "aider", "prompt history", "text", True),
    Artifact(".claude/*.jsonl", "claude-code", "saved transcript", "jsonl", True),
]

# Home-directory stores (relative to $HOME). '**' = any depth.
HOME_ARTIFACTS = [
    Artifact(".claude.json", "claude-code", "global state: MCP servers and per-project prompt history", "json"),
    Artifact(".claude/settings.json", "claude-code", "user settings / permission rules", "json"),
    Artifact(".claude/settings.local.json", "claude-code", "user permission rules", "json"),
    Artifact(".claude/history.jsonl", "claude-code", "prompt history", "jsonl"),
    Artifact(".claude/projects/**.jsonl", "claude-code", "session transcripts", "jsonl"),
    Artifact(".claude/projects/**.txt", "claude-code", "session side files (classifier/error logs)", "text"),
    Artifact(".claude/CLAUDE.md", "claude-code", "user memory file", "text"),
    Artifact(".codex/config.toml", "codex", "config / MCP servers", "toml"),
    Artifact(".codex/history.jsonl", "codex", "prompt history", "jsonl"),
    Artifact(".codex/sessions/**.jsonl", "codex", "session transcripts", "jsonl"),
    Artifact(".gemini/settings.json", "gemini-cli", "settings / MCP servers", "json"),
    Artifact(".gemini/tmp/**.json", "gemini-cli", "chat checkpoints / logs", "json"),
    Artifact(".cursor/mcp.json", "cursor", "global MCP servers", "json"),
    Artifact(".codeium/windsurf/mcp_config.json", "windsurf", "MCP servers", "json"),
    Artifact(".config/Claude/claude_desktop_config.json", "claude-desktop", "MCP servers", "json"),
    Artifact("Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop", "MCP servers", "json"),
    Artifact(".aider.chat.history.md", "aider", "chat history", "text"),
]

_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", ".next",
                 "target", ".mypy_cache", ".pytest_cache"}


def _match(rel: str, glob: str) -> bool:
    rel = rel.replace(os.sep, "/")
    if "**" in glob:
        pre, post = glob.split("**", 1)
        return rel.startswith(pre) and fnmatch.fnmatch(rel[len(pre):], "*" + post)
    return fnmatch.fnmatch(rel, glob)


def classify(rel: str, catalog=REPO_ARTIFACTS) -> Artifact | None:
    rel = rel.replace(os.sep, "/")
    for a in catalog:
        if catalog is REPO_ARTIFACTS:
            if rel == a.glob or rel.endswith("/" + a.glob) or (("*" in a.glob) and (
                    fnmatch.fnmatch(rel, a.glob) or fnmatch.fnmatch(rel, "*/" + a.glob))):
                return a
        elif _match(rel, a.glob):
            return a
    return None


def walk_repo(root: str):
    """Yield (relpath, Artifact) for agent artifacts under root."""
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _EXCLUDE_DIRS]
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, "/")
            a = classify(rel)
            if a:
                yield rel, a


def walk_home(home: str):
    for a in HOME_ARTIFACTS:
        if "**" not in a.glob and "*" not in a.glob:
            p = os.path.join(home, a.glob)
            if os.path.isfile(p):
                yield a.glob, a
            continue
        base = a.glob.split("*", 1)[0].rstrip("/")
        bdir = os.path.join(home, base)
        if not os.path.isdir(bdir):
            continue
        for dp, dns, fns in os.walk(bdir):
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), home).replace(os.sep, "/")
                if _match(rel, a.glob):
                    yield rel, a


# --------------------------------------------------------------------------- parsing

@dataclass
class Spot:
    hit: Hit
    field: str      # JSON-ish path, e.g. permissions.allow[3] or mcpServers.db.env.PGPASSWORD
    context: str    # permission-rule | mcp-env | mcp-header | mcp-arg | mcp-url | env | text
    line: int = 0


def _walk(obj, path, out, parent_key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk(v, f"{path}.{k}" if path else str(k), out, str(k))
    elif isinstance(obj, list):
        if path.endswith("args") and all(isinstance(x, str) for x in obj):
            joined = " ".join(obj)
            for h in text_hits(joined):
                out.append(Spot(h, path, "mcp-arg"))
            return
        for i, v in enumerate(obj):
            _walk(v, f"{path}[{i}]", out, parent_key)
    elif isinstance(obj, str):
        segs = re.split(r"[.\[]", path)
        low = [s.lower().rstrip("]") for s in segs]
        if "permissions" in low:
            ctx = "permission-rule"
            hits = text_hits(obj)
        elif len(low) >= 2 and low[-2] in ("env", "environment"):
            ctx = "mcp-env" if any(x in low for x in ("mcpservers", "servers", "mcp", "mcp_servers")) else "env"
            hits = env_value_hit(parent_key, obj)
        elif len(low) >= 2 and low[-2] in ("headers", "http_headers"):
            ctx = "mcp-header"
            hits = header_value_hit(parent_key, obj)
        elif low[-1] in ("url", "serverurl", "httpurl", "endpoint"):
            ctx = "mcp-url"
            hits = text_hits(obj)
        else:
            ctx = "text"
            hits = text_hits(obj) + (env_value_hit(parent_key, obj) if parent_key and not obj.count(" ") else [])
        for h in dedupe(hits):
            out.append(Spot(h, path, ctx))


def _line_of(raw_lines, secret, start=0):
    enc = json.dumps(secret)[1:-1]
    for i, ln in enumerate(raw_lines):
        if secret in ln or enc in ln:
            return i + 1
    return 0


def parse_text_blob(raw: str, fmt: str) -> list[Spot]:
    lines = raw.splitlines()
    spots: list[Spot] = []
    if fmt == "json":
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
            try:
                data = json.loads(_strip_jsonc(raw))
            except ValueError:
                pass
        if data is not None:
            _walk(data, "", spots)
            for s in spots:
                s.line = _line_of(lines, s.hit.secret)
            return _uniq(spots)
        fmt = "text"
    if fmt == "toml" and tomllib is not None:
        try:
            data = tomllib.loads(raw)
            _walk(data, "", spots)
            for s in spots:
                s.line = _line_of(lines, s.hit.secret)
            return _uniq(spots)
        except Exception:
            fmt = "text"
    if fmt == "toml":  # minimal fallback: key = "value" lines + table headers
        table = ""
        for i, ln in enumerate(lines):
            m = re.match(r"\s*\[([^\]]+)\]", ln)
            if m:
                table = m.group(1)
                continue
            for km in re.finditer(r"([A-Za-z0-9_\-]+)\s*=\s*\"([^\"]*)\"", ln):
                k, v = km.groups()
                hs = env_value_hit(k, v)
                if not hs and re.search(r"headers", table):
                    hs = header_value_hit(k, v)
                for h in hs:
                    spots.append(Spot(h, f"{table}.{k}" if table else k, "mcp-env" if re.search(r"\benv\b", ln + table) else "text", i + 1))
        return _uniq(spots)
    if fmt == "jsonl":
        for i, ln in enumerate(lines):
            if not ln.strip():
                continue
            for h in text_hits(ln.replace("\\n", "\n").replace('\\"', '"')):
                spots.append(Spot(h, f"line {i + 1}", "transcript", i + 1))
        return _uniq(spots)
    for i, ln in enumerate(lines):
        for h in text_hits(ln):
            spots.append(Spot(h, f"line {i + 1}", "text", i + 1))
    return _uniq(spots)


def _uniq(spots):
    seen, out = set(), []
    for s in spots:
        k = (s.hit.secret, s.field)
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


def _strip_jsonc(raw: str) -> str:
    out, i, n, in_str = [], 0, len(raw), False
    while i < n:
        c = raw[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(raw[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True; out.append(c)
        elif raw.startswith("//", i):
            while i < n and raw[i] != "\n":
                i += 1
            continue
        elif raw.startswith("/*", i):
            j = raw.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))
