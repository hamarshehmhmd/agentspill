"""Rewrite agent files so secrets stop living in them.

Everything is a dry run unless write=True.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field

from .artifacts import HOME_ARTIFACTS, REPO_ARTIFACTS, classify
from .detect import redact
from .scan import Finding, git, ignore_source, is_repo

ENV_FILE = ".agentspill.env"
REDACTED = "[REDACTED-by-agentspill]"


@dataclass
class Plan:
    edits: dict = field(default_factory=dict)        # path -> new content
    actions: list = field(default_factory=list)      # human-readable lines
    manual: list = field(default_factory=list)       # things we can't safely rewrite
    env_vars: dict = field(default_factory=dict)     # VAR -> secret (written to .agentspill.env)
    gitignore_add: list = field(default_factory=list)
    untrack: list = field(default_factory=list)


def _var_name(f: Finding, used: dict) -> str:
    segs = [s.rstrip("]") for s in re.split(r"[.\[]", f.field) if s]
    server = ""
    for i, s in enumerate(segs):
        if s.lower() in ("mcpservers", "servers", "mcp", "mcp_servers") and i + 1 < len(segs):
            server = segs[i + 1]
            break
    if f.context in ("mcp-env", "env") and segs:
        base = segs[-1]
    else:
        kind = {"dsn-password": "PASSWORD", "auth-header": "TOKEN", "url-query-secret": "KEY",
                "basic-auth": "PASSWORD", "env-assignment": f.hit.note or "SECRET",
                "cli-flag-secret": (f.hit.note or "SECRET").lstrip("-")}.get(f.hit.kind, f.hit.kind)
        base = f"{server}_{kind}" if server else kind
    name = re.sub(r"[^A-Za-z0-9]+", "_", base).strip("_").upper() or "SECRET"
    if name[0].isdigit():
        name = "_" + name
    if name in used and used[name] != f.hit.secret:
        n = 2
        while f"{name}_{n}" in used and used[f"{name}_{n}"] != f.hit.secret:
            n += 1
        name = f"{name}_{n}"
    used[name] = f.hit.secret
    return name


def _get(obj, segs):
    for s in segs:
        obj = obj[int(s)] if isinstance(obj, list) else obj[s]
    return obj


def _segs(field):
    out = []
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", field):
        out.append(part[1:-1] if part.startswith("[") else part)
    return out


def plan_repo_fix(root: str, findings: list[Finding]) -> Plan:
    root = os.path.abspath(root)
    plan = Plan()
    repo = is_repo(root)
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.path, []).append(f)
    for rel, fs in sorted(by_file.items()):
        art = classify(rel)
        if art is None:
            continue
        p = os.path.join(root, rel)
        if art.fmt != "json":
            for f in fs:
                plan.manual.append(f"{rel}:{f.line}: {f.hit.kind} {redact(f.hit.secret)} in a {art.what}; "
                                   f"edit by hand{' (use env_vars / bearer_token_env_var in Codex)' if art.fmt == 'toml' else ''}")
            continue
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            for f in fs:
                plan.manual.append(f"{rel}:{f.line}: {f.hit.kind} {redact(f.hit.secret)}: file is not strict JSON, edit by hand")
            continue
        changed = False
        removed = []
        for f in fs:
            segs = _segs(f.field)
            if f.context == "permission-rule":
                lst = _get(data, segs[:-1])
                if isinstance(lst, list):
                    for i, item in enumerate(list(lst)):
                        if isinstance(item, str) and f.hit.secret in item:
                            lst.remove(item)
                            removed.append(item)
                            changed = True
                            plan.actions.append(f"{rel}: removed permission rule {redact_rule(item, f.hit.secret)} "
                                                "(Claude Code will ask again next time)")
                continue
            if not art.expand:
                plan.manual.append(f"{rel}:{f.line}: {f.hit.kind} {redact(f.hit.secret)} at {f.field}: "
                                   f"{art.agent} has no env-variable expansion here; load it from the environment "
                                   "or a wrapper script")
                continue
            var = _var_name(f, plan.env_vars)
            ref = art.expand.replace("VAR", var)
            try:
                parent = _get(data, segs[:-1]) if segs else None
                key = segs[-1]
                if isinstance(parent, list):
                    key = int(key)
                val = parent[key]
            except (KeyError, IndexError, TypeError, ValueError):
                plan.manual.append(f"{rel}:{f.line}: could not locate {f.field}")
                continue
            if isinstance(val, list):  # args
                new = [x.replace(f.hit.secret, ref) if isinstance(x, str) else x for x in val]
            else:
                new = val.replace(f.hit.secret, ref)
            if new != val:
                parent[key] = new
                changed = True
                plan.actions.append(f"{rel}: {f.field} now reads {ref} (value moved to {ENV_FILE})")
        if changed:
            plan.edits[rel] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    # local-only files: make the repo ignore them, untrack if committed
    if repo:
        seen = set()
        for f in findings:
            art = classify(f.path)
            if art and art.local_only and f.path not in seen:
                seen.add(f.path)
                ign, src = ignore_source(root, f.path)
                if src != "repo":
                    plan.gitignore_add.append(f.path if "/" not in art.glob or "*" in art.glob else art.glob)
                if f.exposure in ("committed", "pushed"):
                    plan.untrack.append(f.path)
        if plan.env_vars:
            ign, src = ignore_source(root, ENV_FILE)
            if src != "repo":
                plan.gitignore_add.append(ENV_FILE)
        plan.gitignore_add = sorted(set(plan.gitignore_add))
        for g in plan.gitignore_add:
            plan.actions.append(f".gitignore: add {g}")
        for u in plan.untrack:
            plan.actions.append(f"git rm --cached {u} (stays on disk, leaves the index; history still has it)")
    elif plan.env_vars:
        plan.actions.append(f"not a git repo: make sure {ENV_FILE} is never committed")
    if plan.env_vars:
        plan.actions.append(f"{ENV_FILE}: {len(plan.env_vars)} variable(s), mode 600 "
                            f"(load with: set -a; . ./{ENV_FILE}; set +a, or your secret manager)")
    return plan


def redact_rule(rule: str, secret: str) -> str:
    return rule.replace(secret, redact(secret))


def _atomic_write(path, content, mode=None):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".agentspill-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    if mode is None and os.path.exists(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
    os.chmod(tmp, mode if mode is not None else 0o644)
    os.replace(tmp, path)


def apply_plan(root: str, plan: Plan):
    root = os.path.abspath(root)
    for rel, content in plan.edits.items():
        _atomic_write(os.path.join(root, rel), content)
    if plan.env_vars:
        p = os.path.join(root, ENV_FILE)
        existing = {}
        if os.path.exists(p):
            for ln in open(p, encoding="utf-8"):
                if "=" in ln and not ln.startswith("#"):
                    k, v = ln.rstrip("\n").split("=", 1)
                    existing[k] = v
        for k, v in plan.env_vars.items():
            existing[k] = _shell_quote(v)
        body = "# written by agentspill: secrets moved out of agent config files. Never commit this file.\n" + \
            "# Rotate them anyway: they were already on disk in plain text.\n" + \
            "".join(f"{k}={v}\n" for k, v in existing.items())
        _atomic_write(p, body, 0o600)
    if plan.gitignore_add:
        gi = os.path.join(root, ".gitignore")
        cur = open(gi, encoding="utf-8").read() if os.path.exists(gi) else ""
        add = [g for g in plan.gitignore_add if g not in cur.splitlines()]
        if add:
            sep = "" if not cur or cur.endswith("\n") else "\n"
            _atomic_write(gi, cur + sep + "# coding-agent local files (agentspill)\n" + "".join(a + "\n" for a in add))
    for rel in plan.untrack:
        git(root, "rm", "--cached", "--quiet", "--", rel)


def _shell_quote(v: str) -> str:
    return "'" + v.replace("'", "'\"'\"'") + "'"


# --------------------------------------------------------------------------- home scrub

SCRUBBABLE_FMTS = ("jsonl", "text")


def plan_scrub(home: str, findings: list[Finding]):
    """Redact secrets from local transcripts / histories (not live configs)."""
    by_file: dict[str, set] = {}
    json_hist: dict[str, set] = {}
    skipped = []
    for f in findings:
        rel = f.path[2:] if f.path.startswith("~/") else f.path
        art = None
        for a in HOME_ARTIFACTS:
            from .artifacts import _match
            if _match(rel, a.glob):
                art = a
                break
        if art is None:
            continue
        if art.fmt in SCRUBBABLE_FMTS or rel.startswith(".gemini/tmp/"):
            by_file.setdefault(rel, set()).add(f.hit.secret)
        elif art.fmt == "json" and _is_history_field(f.field):
            json_hist.setdefault(rel, set()).add(f.hit.secret)
        else:
            skipped.append(f)
    edits = {}
    for rel, secrets in by_file.items():
        p = os.path.join(home, rel)
        try:
            raw = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        new = raw
        n = 0
        for s in sorted(secrets, key=len, reverse=True):
            enc = json.dumps(s)[1:-1]
            for needle in {s, enc}:
                n += new.count(needle)
                new = new.replace(needle, REDACTED)
        if rel.endswith(".jsonl"):
            ok = True
            for ln in new.splitlines():
                if ln.strip():
                    try:
                        json.loads(ln)
                    except ValueError:
                        ok = False
                        break
            if not ok:
                continue
        if new != raw:
            edits[rel] = (new, n)
    for rel, secrets in json_hist.items():
        p = os.path.join(home, rel)
        try:
            data = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        count = [0]

        def walk(o, path):
            if isinstance(o, dict):
                return {k: walk(v, f"{path}.{k}") for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v, f"{path}[{i}]") for i, v in enumerate(o)]
            if isinstance(o, str) and _is_history_field(path):
                for sec in secrets:
                    if sec in o:
                        count[0] += o.count(sec)
                        o = o.replace(sec, REDACTED)
            return o

        new = walk(data, "")
        if count[0]:
            edits[rel] = (json.dumps(new, indent=2, ensure_ascii=False) + "\n", count[0])
    return edits, skipped


def _is_history_field(field: str) -> bool:
    return bool(re.search(r"(?i)(^|\.)(history|pastedcontents)(\[|\.|$)", field))


def apply_scrub(home, edits):
    for rel, (content, _) in edits.items():
        _atomic_write(os.path.join(home, rel), content)
