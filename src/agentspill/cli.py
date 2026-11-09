"""agentspill command line."""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys

from . import __version__, report
from .detect import SEVERITIES, redact, sev_rank
from .fix import ENV_FILE, apply_plan, apply_scrub, plan_repo_fix, plan_scrub
from .scan import clone_remote, is_repo, scan_history, scan_home, scan_staged, scan_tree, sort_findings

HOOK = """#!/bin/sh
# agentspill pre-commit hook: block secrets in coding-agent files
exec agentspill scan --staged
"""


def _color(args):
    if args.color == "always":
        return True
    if args.color == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _emit(args, findings, artifacts=None, title="", home_mode=False, extra=None):
    fmt = args.format
    if fmt == "json":
        print(report.as_json(findings, artifacts, extra))
    elif fmt == "sarif":
        print(report.sarif(findings))
    elif fmt == "github":
        s = report.github(findings)
        if s:
            print(s)
    elif fmt == "checklist":
        print(report.checklist(findings), end="")
    else:
        print(report.text(findings, artifacts, _color(args), title, home_mode))


def _exit(args, findings, blocked=()):
    if blocked:
        return 1
    if args.fail_on == "none":
        return 0
    th = sev_rank(args.fail_on)
    return 1 if any(sev_rank(f.severity) >= th for f in findings) else 0


def _is_url(s):
    return s.startswith(("https://", "http://", "ssh://", "git@", "file://")) or s.endswith(".git") and ":" in s


def cmd_scan(args):
    if args.staged:
        findings, blocked = scan_staged(args.paths[0] if args.paths else ".")
        findings = sort_findings(findings)
        if args.format == "text":
            for b in blocked:
                print(report._c("high", "blocked:", _color(args)) +
                      f" {b['path']} is a local-only {b['agent']} file ({b['what']}); unstage it "
                      f"(git restore --staged {b['path']}) and add it to .gitignore")
        _emit(args, findings, title="agentspill: staged agent files")
        rc = _exit(args, findings, blocked)
        if rc and args.format == "text":
            print("commit blocked by agentspill (bypass once with: git commit --no-verify)", file=sys.stderr)
        return rc
    all_f, all_a = [], []
    tmpdirs = []
    try:
        targets = args.paths or ["."]
        for t in targets:
            if _is_url(t):
                tmp, dest = clone_remote(t)
                tmpdirs.append(tmp)
                fs = scan_history(dest, args.max_commits)
                for f in fs:
                    f.path = f.path
                all_f.extend(fs)
                continue
            if not os.path.isdir(t):
                print(f"agentspill: not a directory: {t}", file=sys.stderr)
                return 2
            fs, arts = scan_tree(t)
            if args.history:
                if not is_repo(t):
                    print(f"agentspill: --history needs a git repo: {t}", file=sys.stderr)
                    return 2
                hist = scan_history(t, args.max_commits)
                seen = {(f.hit.fingerprint, f.path) for f in hist}
                fs = hist + [f for f in fs if (f.hit.fingerprint, f.path) not in seen]
            if len(targets) > 1:
                for f in fs:
                    f.path = os.path.join(t, f.path)
                for a in arts:
                    a["path"] = os.path.join(t, a["path"])
            all_f.extend(fs)
            all_a.extend(arts)
        if args.home is not None:
            all_f.extend(scan_home(args.home or os.path.expanduser("~")))
    except RuntimeError as e:
        print(f"agentspill: {e}", file=sys.stderr)
        return 2
    finally:
        for d in tmpdirs:
            shutil.rmtree(d, ignore_errors=True)
    if args.min_severity:
        th = sev_rank(args.min_severity)
        all_f = [f for f in all_f if sev_rank(f.severity) >= th]
    all_f = sort_findings(all_f)
    _emit(args, all_f, all_a, title="" if args.format != "text" else "agentspill scan")
    return _exit(args, all_f)


def cmd_home(args):
    home = args.home_dir or os.path.expanduser("~")
    findings = sort_findings(scan_home(home))
    if args.scrub:
        edits, skipped, recent = plan_scrub(home, findings, args.skip_recent)
        total = sum(n for _, n in edits.values())
        print(f"{'scrubbing' if args.write else 'would scrub'} {total} occurrence(s) in {len(edits)} transcript/history "
              f"file(s):")
        for rel, (_, n) in sorted(edits.items()):
            print(f"  ~/{rel}: {n}")
        for rel in recent:
            print(f"skipped ~/{rel}: modified in the last {args.skip_recent:g} min (live session?); "
                  "rerun after it ends or pass --skip-recent 0")
        if skipped:
            print(f"left alone: {len(skipped)} secret(s) in live config files (move them to env vars by hand):")
            for f in skipped:
                print(f"  {f.path}:{f.line} {f.hit.kind} {redact(f.hit.secret)}")
        if args.write:
            apply_scrub(home, edits)
            print("done. Rotate these secrets anyway: they sat on disk in plain text.")
        else:
            print("dry run: add --write to apply")
        return 0
    _emit(args, findings, title="agentspill home: local agent stores", home_mode=True)
    return _exit(args, findings)


def cmd_fix(args):
    root = args.path
    findings, _ = scan_tree(root)
    plan = plan_repo_fix(root, findings)
    if not plan.actions and not plan.manual:
        print("nothing to fix")
        return 0
    print(("applying" if args.write else "plan (dry run)") + ":")
    for a in plan.actions:
        print("  - " + a)
    for m in plan.manual:
        print("  ! manual: " + m)
    if args.write:
        apply_plan(root, plan)
        print(f"done. Now rotate: agentspill scan --history --format checklist")
    else:
        print("add --write to apply")
    return 0


def cmd_install_hook(args):
    root = args.path
    if not is_repo(root):
        print("agentspill: not a git repo", file=sys.stderr)
        return 2
    import subprocess
    hooks = subprocess.run(["git", "-C", root, "rev-parse", "--git-path", "hooks"], capture_output=True,
                           text=True).stdout.strip()
    hooks = hooks if os.path.isabs(hooks) else os.path.join(root, hooks)
    os.makedirs(hooks, exist_ok=True)
    p = os.path.join(hooks, "pre-commit")
    if os.path.exists(p) and not args.force:
        print(f"agentspill: {p} exists; add `agentspill scan --staged` to it, or use --force", file=sys.stderr)
        return 1
    with open(p, "w") as fh:
        fh.write(HOOK)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed {p}")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="agentspill",
        description="Find secrets that coding agents (Claude Code, Cursor, Codex, Gemini CLI, Copilot, Windsurf...) "
                    "leave in permission rules, MCP configs, memory files and transcripts, and get them out of git.")
    ap.add_argument("--version", action="version", version=f"agentspill {__version__}")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--format", choices=["text", "json", "sarif", "github", "checklist"], default="text")
        p.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="high",
                       help="exit 1 if any finding is at least this severe (default: high)")

    s = sub.add_parser("scan", help="scan repos (working tree, --history, --staged) or a remote URL")
    s.add_argument("paths", nargs="*", help="repo directories or git URLs (default: .)")
    s.add_argument("--history", action="store_true", help="also scan every committed version of agent files, all refs")
    s.add_argument("--staged", action="store_true", help="pre-commit mode: scan the index, block local-only files")
    s.add_argument("--home", nargs="?", const="", default=None, metavar="DIR",
                   help="also scan local agent stores in DIR (default ~)")
    s.add_argument("--min-severity", choices=SEVERITIES)
    s.add_argument("--max-commits", type=int, default=5000)
    common(s)
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("home", help="scan local agent stores: ~/.claude.json, transcripts, histories, global MCP configs")
    h.add_argument("--home-dir", help="home directory to scan (default ~)")
    h.add_argument("--scrub", action="store_true", help="redact found secrets in transcripts and histories")
    h.add_argument("--write", action="store_true", help="with --scrub: actually rewrite files")
    h.add_argument("--skip-recent", type=float, default=10, metavar="MIN",
                   help="with --scrub: leave files modified in the last MIN minutes alone (default 10)")
    common(h)
    h.set_defaults(func=cmd_home)

    f = sub.add_parser("fix", help="move secrets out of agent files (dry run unless --write)")
    f.add_argument("path", nargs="?", default=".")
    f.add_argument("--write", action="store_true")
    f.set_defaults(func=cmd_fix)

    i = sub.add_parser("install-hook", help="install a git pre-commit hook running `agentspill scan --staged`")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_install_hook)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not hasattr(args, "color"):
        args.color = "auto"
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
