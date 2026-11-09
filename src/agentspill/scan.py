"""Scanning: working tree, git index, git history, remote repos, home-directory stores."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from .artifacts import HOME_ARTIFACTS, REPO_ARTIFACTS, Artifact, classify, parse_text_blob, walk_home, walk_repo
from .detect import Hit, sev_rank

# exposure, most urgent first
EXPOSURES = ["pushed", "committed", "history", "staged", "unignored", "global-ignore-only", "ignored", "local-store"]
EXPOSURE_TEXT = {
    "pushed": "in a commit that is on a remote branch",
    "committed": "tracked by git (in HEAD)",
    "history": "removed from HEAD but still in git history",
    "staged": "staged for the next commit",
    "unignored": "untracked and NOT ignored: the next `git add .` commits it",
    "global-ignore-only": "ignored only by your global gitignore: a clone on another machine or CI would commit it",
    "ignored": "untracked, ignored by the repo",
    "local-store": "local agent store on this machine (not in git)",
}

MAX_BYTES = 20 * 1024 * 1024


@dataclass
class Finding:
    path: str
    line: int
    agent: str
    what: str
    field: str
    context: str
    hit: Hit
    exposure: str
    commit: str = ""
    commit_note: str = ""
    root: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        s = self.hit.severity
        if self.exposure in ("pushed", "committed", "history") and s == "high":
            return "critical"
        if self.exposure in ("ignored", "local-store") and s == "critical":
            return "high"
        return s


def git(root, *args, check=False, input=None):
    p = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, input=input,
                       errors="replace")
    if check and p.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p


def is_repo(root):
    return git(root, "rev-parse", "--git-dir").returncode == 0


def git_toplevel(root):
    p = git(root, "rev-parse", "--show-toplevel")
    return p.stdout.strip() if p.returncode == 0 else None


def _tracked(root):
    p = git(root, "ls-files", "-z")
    return set(x for x in p.stdout.split("\0") if x)


def _staged(root):
    p = git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    return set(x for x in p.stdout.split("\0") if x)


def ignore_source(root, rel):
    """Return (ignored, source) where source is 'repo', 'global' or ''."""
    p = git(root, "check-ignore", "-v", "--no-index", "--", rel)
    if p.returncode != 0 or not p.stdout.strip():
        return False, ""
    src = p.stdout.split(":", 1)[0]
    top = git_toplevel(root) or root
    srcabs = src if os.path.isabs(src) else os.path.join(top, src)
    srcabs = os.path.realpath(srcabs)
    if srcabs.startswith(os.path.realpath(top) + os.sep):
        return True, "repo"   # .gitignore files and .git/info/exclude
    return True, "global"


def _pushed(root, rel):
    """Is the HEAD version of rel contained in any remote-tracking branch?"""
    refs = git(root, "for-each-ref", "--format=%(refname)", "refs/remotes").stdout.split()
    if not refs:
        return False
    last = git(root, "log", "-1", "--format=%H", "--", rel).stdout.strip()
    if not last:
        return False
    p = git(root, "branch", "-r", "--contains", last)
    return bool(p.stdout.strip())


def _read(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _findings_from_blob(raw, rel, art: Artifact, exposure, root="", commit="", note=""):
    out = []
    for s in parse_text_blob(raw, art.fmt):
        out.append(Finding(rel, s.line, art.agent, art.what, s.field, s.context, s.hit, exposure, commit, note, root))
    return out


def scan_tree(root, include_untracked_status=True):
    """Scan the working tree of root (a git repo or a plain directory)."""
    root = os.path.abspath(root)
    repo = is_repo(root)
    tracked = _tracked(root) if repo else set()
    staged = _staged(root) if repo else set()
    prefix = ""
    if repo:
        top = git_toplevel(root)
        prefix = os.path.relpath(root, top).replace(os.sep, "/")
        prefix = "" if prefix == "." else prefix + "/"
    findings, artifacts = [], []
    for rel, art in walk_repo(root):
        raw = _read(os.path.join(root, rel))
        if raw is None:
            continue
        exposure = "unignored"
        meta = {}
        if repo:
            toprel = prefix + rel
            if toprel in tracked:
                exposure = "pushed" if _pushed(root, rel) else "committed"
                if toprel in staged:
                    meta["staged_change"] = True
            elif toprel in staged:
                exposure = "staged"
            else:
                ign, src = ignore_source(root, rel)
                exposure = {"repo": "ignored", "global": "global-ignore-only"}.get(src, "unignored")
        else:
            exposure = "unignored"
        artifacts.append({"path": rel, "agent": art.agent, "what": art.what, "exposure": exposure,
                          "local_only": art.local_only})
        fs = _findings_from_blob(raw, rel, art, exposure, root)
        for f in fs:
            f.extra.update(meta)
        findings.extend(fs)
    return findings, artifacts


def scan_staged(root):
    """Pre-commit mode: scan the index version of staged agent artifacts."""
    root = os.path.abspath(root)
    top = git_toplevel(root) or root
    findings, blocked = [], []
    for rel in sorted(_staged(top)):
        art = classify(rel)
        if not art:
            continue
        if art.local_only:
            blocked.append({"path": rel, "agent": art.agent, "what": art.what})
        raw = git(top, "show", f":{rel}").stdout
        findings.extend(_findings_from_blob(raw, rel, art, "staged", top))
    return findings, blocked


_PATHSPECS = []
for _a in REPO_ARTIFACTS:
    _PATHSPECS.append(f":(glob){_a.glob}")
    _PATHSPECS.append(f":(glob)**/{_a.glob}")


def scan_history(root, max_commits=5000):
    """Every version of every agent artifact ever committed, on all refs."""
    root = os.path.abspath(root)
    top = git_toplevel(root) or root
    p = git(top, "log", "--all", f"--max-count={max_commits}", "--format=%x00%H%x00%an%x00%ad%x00%B%x01",
            "--date=short", "--name-only", "--diff-filter=AM", "--", *_PATHSPECS)
    head_tracked = _tracked(top)
    head_content = {}
    commits = []
    # parse: \0H\0author\0date\0body\x01\nfiles...
    parts = p.stdout.split("\0")
    i = 1
    while i + 3 < len(parts):
        sha, author, date = parts[i], parts[i + 1], parts[i + 2]
        body_files = parts[i + 3]
        body, _, files = body_files.partition("\x01")
        commits.append((sha, author, date, body, [f for f in files.strip().splitlines() if f.strip()]))
        i += 4
    remote_cache = {}

    def on_remote(sha):
        if sha not in remote_cache:
            remote_cache[sha] = bool(git(top, "branch", "-r", "--contains", sha).stdout.strip())
        return remote_cache[sha]

    best = {}  # (fingerprint, path) -> Finding (oldest commit wins)
    for sha, author, date, body, files in commits:  # newest first
        coauth = bool(re.search(r"(?im)^co-authored-by:.*\b(claude|anthropic|cursor|copilot|codex|gemini)", body)) \
            or "Generated with [Claude Code]" in body
        for rel in files:
            art = classify(rel)
            if not art:
                continue
            raw = git(top, "show", f"{sha}:{rel}").stdout
            for f in _findings_from_blob(raw, rel, art, "history", top, sha[:10],
                                         f"{date} by {author}" + (" (agent co-authored)" if coauth else "")):
                if rel not in head_content:
                    head_content[rel] = git(top, "show", f"HEAD:{rel}").stdout if rel in head_tracked else ""
                still = f.hit.secret in head_content[rel]
                f.exposure = ("pushed" if on_remote(sha) else ("committed" if still else "history"))
                f.extra["in_head"] = still
                f.extra["agent_coauthored"] = coauth
                key = (f.hit.fingerprint, rel)
                prev = best.get(key)
                if prev is not None:  # older commit wins for "introduced in", worst exposure wins overall
                    if EXPOSURES.index(prev.exposure) < EXPOSURES.index(f.exposure):
                        f.exposure = prev.exposure
                    f.extra["in_head"] = prev.extra["in_head"]
                    f.extra["agent_coauthored"] = prev.extra["agent_coauthored"] or coauth
                    f.extra["commits"] = prev.extra.get("commits", 1) + 1
                best[key] = f
    return list(best.values())


def clone_remote(url):
    tmp = tempfile.mkdtemp(prefix="agentspill-")
    dest = os.path.join(tmp, "repo.git")
    p = subprocess.run(["git", "clone", "--quiet", "--bare", "--filter=blob:none", url, dest],
                       capture_output=True, text=True)
    if p.returncode != 0:
        p = subprocess.run(["git", "clone", "--quiet", "--bare", url, dest], capture_output=True, text=True)
    if p.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone {url} failed: {p.stderr.strip()}")
    # make remote-tracking refs so "pushed" classification works: in a bare mirror every branch is on the remote
    for ln in git(dest, "for-each-ref", "--format=%(refname:short)", "refs/heads").stdout.split():
        git(dest, "update-ref", f"refs/remotes/origin/{ln}", f"refs/heads/{ln}")
    return tmp, dest


def scan_home(home):
    findings = []
    for rel, art in walk_home(home):
        raw = _read(os.path.join(home, rel))
        if raw is None:
            continue
        findings.extend(_findings_from_blob(raw, "~/" + rel, art, "local-store", home))
    return findings


def sort_findings(fs):
    return sorted(fs, key=lambda f: (-sev_rank(f.severity), EXPOSURES.index(f.exposure), f.path, f.line))
