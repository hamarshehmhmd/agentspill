"""Output formats: text, json, sarif, github, checklist (markdown rotate-first list)."""
from __future__ import annotations

import json
import os

from . import __version__
from .detect import redact, sev_rank
from .scan import EXPOSURE_TEXT, EXPOSURES, Finding

ROTATE = {
    "aws": "https://console.aws.amazon.com/iam/home#/security_credentials (deactivate, then delete the key)",
    "github": "https://github.com/settings/tokens (or the org's fine-grained token page)",
    "gitlab": "https://gitlab.com/-/user_settings/personal_access_tokens",
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "stripe": "https://dashboard.stripe.com/apikeys (roll key)",
    "slack": "https://api.slack.com/apps (regenerate token / webhook)",
    "google": "https://console.cloud.google.com/apis/credentials",
    "npm": "https://www.npmjs.com/settings/~/tokens",
    "huggingface": "https://huggingface.co/settings/tokens",
    "sendgrid": "https://app.sendgrid.com/settings/api_keys",
    "supabase": "Supabase dashboard > Project Settings > API: rotate the JWT secret / service_role key",
    "ssh/tls": "generate a new key pair; remove the old public key everywhere it is trusted",
    "postgres": "ALTER ROLE <user> WITH PASSWORD '<new>'; then update every client",
    "postgresql": "ALTER ROLE <user> WITH PASSWORD '<new>'; then update every client",
    "mysql": "ALTER USER '<user>'@'%' IDENTIFIED BY '<new>';",
    "mongodb": "db.changeUserPassword('<user>', '<new>') or rotate in Atlas",
    "mongodb+srv": "rotate the database user's password in Atlas",
    "redis": "rotate requirepass / ACL user password",
    "rediss": "rotate requirepass / ACL user password",
    "amqp": "rabbitmqctl change_password <user> <new>",
    "git-host": "revoke the token at your git host",
    "jwt": "rotate the signing secret that issued this token",
}

C = {"critical": "\x1b[1;31m", "high": "\x1b[31m", "medium": "\x1b[33m", "low": "\x1b[2m", "dim": "\x1b[2m",
     "ok": "\x1b[32m", "b": "\x1b[1m", "cyan": "\x1b[36m", "0": "\x1b[0m"}


def _c(color, s, on):
    return f"{C[color]}{s}{C['0']}" if on else s


def rotate_hint(f: Finding) -> str:
    return ROTATE.get(f.hit.provider, "rotate it with whoever issued it")


def to_dict(f: Finding) -> dict:
    d = {
        "path": f.path, "line": f.line, "agent": f.agent, "file_kind": f.what, "field": f.field,
        "context": f.context, "kind": f.hit.kind, "severity": f.severity, "exposure": f.exposure,
        "exposure_text": EXPOSURE_TEXT[f.exposure], "redacted": redact(f.hit.secret),
        "fingerprint": f.hit.fingerprint, "shaped": f.hit.shaped, "provider": f.hit.provider,
        "note": f.hit.note, "rotate": rotate_hint(f),
    }
    if f.commit:
        d["commit"] = f.commit
        d["commit_info"] = f.commit_note
    d.update({k: v for k, v in f.extra.items()})
    return d


def text(findings, artifacts=None, color=False, title="", home_mode=False) -> str:
    out = []
    if title:
        out.append(_c("b", title, color))
    if artifacts is not None and not home_mode:
        out.append(f"agent files found: {len(artifacts)}" + (
            "  (" + ", ".join(sorted({a['agent'] for a in artifacts})) + ")" if artifacts else ""))
        for a in artifacts:
            if a["local_only"] and a["exposure"] in ("committed", "pushed", "unignored", "global-ignore-only",
                                                     "staged"):
                out.append("  " + _c("medium", "!", color) + f" {a['path']}: local-only file, "
                           f"{EXPOSURE_TEXT[a['exposure']]}")
    if not findings:
        out.append(_c("ok", "no secrets found in agent files", color))
        return "\n".join(out)
    groups = {}
    for f in findings:
        groups.setdefault(f.path, []).append(f)
    for path, fs in groups.items():
        f0 = fs[0]
        loc = f"{path}"
        out.append("")
        out.append(_c("b", loc, color) + _c("dim", f"  [{f0.agent}: {f0.what}]", color))
        for f in fs:
            sev = _c(f.severity, f"{f.severity.upper():8}", color)
            where = f"L{f.line}" if f.line else ""
            kind = f.hit.kind + ("" if f.hit.shaped else "*")
            note = f" ({f.hit.note})" if f.hit.note else ""
            out.append(f"  {sev} {where:5} {kind}{note}: {_c('cyan', redact(f.hit.secret), color)}"
                       f"  {_c('dim', 'in ' + f.field, color)}")
            exp = EXPOSURE_TEXT[f.exposure]
            if f.commit:
                exp += f"; first seen {f.commit} {f.commit_note}"
            out.append(" " * 17 + _c("dim", exp, color))
    n = len(findings)
    shapeless = sum(1 for f in findings if not f.hit.shaped)
    uniq = len({f.hit.fingerprint for f in findings})
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    out.append("")
    out.append(_c("b", f"{n} finding(s), {uniq} distinct secret(s)", color) + " · " +
               ", ".join(f"{sev_counts[s]} {s}" for s in reversed(("low", "medium", "high", "critical"))
                         if s in sev_counts) +
               f" · {shapeless} shapeless (*: no vendor token format; most secret scanners miss these)")
    if not home_mode:
        out.append(_c("dim", "next: agentspill fix (dry run) · agentspill scan --history · --format checklist", color))
    return "\n".join(out)


def checklist(findings) -> str:
    """Rotate-first markdown checklist, one item per distinct secret."""
    by = {}
    for f in findings:
        by.setdefault(f.hit.fingerprint, []).append(f)

    def urgency(fs):
        return (min(EXPOSURES.index(f.exposure) for f in fs), -max(sev_rank(f.severity) for f in fs))

    lines = ["# Rotate first: secrets found in coding-agent files", "",
             "Deleting the file or the line does not un-leak a secret that reached git, a fork or a "
             "transcript. Rotate, then clean up (`agentspill fix`).", ""]
    for i, (fp, fs) in enumerate(sorted(by.items(), key=lambda kv: urgency(kv[1])), 1):
        f0 = min(fs, key=lambda f: EXPOSURES.index(f.exposure))
        lines.append(f"- [ ] **{i}. {f0.hit.kind}** `{redact(f0.hit.secret)}` ({f0.severity}, "
                     f"{EXPOSURE_TEXT[f0.exposure]})")
        lines.append(f"  - rotate: {rotate_hint(f0)}")
        for f in sorted(fs, key=lambda f: EXPOSURES.index(f.exposure)):
            c = f" — commit {f.commit} {f.commit_note}" if f.commit else ""
            lines.append(f"  - seen in `{f.path}`" + (f" line {f.line}" if f.line else "") + f" ({f.exposure}){c}")
    if not by:
        lines.append("Nothing to rotate.")
    return "\n".join(lines) + "\n"


def sarif(findings) -> str:
    rules = {}
    results = []
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    for f in findings:
        rules.setdefault(f.hit.kind, {"id": f.hit.kind, "name": f.hit.kind,
                                      "shortDescription": {"text": f"Secret in coding-agent file: {f.hit.kind}"},
                                      "helpUri": "https://github.com/hamarshehmhmd/agentspill"})
        results.append({
            "ruleId": f.hit.kind, "level": level[f.severity],
            "message": {"text": f"{f.hit.kind} {redact(f.hit.secret)} in {f.what} ({f.field}); "
                                f"{EXPOSURE_TEXT[f.exposure]}. Rotate: {rotate_hint(f)}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"secret/v1": f.hit.fingerprint},
        })
    return json.dumps({"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "agentspill", "version": __version__,
                                                     "informationUri": "https://github.com/hamarshehmhmd/agentspill",
                                                     "rules": list(rules.values())}},
                                 "results": results}]}, indent=2)


def github(findings) -> str:
    out = []
    for f in findings:
        lvl = "error" if f.severity in ("critical", "high") else "warning"
        msg = f"{f.hit.kind} {redact(f.hit.secret)} in {f.what}: {EXPOSURE_TEXT[f.exposure]}. Rotate it."
        out.append(f"::{lvl} file={f.path},line={max(1, f.line)},title=agentspill::{msg}")
    return "\n".join(out)


def as_json(findings, artifacts=None, extra=None) -> str:
    d = {"version": __version__, "findings": [to_dict(f) for f in findings]}
    if artifacts is not None:
        d["artifacts"] = artifacts
    if extra:
        d.update(extra)
    return json.dumps(d, indent=2)
