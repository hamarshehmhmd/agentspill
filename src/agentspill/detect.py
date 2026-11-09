"""Secret detectors.

Two families:

* shaped: vendor token formats (AWS, GitHub, OpenAI, Anthropic, Stripe, ...).
  These are what gitleaks / push protection already catch.
* shapeless: secrets recognised by *where* they sit, not what they look like:
  passwords inside DSNs and approved shell commands, Authorization headers,
  --password / --token flags, FOO_PASSWORD=... assignments, and literal values
  of secret-looking env keys in MCP configs. Most scanners miss these.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s)


@dataclass
class Hit:
    kind: str          # e.g. "aws-access-key", "dsn-password"
    secret: str        # the raw secret value (never printed unredacted)
    severity: str
    provider: str = "" # used for rotation hints
    shaped: bool = True
    note: str = ""

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.secret.encode()).hexdigest()[:12]


def redact(s: str) -> str:
    if len(s) <= 8:
        return s[:1] + "*" * 7
    keep = 4 if len(s) >= 16 else 2
    return s[:keep] + "*" * 8 + s[-2:]


# --------------------------------------------------------------------------- placeholders

_PLACEHOLDER_WORDS = {
    "changeme", "change-me", "change_me", "password", "passwd", "secret", "token", "apikey", "api_key",
    "api-key", "null", "none", "true", "false", "redacted", "example", "placeholder", "dummy", "sample",
    "test", "xxx", "todo", "tbd", "pass", "user", "username", "your-token", "mytoken", "mypassword",
    "string", "undefined", "env", "default", "***", "hidden", "masked",
}


def is_reference(v: str) -> bool:
    """A value that points at a secret instead of containing it."""
    v = v.strip().strip("'\"")
    return bool(
        v.startswith("$")
        or v.startswith("%") and v.endswith("%")
        or "${" in v
        or "{env:" in v
        or "{{" in v
        or v.startswith(("op://", "vault:", "vault://", "sm://", "awssm:", "secret://", "keychain:", "env:", "file:"))
        or re.fullmatch(r"\$\(.*\)", v)
        or v.startswith("`")
    )


def is_placeholder(v: str) -> bool:
    raw = v
    v = v.strip().strip("'\"").strip()
    if not v or is_reference(v):
        return True
    low = v.lower()
    if low in _PLACEHOLDER_WORDS:
        return True
    if re.fullmatch(r"[x*.\-_#?0]+", low) or re.fullmatch(r"(.)\1{3,}", low):
        return True
    if low.startswith("<") or low.endswith(">") or low.startswith("[") and low.endswith("]"):
        return True
    for frag in ("your", "xxxx", "example", "placeholder", "changeme", "replace", "insert", "dummy", "redacted",
                 "fake", "sample", "...", "…", "***"):
        if frag in low:
            return True
    if re.search(r"(^|[\s_\-])here$", low):
        return True
    return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


# --------------------------------------------------------------------------- shaped

SHAPED = [
    ("aws-access-key", "aws", "critical", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ("aws-secret-key", "aws", "critical",
     r"(?i)aws_?secret_?(?:access_?)?key[\"'\s]*[=:]\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
    ("github-token", "github", "critical", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"),
    ("github-pat", "github", "critical", r"\b(github_pat_[A-Za-z0-9_]{60,})\b"),
    ("gitlab-token", "gitlab", "critical", r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
    ("anthropic-key", "anthropic", "critical", r"\b(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_\-]{20,})"),
    ("openai-key", "openai", "critical", r"\b(sk-(?:proj-|svcacct-|admin-)?(?!ant-)[A-Za-z0-9_\-]{32,})"),
    ("stripe-key", "stripe", "critical", r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"),
    ("stripe-test-key", "stripe", "medium", r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b"),
    ("slack-token", "slack", "critical", r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})"),
    ("slack-webhook", "slack", "high", r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"),
    ("google-api-key", "google", "high", r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
    ("npm-token", "npm", "critical", r"\b(npm_[A-Za-z0-9]{36})\b"),
    ("huggingface-token", "huggingface", "high", r"\b(hf_[A-Za-z0-9]{30,})\b"),
    ("sendgrid-key", "sendgrid", "high", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    ("private-key", "ssh/tls", "critical", r"(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----)"),
    ("jwt", "jwt", "medium", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
]
_SHAPED = [(k, p, s, re.compile(r)) for k, p, s, r in SHAPED]


def _jwt_role(tok: str) -> dict:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def shaped_hits(text: str) -> list[Hit]:
    out = []
    for kind, prov, sev, rx in _SHAPED:
        for m in rx.finditer(text):
            val = m.group(1)
            if is_placeholder(val) or val.endswith("EXAMPLE"):
                continue
            if kind == "jwt":
                claims = _jwt_role(val)
                role = claims.get("role", "")
                if claims.get("iss", "") == "supabase" or role in ("service_role", "anon"):
                    if role == "anon":
                        continue  # anon keys are public by design
                    out.append(Hit("supabase-service-role-key", val, "critical", "supabase",
                                   note="bypasses Row Level Security"))
                    continue
                if not claims:
                    continue
            out.append(Hit(kind, val, sev, prov))
    return out


# --------------------------------------------------------------------------- shapeless

SECRET_KEY_RX = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|"
    r"bearer|session|cookie|\bpat\b|_pat$|dsn|database_url|db_url|conn(ection)?_?str(ing)?|signing|client_secret)"
)
NOT_SECRET_KEY_RX = re.compile(r"(?i)(_file|_path|_url_env|_env_var|_name|_id$|_user(name)?$|_host|_port|_region|"
                               r"_endpoint|^auth_type|_mode$|_method$|_header$|_enabled$|_ttl$)")

_DSN = re.compile(r"\b([a-z][a-z0-9+.\-]{1,20})://([^:/\s@'\"`]+):([^@\s'\"`/]+)@[^\s'\"`]+")
_HEADER = re.compile(
    r"(?i)(?<![/\w-])(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|private-token|x-goog-api-key|"
    r"x-access-token|cookie)\s*:\s*(bearer\s+|token\s+|basic\s+|bot\s+)?([^\s'\",)\\]+)")
_FLAG = re.compile(
    r"(?i)(?<![\w-])(--?(?:password|passwd|pass|pwd|token|api-key|apikey|api_key|secret|auth-token|access-token|"
    r"client-secret|bearer|auth))(?:=|\s+)(['\"]?)([^\s'\"]+)\2")
_ENV_ASSIGN = re.compile(
    r"(?<![\w$])([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|PWD|TOKEN|SECRET|API_KEY|APIKEY|ACCESS_KEY|"
    r"PRIVATE_KEY|AUTH|CREDENTIALS?|DSN|DATABASE_URL|_PAT))=(['\"]?)([^\s'\";&|]+)\2")
_MYSQL_P = re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]*?\s-p([^\s'\"]{3,})")
_SSHPASS = re.compile(r"\bsshpass\s+-p\s*(['\"]?)([^\s'\"]+)\1")
_CURL_U = re.compile(r"(?:\s-u|--user)\s+(['\"]?)([^\s:'\"]+):([^\s'\"]+)\1")
_QUERY = re.compile(r"(?i)[?&](api[_-]?key|apikey|token|access_token|auth|secret|key|sig|password)=([^&\s'\"#]{8,})")


def shapeless_hits(text: str) -> list[Hit]:
    out: list[Hit] = []

    def add(kind, val, sev="high", prov="", note=""):
        val = val.strip().rstrip(".,;")
        while val.endswith(")") and val.count(")") > val.count("("):
            val = val[:-1]
        if len(val) < 4 or is_placeholder(val):
            return
        out.append(Hit(kind, val, sev, prov, shaped=False, note=note))

    for m in _DSN.finditer(text):
        scheme = m.group(1).lower()
        if scheme in ("http", "https") and m.group(2).lower() in ("git", "x-access-token", "oauth2", "token"):
            add("url-token", m.group(3), "critical", "git-host")
            continue
        add("dsn-password", m.group(3), "high", scheme, note=f"{scheme}:// connection string")
    for m in _HEADER.finditer(text):
        add("auth-header", m.group(3), "high", "", note=m.group(1))
    for m in _FLAG.finditer(text):
        add("cli-flag-secret", m.group(3), "high", "", note=m.group(1))
    for m in _ENV_ASSIGN.finditer(text):
        val = m.group(3)
        if _DSN.search(val):
            continue  # handled by DSN
        add("env-assignment", val, "high", "", note=m.group(1))
    for m in _MYSQL_P.finditer(text):
        add("cli-flag-secret", m.group(1), "high", "mysql", note="mysql -p")
    for m in _SSHPASS.finditer(text):
        add("cli-flag-secret", m.group(2), "high", "ssh", note="sshpass -p")
    for m in _CURL_U.finditer(text):
        add("basic-auth", m.group(3), "high", "", note="curl -u")
    for m in _QUERY.finditer(text):
        add("url-query-secret", m.group(2), "high", "", note=m.group(1))
    return out


def env_value_hit(key: str, value: str) -> list[Hit]:
    """Literal value of a secret-looking env key (MCP env blocks, settings env)."""
    if not isinstance(value, str):
        return []
    hits = shaped_hits(value) + shapeless_hits(value)
    if hits:
        return hits
    if SECRET_KEY_RX.search(key) and not NOT_SECRET_KEY_RX.search(key):
        v = value.strip()
        if len(v) >= 6 and not is_placeholder(v) and not re.fullmatch(r"\d{1,6}|https?://[^@]*", v):
            return [Hit("env-literal", v, "high", "", shaped=False, note=key)]
    return []


def header_value_hit(name: str, value: str) -> list[Hit]:
    if not isinstance(value, str):
        return []
    hits = shaped_hits(value)
    if hits:
        return hits
    if re.search(r"(?i)auth|token|key|secret|cookie|session", name):
        v = re.sub(r"(?i)^(bearer|token|basic|bot)\s+", "", value.strip())
        if len(v) >= 6 and not is_placeholder(v):
            return [Hit("auth-header", v, "high", "", shaped=False, note=name)]
    return []


def text_hits(text: str) -> list[Hit]:
    return dedupe(shaped_hits(text) + shapeless_hits(text))


def dedupe(hits: list[Hit]) -> list[Hit]:
    seen: dict[str, Hit] = {}
    for h in hits:
        cur = seen.get(h.secret)
        # prefer shaped / higher severity classification
        if cur is None or (h.shaped and not cur.shaped) or sev_rank(h.severity) > sev_rank(cur.severity):
            seen[h.secret] = h
    # drop hits whose secret is a substring of a stronger hit (e.g. token inside a DSN)
    vals = list(seen.values())
    res = []
    for h in vals:
        if any(o is not h and h.secret in o.secret and o.shaped >= h.shaped and len(o.secret) > len(h.secret)
               for o in vals):
            continue
        res.append(h)
    return res
