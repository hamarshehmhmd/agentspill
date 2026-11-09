import base64
import json

import pytest
from conftest import ANTHROPIC, AWS, GH, OPENAI, PW, STRIPE

from agentspill.detect import env_value_hit, header_value_hit, is_placeholder, redact, text_hits


def kinds(s):
    return {h.kind for h in text_hits(s)}


@pytest.mark.parametrize("tok,kind", [(GH, "github-token"), (AWS, "aws-access-key"), (OPENAI, "openai-key"),
                                      (ANTHROPIC, "anthropic-key"), (STRIPE, "stripe-key")])
def test_shaped_tokens(tok, kind):
    hits = text_hits(f"export X={tok} && run")
    assert any(h.kind == kind and h.secret == tok and h.shaped for h in hits)


def test_anthropic_not_reported_as_openai():
    assert kinds(ANTHROPIC) == {"anthropic-key"}


def test_aws_example_key_ignored():
    assert not text_hits("AKIA" + "IOSFODNN7EXAMPLE")


def test_dsn_password_shapeless():
    hits = text_hits(f"psql postgresql://app:{PW}@db:5432/x")
    assert [(h.kind, h.secret, h.shaped) for h in hits] == [("dsn-password", PW, False)]


def test_permission_rule_variants():
    rule = f'Bash(PGPASSWORD={PW} psql -h db -U app -c "select 1")'
    assert {h.secret for h in text_hits(rule)} == {PW}
    assert {h.secret for h in text_hits(f"Bash(mysql -u root -p{PW} shop)")} == {PW}
    assert {h.secret for h in text_hits(f"Bash(sshpass -p {PW} ssh root@10.0.0.2)")} == {PW}
    assert {h.secret for h in text_hits(f'Bash(curl -H "Authorization: Bearer {PW}xyz" https://a)')} == {PW + "xyz"}
    assert {h.secret for h in text_hits(f"Bash(curl -u admin:{PW} https://a)")} == {PW}
    assert {h.secret for h in text_hits(f"Bash(./deploy --api-key={PW})")} == {PW}
    assert {h.secret for h in text_hits(f"Bash(redis-cli --pass {PW} ping)")} == {PW}


def test_references_and_placeholders_are_not_secrets():
    for s in ["Bash(npm run test:*)", "PGPASSWORD=$PGPASSWORD psql", "postgres://u:${DB_PASS}@h/db",
              "Authorization: Bearer ${TOKEN}", "--password=<your-password>", "API_KEY=changeme",
              "postgres://user:password@localhost/db", "TOKEN=xxxxxxxx", "--token $(op read op://v/i/t)",
              "Authorization: Bearer {env:API}", "postgres://u:****@h/db"]:
        assert not text_hits(s), s


def test_url_query_and_git_token():
    hits = text_hits(f"https://api.example.com/v1?api_key={PW}abc")
    assert {h.kind for h in hits} == {"url-query-secret"}
    hits = text_hits(f"git clone https://x-access-token:{PW}@github.com/o/r")
    assert hits[0].kind == "url-token" and hits[0].severity == "critical"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256'})}.{enc(claims)}.{'s' * 10}Abc123xyz"


def test_supabase_service_role_vs_anon():
    svc = _jwt({"iss": "supabase", "role": "service_role"})
    anon = _jwt({"iss": "supabase", "role": "anon"})
    assert [h.kind for h in text_hits(svc)] == ["supabase-service-role-key"]
    assert text_hits(anon) == []


def test_env_literal_by_key_name():
    assert env_value_hit("DB_PASSWORD", "hunter2hunter2")[0].kind == "env-literal"
    assert env_value_hit("DB_PASSWORD", "${DB_PASSWORD}") == []
    assert env_value_hit("DB_HOST", "db.internal") == []
    assert env_value_hit("TOKEN_FILE", "/run/secrets/tok") == []
    assert env_value_hit("SUPABASE_URL", "https://x.supabase.co") == []
    assert env_value_hit("GITHUB_TOKEN", GH)[0].kind == "github-token"


def test_header_value():
    assert header_value_hit("Authorization", "Bearer abcdef123456")[0].secret == "abcdef123456"
    assert header_value_hit("Authorization", "Bearer ${X}") == []
    assert header_value_hit("Accept", "application/json") == []


def test_placeholder_rules():
    assert is_placeholder("your-api-key-here")
    assert is_placeholder("${A}")
    assert is_placeholder("op://vault/item/field")
    assert not is_placeholder("somewhere-Th3re-42")


def test_redact_never_returns_secret():
    for s in [PW, GH, "abcd", "abcdefghij"]:
        r = redact(s)
        assert r != s and "*" in r
