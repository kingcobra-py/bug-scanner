from app.core.result_secrets import normalize_result_secrets
from app.extractors.secret_extractor import extract_secrets
from app.extractors.smtp_extractor import extract_smtp

# AWS docs-style fixtures (not real credentials).
FAKE_ASIA = "ASIAIOSFODNN7EXAMPLE"
FAKE_AKIA = "AKIAIOSFODNN7EXAMPLE"
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
FAKE_ASIA_B = "ASIATESTACCESSKEY01"
FAKE_AKIA_B = "AKIATESTACCESSKEY01"


def test_normalize_pairs_aws_env_access_and_secret():
    secrets = [
        {
            "kind": "env",
            "value": f"AWS_ACCESS_KEY_ID={FAKE_ASIA}",
            "source_url": "https://example.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"AWS_SECRET_ACCESS_KEY={FAKE_SECRET}",
            "source_url": "https://example.test",
            "occurrences": 1,
        },
        {
            "kind": "aws_access_key",
            "value": FAKE_ASIA,
            "source_url": "https://example.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": "AWS_LAMBDA_METADATA_TOKEN=ff19351f-4b12-4a8e-aa4f-f179701366e6",
            "source_url": "https://example.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": "__NEXT_PRIVATE_ORIGIN=http://localhost:8000",
            "source_url": "https://example.test",
            "occurrences": 3,
        },
    ]
    out = normalize_result_secrets(secrets)
    values = [s["value"] for s in out]
    assert any(s["kind"] == "aws_cred" for s in out)
    assert f"{FAKE_ASIA}:{FAKE_SECRET}" in values
    assert FAKE_ASIA not in values
    assert not any(s["kind"] == "aws_access_key" for s in out)
    assert not any("AWS_LAMBDA" in v for v in values)
    assert not any("__NEXT_PRIVATE" in v for v in values)
    assert not any(v.startswith("AWS_ACCESS_KEY_ID=") for v in values)
    assert not any(v.startswith("AWS_SECRET_ACCESS_KEY=") for v in values)


def test_normalize_drops_unpaired_aws_access_keys():
    secrets = [
        {
            "kind": "aws_access_key",
            "value": FAKE_ASIA_B,
            "source_url": "https://a.example/.env.production",
            "occurrences": 1,
        },
        {
            "kind": "aws_access_key",
            "value": FAKE_AKIA_B,
            "source_url": "https://b.example",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"AWS_ACCESS_KEY_ID={FAKE_ASIA}",
            "source_url": "https://c.example",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"AWS_SECRET_ACCESS_KEY={FAKE_SECRET}",
            "source_url": "https://c.example",
            "occurrences": 1,
        },
    ]
    out = normalize_result_secrets(secrets)
    assert [s["kind"] for s in out] == ["aws_cred"]
    assert out[0]["value"].startswith(f"{FAKE_ASIA}:")
    assert not any(s["value"] in {FAKE_ASIA_B, FAKE_AKIA_B} for s in out)


def test_normalize_builds_smtp_from_env_and_drops_duplicates():
    secrets = [
        {"kind": "env", "value": "SMTP_HOST=smtp.gmail.com\r", "source_url": "https://a.test", "occurrences": 1},
        {"kind": "env", "value": "SMTP_USER=user@gmail.com\r", "source_url": "https://a.test", "occurrences": 1},
        {"kind": "env", "value": "SMTP_PASS=app-password-123", "source_url": "https://a.test", "occurrences": 1},
        {
            "kind": "smtp",
            "value": {"host": "smtp.gmail.com", "port": "587", "user": "user@gmail.com", "pass": "app-password-123"},
            "source_url": "https://a.test",
            "occurrences": 1,
        },
        {
            "kind": "smtp",
            "value": {"host": "smtp.gmail.com", "port": "", "user": "REPLACE_ME_SMTP_USERNAME", "pass": "REPLACE_ME_SMTP_PASSWORD"},
            "source_url": "https://b.test",
            "occurrences": 1,
        },
        {
            "kind": "smtp",
            "value": {"host": "smtp.sendgrid.net", "port": "", "user": "", "pass": ""},
            "source_url": "https://c.test",
            "occurrences": 1,
        },
        {"kind": "absolute_api", "value": "https://api.example.com/v1", "source_url": "https://d.test", "occurrences": 1},
    ]
    out = normalize_result_secrets(secrets)
    smtp = [s for s in out if s["kind"] == "smtp"]
    assert len(smtp) == 1
    assert "smtp.gmail.com" in smtp[0]["value"]
    assert "app-password-123" in smtp[0]["value"]
    assert not any(s["kind"] == "absolute_api" for s in out)
    assert not any(str(s.get("value", "")).startswith("SMTP_") for s in out)


def test_extract_secrets_pairs_unquoted_aws_env():
    text = f"""
AWS_ACCESS_KEY_ID={FAKE_ASIA}
AWS_SECRET_ACCESS_KEY={FAKE_SECRET}
AWS_LAMBDA_FUNCTION_NAME=example-app-prod-www
__NEXT_PRIVATE_ORIGIN=http://localhost:8000
"""
    secrets = extract_secrets(text, source_url="https://example.test", redact_values=False)
    kinds = {s["kind"] for s in secrets}
    values = [s["value"] for s in secrets]
    assert "aws_cred" in kinds
    assert any(v.startswith(f"{FAKE_ASIA}:") for v in values)
    assert not any("AWS_LAMBDA" in v for v in values)
    assert not any("__NEXT_PRIVATE" in v for v in values)


def test_extract_smtp_from_scattered_env_and_skips_host_only():
    text = """
SMTP_USER=user@example.com
APPSETTING_SMTP_PASS=AppPassExample123!
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=465
random smtp.gmail.com mention without creds
"""
    smtp = extract_smtp(text, redact_values=False)
    assert smtp
    assert any(
        item["value"].get("pass") == "AppPassExample123!" and item["value"].get("host") == "smtp.hostinger.com"
        for item in smtp
    )
    assert not any(
        item["value"].get("host") == "smtp.gmail.com" and not item["value"].get("pass")
        for item in smtp
    )
