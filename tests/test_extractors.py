from pathlib import Path

from app.extractors import extract_all
from app.extractors.secret_extractor import extract_secrets
from app.extractors.smtp_extractor import extract_smtp
from app.extractors.api_extractor import extract_apis
from app.extractors.validators import is_placeholder, redact

FIX = Path(__file__).parent / "fixtures"

# Construct provider-shaped test doubles at runtime so fixture files stay push-safe.
FAKE_GITHUB = "ghp_" + ("a" * 36)
FAKE_SENDGRID = "SG." + ("a" * 22) + "." + ("b" * 43)
FAKE_STRIPE = "sk_live_" + ("c" * 24)
FAKE_SLACK = "xoxb-1234567890-abcdefghijk"


def test_env_secrets_and_placeholder_filter():
    text = (FIX / "sample.env").read_text()
    text += f"\nGITHUB_TOKEN={FAKE_GITHUB}\nMAIL_PASSWORD={FAKE_SENDGRID}\nSTRIPE_KEY={FAKE_STRIPE}\n"
    secrets = extract_secrets(text, source_url="https://t/.env", redact_values=True)
    kinds = {s["kind"] for s in secrets}
    values = " ".join(str(s.get("value")) for s in secrets)
    assert "aws_access_key" in kinds or "aws_cred" in kinds or any("AKIA" in str(s) for s in secrets)
    assert "github_token" in kinds or "ghp_" in values or any(s["kind"] == "env" for s in secrets)
    assert "your-password" not in values
    assert "${VAR}" not in values


def test_smtp_nearby_extraction():
    text = (FIX / "sample.env").read_text()
    smtp = extract_smtp(text, redact_values=True)
    assert smtp
    hosts = [s["value"].get("host") for s in smtp if isinstance(s.get("value"), dict)]
    assert any(h and "sendgrid" in h for h in hosts)


def test_js_api_and_secrets():
    text = (FIX / "sample.js").read_text()
    text += f'\nconst apiKey = "{FAKE_GITHUB}";\nconst SENDGRID = "{FAKE_SENDGRID}";\nconst slack = "{FAKE_SLACK}";\n'
    apis = extract_apis(text, source_url="https://app.example-corp.com/")
    secrets = extract_secrets(text, redact_values=True)
    assert any("/api/v1" in str(a["value"]) or "base_url" == a["kind"] for a in apis)
    assert any(s["kind"] in ("github_token", "sendgrid", "slack", "generic_api_key") for s in secrets)
    assert not any("your-password" in str(s["value"]) for s in secrets)


def test_extract_all_bundle():
    text = (FIX / "sample.env").read_text()
    out = extract_all(text, source_url="https://t/.env")
    assert "secrets" in out and "apis" in out and "smtp" in out


def test_placeholder_and_redact():
    assert is_placeholder("your-password")
    assert is_placeholder("${VAR}")
    assert is_placeholder("xxxx")
    r = redact("abcdefghij", show_last=4)
    assert r.endswith("ghij")
    assert "*" in r


def test_false_positive_short_token():
    secrets = extract_secrets('api_key="short"', redact_values=False)
    assert secrets == [] or all(len(str(s.get("value", ""))) >= 8 for s in secrets)


def test_manifest_and_js_statements_are_not_flagged_as_secrets():
    # Verbatim false positives observed in production: PWA manifest fields,
    # analytics snippets, and bare JS/GLSL statements that happen to be long
    # and high-entropy but carry no credential.
    manifest = (
        '{"name": "Primi - \u041e\u043d\u043b\u0430\u0439\u043d QR-\u043c\u0435\u043d\u044e", '
        '"short_name": "Sappito Tech", "orientation": "portrait-primary", '
        '"start_url": "/?utm_source=rg.ru&utm_medium=pwa", '
        '"description": "Some long enough marketing description text here"}'
    )
    js_body = (
        "backToTop=function() {\n"
        "body=await request.text();\n"
        "vWorldDirection=transformDirection( position, modelMatrix );\n"
    )
    secrets = extract_secrets(manifest, redact_values=False) + extract_secrets(js_body, redact_values=False)
    assert secrets == []


def test_marker_keys_with_real_credentials_still_flagged():
    text = "DB_PASSWORD=SuperSecretPassw0rd!\nAPI_KEY=abcdef0123456789ghijklmn\n"
    secrets = extract_secrets(text, redact_values=False)
    kinds = {s["kind"] for s in secrets}
    values = " ".join(str(s.get("value")) for s in secrets)
    assert "env" in kinds
    assert "SuperSecretPassw0rd" in values or "abcdef0123456789" in values
