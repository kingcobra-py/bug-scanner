from app.core.result_secrets import normalize_result_secrets
from app.extractors.secret_extractor import extract_secrets


def test_normalize_upgrades_pipe_pair_and_drops_duplicate_access_key():
    secrets = [
        {"kind": "aws_access_key", "value": "AKIAEXAMPLEACCESS1", "provider": "aws", "occurrences": 1},
        {
            "kind": "aws_cred",
            "value": "AKIAEXAMPLEACCESS1|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "provider": "aws",
            "occurrences": 2,
        },
        {"kind": "github_token", "value": "ghp_" + ("a" * 36), "provider": "github", "occurrences": 1},
    ]
    out = normalize_result_secrets(secrets)
    aws = [s for s in out if s["provider"] == "aws" or str(s["kind"]).startswith("aws")]
    assert len(aws) == 1
    assert aws[0]["kind"] == "aws_cred"
    assert aws[0]["value"] == "AKIAEXAMPLEACCESS1:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert any(s["kind"] == "github_token" for s in out)


def test_normalize_drops_google_jwt_and_generic_noise():
    secrets = [
        {"kind": "google_api", "value": "AIzaSyDummyGoogleMapsKey000001", "provider": "google"},
        {"kind": "jwt", "value": "eyJhbGciOiJIUzI1NiJ9.e30.signature", "provider": "jwt"},
        {"kind": "generic_api_key", "value": "abcdef0123456789ghijklmn", "provider": "generic"},
        {"kind": "bearer", "value": "Bearer abcdef0123456789", "provider": "generic"},
        {"kind": "github_token", "value": "ghp_" + ("a" * 36), "provider": "github"},
    ]
    out = normalize_result_secrets(secrets)
    assert [s["kind"] for s in out] == ["github_token"]


def test_extract_secrets_skips_google_jwt_generic():
    text = """
    GOOGLE_KEY=AIzaSyDummyGoogleMapsKey000001
    TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig
    api_key="abcdefghijklmnopqrstuvwxyz012345"
    GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    """
    secrets = extract_secrets(text, redact_values=False)
    kinds = {s["kind"] for s in secrets}
    assert "github_token" in kinds
    assert "google_api" not in kinds
    assert "jwt" not in kinds
    assert "generic_api_key" not in kinds
    assert "bearer" not in kinds
    assert not any(str(s["value"]).startswith("AIza") for s in secrets)
    assert not any(str(s["value"]).startswith("eyJ") for s in secrets)


def test_normalize_drops_js_env_noise_and_local_placeholders():
    secrets = [
        {"kind": "env", "value": "token=_ref.token,", "provider": "other"},
        {"kind": "env", "value": "keywordQ=product.post_title", "provider": "other"},
        {"kind": "env", "value": "WORDPRESS_DB_PASSWORD=wp_local_password", "provider": "other"},
        {"kind": "env", "value": "key=method ?", "provider": "other"},
        {"kind": "env", "value": "key=method", "provider": "other"},
        {"kind": "env", "value": "DB_PASSWORD=N7!vKp9xmQ2xR4sL", "provider": "other"},
        {"kind": "github_token", "value": "ghp_" + ("a" * 36), "provider": "github"},
    ]
    out = normalize_result_secrets(secrets)
    values = [s["value"] for s in out]
    assert "DB_PASSWORD=N7!vKp9xmQ2xR4sL" in values
    assert any(s["kind"] == "github_token" for s in out)
    assert not any("_ref.token" in v for v in values)
    assert not any("product.post_title" in v for v in values)
    assert not any("wp_local_password" in v for v in values)
    assert not any(v.startswith("key=") for v in values)
