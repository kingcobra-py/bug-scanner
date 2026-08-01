from app.extractors.priority_secrets import extract_priority_secrets, priority_extractions

FAKE_GITHUB = "ghp_" + ("a" * 36)
FAKE_SENDGRID = "SG." + ("a" * 22) + "." + ("b" * 43)
FAKE_STRIPE = "sk_live_" + ("c" * 24)
FAKE_BREVO = "xkeysib-" + ("d" * 64) + "-" + ("e" * 16)
FAKE_AWS = "AKIA" + ("F" * 16)


def test_priority_packs_only():
    text = f"""
    AWS_ACCESS_KEY_ID={FAKE_AWS}
    GITHUB_TOKEN={FAKE_GITHUB}
    STRIPE={FAKE_STRIPE}
    SENDGRID={FAKE_SENDGRID}
    BREVO={FAKE_BREVO}
    SLACK=xoxb-1234567890-abcdefghijk
    OPENAI=sk-abcdefghijklmnopqrstuvwxyz123456
    """
    secrets = extract_priority_secrets(text, source_url="https://t/.env", redact_values=False)
    kinds = {s["kind"] for s in secrets}
    assert "aws_access_key" in kinds or "aws_cred" in kinds
    assert "github_token" in kinds
    assert "stripe_live" in kinds
    assert "sendgrid" in kinds
    assert "brevo" in kinds
    assert "slack" not in kinds
    assert "openai" not in kinds
    assert all(s.get("extractor") == "priority_secrets" for s in secrets)


def test_priority_extractions_bundle_shape():
    out = priority_extractions(f"token={FAKE_GITHUB}", source_url="https://t/")
    assert out["apis"] == []
    assert out["smtp"] == []
    assert out["extractor"] == "priority_secrets"
    assert out["secrets"]
