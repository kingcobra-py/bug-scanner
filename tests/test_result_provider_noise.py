from app.core.providers import classify_env_assignment, provider_for_kind, PROVIDERS
from app.core.result_secrets import normalize_result_secrets
from app.extractors.secret_extractor import extract_secrets

# Synthetic fixtures only (built in parts so scanners ignore them).
FAKE_STRIPE_LIVE = "sk_" + "live_" + ("E" * 28)
FAKE_STRIPE_TEST = "sk_" + "test_" + ("0" * 40)
FAKE_BREVO = "xkeysib-" + ("a" * 64) + "-" + ("b" * 16)
FAKE_NEXTAUTH = "a" * 64
FAKE_EMAILJS = "emailjs_private_fixture_001"
FAKE_RAZORPAY = "RzrpAySecretFixtureKey0001"
FAKE_TENCENT = "AKID" + ("B" * 20)
FAKE_ALIYUN = "LTAI" + ("C" * 16)


def test_classify_env_promotes_live_stripe_brevo_razorpay_only():
    assert classify_env_assignment("STRIPE_SECRET_KEY", FAKE_STRIPE_LIVE) == (
        "stripe",
        "stripe_live",
        FAKE_STRIPE_LIVE,
    )
    assert classify_env_assignment("STRIPE_WEBHOOK_SECRET", "whsec_" + ("x" * 32)) is None
    assert classify_env_assignment("STRIPE_PUBLISHABLE_KEY", "pk_live_" + ("x" * 40)) is None
    assert classify_env_assignment("STRIPE_PRICE_ID", "price_1ExamplePriceId0001") is None
    assert classify_env_assignment("STRIPE_SECRET_KEY", FAKE_STRIPE_TEST) is None
    assert classify_env_assignment("BREVO_API_KEY", FAKE_BREVO) == ("brevo", "brevo", FAKE_BREVO)
    assert classify_env_assignment("RAZORPAY_KEY_SECRET", FAKE_RAZORPAY) == (
        "razorpay",
        "razorpay",
        FAKE_RAZORPAY,
    )
    assert classify_env_assignment("NEXT_PUBLIC_RAZORPAY_KEY_SECRET", FAKE_RAZORPAY) == (
        "razorpay",
        "razorpay",
        FAKE_RAZORPAY,
    )
    assert classify_env_assignment("JWT_SECRET", FAKE_NEXTAUTH) is None
    assert classify_env_assignment("EMAILJS_PRIVATE_KEY", FAKE_EMAILJS) is None
    assert classify_env_assignment("TENCENT_SECRET_KEY", "abc123") is None
    assert classify_env_assignment("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "abc123") is None


def test_normalize_drops_other_env_noise_keeps_razorpay():
    secrets = [
        {"kind": "env", "value": "JWT_SECRET=my-super-secret-key-for-signing", "source_url": "https://a.test"},
        {"kind": "env", "value": "STRIPE_PRICE_ID=price_1SU5hE7qX3CfPWurSr4Y0Pni", "source_url": "https://a.test"},
        {"kind": "env", "value": "STRIPE_PUBLISHABLE_KEY=pk_live_" + ("x" * 40), "source_url": "https://a.test"},
        {"kind": "env", "value": "STRIPE_WEBHOOK_SECRET=whsec_" + ("y" * 32), "source_url": "https://a.test"},
        {"kind": "env", "value": "GOOGLE_CLIENT_SECRET=GOCSPX-fixtureClientSecret01", "source_url": "https://a.test"},
        {"kind": "env", "value": "RECAPTCHA_SECRET_KEY=6LeFixtureRecaptchaSecretKey01", "source_url": "https://a.test"},
        {"kind": "env", "value": "ADMIN_PASSWORD=Kitchen@2024", "source_url": "https://a.test"},
        {"kind": "env", "value": "EMAIL_RECEIVER=user@example.com", "source_url": "https://a.test"},
        {"kind": "env", "value": f"NEXTAUTH_SECRET={FAKE_NEXTAUTH}", "source_url": "https://a.test"},
        {"kind": "env", "value": f"RAZORPAY_KEY_SECRET={FAKE_RAZORPAY}", "source_url": "https://nexivus.ai"},
        {
            "kind": "env",
            "value": f"NEXT_PUBLIC_RAZORPAY_KEY_SECRET={FAKE_RAZORPAY}",
            "source_url": "https://idkwholesale.in",
        },
        {"kind": "env", "value": f"STRIPE_SECRET_KEY={FAKE_STRIPE_LIVE}", "source_url": "https://b.test"},
        {"kind": "stripe_live", "value": FAKE_STRIPE_LIVE, "source_url": "https://b.test", "occurrences": 2},
        {"kind": "tencent", "value": FAKE_TENCENT, "source_url": "https://c.test"},
        {"kind": "aliyun", "value": FAKE_ALIYUN, "source_url": "https://c.test"},
        {"kind": "env", "value": f"TENCENT_SECRET_KEY={FAKE_TENCENT}", "source_url": "https://c.test"},
        {"kind": "env", "value": f"ALIBABA_CLOUD_ACCESS_KEY_ID={FAKE_ALIYUN}", "source_url": "https://c.test"},
    ]
    out = normalize_result_secrets(secrets)
    by_provider = {}
    for item in out:
        by_provider.setdefault(item["provider"], []).append(item)

    assert "other" not in by_provider
    assert "tencent" not in by_provider
    assert "aliyun" not in by_provider
    assert len(by_provider["razorpay"]) == 1
    assert by_provider["razorpay"][0]["value"] == FAKE_RAZORPAY
    assert len(by_provider["stripe"]) == 1
    assert by_provider["stripe"][0]["value"] == FAKE_STRIPE_LIVE
    assert not any("JWT_SECRET" in str(s.get("value")) for s in out)
    assert not any("PRICE" in str(s.get("value")) for s in out)
    assert not any(str(s.get("value", "")).startswith("pk_live_") for s in out)
    assert not any(str(s.get("value", "")).startswith("whsec_") for s in out)


def test_extract_skips_sk_test_tencent_aliyun_keeps_razorpay():
    text = f"""
RAZORPAY_KEY_SECRET={FAKE_RAZORPAY}
STRIPE_SECRET_KEY={FAKE_STRIPE_LIVE}
STRIPE_TEST_KEY={FAKE_STRIPE_TEST}
TENCENT_SECRET_KEY={FAKE_TENCENT}
ALIBABA_CLOUD_ACCESS_KEY_ID={FAKE_ALIYUN}
JWT_SECRET=dev-secret-change-me
{FAKE_TENCENT}
{FAKE_ALIYUN}
"""
    secrets = extract_secrets(text, redact_values=False)
    values = [s["value"] for s in secrets]
    kinds = {s["kind"] for s in secrets}
    assert "stripe_live" in kinds
    assert FAKE_STRIPE_LIVE in values
    assert "stripe_test" not in kinds
    assert "tencent" not in kinds
    assert "aliyun" not in kinds
    assert FAKE_TENCENT not in values
    assert FAKE_ALIYUN not in values
    assert any("RAZORPAY" in str(v) or v == FAKE_RAZORPAY for v in values)
    out = normalize_result_secrets(
        [{**s, "occurrences": 1} for s in secrets]
    )
    assert any(s["provider"] == "razorpay" and s["value"] == FAKE_RAZORPAY for s in out)
    assert not any(s["provider"] in {"tencent", "aliyun", "other"} for s in out)


def test_provider_logos_and_kinds():
    assert provider_for_kind("stripe_live") == "stripe"
    assert provider_for_kind("razorpay") == "razorpay"
    assert provider_for_kind("openai") == "openai"
    assert provider_for_kind("postmark") == "postmark"
    assert "tencent" not in PROVIDERS
    assert "aliyun" not in PROVIDERS
    assert PROVIDERS["openai"]["logo"].startswith("/static/img/providers/")
    assert PROVIDERS["postmark"]["logo"].startswith("/static/img/providers/")
    assert PROVIDERS["razorpay"]["logo"].startswith("/static/img/providers/")
