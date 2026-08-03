from app.core.providers import classify_env_assignment, provider_for_kind
from app.core.result_secrets import normalize_result_secrets
from app.extractors.secret_extractor import extract_secrets

# Synthetic fixtures only (built in parts so scanners ignore them).
FAKE_STRIPE_LIVE = "sk_" + "live_" + ("E" * 28)
FAKE_STRIPE_TEST = "sk_" + "test_" + ("0" * 40)
FAKE_BREVO = "xkeysib-" + ("a" * 64) + "-" + ("b" * 16)
FAKE_NEXTAUTH = "a" * 64
FAKE_EMAILJS = "emailjs_private_fixture_001"
FAKE_SANITY = "sk" + ("Z" * 100) + "sanityFixtureToken000001"


def test_classify_env_promotes_live_stripe_and_brevo_only():
    assert classify_env_assignment("STRIPE_SECRET_KEY", FAKE_STRIPE_LIVE) == (
        "stripe",
        "stripe_live",
        FAKE_STRIPE_LIVE,
    )
    assert classify_env_assignment("STRIPE_SECRET_KEY", FAKE_STRIPE_TEST) is None
    assert classify_env_assignment("PAYSTACK_SECRET_KEY", FAKE_STRIPE_TEST) is None
    assert classify_env_assignment("BREVO_API_KEY", FAKE_BREVO) == ("brevo", "brevo", FAKE_BREVO)
    assert classify_env_assignment("EMAILJS_PRIVATE_KEY", FAKE_EMAILJS) is None
    assert classify_env_assignment("SANITY_API_TOKEN", FAKE_SANITY) is None
    assert classify_env_assignment("NEXTAUTH_SECRET", FAKE_NEXTAUTH) is None


def test_normalize_drops_user_listed_other_noise():
    secrets = [
        {
            "kind": "env",
            "value": f"NEXTAUTH_SECRET={FAKE_NEXTAUTH}",
            "source_url": "https://ucscogroup.com",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": "MSI_SECRET=ac47478f-7806-afa4-4506-af6c1ab747c6",
            "source_url": "https://techsundae.com",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": "NEXTAUTH_SECRET=some-secret-key",
            "source_url": "http://leaderboard.com.ua",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"EMAILJS_PRIVATE_KEY={FAKE_EMAILJS}",
            "source_url": "https://adilicyber.africa",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"SANITY_API_TOKEN={FAKE_SANITY}",
            "source_url": "https://adilicyber.africa",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"APPSETTING_EMAILJS_PRIVATE_KEY={FAKE_EMAILJS}",
            "source_url": "https://adilicyber.africa",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"APPSETTING_PAYSTACK_SECRET_KEY={FAKE_STRIPE_TEST}",
            "source_url": "https://adilicyber.africa",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"PAYSTACK_SECRET_KEY={FAKE_STRIPE_TEST}",
            "source_url": "https://adilicyber.africa",
            "occurrences": 1,
        },
        {"kind": "stripe_test", "value": FAKE_STRIPE_TEST, "source_url": "https://x.test", "occurrences": 1},
        {"kind": "env", "value": f"STRIPE_SECRET_KEY={FAKE_STRIPE_LIVE}", "source_url": "https://a.test", "occurrences": 1},
        {"kind": "stripe_live", "value": FAKE_STRIPE_LIVE, "source_url": "https://a.test", "occurrences": 2},
        {"kind": "env", "value": f"BREVO_API_KEY={FAKE_BREVO}", "source_url": "https://b.test", "occurrences": 1},
        {"kind": "brevo", "value": FAKE_BREVO, "source_url": "https://b.test", "occurrences": 1},
    ]
    out = normalize_result_secrets(secrets)
    by_provider = {}
    for item in out:
        by_provider.setdefault(item["provider"], []).append(item)

    assert "other" not in by_provider
    assert len(by_provider["stripe"]) == 1
    assert by_provider["stripe"][0]["value"] == FAKE_STRIPE_LIVE
    assert by_provider["stripe"][0]["kind"] == "stripe_live"
    assert len(by_provider["brevo"]) == 1
    assert by_provider["brevo"][0]["value"] == FAKE_BREVO
    assert not any(str(s.get("value", "")).lower().startswith("sk_test_") for s in out)
    assert not any("NEXTAUTH" in str(s.get("value", "")) for s in out)
    assert not any("EMAILJS" in str(s.get("value", "")) for s in out)
    assert not any("SANITY" in str(s.get("value", "")) for s in out)
    assert not any("PAYSTACK" in str(s.get("value", "")) for s in out)
    assert not any("MSI_SECRET" in str(s.get("value", "")) for s in out)


def test_extract_skips_sk_test_and_low_value_env():
    text = f"""
PAYSTACK_SECRET_KEY={FAKE_STRIPE_TEST}
STRIPE_SECRET_KEY={FAKE_STRIPE_LIVE}
STRIPE_TEST_KEY={FAKE_STRIPE_TEST}
NEXTAUTH_SECRET={FAKE_NEXTAUTH}
EMAILJS_PRIVATE_KEY={FAKE_EMAILJS}
SANITY_API_TOKEN={FAKE_SANITY}
BREVO_API_KEY={FAKE_BREVO}
"""
    secrets = extract_secrets(text, redact_values=False)
    values = [s["value"] for s in secrets]
    kinds = {s["kind"] for s in secrets}
    assert "stripe_live" in kinds
    assert FAKE_STRIPE_LIVE in values
    assert "stripe_test" not in kinds
    assert not any(str(v).lower().startswith("sk_test_") or "sk_test_" in str(v).lower() for v in values)
    assert not any("NEXTAUTH" in str(v) for v in values)
    assert not any("EMAILJS" in str(v) for v in values)
    assert not any("SANITY" in str(v) for v in values)
    assert not any("PAYSTACK" in str(v) for v in values)


def test_provider_for_kind_live_providers():
    assert provider_for_kind("stripe_live") == "stripe"
    assert provider_for_kind("brevo") == "brevo"
    assert provider_for_kind("unknown_vendor_key") == "other"
