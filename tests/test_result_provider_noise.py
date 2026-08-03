from app.core.providers import classify_env_assignment, provider_for_kind
from app.core.result_secrets import normalize_result_secrets
from app.extractors.secret_extractor import extract_secrets

# Synthetic fixtures only (built in parts so scanners ignore them).
FAKE_STRIPE = "sk_" + "live_" + ("E" * 28)
FAKE_PAYSTACK = "sk_" + "test_" + ("0" * 40)
FAKE_BREVO = "xkeysib-" + ("a" * 64) + "-" + ("b" * 16)
FAKE_NEXTAUTH = "a" * 64
FAKE_EMAILJS = "emailjs_private_fixture_001"
FAKE_SANITY = "sk" + ("Z" * 100) + "sanityFixtureToken000001"


def test_classify_env_promotes_known_providers():
    assert classify_env_assignment("STRIPE_SECRET_KEY", FAKE_STRIPE) == ("stripe", "stripe_live", FAKE_STRIPE)
    assert classify_env_assignment("PAYSTACK_SECRET_KEY", FAKE_PAYSTACK) == ("paystack", "paystack", FAKE_PAYSTACK)
    assert classify_env_assignment("APPSETTING_PAYSTACK_SECRET_KEY", FAKE_PAYSTACK) == (
        "paystack",
        "paystack",
        FAKE_PAYSTACK,
    )
    assert classify_env_assignment("BREVO_API_KEY", FAKE_BREVO) == ("brevo", "brevo", FAKE_BREVO)
    assert classify_env_assignment("EMAILJS_PRIVATE_KEY", FAKE_EMAILJS)[0] == "emailjs"
    assert classify_env_assignment("SANITY_API_TOKEN", FAKE_SANITY)[0] == "sanity"


def test_normalize_drops_bool_msi_placeholder_noise():
    secrets = [
        {"kind": "env", "value": "DD_LOGS_INJECTION=true", "source_url": "https://a.test", "occurrences": 1},
        {"kind": "env", "value": "windowsHide=true", "source_url": "https://b.test", "occurrences": 1},
        {
            "kind": "env",
            "value": "MSI_SECRET=ac47478f-7806-afa4-4506-af6c1ab747c6",
            "source_url": "https://c.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": "NEXTAUTH_SECRET=some-secret-key",
            "source_url": "https://d.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"NEXTAUTH_SECRET={FAKE_NEXTAUTH}",
            "source_url": "https://e.test",
            "occurrences": 1,
        },
    ]
    out = normalize_result_secrets(secrets)
    values = [s["value"] for s in out]
    assert values == [f"NEXTAUTH_SECRET={FAKE_NEXTAUTH}"]
    assert out[0]["provider"] == "other"


def test_normalize_dedupes_provider_env_and_token_rows():
    secrets = [
        {"kind": "env", "value": f"STRIPE_SECRET_KEY={FAKE_STRIPE}", "source_url": "https://a.test", "occurrences": 1},
        {"kind": "stripe_live", "value": FAKE_STRIPE, "source_url": "https://a.test", "occurrences": 2},
        {"kind": "env", "value": f"BREVO_API_KEY={FAKE_BREVO}", "source_url": "https://b.test", "occurrences": 1},
        {"kind": "brevo", "value": FAKE_BREVO, "source_url": "https://b.test", "occurrences": 1},
        {
            "kind": "env",
            "value": f"APPSETTING_PAYSTACK_SECRET_KEY={FAKE_PAYSTACK}",
            "source_url": "https://c.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"PAYSTACK_SECRET_KEY={FAKE_PAYSTACK}",
            "source_url": "https://c.test",
            "occurrences": 1,
        },
        {"kind": "stripe_test", "value": FAKE_PAYSTACK, "source_url": "https://c.test", "occurrences": 1},
        {
            "kind": "env",
            "value": f"APPSETTING_EMAILJS_PRIVATE_KEY={FAKE_EMAILJS}",
            "source_url": "https://d.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"EMAILJS_PRIVATE_KEY={FAKE_EMAILJS}",
            "source_url": "https://d.test",
            "occurrences": 1,
        },
        {
            "kind": "env",
            "value": f"SANITY_API_TOKEN={FAKE_SANITY}",
            "source_url": "https://d.test",
            "occurrences": 1,
        },
    ]
    out = normalize_result_secrets(secrets)
    by_provider = {}
    for item in out:
        by_provider.setdefault(item["provider"], []).append(item)

    assert len(by_provider["stripe"]) == 1
    assert by_provider["stripe"][0]["value"] == FAKE_STRIPE
    assert by_provider["stripe"][0]["kind"] == "stripe_live"
    assert by_provider["stripe"][0]["occurrences"] == 2

    assert len(by_provider["brevo"]) == 1
    assert by_provider["brevo"][0]["value"] == FAKE_BREVO

    assert len(by_provider["paystack"]) == 1
    assert by_provider["paystack"][0]["value"] == FAKE_PAYSTACK
    assert by_provider["paystack"][0]["kind"] == "paystack"

    assert len(by_provider["emailjs"]) == 1
    assert by_provider["emailjs"][0]["value"] == FAKE_EMAILJS

    assert len(by_provider["sanity"]) == 1
    assert "other" not in by_provider or not any(
        FAKE_STRIPE in str(s.get("value")) or FAKE_BREVO in str(s.get("value")) for s in by_provider.get("other", [])
    )


def test_extract_paystack_not_stripe():
    text = f"PAYSTACK_SECRET_KEY={FAKE_PAYSTACK}\nSTRIPE_SECRET_KEY={FAKE_STRIPE}\n"
    secrets = extract_secrets(text, redact_values=False)
    kinds = {s["kind"] for s in secrets}
    values = {s["value"] for s in secrets}
    assert "paystack" in kinds
    assert "stripe_live" in kinds
    assert FAKE_PAYSTACK in values
    assert FAKE_STRIPE in values
    # Paystack value must not also be emitted as stripe_test.
    assert not any(s["kind"] == "stripe_test" and s["value"] == FAKE_PAYSTACK for s in secrets)


def test_provider_for_kind_covers_new_providers():
    assert provider_for_kind("paystack") == "paystack"
    assert provider_for_kind("sanity") == "sanity"
    assert provider_for_kind("emailjs") == "emailjs"
    assert provider_for_kind("stripe_live") == "stripe"
