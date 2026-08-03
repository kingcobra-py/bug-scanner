from app.extractors.cms_extractions import filter_cms_extractions

FAKE_GITHUB = "ghp_" + ("a" * 36)
FAKE_SENDGRID = "SG." + ("a" * 22) + "." + ("b" * 43)
FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
FAKE_GOOGLE = "AIza" + ("A" * 35)


def test_cms_filter_drops_noise_and_apis():
    extracted = filter_cms_extractions(
        {
            "secrets": [
                {"kind": "generic_api_key", "value": "abc123456789012345678901234567890"},
                {"kind": "jwt", "value": FAKE_JWT},
                {"kind": "google_api", "value": FAKE_GOOGLE},
                {"kind": "jconfig_password", "value": "SuperSecretPass1"},
                {"kind": "github_token", "value": FAKE_GITHUB},
                {"kind": "sendgrid", "value": FAKE_SENDGRID},
                {"kind": "env", "value": "APP_DEBUG=true"},
                {"kind": "env", "value": f"MAIL_PASSWORD={FAKE_SENDGRID}"},
            ],
            "smtp": [
                {"kind": "smtp", "value": {"host": "smtp.sendgrid.net", "pass": ""}, "confidence": 0.55},
                {
                    "kind": "smtp",
                    "value": {"host": "smtp.sendgrid.net", "user": "apikey", "pass": FAKE_SENDGRID},
                    "confidence": 0.92,
                },
            ],
            "apis": [{"kind": "api_path", "value": "/api/v1/users"}],
            "endpoints": ["/api/v1/users"],
        }
    )
    kinds = {s["kind"] for s in extracted["secrets"]}
    assert "generic_api_key" not in kinds
    assert "jwt" not in kinds
    assert "google_api" not in kinds
    assert "jconfig_password" not in kinds
    assert "github_token" in kinds
    assert "sendgrid" in kinds
    assert extracted["apis"] == []
    assert len(extracted["smtp"]) == 1
    assert extracted["smtp"][0]["value"]["pass"] == FAKE_SENDGRID
