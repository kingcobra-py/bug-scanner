from app.api.server import normalize_result_secrets


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
