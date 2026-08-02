from app.utils.dedupe import dedupe_findings, dedupe_strings, finding_id
from app.core.wordlists import merge_paths


def test_dedupe_strings():
    assert dedupe_strings(["a", "a", "b"]) == ["a", "b"]


def test_finding_id_stable():
    a = finding_id("env", "https://t", "https://t/.env", "Exposed", "x")
    b = finding_id("env", "https://t", "https://t/.env", "Exposed", "x")
    assert a == b


def test_dedupe_findings():
    f = {
        "type": "env",
        "target": "https://t",
        "url": "https://t/.env",
        "title": "Exposed",
        "extracted": {"secrets": [1]},
    }
    out = dedupe_findings([f, dict(f)])
    assert len(out) == 1
    assert out[0]["id"]


def test_merge_paths_modes():
    custom = ["admin", "# comment", "", "/backup.zip"]
    merged = merge_paths(custom, mode="merge", builtin_kinds=["git"])
    assert "/.git/HEAD" in merged
    assert "/admin" in merged
    assert "/backup.zip" in merged
    only = merge_paths(custom, mode="custom_only")
    assert only == ["/admin", "/backup.zip"]
    built = merge_paths(custom, mode="builtin_only", builtin_kinds=["git"])
    assert "/.git/HEAD" in built
    assert "/admin" not in built


def test_common_builtins_include_extended_default_paths():
    # Path module uses builtin_kinds=["common"], which must include both the
    # short common_sensitive list and the extended default_paths wordlist.
    built = merge_paths([], mode="builtin_only", builtin_kinds=["common"])
    assert "/admin" in built
    assert "/.env" in built or "/wp-config.php" in built
    assert "/secrets/secrets.env" in built or "/secrets/apikeys.txt" in built
    assert "/config/aws/prod/config.json" in built
    assert len(built) > 10_000
