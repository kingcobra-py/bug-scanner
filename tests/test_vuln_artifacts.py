from pathlib import Path

from app.core.vuln_artifacts import (
    classify_finding,
    detection_method,
    host_from_finding,
    write_vuln_artifacts,
)


def test_classify_and_host():
    f = {
        "module": "config",
        "target": "https://10.1.2.3",
        "url": "https://10.1.2.3/.env",
        "title": "Exposed .env",
        "severity": "critical",
        "type": "env",
        "tags": ["env"],
        "id": "1",
    }
    assert host_from_finding(f) == "10.1.2.3"
    assert "env" in classify_finding(f)
    assert detection_method(f, ["env"]) == "env"


def test_write_vuln_artifacts_tree(tmp_path):
    findings = [
        {
            "id": "a1",
            "module": "git",
            "target": "https://git.victim.test",
            "url": "https://git.victim.test/.git/HEAD",
            "title": "Exposed .git/HEAD",
            "severity": "high",
            "type": "path",
            "tags": ["git"],
            "confidence": 0.95,
            "evidence": "ref: refs/heads/main",
            "extracted": {},
        },
        {
            "id": "a2",
            "module": "wordpress",
            "target": "https://wp.victim.test",
            "url": "https://wp.victim.test/wp-json/batch/v1",
            "title": "WordPress REST batch endpoint reachable",
            "severity": "medium",
            "type": "other",
            "tags": ["wordpress", "wp2shell"],
            "confidence": 0.82,
            "evidence": "batch",
            "extracted": {"secrets": [{"kind": "github_token", "value": "ghp_xxx"}]},
        },
        {
            "id": "a3",
            "module": "react",
            "target": "https://next.victim.test",
            "url": "https://next.victim.test/package.json",
            "title": "React2Shell affected package version: next@15.0.3",
            "severity": "critical",
            "type": "vuln",
            "tags": ["react2shell", "cve-2025-55182"],
            "confidence": 0.92,
            "evidence": "next 15.0.3",
            "extracted": {},
        },
        {
            "id": "a4",
            "module": "joomla",
            "target": "https://joom.victim.test",
            "url": "https://joom.victim.test/plugins/editors/jce/jce.xml",
            "title": "JCE 2.9.80 matches CVE-2026-48907 exposure range",
            "severity": "critical",
            "type": "vuln",
            "tags": ["joomla", "jce", "cve-2026-48907"],
            "confidence": 0.93,
            "evidence": "JCE",
            "extracted": {},
        },
    ]
    # seed a raw evidence file referenced by one finding
    evid = tmp_path / "evidence"
    evid.mkdir()
    raw = evid / "env_sample.txt"
    raw.write_text("AWS_ACCESS_KEY_ID=AKIATEST\n", encoding="utf-8")
    findings.append(
        {
            "id": "a5",
            "module": "config",
            "target": "https://env.victim.test",
            "url": "https://env.victim.test/.env",
            "title": "Exposed .env",
            "severity": "critical",
            "type": "env",
            "tags": ["env"],
            "confidence": 0.95,
            "evidence": "KEY=",
            "raw_ref": str(raw),
            "extracted": {},
        }
    )

    bundle = write_vuln_artifacts(tmp_path, findings)
    vulns = Path(bundle["dir"])
    assert (vulns / "by_target.json").exists()
    assert (vulns / "by_method.json").exists()
    assert (vulns / "hosts.txt").exists()
    assert (vulns / "git" / "index.jsonl").exists()
    assert (vulns / "env" / "index.jsonl").exists()
    assert (vulns / "wordpress" / "index.jsonl").exists()
    assert (vulns / "react2shell" / "index.jsonl").exists()
    assert (vulns / "joomla" / "index.jsonl").exists()
    hosts = (vulns / "hosts.txt").read_text().splitlines()
    assert "git.victim.test" in hosts
    assert "wp.victim.test" in hosts
    assert any(h["host"] == "wp.victim.test" and "wp2shell" in h["methods"] for h in bundle["vulnerable_hosts"])
    # raw body copied into category folder
    assert any(p.name.startswith("env.victim.test__body__") for p in (vulns / "env").glob("*"))

    # Second rewrite must replace the tree (rmtree), not accumulate duplicates.
    stale = vulns / "git" / "stale-should-vanish.json"
    stale.write_text("{}", encoding="utf-8")
    write_vuln_artifacts(tmp_path, findings[:1])
    assert not stale.exists()
    assert (vulns / "git" / "index.jsonl").exists()
    assert not (vulns / "wordpress" / "index.jsonl").exists()
