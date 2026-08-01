from app.modules.base import finding_from_hit, stream_findings
from app.storage.models import TargetContext
from app.utils.logger import add_log_subscriber, get_scan_logger, remove_log_subscriber


def test_normal_log_calls_emit_live_events(tmp_path):
    events = []
    callback = events.append
    add_log_subscriber(callback)
    try:
        logger = get_scan_logger("live-log-test", tmp_path, module="js")
        logger.info("module hit %s", "https://example.test/app.js")
    finally:
        remove_log_subscriber(callback)

    assert len(events) == 1
    assert events[0]["scan_id"] == "live-log-test"
    assert events[0]["module"] == "js"
    assert events[0]["message"] == "module hit https://example.test/app.js"


def test_finding_stream_fires_when_finding_is_created():
    streamed = []
    target = TargetContext(url="https://example.test", live=True)

    with stream_findings(streamed.append):
        finding = finding_from_hit(
            module="js",
            ftype="js_secret",
            severity="critical",
            target=target,
            url="https://example.test/app.js",
            title="API key",
            evidence="key",
            confidence=0.9,
        )
        assert streamed == [finding]

    # Thread-local callback is removed after the module scope exits.
    finding_from_hit(
        module="js",
        ftype="js_secret",
        severity="critical",
        target=target,
        url="https://example.test/other.js",
        title="Other key",
        evidence="key",
        confidence=0.9,
    )
    assert streamed == [finding]
