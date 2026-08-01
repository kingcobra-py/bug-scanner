from app.core.engine import ScanEngine
from app.core.http_client import HttpResponse
from app.storage.db import ScanStore
from app.utils.normalize import origin_variants


class BothSchemesClient:
    def probe_live(self, url):
        return HttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            text="ok",
            content=b"ok",
            elapsed=0.01,
            method="GET",
        )


def test_origin_variants_honors_explicit_http_first():
    assert origin_variants("http://example.test") == [
        "http://example.test",
        "https://example.test",
    ]
    assert origin_variants("https://example.test") == [
        "https://example.test",
        "http://example.test",
    ]


def test_live_probes_returns_http_and_https(tmp_path):
    engine = ScanEngine(store=ScanStore(tmp_path / "scanner.db"), enable_cli_progress=False)
    live = engine._live_probes(BothSchemesClient(), "https://example.test", both=True)
    assert [target.url for target in live] == [
        "https://example.test",
        "http://example.test",
    ]


def test_explicit_http_is_selected_first(tmp_path):
    engine = ScanEngine(store=ScanStore(tmp_path / "scanner.db"), enable_cli_progress=False)
    selected = engine._live_probe(BothSchemesClient(), "http://example.test", both=True)
    assert selected.url == "http://example.test"
