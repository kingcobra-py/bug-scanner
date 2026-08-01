from app.core.fingerprint import fingerprint_response
from app.core.http_client import HttpResponse
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def _resp(text: str, headers=None) -> HttpResponse:
    return HttpResponse(
        url="https://example.test/",
        status_code=200,
        headers=headers or {},
        text=text,
        content=text.encode(),
        elapsed=0.01,
    )


def test_wordpress_fingerprint():
    html = (FIX / "wp_home.html").read_text()
    fp = fingerprint_response(_resp(html))
    assert "wordpress" in fp["tech"]
    assert fp["meta"].get("wordpress_version") == "6.4.2"


def test_next_fingerprint():
    html = (FIX / "next_home.html").read_text()
    fp = fingerprint_response(_resp(html))
    assert "nextjs" in fp["tech"]
    assert "react" in fp["tech"]


def test_joomla_fingerprint():
    html = (FIX / "joomla_home.html").read_text()
    fp = fingerprint_response(_resp(html))
    assert "joomla" in fp["tech"]
    assert fp["meta"].get("joomla_version") == "4.4.2"


def test_next_powered_by_and_rsc_headers():
    html = (FIX / "next_home.html").read_text()
    fp = fingerprint_response(
        _resp(
            html,
            headers={
                "x-powered-by": "Next.js 15.0.3",
                "rsc": "1",
                "next-router-state-tree": "1",
            },
        )
    )
    assert "nextjs" in fp["tech"]
    assert "rsc" in fp["tech"]
    assert fp["meta"].get("nextjs_version") == "15.0.3"