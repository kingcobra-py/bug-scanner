from types import SimpleNamespace
from unittest.mock import MagicMock

from app.core.engine import ScanEngine
from app.storage.models import Finding, ScanConfig, ScanContext, TargetContext


class _Mod:
    def __init__(self, name: str, order: list[str]):
        self.name = name
        self._order = order

    def match(self, target):
        return True

    def run(self, target, ctx):
        self._order.append(self.name)
        return []


def test_scan_target_runs_modules_in_random_order(monkeypatch):
    engine = ScanEngine(enable_cli_progress=False)
    seen = []
    for _ in range(40):
        order: list[str] = []
        modules = [_Mod("git", order), _Mod("path", order), _Mod("wordpress", order), _Mod("react", order)]
        cfg = ScanConfig(targets=["https://example.test"], modules=["git", "path", "wordpress", "react"])
        progress = MagicMock()
        ctx = ScanContext(
            config=cfg,
            output_dir="/tmp",
            stop_event=SimpleNamespace(is_set=lambda: False),
            progress=progress,
            store=None,
            http=None,
            logger=None,
        )
        target = TargetContext(url="https://example.test", live=True, tech=[])
        engine._scan_target(target, modules, ctx, on_finding=None)
        seen.append(tuple(order))
    # With a fair shuffle, not every run should keep the original order.
    assert len(set(seen)) > 1
    assert all(len(o) == 4 for o in seen)
