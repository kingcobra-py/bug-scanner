#!/usr/bin/env python3
"""BB Scanner CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from app.core.engine import ScanEngine
from app.core.wordlists import load_wordlist
from app.storage.db import ScanStore
from app.storage.models import ScanConfig
from app.utils.logger import setup_root_logger


ROOT = Path(__file__).resolve().parent


def load_yaml_config(path: Path | None = None) -> dict:
    cfg_path = path or (ROOT / "config" / "default.yaml")
    if not cfg_path.exists():
        return {}
    with cfg_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def cmd_scan(args: argparse.Namespace) -> int:
    yml = load_yaml_config()
    scanner = yml.get("scanner", {})
    setup_root_logger("DEBUG" if args.verbose else yml.get("logging", {}).get("level", "INFO"))

    targets: list[str] = []
    if args.target:
        targets.extend(args.target)
    if args.targets_file:
        targets.extend(
            ln.strip()
            for ln in Path(args.targets_file).read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )
    if not targets:
        print("No targets provided. Use -t URL and/or -t targets.txt / --targets-file", file=sys.stderr)
        return 2

    # support -t file path convenience
    expanded: list[str] = []
    for t in targets:
        p = Path(t)
        if p.exists() and p.is_file():
            expanded.extend(
                ln.strip()
                for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )
        else:
            expanded.append(t)
    targets = expanded

    modules = [m.strip() for m in (args.modules or "git,js,config,path,methods,wordpress,joomla,react").split(",") if m.strip()]
    custom_paths: list[str] = []
    if args.paths:
        custom_paths = load_wordlist(args.paths)

    formats = [f.strip() for f in (args.format or "json,md,csv").split(",") if f.strip()]
    cfg = ScanConfig(
        targets=targets,
        threads=args.threads or scanner.get("threads", 20),
        worker_processes=max(1, int(args.processes or 1)),
        timeout=args.timeout or scanner.get("timeout", 8.0),
        modules=modules,
        paths_mode=args.paths_mode or yml.get("paths", {}).get("mode", "merge"),
        custom_paths=custom_paths,
        output_dir=args.output or yml.get("output", {}).get("dir", "output/scans"),
        formats=formats,
        verify_tls=bool(scanner.get("verify_tls", False)),
        proxy=args.proxy or yml.get("proxy"),
        verbose=bool(args.verbose),
        method_test_trace=bool(args.trace_method),
    )

    store = ScanStore(Path(cfg.output_dir) / "scanner.db")
    engine = ScanEngine(store=store, enable_cli_progress=True)
    try:
        report = engine.run(cfg)
    except KeyboardInterrupt:
        engine.stop(cfg.scan_id)
        print("\nInterrupted — stopping scan...", file=sys.stderr)
        return 130

    if report.get("error"):
        print(f"Scan failed: {report['error']}", file=sys.stderr)
        return 1
    summary = report.get("summary", {})
    print(
        f"Scan {summary.get('scan_id')} complete — findings={summary.get('finding_count', 0)} "
        f"severity={summary.get('by_severity', {})}"
    )
    print(f"Reports: {Path(cfg.output_dir) / cfg.scan_id}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from app.api.server import app

    yml = load_yaml_config()
    dash = yml.get("dashboard", {})
    host = args.host or dash.get("host", "0.0.0.0")
    port = args.port or dash.get("port", 8080)
    setup_root_logger("INFO")
    uvicorn.run(app, host=host, port=int(port), log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BB Scanner — authorized web vulnerability recon scanner")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Run a scan")
    s.add_argument("-t", "--target", action="append", default=[], help="Target URL/host or list file (repeatable)")
    s.add_argument("--targets-file", help="File with targets")
    s.add_argument("--threads", type=int, default=None)
    s.add_argument(
        "--processes",
        type=int,
        default=1,
        help="Run across N OS processes instead of one (bypasses Python's single-core GIL ceiling for large scans)",
    )
    s.add_argument("--timeout", type=float, default=None)
    s.add_argument("--modules", default="git,js,config,path,methods,wordpress,joomla,react")
    s.add_argument("--paths", help="Custom path wordlist .txt")
    s.add_argument("--paths-mode", choices=["merge", "custom_only", "builtin_only"], default="merge")
    s.add_argument("--output", default=None)
    s.add_argument("--format", default="json,md,csv")
    s.add_argument("--proxy", default=None)
    s.add_argument("--trace-method", action="store_true")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    srv = sub.add_parser("serve", help="Start dashboard API/UI")
    srv.add_argument("--host", default=None)
    srv.add_argument("--port", type=int, default=None)
    srv.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())