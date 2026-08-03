# BB Scanner

Production-oriented **authorized** bug-bounty recon scanner in Python.

It discovers exposed git/config/env/JS paths, fingerprints WordPress / Joomla / React-Next, extracts APIs · tokens · SMTP credentials, tests HTTP methods, and streams progress to a FastAPI dashboard.

> **Safety:** Weaponized RCE exploit PoCs (React2Shell command execution, wp2shell RCE, Joomla webshell upload) are **not** executed. CMS/framework modules integrate those surfaces as **safe detection only**: version scoring, endpoint reachability, and webshell path indicators. See `app/exploits/README.md`.

## Features

- Thread-pool scan engine (`ThreadPoolExecutor`)
- httpx client with retries, soft-404 baseline, 403/404 alternates, method probing
- Built-in wordlists for git / JS / config / sensitive paths + custom upload merge modes
- High-quality extractors (env/json parsers + regex packs, placeholder filtering, redaction)
- Rich CLI progress + rotating per-scan logs
- Dashboard UI with live websocket progress/logs/findings
- SQLite history + JSON/MD/CSV reports + evidence files

## Install

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI

```bash
# scan targets
python main.py scan -t targets.txt --threads 30 --timeout 8 \
  --modules git,js,config,path,methods,wordpress,joomla,react \
  --paths custom_paths.txt --paths-mode merge \
  --output output/scans --format json,md,csv --verbose

# single target
python main.py scan -t https://authorized-target.example --threads 20

# dashboard
python main.py serve --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8080`.

## Docker

```bash
docker compose up --build
```

## Pipeline order

1. Ingest targets + config + optional custom wordlist  
2. Normalize + dedupe  
3. Live probe (HTTP/HTTPS)  
4. Soft-404 baseline  
5. Fingerprint  
6. Path discovery (git / js / config / custom)  
7. Crawl HTML/JS  
8. Method testing  
9. Safe CMS/framework detectors (WP / Joomla / React-Next)  
10. Extract APIs/secrets/SMTP  
11. Validate + score + dedupe  
12. Reports + live dashboard updates  

## Module interface

```python
class ScanModule(Protocol):
    name: str
    def match(self, target: TargetContext) -> bool: ...
    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]: ...
```

Add a detector under `app/modules/`, wire it in `app/core/engine.py` `_build_modules()`, and expose a dashboard toggle.

## Custom wordlists

- One path per line, `#` comments ignored  
- Normalized to leading `/`  
- Modes: `merge` | `custom_only` | `builtin_only`  
- Upload via CLI `--paths` or dashboard `/api/wordlists/upload`  
- Built-in path discovery uses `wordlists/common_sensitive.txt` plus the extended `wordlists/default_paths.txt` set (~12k paths)

## Tests

```bash
pytest -q
```

Coverage includes extractors, fingerprinting, HTTP client soft-404/timeout/methods, dedupe/wordlists, and a local fixture end-to-end scan.

## Config

Defaults live in `config/default.yaml` (threads, timeouts, modules, output, dashboard).

## Authorization

Only scan systems you are explicitly authorized to test. Secrets are redacted in normal logs/UI (`show_last` configurable).