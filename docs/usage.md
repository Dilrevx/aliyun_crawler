# Usage

## Quick Start

1. Install dependencies:

```bash
uv sync
uv run playwright install chromium
```

2. Prepare env:

```bash
cp .env.example .env
```

3. Run crawler:

```bash
uv run vulndb-mirror crawl
```

## Commands

### Crawl incremental raw data

```bash
uv run vulndb-mirror crawl
uv run vulndb-mirror crawl --start-page 50
```

### Show missing/failed page ranges

```bash
uv run vulndb-mirror gaps
```

### Retry specific pages

```bash
uv run vulndb-mirror retry --pages 50 51 52
```

### Start API service

```bash
uv run vulndb-mirror api
```

If port `8787` is already in use:

```bash
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

Then open:

- `http://127.0.0.1:<RAWDB_API_PORT>/docs` for OpenAPI docs (default port is `8787`)

### Start standalone web UI

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

Web UI: `http://127.0.0.1:3000`

The browser is optimized for vulnerability triage:

- fixed left filter sidebar with summary stats
- inline detail cards in the list
- right-side drawer for full CVE details
- direct hyperlinks for detail / references / patch URLs
- configurable PoC status heuristics shown per CVE
- date filters hidden under advanced options

## Minimal Env Keys

```env
MAX_PAGES=200
PAGE_CONCURRENCY=4
DATA_DIR=./output/aliyun_cve
RAWDB_STORAGE_BACKEND=dual
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
LOG_DIR=./logs
```

## Output Locations

- Command JSON result: printed to terminal stdout.
- Raw files: `output/aliyun_cve/raw/CVE-*.json`.
- SQLite DB (when backend includes sqlite): `output/aliyun_cve/raw.db`.
- Page/meta state: `output/aliyun_cve/.rawdb.state.json`.
- Logs: `logs/*-crawler.log` (or custom path from `LOG_DIR`).
