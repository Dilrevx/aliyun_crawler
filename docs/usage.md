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
uv run aliyun-crawler crawl
```

## Commands

### Crawl incremental raw data

```bash
uv run aliyun-crawler crawl
uv run aliyun-crawler crawl --start-page 50
```

### Show missing/failed page ranges

```bash
uv run aliyun-crawler gaps
```

### Retry specific pages

```bash
uv run aliyun-crawler retry --pages 50 51 52
```

### Start API service

```bash
uv run aliyun-crawler api
```

## Minimal Env Keys

```env
MAX_PAGES=200
PAGE_CONCURRENCY=4
DATA_DIR=./output/aliyun_cve
RAWDB_STORAGE_BACKEND=dual
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
```
