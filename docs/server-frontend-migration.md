# Server + Frontend Migration Guide (Quick Copy)

This guide focuses on a minimal copy-and-run path.

## Package split

- `vulndb_mirror`: mirror crawler + storage + server + config + CLI
- `logic_vulns`: filter/tracer logic

Removed:

- `vulndb_channels`
- starter template
- all `aliyun_crawler` compatibility

## 1) Backend quick copy

Copy into target project:

- `src/vulndb_mirror/`
- `src/logic_vulns/`

Install dependencies:

```bash
uv add fastapi uvicorn pydantic pydantic-settings httpx[socks] playwright playwright-stealth beautifulsoup4 pyyaml
uv run playwright install chromium
```

Bootstrap server:

```python
from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.ingest_service import RawIngestService
from vulndb_mirror.storage.repository_factory import build_raw_repository

settings = CrawlerSettings()
repository = build_raw_repository(settings)
service = RawIngestService(settings.to_crawl_config(), repository)
app = create_app(repository, service)
```

Run:

```bash
uvicorn your_module:app --host 0.0.0.0 --port 8787
```

## 2) Frontend quick copy

Copy:

- `web/`

Set env:

- `NEXT_PUBLIC_API_BASE=http://127.0.0.1:8787`

Run:

```bash
cd web
npm install
npm run dev
```

## 3) Import map

- Server: `vulndb_mirror.server.create_app`
- Mirror config: `vulndb_mirror.config.CrawlerSettings`
- Filter: `logic_vulns.filter.FilterPipeline`
- Tracer: `logic_vulns.tracer.CalltraceExplorer`

## 4) Recommended target layout

```text
src/
  vulndb_mirror/
  logic_vulns/
web/
```

## 5) Verification checklist

1. `GET /health` returns `{"status": "ok"}`.
2. `GET /raw?page=1&page_size=20` returns items.
3. Frontend can fetch and paginate vulnerabilities.
4. Frontend can execute gaps/checkpoints/retry operations.
