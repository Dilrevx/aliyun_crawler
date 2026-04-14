# vulndb-mirror

精简后的漏洞镜像库，保留两个独立 Python 包：

- `vulndb_mirror`: 镜像抓取 + storage + server + CLI
- `logic_vulns`: 分析逻辑（`filter` + `tracer`）

历史重构中已移除：

- `vulndb_channels`
- starter template（`templates/vulndb-mirror-starter`）

## 快速安装

```bash
uv sync
uv run playwright install chromium
cp .env.example .env
```

## CLI

```bash
uv run vulndb-mirror crawl
uv run vulndb-mirror gaps
uv run vulndb-mirror retry --pages 50 51
uv run vulndb-mirror api
```

`crawl` 默认使用 `SYNC_MODE=hybrid`，会执行：

1. `head_incremental`：从第 1 页按 `SINCE`（未设置时回退到 `last_seen_date`）做前段增量。
2. `head` 阶段默认会跳过已有成功 checkpoint 的中间页，并保留前 `HEAD_RECHECK_PAGES` 页强制重查。

如需旧的单段线性行为：

```bash
SYNC_MODE=linear uv run vulndb-mirror crawl
```

常用环境变量（可写入 `.env`）：

```env
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10
```

如果默认端口 `8787` 被占用：

```bash
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

## FastAPI

- `GET /health`
- `GET /raw/{cve_id}`
- `GET /raw`
- `GET /pages/checkpoints`
- `GET /pages/gaps`
- `POST /pages/retry`
- `POST /crawl/resume`

## 快速拷贝到其他项目

仅需拷贝：

- `src/vulndb_mirror/`
- `src/logic_vulns/`

以及在目标项目安装依赖：

```bash
uv add fastapi uvicorn pydantic pydantic-settings httpx[socks] playwright playwright-stealth beautifulsoup4 pyyaml
uv run playwright install chromium
```

API 启动示例：

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

```bash
uvicorn your_module:app --host 0.0.0.0 --port 8787
```

## Web 前端

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

## 迁移文档

- `docs/server-frontend-migration.md`
- `docs/rawdb-package-evaluation.md`
- `docs/usage.md`
