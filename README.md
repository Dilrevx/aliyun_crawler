# aliyun-crawler

抓取阿里云 AVD 漏洞数据并构建本地 RawDB。

本次重构后：
- 不再保留重构前兼容层代码。
- 统一使用分层包结构。
- 统一使用一个 CLI 命令入口：`aliyun-crawler`。

## 目录结构

```text
main.py
web/
  src/app/page.tsx
  .env.local.example
src/aliyun_crawler/
  cli/
    app.py
  crawler/
    core.py
  filter/
    pipeline.py
  rawdb/
    api.py
    factory.py
    repositories.py
    service.py
  server/
    __init__.py
  storage/
    file_storage.py
  tracer/
    explorer.py
  utils/
    commit_resolver.py
  config.py
  models.py
```

## 安装

```bash
uv sync
uv run playwright install chromium
```

## 配置

复制并编辑环境变量：

```bash
cp .env.example .env
```

常用变量：

- `MAX_PAGES`: 最大抓取页数
- `PAGE_CONCURRENCY`: 按页并发
- `SINCE`: 增量时间下限（可选）
- `DATA_DIR`: 数据目录
- `RAWDB_STORAGE_BACKEND`: `file` / `sqlite` / `dual`
- `RAWDB_SQLITE_PATH`: sqlite 路径（可选）
- `RAWDB_API_HOST`, `RAWDB_API_PORT`: API 监听地址
- `LOG_DIR`: 日志目录，默认 `./logs`（可用环境变量覆盖）

## 单一启动命令

```bash
uv run aliyun-crawler crawl
```

这是推荐默认入口，按“缺口页优先 + 增量”策略抓取并写入 RawDB。

## 其他子命令

```bash
uv run aliyun-crawler retry --pages 50 51
uv run aliyun-crawler gaps
uv run aliyun-crawler api
```

## FastAPI 接口

- `GET /health`
- `GET /raw/{cve_id}`
- `GET /raw?modified_from=YYYY-MM-DD&modified_to=YYYY-MM-DD&page=1&page_size=50`
- `GET /pages/checkpoints`
- `GET /pages/gaps?max_page=200`
- `POST /pages/retry`
- `POST /crawl/resume`

## Web 前端（Next + Tailwind + React）

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

默认访问：`http://127.0.0.1:3000`

说明：
- 前端在独立 `web/` 目录，不与后端代码混合。
- 前端仅通过 HTTP API 访问数据，不直接访问持久化层。
- 主界面是漏洞浏览器，不是架构说明页。
- 左侧固定筛选栏 + 统计卡，中间卡片流，右侧抽屉详情。
- 列表直接展示摘要、CWE、CVSS、PoC 线索、补丁链接和详情。
- PoC 规则可切 `strict / balanced / loose`。
- 日期筛选收进高级筛选，默认不占主视觉。

## 说明

- `main.py` 现在是薄入口，等价于执行 `uv run aliyun-crawler`。
- RawDB 是独立模块，支持 `file/sqlite/dual` 后端。
- 建议生产使用 `dual`，便于兼顾文件可读性与 sqlite 查询性能。
- 爬虫运行中会按页完成即落盘（raw entry + checkpoint + meta），无需等任务整体结束。

## crawl 结果在哪里

- 终端标准输出：`uv run aliyun-crawler crawl` 会打印本次运行 JSON 结果。
- 原始数据文件：`output/aliyun_cve/raw/CVE-*.json`
- SQLite 数据库：`output/aliyun_cve/raw.db`（当后端包含 sqlite）
- 爬取状态文件：`output/aliyun_cve/.rawdb.state.json`
- 日志文件：`logs/*-crawler.log`（或 `LOG_DIR` 指定目录）
