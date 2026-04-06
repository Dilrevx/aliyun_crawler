# aliyun-crawler

抓取阿里云 AVD 漏洞数据并构建本地 RawDB。

本次重构后：
- 不再保留重构前兼容层代码。
- 统一使用分层包结构。
- 统一使用一个 CLI 命令入口：`aliyun-crawler`。

## 目录结构

```text
main.py
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

## 说明

- `main.py` 现在是薄入口，等价于执行 `uv run aliyun-crawler`。
- RawDB 是独立模块，支持 `file/sqlite/dual` 后端。
- 建议生产使用 `dual`，便于兼顾文件可读性与 sqlite 查询性能。
