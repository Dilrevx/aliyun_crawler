# aliyun-crawler

从 [avd.aliyun.com](https://avd.aliyun.com) 爬取 CVE 漏洞数据，当前默认只筛选**逻辑漏洞（访问控制/授权相关）**并保留有 GitHub Patch URL 的条目，然后可选用 LLM 标注从 HTTP 入口到漏洞触发点的调用链（calltrace）。

## 目录结构

```
main.py                  # 入口，三个主步骤 + 本地开关
src/aliyun_crawler/
  config.py              # 配置（从 .env 读取）
  models.py              # Pydantic 数据模型
  commit_resolver.py     # GitHub API：PR/Issue → commit SHA
  cli/                   # CLI 入口包
  crawler/               # 爬虫包（兼容旧 crawler.py）
  filter/                # 过滤器包（兼容旧 filter.py）
  server/                # FastAPI 服务器包
  storage/               # 存储包（兼容旧 storage.py）
  tracer/                # calltrace/tracer 包（兼容旧 calltrace.py）
  rawdb/                 # 独立 raw 数据库模块：file/sqlite/dual + API
.env.example             # 配置模板，复制为 .env 后填写
```

## 快速开始

### 1. 安装依赖

```bash
uv sync
uv run playwright install chromium
```

### 2. 创建配置文件

```bash
cp .env.example .env
```

然后编辑 `.env`，**至少填写** `LLM__API_KEY`。建议先关注关键变量，其它保持默认即可。

### 关键变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `LLM__API_KEY` | OpenAI 兼容接口密钥（必填） | — |
| `MAX_PAGES` | 爬取列表页数（每页 30 条） | `100` |
| `PAGE_CONCURRENCY` | Step1 按页并发窗口大小 | `4` |
| `SINCE` | 增量阈值（仅抓取该日期之后修改的条目） | 不限制 |
| `DATA_DIR` | 输出目录 | `./output/aliyun_cve` |

### 其他变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `GITHUB_TOKEN` | GitHub PAT，避免 API 速率限制 | 无认证 |
| `LLM__MODEL` | 模型名称 | `deepseek-v3.2` |
| `LLM__BASE_URL` | 自定义 API 地址（代理 / 本地模型） | OpenAI 官方 |
| `GIT_PROXY` | git 代理，如 `socks5://127.0.0.1:1080` | 无 |
| `GIT_CLONE_VIA_SSH` | 使用 SSH 克隆（需加载 SSH key） | `false` |
| `CALLTRACE_CONCURRENCY` | Step3 并行处理的 CVE 数量 | `5` |
| `CALLTRACE_MAX_ROUNDS` | 每个 CVE 最多 LLM 对话轮数 | `4` |
| `LOG_DIR` | 日志目录（按时间命名） | 关闭（仅终端） |

### 3. 运行

```bash
uv run python main.py
```

或者使用拆分后的命令入口：

```bash
uv run aliyun-crawler
uv run aliyun-rawdb
```

## RawDB 模块（新增）

RawDB 用于独立承载 raw 构建与查询能力，支持双写存储与页面级断点恢复。

### 存储后端

- `RAWDB_STORAGE_BACKEND=file`：仅本地文件（`<DATA_DIR>/raw/*.json` + `.rawdb.state.json`）
- `RAWDB_STORAGE_BACKEND=sqlite`：仅 SQLite（默认 `<DATA_DIR>/raw.db`）
- `RAWDB_STORAGE_BACKEND=dual`：双写（推荐，sqlite 主读 + file 兜底）

可选：`RAWDB_SQLITE_PATH=/abs/path/to/raw.db`

### CLI

```bash
# 增量抓取（默认从最早缺口页恢复）
uv run aliyun-rawdb crawl

# 从指定页开始
uv run aliyun-rawdb crawl --start-page 50

# 查看缺失/失败页段
uv run aliyun-rawdb gaps --max-page 200

# 重试指定页面
uv run aliyun-rawdb retry --pages 50 51 52

# 启动 FastAPI
uv run aliyun-rawdb api
```

对应的 CLI 分层入口现在也可以通过 `uv run aliyun-crawler` 启动，后续如果要再拆细命令，可以直接放进 `src/aliyun_crawler/cli/`。

### FastAPI 接口

- `GET /health`：健康检查
- `GET /raw/{cve_id}`：按 CVE 精确查询
- `GET /raw?modified_from=2024-01-01&modified_to=2024-12-31&page=1&page_size=50`：范围 + 分页查询
- `GET /pages/checkpoints`：查看页级检查点
- `GET /pages/gaps?max_page=200`：返回缺失/失败页段
- `POST /pages/retry`：重试指定页面
- `POST /crawl/resume`：按恢复策略继续抓取

## 运行流程（重构后）

### Step 1 – 仅爬取 RAW

- 用 Playwright（无头 Chromium + playwright-stealth 绕过 WAF）爬取列表页与详情页
- 按页并发抓取（窗口大小由 `PAGE_CONCURRENCY` 控制，默认 `4`）
- 虽然抓取并发，但结果按页序消费，确保 `since` 旧数据截断与 break 语义正确
- 不做业务筛选，直接写入 `<DATA_DIR>/raw/<CVE-ID>.json`

### Step 2 – RAW → YAML 过滤

- 过滤条件（AND 逻辑）：
  - 命中“逻辑漏洞启发式”：
    - 主条件：CWE ∈ {`CWE-284`, `CWE-285`, `CWE-862`, `CWE-863`, `CWE-639`}
    - 补充条件：标题/描述中命中访问控制关键词（用于补漏）
  - 至少有一个可解析的 GitHub commit / PR / Issue URL
- 命中的条目写入 `<DATA_DIR>/yaml/<CVE-ID>.yaml`（初始 YAML，calltrace 字段为空）

### Step 3 – LLM calltrace 标注（可选）

- 通过 GitHub API 将 patch URL（commit / PR / Issue）解析为具体 commit SHA
- 克隆（或复用缓存的）仓库，切到漏洞版本（patch commit 的父提交）
- 运行 `git diff` 获取 patch 内容，识别被修改的方法
- 多轮 LLM 对话：从 patch 点**反向追溯**到 HTTP / RPC 入口点
  - 若 entry point 和 patch 不在同一文件，LLM 可在每轮请求更多源文件
  - 达到 `CALLTRACE_MAX_ROUNDS` 后强制要求给出最终答案
- 结果写回 `<DATA_DIR>/yaml/<CVE-ID>.yaml`，填充 `CallTrace`、`patch_method_before/after`、`source`、`sink`、`reason` 字段

### main 内开关

在 `main()` 中直接控制，不新增 `.env` 开关：

- `run_step1_crawl_raw`
- `run_step2_filter_yaml`
- `run_step3_calltrace`

当 Step1 关闭但 Step2 打开时，Step2 会自动读取现有 raw 文件继续处理。

## 过滤机制反思（充分/必要/等价）

- **CWE 过滤不是“逻辑漏洞”的充要条件，也不等价**。
- 仅用 CWE 做主判定，精度较高，但会漏掉 CWE 标注缺失或标注不稳定的条目（非必要）。
- 仅用关键词做判定，召回更高，但会引入噪声（非充分）。
- 当前采用“CWE 主判定 + 关键词补漏 + patch_url 约束”的折中策略，实际效果通常比单一条件更稳。

## 并发与性能现状

- Step1（爬虫）是主要瓶颈：已改为按页并发窗口抓取，但仍保留每条详情请求的随机延迟（抗封禁）。
- Step3（LLM 标注）支持并发，受 `CALLTRACE_CONCURRENCY` 控制。
- 已在 Step1 增加运行统计日志（总耗时与 entries/s），并在代码里提供了本地延迟覆盖（`_STEP1_DELAY_RANGE_OVERRIDE`）用于加速测试。

## 日志

日志默认输出到 `stderr`，格式：

```
2026-03-16 12:00:00,123 INFO __main__: === Step 1 – crawl (max_pages=5) ===
2026-03-16 12:00:05,456 INFO __main__: accepted  CVE-2024-12345  cwe=CWE-79     patches=2
2026-03-16 12:00:05,457 INFO __main__: Step 1 complete – 3 entries accepted
2026-03-16 12:00:06,000 INFO __main__: === Step 2 – resolving patch commits for 3 entries ===
2026-03-16 12:00:10,000 INFO __main__: resolved  CVE-2024-12345  →  https://github.com/...  @  abc1234def56
2026-03-16 12:00:10,001 INFO __main__: === Step 2 – LLM annotation (3 targets, concurrency=5) ===
2026-03-16 12:01:00,000 INFO __main__: annotated  CVE-2024-12345  rounds=2  tokens=3812
2026-03-16 12:01:01,000 INFO __main__: Step 2 complete – 3 entries annotated  total_tokens=10234
```

调整日志级别：在 `.env` 中无对应配置项，直接修改 [main.py](main.py) 顶部的 `logging.basicConfig` 调用：

```python
# 更详细（显示筛掉的条目、git 命令、LLM 每轮响应片段）
logging.basicConfig(level=logging.DEBUG, ...)

# 只看关键信息
logging.basicConfig(level=logging.WARNING, ...)
```

写入文件同时保留终端输出：

```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("crawler.log", encoding="utf-8"),
    ],
)
```

## 输出文件说明

```
output/aliyun_cve/
  .state.json          # 增量爬取状态（最近一次爬到的修改时间）
  raw/
    CVE-2024-12345.json   # RawAVDEntry：爬虫原始抓取数据
  yaml/
    CVE-2024-12345.yaml   # AVDCveEntry：含 calltrace 的完整结构
  repos/
    owner__repo/          # 已克隆的 Git 仓库（自动复用）
```
