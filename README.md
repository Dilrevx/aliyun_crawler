# aliyun-crawler

从 [avd.aliyun.com](https://avd.aliyun.com) 爬取 CVE 漏洞数据，按注入类 CWE 筛选并保留有 GitHub Patch URL 的条目，然后用 LLM 标注从 HTTP 入口到漏洞触发点的调用链（calltrace）。

## 目录结构

```
main.py                  # 入口，两个主步骤
src/aliyun_crawler/
  config.py              # 配置（从 .env 读取）
  crawler.py             # Playwright 爬虫
  filter.py              # 可链式组合的过滤管道
  models.py              # Pydantic 数据模型
  storage.py             # 文件持久化（JSON + YAML）
  commit_resolver.py     # GitHub API：PR/Issue → commit SHA
  calltrace.py           # Git 操作 + 异步多轮 LLM 对话
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

然后编辑 `.env`，**至少填写** `LLM__API_KEY`；其余可保持默认：

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MAX_PAGES` | 爬取列表页数（每页 30 条），建议先用 3–5 测试 | `100` |
| `SINCE` | 只爬取该日期之后修改的条目（增量模式） | 不限制 |
| `DATA_DIR` | 输出目录 | `./output/aliyun_cve` |
| `GITHUB_TOKEN` | GitHub PAT，避免 API 速率限制 | 无认证 |
| `LLM__API_KEY` | OpenAI 兼容接口的密钥 **（必填）** | — |
| `LLM__MODEL` | 模型名称 | `gpt-4o` |
| `LLM__BASE_URL` | 自定义 API 地址（代理 / 本地模型） | OpenAI 官方 |
| `GIT_PROXY` | git 操作的代理，如 `socks5://127.0.0.1:1080` | 无 |
| `GIT_CLONE_VIA_SSH` | 使用 SSH 克隆（需加载 SSH key） | `false` |
| `CALLTRACE_CONCURRENCY` | 并行处理的 CVE 数量 | `5` |
| `CALLTRACE_MAX_ROUNDS` | 每个 CVE 最多 LLM 对话轮数 | `4` |

### 3. 运行

```bash
uv run python main.py
```

## 运行流程

### Step 1 – 爬取 + 过滤

- 用 Playwright（无头 Chromium + playwright-stealth 绕过 WAF）爬取列表页与详情页
- 过滤条件（AND 逻辑）：
  - CWE 属于注入 / 反序列化 / RCE 类型（CWE-79 / CWE-89 / CWE-78 / CWE-94 / CWE-502 / CWE-22 / CWE-611 / CWE-918 / CWE-917 / CWE-74 等）
  - 至少有一个可解析的 GitHub commit / PR / Issue URL
- 接受的条目写入：
  - `<DATA_DIR>/raw/<CVE-ID>.json`（原始数据）
  - `<DATA_DIR>/yaml/<CVE-ID>.yaml`（初始 YAML，calltrace 字段为空）

### Step 2 – LLM calltrace 标注

- 通过 GitHub API 将 patch URL（commit / PR / Issue）解析为具体 commit SHA
- 克隆（或复用缓存的）仓库，切到漏洞版本（patch commit 的父提交）
- 运行 `git diff` 获取 patch 内容，识别被修改的方法
- 多轮 LLM 对话：从 patch 点**反向追溯**到 HTTP / RPC 入口点
  - 若 entry point 和 patch 不在同一文件，LLM 可在每轮请求更多源文件
  - 达到 `CALLTRACE_MAX_ROUNDS` 后强制要求给出最终答案
- 结果写回 `<DATA_DIR>/yaml/<CVE-ID>.yaml`，填充 `CallTrace`、`patch_method_before/after`、`source`、`sink`、`reason` 字段

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
