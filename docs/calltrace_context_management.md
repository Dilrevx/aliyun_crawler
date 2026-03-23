# Calltrace Context Management 方案说明

本文针对 `CalltraceExplorer` 的两阶段流程（Explorer + Validator）给出可落地的上下文管理方案，重点回答：
- 为什么保留 `max_rounds` 是合理的
- 如何在 token/质量/延迟之间做平衡
- 如何从当前实现平滑演进

关于 explorer 的上下文管理：有基础版，但不算强。

有：多轮 messages 累积上下文、按轮请求文件、每轮最多 10 个文件、每文件截断、最多 max_rounds（calltrace.py:787-877）。
没有：智能裁剪旧对话、去重/优先级重排、token 预算驱动压缩、跨轮摘要记忆。
## 1. 当前实现（Baseline）

当前 `explorer` 的上下文策略：
- 固定 `max_rounds`（例如 4）
- 每轮最多请求 10 个文件
- 单文件内容截断（6k~8k 字符）
- 所有历史消息持续累积到 `messages`

优点：
- 简单、稳定、易排障
- 对中小仓库效果可接受

缺点：
- 对话只增不减，后续轮次 prompt 膨胀
- 没有“高价值上下文优先”机制
- 大仓库容易触发噪声堆积

## 2. 方案 A：固定轮次 + 文件预算（推荐起点）

在 Baseline 上增加“预算意识”，但不引入复杂状态机。

### 关键策略
- `max_rounds` 保持固定（例如 4）
- 每轮文件数限制：`N`（如 6~10）
- 每轮总字符上限：`round_char_budget`（如 40k）
- 文件优先级：
  1) diff 涉及文件
  2) 与已知链路同目录文件
  3) 名称命中 controller/router/service/handler 等关键词

### 适用场景
- 追求实现成本低
- 需要快速稳定上线

### 风险
- 仍有“关键信息被截断”可能

## 3. 方案 B：滑动窗口（Sliding Window）

核心思想：不保留全部历史对话，只保留“最近 K 轮 + 摘要”。

### 关键策略
- 历史消息分为：
  - `working_window`：最近 1~2 轮原文
  - `summary_memory`：更早轮次压缩摘要
- 每轮结束后：
  - 把最旧一轮合并进摘要
  - 保持窗口大小恒定

### 适用场景
- 仓库大、调用链长
- token 成本敏感

### 风险
- 摘要失真会误导后续推理

## 4. 方案 C：证据图（Evidence Graph）+ 检索

把上下文从“聊天记录”升级为“结构化证据库”。

### 关键策略
- 每轮把发现写成结构化事实：
  - `entry_points`
  - `call_edges`（caller -> callee）
  - `sink_candidates`
  - `open_questions`
- 下一轮只把“与 open_questions 相关”的证据送给模型

### 适用场景
- 要求可解释性和可审计
- 需要长期演进成生产级系统

### 风险
- 开发复杂度最高

## 5. 方案 D：双模型（Planner / Analyzer）

用一个轻量模型做“文件规划”，重模型做“调用链分析”。

### 关键策略
- Planner 负责：下一轮要看哪些文件、为什么
- Analyzer 负责：基于输入证据输出 trace
- Validator 继续做最终一致性收敛

### 适用场景
- 成本和时延压力较大

### 风险
- 链路复杂，调试成本上升

## 6. `max_rounds` 为什么合理

`max_rounds` 的价值不只是“防死循环”，还有：
- **确定性成本上界**：总 token 成本可预估
- **确定性时延上界**：不会因单个 CVE 长尾卡死
- **失败可恢复**：达到上限后可进入 validator 收敛，产出可用结果

建议范围：
- 小仓库：3~4
- 中仓库：4~6
- 大仓库：6+（建议配合滑动窗口/证据图）

## 7. 推荐落地路径（从当前代码演进）

### Phase 1（低风险，立即可做）
- 保持 `max_rounds`
- 新增每轮字符预算 + 文件优先级
- 保持现有 Explorer/Validator 结构

### Phase 2（中等复杂度）
- 引入滑动窗口摘要
- 增加“证据摘要字段”到每轮 follow-up

### Phase 3（高价值）
- 引入证据图 + 检索
- 让 validator 校验“证据是否覆盖关键链路节点”

## 8. 评估指标（建议）

每个 CVE 记录：
- explorer 轮次
- prompt/completion token
- 请求文件数
- 最终 trace 条数
- validator 是否重写 trace
- 是否命中 entry/sink 关键字

建议按周看：
- 成功率（有有效 trace）
- 平均 token 成本
- P95 时延
- 人工抽检准确率

## 9. 与当前 patch-method 规则的关系

- 原始 diff 仍是主要事实来源
- patch-method 提取可作为“软提示（hint）”，不应作为强阻断条件
- validator 可把“是否覆盖 hint”作为质量信号，而非 hard fail

这样可以在“规则不准”的现实下，保留可用提示信息，同时避免误杀。

---
applyTo: "**"
description: "Use when reading many files or long files; enforce post-read context compaction, concise digests, and line-accurate edit planning"
---

# Context Compaction Rule

When code exploration involves many files or long files, always compress context immediately after each read batch.

## Required behavior

1. After every 3-5 read/search tool calls, produce a short "Context Digest" with:
   - Goal (1 line)
   - Key findings (max 5 bullets)
   - Open questions/unknowns (max 3 bullets)
   - Next action (1 line)

2. Replace verbose restatement with references to symbols/files only.

3. Before editing, create an "Edit Plan" that includes:
   - Target file
   - Function/class/symbol scope
   - Why this location is chosen
   - Expected side effects

4. For line-accurate edits, prefer this workflow:
   - `grep_search`/`semantic_search` to locate symbols
   - `read_file` with narrow ranges around target symbols
   - Avoid reading full files repeatedly unless required

5. Keep runtime memory bounded:
   - Do not repeat unchanged context summaries.
   - Carry forward only the latest digest plus unresolved items.

## Style constraints

- Keep each digest under 120 words.
- Prefer bullets over paragraphs.
- Avoid duplicating previously confirmed facts.
