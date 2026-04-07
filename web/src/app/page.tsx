"use client";

import { useMemo, useState } from "react";

type RawItem = {
    cve_id: string;
    title?: string;
    description?: string;
    severity?: string;
    cvss_score?: number | null;
    cvss_vector?: string;
    cwe_id?: string;
    cwe_description?: string;
    published_date?: string | null;
    modified_date?: string | null;
    affected_software?: string[];
    references?: string[];
    patch_urls?: string[];
    detail_url?: string;
    crawled_at?: string;
};

type QueryResp = {
    page: number;
    page_size: number;
    total: number;
    items: RawItem[];
};

type CheckpointItem = {
    page: number;
    status: string;
    entry_count: number;
    has_next: boolean;
    error?: string | null;
    updated_at: string;
};

type GapsResp = {
    gaps: Array<{ start_page: number; end_page: number; reason: string }>;
    meta: Record<string, unknown>;
};

type CheckpointsResp = {
    items: CheckpointItem[];
    meta: Record<string, unknown>;
};

const API_BASE =
    process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://127.0.0.1:8787";

type PocMode = "all" | "yes" | "no";
type PoCRuleMode = "balanced" | "strict" | "loose";

async function apiGet<T>(path: string): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json()) as T;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json()) as T;
}

function textOrDash(value?: string | null) {
    return value && value.trim() ? value : "-";
}

function scoreText(score?: number | null) {
    return score === null || score === undefined ? "-" : score.toFixed(1);
}

function hostLabel(url: string) {
    try {
        return new URL(url).hostname.replace(/^www\./, "");
    } catch {
        return url;
    }
}

function toneClass(kind: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted") {
    switch (kind) {
        case "critical":
            return "bg-rose-600/15 text-rose-700 ring-rose-600/20";
        case "high":
            return "bg-amber-500/15 text-amber-700 ring-amber-500/20";
        case "medium":
            return "bg-sky-500/15 text-sky-700 ring-sky-500/20";
        case "warning":
            return "bg-violet-500/15 text-violet-700 ring-violet-500/20";
        case "info":
            return "bg-cyan-500/15 text-cyan-700 ring-cyan-500/20";
        case "low":
            return "bg-emerald-500/15 text-emerald-700 ring-emerald-500/20";
        default:
            return "bg-slate-500/10 text-slate-600 ring-slate-500/20";
    }
}

function riskTone(severity?: string) {
    const low = (severity || "").toLowerCase();
    if (low.includes("严重") || low.includes("critical")) return "critical";
    if (low.includes("高危") || low.includes("high")) return "high";
    if (low.includes("中危") || low.includes("medium")) return "medium";
    return "low";
}

function linkHost(url: string) {
    return hostLabel(url);
}

function summarizePoc(item: RawItem, mode: PoCRuleMode) {
    const refs = item.references || [];
    const patches = item.patch_urls || [];
    const text = `${item.title || ""} ${item.description || ""} ${refs.join(" ")}`.toLowerCase();
    const hasPocWords = /poc|proof\s*of\s*concept|exploit|exp\b|payload|reproduce/.test(text);

    if (mode === "strict") {
        if (patches.length > 0 && hasPocWords) return { label: "疑似 PoC", tone: "warning" as const };
        if (hasPocWords) return { label: "PoC 命中", tone: "warning" as const };
        return { label: "未见 PoC 线索", tone: "muted" as const };
    }

    if (mode === "loose") {
        if (hasPocWords) return { label: "PoC 线索", tone: "warning" as const };
        if (patches.length > 0 && refs.length > 0) return { label: "补丁/引用齐全", tone: "info" as const };
        return { label: "未见 PoC 线索", tone: "muted" as const };
    }

    if (patches.length > 0 && hasPocWords) return { label: "疑似 PoC", tone: "warning" as const };
    if (patches.length > 0 && refs.length > 0) return { label: "有补丁线索", tone: "info" as const };
    if (hasPocWords) return { label: "PoC 线索", tone: "warning" as const };
    return { label: "未见 PoC 线索", tone: "muted" as const };
}

function unique<T>(items: T[]) {
    return Array.from(new Set(items));
}

export default function Home() {
    const [query, setQuery] = useState<QueryResp | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [keyword, setKeyword] = useState("");
    const [cwe, setCwe] = useState("");
    const [severity, setSeverity] = useState("");
    const [patchOnly, setPatchOnly] = useState<PocMode>("all");
    const [pocOnly, setPocOnly] = useState<PocMode>("all");
    const [pocRuleMode, setPocRuleMode] = useState<PoCRuleMode>("balanced");
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [from, setFrom] = useState("");
    const [to, setTo] = useState("");
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);

    const [selected, setSelected] = useState<RawItem | null>(null);
    const [detailJson, setDetailJson] = useState<string>("{}");

    const [cveId, setCveId] = useState("");
    const [maxPage, setMaxPage] = useState(500);
    const [gaps, setGaps] = useState<GapsResp | null>(null);
    const [checkpoints, setCheckpoints] = useState<CheckpointsResp | null>(null);
    const [retryPages, setRetryPages] = useState("");
    const [retryResult, setRetryResult] = useState<string>("{}");

    const filteredItems = useMemo(() => {
        return (query?.items || []).filter((item) => {
            const pool = [
                item.cve_id,
                item.title,
                item.description,
                item.cwe_id,
                item.cwe_description,
                item.severity,
                item.cvss_vector,
                ...(item.references || []),
                ...(item.patch_urls || []),
            ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            if (keyword && !pool.includes(keyword.toLowerCase())) return false;
            if (cwe && (item.cwe_id || "").toLowerCase() !== cwe.toLowerCase()) return false;
            if (severity && (item.severity || "").toLowerCase() !== severity.toLowerCase()) {
                return false;
            }
            if (patchOnly === "yes" && !(item.patch_urls || []).length) return false;
            if (patchOnly === "no" && (item.patch_urls || []).length > 0) return false;

            const poc = summarizePoc(item, pocRuleMode).label;
            if (pocOnly === "yes" && poc === "未见 PoC 线索") return false;
            if (pocOnly === "no" && poc !== "未见 PoC 线索") return false;
            return true;
        });
    }, [query, keyword, cwe, severity, patchOnly, pocOnly, pocRuleMode]);

    const stats = useMemo(() => {
        const patchCount = filteredItems.filter((x) => (x.patch_urls || []).length > 0).length;
        const pocCount = filteredItems.filter((x) => summarizePoc(x, pocRuleMode).label !== "未见 PoC 线索").length;
        const criticalCount = filteredItems.filter((x) => riskTone(x.severity) === "critical").length;
        const highCount = filteredItems.filter((x) => riskTone(x.severity) === "high").length;
        const referenceCount = filteredItems.filter((x) => (x.references || []).length > 0).length;
        const detailLinks = filteredItems.filter((x) => x.detail_url).length;
        return {
            patchCount,
            pocCount,
            criticalCount,
            highCount,
            referenceCount,
            detailLinks,
        };
    }, [filteredItems, pocRuleMode]);

    async function runQuery(targetPage = page, targetPageSize = pageSize) {
        setLoading(true);
        setError("");
        try {
            const params = new URLSearchParams({
                page: String(targetPage),
                page_size: String(targetPageSize),
            });
            if (showAdvanced && from) params.set("modified_from", from);
            if (showAdvanced && to) params.set("modified_to", to);
            const data = await apiGet<QueryResp>(`/raw?${params.toString()}`);
            setQuery(data);
            setPage(data.page);
            setPageSize(data.page_size);
            if (!selected && data.items.length > 0) {
                await openDetail(data.items[0]);
            }
        } catch (e) {
            setError(String(e));
        } finally {
            setLoading(false);
        }
    }

    async function openDetail(item: RawItem) {
        setSelected(item);
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(item.cve_id)}`);
            setDetailJson(JSON.stringify(data, null, 2));
        } catch (e) {
            setDetailJson(JSON.stringify(item, null, 2));
            setRetryResult(String(e));
        }
    }

    async function loadByCve() {
        if (!cveId.trim()) return;
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(cveId.trim())}`);
            await openDetail(data);
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    async function loadGaps() {
        try {
            const data = await apiGet<GapsResp>(`/pages/gaps?max_page=${maxPage}&include_failed=true`);
            setGaps(data);
        } catch (e) {
            setGaps(null);
            setRetryResult(String(e));
        }
    }

    async function loadCheckpoints() {
        try {
            const data = await apiGet<CheckpointsResp>(`/pages/checkpoints`);
            setCheckpoints(data);
        } catch (e) {
            setCheckpoints(null);
            setRetryResult(String(e));
        }
    }

    async function runRetry() {
        const parsed = retryPages
            .split(/[\s,]+/)
            .map((x) => Number(x))
            .filter((x) => Number.isInteger(x) && x > 0);
        if (!parsed.length) {
            setRetryResult("Please enter page numbers, e.g. 50 51 52");
            return;
        }
        try {
            const data = await apiPost(`/pages/retry`, { pages: parsed });
            setRetryResult(JSON.stringify(data, null, 2));
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    const rows = filteredItems;

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.18),_transparent_30%),linear-gradient(180deg,#f8fbff_0%,#eef2ff_100%)] text-slate-900">
            <main className="mx-auto max-w-[1700px] px-4 py-5 lg:px-6">
                <section className="relative overflow-hidden rounded-[28px] border border-white/70 bg-slate-950 px-6 py-6 text-white shadow-[0_24px_80px_rgba(15,23,42,0.22)]">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.35),transparent_30%),radial-gradient(circle_at_bottom_left,rgba(59,130,246,0.28),transparent_25%)]" />
                    <div className="relative flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                        <div>
                            <p className="text-xs uppercase tracking-[0.35em] text-sky-200/70">Aliyun Vulnerability Browser</p>
                            <h1 className="mt-3 text-4xl font-semibold tracking-tight md:text-6xl">漏洞列表、详情、PoC、链接，一屏看完。</h1>
                            <p className="mt-4 max-w-4xl text-sm leading-7 text-slate-200/80 md:text-base">
                                左边是固定筛选和统计，中间是漏洞卡片流，右边是抽屉详情。日期筛选收进高级区，不抢视觉焦点。
                            </p>
                        </div>
                        <div className="grid min-w-[320px] gap-3 rounded-[24px] border border-white/10 bg-white/8 p-4 backdrop-blur">
                            <div className="text-xs text-slate-300">API Base</div>
                            <div className="break-all text-lg font-medium">{API_BASE}</div>
                            <div className="grid grid-cols-2 gap-3 text-sm text-slate-200">
                                <div className="rounded-2xl bg-white/8 p-3">
                                    <div className="text-slate-400">Server Total</div>
                                    <div className="mt-1 text-2xl font-semibold">{query?.total ?? 0}</div>
                                </div>
                                <div className="rounded-2xl bg-white/8 p-3">
                                    <div className="text-slate-400">Visible</div>
                                    <div className="mt-1 text-2xl font-semibold">{rows.length}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <div className="mt-5 grid gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
                    <aside className="sticky top-4 self-start rounded-[28px] border border-slate-200 bg-white/90 p-4 shadow-[0_18px_55px_rgba(15,23,42,0.08)] backdrop-blur">
                        <div className="flex items-center justify-between gap-2">
                            <div>
                                <h2 className="text-lg font-semibold">筛选</h2>
                                <p className="text-sm text-slate-500">把时间放到后面，先抓漏洞。</p>
                            </div>
                            <button
                                className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700"
                                onClick={() => setShowAdvanced((v) => !v)}
                            >
                                {showAdvanced ? "收起" : "高级"}
                            </button>
                        </div>

                        <div className="mt-4 space-y-3">
                            <input className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 outline-none focus:border-blue-400 focus:bg-white" placeholder="关键词 / CVE / 链接" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
                            <input className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 outline-none focus:border-blue-400 focus:bg-white" placeholder="CWE-79" value={cwe} onChange={(e) => setCwe(e.target.value)} />
                            <input className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 outline-none focus:border-blue-400 focus:bg-white" placeholder="high / medium / 高危" value={severity} onChange={(e) => setSeverity(e.target.value)} />

                            <div className="grid grid-cols-2 gap-3">
                                <select className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 outline-none focus:border-blue-400 focus:bg-white" value={patchOnly} onChange={(e) => setPatchOnly(e.target.value as PocMode)}>
                                    <option value="all">Patch: all</option>
                                    <option value="yes">Patch: yes</option>
                                    <option value="no">Patch: no</option>
                                </select>
                                <select className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 outline-none focus:border-blue-400 focus:bg-white" value={pocOnly} onChange={(e) => setPocOnly(e.target.value as PocMode)}>
                                    <option value="all">PoC: all</option>
                                    <option value="yes">PoC: yes</option>
                                    <option value="no">PoC: no</option>
                                </select>
                            </div>

                            <select className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 outline-none focus:border-blue-400 focus:bg-white" value={pocRuleMode} onChange={(e) => setPocRuleMode(e.target.value as PoCRuleMode)}>
                                <option value="balanced">PoC rule: balanced</option>
                                <option value="strict">PoC rule: strict</option>
                                <option value="loose">PoC rule: loose</option>
                            </select>

                            {showAdvanced ? (
                                <div className="grid gap-3 rounded-3xl bg-slate-50 p-3">
                                    <input className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 outline-none focus:border-blue-400" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
                                    <input className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 outline-none focus:border-blue-400" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
                                    <div className="grid grid-cols-2 gap-3">
                                        <input className="rounded-2xl border border-slate-200 bg-white px-4 py-3 outline-none focus:border-blue-400" type="number" min={1} value={page} onChange={(e) => setPage(Number(e.target.value || 1))} placeholder="page" />
                                        <select className="rounded-2xl border border-slate-200 bg-white px-4 py-3 outline-none focus:border-blue-400" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}>
                                            <option value={10}>10</option>
                                            <option value={20}>20</option>
                                            <option value={50}>50</option>
                                            <option value={100}>100</option>
                                        </select>
                                    </div>
                                </div>
                            ) : null}
                        </div>

                        <div className="mt-4 flex gap-2">
                            <button className="flex-1 rounded-2xl bg-blue-600 px-4 py-3 text-sm font-medium text-white transition hover:bg-blue-500" onClick={() => runQuery()}>
                                {loading ? "Loading..." : "刷新"}
                            </button>
                            <button className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700" onClick={() => setPage((p) => Math.max(1, p - 1))}>
                                上
                            </button>
                            <button className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700" onClick={() => setPage((p) => p + 1)}>
                                下
                            </button>
                        </div>
                        <div className="mt-2 text-xs text-slate-500">page {query?.page ?? page} / total {query?.total ?? 0}</div>
                        {error ? <p className="mt-2 text-sm text-rose-600">{error}</p> : null}

                        <div className="mt-4 grid grid-cols-2 gap-3">
                            <Stat label="高危" value={stats.highCount} tone="high" />
                            <Stat label="严重" value={stats.criticalCount} tone="critical" />
                            <Stat label="PoC" value={stats.pocCount} tone="warning" />
                            <Stat label="补丁" value={stats.patchCount} tone="info" />
                            <Stat label="引用" value={stats.referenceCount} tone="low" />
                            <Stat label="详情链接" value={stats.detailLinks} tone="muted" />
                        </div>

                        <div className="mt-4 rounded-3xl bg-slate-950 p-4 text-white">
                            <h3 className="text-sm font-semibold text-slate-200">辅助操作</h3>
                            <div className="mt-3 space-y-3">
                                <div>
                                    <label className="text-xs uppercase tracking-widest text-slate-400">CVE 详情</label>
                                    <div className="mt-2 flex gap-2">
                                        <input className="min-w-0 flex-1 rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-blue-400" value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2026-xxxx" />
                                        <button className="rounded-2xl bg-white px-4 py-2 text-sm font-medium text-slate-900" onClick={loadByCve}>查</button>
                                    </div>
                                </div>
                                <div>
                                    <label className="text-xs uppercase tracking-widest text-slate-400">页段上限</label>
                                    <div className="mt-2 flex gap-2">
                                        <input className="min-w-0 flex-1 rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-blue-400" type="number" min={1} value={maxPage} onChange={(e) => setMaxPage(Number(e.target.value || 1))} />
                                        <button className="rounded-2xl bg-emerald-600 px-4 py-2 text-sm font-medium text-white" onClick={loadGaps}>gaps</button>
                                    </div>
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <button className="rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-white" onClick={loadCheckpoints}>checkpoints</button>
                                    <button className="rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-white" onClick={runRetry}>retry</button>
                                </div>
                                <input className="w-full rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-blue-400" value={retryPages} onChange={(e) => setRetryPages(e.target.value)} placeholder="50 51 52" />
                            </div>
                        </div>
                    </aside>

                    <section className="space-y-4">
                        <div className="rounded-[28px] border border-slate-200 bg-white/90 p-4 shadow-[0_18px_55px_rgba(15,23,42,0.08)] backdrop-blur">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                                <div>
                                    <h2 className="text-lg font-semibold">列表</h2>
                                    <p className="text-sm text-slate-500">卡片内直接展示摘要、详情、链接和 PoC 线索。</p>
                                </div>
                                <div className="rounded-full bg-slate-100 px-4 py-2 text-sm text-slate-600">
                                    {rows.length} / {query?.total ?? 0}
                                </div>
                            </div>
                        </div>

                        <div className="space-y-4">
                            {rows.map((item) => {
                                const poc = summarizePoc(item, pocRuleMode);
                                const sevTone = riskTone(item.severity);
                                const refs = unique((item.references || []).filter(Boolean)).slice(0, 8);
                                const patches = unique((item.patch_urls || []).filter(Boolean));
                                const affected = item.affected_software || [];

                                return (
                                    <article key={item.cve_id} className="overflow-hidden rounded-[30px] border border-slate-200 bg-white shadow-[0_18px_55px_rgba(15,23,42,0.08)]">
                                        <div className="grid gap-0 xl:grid-cols-[1.2fr_0.8fr]">
                                            <div className="p-5 md:p-6">
                                                <div className="flex flex-wrap items-start gap-3">
                                                    <div>
                                                        <div className="flex flex-wrap items-center gap-2">
                                                            <h3 className="text-xl font-semibold text-slate-950 md:text-2xl">{item.cve_id}</h3>
                                                            <span className={`rounded-full px-3 py-1 text-xs ring-1 ${toneClass(sevTone)}`}>{item.severity || "unknown"}</span>
                                                            <span className={`rounded-full px-3 py-1 text-xs ring-1 ${toneClass(poc.tone)}`}>{poc.label}</span>
                                                            {patches.length ? <span className="rounded-full bg-slate-900 px-3 py-1 text-xs text-white">patch {patches.length}</span> : null}
                                                        </div>
                                                        <p className="mt-2 max-w-4xl text-sm leading-7 text-slate-600">{item.title || "无标题"}</p>
                                                    </div>
                                                    <div className="ml-auto flex flex-wrap gap-2">
                                                        <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-700 transition hover:border-blue-300 hover:bg-blue-50" onClick={() => openDetail(item)}>打开抽屉</button>
                                                        {item.detail_url ? (
                                                            <a className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-700 transition hover:border-blue-300 hover:bg-blue-50" href={item.detail_url} target="_blank" rel="noreferrer">原始详情</a>
                                                        ) : null}
                                                    </div>
                                                </div>

                                                <p className="mt-4 whitespace-pre-wrap text-sm leading-7 text-slate-700">{item.description || "暂无描述"}</p>

                                                <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                                                    <SmallCard title="CWE" value={item.cwe_id || "-"} desc={item.cwe_description || "-"} />
                                                    <SmallCard title="CVSS" value={scoreText(item.cvss_score)} desc={item.cvss_vector || "-"} />
                                                    <SmallCard title="发布 / 更新" value={textOrDash(item.published_date)} desc={textOrDash(item.modified_date)} />
                                                    <SmallCard title="引用 / 补丁" value={`${refs.length} / ${patches.length}`} desc={item.detail_url ? "有详情链接" : "无详情链接"} />
                                                </div>

                                                <div className="mt-4 grid gap-3 lg:grid-cols-2">
                                                    <div className="rounded-2xl border border-slate-200 p-4">
                                                        <div className="text-xs uppercase tracking-widest text-slate-500">详情摘要</div>
                                                        <div className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-sm leading-7 text-slate-700">
                                                            {item.description || "暂无描述"}
                                                        </div>
                                                    </div>
                                                    <div className="rounded-2xl border border-slate-200 p-4">
                                                        <div className="text-xs uppercase tracking-widest text-slate-500">Affected Software</div>
                                                        <div className="mt-3 flex flex-wrap gap-2">
                                                            {affected.length ? (
                                                                affected.map((x) => (
                                                                    <span key={x} className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-700">
                                                                        {x}
                                                                    </span>
                                                                ))
                                                            ) : (
                                                                <span className="text-sm text-slate-500">-</span>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="border-t border-slate-200 bg-gradient-to-b from-slate-50 to-white p-5 md:p-6 xl:border-l xl:border-t-0">
                                                <div className="space-y-4">
                                                    <div>
                                                        <div className="text-xs uppercase tracking-widest text-slate-500">PoC 状态</div>
                                                        <div className={`mt-2 inline-flex rounded-full px-3 py-1 text-sm ring-1 ${toneClass(poc.tone)}`}>{poc.label}</div>
                                                        <p className="mt-2 text-sm leading-7 text-slate-600">PoC 依据标题、描述、引用和补丁链接做启发式判断。右上角规则可切 strict / balanced / loose。</p>
                                                    </div>

                                                    <div>
                                                        <div className="text-xs uppercase tracking-widest text-slate-500">Patch Links</div>
                                                        <div className="mt-3 space-y-2">
                                                            {patches.length ? patches.map((url) => (
                                                                <a key={url} href={url} target="_blank" rel="noreferrer" className="block rounded-2xl border border-blue-200 bg-blue-50 px-3 py-2 text-xs leading-5 text-blue-800 transition hover:border-blue-300 hover:bg-blue-100">
                                                                    {linkHost(url)}
                                                                    <span className="mt-1 block break-all text-[11px] text-blue-700/80">{url}</span>
                                                                </a>
                                                            )) : <div className="text-sm text-slate-500">无补丁链接</div>}
                                                        </div>
                                                    </div>

                                                    <div>
                                                        <div className="text-xs uppercase tracking-widest text-slate-500">References</div>
                                                        <div className="mt-3 flex flex-wrap gap-2">
                                                            {refs.length ? refs.map((url) => (
                                                                <a key={url} href={url} target="_blank" rel="noreferrer" className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-slate-700 transition hover:border-slate-400 hover:bg-slate-50">
                                                                    {linkHost(url)}
                                                                </a>
                                                            )) : <span className="text-sm text-slate-500">-</span>}
                                                        </div>
                                                    </div>

                                                    <div className="grid grid-cols-2 gap-2">
                                                        <button className="rounded-2xl bg-slate-900 px-4 py-3 text-sm font-medium text-white" onClick={() => openDetail(item)}>
                                                            抽屉详情
                                                        </button>
                                                        {item.detail_url ? (
                                                            <a className="rounded-2xl border border-slate-300 bg-white px-4 py-3 text-center text-sm font-medium text-slate-700" href={item.detail_url} target="_blank" rel="noreferrer">
                                                                外部打开
                                                            </a>
                                                        ) : (
                                                            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-center text-sm text-slate-400">
                                                                无外链
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </article>
                                );
                            })}

                            {rows.length === 0 ? (
                                <div className="rounded-[28px] border border-dashed border-slate-300 bg-white p-10 text-center text-slate-500">
                                    没有匹配结果，换个关键词或放宽过滤条件。
                                </div>
                            ) : null}
                        </div>
                    </section>
                </div>

                <div className="mt-6 grid gap-4 xl:grid-cols-2">
                    <div className="rounded-[28px] border border-slate-200 bg-white p-4 shadow-[0_18px_55px_rgba(15,23,42,0.08)]">
                        <h2 className="text-lg font-semibold">Gaps / Checkpoints</h2>
                        <div className="mt-3 grid gap-2 md:grid-cols-2">
                            <button className="rounded-2xl bg-emerald-600 px-3 py-2 text-sm font-medium text-white" onClick={loadGaps}>重新拉取 gaps</button>
                            <button className="rounded-2xl bg-teal-700 px-3 py-2 text-sm font-medium text-white" onClick={loadCheckpoints}>重新拉取 checkpoints</button>
                        </div>
                        <pre className="mt-3 max-h-64 overflow-auto rounded-2xl bg-slate-50 p-3 text-xs text-slate-700">{gaps ? JSON.stringify(gaps, null, 2) : "暂无 gaps 数据"}</pre>
                        <pre className="mt-3 max-h-64 overflow-auto rounded-2xl bg-slate-50 p-3 text-xs text-slate-700">{checkpoints ? JSON.stringify(checkpoints, null, 2) : "暂无 checkpoints 数据"}</pre>
                    </div>

                    <div className="rounded-[28px] border border-slate-200 bg-white p-4 shadow-[0_18px_55px_rgba(15,23,42,0.08)]">
                        <h2 className="text-lg font-semibold">Retry Pages</h2>
                        <p className="mt-1 text-sm text-slate-500">输入页号重试，适合补漏页。</p>
                        <input className="mt-3 w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 outline-none focus:border-blue-400" value={retryPages} onChange={(e) => setRetryPages(e.target.value)} placeholder="50 51 52" />
                        <button className="mt-3 w-full rounded-2xl bg-amber-600 px-4 py-3 text-sm font-medium text-white" onClick={runRetry}>执行 retry</button>
                        <pre className="mt-3 max-h-56 overflow-auto rounded-2xl bg-slate-50 p-3 text-xs text-slate-700">{retryResult}</pre>
                    </div>
                </div>
            </main>

            {selected ? (
                <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/50 backdrop-blur-sm" onClick={() => setSelected(null)}>
                    <aside className="h-full w-full max-w-[680px] overflow-auto border-l border-slate-200 bg-white shadow-2xl" onClick={(e) => e.stopPropagation()}>
                        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-200 bg-white/95 px-5 py-4 backdrop-blur">
                            <div>
                                <div className="text-xs uppercase tracking-widest text-slate-400">Detail Drawer</div>
                                <h3 className="text-xl font-semibold text-slate-950">{selected.cve_id}</h3>
                            </div>
                            <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm" onClick={() => setSelected(null)}>关闭</button>
                        </div>

                        <div className="space-y-4 p-5">
                            <div className="grid gap-3 md:grid-cols-2">
                                <SmallCard title="标题" value={selected.title || "-"} desc={selected.severity || "-"} />
                                <SmallCard title="CWE" value={selected.cwe_id || "-"} desc={selected.cwe_description || "-"} />
                                <SmallCard title="CVSS" value={scoreText(selected.cvss_score)} desc={selected.cvss_vector || "-"} />
                                <SmallCard title="更新" value={textOrDash(selected.modified_date)} desc={textOrDash(selected.published_date)} />
                            </div>

                            <div className="rounded-3xl bg-slate-950 p-4 text-white">
                                <div className="text-xs uppercase tracking-widest text-slate-400">JSON</div>
                                <pre className="mt-3 max-h-[560px] overflow-auto whitespace-pre-wrap break-words text-xs text-slate-100">{detailJson}</pre>
                            </div>

                            <div className="grid gap-4 md:grid-cols-2">
                                <div className="rounded-3xl border border-slate-200 p-4">
                                    <div className="text-xs uppercase tracking-widest text-slate-500">Reference Links</div>
                                    <div className="mt-3 flex flex-wrap gap-2">
                                        {(selected.references || []).length ? (selected.references || []).map((url) => (
                                            <a key={url} href={url} target="_blank" rel="noreferrer" className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-slate-700 hover:border-slate-400">
                                                {linkHost(url)}
                                            </a>
                                        )) : <span className="text-sm text-slate-500">-</span>}
                                    </div>
                                </div>
                                <div className="rounded-3xl border border-slate-200 p-4">
                                    <div className="text-xs uppercase tracking-widest text-slate-500">Patch Links</div>
                                    <div className="mt-3 space-y-2">
                                        {(selected.patch_urls || []).length ? (selected.patch_urls || []).map((url) => (
                                            <a key={url} href={url} target="_blank" rel="noreferrer" className="block rounded-2xl border border-blue-200 bg-blue-50 px-3 py-2 text-xs text-blue-800">
                                                {url}
                                            </a>
                                        )) : <span className="text-sm text-slate-500">-</span>}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </aside>
                </div>
            ) : null}
        </div>
    );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted" }) {
    return (
        <div className={`rounded-2xl p-3 ring-1 ${toneClass(tone)}`}>
            <div className="text-[11px] uppercase tracking-widest opacity-70">{label}</div>
            <div className="mt-1 text-2xl font-semibold">{value}</div>
        </div>
    );
}

function SmallCard({ title, value, desc }: { title: string; value: string; desc: string }) {
    return (
        <div className="rounded-2xl bg-slate-50 p-4">
            <div className="text-xs uppercase tracking-widest text-slate-500">{title}</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">{value}</div>
            <div className="mt-2 max-h-24 overflow-auto text-xs leading-5 text-slate-500">{desc}</div>
        </div>
    );
}
