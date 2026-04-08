"use client";

import { useEffect, useMemo, useState } from "react";

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

    const totalPages = Math.max(1, Math.ceil((query?.total ?? 0) / pageSize));

    const severityBreakdown = useMemo(() => {
        const counts = {
            critical: filteredItems.filter((x) => riskTone(x.severity) === "critical").length,
            high: filteredItems.filter((x) => riskTone(x.severity) === "high").length,
            medium: filteredItems.filter((x) => riskTone(x.severity) === "medium").length,
            low: filteredItems.filter((x) => riskTone(x.severity) === "low").length,
        };
        const total = Math.max(1, counts.critical + counts.high + counts.medium + counts.low);
        return [
            { key: "critical", label: "严重", count: counts.critical, tone: "critical" as const, pct: (counts.critical / total) * 100 },
            { key: "high", label: "高危", count: counts.high, tone: "high" as const, pct: (counts.high / total) * 100 },
            { key: "medium", label: "中危", count: counts.medium, tone: "medium" as const, pct: (counts.medium / total) * 100 },
            { key: "low", label: "低危", count: counts.low, tone: "low" as const, pct: (counts.low / total) * 100 },
        ];
    }, [filteredItems]);

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
        } catch (e) {
            setError(String(e));
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        let mounted = true;
        async function initQuery() {
            setLoading(true);
            setError("");
            try {
                const data = await apiGet<QueryResp>("/raw?page=1&page_size=20");
                if (!mounted) return;
                setQuery(data);
                setPage(data.page);
                setPageSize(data.page_size);
            } catch (e) {
                if (!mounted) return;
                setError(String(e));
            } finally {
                if (mounted) setLoading(false);
            }
        }
        void initQuery();
        return () => {
            mounted = false;
        };
    }, []);

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
                <section className="relative overflow-hidden rounded-[28px] border border-white/70 bg-slate-950 px-6 py-5 text-white shadow-[0_24px_80px_rgba(15,23,42,0.22)]">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.35),transparent_30%),radial-gradient(circle_at_bottom_left,rgba(59,130,246,0.28),transparent_25%)]" />
                    <div className="relative flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                        <div className="max-w-4xl">
                            <p className="text-xs uppercase tracking-[0.35em] text-sky-200/70">Aliyun CVE Browser</p>
                            <h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-5xl">CVE 浏览、筛选、补漏，一页完成。</h1>
                            <p className="mt-3 text-sm leading-6 text-slate-200/80 md:text-base">
                                先看统计，再缩范围，最后进入详情。右侧保留服务器状态和危险分布，主区域只保留核心结果。
                            </p>
                            <div className="mt-4 flex flex-wrap gap-2">
                                <StatPill label="总数" value={query?.total ?? 0} />
                                <StatPill label="可见" value={rows.length} />
                                <StatPill label="高危" value={stats.highCount} tone="high" />
                                <StatPill label="严重" value={stats.criticalCount} tone="critical" />
                                <StatPill label="PoC" value={stats.pocCount} tone="warning" />
                            </div>
                        </div>
                        <div className="grid min-w-[280px] gap-3 rounded-[22px] border border-white/10 bg-white/8 p-4 backdrop-blur">
                            <div className="flex items-center justify-between gap-3 text-xs uppercase tracking-[0.2em] text-slate-300">
                                <span>Server</span>
                                <span className={`rounded-full px-2 py-1 ${loading ? "bg-amber-500/20 text-amber-200" : "bg-emerald-500/20 text-emerald-200"}`}>
                                    {loading ? "同步中" : "在线"}
                                </span>
                            </div>
                            <div className="space-y-1 text-sm text-slate-200">
                                <div className="truncate text-slate-300">{API_BASE}</div>
                                <div className="flex items-center justify-between text-slate-300">
                                    <span>Page</span>
                                    <span>{query?.page ?? page}/{totalPages}</span>
                                </div>
                                <div className="flex items-center justify-between text-slate-300">
                                    <span>Page Size</span>
                                    <span>{query?.page_size ?? pageSize}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <div className="mt-5 grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
                    <aside className="sticky top-4 self-start rounded-[28px] border border-slate-200 bg-white/90 p-4 shadow-[0_18px_55px_rgba(15,23,42,0.08)] backdrop-blur">
                        <div className="flex items-center justify-between gap-2">
                            <div>
                                <h2 className="text-lg font-semibold">筛选</h2>
                                <p className="text-sm text-slate-500">先缩范围，再看详情。</p>
                            </div>
                            <button
                                className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700"
                                onClick={() => setShowAdvanced((v) => !v)}
                            >
                                {showAdvanced ? "收起" : "高级"}
                            </button>
                        </div>

                        <div className="mt-4 rounded-3xl bg-slate-950 p-4 text-white">
                            <div className="flex items-center justify-between text-xs uppercase tracking-widest text-slate-400">
                                <span>Server</span>
                                <span>{loading ? "busy" : "ready"}</span>
                            </div>
                            <div className="mt-2 space-y-2 text-sm text-slate-200">
                                <div className="truncate text-slate-300">{API_BASE}</div>
                                <div className="flex items-center justify-between">
                                    <span>total</span>
                                    <span>{query?.total ?? 0}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span>page</span>
                                    <span>{query?.page ?? page}/{totalPages}</span>
                                </div>
                            </div>
                        </div>

                        <div className="mt-4 rounded-3xl border border-slate-200 bg-slate-50 p-4">
                            <div className="flex items-center justify-between gap-2">
                                <div>
                                    <div className="text-xs uppercase tracking-widest text-slate-500">Severity</div>
                                    <div className="text-sm font-medium text-slate-800">分布饼图</div>
                                </div>
                                <div className="text-xs text-slate-500">{filteredItems.length} 条</div>
                            </div>
                            <SeverityPie segments={severityBreakdown} />
                            <div className="mt-3 space-y-2">
                                {severityBreakdown.map((item) => (
                                    <div key={item.key} className="flex items-center justify-between text-sm text-slate-700">
                                        <span className="flex items-center gap-2">
                                            <span className={`h-2.5 w-2.5 rounded-full ${toneDotClass(item.tone)}`} />
                                            {item.label}
                                        </span>
                                        <span>{item.count}</span>
                                    </div>
                                ))}
                            </div>
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
                                </div>
                            ) : null}
                        </div>

                        <div className="mt-4 grid grid-cols-2 gap-2">
                            <button className="rounded-2xl bg-blue-600 px-4 py-3 text-sm font-medium text-white transition hover:bg-blue-500" onClick={() => runQuery(1, pageSize)}>
                                {loading ? "Loading..." : "刷新"}
                            </button>
                            <button className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700" onClick={() => void runQuery(Math.max(1, page - 1), pageSize)}>
                                上一页
                            </button>
                            <button className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700" onClick={() => void runQuery(Math.min(totalPages, page + 1), pageSize)}>
                                下一页
                            </button>
                            <select
                                className="rounded-2xl border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-blue-400"
                                value={page}
                                onChange={(e) => void runQuery(Number(e.target.value), pageSize)}
                            >
                                {Array.from({ length: totalPages }, (_, index) => index + 1).map((value) => (
                                    <option key={value} value={value}>
                                        第 {value} 页
                                    </option>
                                ))}
                            </select>
                            <select
                                className="col-span-2 rounded-2xl border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-blue-400"
                                value={pageSize}
                                onChange={(e) => void runQuery(1, Number(e.target.value))}
                            >
                                <option value={10}>每页 10 条</option>
                                <option value={20}>每页 20 条</option>
                                <option value={50}>每页 50 条</option>
                                <option value={100}>每页 100 条</option>
                            </select>
                        </div>
                        <div className="mt-2 text-xs text-slate-500">page {query?.page ?? page} / total {query?.total ?? 0}</div>
                        {error ? <p className="mt-2 text-sm text-rose-600">{error}</p> : null}

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
                        <div className="flex flex-wrap items-center justify-between gap-3 rounded-[28px] border border-slate-200 bg-white/90 px-4 py-3 shadow-[0_18px_55px_rgba(15,23,42,0.08)] backdrop-blur">
                            <div>
                                <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-500">Results</h2>
                                <p className="text-sm text-slate-500">按行展示核心信息，减少无效占位。</p>
                            </div>
                            <div className="flex flex-wrap items-center gap-2 text-sm text-slate-600">
                                <span className="rounded-full bg-slate-100 px-3 py-1">{rows.length} visible</span>
                                <span className="rounded-full bg-slate-100 px-3 py-1">page {query?.page ?? page}/{totalPages}</span>
                            </div>
                        </div>

                        <div className="divide-y divide-slate-200 overflow-hidden rounded-[22px] border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.08)]">
                            {rows.map((item) => {
                                const poc = summarizePoc(item, pocRuleMode);
                                const sevTone = riskTone(item.severity);
                                const refs = unique((item.references || []).filter(Boolean)).slice(0, 8);
                                const patches = unique((item.patch_urls || []).filter(Boolean));
                                const affected = item.affected_software || [];
                                const cweText = [item.cwe_id || "-", item.cwe_description || "-"]
                                    .filter(Boolean)
                                    .join(" | ");
                                const cvssText = `score=${scoreText(item.cvss_score)} | vector=${item.cvss_vector || "-"}`;

                                return (
                                    <article key={item.cve_id} className="px-4 py-4 md:px-5 md:py-4">
                                        <div className="flex flex-wrap items-start gap-2">
                                            <h3 className="text-lg font-semibold text-slate-950">{item.cve_id}</h3>
                                            <span className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${toneClass(sevTone)}`}>{item.severity || "unknown"}</span>
                                            <span className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${toneClass(poc.tone)}`}>{poc.label}</span>
                                            {patches.length ? <span className="rounded-full bg-slate-900 px-2.5 py-0.5 text-xs text-white">patch {patches.length}</span> : null}
                                            <div className="ml-auto flex flex-wrap gap-2">
                                                <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700" onClick={() => openDetail(item)}>查看详情</button>
                                                {item.detail_url ? (
                                                    <a className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700" href={item.detail_url} target="_blank" rel="noreferrer">原始详情</a>
                                                ) : null}
                                            </div>
                                        </div>

                                        <p className="mt-1 text-sm text-slate-600">{item.title || "无标题"}</p>

                                        <div className="mt-3 space-y-2 text-sm leading-6 text-slate-700">
                                            <CollapsibleText label="简介" text={item.description || "暂无描述"} lines={2} />
                                            <div className="grid gap-2 md:grid-cols-2">
                                                <LabeledLine label="CWE" text={cweText} />
                                                <LabeledLine label="CVSS" text={cvssText} mono />
                                            </div>
                                            <LabeledLine label="Affected Software" text={affected.length ? affected.join(" | ") : "-"} />
                                            <div className="grid gap-3 md:grid-cols-2">
                                                <UrlList title="引用链接（原始）" urls={refs} />
                                                <UrlList title="补丁链接（提取）" urls={patches} />
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
                                <div className="text-xs uppercase tracking-widest text-slate-400">Vulnerability Detail</div>
                                <h3 className="text-xl font-semibold text-slate-950">{selected.cve_id}</h3>
                            </div>
                            <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm" onClick={() => setSelected(null)}>关闭</button>
                        </div>

                        <div className="space-y-4 p-5">
                            <div className="rounded-3xl border border-slate-200 bg-slate-50/70 p-4 space-y-2">
                                <LabeledLine label="标题" text={selected.title || "-"} />
                                <LabeledLine label="严重等级" text={selected.severity || "-"} />
                                <CollapsibleText label="简介" text={selected.description || "暂无描述"} lines={3} />
                                <div className="grid gap-2 md:grid-cols-2">
                                    <LabeledLine
                                        label="CWE"
                                        text={`${selected.cwe_id || "-"}${selected.cwe_description ? ` - ${selected.cwe_description}` : ""}`}
                                    />
                                    <LabeledLine
                                        label="CVSS"
                                        text={`${scoreText(selected.cvss_score)}${selected.cvss_vector ? ` | ${selected.cvss_vector}` : ""}`}
                                        mono
                                    />
                                </div>
                                <LabeledLine label="时间" text={`更新 ${textOrDash(selected.modified_date)} / 发布 ${textOrDash(selected.published_date)}`} />
                            </div>

                            <div className="rounded-3xl bg-slate-950 p-4 text-white">
                                <div className="text-xs uppercase tracking-widest text-slate-400">JSON</div>
                                <pre className="mt-3 max-h-[560px] overflow-auto whitespace-pre-wrap break-words text-xs text-slate-100">{detailJson}</pre>
                            </div>

                            <div className="grid gap-4 md:grid-cols-2">
                                <div className="rounded-3xl border border-slate-200 p-4">
                                    <UrlList title="引用链接（原始）" urls={unique((selected.references || []).filter(Boolean))} limit={12} />
                                </div>
                                <div className="rounded-3xl border border-slate-200 p-4">
                                    <UrlList title="补丁链接（提取）" urls={unique((selected.patch_urls || []).filter(Boolean))} limit={12} />
                                </div>
                            </div>
                        </div>
                    </aside>
                </div>
            ) : null}
        </div>
    );
}

function StatPill({ label, value, tone = "muted" }: { label: string; value: number; tone?: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted" }) {
    return (
        <div className={`rounded-full px-3 py-2 text-sm ring-1 ${toneClass(tone)}`}>
            <span className="text-[11px] uppercase tracking-widest opacity-70">{label}</span>
            <span className="ml-2 text-base font-semibold">{value}</span>
        </div>
    );
}

function toneDotClass(kind: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted") {
    switch (kind) {
        case "critical":
            return "bg-rose-500";
        case "high":
            return "bg-amber-500";
        case "medium":
            return "bg-sky-500";
        case "low":
            return "bg-emerald-500";
        default:
            return "bg-slate-400";
    }
}

function SeverityPie({ segments }: { segments: Array<{ key: string; label: string; count: number; tone: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted"; pct: number }> }) {
    const colors = ["#f43f5e", "#f59e0b", "#0ea5e9", "#10b981"];
    const gradientStops: string[] = [];
    let accumulated = 0;
    segments.forEach((segment, index) => {
        const start = accumulated;
        accumulated += segment.pct;
        gradientStops.push(`${colors[index]} ${start}% ${accumulated}%`);
    });
    return (
        <div className="mt-3 grid place-items-center">
            <div className="relative h-40 w-40 rounded-full" style={{ background: `conic-gradient(${gradientStops.join(", ")})` }}>
                <div className="absolute inset-7 rounded-full bg-slate-50" />
                <div className="absolute inset-0 grid place-items-center text-center">
                    <div>
                        <div className="text-2xl font-semibold text-slate-900">{segments.reduce((sum, item) => sum + item.count, 0)}</div>
                        <div className="text-xs uppercase tracking-widest text-slate-500">items</div>
                    </div>
                </div>
            </div>
        </div>
    );
}

function CollapsibleText({ label, text, lines = 2, mono = false }: { label: string; text: string; lines?: number; mono?: boolean }) {
    const [expanded, setExpanded] = useState(false);
    const clampClass = lines === 1 ? "line-clamp-1" : lines === 2 ? "line-clamp-2" : "line-clamp-3";
    const canExpand = (text || "").length > (lines === 1 ? 80 : lines === 2 ? 140 : 220);

    return (
        <div className="text-sm leading-6 text-slate-700">
            <p className="text-sm leading-6 text-slate-700">
                <strong className="font-semibold text-slate-900">{label}: </strong>
                <span className={`${mono ? "font-mono text-[13px]" : ""} ${expanded ? "" : clampClass}`}>
                    {text || "-"}
                </span>
                {canExpand ? (
                    <button
                        type="button"
                        className="ml-2 text-xs font-medium text-blue-600 hover:text-blue-500"
                        onClick={() => setExpanded((v) => !v)}
                    >
                        {expanded ? "收起" : "展开"}
                    </button>
                ) : null}
            </p>
        </div>
    );
}

function LabeledLine({ label, text, mono = false }: { label: string; text: string; mono?: boolean }) {
    return (
        <p className="text-sm leading-6 text-slate-700">
            <strong className="font-semibold text-slate-900">{label}: </strong>
            <span className={mono ? "font-mono text-[13px]" : ""}>{text || "-"}</span>
        </p>
    );
}

function trimUrl(url: string, keep = 52) {
    try {
        const u = new URL(url);
        const full = `${u.hostname}${u.pathname}${u.search}`;
        if (full.length <= keep) return full;
        return `${full.slice(0, keep)}...`;
    } catch {
        if (url.length <= keep) return url;
        return `${url.slice(0, keep)}...`;
    }
}

function UrlList({ title, urls, limit = 4 }: { title: string; urls: string[]; limit?: number }) {
    const [expanded, setExpanded] = useState(false);
    const show = expanded ? urls : urls.slice(0, limit);
    return (
        <div>
            <div className="text-xs uppercase tracking-widest text-slate-500">{title}</div>
            {show.length ? (
                <div className={`mt-2 text-xs leading-5 text-slate-700 ${expanded ? "" : "line-clamp-2"}`}>
                    {show.map((url, index) => (
                        <span key={url}>
                            <a
                                href={url}
                                target="_blank"
                                rel="noreferrer"
                                className="underline decoration-slate-300 underline-offset-2 hover:text-blue-700"
                                title={url}
                            >
                                {trimUrl(url)}
                            </a>
                            {index < show.length - 1 ? <span className="mx-1 text-slate-400">·</span> : null}
                        </span>
                    ))}
                </div>
            ) : (
                <p className="text-sm text-slate-500">-</p>
            )}
            {urls.length > limit ? (
                <button
                    type="button"
                    className="mt-1 text-xs font-medium text-blue-600 hover:text-blue-500"
                    onClick={() => setExpanded((v) => !v)}
                >
                    {expanded ? "收起" : `展开 ${urls.length - limit} 条`}
                </button>
            ) : null}
        </div>
    );
}
