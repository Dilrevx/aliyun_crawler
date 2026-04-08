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

type SmartSearchTokens = {
    text: string[];
    cve: string;
    cwe: string;
    severity: string;
    patch: PocMode;
    poc: PocMode;
};

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

function useDebouncedValue<T>(value: T, delayMs: number): T {
    const [debounced, setDebounced] = useState(value);
    useEffect(() => {
        const id = window.setTimeout(() => setDebounced(value), delayMs);
        return () => window.clearTimeout(id);
    }, [value, delayMs]);
    return debounced;
}

function parseSmartSearch(raw: string): SmartSearchTokens {
    const result: SmartSearchTokens = {
        text: [],
        cve: "",
        cwe: "",
        severity: "",
        patch: "all",
        poc: "all",
    };

    const tokens = raw
        .trim()
        .split(/\s+/)
        .filter(Boolean);

    for (const token of tokens) {
        const lower = token.toLowerCase();
        if (lower.startsWith("cve:")) {
            result.cve = lower.slice(4);
            continue;
        }
        if (lower.startsWith("cwe:")) {
            result.cwe = lower.slice(4);
            continue;
        }
        if (lower.startsWith("sev:")) {
            result.severity = lower.slice(4);
            continue;
        }
        if (lower === "patch:yes" || lower === "patch:no") {
            result.patch = lower.endsWith("yes") ? "yes" : "no";
            continue;
        }
        if (lower === "poc:yes" || lower === "poc:no") {
            result.poc = lower.endsWith("yes") ? "yes" : "no";
            continue;
        }
        result.text.push(lower);
    }

    return result;
}

export default function Home() {
    const [query, setQuery] = useState<QueryResp | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [search, setSearch] = useState("");
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

    const debouncedSearch = useDebouncedValue(search, 350);
    const searchTokens = useMemo(() => parseSmartSearch(debouncedSearch), [debouncedSearch]);

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

            if (searchTokens.text.length) {
                const ok = searchTokens.text.every((token) => pool.includes(token));
                if (!ok) return false;
            }

            if (searchTokens.cve && !item.cve_id.toLowerCase().includes(searchTokens.cve)) return false;
            if (searchTokens.cwe && !(item.cwe_id || "").toLowerCase().includes(searchTokens.cwe)) return false;
            if (searchTokens.severity && !(item.severity || "").toLowerCase().includes(searchTokens.severity)) return false;

            if (patchOnly === "yes" && !(item.patch_urls || []).length) return false;
            if (patchOnly === "no" && (item.patch_urls || []).length > 0) return false;

            if (searchTokens.patch === "yes" && !(item.patch_urls || []).length) return false;
            if (searchTokens.patch === "no" && (item.patch_urls || []).length > 0) return false;

            const poc = summarizePoc(item, pocRuleMode).label;
            if (pocOnly === "yes" && poc === "未见 PoC 线索") return false;
            if (pocOnly === "no" && poc !== "未见 PoC 线索") return false;
            if (searchTokens.poc === "yes" && poc === "未见 PoC 线索") return false;
            if (searchTokens.poc === "no" && poc !== "未见 PoC 线索") return false;
            return true;
        });
    }, [query, searchTokens, patchOnly, pocOnly, pocRuleMode]);

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
        const params = new URLSearchParams(window.location.search);
        const startPage = Number(params.get("page") || "1");
        const startPageSize = Number(params.get("page_size") || "20");
        const startFrom = params.get("modified_from") || "";
        const startTo = params.get("modified_to") || "";
        const startSearch = params.get("q") || "";
        const startPatch = (params.get("patch") as PocMode) || "all";
        const startPoc = (params.get("poc") as PocMode) || "all";
        const startRule = (params.get("poc_rule") as PoCRuleMode) || "balanced";
        const startAdvanced = params.get("advanced") === "1";

        setSearch(startSearch);
        setPatchOnly(startPatch === "yes" || startPatch === "no" ? startPatch : "all");
        setPocOnly(startPoc === "yes" || startPoc === "no" ? startPoc : "all");
        setPocRuleMode(startRule === "strict" || startRule === "loose" ? startRule : "balanced");
        setShowAdvanced(startAdvanced);
        setFrom(startFrom);
        setTo(startTo);

        let mounted = true;
        async function initQuery() {
            setLoading(true);
            setError("");
            try {
                const data = await apiGet<QueryResp>(`/raw?page=${Math.max(1, startPage || 1)}&page_size=${[10, 20, 50, 100].includes(startPageSize) ? startPageSize : 20}${startFrom ? `&modified_from=${encodeURIComponent(startFrom)}` : ""}${startTo ? `&modified_to=${encodeURIComponent(startTo)}` : ""}`);
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

    useEffect(() => {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("page_size", String(pageSize));
        if (showAdvanced) params.set("advanced", "1");
        if (showAdvanced && from) params.set("modified_from", from);
        if (showAdvanced && to) params.set("modified_to", to);
        if (search.trim()) params.set("q", search.trim());
        if (patchOnly !== "all") params.set("patch", patchOnly);
        if (pocOnly !== "all") params.set("poc", pocOnly);
        if (pocRuleMode !== "balanced") params.set("poc_rule", pocRuleMode);
        window.history.replaceState(null, "", `${window.location.pathname}?${params.toString()}`);
    }, [page, pageSize, showAdvanced, from, to, search, patchOnly, pocOnly, pocRuleMode]);

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

    function resetFilters() {
        setSearch("");
        setPatchOnly("all");
        setPocOnly("all");
        setPocRuleMode("balanced");
        setFrom("");
        setTo("");
        setShowAdvanced(false);
    }

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.18),_transparent_30%),linear-gradient(180deg,#f8fbff_0%,#eef2ff_100%)] text-slate-900">
            <main className="mx-auto max-w-[1700px] px-4 py-5 lg:px-6">
                <div className="mt-5 grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)]">
                    <aside className="sticky top-4 self-start rounded-xl border border-slate-200 bg-white p-3 shadow-[0_8px_25px_rgba(15,23,42,0.06)]">
                        <div className="flex items-center justify-between gap-2">
                            <div>
                                <h2 className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-600">Filters</h2>
                                <p className="text-xs text-slate-500">支持语法检索与快速筛选</p>
                            </div>
                            <button
                                className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-medium text-slate-700"
                                onClick={() => setShowAdvanced((v) => !v)}
                            >
                                {showAdvanced ? "收起" : "高级"}
                            </button>
                        </div>

                        <div className="mt-3 rounded border border-slate-200 bg-slate-50 px-2 py-2 text-[11px] text-slate-600">
                            <div className="flex items-center justify-between gap-2">
                                <span className="truncate">{API_BASE}</span>
                                <span className={`rounded-full px-2 py-0.5 ${loading ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"}`}>
                                    {loading ? "同步中" : "在线"}
                                </span>
                            </div>
                            <div className="mt-1 flex items-center justify-between text-slate-500">
                                <span>{query?.total ?? 0} total</span>
                                <span>{query?.page ?? page}/{totalPages}</span>
                            </div>
                        </div>

                        <div className="mt-3 space-y-2">
                            <input
                                className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400"
                                placeholder="高级检索: cve:CVE-2024 cwe:79 sev:high patch:yes poc:no nginx"
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                            />

                            <div className="grid grid-cols-2 gap-3">
                                <select className="rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400" value={patchOnly} onChange={(e) => setPatchOnly(e.target.value as PocMode)}>
                                    <option value="all">Patch 全部</option>
                                    <option value="yes">仅有 Patch</option>
                                    <option value="no">无 Patch</option>
                                </select>
                                <select className="rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400" value={pocOnly} onChange={(e) => setPocOnly(e.target.value as PocMode)}>
                                    <option value="all">PoC 全部</option>
                                    <option value="yes">仅 PoC</option>
                                    <option value="no">无 PoC</option>
                                </select>
                            </div>

                            <select className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400" value={pocRuleMode} onChange={(e) => setPocRuleMode(e.target.value as PoCRuleMode)}>
                                <option value="balanced">PoC 规则: balanced</option>
                                <option value="strict">PoC 规则: strict</option>
                                <option value="loose">PoC 规则: loose</option>
                            </select>

                            {showAdvanced ? (
                                <div className="grid gap-2 rounded border border-slate-200 bg-slate-50 p-2">
                                    <input className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
                                    <input className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
                                </div>
                            ) : null}
                        </div>

                        <div className="mt-4 grid grid-cols-2 gap-2">
                            <button className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700" onClick={() => { resetFilters(); void runQuery(1, pageSize); }}>
                                清空
                            </button>
                            <button className="rounded-2xl bg-blue-600 px-4 py-3 text-sm font-medium text-white transition hover:bg-blue-500" onClick={() => runQuery(1, pageSize)}>
                                {loading ? "Loading..." : "应用"}
                            </button>
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
                        <div className="flex flex-wrap items-center justify-between gap-3 rounded-[18px] border border-slate-200 bg-white/90 px-4 py-3 shadow-[0_18px_55px_rgba(15,23,42,0.08)] backdrop-blur">
                            <div>
                                <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-500">Results</h2>
                            </div>
                            <div className="flex flex-wrap items-center gap-2 text-sm text-slate-600">
                                <span className="rounded-full bg-slate-100 px-3 py-1">{rows.length} visible</span>
                                <span className="rounded-full bg-slate-100 px-3 py-1">高危 {stats.highCount}</span>
                                <span className="rounded-full bg-slate-100 px-3 py-1">严重 {stats.criticalCount}</span>
                                <select
                                    className="rounded border border-slate-200 bg-white px-2 py-1 text-xs"
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
                                    className="rounded border border-slate-200 bg-white px-2 py-1 text-xs"
                                    value={pageSize}
                                    onChange={(e) => void runQuery(1, Number(e.target.value))}
                                >
                                    <option value={10}>10/页</option>
                                    <option value={20}>20/页</option>
                                    <option value={50}>50/页</option>
                                    <option value={100}>100/页</option>
                                </select>
                            </div>
                        </div>

                        <div className="divide-y divide-slate-200 overflow-hidden rounded-[22px] border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.08)]">
                            {rows.map((item) => {
                                const poc = summarizePoc(item, pocRuleMode);
                                const sevTone = riskTone(item.severity);
                                const refs = unique((item.references || []).filter(Boolean)).slice(0, 8);
                                const patches = unique((item.patch_urls || []).filter(Boolean));
                                const cweText = [item.cwe_id || "-", item.cwe_description || "-"]
                                    .filter(Boolean)
                                    .join(" | ");
                                const cvssText = `score=${scoreText(item.cvss_score)} | vector=${item.cvss_vector || "-"}`;

                                return (
                                    <article key={item.cve_id} className="px-4 py-4 md:px-5 md:py-4">
                                        <div className="flex flex-wrap items-start gap-2">
                                            <h3 className="text-base font-semibold text-slate-950">
                                                {item.title || "无标题"}
                                                <span className="ml-2 font-mono text-xs text-slate-500">{item.cve_id}</span>
                                            </h3>
                                            <span className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${toneClass(sevTone)}`}>{item.severity || "unknown"}</span>
                                            <span className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${toneClass(poc.tone)}`}>{poc.label}</span>
                                            {patches.length ? <span className="rounded-full bg-slate-900 px-2.5 py-0.5 text-xs text-white">patch {patches.length}</span> : null}
                                            <div className="ml-auto flex flex-wrap gap-2">
                                                <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700" onClick={() => openDetail(item)}>展开</button>
                                                {item.detail_url ? (
                                                    <a className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700" href={item.detail_url} target="_blank" rel="noreferrer">跳转</a>
                                                ) : null}
                                            </div>
                                        </div>

                                        <div className="mt-3 space-y-2 text-sm leading-6 text-slate-700">
                                            <PlainSummary text={item.description || "暂无描述"} lines={2} />
                                            <div className="grid gap-2 md:grid-cols-2">
                                                <LabeledLine label="CWE" text={cweText} />
                                                <LabeledLine label="CVSS" text={cvssText} mono />
                                            </div>
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

                        <div className="flex justify-end gap-2">
                            <button className="rounded border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-700" onClick={() => void runQuery(Math.max(1, page - 1), pageSize)}>
                                上一页
                            </button>
                            <button className="rounded border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-700" onClick={() => void runQuery(Math.min(totalPages, page + 1), pageSize)}>
                                下一页
                            </button>
                            <select
                                className="rounded border border-slate-200 bg-white px-2 py-1.5 text-xs"
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
                                className="rounded border border-slate-200 bg-white px-2 py-1.5 text-xs"
                                value={pageSize}
                                onChange={(e) => void runQuery(1, Number(e.target.value))}
                            >
                                <option value={10}>10/页</option>
                                <option value={20}>20/页</option>
                                <option value={50}>50/页</option>
                                <option value={100}>100/页</option>
                            </select>
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

function CollapsibleText({ label, text, lines = 2, mono = false }: { label: string; text: string; lines?: number; mono?: boolean }) {
    const [expanded, setExpanded] = useState(false);
    const clampClass = lines === 1 ? "line-clamp-1" : lines === 2 ? "line-clamp-2" : "line-clamp-3";
    const canExpand = (text || "").length > (lines === 1 ? 80 : lines === 2 ? 140 : 220);

    return (
        <div className="text-sm leading-6 text-slate-700">
            <div className="flex items-end gap-1 text-sm leading-6 text-slate-700">
                <strong className="font-semibold text-slate-900">{label}: </strong>
                <span className={`min-w-0 flex-1 ${mono ? "font-mono text-[13px]" : ""} ${expanded ? "" : clampClass}`}>
                    {text || "-"}
                </span>
                {canExpand ? (
                    <button
                        type="button"
                        className="shrink-0 text-xs font-medium text-blue-600 hover:text-blue-500"
                        onClick={() => setExpanded((v) => !v)}
                    >
                        {expanded ? "收起" : "展开"}
                    </button>
                ) : null}
            </div>
        </div>
    );
}

function PlainSummary({ text, lines = 2 }: { text: string; lines?: number }) {
    const [expanded, setExpanded] = useState(false);
    const clampClass = lines === 1 ? "line-clamp-1" : lines === 2 ? "line-clamp-2" : "line-clamp-3";
    const canExpand = (text || "").length > (lines === 1 ? 80 : lines === 2 ? 140 : 220);

    return (
        <div className="flex items-end gap-1 text-sm leading-6 text-slate-600">
            <span className={`min-w-0 flex-1 ${expanded ? "" : clampClass}`}>{text || "-"}</span>
            {canExpand ? (
                <button
                    type="button"
                    className="shrink-0 text-xs font-medium text-blue-600 hover:text-blue-500"
                    onClick={() => setExpanded((v) => !v)}
                >
                    {expanded ? "收起" : "展开"}
                </button>
            ) : null}
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
    const canExpand = urls.length > limit;
    return (
        <div>
            <div className="text-xs uppercase tracking-widest text-slate-500">{title}</div>
            {urls.length ? (
                <div className="mt-2 flex items-end gap-1">
                    <div className={`min-w-0 flex-1 text-xs leading-5 text-slate-700 ${expanded ? "" : "line-clamp-2"}`}>
                        {urls.map((url, index) => (
                            <p key={url}>
                                <a
                                    href={url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="underline decoration-slate-300 underline-offset-2 hover:text-blue-700"
                                    title={url}
                                >
                                    {trimUrl(url)}
                                </a>
                                {index < urls.length - 1 ? <span className="mx-1 text-slate-400">·</span> : null}
                            </p>
                        ))}
                    </div>
                    {canExpand ? (
                        <button
                            type="button"
                            className="shrink-0 text-xs font-medium text-blue-600 hover:text-blue-500"
                            onClick={() => setExpanded((v) => !v)}
                        >
                            {expanded ? "收起" : "展开"}
                        </button>
                    ) : null}
                </div>
            ) : (
                <p className="text-sm text-slate-500">-</p>
            )}
        </div>
    );
}
