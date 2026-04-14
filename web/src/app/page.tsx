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
    references?: string[];
    patch_urls?: string[];
    detail_url?: string;
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

type TabMode = "search" | "debug";
type TriMode = "all" | "yes" | "no";
type PoCRuleMode = "balanced" | "strict" | "loose";

type SmartSearchTokens = {
    text: string[];
    cve: string;
    cwe: string;
    severity: string;
    patch: TriMode;
    poc: TriMode;
};

type FilterDraft = {
    search: string;
    patchOnly: TriMode;
    pocOnly: TriMode;
    refOnly: TriMode;
    detailOnly: TriMode;
    pocRuleMode: PoCRuleMode;
    showAdvanced: boolean;
    from: string;
    to: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://127.0.0.1:8787";

const DEFAULT_FILTERS: FilterDraft = {
    search: "",
    patchOnly: "all",
    pocOnly: "all",
    refOnly: "all",
    detailOnly: "all",
    pocRuleMode: "balanced",
    showAdvanced: false,
    from: "",
    to: "",
};

async function apiGet<T>(path: string): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    return (await response.json()) as T;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    return (await response.json()) as T;
}

function scoreText(score?: number | null): string {
    return score === null || score === undefined ? "-" : score.toFixed(1);
}

function normalizeTri(value: string | null): TriMode {
    if (value === "yes" || value === "no") return value;
    return "all";
}

function normalizeRule(value: string | null): PoCRuleMode {
    if (value === "strict" || value === "loose") return value;
    return "balanced";
}

function parseSmartSearch(raw: string): SmartSearchTokens {
    const result: SmartSearchTokens = { text: [], cve: "", cwe: "", severity: "", patch: "all", poc: "all" };
    const tokens = raw.trim().split(/\s+/).filter(Boolean);
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

function riskTone(severity?: string): "critical" | "high" | "medium" | "low" {
    const low = (severity || "").toLowerCase();
    if (low.includes("严重") || low.includes("critical")) return "critical";
    if (low.includes("高危") || low.includes("high")) return "high";
    if (low.includes("中危") || low.includes("medium")) return "medium";
    return "low";
}

function toneClass(kind: "critical" | "high" | "medium" | "low" | "warning" | "info" | "muted"): string {
    if (kind === "critical") return "bg-rose-600/15 text-rose-700 ring-rose-600/20";
    if (kind === "high") return "bg-amber-500/15 text-amber-700 ring-amber-500/20";
    if (kind === "medium") return "bg-sky-500/15 text-sky-700 ring-sky-500/20";
    if (kind === "warning") return "bg-violet-500/15 text-violet-700 ring-violet-500/20";
    if (kind === "info") return "bg-cyan-500/15 text-cyan-700 ring-cyan-500/20";
    if (kind === "low") return "bg-emerald-500/15 text-emerald-700 ring-emerald-500/20";
    return "bg-slate-500/10 text-slate-600 ring-slate-500/20";
}

function summarizePoc(item: RawItem, mode: PoCRuleMode): { label: string; tone: "warning" | "info" | "muted" } {
    const refs = item.references || [];
    const patches = item.patch_urls || [];
    const text = `${item.title || ""} ${item.description || ""} ${refs.join(" ")}`.toLowerCase();
    const hasPocWords = /poc|proof\s*of\s*concept|exploit|exp\b|payload|reproduce/.test(text);
    if (mode === "strict") {
        if (patches.length > 0 && hasPocWords) return { label: "疑似 PoC", tone: "warning" };
        if (hasPocWords) return { label: "PoC 命中", tone: "warning" };
        return { label: "未见 PoC 线索", tone: "muted" };
    }
    if (mode === "loose") {
        if (hasPocWords) return { label: "PoC 线索", tone: "warning" };
        if (patches.length > 0 && refs.length > 0) return { label: "补丁/引用齐全", tone: "info" };
        return { label: "未见 PoC 线索", tone: "muted" };
    }
    if (patches.length > 0 && hasPocWords) return { label: "疑似 PoC", tone: "warning" };
    if (patches.length > 0 && refs.length > 0) return { label: "有补丁线索", tone: "info" };
    if (hasPocWords) return { label: "PoC 线索", tone: "warning" };
    return { label: "未见 PoC 线索", tone: "muted" };
}

function trimUrl(url: string, keep = 56): string {
    try {
        const u = new URL(url);
        const text = `${u.hostname}${u.pathname}${u.search}`;
        return text.length <= keep ? text : `${text.slice(0, keep)}...`;
    } catch {
        return url.length <= keep ? url : `${url.slice(0, keep)}...`;
    }
}

function unique(items: string[]): string[] {
    return Array.from(new Set(items.filter(Boolean)));
}

export default function Home() {
    const [activeTab, setActiveTab] = useState<TabMode>("search");
    const [query, setQuery] = useState<QueryResp | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [draft, setDraft] = useState<FilterDraft>(DEFAULT_FILTERS);
    const [applied, setApplied] = useState<FilterDraft>(DEFAULT_FILTERS);

    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);

    const [selected, setSelected] = useState<RawItem | null>(null);
    const [detailJson, setDetailJson] = useState("{}");

    const [cveId, setCveId] = useState("");
    const [maxPage, setMaxPage] = useState(500);
    const [gaps, setGaps] = useState<GapsResp | null>(null);
    const [checkpoints, setCheckpoints] = useState<CheckpointsResp | null>(null);
    const [retryPages, setRetryPages] = useState("");
    const [retryResult, setRetryResult] = useState("{}");

    const searchTokens = useMemo(() => parseSmartSearch(applied.search), [applied.search]);

    const filteredRows = useMemo(() => {
        const items = query?.items || [];
        return items.filter((item) => {
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

            if (searchTokens.text.length && !searchTokens.text.every((t) => pool.includes(t))) return false;
            if (searchTokens.cve && !item.cve_id.toLowerCase().includes(searchTokens.cve)) return false;
            if (searchTokens.cwe && !(item.cwe_id || "").toLowerCase().includes(searchTokens.cwe)) return false;
            if (searchTokens.severity && !(item.severity || "").toLowerCase().includes(searchTokens.severity)) return false;

            if (applied.patchOnly === "yes" && !(item.patch_urls || []).length) return false;
            if (applied.patchOnly === "no" && (item.patch_urls || []).length > 0) return false;
            if (applied.refOnly === "yes" && !(item.references || []).length) return false;
            if (applied.refOnly === "no" && (item.references || []).length > 0) return false;
            if (applied.detailOnly === "yes" && !item.detail_url) return false;
            if (applied.detailOnly === "no" && !!item.detail_url) return false;

            if (searchTokens.patch === "yes" && !(item.patch_urls || []).length) return false;
            if (searchTokens.patch === "no" && (item.patch_urls || []).length > 0) return false;

            const poc = summarizePoc(item, applied.pocRuleMode).label;
            if (applied.pocOnly === "yes" && poc === "未见 PoC 线索") return false;
            if (applied.pocOnly === "no" && poc !== "未见 PoC 线索") return false;
            if (searchTokens.poc === "yes" && poc === "未见 PoC 线索") return false;
            if (searchTokens.poc === "no" && poc !== "未见 PoC 线索") return false;

            return true;
        });
    }, [query, searchTokens, applied]);

    const stats = useMemo(() => {
        const critical = filteredRows.filter((x) => riskTone(x.severity) === "critical").length;
        const high = filteredRows.filter((x) => riskTone(x.severity) === "high").length;
        const patch = filteredRows.filter((x) => (x.patch_urls || []).length > 0).length;
        const poc = filteredRows.filter((x) => summarizePoc(x, applied.pocRuleMode).label !== "未见 PoC 线索").length;
        return { critical, high, patch, poc };
    }, [filteredRows, applied.pocRuleMode]);

    const totalPages = Math.max(1, Math.ceil((query?.total ?? 0) / pageSize));

    const hasUnappliedChanges = JSON.stringify(draft) !== JSON.stringify(applied);

    async function runQuery(targetPage = page, targetPageSize = pageSize, filters = applied): Promise<void> {
        setLoading(true);
        setError("");
        try {
            const params = new URLSearchParams({ page: String(targetPage), page_size: String(targetPageSize) });
            if (filters.search.trim()) params.set("q", filters.search.trim());
            if (filters.showAdvanced && filters.from) params.set("modified_from", filters.from);
            if (filters.showAdvanced && filters.to) params.set("modified_to", filters.to);
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
        const initPage = Number(params.get("page") || "1");
        const initPageSize = Number(params.get("page_size") || "20");
        const tabValue = params.get("tab");
        const initTab: TabMode = tabValue === "debug" || tabValue === "ops" ? "debug" : "search";
        const initFilters: FilterDraft = {
            search: params.get("q") || "",
            patchOnly: normalizeTri(params.get("patch")),
            pocOnly: normalizeTri(params.get("poc")),
            refOnly: normalizeTri(params.get("ref")),
            detailOnly: normalizeTri(params.get("detail")),
            pocRuleMode: normalizeRule(params.get("poc_rule")),
            showAdvanced: params.get("advanced") === "1",
            from: params.get("modified_from") || "",
            to: params.get("modified_to") || "",
        };

        setActiveTab(initTab);
        setDraft(initFilters);
        setApplied(initFilters);

        let mounted = true;
        void (async () => {
            setLoading(true);
            setError("");
            try {
                const safePage = Math.max(1, initPage || 1);
                const safeSize = [10, 20, 50, 100].includes(initPageSize) ? initPageSize : 20;
                const queryParams = new URLSearchParams({ page: String(safePage), page_size: String(safeSize) });
                if (initFilters.search.trim()) queryParams.set("q", initFilters.search.trim());
                if (initFilters.showAdvanced && initFilters.from) queryParams.set("modified_from", initFilters.from);
                if (initFilters.showAdvanced && initFilters.to) queryParams.set("modified_to", initFilters.to);
                const data = await apiGet<QueryResp>(`/raw?${queryParams.toString()}`);
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
        })();

        return () => {
            mounted = false;
        };
    }, []);

    useEffect(() => {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("page_size", String(pageSize));
        if (applied.showAdvanced) params.set("advanced", "1");
        if (applied.showAdvanced && applied.from) params.set("modified_from", applied.from);
        if (applied.showAdvanced && applied.to) params.set("modified_to", applied.to);
        if (applied.search) params.set("q", applied.search);
        if (applied.patchOnly !== "all") params.set("patch", applied.patchOnly);
        if (applied.pocOnly !== "all") params.set("poc", applied.pocOnly);
        if (applied.refOnly !== "all") params.set("ref", applied.refOnly);
        if (applied.detailOnly !== "all") params.set("detail", applied.detailOnly);
        if (applied.pocRuleMode !== "balanced") params.set("poc_rule", applied.pocRuleMode);
        if (activeTab !== "search") params.set("tab", activeTab);
        window.history.replaceState(null, "", `${window.location.pathname}?${params.toString()}`);
    }, [page, pageSize, applied, activeTab]);

    function resetDraftAndApply(): void {
        setDraft(DEFAULT_FILTERS);
        setApplied(DEFAULT_FILTERS);
        void runQuery(1, pageSize, DEFAULT_FILTERS);
    }

    function applyDraft(): void {
        setApplied(draft);
        void runQuery(1, pageSize, draft);
    }

    async function openDetail(item: RawItem): Promise<void> {
        setSelected(item);
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(item.cve_id)}`);
            setDetailJson(JSON.stringify(data, null, 2));
        } catch {
            setDetailJson(JSON.stringify(item, null, 2));
        }
    }

    async function debugLoadByCve(): Promise<void> {
        if (!cveId.trim()) return;
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(cveId.trim())}`);
            await openDetail(data);
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    async function debugLoadGaps(): Promise<void> {
        try {
            setGaps(await apiGet<GapsResp>(`/pages/gaps?max_page=${maxPage}&include_failed=true`));
        } catch (e) {
            setGaps(null);
            setRetryResult(String(e));
        }
    }

    async function debugLoadCheckpoints(): Promise<void> {
        try {
            setCheckpoints(await apiGet<CheckpointsResp>("/pages/checkpoints"));
        } catch (e) {
            setCheckpoints(null);
            setRetryResult(String(e));
        }
    }

    async function debugRetryPages(): Promise<void> {
        const parsed = retryPages.split(/[\s,]+/).map((x) => Number(x)).filter((x) => Number.isInteger(x) && x > 0);
        if (!parsed.length) {
            setRetryResult("Please enter page numbers, e.g. 50 51 52");
            return;
        }
        try {
            const data = await apiPost("/pages/retry", { pages: parsed });
            setRetryResult(JSON.stringify(data, null, 2));
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.16),_transparent_34%),linear-gradient(180deg,#f8fbff_0%,#eef2ff_100%)] text-slate-900">
            <main className="mx-auto max-w-[1700px] px-4 py-5 lg:px-6">
                <div className="flex items-center gap-2">
                    <TabButton label="漏洞检索" active={activeTab === "search"} onClick={() => setActiveTab("search")} />
                    <TabButton label="Aliyun 调试" active={activeTab === "debug"} onClick={() => setActiveTab("debug")} />
                </div>

                {activeTab === "search" ? (
                    <div className="mt-4 grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
                        <aside className="sticky top-4 self-start rounded-xl border border-slate-200 bg-white p-3 shadow-[0_8px_25px_rgba(15,23,42,0.06)]">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-600">Filters</h2>
                                    <p className="mt-1 text-[11px] text-slate-500">大数据场景下仅在点击应用后筛选</p>
                                </div>
                                <button
                                    className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-700"
                                    onClick={() => setDraft((prev) => ({ ...prev, showAdvanced: !prev.showAdvanced }))}
                                >
                                    {draft.showAdvanced ? "收起" : "高级"}
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
                                    <span>{page}/{totalPages}</span>
                                </div>
                            </div>

                            <div className="mt-3 space-y-2">
                                <input
                                    className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400"
                                    placeholder="cve:CVE-2024 cwe:79 sev:high patch:yes poc:no nginx"
                                    value={draft.search}
                                    onChange={(e) => setDraft((prev) => ({ ...prev, search: e.target.value }))}
                                />

                                <div className="grid grid-cols-2 gap-2">
                                    <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.patchOnly} onChange={(e) => setDraft((prev) => ({ ...prev, patchOnly: normalizeTri(e.target.value) }))}>
                                        <option value="all">Patch 全部</option>
                                        <option value="yes">有 Patch</option>
                                        <option value="no">无 Patch</option>
                                    </select>
                                    <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.pocOnly} onChange={(e) => setDraft((prev) => ({ ...prev, pocOnly: normalizeTri(e.target.value) }))}>
                                        <option value="all">PoC 全部</option>
                                        <option value="yes">有 PoC</option>
                                        <option value="no">无 PoC</option>
                                    </select>
                                </div>

                                <div className="grid grid-cols-2 gap-2">
                                    <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.refOnly} onChange={(e) => setDraft((prev) => ({ ...prev, refOnly: normalizeTri(e.target.value) }))}>
                                        <option value="all">引用 全部</option>
                                        <option value="yes">有引用</option>
                                        <option value="no">无引用</option>
                                    </select>
                                    <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.detailOnly} onChange={(e) => setDraft((prev) => ({ ...prev, detailOnly: normalizeTri(e.target.value) }))}>
                                        <option value="all">详情链接 全部</option>
                                        <option value="yes">有详情链接</option>
                                        <option value="no">无详情链接</option>
                                    </select>
                                </div>

                                <select className="w-full rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.pocRuleMode} onChange={(e) => setDraft((prev) => ({ ...prev, pocRuleMode: normalizeRule(e.target.value) }))}>
                                    <option value="balanced">PoC 规则: balanced</option>
                                    <option value="strict">PoC 规则: strict</option>
                                    <option value="loose">PoC 规则: loose</option>
                                </select>

                                {draft.showAdvanced ? (
                                    <div className="grid gap-2 rounded border border-slate-200 bg-slate-50 p-2">
                                        <input className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" type="date" value={draft.from} onChange={(e) => setDraft((prev) => ({ ...prev, from: e.target.value }))} />
                                        <input className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" type="date" value={draft.to} onChange={(e) => setDraft((prev) => ({ ...prev, to: e.target.value }))} />
                                    </div>
                                ) : null}
                            </div>

                            <div className="mt-4 grid grid-cols-2 gap-2">
                                <button className="rounded border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700" onClick={resetDraftAndApply}>清空</button>
                                <button className="rounded bg-blue-600 px-3 py-2 text-xs font-medium text-white hover:bg-blue-500" onClick={applyDraft}>{loading ? "Loading..." : "应用筛选"}</button>
                            </div>

                            {hasUnappliedChanges ? <p className="mt-2 text-[11px] text-amber-700">筛选已修改，点击“应用筛选”后生效。</p> : null}
                            {error ? <p className="mt-2 text-xs text-rose-600">{error}</p> : null}
                        </aside>

                        <section className="space-y-3">
                            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">
                                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
                                    <span className="rounded-full bg-slate-100 px-2.5 py-1">{filteredRows.length} visible</span>
                                    <span className="rounded-full bg-slate-100 px-2.5 py-1">高危 {stats.high}</span>
                                    <span className="rounded-full bg-slate-100 px-2.5 py-1">严重 {stats.critical}</span>
                                    <span className="rounded-full bg-slate-100 px-2.5 py-1">PoC {stats.poc}</span>
                                </div>
                                <PageControls page={page} totalPages={totalPages} pageSize={pageSize} onPage={(p) => void runQuery(p, pageSize)} onPageSize={(size) => void runQuery(1, size)} />
                            </div>

                            <div className="divide-y divide-slate-200 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-[0_12px_28px_rgba(15,23,42,0.07)]">
                                {filteredRows.map((item) => {
                                    const poc = summarizePoc(item, applied.pocRuleMode);
                                    const severityTone = riskTone(item.severity);
                                    const cweText = [item.cwe_id || "-", item.cwe_description || "-"].filter(Boolean).join(" | ");
                                    const cvssText = `score=${scoreText(item.cvss_score)} | vector=${item.cvss_vector || "-"}`;
                                    return (
                                        <article key={item.cve_id} className="px-4 py-4">
                                            <div className="flex flex-wrap items-start gap-2">
                                                <h3 className="text-sm font-semibold text-slate-950">
                                                    {item.title || "无标题"}
                                                    <span className="ml-2 font-mono text-xs text-slate-500">{item.cve_id}</span>
                                                </h3>
                                                <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ${toneClass(severityTone)}`}>{item.severity || "unknown"}</span>
                                                <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ${toneClass(poc.tone)}`}>{poc.label}</span>
                                                <div className="ml-auto flex items-center gap-2">
                                                    <button className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px]" onClick={() => void openDetail(item)}>展开</button>
                                                    {item.detail_url ? <a className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px]" href={item.detail_url} target="_blank" rel="noreferrer">跳转</a> : null}
                                                </div>
                                            </div>

                                            <div className="mt-2 space-y-2 text-sm text-slate-700">
                                                <SummaryLine text={item.description || "暂无描述"} />
                                                <div className="grid gap-2 md:grid-cols-2">
                                                    <LabeledLine label="CWE" text={cweText} />
                                                    <LabeledLine label="CVSS" text={cvssText} mono />
                                                </div>
                                                <div className="grid gap-2 md:grid-cols-2">
                                                    <LinkLine title="引用链接（原始）" urls={unique(item.references || [])} />
                                                    <LinkLine title="补丁链接（提取）" urls={unique(item.patch_urls || [])} />
                                                </div>
                                            </div>
                                        </article>
                                    );
                                })}

                                {filteredRows.length === 0 ? (
                                    <div className="px-4 py-12 text-center text-sm text-slate-500">没有匹配结果，调整筛选后再试。</div>
                                ) : null}
                            </div>

                            <div className="flex justify-end">
                                <PageControls page={page} totalPages={totalPages} pageSize={pageSize} onPage={(p) => void runQuery(p, pageSize)} onPageSize={(size) => void runQuery(1, size)} />
                            </div>
                        </section>
                    </div>
                ) : (
                    <section className="mt-4 space-y-4">
                        <div className="rounded-xl border border-slate-200 bg-white px-4 py-3">
                            <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-600">Aliyun Debug</h2>
                            <p className="mt-1 text-sm text-slate-500">用于补漏、覆盖检查、页重试与排障。</p>
                        </div>

                        <div className="grid gap-4 xl:grid-cols-3">
                            <div className="rounded-xl border border-slate-200 bg-white p-4">
                                <h3 className="text-sm font-semibold">按 CVE 调试</h3>
                                <div className="mt-3 flex gap-2">
                                    <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2026-xxxx" />
                                    <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={() => void debugLoadByCve()}>查询</button>
                                </div>
                            </div>

                            <div className="rounded-xl border border-slate-200 bg-white p-4">
                                <h3 className="text-sm font-semibold">覆盖检查</h3>
                                <div className="mt-3 flex gap-2">
                                    <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" type="number" min={1} value={maxPage} onChange={(e) => setMaxPage(Number(e.target.value || 1))} />
                                    <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={() => void debugLoadGaps()}>gaps</button>
                                    <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={() => void debugLoadCheckpoints()}>checkpoints</button>
                                </div>
                            </div>

                            <div className="rounded-xl border border-slate-200 bg-white p-4">
                                <h3 className="text-sm font-semibold">页重试</h3>
                                <div className="mt-3 flex gap-2">
                                    <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" value={retryPages} onChange={(e) => setRetryPages(e.target.value)} placeholder="50 51 52" />
                                    <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={() => void debugRetryPages()}>retry</button>
                                </div>
                            </div>
                        </div>

                        <div className="grid gap-4 xl:grid-cols-3">
                            <DebugBlock title="Gaps" text={gaps ? JSON.stringify(gaps, null, 2) : "暂无 gaps 数据"} />
                            <DebugBlock title="Checkpoints" text={checkpoints ? JSON.stringify(checkpoints, null, 2) : "暂无 checkpoints 数据"} />
                            <DebugBlock title="Retry 结果" text={retryResult} />
                        </div>
                    </section>
                )}
            </main>

            {selected ? (
                <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/50 backdrop-blur-sm" onClick={() => setSelected(null)}>
                    <aside className="h-full w-full max-w-[680px] overflow-auto border-l border-slate-200 bg-white shadow-2xl" onClick={(e) => e.stopPropagation()}>
                        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-200 bg-white/95 px-5 py-4">
                            <div>
                                <div className="text-xs uppercase tracking-widest text-slate-400">Vulnerability Detail</div>
                                <h3 className="text-xl font-semibold text-slate-950">{selected.cve_id}</h3>
                            </div>
                            <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm" onClick={() => setSelected(null)}>关闭</button>
                        </div>

                        <div className="space-y-4 p-5">
                            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 space-y-2">
                                <LabeledLine label="标题" text={selected.title || "-"} />
                                <LabeledLine label="严重等级" text={selected.severity || "-"} />
                                <CollapsibleText label="简介" text={selected.description || "暂无描述"} lines={3} />
                                <div className="grid gap-2 md:grid-cols-2">
                                    <LabeledLine label="CWE" text={`${selected.cwe_id || "-"}${selected.cwe_description ? ` - ${selected.cwe_description}` : ""}`} />
                                    <LabeledLine label="CVSS" text={`${scoreText(selected.cvss_score)}${selected.cvss_vector ? ` | ${selected.cvss_vector}` : ""}`} mono />
                                </div>
                                <LabeledLine label="时间" text={`更新 ${selected.modified_date || "-"} / 发布 ${selected.published_date || "-"}`} />
                            </div>

                            <div className="rounded-xl bg-slate-950 p-4 text-white">
                                <div className="text-xs uppercase tracking-widest text-slate-400">JSON</div>
                                <pre className="mt-3 max-h-[560px] overflow-auto whitespace-pre-wrap break-words text-xs text-slate-100">{detailJson}</pre>
                            </div>
                        </div>
                    </aside>
                </div>
            ) : null}
        </div>
    );
}

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
    return (
        <button className={`rounded border px-3 py-1.5 text-xs font-medium ${active ? "border-blue-300 bg-blue-50 text-blue-700" : "border-slate-200 bg-white text-slate-600"}`} onClick={onClick}>
            {label}
        </button>
    );
}

function PageControls({
    page,
    totalPages,
    pageSize,
    onPage,
    onPageSize,
}: {
    page: number;
    totalPages: number;
    pageSize: number;
    onPage: (page: number) => void;
    onPageSize: (size: number) => void;
}) {
    return (
        <div className="flex items-center gap-2">
            <button className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" onClick={() => onPage(Math.max(1, page - 1))}>上一页</button>
            <button className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" onClick={() => onPage(Math.min(totalPages, page + 1))}>下一页</button>
            <select className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" value={page} onChange={(e) => onPage(Number(e.target.value))}>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((value) => (
                    <option key={value} value={value}>第 {value} 页</option>
                ))}
            </select>
            <select className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
                <option value={10}>10/页</option>
                <option value={20}>20/页</option>
                <option value={50}>50/页</option>
                <option value={100}>100/页</option>
            </select>
        </div>
    );
}

function SummaryLine({ text }: { text: string }) {
    const [expanded, setExpanded] = useState(false);
    const canExpand = text.length > 140;
    return (
        <div className="flex items-end gap-1 text-sm text-slate-600">
            <span className={`min-w-0 flex-1 leading-6 ${expanded ? "" : "line-clamp-2"}`}>{text}</span>
            {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
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

function LinkLine({ title, urls }: { title: string; urls: string[] }) {
    const [expanded, setExpanded] = useState(false);
    const canExpand = urls.length > 4;
    return (
        <div>
            <div className="text-xs uppercase tracking-widest text-slate-500">{title}</div>
            {urls.length ? (
                <div className="mt-1 flex items-end gap-1">
                    <div className={`min-w-0 flex-1 text-xs leading-5 text-slate-700 ${expanded ? "" : "line-clamp-2"}`}>
                        {urls.map((url, index) => (
                            <span key={url}>
                                <a href={url} target="_blank" rel="noreferrer" className="underline decoration-slate-300 underline-offset-2 hover:text-blue-700" title={url}>
                                    {trimUrl(url)}
                                </a>
                                {index < urls.length - 1 ? <span className="mx-1 text-slate-400">·</span> : null}
                            </span>
                        ))}
                    </div>
                    {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
                </div>
            ) : (
                <p className="text-xs text-slate-500">-</p>
            )}
        </div>
    );
}

function CollapsibleText({ label, text, lines = 2 }: { label: string; text: string; lines?: number }) {
    const [expanded, setExpanded] = useState(false);
    const clampClass = lines === 1 ? "line-clamp-1" : lines === 2 ? "line-clamp-2" : "line-clamp-3";
    const canExpand = text.length > (lines === 1 ? 80 : lines === 2 ? 140 : 220);
    return (
        <div className="text-sm leading-6 text-slate-700">
            <div className="flex items-end gap-1">
                <strong className="font-semibold text-slate-900">{label}: </strong>
                <span className={`min-w-0 flex-1 ${expanded ? "" : clampClass}`}>{text}</span>
                {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
            </div>
        </div>
    );
}

function DebugBlock({ title, text }: { title: string; text: string }) {
    return (
        <div className="rounded-xl border border-slate-200 bg-white p-4">
            <h3 className="text-sm font-semibold">{title}</h3>
            <pre className="mt-3 max-h-72 overflow-auto rounded border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">{text}</pre>
        </div>
    );
}
