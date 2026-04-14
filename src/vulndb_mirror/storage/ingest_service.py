from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from typing import Literal, Optional

from playwright.async_api import async_playwright

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.crawler.core import _BROWSER_ARGS, _STEALTH, _USER_AGENT, AVDCrawler
from vulndb_mirror.storage.raw_models import (
    CrawlPhaseResult,
    CrawlRunResult,
    PageCheckpoint,
    RetryResult,
    now_iso,
)
from vulndb_mirror.storage.repositories import RawRepository

logger = logging.getLogger(__name__)


@dataclass
class _PageTaskResult:
    page: int
    status: str
    entry_count: int
    has_next: bool
    saved_count: int
    stopped_by_since: bool = False
    error: Optional[str] = None


class RawIngestService:
    def __init__(self, config: CrawlConfig, repository: RawRepository) -> None:
        self.config = config
        self.repository = repository

    def crawl_incremental(self, start_page: Optional[int] = None) -> CrawlRunResult:
        sync_mode = (self.config.sync_mode or "hybrid").lower()
        if start_page is not None or sync_mode == "linear":
            linear_start = (
                start_page if start_page is not None else self._resolve_linear_start_page()
            )
            result = asyncio.run(
                self._crawl_page_range(
                    start_page=linear_start,
                    max_page=self.config.max_pages,
                    apply_since=True,
                )
            )
            phase = self._to_phase("linear", result)
            return CrawlRunResult(
                start_page=result.start_page,
                last_page=result.last_page,
                saved_entries=result.saved_entries,
                stopped_by_since=result.stopped_by_since,
                executed_pages=result.executed_pages,
                failed_pages=result.failed_pages,
                mode="linear",
                phases=[phase],
            )
        return asyncio.run(self._crawl_hybrid())

    def retry_pages(self, pages: list[int]) -> RetryResult:
        if not pages:
            return RetryResult(
                requested_pages=[], succeeded_pages=[], failed_pages=[], saved_entries=0
            )
        result = asyncio.run(self._crawl_explicit_pages(sorted(set(pages))))
        return RetryResult(
            requested_pages=sorted(set(pages)),
            succeeded_pages=[
                p for p in result.executed_pages if p not in result.failed_pages
            ],
            failed_pages=result.failed_pages,
            saved_entries=result.saved_entries,
        )

    async def _crawl_page_range(
        self,
        *,
        start_page: int,
        max_page: int,
        apply_since: bool,
        since_override: Optional[str] = None,
        skip_ok_checkpoints: bool = False,
    ) -> CrawlRunResult:
        crawler_config = self.config
        if since_override is not None:
            crawler_config = replace(self.config, since=since_override)
        crawler = AVDCrawler(crawler_config)
        concurrency = max(1, self.config.page_concurrency)

        saved_entries = 0
        failed_pages: list[int] = []
        executed_pages: list[int] = []
        stopped_by_since = False
        stop_all = False
        last_page = start_page
        checkpoint_map: dict[int, PageCheckpoint] = {}
        if skip_ok_checkpoints:
            checkpoint_map = {
                cp.page: cp for cp in self.repository.list_checkpoints(status=None)
            }
        head_recheck_pages = max(0, int(getattr(self.config, "head_recheck_pages", 0)))

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.config.headless, args=_BROWSER_ARGS
            )
            try:
                ctx = await browser.new_context(
                    user_agent=_USER_AGENT,
                    viewport={"width": 1280, "height": 800},
                    locale="zh-CN",
                )
                if hasattr(_STEALTH, "apply_stealth_async"):
                    await _STEALTH.apply_stealth_async(ctx)  # type: ignore[attr-defined]

                page_num = max(1, start_page)
                while page_num <= max_page and not stop_all:
                    window, next_page, stop_all = self._build_page_window(
                        page_num=page_num,
                        max_page=max_page,
                        concurrency=concurrency,
                        apply_since=apply_since,
                        skip_ok_checkpoints=skip_ok_checkpoints,
                        checkpoint_map=checkpoint_map,
                        head_recheck_pages=head_recheck_pages,
                    )
                    if stop_all:
                        break
                    if not window:
                        page_num = next_page
                        continue
                    page_results = await self._execute_window(
                        crawler,
                        ctx,
                        window,
                        apply_since=apply_since,
                    )
                    for page_result in page_results:
                        executed_pages.append(page_result.page)
                        last_page = page_result.page
                        if page_result.status == "failed":
                            failed_pages.append(page_result.page)
                        saved_entries += page_result.saved_count
                        if page_result.stopped_by_since:
                            stopped_by_since = True
                            stop_all = True
                            break
                        if page_result.status == "ok" and not page_result.has_next:
                            stop_all = True
                            break
                        checkpoint_map[page_result.page] = PageCheckpoint(
                            page=page_result.page,
                            status=page_result.status,  # type: ignore[arg-type]
                            entry_count=page_result.entry_count,
                            has_next=page_result.has_next,
                            error=page_result.error,
                            updated_at=now_iso(),
                        )
                    page_num = next_page
            finally:
                await browser.close()

        self.repository.update_resume_page(last_page + 1)
        return CrawlRunResult(
            start_page=start_page,
            last_page=max(start_page, last_page),
            saved_entries=saved_entries,
            stopped_by_since=stopped_by_since,
            executed_pages=executed_pages,
            failed_pages=failed_pages,
            mode="linear",
        )

    def _build_page_window(
        self,
        *,
        page_num: int,
        max_page: int,
        concurrency: int,
        apply_since: bool,
        skip_ok_checkpoints: bool,
        checkpoint_map: dict[int, PageCheckpoint],
        head_recheck_pages: int,
    ) -> tuple[list[int], int, bool]:
        window: list[int] = []
        cursor = page_num
        stop_all = False

        while cursor <= max_page and len(window) < concurrency:
            cp = checkpoint_map.get(cursor)
            should_force_recheck = cursor <= head_recheck_pages
            can_skip_ok = (
                skip_ok_checkpoints
                and apply_since
                and not should_force_recheck
                and cp is not None
                and cp.status == "ok"
                and cp.entry_count > 0
            )
            if can_skip_ok:
                if not cp.has_next:
                    stop_all = True
                    break
                cursor += 1
                continue
            window.append(cursor)
            cursor += 1
        return window, cursor, stop_all

    async def _crawl_explicit_pages(self, pages: list[int]) -> CrawlRunResult:
        crawler = AVDCrawler(self.config)
        saved_entries = 0
        failed_pages: list[int] = []
        executed_pages: list[int] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.config.headless, args=_BROWSER_ARGS
            )
            try:
                ctx = await browser.new_context(
                    user_agent=_USER_AGENT,
                    viewport={"width": 1280, "height": 800},
                    locale="zh-CN",
                )
                if hasattr(_STEALTH, "apply_stealth_async"):
                    await _STEALTH.apply_stealth_async(ctx)  # type: ignore[attr-defined]

                batch_size = max(1, self.config.page_concurrency)
                for idx in range(0, len(pages), batch_size):
                    window = pages[idx : idx + batch_size]
                    page_results = await self._execute_window(
                        crawler,
                        ctx,
                        window,
                        apply_since=False,
                    )
                    for page_result in page_results:
                        executed_pages.append(page_result.page)
                        if page_result.status == "failed":
                            failed_pages.append(page_result.page)
                        saved_entries += page_result.saved_count
            finally:
                await browser.close()

        last_page = max(pages) if pages else 1
        return CrawlRunResult(
            start_page=min(pages) if pages else 1,
            last_page=last_page,
            saved_entries=saved_entries,
            stopped_by_since=False,
            executed_pages=executed_pages,
            failed_pages=failed_pages,
            mode="linear",
        )

    async def _crawl_hybrid(self) -> CrawlRunResult:
        phases: list[CrawlPhaseResult] = []

        head_result = await self._crawl_page_range(
            start_page=1,
            max_page=self.config.max_pages,
            apply_since=True,
            since_override=self._resolve_head_since(),
            skip_ok_checkpoints=bool(
                getattr(self.config, "head_skip_ok_pages", False)
            ),
        )
        self.repository.update_sync_markers(head_last_stop_page=head_result.last_page)
        phases.append(self._to_phase("head_incremental", head_result))
        return self._merge_phases(phases, mode="hybrid")

    def _resolve_linear_start_page(self) -> int:
        gaps = self.repository.get_gaps(
            max_page=self.config.max_pages,
            include_failed=True,
        )
        return (
            gaps[0].start_page if gaps else self.repository.get_meta().resumable_from_page
        )

    def _resolve_head_since(self) -> Optional[str]:
        if self.config.since:
            return self.config.since
        return self.repository.get_meta().last_seen_date

    def _to_phase(
        self,
        phase: Literal["head_incremental", "linear"],
        result: CrawlRunResult,
    ) -> CrawlPhaseResult:
        return CrawlPhaseResult(
            phase=phase,
            start_page=result.start_page,
            last_page=result.last_page,
            saved_entries=result.saved_entries,
            stopped_by_since=result.stopped_by_since,
            executed_pages=result.executed_pages,
            failed_pages=result.failed_pages,
        )

    def _merge_phases(
        self, phases: list[CrawlPhaseResult], *, mode: str
    ) -> CrawlRunResult:
        if not phases:
            return CrawlRunResult(
                start_page=1,
                last_page=1,
                saved_entries=0,
                stopped_by_since=False,
                executed_pages=[],
                failed_pages=[],
                mode="hybrid" if mode == "hybrid" else "linear",
                phases=[],
            )

        executed_pages: list[int] = []
        failed_pages: list[int] = []
        saved_entries = 0
        stopped_by_since = False
        for phase in phases:
            executed_pages.extend(phase.executed_pages)
            failed_pages.extend(phase.failed_pages)
            saved_entries += phase.saved_entries
            stopped_by_since = stopped_by_since or phase.stopped_by_since

        unique_failed = sorted(set(failed_pages))
        return CrawlRunResult(
            start_page=min(p.start_page for p in phases),
            last_page=max(p.last_page for p in phases),
            saved_entries=saved_entries,
            stopped_by_since=stopped_by_since,
            executed_pages=executed_pages,
            failed_pages=unique_failed,
            mode="hybrid" if mode == "hybrid" else "linear",
            phases=phases,
        )

    async def _execute_window(
        self,
        crawler: AVDCrawler,
        ctx,
        pages: list[int],
        *,
        apply_since: bool,
    ) -> list[_PageTaskResult]:
        async def _fetch_page(page: int):
            try:
                bundle = await crawler._fetch_page_bundle_async(ctx, page)
                return page, bundle
            except Exception as exc:  # keep page context for checkpointing
                return page, exc

        tasks_by_page = {p: asyncio.create_task(_fetch_page(p)) for p in pages}

        page_result_map: dict[int, _PageTaskResult] = {}
        completed_pages: set[int] = set()
        try:
            for task in asyncio.as_completed(tasks_by_page.values()):
                page, bundle = await task
                completed_pages.add(page)

                if isinstance(bundle, BaseException):
                    msg = str(bundle)
                    checkpoint = PageCheckpoint(
                        page=page,
                        status="failed",
                        entry_count=0,
                        has_next=True,
                        error=msg,
                        updated_at=now_iso(),
                    )
                    self.repository.save_checkpoint(checkpoint)
                    page_result_map[page] = _PageTaskResult(
                        page=page,
                        status="failed",
                        entry_count=0,
                        has_next=True,
                        saved_count=0,
                        error=msg,
                    )
                    continue

                entries, has_next = bundle
                saved_count = 0
                stopped_by_since = False
                for entry in entries:
                    if (
                        apply_since
                        and crawler._since is not None
                        and entry.modified_date is not None
                        and entry.modified_date <= crawler._since
                    ):
                        stopped_by_since = True
                        break
                    self.repository.upsert_raw(entry, page=page)
                    saved_count += 1

                checkpoint = PageCheckpoint(
                    page=page,
                    status="ok",
                    entry_count=saved_count,
                    has_next=has_next,
                    error=None,
                    updated_at=now_iso(),
                )
                self.repository.save_checkpoint(checkpoint)
                page_result_map[page] = _PageTaskResult(
                    page=page,
                    status="ok",
                    entry_count=saved_count,
                    has_next=has_next,
                    saved_count=saved_count,
                    stopped_by_since=stopped_by_since,
                )
        except asyncio.CancelledError:
            for page, pending in tasks_by_page.items():
                if page in completed_pages:
                    continue
                if not pending.done():
                    pending.cancel()
                self.repository.save_checkpoint(
                    PageCheckpoint(
                        page=page,
                        status="failed",
                        entry_count=0,
                        has_next=True,
                        error="cancelled",
                        updated_at=now_iso(),
                    )
                )
            raise
        finally:
            await asyncio.gather(*tasks_by_page.values(), return_exceptions=True)

        # Keep consumer logic deterministic by returning results in page order.
        return [page_result_map[p] for p in pages]
