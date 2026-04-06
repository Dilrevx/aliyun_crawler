from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from playwright.async_api import async_playwright

from aliyun_crawler.config import CrawlConfig
from aliyun_crawler.crawler import _BROWSER_ARGS, _STEALTH, _USER_AGENT, AVDCrawler
from aliyun_crawler.rawdb.models import (
    CrawlRunResult,
    PageCheckpoint,
    RetryResult,
    now_iso,
)
from aliyun_crawler.rawdb.repositories import RawRepository

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
        if start_page is None:
            gaps = self.repository.get_gaps(
                max_page=self.config.max_pages,
                include_failed=True,
            )
            start_page = (
                gaps[0].start_page
                if gaps
                else self.repository.get_meta().resumable_from_page
            )
        return asyncio.run(
            self._crawl_page_range(
                start_page=start_page, max_page=self.config.max_pages
            )
        )

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
        self, *, start_page: int, max_page: int
    ) -> CrawlRunResult:
        crawler = AVDCrawler(self.config)
        concurrency = max(1, self.config.page_concurrency)

        saved_entries = 0
        failed_pages: list[int] = []
        executed_pages: list[int] = []
        stopped_by_since = False
        stop_all = False
        last_page = start_page

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
                    window = list(
                        range(page_num, min(page_num + concurrency, max_page + 1))
                    )
                    page_results = await self._execute_window(
                        crawler,
                        ctx,
                        window,
                        apply_since=True,
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
                    page_num += concurrency
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
        )

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
        )

    async def _execute_window(
        self,
        crawler: AVDCrawler,
        ctx,
        pages: list[int],
        *,
        apply_since: bool,
    ) -> list[_PageTaskResult]:
        tasks = [
            asyncio.create_task(crawler._fetch_page_bundle_async(ctx, p)) for p in pages
        ]
        bundles = await asyncio.gather(*tasks, return_exceptions=True)

        out: list[_PageTaskResult] = []
        for idx, bundle in enumerate(bundles):
            page = pages[idx]
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
                out.append(
                    _PageTaskResult(
                        page=page,
                        status="failed",
                        entry_count=0,
                        has_next=True,
                        saved_count=0,
                        error=msg,
                    )
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
            out.append(
                _PageTaskResult(
                    page=page,
                    status="ok",
                    entry_count=saved_count,
                    has_next=has_next,
                    saved_count=saved_count,
                    stopped_by_since=stopped_by_since,
                )
            )
        return out
