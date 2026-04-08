"""Aliyun AVD page crawler.

Fetches CVE list pages from ``avd.aliyun.com/nvd/list`` and detail pages from
``avd.aliyun.com/detail?id=AVD-XXXX-XXXX``, renders JavaScript with Playwright
(+ playwright-stealth to bypass the Alibaba Cloud WAF), parses the HTML with
BeautifulSoup, and yields :class:`~vulndb_mirror.models.RawAVDEntry` objects.

Incremental mode: pass :attr:`CrawlConfig.since` (ISO date) to skip entries
whose ``modified_date`` is older than that threshold.  The last-seen timestamp
is persisted in ``<data_dir>/.state.json`` by :class:`~vulndb_mirror.storage.CrawlStorage`.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, Iterator, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag
from playwright.async_api import BrowserContext as AsyncBrowserContext
from playwright.async_api import Page as AsyncPage
from playwright.async_api import async_playwright
from playwright.sync_api import BrowserContext, Page, sync_playwright
from playwright_stealth import Stealth

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.models import RawAVDEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns for identifying GitHub commit / PR / issue links
# ---------------------------------------------------------------------------

_GITHUB_ANY_RE = re.compile(
    r"https?://github\.com/[^/]+/[^/]+/(commit|pull|issues)/[\w\d\-]+",
    re.IGNORECASE,
)

# Date formats seen on avd.aliyun.com
_DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%Y/%m/%d",
]

# Stealth settings shared across all instances
_STEALTH = Stealth(
    navigator_webdriver=True,
    navigator_platform_override="Linux x86_64",
    navigator_languages_override=("zh-CN", "zh"),
)

_BROWSER_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


def _parse_date(text: str) -> Optional[datetime]:
    text = text.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_patch_urls(urls: list[str]) -> list[str]:
    """Return only URLs that look like GitHub commit / PR / issue links."""
    return [u for u in urls if _GITHUB_ANY_RE.search(u)]


class AVDCrawler:
    """Playwright-based crawler for avd.aliyun.com.

    Uses headless Chromium with playwright-stealth to bypass the Alibaba Cloud
    WAF JS challenge, then parses the rendered HTML with BeautifulSoup.

    Args:
        config: Runtime parameters.  Defaults to a :class:`CrawlConfig` with
                all default values.
    """

    def __init__(self, config: Optional[CrawlConfig] = None) -> None:
        self.config = config or CrawlConfig()
        self._page: Optional[Page] = None
        self._since: Optional[datetime] = None
        if self.config.since:
            self._since = _parse_date(self.config.since)
            if self._since is None:
                logger.warning("Could not parse 'since' date: %s", self.config.since)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> Generator[RawAVDEntry, None, None]:
        """Crawl CVE list pages and yield parsed :class:`RawAVDEntry` objects.

        Uses page-level concurrency while preserving ordered consumption:
        - pages are fetched concurrently in windows of ``config.page_concurrency``;
        - results are consumed in ascending page order so incremental ``since``
          break semantics remain correct.
        """
        entries = asyncio.run(self._crawl_async())
        for entry in entries:
            yield entry

    async def _crawl_async(self) -> list[RawAVDEntry]:
        """Async implementation for concurrent page crawling.

        Important: although pages are fetched concurrently, we process completed
        pages in page-number order to ensure the first old entry (``since``)
        triggers a deterministic global stop.
        """
        out: list[RawAVDEntry] = []
        concurrency = max(1, getattr(self.config, "page_concurrency", 1))

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.config.headless,
                args=_BROWSER_ARGS,
            )
            try:
                ctx = await browser.new_context(
                    user_agent=_USER_AGENT,
                    viewport={"width": 1280, "height": 800},
                    locale="zh-CN",
                )
                if hasattr(_STEALTH, "apply_stealth_async"):
                    await _STEALTH.apply_stealth_async(ctx)  # type: ignore[attr-defined]

                page_num = 1
                stop_all = False
                while page_num <= self.config.max_pages and not stop_all:
                    window_pages = list(
                        range(
                            page_num,
                            min(page_num + concurrency, self.config.max_pages + 1),
                        )
                    )
                    tasks = [
                        asyncio.create_task(self._fetch_page_bundle_async(ctx, pnum))
                        for pnum in window_pages
                    ]
                    bundles = await asyncio.gather(*tasks, return_exceptions=True)

                    by_page: dict[int, tuple[list[RawAVDEntry], bool]] = {}
                    for i, result in enumerate(bundles):
                        pnum = window_pages[i]
                        if isinstance(result, BaseException):
                            logger.error(
                                "Failed to fetch page %d bundle: %s", pnum, result
                            )
                            by_page[pnum] = ([], False)
                        else:
                            by_page[pnum] = result

                    for pnum in window_pages:
                        entries, has_next = by_page[pnum]
                        if not entries:
                            logger.info("No entries on page %d — stopping.", pnum)
                            stop_all = True
                            break

                        stop_page = False
                        for entry in entries:
                            if (
                                self._since
                                and entry.modified_date
                                and entry.modified_date <= self._since
                            ):
                                logger.info(
                                    "Entry %s modified at %s before since=%s — stopping.",
                                    entry.cve_id,
                                    entry.modified_date,
                                    self._since,
                                )
                                stop_page = True
                                stop_all = True
                                break
                            out.append(entry)

                        if stop_page or not has_next:
                            stop_all = True
                            break

                    page_num += concurrency
            finally:
                await browser.close()

        return out

    async def _fetch_page_bundle_async(
        self,
        ctx: AsyncBrowserContext,
        page_num: int,
    ) -> tuple[list[RawAVDEntry], bool]:
        """Fetch one list page and all its detail pages (same page number)."""
        page = await ctx.new_page()
        try:
            entries, has_next = await self._fetch_list_page_async(page, page_num)
            if not entries:
                return [], has_next

            detailed: list[RawAVDEntry] = []
            for entry in entries:
                detailed.append(await self._fetch_detail_async(page, entry))
                await self._sleep_async()
            return detailed, has_next
        finally:
            await page.close()

    async def _sleep_async(self) -> None:
        lo, hi = self.config.delay_range
        delay = random.uniform(lo, hi)
        logger.debug("Sleeping %.1fs between requests.", delay)
        await asyncio.sleep(delay)

    async def _render_async(self, page: AsyncPage, url: str) -> BeautifulSoup:
        timeout_ms = int(self.config.timeout * 1000)
        await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        html = await page.content()
        return BeautifulSoup(html, "html.parser")

    async def _fetch_list_page_async(
        self,
        page: AsyncPage,
        page_num: int,
    ) -> tuple[list[RawAVDEntry], bool]:
        url = f"{self.config.list_url}?page={page_num}&pageSize={self.config.page_size}"
        try:
            soup = await self._render_async(page, url)
        except Exception as exc:
            logger.error("Failed to fetch list page %d: %s", page_num, exc)
            return [], False

        entries = self._parse_list_page(soup)
        has_next = self._has_next_page(soup)
        logger.info(
            "Page %d: %d entries, has_next=%s", page_num, len(entries), has_next
        )
        return entries, has_next

    async def _fetch_detail_async(
        self, page: AsyncPage, stub: RawAVDEntry
    ) -> RawAVDEntry:
        if not stub.detail_url:
            stub.detail_url = self.config.detail_url_template.format(stub.cve_id)

        try:
            soup = await self._render_async(page, stub.detail_url)
        except Exception as exc:
            logger.error("Failed to fetch detail for %s: %s", stub.cve_id, exc)
            return stub

        return self._parse_detail_page(stub, soup)

    def fetch_single(self, cve_id: str) -> Optional[RawAVDEntry]:
        """Fetch and return a single CVE entry by ID."""
        with self._browser_context() as ctx:
            self._page = ctx.new_page()
            try:
                url = self.config.detail_url_template.format(cve_id)
                stub = RawAVDEntry(cve_id=cve_id, detail_url=url)
                return self._fetch_detail(stub)
            finally:
                self._page = None

    # ------------------------------------------------------------------
    # Browser context manager
    # ------------------------------------------------------------------

    @contextmanager
    def _browser_context(self) -> Iterator[BrowserContext]:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=self.config.headless,
                args=_BROWSER_ARGS,
            )
            try:
                ctx = browser.new_context(
                    user_agent=_USER_AGENT,
                    viewport={"width": 1280, "height": 800},
                    locale="zh-CN",
                )
                _STEALTH.apply_stealth_sync(ctx)
                yield ctx
            finally:
                browser.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sleep(self) -> None:
        lo, hi = self.config.delay_range
        delay = random.uniform(lo, hi)
        logger.debug("Sleeping %.1fs between requests.", delay)
        time.sleep(delay)

    def _render(self, url: str) -> BeautifulSoup:
        """Navigate to *url*, wait for the table or body, return parsed soup."""
        assert self._page is not None, "_render called outside browser context"
        timeout_ms = int(self.config.timeout * 1000)
        self._page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        html = self._page.content()
        return BeautifulSoup(html, "html.parser")

    # ---- List page ----------------------------------------------------------

    def _fetch_list_page(self, page: int) -> tuple[list[RawAVDEntry], bool]:
        """Fetch one list page; returns (entries, has_next_page)."""
        url = f"{self.config.list_url}?page={page}&pageSize={self.config.page_size}"
        try:
            soup = self._render(url)
        except Exception as exc:
            logger.error("Failed to fetch list page %d: %s", page, exc)
            return [], False

        entries = self._parse_list_page(soup)
        has_next = self._has_next_page(soup)
        logger.info("Page %d: %d entries, has_next=%s", page, len(entries), has_next)
        return entries, has_next

    def _parse_list_page(self, soup: BeautifulSoup) -> list[RawAVDEntry]:
        """Parse the CVE table on a list page into RawAVDEntry stubs.

        Table columns (in order): CVE编号, 漏洞名称, 漏洞类型, 披露时间, CVSS评分
        """
        entries: list[RawAVDEntry] = []
        table = soup.find("table")
        if table is None:
            return entries
        tbody = table.find("tbody") or table
        for row in tbody.find_all("tr"):  # type: ignore[union-attr]
            cells = row.find_all("td")
            if len(cells) < 4:
                continue
            entry = self._parse_list_row(cells)
            if entry:
                entries.append(entry)
        return entries

    def _parse_list_row(self, cells: list[Tag]) -> Optional[RawAVDEntry]:
        """Parse a single <tr> into a stub RawAVDEntry.

        Column layout observed on avd.aliyun.com/nvd/list:
          0 – CVE编号:  <a href="/detail?id=AVD-XXXX-XXXX">CVE-XXXX-XXXX</a>
          1 – 漏洞名称: plain text
          2 – 漏洞类型: <button data-original-title="CWE desc">CWE-xxx</button>
          3 – 披露时间: "YYYY-MM-DD"
          4 – CVSS评分: <button>N.N</button>
        """
        try:
            # Cell 0: CVE link → ID and detail URL
            link_tag = cells[0].find("a")
            if not link_tag:
                return None
            cve_id = link_tag.get_text(strip=True)
            href = link_tag.get("href", "")
            if not cve_id.startswith("CVE-"):
                return None
            detail_url = (
                href if href.startswith("http") else urljoin(self.config.base_url, href)
            )

            # Cell 1: vuln name
            title = cells[1].get_text(strip=True) if len(cells) > 1 else ""

            # Cell 2: CWE type button (data-original-title = human name)
            cwe_id: Optional[str] = None
            cwe_description: Optional[str] = None
            if len(cells) > 2:
                cwe_btn = cells[2].find("button")
                if cwe_btn:
                    raw = cwe_btn.get_text(strip=True)
                    if re.match(r"CWE-\d+", raw):
                        cwe_id = raw
                    cwe_description = cwe_btn.get("data-original-title") or None

            # Cell 3: disclosed date (披露时间)
            date_text = cells[3].get_text(strip=True) if len(cells) > 3 else ""
            modified_date = _parse_date(date_text)

            # Cell 4: CVSS score button
            cvss_score: Optional[float] = None
            if len(cells) > 4:
                cvss_txt = cells[4].get_text(strip=True)
                try:
                    cvss_score = float(cvss_txt)
                except ValueError:
                    pass

            return RawAVDEntry(
                cve_id=cve_id,
                title=title,
                cwe_id=cwe_id,
                cwe_description=cwe_description,
                cvss_score=cvss_score,
                modified_date=modified_date,
                detail_url=detail_url,
            )
        except Exception as exc:
            logger.debug("Skipping malformed row: %s", exc)
            return None

    def _parse_list_cards(self, soup: BeautifulSoup) -> list[RawAVDEntry]:
        """Fallback parser for card-style list layout (not currently used)."""
        entries: list[RawAVDEntry] = []
        for card in soup.find_all(class_=re.compile(r"cve-item|vuln-item|list-item")):
            link = card.find("a", href=re.compile(r"/detail"))
            if not link:
                continue
            href = link.get("href", "")
            # Extract CVE-ID from href or text
            cve_match = re.search(r"CVE-\d{4}-\d+", href + link.get_text())
            if not cve_match:
                continue
            cve_id = cve_match.group(0)
            detail_url = (
                href if href.startswith("http") else urljoin(self.config.base_url, href)
            )
            entries.append(RawAVDEntry(cve_id=cve_id, detail_url=detail_url))
        return entries

    def _has_next_page(self, soup: BeautifulSoup) -> bool:
        """Detect whether a 'next page' link exists on the current list page.

        avd.aliyun.com renders two «下一页 »» links (top and bottom of table),
        both as plain ``<a href="?page=N&pageSize=30">`` (no Bootstrap pagination
        ``<ul class="pagination">``).  The link text contains "下一页" but may
        also include a surrounding "»" character.

        Strategy: look for any ``<a>`` whose text contains "下一页" **and** whose
        href contains ``page=`` pointing to a page > 1.
        """
        for tag in soup.find_all("a", href=True):
            text = tag.get_text(strip=True)
            href = tag["href"]
            if "下一页" in text and "page=" in href:
                # Make sure it's not a disabled / page=0 link
                m = re.search(r"[?&]page=(\d+)", href)
                if m and int(m.group(1)) >= 2:
                    return True
        return False

    # ---- Detail page --------------------------------------------------------

    def _fetch_detail(self, stub: RawAVDEntry) -> RawAVDEntry:
        """Fetch the detail page for *stub* and return an enriched entry."""
        if not stub.detail_url:
            stub.detail_url = self.config.detail_url_template.format(stub.cve_id)

        try:
            soup = self._render(stub.detail_url)
        except Exception as exc:
            logger.error("Failed to fetch detail for %s: %s", stub.cve_id, exc)
            return stub

        return self._parse_detail_page(stub, soup)

    def _parse_detail_page(self, stub: RawAVDEntry, soup: BeautifulSoup) -> RawAVDEntry:
        """Enrich *stub* with data parsed from the rendered detail page HTML.

        Selectors are derived from the live avd.aliyun.com/detail page structure::

            .metric                         → key-value pairs (CVE编号, 披露时间, …)
            .badge                          → severity badge text (高危/中危/…)
            .header__title__text            → vuln title
            h6:contains("漏洞描述") + div   → description body
            div.cvss-breakdown__score       → CVSS numeric score
            table thead h6:contains("参考链接") → references table tbody a[href]
            table: CWE-ID column            → CWE id + human name
        """

        # ---- Metrics block (CVE编号, 利用情况, 补丁情况, 披露时间) -------------
        for metric in soup.select(".metric"):
            label_el = metric.select_one(".metric-label")
            value_el = metric.select_one(".metric-value")
            if not label_el or not value_el:
                continue
            label = label_el.get_text(strip=True)
            value = value_el.get_text(strip=True)
            if "披露时间" in label:
                dt = _parse_date(value)
                if dt and not stub.modified_date:
                    stub.modified_date = dt
                if dt and not stub.published_date:
                    stub.published_date = dt

        # ---- Severity badge -------------------------------------------------
        badge = soup.select_one(".badge")
        if badge and not stub.severity:
            stub.severity = badge.get_text(strip=True)

        # ---- Title ----------------------------------------------------------
        title_el = soup.select_one(".header__title__text")
        if title_el and not stub.title:
            stub.title = title_el.get_text(strip=True)

        # ---- Description ----------------------------------------------------
        desc_h6 = soup.find("h6", string=lambda t: t and "漏洞描述" in t)
        if desc_h6:
            desc_div = desc_h6.find_next_sibling()
            if desc_div:
                stub.description = desc_div.get_text(separator=" ", strip=True)

        # ---- CVSS numeric score ---------------------------------------------
        score_el = soup.find(
            "div",
            class_=lambda c: (
                c and "cvss-breakdown__score" in " ".join(c) if c else False
            ),
        )
        if score_el and stub.cvss_score is None:
            try:
                stub.cvss_score = float(score_el.get_text(strip=True))
            except ValueError:
                pass

        # ---- CWE (table where one row starts with "CWE-ID") -----------------
        # The browser may wrap each <tr> in its own <tbody>, so
        # find_next_sibling("tr") won't work.  We collect all rows from the
        # table and look for the header row by index.
        for table in soup.find_all("table"):
            all_rows = table.find_all("tr")
            for idx, row in enumerate(all_rows):
                cells = row.find_all(["td", "th"])
                if cells and cells[0].get_text(strip=True) == "CWE-ID":
                    if idx + 1 < len(all_rows):
                        data_cells = all_rows[idx + 1].find_all(["td", "th"])
                        if len(data_cells) >= 2:
                            cwe_candidate = data_cells[0].get_text(strip=True)
                            if re.match(r"CWE-\d+", cwe_candidate):
                                stub.cwe_id = cwe_candidate
                                stub.cwe_description = data_cells[1].get_text(
                                    strip=True
                                )
                    break
            else:
                continue
            break

        # ---- References / patch URLs ----------------------------------------
        all_refs: list[str] = []
        refs_h6 = soup.find("h6", string=lambda t: t and "参考链接" in t)
        if refs_h6:
            refs_table = refs_h6.find_parent("table")
            if refs_table:
                for a in refs_table.select("tbody a[href]"):
                    href = a["href"]
                    if href.startswith("http"):
                        all_refs.append(href)

        stub.references = list(dict.fromkeys(all_refs))
        stub.patch_urls = _extract_patch_urls(stub.references)

        return stub
