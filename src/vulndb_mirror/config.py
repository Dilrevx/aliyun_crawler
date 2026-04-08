"""Crawler configuration – mirrors the CrawlConfig API spec.

Environment variables are loaded from ``.env`` (dev) via pydantic-settings.
All ``CRAWL__*`` keys map to :class:`CrawlerSettings` which wraps
:class:`CrawlConfig` with env-override support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Raw dataclass – matches the API spec exactly
# ---------------------------------------------------------------------------


@dataclass
class CrawlConfig:
    """Crawler runtime parameters (spec-compliant dataclass)."""

    # ---- URLs ---------------------------------------------------------------
    base_url: str = "https://avd.aliyun.com"
    list_url: str = "https://avd.aliyun.com/nvd/list"
    detail_url_template: str = "https://avd.aliyun.com/detail?id={}"

    # ---- Pagination ----------------------------------------------------------
    max_pages: int = 100
    page_size: int = 30
    page_concurrency: int = 4

    # ---- HTTP behaviour ------------------------------------------------------
    delay_range: tuple[float, float] = (1.0, 3.0)
    timeout: int = 30

    # ---- Browser / headless mode --------------------------------------------
    headless: bool = True
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )

    # ---- Storage ------------------------------------------------------------
    data_dir: str = "./data/aliyun_cve"
    cache_ttl: int = 86400  # seconds

    # ---- Incremental crawl --------------------------------------------------
    # ISO-8601 date/datetime string; only entries *after* this date are fetched.
    since: Optional[str] = None

    # ---- GitHub API ---------------------------------------------------------
    github_token: Optional[str] = None  # populated from env via CrawlerSettings


# ---------------------------------------------------------------------------
# Pydantic-settings wrapper – reads .env / environment variables
# ---------------------------------------------------------------------------


class CrawlerSettings(BaseSettings):
    """Environment-configurable wrapper around :class:`CrawlConfig`.

    Create a ``.env`` file (or set env vars) to override defaults::

        MAX_PAGES=5
        GITHUB_TOKEN=ghp_...
        DATA_DIR=./output/aliyun_cve
        SINCE=2024-01-01
        LLM__API_KEY=sk-...
        LLM__MODEL=deepseek-v3.2
        LLM__BASE_URL=https://your-proxy/v1   # optional
    """

    base_url: str = "https://avd.aliyun.com"
    list_url: str = "https://avd.aliyun.com/nvd/list"
    detail_url_template: str = "https://avd.aliyun.com/detail?id={}"

    max_pages: int = 100
    page_size: int = 30
    page_concurrency: int = 4
    delay_range: tuple[float, float] = (1.0, 3.0)
    timeout: int = 30

    headless: bool = True
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )

    data_dir: str = "./output/aliyun_cve"
    cache_ttl: int = 86400

    # RawDB settings
    rawdb_storage_backend: str = Field(
        default="dual",
        description="RawDB backend: file/sqlite/dual",
    )
    rawdb_sqlite_path: Optional[str] = Field(
        default=None,
        description="SQLite file path for RawDB backend",
    )
    rawdb_api_host: str = Field(
        default="127.0.0.1",
        description="RawDB FastAPI bind host",
    )
    rawdb_api_port: int = Field(
        default=8787,
        description="RawDB FastAPI bind port",
    )

    since: Optional[str] = Field(
        default=None, description="ISO date string for incremental crawl"
    )
    github_token: Optional[str] = Field(default=None, description="GitHub API token")

    # LLM settings (re-uses the route-hacker LLM__ variables)
    llm_provider: str = Field(default="openai", alias="LLM__PROVIDER")
    llm_model: str = Field(default="deepseek-v3.2", alias="LLM__MODEL")
    llm_api_key: Optional[str] = Field(default=None, alias="LLM__API_KEY")
    llm_base_url: Optional[str] = Field(default=None, alias="LLM__BASE_URL")

    # Git clone settings
    git_clone_via_ssh: bool = Field(
        default=False,
        description="Use SSH (git@github.com) instead of HTTPS for git clone; faster without proxy",
    )
    git_proxy: Optional[str] = Field(
        default=None,
        description="HTTP/SOCKS proxy for git operations, e.g. socks5://127.0.0.1:1080",
    )

    # Calltrace settings
    calltrace_concurrency: int = Field(
        default=5,
        description="Max simultaneous CVE explorations in explore_many",
    )
    calltrace_max_rounds: int = Field(
        default=4,
        description="Max LLM conversation turns per CVE (1 initial + N-1 file-request rounds)",
    )

    # Logging
    log_dir: Optional[str] = Field(
        default="./logs",
        description="Directory for log files; set empty/unset to disable file logging",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    def to_crawl_config(self) -> CrawlConfig:
        """Convert settings to the spec-compliant :class:`CrawlConfig`."""
        return CrawlConfig(
            base_url=self.base_url,
            list_url=self.list_url,
            detail_url_template=self.detail_url_template,
            max_pages=self.max_pages,
            page_size=self.page_size,
            page_concurrency=self.page_concurrency,
            delay_range=self.delay_range,
            timeout=self.timeout,
            headless=self.headless,
            user_agent=self.user_agent,
            data_dir=self.data_dir,
            cache_ttl=self.cache_ttl,
            since=self.since,
            github_token=self.github_token,
        )
