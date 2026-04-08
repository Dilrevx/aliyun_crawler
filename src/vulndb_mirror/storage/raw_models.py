from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

from vulndb_mirror.models import RawAVDEntry


class PageCheckpoint(BaseModel):
    page: int = Field(..., ge=1)
    status: Literal["ok", "failed", "running"] = "ok"
    entry_count: int = Field(default=0, ge=0)
    has_next: bool = False
    error: Optional[str] = None
    updated_at: str


class PageGap(BaseModel):
    start_page: int = Field(..., ge=1)
    end_page: int = Field(..., ge=1)
    reason: Literal["missing", "failed"]


class RawQueryResult(BaseModel):
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    total: int = Field(..., ge=0)
    items: list[RawAVDEntry]


class RetryRequest(BaseModel):
    pages: list[int] = Field(default_factory=list)


class RetryResult(BaseModel):
    requested_pages: list[int]
    succeeded_pages: list[int]
    failed_pages: list[int]
    saved_entries: int = 0


class CrawlRunResult(BaseModel):
    start_page: int = Field(..., ge=1)
    last_page: int = Field(..., ge=1)
    saved_entries: int = Field(..., ge=0)
    stopped_by_since: bool = False
    executed_pages: list[int] = Field(default_factory=list)
    failed_pages: list[int] = Field(default_factory=list)


class RawMeta(BaseModel):
    updated_at: str
    last_seen_date: Optional[str] = None
    last_seen_cve: Optional[str] = None
    resumable_from_page: int = 1


class PageRangeQuery(BaseModel):
    max_page: int = Field(..., ge=1)
    include_failed: bool = True


def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
