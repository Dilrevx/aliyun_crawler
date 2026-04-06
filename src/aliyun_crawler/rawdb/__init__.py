"""Raw database module for Aliyun crawler.

Provides storage backends (file/sqlite/dual-write), incremental page
checkpointing, crawl orchestration and FastAPI query surface.
"""

from aliyun_crawler.rawdb.api import create_app
from aliyun_crawler.rawdb.factory import build_raw_repository
from aliyun_crawler.rawdb.models import PageCheckpoint, PageGap, RawQueryResult
from aliyun_crawler.rawdb.repositories import (
    DualWriteRawRepository,
    FileRawRepository,
    RawRepository,
    SqliteRawRepository,
)
from aliyun_crawler.rawdb.service import RawIngestService

__all__ = [
    "RawRepository",
    "FileRawRepository",
    "SqliteRawRepository",
    "DualWriteRawRepository",
    "RawIngestService",
    "PageCheckpoint",
    "PageGap",
    "RawQueryResult",
    "build_raw_repository",
    "create_app",
]
