from __future__ import annotations

from pathlib import Path

from aliyun_crawler.config import CrawlerSettings
from aliyun_crawler.rawdb.repositories import (
    DualWriteRawRepository,
    FileRawRepository,
    RawRepository,
    SqliteRawRepository,
)


def build_raw_repository(settings: CrawlerSettings) -> RawRepository:
    backend = settings.rawdb_storage_backend.lower()
    data_dir = settings.data_dir
    sqlite_path = settings.rawdb_sqlite_path or str(Path(data_dir) / "raw.db")

    file_repo = FileRawRepository(data_dir=data_dir)
    sqlite_repo = SqliteRawRepository(sqlite_path=sqlite_path)

    if backend == "file":
        return file_repo
    if backend == "sqlite":
        return sqlite_repo
    return DualWriteRawRepository(primary=sqlite_repo, secondary=file_repo)
