from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

import uvicorn

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.ingest_service import RawIngestService
from vulndb_mirror.storage.repository_factory import build_raw_repository


def _setup_logging(log_dir: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        handlers.append(
            logging.FileHandler(
                log_path / f"{timestamp}-crawler.log",
                encoding="utf-8",
                delay=True,
            )
        )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aliyun crawler tools")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="run incremental crawl into raw storage")
    crawl.add_argument("--start-page", type=int, default=None)

    retry = sub.add_parser("retry", help="retry explicit pages")
    retry.add_argument("--pages", nargs="+", type=int, required=True)

    sub.add_parser("gaps", help="show missing/failed page segments")
    sub.add_parser("api", help="start FastAPI service")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    settings = CrawlerSettings()
    _setup_logging(settings.log_dir)
    repository = build_raw_repository(settings)
    service = RawIngestService(settings.to_crawl_config(), repository)

    if args.command == "crawl":
        result = service.crawl_incremental(start_page=args.start_page)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "retry":
        result = service.retry_pages(args.pages)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "gaps":
        gap_items = repository.get_gaps(
            max_page=settings.max_pages,
            include_failed=True,
        )
        print(
            json.dumps(
                {
                    "meta": repository.get_meta().model_dump(),
                    "gaps": [g.model_dump() for g in gap_items],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    app = create_app(repository, service)
    uvicorn.run(
        app,
        host=settings.rawdb_api_host,
        port=settings.rawdb_api_port,
        log_level="info",
    )
