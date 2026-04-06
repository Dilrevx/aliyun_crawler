from __future__ import annotations

import argparse
import json

import uvicorn

from aliyun_crawler.config import CrawlerSettings
from aliyun_crawler.rawdb.api import create_app
from aliyun_crawler.rawdb.factory import build_raw_repository
from aliyun_crawler.rawdb.service import RawIngestService


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aliyun RawDB tools")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="run incremental crawl into RawDB")
    crawl.add_argument("--start-page", type=int, default=None)

    retry = sub.add_parser("retry", help="retry explicit pages")
    retry.add_argument("--pages", nargs="+", type=int, required=True)

    gaps = sub.add_parser("gaps", help="show missing/failed page segments")
    gaps.add_argument("--max-page", type=int, required=True)
    gaps.add_argument("--exclude-failed", action="store_true")

    sub.add_parser("api", help="start FastAPI service")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    settings = CrawlerSettings()
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
            max_page=args.max_page,
            include_failed=not args.exclude_failed,
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


if __name__ == "__main__":
    main()
