from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from aliyun_crawler.rawdb.models import RetryRequest
from aliyun_crawler.rawdb.repositories import RawRepository
from aliyun_crawler.rawdb.service import RawIngestService


def create_app(repository: RawRepository, service: RawIngestService) -> FastAPI:
    app = FastAPI(title="Aliyun RawDB API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/raw/{cve_id}")
    def get_raw(cve_id: str):
        item = repository.get_raw(cve_id)
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return item.model_dump()

    @app.get("/raw")
    def query_raw(
        modified_from: str | None = Query(default=None),
        modified_to: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=500),
    ):
        result = repository.query_raw(
            modified_from=modified_from,
            modified_to=modified_to,
            page=page,
            page_size=page_size,
        )
        return result.model_dump(mode="json")

    @app.get("/pages/checkpoints")
    def checkpoints(status: str | None = Query(default=None)):
        return {
            "items": [
                cp.model_dump() for cp in repository.list_checkpoints(status=status)
            ],
            "meta": repository.get_meta().model_dump(),
        }

    @app.get("/pages/gaps")
    def gaps(
        max_page: int = Query(..., ge=1), include_failed: bool = Query(default=True)
    ):
        return {
            "gaps": [
                g.model_dump()
                for g in repository.get_gaps(
                    max_page=max_page, include_failed=include_failed
                )
            ],
            "meta": repository.get_meta().model_dump(),
        }

    @app.post("/pages/retry")
    def retry(req: RetryRequest):
        result = service.retry_pages(req.pages)
        return result.model_dump()

    @app.post("/crawl/resume")
    def resume(start_page: int | None = Query(default=None, ge=1)):
        result = service.crawl_incremental(start_page=start_page)
        return result.model_dump()

    return app
