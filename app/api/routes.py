"""FastAPI routes. HTTP surface only — delegates to services."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.database.db import Database, get_db
from app.cache.cache import get_cache
from app.metrics.collector import get_metrics
from app.models.schemas import QueryRequest, QueryResponse
from app.services.query_service import QueryService

router = APIRouter()


def get_query_service() -> QueryService:
    return QueryService()


@router.get("/health")
def health(db: Database = Depends(get_db)) -> dict:
    try:
        ok = db.ping()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"database unavailable: {exc}") from exc
    return {"status": "ok" if ok else "degraded", "database": ok}


@router.post("/query", response_model=QueryResponse)
def query(
    request: QueryRequest,
    service: QueryService = Depends(get_query_service),
) -> QueryResponse:
    return service.process_query(request)


@router.get("/metrics")
def metrics() -> dict:
    """Expose request + cache metrics (project-instructions.md §8, §11)."""
    return get_metrics().snapshot(cache_metrics=get_cache().metrics.as_dict())


@router.post("/admin/cache/flush")
def flush_cache() -> dict:
    """Invalidate all cached analysis (used for reproducible benchmarking)."""
    removed = get_cache().invalidate_all()
    return {"flushed": removed}


@router.post("/admin/metrics/reset")
def reset_metrics() -> dict:
    """Reset in-process request AND cache metrics (reproducible benchmarking)."""
    get_metrics().reset()
    get_cache().metrics.reset()
    return {"reset": True}
