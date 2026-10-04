"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.database.db import get_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = get_db()
    try:
        db.connect()
    except Exception:
        # Allow the app to start even if DB is briefly unavailable; /health reports it.
        pass
    yield
    db.close()


app = FastAPI(
    title="Semantic Database Firewall & Query Optimizer",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(router)
