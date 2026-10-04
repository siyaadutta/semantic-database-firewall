"""Phase 1: basic FastAPI -> PostgreSQL path.

These are integration tests that require the docker-compose Postgres to be up.
"""
import os

import pytest
from fastapi.testclient import TestClient

# Point at the compose-exposed Postgres on localhost.
os.environ.setdefault("POSTGRES_HOST", "localhost")

from app.main import app  # noqa: E402

client = TestClient(app)


def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] is True


def test_basic_select_executes():
    resp = client.post("/query", json={"sql": "SELECT id, email FROM users ORDER BY id LIMIT 3"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "allowed"
    assert body["executed"] is True
    assert body["row_count"] == 3
    assert body["rows"][0]["email"].endswith("@example.com")
    assert body["execution_time_ms"] is not None


def test_query_request_validation_rejects_empty_sql():
    resp = client.post("/query", json={"sql": ""})
    assert resp.status_code == 422
