"""Phase 3 (API): security enforcement through the HTTP endpoint."""
import os

from fastapi.testclient import TestClient

os.environ.setdefault("POSTGRES_HOST", "localhost")

from app.main import app  # noqa: E402

client = TestClient(app)


def test_api_blocks_drop():
    resp = client.post("/query", json={"sql": "DROP TABLE users"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "blocked"
    assert body["security"]["allowed"] is False
    assert body["executed"] is False


def test_api_allows_safe_select():
    resp = client.post(
        "/query",
        json={"sql": "SELECT id, email FROM users WHERE id = 1"},
    )
    body = resp.json()
    assert body["status"] == "allowed"
    assert body["security"]["allowed"] is True


def test_api_blocks_multi_statement():
    resp = client.post("/query", json={"sql": "SELECT 1; DROP TABLE users"})
    body = resp.json()
    assert body["status"] == "blocked"
    assert body["security"]["rule"] == "multi_statement"
