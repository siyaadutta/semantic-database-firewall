"""Row-limit enforcement (Fix 3): AST capping + execution-time hard cap."""
import os

import pytest

from app.optimizer.row_limit import apply_row_limit


# --- Unit: AST-based capping (no DB) ---------------------------------------

def test_injects_limit_when_absent():
    out, action = apply_row_limit("SELECT id FROM users", 100)
    assert action == "injected"
    assert out.strip().upper().endswith("LIMIT 100")


def test_caps_limit_that_exceeds_max():
    out, action = apply_row_limit("SELECT id FROM users LIMIT 5000", 100)
    assert action == "capped"
    assert out.strip().upper().endswith("LIMIT 100")


def test_keeps_smaller_existing_limit():
    out, action = apply_row_limit("SELECT id FROM users LIMIT 5", 100)
    assert action == "kept"
    assert out.strip().upper().endswith("LIMIT 5")


def test_preserves_order_by_when_injecting():
    out, action = apply_row_limit("SELECT id FROM users ORDER BY id", 100)
    assert action == "injected"
    assert "ORDER BY" in out.upper()
    assert out.strip().upper().endswith("LIMIT 100")


def test_non_select_left_untouched():
    out, action = apply_row_limit("DELETE FROM orders WHERE id = 1", 100)
    assert action == "untouched"
    assert "LIMIT" not in out.upper()


def test_zero_or_negative_limit_untouched():
    out, action = apply_row_limit("SELECT id FROM users", 0)
    assert action == "untouched"
    assert out == "SELECT id FROM users"


# --- Integration: real DB enforcement through the API ----------------------

os.environ.setdefault("POSTGRES_HOST", "localhost")
from fastapi.testclient import TestClient  # noqa: E402
from app.config import Settings  # noqa: E402
from app.services.query_service import QueryService  # noqa: E402
from app.models.schemas import QueryRequest  # noqa: E402


def test_execution_respects_row_limit_against_large_table():
    # users has 100k rows; a bare SELECT would return all of them without a cap.
    svc = QueryService(settings=Settings(max_row_limit=25, restrict_select_star=False))
    resp = svc.process_query(QueryRequest(sql="SELECT id FROM users", execute=True))
    assert resp.status == "allowed"
    assert resp.executed is True
    assert resp.row_count == 25  # capped, not 100000


def test_smaller_user_limit_is_respected():
    svc = QueryService(settings=Settings(max_row_limit=1000))
    resp = svc.process_query(QueryRequest(sql="SELECT id FROM users LIMIT 10", execute=True))
    assert resp.row_count == 10
