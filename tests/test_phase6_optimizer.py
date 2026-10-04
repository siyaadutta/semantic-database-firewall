"""Phase 6: EXPLAIN / query-plan analysis + recommendations."""
import os

import pytest

from app.optimizer.analyzer import analyze_plan, plan_summary
from app.models.schemas import Severity

# --- Unit tests on plan JSON (no DB) ---------------------------------------

SMALL_SEQ_SCAN = {
    "Plan": {
        "Node Type": "Seq Scan",
        "Relation Name": "products",
        "Total Cost": 100.0,
        "Plan Rows": 500,
        "Filter": "(category = 'books'::text)",
    }
}

LARGE_SEQ_SCAN_WITH_FILTER = {
    "Plan": {
        "Node Type": "Seq Scan",
        "Relation Name": "users",
        "Total Cost": 2280.0,
        "Plan Rows": 100000,
        "Filter": "(email = 'user5000@example.com'::text)",
    }
}

INDEX_SCAN = {
    "Plan": {
        "Node Type": "Index Scan",
        "Relation Name": "orders",
        "Total Cost": 15.57,
        "Plan Rows": 3,
        "Index Cond": "(user_id = 5000)",
    }
}


def test_small_seq_scan_not_flagged():
    a = analyze_plan(SMALL_SEQ_SCAN)
    assert a.seq_scans == ["products"]
    assert a.issues == []  # small scan is not a problem


def test_large_seq_scan_with_filter_flagged_as_recommendation():
    a = analyze_plan(LARGE_SEQ_SCAN_WITH_FILTER)
    assert a.seq_scans == ["users"]
    assert len(a.issues) == 1
    issue = a.issues[0]
    assert issue.type == "large_seq_scan_with_filter"
    assert issue.severity == Severity.MEDIUM
    # Must suggest an index on the filtered column and be labeled a recommendation.
    assert "users(email)" in issue.recommendation
    assert "recommendation only" in issue.recommendation.lower()


def test_index_scan_recognized_no_issue():
    a = analyze_plan(INDEX_SCAN)
    assert a.index_scans == ["orders"]
    assert a.issues == []


def test_plan_summary_shape():
    a = analyze_plan(LARGE_SEQ_SCAN_WITH_FILTER)
    s = plan_summary(a)
    assert set(s.keys()) == {
        "node_types",
        "total_estimated_cost",
        "seq_scans",
        "index_scans",
        "issues",
    }


# --- Integration through API (real Postgres + Redis) -----------------------

os.environ.setdefault("POSTGRES_HOST", "localhost")
from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app.cache.cache import get_cache  # noqa: E402

client = TestClient(app)


def test_api_returns_seq_scan_recommendation_for_unindexed_lookup():
    # users.email is intentionally unindexed -> large seq scan with filter.
    get_cache().invalidate_all()
    resp = client.post(
        "/query",
        json={"sql": "SELECT id FROM users WHERE email = 'user5000@example.com'", "execute": False},
    )
    body = resp.json()
    assert body["status"] == "allowed"
    assert body["analysis"] is not None
    assert "users" in body["analysis"]["seq_scans"]
    types = [i["type"] for i in body["analysis"]["issues"]]
    assert "large_seq_scan_with_filter" in types


def test_api_indexed_lookup_uses_index_scan_no_issue():
    resp = client.post(
        "/query",
        json={"sql": "SELECT id FROM orders WHERE user_id = 5000", "execute": False},
    )
    body = resp.json()
    assert body["analysis"] is not None
    assert "orders" in body["analysis"]["index_scans"]


def test_api_cache_hit_on_repeat_structural_query():
    get_cache().invalidate_all()
    sql1 = {"sql": "SELECT id FROM users WHERE email = 'user1@example.com'", "execute": False}
    # differ only by literal -> same fingerprint -> should hit cache second time
    sql2 = {"sql": "SELECT id FROM users WHERE email = 'user2@example.com'", "execute": False}
    first = client.post("/query", json=sql1).json()
    second = client.post("/query", json=sql2).json()
    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
