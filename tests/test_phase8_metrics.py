"""Phase 8: metrics collector + /metrics endpoint."""
import os

from app.metrics.collector import MetricsCollector, _percentile


def test_percentile_basic():
    values = [10, 20, 30, 40, 50]
    assert _percentile(values, 0.0) == 10
    assert _percentile(values, 1.0) == 50
    assert _percentile(values, 0.5) == 30


def test_collector_counts_and_split_latency():
    m = MetricsCollector()
    m.record_request(allowed=True, cache_hit=False, executed=True, latency_ms=50.0, execution_time_ms=10.0)
    m.record_request(allowed=True, cache_hit=True, executed=False, latency_ms=5.0, execution_time_ms=None)
    m.record_request(allowed=False, cache_hit=False, executed=False, latency_ms=2.0, execution_time_ms=None)

    snap = m.snapshot()
    assert snap["requests_total"] == 3
    assert snap["allowed_total"] == 2
    assert snap["blocked_total"] == 1
    assert snap["executed_total"] == 1
    assert snap["cache_hit_latency"]["count"] == 1
    assert snap["cache_miss_latency"]["count"] == 1
    assert snap["query_execution_time"]["count"] == 1


def test_snapshot_includes_cache_metrics_when_provided():
    m = MetricsCollector()
    snap = m.snapshot(cache_metrics={"hits": 5, "misses": 2, "hit_rate": 0.7142})
    assert snap["cache"]["hits"] == 5


# --- API ---
os.environ.setdefault("POSTGRES_HOST", "localhost")
from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def test_metrics_endpoint_shape():
    # Generate some traffic first.
    client.post("/query", json={"sql": "SELECT id FROM users WHERE id = 1", "execute": False})
    client.post("/query", json={"sql": "DROP TABLE users"})
    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "requests_total" in body
    assert "request_latency" in body
    assert "cache_hit_latency" in body
    assert "cache_miss_latency" in body
    assert "cache" in body
    assert body["requests_total"] >= 2
