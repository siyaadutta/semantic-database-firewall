"""Phase 9: benchmark functionality (helpers tested without needing load)."""
import importlib.util
import os

# Load the benchmark module by path (it lives outside the app package).
_BENCH_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "benchmark.py")
_spec = importlib.util.spec_from_file_location("benchmark", os.path.abspath(_BENCH_PATH))
benchmark = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(benchmark)


def test_percentile():
    assert benchmark.percentile([10, 20, 30, 40, 50], 0.5) == 30
    assert benchmark.percentile([], 0.5) is None


def test_stats_shape():
    s = benchmark.stats([1.0, 2.0, 3.0])
    assert s["count"] == 3
    assert set(s.keys()) >= {"avg_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"}


def test_structural_templates_are_distinct():
    # Distinct structures produce distinct cache fingerprints (genuine misses).
    tmpls = benchmark.STRUCTURAL_TEMPLATES
    assert len(tmpls) >= 4
    # Formatting the same template with different literals keeps the same
    # column/table structure (a cache hit after the first miss).
    a = tmpls[0].format(n=1)
    b = tmpls[0].format(n=2)
    assert a.split("=")[0] == b.split("=")[0]
    assert a != b


def test_concurrent_requests_handled_correctly():
    """Spec: verify concurrent requests are processed correctly (no crashes,
    consistent verdicts). Uses the in-process TestClient with threads."""
    import concurrent.futures as cf
    import os

    os.environ.setdefault("POSTGRES_HOST", "localhost")
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    def do(i):
        # Mix allowed and blocked queries concurrently.
        if i % 3 == 0:
            r = client.post("/query", json={"sql": "DROP TABLE users"})
            return ("blocked", r.json()["status"])
        r = client.post(
            "/query",
            json={"sql": f"SELECT id FROM orders WHERE user_id = {i}", "execute": False},
        )
        return ("allowed", r.json()["status"])

    with cf.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(do, range(30)))

    for expected, actual in results:
        assert actual == expected
