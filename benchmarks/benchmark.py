#!/usr/bin/env python3
"""Reproducible benchmark for the Semantic Database Firewall & Query Optimizer.

Measures (project-instructions.md §11), from REAL measured output only:
- request latency (overall)
- cache-miss latency (first time a structural query is seen)
- cache-hit latency (repeat structural queries)
- query execution time (from the API response)
- throughput under concurrent requests
- cache hit rate (from /metrics)
- number of LLM calls avoided through caching (from /metrics)

The script does NOT fabricate numbers. It drives the running HTTP API and
reports whatever it observes. Requires the app + Postgres + Redis to be up
(e.g. `docker compose up` or a locally-run uvicorn).

Usage:
    python benchmarks/benchmark.py --base-url http://localhost:8000 \
        --concurrency 20 --requests 500

Results are printed as a table and optionally written to JSON via --out.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import httpx

# Structurally-distinct query templates. Each {c}/{n} substitution that changes
# a COLUMN or TABLE produces a DIFFERENT cache fingerprint (a genuine miss the
# first time); repeating the same structure with a different literal is a HIT.
STRUCTURAL_TEMPLATES = [
    "SELECT id FROM users WHERE email = 'user{n}@example.com'",
    "SELECT id FROM users WHERE country = 'C{n}'",
    "SELECT id, status FROM orders WHERE user_id = {n}",
    "SELECT id FROM orders WHERE status = 'paid' AND total_cents > {n}",
    "SELECT COUNT(*) FROM transactions WHERE order_id = {n}",
    "SELECT id FROM transactions WHERE product_id = {n}",
    "SELECT id FROM products WHERE category = 'cat{n}'",
    "SELECT id FROM products WHERE price_cents > {n}",
]


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def stats(values: List[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "avg_ms": round(statistics.mean(values), 3),
        "p50_ms": round(percentile(values, 0.50), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def reset_server_state(base_url: str) -> None:
    """Flush the analysis cache AND reset in-process metrics so the reported
    server metrics belong ONLY to this benchmark invocation."""
    httpx.post(f"{base_url}/admin/cache/flush", timeout=10.0)
    httpx.post(f"{base_url}/admin/metrics/reset", timeout=10.0)


def one_request(client: httpx.Client, base_url: str, sql: str, execute: bool = False) -> Dict:
    t0 = time.perf_counter()
    resp = client.post(f"{base_url}/query", json={"sql": sql, "execute": execute})
    client_latency_ms = (time.perf_counter() - t0) * 1000.0
    body = resp.json()
    return {
        "status_code": resp.status_code,
        "client_latency_ms": client_latency_ms,
        "server_latency_ms": body.get("latency_ms"),
        "cache_hit": body.get("cache_hit", False),
        "execution_time_ms": body.get("execution_time_ms"),
        "status": body.get("status"),
    }


def run_benchmark(base_url: str, concurrency: int, total_requests: int, execute: bool) -> Dict:
    # Flush cache AND reset metrics so reported server metrics reflect ONLY
    # this benchmark invocation (no contamination from prior runs).
    try:
        reset_server_state(base_url)
    except Exception:  # noqa: BLE001
        pass

    # --- Phase A: COLD (each distinct structure once -> cache miss) ---------
    cold_results: List[Dict] = []
    with httpx.Client(timeout=30.0) as client:
        for tmpl in STRUCTURAL_TEMPLATES:
            cold_results.append(one_request(client, base_url, tmpl.format(n=1), execute))

    # --- Phase B: WARM (repeat same structures, different literals -> hits) -
    warm_results: List[Dict] = []
    with httpx.Client(timeout=30.0) as client:
        for rep in range(2, 12):  # 10 repeats per structure
            for tmpl in STRUCTURAL_TEMPLATES:
                warm_results.append(one_request(client, base_url, tmpl.format(n=rep), execute))

    # --- Phase C: CONCURRENT throughput (mixed workload) --------------------
    workload = [
        STRUCTURAL_TEMPLATES[i % len(STRUCTURAL_TEMPLATES)].format(n=(i // len(STRUCTURAL_TEMPLATES)) + 100)
        for i in range(total_requests)
    ]
    conc_results: List[Dict] = []
    wall_start = time.perf_counter()
    with httpx.Client(timeout=30.0) as client:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(one_request, client, base_url, sql, execute) for sql in workload]
            for fut in as_completed(futures):
                conc_results.append(fut.result())
    wall_elapsed = time.perf_counter() - wall_start

    ok = [r for r in conc_results if r["status_code"] == 200]
    throughput = len(ok) / wall_elapsed if wall_elapsed > 0 else 0.0

    cold_lat = [r["server_latency_ms"] for r in cold_results if r["server_latency_ms"] is not None]
    warm_lat = [r["server_latency_ms"] for r in warm_results if r["server_latency_ms"] is not None]
    conc_lat = [r["client_latency_ms"] for r in ok]
    exec_times = [r["execution_time_ms"] for r in (cold_results + warm_results + ok) if r["execution_time_ms"] is not None]

    with httpx.Client(timeout=10.0) as client:
        server_metrics = client.get(f"{base_url}/metrics").json()

    return {
        "config": {
            "base_url": base_url,
            "concurrency": concurrency,
            "concurrent_requests": total_requests,
            "execute": execute,
            "structural_templates": len(STRUCTURAL_TEMPLATES),
        },
        "cache_miss_latency_ms (cold phase)": stats(cold_lat),
        "cache_hit_latency_ms (warm phase)": stats(warm_lat),
        "concurrent_request_latency_ms": stats(conc_lat),
        "query_execution_time_ms": stats(exec_times),
        "concurrent_wall_time_s": round(wall_elapsed, 4),
        "throughput_rps": round(throughput, 2),
        "successful_concurrent_requests": len(ok),
        "cold_cache_hits": sum(1 for r in cold_results if r["cache_hit"]),
        "cold_cache_misses": sum(1 for r in cold_results if not r["cache_hit"]),
        "warm_cache_hits": sum(1 for r in warm_results if r["cache_hit"]),
        "server_metrics": server_metrics,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the query firewall API.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--execute", action="store_true", help="Execute queries (measure execution time) instead of analyze-only.")
    parser.add_argument("--out", default=None, help="Optional path to write JSON results.")
    args = parser.parse_args()

    report = run_benchmark(args.base_url, args.concurrency, args.requests, args.execute)

    print("\n=== Benchmark Results (measured, not fabricated) ===")
    print(json.dumps(report, indent=2))

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nWrote results to {args.out}")


if __name__ == "__main__":
    main()
