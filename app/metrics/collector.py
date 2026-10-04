"""Runtime metrics collector (project-instructions.md §8, §11).

Tracks, in-process and thread-safe:
- total requests, allowed / blocked counts
- executed query count
- request latency (overall, and split by cache hit vs miss)
- query execution time
- cache hit rate + LLM calls avoided (sourced from the cache metrics)

These are lightweight aggregates suitable for the /metrics endpoint and for
the benchmark script to read. They are NOT a substitute for a full metrics
system; the spec explicitly excludes heavy infrastructure.
"""
from __future__ import annotations

import threading
from statistics import mean
from typing import Dict, List, Optional


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _latency_stats(values: List[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"count": 0, "avg_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
    return {
        "count": len(values),
        "avg_ms": round(mean(values), 3),
        "p50_ms": round(_percentile(values, 0.50), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "max_ms": round(max(values), 3),
    }


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests_total = 0
        self.allowed_total = 0
        self.blocked_total = 0
        self.executed_total = 0
        self._request_latencies: List[float] = []
        self._cache_hit_latencies: List[float] = []
        self._cache_miss_latencies: List[float] = []
        self._execution_times: List[float] = []

    def record_request(
        self,
        *,
        allowed: bool,
        cache_hit: bool,
        executed: bool,
        latency_ms: float,
        execution_time_ms: Optional[float],
    ) -> None:
        with self._lock:
            self.requests_total += 1
            if allowed:
                self.allowed_total += 1
            else:
                self.blocked_total += 1
            if executed:
                self.executed_total += 1
            self._request_latencies.append(latency_ms)
            # Only allowed queries do analysis, so hit/miss latency is meaningful there.
            if allowed:
                if cache_hit:
                    self._cache_hit_latencies.append(latency_ms)
                else:
                    self._cache_miss_latencies.append(latency_ms)
            if execution_time_ms is not None:
                self._execution_times.append(execution_time_ms)

    def snapshot(self, cache_metrics: Optional[Dict] = None) -> Dict:
        with self._lock:
            data = {
                "requests_total": self.requests_total,
                "allowed_total": self.allowed_total,
                "blocked_total": self.blocked_total,
                "executed_total": self.executed_total,
                "request_latency": _latency_stats(self._request_latencies),
                "cache_hit_latency": _latency_stats(self._cache_hit_latencies),
                "cache_miss_latency": _latency_stats(self._cache_miss_latencies),
                "query_execution_time": _latency_stats(self._execution_times),
            }
        if cache_metrics is not None:
            data["cache"] = cache_metrics
        return data

    def reset(self) -> None:
        with self._lock:
            self.requests_total = 0
            self.allowed_total = 0
            self.blocked_total = 0
            self.executed_total = 0
            self._request_latencies = []
            self._cache_hit_latencies = []
            self._cache_miss_latencies = []
            self._execution_times = []


_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics
