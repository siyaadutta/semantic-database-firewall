"""Redis analysis cache (project-instructions.md §8, §11).

Caches the expensive part of the pipeline (query-plan analysis + LLM advisory)
keyed by the normalized query fingerprint. Repeated analysis of structurally
identical queries is served from cache, avoiding EXPLAIN re-runs and — most
importantly — avoiding LLM API calls.

Provides:
- get / set with TTL
- invalidation (single key and namespace-wide)
- hit/miss/set counters for metrics
- advisory_computations_avoided: cache hits on entries that carried any
  advisory (the analysis/advisory work that was skipped).
- llm_calls_avoided: cache hits on entries whose advisory was actually produced
  by the LLM (source == "llm"). This stays 0 when the LLM is disabled and the
  deterministic fallback advisory is used, so it is never overstated.

An in-memory fallback backend is used when Redis is unavailable so that unit
tests do not require a running Redis. The Redis backend is used in integration
tests and at runtime.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

import redis

from app.config import get_settings
from app.parser.normalizer import CACHE_NAMESPACE


@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    sets: int = 0
    # Cache hits on entries that contained ANY advisory (LLM or deterministic
    # fallback). This is the advisory/analysis recomputation that was avoided.
    advisory_computations_avoided: int = 0
    # Cache hits on entries whose advisory was actually produced by the LLM
    # (source == "llm"). This is the ONLY truthful "LLM API calls avoided"
    # count; it stays 0 when the LLM is disabled and the fallback is used.
    llm_calls_avoided: int = 0

    @property
    def total_lookups(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total_lookups if self.total_lookups else 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "advisory_computations_avoided": self.advisory_computations_avoided,
            "llm_calls_avoided": self.llm_calls_avoided,
            "total_lookups": self.total_lookups,
            "hit_rate": round(self.hit_rate, 4),
        }

    def reset(self) -> None:
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.advisory_computations_avoided = 0
        self.llm_calls_avoided = 0


class CacheBackend(Protocol):
    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def delete(self, key: str) -> int: ...
    def delete_namespace(self, namespace: str) -> int: ...
    def ping(self) -> bool: ...


class InMemoryBackend:
    """Thread-safe in-memory backend with TTL, used as a fallback for tests."""

    def __init__(self) -> None:
        self._store: Dict[str, tuple[str, Optional[float]]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at is not None and time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: str, ttl: int) -> None:
        expires_at = time.time() + ttl if ttl > 0 else None
        with self._lock:
            self._store[key] = (value, expires_at)

    def delete(self, key: str) -> int:
        with self._lock:
            return 1 if self._store.pop(key, None) is not None else 0

    def delete_namespace(self, namespace: str) -> int:
        with self._lock:
            keys = [k for k in self._store if k.startswith(namespace)]
            for k in keys:
                del self._store[k]
            return len(keys)

    def ping(self) -> bool:
        return True


class RedisBackend:
    def __init__(self, client: "redis.Redis") -> None:
        self._client = client

    def get(self, key: str) -> Optional[str]:
        val = self._client.get(key)
        return val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else val

    def set(self, key: str, value: str, ttl: int) -> None:
        if ttl > 0:
            self._client.set(key, value, ex=ttl)
        else:
            self._client.set(key, value)

    def delete(self, key: str) -> int:
        return int(self._client.delete(key))

    def delete_namespace(self, namespace: str) -> int:
        deleted = 0
        for key in self._client.scan_iter(match=f"{namespace}*"):
            deleted += int(self._client.delete(key))
        return deleted

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:  # noqa: BLE001
            return False


class AnalysisCache:
    def __init__(self, backend: Optional[CacheBackend] = None, ttl: Optional[int] = None) -> None:
        settings = get_settings()
        self.ttl = ttl if ttl is not None else settings.cache_ttl_seconds
        self.metrics = CacheMetrics()
        if backend is not None:
            self.backend = backend
        else:
            self.backend = self._build_default_backend()

    @staticmethod
    def _build_default_backend() -> CacheBackend:
        settings = get_settings()
        try:
            client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                socket_connect_timeout=1,
            )
            backend = RedisBackend(client)
            if backend.ping():
                return backend
        except Exception:  # noqa: BLE001
            pass
        # Fallback keeps the app functional without Redis (degraded, no shared cache).
        return InMemoryBackend()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        raw = self.backend.get(key)
        if raw is None:
            self.metrics.misses += 1
            return None
        self.metrics.hits += 1
        payload = json.loads(raw)
        # A cache hit on an entry that carried an advisory means we avoided
        # recomputing that advisory (EXPLAIN + advisory generation).
        advisory = payload.get("advisory")
        if advisory is not None:
            self.metrics.advisory_computations_avoided += 1
            # Only count a real LLM API call as avoided when the cached advisory
            # was actually produced by the LLM. When the LLM is disabled the
            # fallback advisory has source != "llm", so this stays 0 — truthful.
            if isinstance(advisory, dict) and advisory.get("source") == "llm":
                self.metrics.llm_calls_avoided += 1
        return payload

    def set(self, key: str, value: Dict[str, Any]) -> None:
        self.backend.set(key, json.dumps(value, default=str), self.ttl)
        self.metrics.sets += 1

    def invalidate(self, key: str) -> int:
        return self.backend.delete(key)

    def invalidate_all(self) -> int:
        """Invalidate every entry in the analysis namespace."""
        return self.backend.delete_namespace(CACHE_NAMESPACE)


_cache: Optional[AnalysisCache] = None


def get_cache() -> AnalysisCache:
    global _cache
    if _cache is None:
        _cache = AnalysisCache()
    return _cache
