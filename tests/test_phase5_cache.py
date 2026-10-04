"""Phase 5: Redis caching — hit/miss/TTL/invalidation + metrics."""
import os
import time

import pytest

from app.cache.cache import AnalysisCache, InMemoryBackend, RedisBackend
from app.parser.normalizer import CACHE_NAMESPACE, normalize


def make_cache(ttl=300):
    return AnalysisCache(backend=InMemoryBackend(), ttl=ttl)


def test_miss_then_hit():
    c = make_cache()
    key = normalize("SELECT id FROM users WHERE id = 1").cache_key
    assert c.get(key) is None
    assert c.metrics.misses == 1
    c.set(key, {"analysis": {"ok": True}})
    got = c.get(key)
    assert got == {"analysis": {"ok": True}}
    assert c.metrics.hits == 1


def test_hit_rate_metric():
    c = make_cache()
    key = "analysis:v1:abc"
    c.get(key)          # miss
    c.set(key, {"x": 1})
    c.get(key)          # hit
    c.get(key)          # hit
    assert c.metrics.hits == 2
    assert c.metrics.misses == 1
    assert abs(c.metrics.hit_rate - (2 / 3)) < 1e-9


def test_advisory_and_llm_avoidance_counters():
    c = make_cache()
    # Fallback advisory (source != "llm"): counts as advisory work avoided but
    # NOT as an LLM call avoided.
    fb = "analysis:v1:fallback"
    c.set(fb, {"analysis": {}, "advisory": {"explanation": "x", "source": "fallback"}})
    c.get(fb)
    c.get(fb)
    assert c.metrics.advisory_computations_avoided == 2
    assert c.metrics.llm_calls_avoided == 0

    # Real LLM advisory (source == "llm"): counts as both.
    llm = "analysis:v1:withllm"
    c.set(llm, {"analysis": {}, "advisory": {"explanation": "x", "source": "llm"}})
    c.get(llm)
    assert c.metrics.advisory_computations_avoided == 3
    assert c.metrics.llm_calls_avoided == 1


def test_ttl_expiry():
    c = make_cache(ttl=1)
    key = "analysis:v1:ttl"
    c.set(key, {"x": 1})
    assert c.get(key) is not None
    time.sleep(1.1)
    assert c.get(key) is None


def test_invalidate_single_key():
    c = make_cache()
    key = "analysis:v1:one"
    c.set(key, {"x": 1})
    assert c.invalidate(key) == 1
    assert c.get(key) is None


def test_invalidate_namespace():
    c = make_cache()
    c.set(f"{CACHE_NAMESPACE}:a", {"x": 1})
    c.set(f"{CACHE_NAMESPACE}:b", {"x": 2})
    removed = c.invalidate_all()
    assert removed == 2


# --- Integration test against real Redis (docker compose) -------------------

def _redis_available() -> bool:
    try:
        import redis

        client = redis.Redis(host=os.environ.get("REDIS_HOST", "localhost"), port=6379, socket_connect_timeout=1)
        return bool(client.ping())
    except Exception:
        return False


@pytest.mark.skipif(not _redis_available(), reason="Redis not available")
def test_real_redis_roundtrip_and_ttl():
    import redis

    client = redis.Redis(host=os.environ.get("REDIS_HOST", "localhost"), port=6379)
    c = AnalysisCache(backend=RedisBackend(client), ttl=2)
    key = "analysis:v1:integration-test"
    c.invalidate(key)
    assert c.get(key) is None            # miss
    c.set(key, {"analysis": {"real": True}})
    assert c.get(key) == {"analysis": {"real": True}}  # hit
    time.sleep(2.2)
    assert c.get(key) is None            # expired
    c.invalidate(key)
