"""Phase 4: query normalization + stable cache key. Pure unit tests."""
import pytest

from app.parser.normalizer import CACHE_NAMESPACE, normalize


def test_whitespace_and_case_normalized_to_same_key():
    a = normalize("select   ID , Email  from Users where id = 1")
    b = normalize("SELECT id, email FROM users WHERE id = 1")
    assert a.canonical_sql == b.canonical_sql
    assert a.cache_key == b.cache_key


def test_literal_differences_share_fingerprint_and_key():
    a = normalize("SELECT id FROM users WHERE id = 1")
    b = normalize("SELECT id FROM users WHERE id = 2")
    # Canonical differs (literals preserved) ...
    assert a.canonical_sql != b.canonical_sql
    # ... but fingerprint and analysis cache key are the same.
    assert a.fingerprint == b.fingerprint
    assert a.cache_key == b.cache_key


def test_structurally_different_queries_have_different_keys():
    a = normalize("SELECT id FROM users WHERE id = 1")
    b = normalize("SELECT id FROM orders WHERE id = 1")
    assert a.cache_key != b.cache_key


def test_cache_key_is_stable_and_namespaced():
    a = normalize("SELECT id FROM users WHERE id = 1")
    b = normalize("SELECT id FROM users WHERE id = 1")
    assert a.cache_key == b.cache_key
    assert a.cache_key.startswith(f"{CACHE_NAMESPACE}:")


def test_fingerprint_replaces_all_literals():
    n = normalize("SELECT id FROM users WHERE id = 999 AND country = 'US'")
    assert "999" not in n.fingerprint
    assert "US" not in n.fingerprint


def test_unparseable_raises():
    # Normalization runs only on SQL already validated by the security engine.
    # A structurally invalid statement still raises defensively.
    with pytest.raises(ValueError):
        normalize("SELECT FROM")
