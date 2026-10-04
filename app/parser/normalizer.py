"""Query normalization + stable cache-key hashing (project-instructions.md §8).

Two canonical forms are produced:

- `canonical_sql`: whitespace and identifier casing normalized, literals
  preserved. Represents the exact query semantics.
- `fingerprint`: like canonical_sql but with literal values replaced by
  placeholders. Queries that differ only in literal values (e.g.
  `WHERE id = 1` vs `WHERE id = 2`) share a fingerprint because their query
  PLAN SHAPE and analysis are effectively the same. This is what we key the
  analysis cache on, so repeated analysis of structurally-identical queries
  avoids recomputation and LLM calls.

The cache key is a SHA-256 hash of the fingerprint (plus a namespace/version
prefix so the cache can be invalidated wholesale by bumping the version).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

DIALECT = "postgres"
# Bump to invalidate all existing cache entries after an analysis-format change.
CACHE_NAMESPACE = "analysis:v1"


@dataclass
class NormalizedQuery:
    canonical_sql: str
    fingerprint: str
    cache_key: str


def _canonicalize(sql: str) -> str:
    tree = sqlglot.parse_one(sql, read=DIALECT)
    return tree.sql(dialect=DIALECT, normalize=True, pretty=False)


def _fingerprint(sql: str) -> str:
    tree = sqlglot.parse_one(sql, read=DIALECT)
    for literal in list(tree.find_all(exp.Literal)):
        literal.replace(exp.Placeholder())
    return tree.sql(dialect=DIALECT, normalize=True, pretty=False)


def normalize(sql: str) -> NormalizedQuery:
    """Return canonical form, fingerprint, and stable cache key.

    Raises ValueError (via sqlglot ParseError) if the SQL cannot be parsed;
    callers should have already validated parseability via the security engine.
    """
    try:
        canonical = _canonicalize(sql)
        fingerprint = _fingerprint(sql)
    except ParseError as exc:
        raise ValueError(f"Cannot normalize unparseable SQL: {exc}") from exc

    digest = hashlib.sha256(f"{CACHE_NAMESPACE}|{fingerprint}".encode("utf-8")).hexdigest()
    cache_key = f"{CACHE_NAMESPACE}:{digest}"
    return NormalizedQuery(
        canonical_sql=canonical,
        fingerprint=fingerprint,
        cache_key=cache_key,
    )
