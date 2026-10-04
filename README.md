# Semantic Database Firewall & Query Optimizer

A database middleware proxy that sits between an application and PostgreSQL. It
receives SQL over a REST API, enforces **deterministic** security policies,
analyzes PostgreSQL query plans, uses an **LLM as an advisory layer** for
optimization recommendations, caches analysis in Redis, and can execute approved
queries — returning a clear verdict for every request.

> **Architectural principle:** the LLM is **never** the security authority.
> All security-critical decisions are deterministic (SQL parsing + explicit
> policy rules). The LLM only explains and recommends; any SQL it suggests is
> treated as untrusted text and re-validated by the deterministic engine — it is
> never auto-executed.

The full engineering specification is in
[`.kiro/steering/project-instructions.md`](.kiro/steering/project-instructions.md),
which is the source of truth for this project.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture](#architecture)
- [Request Flow](#request-flow)
- [Security Model](#security-model)
- [Query Optimization Flow](#query-optimization-flow)
- [Redis Caching Strategy](#redis-caching-strategy)
- [The LLM's Role](#the-llms-role)
- [Database Schema](#database-schema)
- [API](#api)
- [Example Requests & Responses](#example-requests--responses)
- [Example Before/After Query Plans](#example-beforeafter-query-plans)
- [Benchmark Methodology & Results](#benchmark-methodology--results)
- [Test Strategy](#test-strategy)
- [Setup & Run](#setup--run)
- [Limitations](#limitations)
- [Technologies Actually Used](#technologies-actually-used)

---

## Problem Statement

Applications frequently send SQL that is dangerous (accidental `DROP`/`TRUNCATE`,
unfiltered bulk writes, injection attempts) or inefficient (sequential scans on
large unindexed columns). Reviewing every query by hand does not scale. This
project provides a middleware proxy that:

1. **Blocks** dangerous SQL deterministically, before it reaches the database.
2. **Analyzes** the plan of safe queries and surfaces performance
   recommendations (e.g. a missing index).
3. **Explains** issues in human-readable form via an advisory LLM.
4. **Caches** analysis so repeated queries avoid recomputation and LLM calls.

## Architecture

Clean modular monolith. Each module has one responsibility.

```
Client
  │
  ▼
FastAPI API (app/api)
  │
  ▼
SQL Parser (app/parser/sql_parser.py — sqlglot)      reject malformed / multi-statement
  │
  ▼
Deterministic Security Policy Engine (app/security)  AUTHORITATIVE allow/block
  │
  ▼
Normalization (app/parser/normalizer.py)             canonical form + stable cache key
  │
  ▼
Redis Cache (app/cache)                              hit → return cached analysis
  │
  ▼
EXPLAIN / Plan Analysis (app/database + app/optimizer)
  │
  ▼
LLM Advisory Optimizer (app/llm)                     advisory JSON, never authoritative
  │
  ▼
Validated Query Execution (app/database)             only if approved
  │
  ▼
Metrics / Audit Result (app/metrics)
```

Module map:

| Module | Responsibility |
|--------|----------------|
| `app/api` | HTTP surface (FastAPI routers). No business logic. |
| `app/parser` | `sql_parser.py` (sqlglot AST, malformed/multi-statement detection) + `normalizer.py` (canonical form, fingerprint, cache key). |
| `app/security` | Deterministic policy engine. Parser-based (authoritative) + heuristic (labeled) rules. |
| `app/database` | psycopg3 connection pool, `EXPLAIN (FORMAT JSON)`, query execution with timing. |
| `app/optimizer` | Query-plan analysis and index recommendations. |
| `app/cache` | Redis analysis cache with in-memory fallback, TTL, invalidation, metrics. |
| `app/llm` | LLM advisory client: structured JSON, graceful fallback, rewrite re-validation. |
| `app/metrics` | Thread-safe request/latency/cache metrics. |
| `app/models` | Pydantic request/response contracts. |
| `app/services` | Orchestrates the pipeline. |

## Request Flow

1. **Parse & validate** — `sqlglot` parses the SQL. Malformed SQL and multiple
   statements are detected here.
2. **Security (authoritative)** — the deterministic engine returns
   `{allowed, reason, rule, severity}`. If blocked, the pipeline stops and
   returns `status: "blocked"`.
3. **Normalize** — the query is canonicalized and a stable cache key is derived
   from a literal-agnostic fingerprint.
4. **Cache lookup** — on hit, the cached analysis + advisory are returned
   (`cache_hit: true`) and no EXPLAIN/LLM work is done.
5. **EXPLAIN & analyze** — on miss, `EXPLAIN (FORMAT JSON)` is run and the plan
   analyzed for performance concerns.
6. **LLM advisory** — an advisory is produced (LLM if enabled, deterministic
   fallback otherwise) and cached alongside the analysis.
7. **Execute** — only if the request asked to execute and the query is allowed.
8. **Metrics** — every request is recorded.

## Security Model

The security engine (`app/security/engine.py`) evaluates **ordered rules**.
Parser-based rules are **authoritative**; heuristic rules are **clearly labeled**
and are explicitly *not* treated as a complete injection defense.

**Write posture (default: read-only).** By default `read_only_mode=True`, so the
firewall behaves as a **read-only proxy**: any data-modifying statement is
blocked. Set `read_only_mode=False` to allow writes (still subject to the
unfiltered-write rule). Write detection scans the **entire AST**, so a write
hidden inside a CTE — e.g. `WITH d AS (DELETE ... RETURNING ...) SELECT ...`,
whose top-level statement type is `SELECT` — is still caught.

**Read-side protection.** Read-only mode blocks *writes*, but a read-only
connection can still exfiltrate data through server-side functions and system
catalogs. The `dangerous_function` and `system_catalog` rules (on by default via
`block_dangerous_functions`) block file/OS/large-object/remote functions and
reads of `pg_catalog`/`information_schema`/`pg_*` metadata — **independently of
the `SELECT *` rule**, so disabling `restrict_select_star` does not reopen them.

**Parser-based (authoritative) rules**

| Rule | Blocks | Severity |
|------|--------|----------|
| `multi_statement` | more than one statement | CRITICAL |
| `blocked_operations` | `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE` (configurable) | CRITICAL |
| `admin_operations` | other DDL/admin (`CREATE`, `SET`, `VACUUM`, `COPY`, …) | HIGH |
| `read_only` | any `INSERT`/`UPDATE`/`DELETE`/`MERGE` anywhere in the AST (when `read_only_mode`) | HIGH |
| `dangerous_function` | server-side file/OS/large-object/remote functions (`pg_read_file`, `pg_ls_dir`, `pg_read_binary_file`, `lo_import`/`lo_export`, `dblink*`, `current_setting`, …) | CRITICAL |
| `system_catalog` | reads of system catalogs / metadata (`pg_catalog.*`, `information_schema.*`, `pg_*` tables like `pg_stat_activity`) | HIGH |
| `blocked_tables` | access to configured tables (recurses into CTEs/subqueries; ignores CTE aliases) | HIGH |
| `unfiltered_write` | `DELETE`/`UPDATE` without `WHERE`, anywhere in the AST (when writes allowed) | HIGH |
| `select_star` | bare `SELECT *` (COUNT(*) allowed) | LOW |
| `unparseable_sql` | SQL that cannot be parsed | HIGH |

**Heuristic (labeled, not a complete defense)**

`injection_heuristics` flags classic markers: tautologies where both operands
are **identical** (`OR 1=1`, `OR 'a'='a'`, `OR a=a` — but not legitimate
`OR user_id=5 OR user_id=6`), comment terminators `--`, `UNION SELECT` probes,
stacked-query markers, and `pg_sleep`. To reduce false positives, the regexes
run over the SQL with **string-literal contents removed** (via the AST), so a
marker that appears only inside a quoted value — e.g. `WHERE name = 'a--b'` — is
treated as data and not flagged, while a genuine trailing `-- comment` outside
any literal still is. These complement — not replace — the authoritative
parser-based rules.

Note on parameterization: the `/query` API accepts a full SQL string and does
not expose separate query parameters, so it does **not** perform parameterized
execution of user-supplied values. The demonstrated protections are therefore
the deterministic parser-based rules above plus the configurable row-return
limit — not prepared-statement parameter binding.

Structured result returned for every query:

```json
{ "allowed": false, "reason": "...", "rule": "blocked_operation:DROP", "severity": "CRITICAL" }
```

## Query Optimization Flow

`app/optimizer/analyzer.py` walks the `EXPLAIN (FORMAT JSON)` tree and records
node types, sequential scans, index scans, and estimated cost.

**It does not claim every sequential scan is bad.** A `Seq Scan` node's
`Plan Rows` reflects *post-filter output*, not rows scanned, so the analyzer
uses the node's **estimated total cost** as the "large scan" signal. It flags a
sequential scan only when it has a **filter** *and* an estimated cost above a
configurable threshold — the case where an index on the filtered column would
likely help. Every finding is explicitly labeled a **recommendation**.

## Redis Caching Strategy

- **Key:** `analysis:v1:<sha256(fingerprint)>`, where the *fingerprint* is the
  normalized SQL with literal values replaced by placeholders. Queries that
  differ only in literal values (`WHERE id = 1` vs `WHERE id = 2`) share a key,
  because their plan shape and analysis are the same.
- **Value:** the plan analysis **and** the LLM advisory, together.
- **TTL:** configurable (`CACHE_TTL_SECONDS`, default 300s).
- **Invalidation:** single key, or namespace-wide (`invalidate_all` / bump
  `CACHE_NAMESPACE`). Exposed for benchmarking via `POST /admin/cache/flush`.
- **Metrics:** hits, misses, hit rate, `advisory_computations_avoided` (cache
  hits on entries that carried any advisory — the analysis/advisory work
  skipped), and `llm_calls_avoided` (cache hits on entries whose advisory was
  actually produced by the LLM, i.e. `source == "llm"`). When the LLM is
  disabled and the deterministic fallback is used, `llm_calls_avoided` is
  truthfully `0` while `advisory_computations_avoided` reflects the work saved.
- **Fallback:** if Redis is unreachable, an in-memory backend keeps the app
  functional (degraded, no shared cache).

## The LLM's Role

Advisory only (`app/llm/advisor.py`). It receives the normalized SQL, schema
context, plan summary, and detected concerns, and returns **structured JSON**:
`risk_assessment`, `performance_assessment`, `explanation`,
`optimization_recommendation`, `suggested_index`, `suggested_rewrite`.

Guarantees:

- **Never a security authority.** It cannot allow/block queries.
- **Never executes SQL.** A `suggested_rewrite` is re-validated by the
  deterministic engine (`rewrite_validation`) and surfaced to a human; it is
  never auto-run. (A rewrite of `DROP TABLE ...` comes back `allowed: false`.)
- **Graceful fallback.** If the LLM is disabled, missing a key, times out,
  errors, or returns invalid JSON, a deterministic advisory is produced from the
  plan analysis (`source: "fallback"`). The advisory call never raises.

Set `LLM_ENABLED=true` and `LLM_API_KEY=...` to use a real OpenAI-compatible
endpoint. Left disabled by default so the system is fully functional offline.

## Database Schema

Reproducible sample DB (`db/01_schema.sql`, `db/02_seed.sql`), seeded on first
`docker compose up`:

| Table | Rows | Notes |
|-------|------|-------|
| `users` | 100,000 | `email`, `country` **unindexed** (seq-scan demo) |
| `products` | 5,000 | `category`, `price_cents` unindexed |
| `orders` | 300,000 | `user_id` **indexed** (index-scan demo); `status` unindexed |
| `transactions` | 600,000 | `order_id` **indexed** |

The mix of indexed and intentionally-unindexed columns is what makes the
optimizer's seq-scan-vs-index-scan recommendations demonstrable.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + DB connectivity. |
| POST | `/query` | Evaluate a SQL query. Body: `{"sql": "...", "execute": true|false}`. |
| GET | `/metrics` | Request + cache metrics snapshot. |
| POST | `/admin/cache/flush` | Invalidate all cached analysis (benchmarking). |
| POST | `/admin/metrics/reset` | Reset in-process metrics (benchmarking). |

## Example Requests & Responses

**Blocked (dangerous operation):**

```bash
curl -s -X POST localhost:8000/query -H 'content-type: application/json' \
  -d '{"sql":"DROP TABLE users"}'
```
```json
{
  "status": "blocked",
  "security": {"allowed": false, "reason": "Operation 'DROP' is blocked by policy.",
               "rule": "blocked_operation:DROP", "severity": "CRITICAL"},
  "executed": false
}
```

**Allowed + optimization recommendation (unindexed lookup, analyze-only):**

```bash
curl -s -X POST localhost:8000/query -H 'content-type: application/json' \
  -d '{"sql":"SELECT id FROM users WHERE email = '\''user5000@example.com'\''","execute":false}'
```
```json
{
  "status": "allowed",
  "security": {"allowed": true, "rule": "allow", "severity": "LOW"},
  "normalized_sql": "SELECT id FROM users WHERE email = 'user5000@example.com'",
  "cache_hit": false,
  "analysis": {
    "seq_scans": ["users"],
    "index_scans": [],
    "issues": [{
      "type": "large_seq_scan_with_filter",
      "severity": "MEDIUM",
      "recommendation": "Consider an index on users(email) ... Recommendation only ..."
    }]
  },
  "advisory": {
    "source": "fallback",
    "suggested_index": "users(email)",
    "performance_assessment": "Detected: large_seq_scan_with_filter ...",
    "optimization_recommendation": "Consider an index on users(email) ..."
  }
}
```

## Example Before/After Query Plans

Real `EXPLAIN ANALYZE` on the seeded DB (the index below was created inside a
transaction and rolled back, so the sample data is unchanged):

**Before — no index on `users.email`:**
```
Seq Scan on users  (cost=0.00..2280.00 rows=1 width=8) (actual time=0.427..6.793 rows=1 loops=1)
Execution Time: 6.830 ms
```

**After — with an index on `users.email`:**
```
Index Scan using tmp_email on users  (cost=0.42..8.44 rows=1 width=8) (actual time=0.048..0.049 rows=1 loops=1)
Execution Time: 0.090 ms
```

The proxy **recommended** the `users(email)` index; PostgreSQL delivers the
speedup. On this 100k-row table the recommended index took the same equality
lookup from a **6.830 ms sequential scan to a 0.090 ms index scan** (a single
`EXPLAIN ANALYZE` measurement in a rolled-back transaction). This is a standard
database-indexing result — the middleware's contribution is *detecting the
missing-index opportunity and recommending it*, not making Postgres faster
itself. State it that way: "recommended an index that yielded a measured
6.830 ms → 0.090 ms lookup improvement," not "the system made queries 75× faster."

## Benchmark Methodology & Results

`benchmarks/benchmark.py` drives the running HTTP API in three phases and
reports **only measured** numbers:

- **Cold phase** — each of 8 structurally-distinct queries once → genuine cache
  **misses**.
- **Warm phase** — 10 repeats per structure (varying literals) → cache **hits**.
- **Concurrent phase** — `--requests` queries across `--concurrency` threads →
  throughput and latency under load.

It reads `/metrics` for cache hit rate and LLM-calls-avoided.

> **This is a synthetic workload, not a realistic traffic model.** It replays a
> small fixed set of 8 query structures many times, so the ~98% hit rate simply
> demonstrates that the cache works and that hits/misses reconcile — it does not
> represent a production hit rate, which depends entirely on real query
> diversity.

```bash
# analyze-only
python benchmarks/benchmark.py --base-url http://localhost:8000 --concurrency 20 --requests 500
# execute mode (measures real query execution time)
python benchmarks/benchmark.py --base-url http://localhost:8000 --concurrency 20 --requests 300 --execute
```

**Measured results on this machine** (LLM disabled → cheap deterministic
fallback; full JSON in `benchmarks/results/`):

*Analyze-only (concurrency 20, 500 concurrent requests; cache + metrics reset first):*

| Metric | Value |
|--------|-------|
| Cache-miss latency (cold, avg) | 3.23 ms |
| Cache-hit latency (warm, avg) | 1.73 ms |
| Concurrent throughput | 287.2 req/s |
| Cache hit rate (synthetic workload) | 98.6 % (580 hits / 8 misses / 588 lookups) |
| Advisory computations avoided (cache hits) | 580 |
| Actual LLM calls avoided | 0 (LLM disabled — deterministic fallback used) |

*Execute mode (concurrency 20, 300 concurrent requests; cache + metrics reset first):*

| Metric | Value |
|--------|-------|
| Query execution time (avg / p50 / p95) | 72.8 / 65.8 / 178.3 ms |
| Cold-miss latency (avg) | 17.2 ms |
| Warm-hit latency (avg) | 11.1 ms |
| Throughput | 81.4 req/s |
| Cache hit rate (synthetic workload) | 97.9 % (380 hits / 8 misses / 388 lookups) |
| Advisory computations avoided (cache hits) | 380 |
| Actual LLM calls avoided | 0 (LLM disabled — deterministic fallback used) |

The counts reconcile exactly: `sets == misses` (one compute per distinct
structure), `hits + misses == total_lookups == requests_total`, and each run's
server metrics are reset beforehand so they belong only to that invocation.

**Honest note:** these benchmarks were run with the **LLM disabled**, so the
deterministic fallback advisory was used and **no LLM API calls occurred** —
`llm_calls_avoided` is therefore truthfully `0`. What the cache demonstrably
avoids here is recomputing the analysis/advisory (`advisory_computations_avoided`
= 380–580 above), plus repeated `EXPLAIN` calls. Because the fallback advisory is
cheap, the cache's latency benefit on the analyze path is modest. When
`LLM_ENABLED=true`, cached advisories carry `source == "llm"`, so a cache hit on
them increments `llm_calls_avoided` and represents a real network round-trip
saved. Numbers are machine-dependent — re-run the script to reproduce.

## Test Strategy

112 tests, one file per phase, run against real Postgres + Redis where relevant;
external LLM calls are mocked via `httpx.MockTransport`.

Coverage: allowed queries, blocked dangerous queries, malformed SQL, multiple
statements, policy enforcement (parser + heuristic), **read-only write posture
(INSERT/UPDATE/DELETE blocked by default), data-modifying-CTE detection, dangerous-function & system-catalog denylists, and
injection markers inside string literals not being false-flagged**, query
normalization & stable keys, cache hit/miss/TTL/invalidation, row-limit
enforcement, PostgreSQL plan analysis, LLM structured-response parsing,
LLM failure/fallback, rewrite re-validation, API validation, concurrent
requests, and benchmark helpers.

```bash
pytest -q
```

## Setup & Run

**Option A — Docker Compose (Postgres + Redis + app):**
```bash
docker compose up --build          # app on http://localhost:8000
docker compose up -d postgres redis # or just the datastores
```

**Option B — run the app locally against compose datastores:**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d postgres redis
POSTGRES_HOST=localhost REDIS_HOST=localhost uvicorn app.main:app --port 8000
```

**Commands:**
```bash
# run tests
pytest -q
# run benchmarks (server must be up)
python benchmarks/benchmark.py --base-url http://localhost:8000 --concurrency 20 --requests 500
python benchmarks/benchmark.py --base-url http://localhost:8000 --concurrency 20 --requests 300 --execute
```

Configuration is via environment variables (see `.env.example`).

## Limitations

- **Not a complete SQL-injection defense.** Heuristics are labeled as such and
  run over the SQL with string-literal contents removed (so markers inside
  quoted values are not false-flagged), but they remain simple regexes. The
  tautology check now requires identical operands (no longer flags legitimate
  `OR a=5 OR a=6`), but a legitimate analytics `UNION SELECT` is still flagged
  by `union_probe` — a deliberately conservative, clearly-secondary tradeoff.
  The real, implemented protections are the deterministic parser-based rules
  (single-statement enforcement, read-only write posture, dangerous-function and
  system-catalog denylists, statement-type/table policy, unparseable rejection)
  and the configurable row-return limit.
- **Read-side denylist is a denylist, not an allowlist.** Dangerous functions
  and system catalogs are blocked by explicit lists (`dangerous_functions`,
  `blocked_schemas`, `system_table_prefixes`). This closes the well-known
  file/OS/catalog exfiltration vectors, but a denylist can never be exhaustive;
  a strict allowlist of permitted functions/schemas would be stronger for a
  hardened deployment.
- **`/query` accepts raw SQL** and does **not** perform parameterized
  (prepared-statement) binding of user values.
- **Write posture is deliberate, not accidental.** The default is read-only
  (`read_only_mode=True`): all INSERT/UPDATE/DELETE/MERGE are blocked, including
  writes hidden inside CTEs/subqueries. Enabling writes (`read_only_mode=False`)
  still blocks unfiltered bulk writes. The unfiltered-write check treats a WHERE
  anywhere in the statement as "filtered," which is a conservative simplification
  (a WHERE that lives only in a subquery would still pass).
- **No cache stampede protection.** On a cache miss there is no per-key lock, so
  N concurrent identical misses each run EXPLAIN (and, if enabled, the LLM call).
- **Single-node, in-process metrics.** Metrics reset on restart; no Prometheus.
- **Cache key is the normalized query structure/fingerprint** (literals replaced
  by placeholders), not the data. PostgreSQL's actual plan selection can depend
  on table statistics, data distribution, and the *selectivity of specific
  literal values*, which the fingerprint deliberately abstracts away. A cached
  analysis can therefore become stale relative to the live plan if statistics or
  data distribution change; entries expire via the configurable TTL
  (`CACHE_TTL_SECONDS`, default 300s) and can be flushed via
  `POST /admin/cache/flush`.
- **Read-optimized.** Writes are supported but the analysis/EXPLAIN path targets
  read queries; execution has no automatic statement timeout configured.
- **LLM advisory quality depends on the model**; the system is intentionally
  usable with the LLM disabled.
- **Benchmarks are machine-dependent** and are for demonstration, not
  production capacity planning.

This project does **not** claim production deployment, multi-tenant scale, or
formal security guarantees.

## Technologies Actually Used

Python 3.11+, FastAPI, Uvicorn, Pydantic v2 + pydantic-settings, PostgreSQL
(psycopg 3 + psycopg-pool), Redis (redis-py), sqlglot (SQL parsing &
normalization), httpx (LLM client + benchmark driver), pytest, Docker &
Docker Compose, Git.
