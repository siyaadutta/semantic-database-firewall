"""Query orchestration service.

Pipeline order follows project-instructions.md §4:
  parse/validate -> security (authoritative) -> normalize -> cache lookup ->
  EXPLAIN plan analysis -> [LLM advisory in phase 7] -> execute (if approved)
  -> metrics.

The expensive analysis (EXPLAIN + later the LLM advisory) is cached in Redis
keyed by the normalized fingerprint, so structurally-identical repeat queries
are served from cache.
"""
from __future__ import annotations

import time
from typing import Optional

from app.cache.cache import AnalysisCache, get_cache
from app.config import Settings, get_settings
from app.database.db import Database, get_db
from app.llm.advisor import LLMAdvisor, get_advisor
from app.metrics.collector import MetricsCollector, get_metrics
from app.models.schemas import LLMAdvisory, PlanAnalysis, QueryRequest, QueryResponse
from app.optimizer.analyzer import analyze_plan
from app.optimizer.row_limit import apply_row_limit
from app.parser.normalizer import normalize
from app.security.engine import SecurityEngine


# Compact schema description passed to the advisory layer (§7).
_SCHEMA_INFO = (
    "users(id PK, email, full_name, country, created_at); "
    "products(id PK, sku, name, category, price_cents, created_at); "
    "orders(id PK, user_id FK->users.id [indexed], status, total_cents, created_at); "
    "transactions(id PK, order_id FK->orders.id [indexed], product_id FK->products.id, "
    "quantity, amount_cents, created_at). "
    "Indexes: orders(user_id), transactions(order_id). "
    "users.email and orders.status are NOT indexed."
)


class QueryService:
    def __init__(
        self,
        db: Database | None = None,
        security: SecurityEngine | None = None,
        cache: AnalysisCache | None = None,
        advisor: LLMAdvisor | None = None,
        metrics: MetricsCollector | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._db = db or get_db()
        self._security = security or SecurityEngine()
        self._cache = cache or get_cache()
        self._advisor = advisor or get_advisor()
        self._metrics = metrics or get_metrics()
        self._settings = settings or get_settings()

    def process_query(self, request: QueryRequest) -> QueryResponse:
        start = time.perf_counter()

        # 1-3. Parse + deterministic security verdict (authoritative).
        security = self._security.evaluate(request.sql)
        if not security.allowed:
            latency_ms = (time.perf_counter() - start) * 1000.0
            self._metrics.record_request(
                allowed=False,
                cache_hit=False,
                executed=False,
                latency_ms=latency_ms,
                execution_time_ms=None,
            )
            return QueryResponse(
                status="blocked",
                security=security,
                executed=False,
                latency_ms=latency_ms,
            )

        # 4. Normalize for cache key + response transparency.
        try:
            normalized = normalize(request.sql)
            normalized_sql: Optional[str] = normalized.canonical_sql
            cache_key: Optional[str] = normalized.cache_key
        except ValueError:
            normalized = None
            normalized_sql = None
            cache_key = None

        # 5-7. Cache lookup; on miss run EXPLAIN + analyze + LLM advisory and
        # cache the combined result. On hit, restore both from cache (this is
        # what lets repeat queries avoid EXPLAIN re-runs and LLM API calls).
        analysis: Optional[PlanAnalysis] = None
        advisory: Optional[LLMAdvisory] = None
        cache_hit = False
        if cache_key is not None:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.get("analysis") is not None:
                cache_hit = True
                analysis = PlanAnalysis(**cached["analysis"])
                if cached.get("advisory") is not None:
                    advisory = LLMAdvisory(**cached["advisory"])
            else:
                analysis = self._analyze(request.sql)
                if analysis is not None:
                    advisory = self._advisor.advise(
                        normalized_sql or request.sql, analysis, _SCHEMA_INFO
                    )
                    self._cache.set(
                        cache_key,
                        {
                            "analysis": analysis.model_dump(),
                            "advisory": advisory.model_dump() if advisory else None,
                        },
                    )

        # 7. Execute only if requested and allowed. Enforce the configured
        # row-return limit two ways: (a) rewrite a top-level SELECT's LIMIT via
        # the AST, and (b) hard-cap fetched rows at execution time.
        executed = False
        rows = None
        row_count = None
        exec_ms = None
        if request.execute:
            max_rows = self._settings.max_row_limit
            exec_sql = request.sql
            if max_rows and max_rows > 0:
                exec_sql, _ = apply_row_limit(request.sql, max_rows)
            rows, exec_ms = self._db.execute(
                exec_sql, max_rows=max_rows if max_rows and max_rows > 0 else None
            )
            row_count = len(rows)
            executed = True

        latency_ms = (time.perf_counter() - start) * 1000.0
        self._metrics.record_request(
            allowed=True,
            cache_hit=cache_hit,
            executed=executed,
            latency_ms=latency_ms,
            execution_time_ms=exec_ms,
        )
        return QueryResponse(
            status="allowed",
            security=security,
            normalized_sql=normalized_sql,
            cache_hit=cache_hit,
            analysis=analysis,
            advisory=advisory,
            executed=executed,
            rows=rows,
            row_count=row_count,
            execution_time_ms=exec_ms,
            latency_ms=latency_ms,
        )

    def _analyze(self, sql: str) -> Optional[PlanAnalysis]:
        """Run EXPLAIN (FORMAT JSON) and analyze the plan. Best-effort."""
        try:
            plan_json, explain_ms = self._db.explain(sql, analyze=False)
        except Exception:  # noqa: BLE001
            return None
        return analyze_plan(plan_json, explain_time_ms=explain_ms)
