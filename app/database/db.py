"""PostgreSQL access layer.

Responsibilities (see project-instructions.md §3, §8):
- manage a connection pool,
- run EXPLAIN (FORMAT JSON),
- execute approved queries with timing.

This layer performs NO security decisions. It only executes what it is given.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.config import get_settings


class Database:
    def __init__(self, dsn: Optional[str] = None) -> None:
        settings = get_settings()
        self._dsn = dsn or settings.postgres_dsn
        self._pool: Optional[ConnectionPool] = None

    def connect(self) -> None:
        if self._pool is None:
            self._pool = ConnectionPool(
                self._dsn, min_size=1, max_size=10, open=True, kwargs={"row_factory": dict_row}
            )

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    @property
    def pool(self) -> ConnectionPool:
        if self._pool is None:
            self.connect()
        assert self._pool is not None
        return self._pool

    def ping(self) -> bool:
        """Return True if the database answers a trivial query."""
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                row = cur.fetchone()
                return bool(row and row.get("ok") == 1)

    def execute(
        self,
        sql: str,
        params: Optional[Tuple[Any, ...]] = None,
        max_rows: Optional[int] = None,
    ) -> Tuple[List[Dict[str, Any]], float]:
        """Execute a query, returning (rows, execution_time_ms).

        Read-only intent is enforced upstream by the security engine; this
        method simply runs the SQL. A per-call statement timeout could be
        added here if desired.
        """
        start = time.perf_counter()
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows: List[Dict[str, Any]] = []
                if cur.description is not None:
                    if max_rows is not None:
                        rows = cur.fetchmany(max_rows)
                    else:
                        rows = cur.fetchall()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return rows, elapsed_ms

    def explain(self, sql: str, analyze: bool = False) -> Tuple[Dict[str, Any], float]:
        """Run EXPLAIN (FORMAT JSON) and return (plan_json, explain_time_ms).

        When analyze=True, EXPLAIN ANALYZE actually executes the statement to
        capture real timing. Callers must only pass safe, read-only SQL when
        using analyze=True.
        """
        options = "ANALYZE, BUFFERS, FORMAT JSON" if analyze else "FORMAT JSON"
        explain_sql = f"EXPLAIN ({options}) {sql}"
        start = time.perf_counter()
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(explain_sql)
                row = cur.fetchone()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        # EXPLAIN FORMAT JSON returns a single column containing a list with one plan dict.
        plan_container = list(row.values())[0] if row else []
        plan_json = plan_container[0] if plan_container else {}
        return plan_json, elapsed_ms


# Module-level singleton used by the app.
_db: Optional[Database] = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
