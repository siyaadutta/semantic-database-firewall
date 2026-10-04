"""Configurable row-return limit enforcement (project-instructions.md §6, §8).

Safely caps the number of rows an allowed query may return, using the parsed
sqlglot AST — NOT raw string manipulation. Two layers of protection:

1. AST rewrite: for a top-level SELECT, inject `LIMIT max_rows` when absent, or
   lower an existing LIMIT that exceeds max_rows. Non-SELECT statements and
   compound statements (e.g. UNION) are left structurally untouched here.
2. A hard `fetchmany(max_rows)` cap is applied at execution time in the database
   layer, which bounds the returned rows regardless of the query's AST shape.

The AST rewrite preserves query semantics (ORDER BY, existing smaller LIMITs)
and never alters non-SELECT statements, so API semantics are unchanged.
"""
from __future__ import annotations

from typing import Tuple

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

DIALECT = "postgres"


def apply_row_limit(sql: str, max_rows: int) -> Tuple[str, str]:
    """Return (possibly_rewritten_sql, action).

    action is one of: "injected", "capped", "kept", "untouched".
    On any parse issue the original SQL is returned untouched (the execution
    layer still enforces the hard fetch cap).
    """
    if max_rows is None or max_rows <= 0:
        return sql, "untouched"
    try:
        tree = sqlglot.parse_one(sql, read=DIALECT)
    except ParseError:
        return sql, "untouched"

    if not isinstance(tree, exp.Select):
        # DELETE/UPDATE/INSERT/UNION/etc. are not row-limited by AST rewrite.
        return sql, "untouched"

    limit = tree.args.get("limit")
    if limit is None:
        return tree.limit(max_rows).sql(dialect=DIALECT), "injected"

    # Try to read the existing numeric LIMIT; if it is non-numeric (e.g. a
    # parameter/expression), leave it and rely on the execution-time cap.
    try:
        current = int(limit.expression.name)
    except (AttributeError, ValueError):
        return tree.sql(dialect=DIALECT), "kept"

    if current > max_rows:
        return tree.limit(max_rows).sql(dialect=DIALECT), "capped"
    return tree.sql(dialect=DIALECT), "kept"
