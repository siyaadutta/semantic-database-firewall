"""SQL parsing via sqlglot (project-instructions.md §3, §8).

Responsibilities:
- parse SQL into an AST,
- reject malformed / unparseable SQL,
- detect multiple statements.

This module is parser-based and deterministic. It does NOT make security
decisions (that is the security engine's job), but the security engine relies
on the structured information produced here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

# PostgreSQL dialect for accurate parsing of the target database.
DIALECT = "postgres"


class SQLParseError(ValueError):
    """Raised when SQL cannot be parsed or is otherwise structurally invalid."""


@dataclass
class ParsedSQL:
    raw: str
    statements: List[exp.Expression]
    statement_count: int
    root: exp.Expression  # first (and, for our purposes, only allowed) statement
    statement_type: str  # e.g. SELECT, INSERT, UPDATE, DELETE, DROP, ...
    tables: List[str] = field(default_factory=list)

    @property
    def is_multi_statement(self) -> bool:
        return self.statement_count > 1


_TYPE_ALIASES = {
    "TRUNCATETABLE": "TRUNCATE",
}


def _statement_type(node: exp.Expression) -> str:
    name = type(node).__name__.upper()
    return _TYPE_ALIASES.get(name, name)


def parse_sql(sql: str) -> ParsedSQL:
    """Parse SQL and return structured info.

    Raises SQLParseError for malformed SQL or empty input.
    Multiple statements are parsed and reported (not rejected here); the
    security engine decides that multi-statement input is disallowed.
    """
    if sql is None or not sql.strip():
        raise SQLParseError("Empty SQL statement.")

    try:
        # parse() returns a list of top-level statements; empty statements are dropped.
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except ParseError as exc:
        raise SQLParseError(f"Malformed SQL: {exc}") from exc

    if not statements:
        raise SQLParseError("No parseable SQL statement found.")

    root = statements[0]
    tables = sorted({t.name for t in root.find_all(exp.Table) if t.name})

    return ParsedSQL(
        raw=sql,
        statements=statements,
        statement_count=len(statements),
        root=root,
        statement_type=_statement_type(root),
        tables=tables,
    )
