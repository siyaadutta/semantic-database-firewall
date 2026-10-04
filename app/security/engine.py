"""Deterministic security policy engine (project-instructions.md §6).

What it does: decides whether a SQL query is allowed or blocked, deterministically.
Why it exists: security decisions must be predictable and explainable — the LLM
is never consulted here.
Input: a raw SQL string.
Output: a SecurityResult {allowed, reason, rule, severity}.

Design: `evaluate()` runs a fixed, ordered sequence of checks and returns on the
first one that blocks. The checks come in two groups:

  1. Parser-based checks (authoritative): derived from the sqlglot AST —
     write detection (including writes hidden inside CTEs/subqueries), statement
     type, multiple statements, table access, WHERE presence, SELECT *.
  2. A heuristic injection check (clearly labeled): simple regex signals for
     classic injection markers, run over the SQL with string-literal CONTENTS
     removed so that markers inside quoted values (e.g. '--' in a literal) do
     not cause false positives. This is NOT a complete injection defense; the
     parser-based checks are the real protection.

Write posture: by default the firewall is read-only (`read_only_mode=True`) and
blocks any INSERT/UPDATE/DELETE/MERGE anywhere in the query. Set
`read_only_mode=False` to allow writes; unfiltered bulk writes (DELETE/UPDATE
without WHERE) are still blocked when `block_unfiltered_write` is on.

Ordering matters: authoritative parser checks run before the heuristic one, so a
dangerous statement is reported by its precise rule (e.g. blocked_operation:DROP)
rather than by a generic heuristic.

Limitations: the heuristic regexes can have false positives/negatives; they are
intentionally conservative and secondary.
"""
from __future__ import annotations

import re
from typing import Optional

from sqlglot import exp

from app.config import Settings, get_settings
from app.models.schemas import SecurityResult, Severity
from app.parser.sql_parser import ParsedSQL, SQLParseError, parse_sql

# Data-modifying statement types. Detected anywhere in the AST (including inside
# CTEs like `WITH x AS (DELETE ... RETURNING ...) SELECT ...`), because the
# top-level statement type of such a query is SELECT.
WRITE_STATEMENT_TYPES = {"INSERT", "UPDATE", "DELETE", "MERGE"}
# sqlglot expression classes corresponding to those writes.
WRITE_EXPRESSIONS = (exp.Insert, exp.Update, exp.Delete, exp.Merge)

# Administrative / DDL / privilege-changing statement types that must never run
# through the firewall (beyond the always-blocked operations in settings).
ADMIN_STATEMENT_TYPES = {
    "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE",
    "COMMAND", "SET", "VACUUM", "ANALYZE", "COPY",
}

# Heuristic SQL-injection markers. NOT a complete defense — clearly labeled.
INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # OR <x> = <x> tautologies where BOTH operands are identical: numeric
    # (1=1), quoted-string ('a'='a'), or identifier (a=a). The backreference
    # (\1) requires the same operand on both sides, so legitimate comparisons
    # like `OR user_id = 5` (different operands) are NOT flagged.
    ("tautology", re.compile(
        r"\bOR\b\s+('[^']*'|\"[^\"]*\"|\w+)\s*=\s*\1(?!\w)",
        re.IGNORECASE,
    )),
    ("comment_terminator", re.compile(r"(--|#|/\*)")),
    ("stacked_query_marker", re.compile(r";\s*\w")),
    ("union_probe", re.compile(r"\bUNION\b\s+(ALL\s+)?SELECT\b", re.IGNORECASE)),
    ("sleep_probe", re.compile(r"\b(pg_sleep|sleep)\s*\(", re.IGNORECASE)),
]


def _blocked(reason: str, rule: str, severity: Severity) -> SecurityResult:
    return SecurityResult(allowed=False, reason=reason, rule=rule, severity=severity)


class SecurityEngine:
    """Runs deterministic policy checks in a fixed order."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    def evaluate(self, sql: str) -> SecurityResult:
        # A query we cannot parse is rejected outright — this is a deterministic,
        # security-relevant decision, not a heuristic guess.
        try:
            parsed = parse_sql(sql)
        except SQLParseError as exc:
            return _blocked(
                f"SQL could not be parsed and is rejected: {exc}",
                "unparseable_sql",
                Severity.HIGH,
            )

        # Authoritative parser-based checks, in order. The first block wins.
        for check in (
            self._check_multiple_statements,
            self._check_blocked_operation,
            self._check_admin_operation,
            self._check_read_only,
            self._check_dangerous_functions,
            self._check_system_catalog,
            self._check_blocked_table,
            self._check_unfiltered_write,
            self._check_select_star,
        ):
            result = check(parsed)
            if result is not None:
                return result

        # Heuristic check runs last and only if nothing authoritative blocked.
        result = self._check_injection_heuristics(parsed)
        if result is not None:
            return result

        return SecurityResult(
            allowed=True,
            reason="Query passed all deterministic security policies.",
            rule="allow",
            severity=Severity.LOW,
        )

    # --- parser-based checks (authoritative) -------------------------------

    def _check_multiple_statements(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        if parsed.is_multi_statement:
            return _blocked(
                f"Multiple SQL statements are not permitted ({parsed.statement_count} found).",
                "multi_statement",
                Severity.CRITICAL,
            )
        return None

    def _check_blocked_operation(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        blocked = {op.upper() for op in self.settings.blocked_operations}
        if parsed.statement_type in blocked:
            return _blocked(
                f"Operation '{parsed.statement_type}' is blocked by policy.",
                f"blocked_operation:{parsed.statement_type}",
                Severity.CRITICAL,
            )
        return None

    def _check_admin_operation(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        if parsed.statement_type in ADMIN_STATEMENT_TYPES:
            return _blocked(
                f"Administrative/DDL operation '{parsed.statement_type}' is not permitted "
                f"through the firewall.",
                f"admin_operation:{parsed.statement_type}",
                Severity.HIGH,
            )
        return None

    def _check_read_only(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        """When read_only_mode is on, block any data-modifying statement.

        Uses find_all over the whole AST so a write hidden inside a CTE or
        subquery — e.g. `WITH d AS (DELETE ... RETURNING ...) SELECT ...`, whose
        top-level type is SELECT — is still caught.
        """
        if not self.settings.read_only_mode:
            return None
        write = parsed.root.find(*WRITE_EXPRESSIONS)
        if write is not None:
            kind = type(write).__name__.upper()
            return _blocked(
                f"Read-only mode: data-modifying statement ({kind}) is not permitted "
                f"(including inside CTEs/subqueries).",
                f"read_only:{kind}",
                Severity.HIGH,
            )
        return None

    def _check_dangerous_functions(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        """Block dangerous server-side functions (file/OS/large-object/dblink).

        These functions let a read-only connection exfiltrate data from disk or
        reach other systems (e.g. pg_read_file('/etc/passwd')). sqlglot parses
        unknown functions as exp.Anonymous, so we match on the function name.
        """
        if not self.settings.block_dangerous_functions:
            return None
        blocked = {name.lower() for name in self.settings.dangerous_functions}
        for func in parsed.root.find_all(exp.Anonymous):
            name = (func.name or "").lower()
            if name in blocked:
                return _blocked(
                    f"Function '{name}' is blocked (file/OS/large-object/remote access).",
                    f"dangerous_function:{name}",
                    Severity.CRITICAL,
                )
        return None

    def _check_system_catalog(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        """Block reads of system catalogs / metadata schemas.

        Blocks tables in a blocked schema (pg_catalog, information_schema) and
        unqualified system tables by name prefix (e.g. pg_stat_activity). CTE
        names are ignored — they are not real tables.
        """
        if not self.settings.block_dangerous_functions:
            return None
        blocked_schemas = {s.lower() for s in self.settings.blocked_schemas}
        prefixes = tuple(p.lower() for p in self.settings.system_table_prefixes)
        cte_names = {c.alias_or_name.lower() for c in parsed.root.find_all(exp.CTE)}
        for table in parsed.root.find_all(exp.Table):
            schema = (table.db or "").lower()
            name = (table.name or "").lower()
            if name in cte_names and not schema:
                continue
            if schema in blocked_schemas or name.startswith(prefixes):
                target = f"{schema}.{name}" if schema else name
                return _blocked(
                    f"Access to system catalog/metadata '{target}' is not permitted.",
                    f"system_catalog:{target}",
                    Severity.HIGH,
                )
        return None

    def _check_blocked_table(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        blocked = {t.lower() for t in self.settings.blocked_tables}
        if not blocked:
            return None
        # CTE names are query-local aliases, not base tables — don't flag them.
        cte_names = {c.alias_or_name.lower() for c in parsed.root.find_all(exp.CTE)}
        for table in parsed.root.find_all(exp.Table):
            name = table.name.lower()
            if name in cte_names and not table.db:
                continue
            if name in blocked:
                return _blocked(
                    f"Access to table '{table.name}' is blocked by policy.",
                    f"blocked_table:{table.name}",
                    Severity.HIGH,
                )
        return None

    def _check_unfiltered_write(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        """Block any DELETE/UPDATE without a WHERE clause (unfiltered bulk write).

        Scans every DELETE/UPDATE node in the AST, not just the top-level
        statement, so an unfiltered write inside a CTE is also caught. Only
        relevant when writes are allowed (read_only_mode=False); when read-only
        is on, _check_read_only has already blocked all writes.
        """
        if not self.settings.block_unfiltered_write:
            return None
        for node in parsed.root.find_all(exp.Delete, exp.Update):
            if node.find(exp.Where) is None:
                kind = type(node).__name__.upper()
                return _blocked(
                    f"{kind} without a WHERE clause is not permitted "
                    f"(unfiltered bulk write).",
                    f"unfiltered_write:{kind}",
                    Severity.HIGH,
                )
        return None

    def _check_select_star(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        """Flag a bare `SELECT *`. COUNT(*) and qualified `t.*` are allowed
        because only a bare star in the projection list is a column-enumeration
        concern."""
        if not self.settings.restrict_select_star or parsed.statement_type != "SELECT":
            return None
        for select in parsed.root.find_all(exp.Select):
            for projection in select.expressions:
                if isinstance(projection, exp.Star):
                    return _blocked(
                        "SELECT * is restricted by policy; enumerate explicit columns.",
                        "select_star",
                        Severity.LOW,
                    )
        return None

    # --- heuristic check (labeled; NOT a complete injection defense) -------

    def _sql_without_string_literals(self, parsed: ParsedSQL) -> str:
        """Return the SQL with string-literal CONTENTS blanked out.

        Markers like '--' or 'UNION' that appear *inside* a quoted value are
        legitimate data, not injection. By emptying string literals before
        running the regexes, we avoid flagging e.g. `WHERE name = 'a--b'`.
        Numeric literals are left as-is (needed by the tautology pattern).
        Falls back to the raw SQL if anything goes wrong.
        """
        try:
            tree = parsed.root.copy()
            for literal in tree.find_all(exp.Literal):
                if literal.args.get("is_string"):
                    literal.set("this", "")
            return tree.sql(dialect="postgres")
        except Exception:  # noqa: BLE001 — heuristic must never break evaluation
            return parsed.raw

    def _check_injection_heuristics(self, parsed: ParsedSQL) -> Optional[SecurityResult]:
        scan_target = self._sql_without_string_literals(parsed)
        for label, pattern in INJECTION_PATTERNS:
            if pattern.search(scan_target):
                return _blocked(
                    f"Heuristic SQL-injection marker detected ({label}). "
                    "Heuristic only — not a complete injection defense.",
                    f"injection_heuristic:{label}",
                    Severity.MEDIUM,
                )
        return None
