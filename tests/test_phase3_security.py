"""Phase 3: deterministic security policy engine. Pure unit tests."""
import pytest

from app.config import Settings
from app.models.schemas import Severity
from app.security.engine import SecurityEngine


@pytest.fixture
def engine():
    # Explicit settings so tests are independent of environment.
    # read_only_mode defaults to True (writes denied).
    return SecurityEngine(
        settings=Settings(
            blocked_operations=["DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"],
            blocked_tables=["secrets"],
            block_unfiltered_write=True,
            restrict_select_star=True,
        )
    )


@pytest.fixture
def writes_allowed_engine():
    # read_only_mode=False so the unfiltered-write rule (not read-only) is what
    # governs DELETE/UPDATE.
    return SecurityEngine(
        settings=Settings(
            read_only_mode=False,
            block_unfiltered_write=True,
            restrict_select_star=True,
        )
    )


def test_allows_safe_select(engine):
    r = engine.evaluate("SELECT id, email FROM users WHERE id = 1")
    assert r.allowed is True
    assert r.rule == "allow"


def test_allows_count_star(engine):
    assert engine.evaluate("SELECT COUNT(*) FROM users").allowed is True


@pytest.mark.parametrize(
    "sql,rule,severity",
    [
        ("DROP TABLE users", "blocked_operation:DROP", Severity.CRITICAL),
        ("TRUNCATE users", "blocked_operation:TRUNCATE", Severity.CRITICAL),
        ("ALTER TABLE users ADD COLUMN x int", "blocked_operation:ALTER", Severity.CRITICAL),
        ("GRANT ALL ON users TO public", "blocked_operation:GRANT", Severity.CRITICAL),
    ],
)
def test_blocks_dangerous_operations(engine, sql, rule, severity):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == rule
    assert r.severity == severity


def test_blocks_multi_statement(engine):
    r = engine.evaluate("SELECT 1; DROP TABLE users")
    assert r.allowed is False
    assert r.rule == "multi_statement"
    assert r.severity == Severity.CRITICAL


def test_blocks_unfiltered_delete(writes_allowed_engine):
    r = writes_allowed_engine.evaluate("DELETE FROM orders")
    assert r.allowed is False
    assert r.rule == "unfiltered_write:DELETE"


def test_allows_filtered_delete(writes_allowed_engine):
    assert writes_allowed_engine.evaluate("DELETE FROM orders WHERE id = 1").allowed is True


def test_blocks_unfiltered_update(writes_allowed_engine):
    r = writes_allowed_engine.evaluate("UPDATE users SET email = 'x'")
    assert r.allowed is False
    assert r.rule == "unfiltered_write:UPDATE"


def test_allows_filtered_update(writes_allowed_engine):
    assert writes_allowed_engine.evaluate("UPDATE users SET email = 'x' WHERE id = 2").allowed is True


# --- Read-only posture (default) + CTE write detection ---------------------

@pytest.mark.parametrize(
    "sql,rule",
    [
        ("INSERT INTO users(email) VALUES ('x')", "read_only:INSERT"),
        ("UPDATE users SET email = 'y' WHERE id = 1", "read_only:UPDATE"),
        ("DELETE FROM orders WHERE id = 1", "read_only:DELETE"),
    ],
)
def test_read_only_blocks_writes_by_default(engine, sql, rule):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == rule
    assert r.severity == Severity.HIGH


@pytest.mark.parametrize(
    "sql,rule",
    [
        ("WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING id) SELECT id FROM d", "read_only:DELETE"),
        ("WITH u AS (UPDATE users SET email = 1 WHERE id = 1 RETURNING id) SELECT id FROM u", "read_only:UPDATE"),
        ("WITH i AS (INSERT INTO users(email) VALUES (1) RETURNING id) SELECT id FROM i", "read_only:INSERT"),
    ],
)
def test_read_only_blocks_data_modifying_cte(engine, sql, rule):
    # The top-level statement type is SELECT, but a write hides inside the CTE.
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == rule


def test_unfiltered_write_inside_cte_blocked_when_writes_allowed(writes_allowed_engine):
    r = writes_allowed_engine.evaluate(
        "WITH d AS (DELETE FROM orders RETURNING id) SELECT id FROM d"
    )
    assert r.allowed is False
    assert r.rule == "unfiltered_write:DELETE"


def test_read_only_still_allows_selects(engine):
    assert engine.evaluate("SELECT id FROM users WHERE id = 1").allowed is True


def test_blocks_blocked_table(engine):
    r = engine.evaluate("SELECT id FROM secrets WHERE id = 1")
    assert r.allowed is False
    assert r.rule == "blocked_table:secrets"


def test_blocks_select_star(engine):
    r = engine.evaluate("SELECT * FROM users")
    assert r.allowed is False
    assert r.rule == "select_star"


def test_select_star_can_be_disabled():
    e = SecurityEngine(settings=Settings(restrict_select_star=False))
    assert e.evaluate("SELECT * FROM users").allowed is True


@pytest.mark.parametrize(
    "sql,label",
    [
        ("SELECT id FROM users WHERE email = 'a' OR 1=1", "tautology"),
        ("SELECT id FROM users WHERE email = 'a' -- x", "comment_terminator"),
        ("SELECT id FROM users UNION SELECT id FROM orders", "union_probe"),
        ("SELECT pg_sleep(5)", "sleep_probe"),
    ],
)
def test_injection_heuristics_flagged_and_labeled(engine, sql, label):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == f"injection_heuristic:{label}"
    # Heuristic must be clearly labeled as not a complete defense.
    assert "not a complete injection defense" in r.reason.lower()


@pytest.mark.parametrize(
    "sql",
    [
        # '--' inside a string literal is data, not a comment terminator.
        "SELECT id FROM users WHERE full_name = 'a--b'",
        # 'UNION SELECT' inside a literal is data, not a union probe.
        "SELECT id FROM users WHERE full_name = 'buy UNION SELECT now'",
    ],
)
def test_injection_markers_inside_string_literals_not_flagged(engine, sql):
    # The heuristic scans SQL with string-literal contents removed, so markers
    # appearing only inside quoted values must not be treated as injection.
    r = engine.evaluate(sql)
    assert r.allowed is True, r.reason


def test_real_trailing_comment_still_flagged(engine):
    # A genuine trailing comment (outside any literal) is still caught.
    r = engine.evaluate("SELECT id FROM users WHERE id = 1 -- drop everything")
    assert r.allowed is False
    assert r.rule == "injection_heuristic:comment_terminator"


def test_unparseable_sql_blocked(engine):
    r = engine.evaluate("SELCT bad sql")
    assert r.allowed is False
    assert r.rule == "unparseable_sql"


def test_parser_rules_take_precedence_over_heuristics(engine):
    # DROP is caught by the authoritative parser rule, not a heuristic.
    r = engine.evaluate("DROP TABLE users")
    assert r.rule.startswith("blocked_operation")
