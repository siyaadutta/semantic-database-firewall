"""Read-side hardening (second review): dangerous functions, system catalogs,
string tautologies, and the CTE-alias false positive."""
import pytest

from app.config import Settings
from app.models.schemas import Severity
from app.security.engine import SecurityEngine


@pytest.fixture
def engine():
    # SELECT * restriction OFF so these checks are exercised on their own merit
    # (the review noted SELECT * only "accidentally" blocked some of these).
    return SecurityEngine(settings=Settings(restrict_select_star=False))


@pytest.mark.parametrize(
    "sql,rule_prefix",
    [
        ("SELECT pg_read_file('/etc/passwd')", "dangerous_function:pg_read_file"),
        ("SELECT pg_read_binary_file('/etc/passwd')", "dangerous_function:pg_read_binary_file"),
        ("SELECT pg_ls_dir('/')", "dangerous_function:pg_ls_dir"),
        ("SELECT lo_import('/x')", "dangerous_function:lo_import"),
        ("SELECT current_setting('data_directory')", "dangerous_function:current_setting"),
    ],
)
def test_dangerous_functions_blocked(engine, sql, rule_prefix):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == rule_prefix
    assert r.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM pg_stat_activity",
        "SELECT * FROM pg_catalog.pg_authid",
        "SELECT * FROM information_schema.tables",
        "SELECT datname FROM pg_database",
    ],
)
def test_system_catalog_access_blocked(engine, sql):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule.startswith("system_catalog:")


def test_dangerous_checks_independent_of_select_star():
    # Even with SELECT * restriction ON, the reason must be the specific
    # dangerous-function/system-catalog rule, not select_star.
    e = SecurityEngine(settings=Settings(restrict_select_star=True))
    assert e.evaluate("SELECT pg_read_file('/etc/passwd')").rule.startswith("dangerous_function:")
    assert e.evaluate("SELECT c FROM pg_stat_activity").rule.startswith("system_catalog:")


def test_dangerous_functions_can_be_disabled():
    e = SecurityEngine(
        settings=Settings(block_dangerous_functions=False, restrict_select_star=False)
    )
    assert e.evaluate("SELECT pg_read_file('/x')").allowed is True


def test_normal_functions_not_blocked(engine):
    assert engine.evaluate("SELECT COUNT(*) FROM users").allowed is True
    assert engine.evaluate("SELECT max(id), lower(email) FROM users WHERE id = 1").allowed is True


# --- string tautology (heuristic false-negative fix) -----------------------

@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM users WHERE id = 1 OR 'a' = 'a'",
        "SELECT id FROM users WHERE id = 1 OR 1 = 1",
    ],
)
def test_string_and_numeric_tautologies_flagged(engine, sql):
    r = engine.evaluate(sql)
    assert r.allowed is False
    assert r.rule == "injection_heuristic:tautology"


@pytest.mark.parametrize(
    "sql",
    [
        # Legitimate OR comparisons with DIFFERENT operands must NOT be flagged.
        "SELECT id FROM orders WHERE user_id = 5 OR user_id = 6",
        "SELECT id FROM users WHERE country = 1 OR country = 2",
        "SELECT id FROM users WHERE name = 'a' OR name = 'b'",
    ],
)
def test_legitimate_or_comparisons_not_flagged(engine, sql):
    assert engine.evaluate(sql).allowed is True, sql


# --- CTE-alias false positive ---------------------------------------------

def test_cte_named_like_blocked_table_is_allowed():
    e = SecurityEngine(settings=Settings(blocked_tables=["secrets"]))
    r = e.evaluate("WITH secrets AS (SELECT 1 AS x) SELECT x FROM secrets")
    assert r.allowed is True, r.reason


def test_real_blocked_table_still_blocked():
    e = SecurityEngine(settings=Settings(blocked_tables=["secrets"]))
    r = e.evaluate("SELECT id FROM secrets")
    assert r.allowed is False
    assert r.rule == "blocked_table:secrets"
