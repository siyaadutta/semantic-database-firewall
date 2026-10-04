"""Phase 2: SQL parsing with sqlglot. Pure unit tests, no DB required."""
import pytest

from app.parser.sql_parser import ParsedSQL, SQLParseError, parse_sql


def test_parse_simple_select():
    p = parse_sql("SELECT id, email FROM users WHERE id = 1")
    assert isinstance(p, ParsedSQL)
    assert p.statement_type == "SELECT"
    assert p.statement_count == 1
    assert p.is_multi_statement is False
    assert p.tables == ["users"]


def test_parse_join_extracts_all_tables():
    p = parse_sql("SELECT * FROM orders o JOIN users u ON o.user_id = u.id")
    assert p.statement_type == "SELECT"
    assert set(p.tables) == {"orders", "users"}


@pytest.mark.parametrize(
    "sql,expected_type",
    [
        ("DROP TABLE users", "DROP"),
        ("TRUNCATE users", "TRUNCATE"),
        ("DELETE FROM orders", "DELETE"),
        ("UPDATE users SET email = 'x'", "UPDATE"),
        ("INSERT INTO users (email) VALUES ('x')", "INSERT"),
    ],
)
def test_statement_type_detection(sql, expected_type):
    assert parse_sql(sql).statement_type == expected_type


def test_multi_statement_detected():
    p = parse_sql("SELECT 1; SELECT 2")
    assert p.statement_count == 2
    assert p.is_multi_statement is True


@pytest.mark.parametrize("bad", ["", "   ", "SELCT id FRM users", "SELECT FROM", "not sql !!!"])
def test_malformed_sql_raises(bad):
    with pytest.raises(SQLParseError):
        parse_sql(bad)
