"""Application configuration loaded from environment variables.

Source of truth: .kiro/steering/project-instructions.md (§2, §12).
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- PostgreSQL ---
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "firewall"
    postgres_user: str = "firewall"
    postgres_password: str = "firewall"

    # --- Redis ---
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    cache_ttl_seconds: int = 300

    # --- LLM (advisory only) ---
    llm_enabled: bool = False
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 15.0

    # --- Security policy (configurable, deterministic) ---
    # When true (default), the firewall is a READ-ONLY proxy: any data-modifying
    # statement (INSERT/UPDATE/DELETE/MERGE), including one hidden inside a CTE,
    # is blocked. Set to false to allow writes (still subject to the unfiltered
    # bulk-write check below).
    read_only_mode: bool = True
    # Tables that may never be written to / accessed depending on rule.
    blocked_tables: List[str] = Field(default_factory=list)
    # Operations that are always blocked regardless of table.
    blocked_operations: List[str] = Field(
        default_factory=lambda: ["DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]
    )
    # Whether unauthorized DELETE/UPDATE (no WHERE) is blocked.
    block_unfiltered_write: bool = True
    # Whether SELECT * is flagged/restricted.
    restrict_select_star: bool = True
    # Block dangerous server-side functions (file/OS/large-object/dblink access)
    # and reads of system catalogs/metadata schemas. This protects a read-only
    # connection from read-side exfiltration (e.g. pg_read_file('/etc/passwd')).
    block_dangerous_functions: bool = True
    # Function names blocked regardless of casing. Extend via env if needed.
    dangerous_functions: List[str] = Field(
        default_factory=lambda: [
            "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_ls_logdir",
            "pg_ls_waldir", "pg_stat_file", "lo_import", "lo_export", "lo_get",
            "dblink", "dblink_exec", "dblink_connect", "current_setting",
        ]
    )
    # Table schemas whose access is blocked (system catalogs / metadata).
    blocked_schemas: List[str] = Field(
        default_factory=lambda: ["pg_catalog", "information_schema"]
    )
    # Table-name prefixes treated as system catalogs even without a schema
    # qualifier (e.g. pg_stat_activity, pg_authid).
    system_table_prefixes: List[str] = Field(default_factory=lambda: ["pg_"])
    # Maximum rows an executed query may return. Enforced two ways: a top-level
    # SELECT's LIMIT is capped/injected via the sqlglot AST, and a hard
    # fetchmany(max_row_limit) cap is applied at execution time.
    max_row_limit: int = 10000

    # --- Query analysis ---
    # Estimated total-cost threshold above which a filtered sequential scan is
    # flagged as a concern. Cost is used (not row count) because a Seq Scan
    # node's Plan Rows reflects POST-filter output, not the rows actually scanned.
    seq_scan_cost_threshold: float = 1000.0

    @property
    def postgres_dsn(self) -> str:
        return (
            f"host={self.postgres_host} port={self.postgres_port} "
            f"dbname={self.postgres_db} user={self.postgres_user} "
            f"password={self.postgres_password}"
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
