"""Pydantic models shared across layers (project-instructions.md §3, §6, §7, §9)."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QueryRequest(BaseModel):
    sql: str = Field(..., min_length=1, description="The SQL query to evaluate.")
    execute: bool = Field(
        default=True,
        description="If true, execute the query when allowed. If false, analyze only.",
    )


class SecurityResult(BaseModel):
    """Deterministic security verdict (project-instructions.md §6)."""

    allowed: bool
    reason: str
    rule: str
    severity: Severity


class PlanIssue(BaseModel):
    """A single detected performance concern. Always a recommendation."""

    type: str
    detail: str
    severity: Severity
    recommendation: str


class PlanAnalysis(BaseModel):
    """Deterministic query-plan analysis (project-instructions.md §8)."""

    node_types: List[str] = Field(default_factory=list)
    total_estimated_cost: Optional[float] = None
    seq_scans: List[str] = Field(default_factory=list)
    index_scans: List[str] = Field(default_factory=list)
    issues: List[PlanIssue] = Field(default_factory=list)
    explain_time_ms: Optional[float] = None
    raw_plan: Optional[Dict[str, Any]] = None


class LLMAdvisory(BaseModel):
    """Advisory-only LLM output (project-instructions.md §7). Never authoritative."""

    risk_assessment: str
    performance_assessment: str
    explanation: str
    optimization_recommendation: str
    suggested_index: Optional[str] = None
    suggested_rewrite: Optional[str] = None
    source: str = Field(
        default="llm",
        description="'llm' when produced by the model, 'fallback' when the model was unavailable.",
    )
    rewrite_validation: Optional[SecurityResult] = Field(
        default=None,
        description="Deterministic validation of any suggested rewrite. Rewrites are never auto-executed.",
    )


class QueryResponse(BaseModel):
    status: str = Field(..., description="allowed | blocked | analyzed")
    security: SecurityResult
    normalized_sql: Optional[str] = None
    cache_hit: bool = False
    analysis: Optional[PlanAnalysis] = None
    advisory: Optional[LLMAdvisory] = None
    executed: bool = False
    rows: Optional[List[Dict[str, Any]]] = None
    row_count: Optional[int] = None
    execution_time_ms: Optional[float] = None
    latency_ms: Optional[float] = None
