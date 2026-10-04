"""Query-plan analysis and recommendations (project-instructions.md §8).

Consumes a PostgreSQL `EXPLAIN (FORMAT JSON)` plan and produces a deterministic
PlanAnalysis. Design principles from the spec:

- Do NOT claim every sequential scan is bad. A seq scan on a small table, or a
  seq scan that reads most of a large table anyway, is often optimal.
- Only flag a seq scan as a concern when it has a Filter AND its estimated total
  cost is high (>= seq_scan_cost_threshold). Cost is used rather than row count
  because a Seq Scan node's "Plan Rows" is the POST-filter estimate, not the
  number of rows actually scanned.
- Everything produced here is a RECOMMENDATION, never an automatic change.

The Filter expression is parsed heuristically to suggest a candidate index
column. This is a best-effort suggestion, clearly labeled as such.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.config import get_settings
from app.models.schemas import PlanAnalysis, PlanIssue, Severity

# Extract a column name from a Filter like "(email = 'x'::text)" or
# "(country = 'US'::text)". Best-effort; returns the first column-looking token.
_FILTER_COL = re.compile(r"\(?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|<|>|<=|>=|IN|LIKE)", re.IGNORECASE)


def _walk(node: Dict[str, Any], acc: List[Dict[str, Any]]) -> None:
    acc.append(node)
    for child in node.get("Plans", []) or []:
        _walk(child, acc)


def _candidate_column(filter_expr: Optional[str]) -> Optional[str]:
    if not filter_expr:
        return None
    m = _FILTER_COL.search(filter_expr)
    return m.group(1) if m else None


def analyze_plan(
    plan_json: Dict[str, Any],
    explain_time_ms: Optional[float] = None,
    seq_scan_cost_threshold: Optional[float] = None,
) -> PlanAnalysis:
    """Analyze an EXPLAIN (FORMAT JSON) plan dict.

    `plan_json` is the object with a top-level "Plan" key (i.e. the first element
    of the EXPLAIN JSON array).
    """
    settings = get_settings()
    cost_threshold = (
        seq_scan_cost_threshold
        if seq_scan_cost_threshold is not None
        else settings.seq_scan_cost_threshold
    )

    root = plan_json.get("Plan", plan_json)
    nodes: List[Dict[str, Any]] = []
    _walk(root, nodes)

    node_types: List[str] = []
    seq_scans: List[str] = []
    index_scans: List[str] = []
    issues: List[PlanIssue] = []

    for node in nodes:
        ntype = node.get("Node Type", "")
        node_types.append(ntype)
        relation = node.get("Relation Name")

        if ntype == "Seq Scan":
            if relation:
                seq_scans.append(relation)
            filter_expr = node.get("Filter")
            node_cost = node.get("Total Cost", 0.0) or 0.0
            # Context-aware: a Seq Scan reads the whole relation, so its
            # Plan Rows (post-filter estimate) is NOT the scan size. We use the
            # node's estimated Total Cost as the "large scan" signal instead:
            # a filtered Seq Scan whose cost is high scans a large table and an
            # index on the filtered column could reduce the work. Small/cheap
            # scans and unfiltered full reads are intentionally NOT flagged.
            if filter_expr and node_cost >= cost_threshold:
                col = _candidate_column(filter_expr)
                if col:
                    rec = (
                        f"Consider an index on {relation}({col}) so this filtered "
                        f"lookup can use an index scan instead of scanning the whole "
                        f"table (estimated cost {node_cost:.0f}). Recommendation only "
                        f"— validate with EXPLAIN ANALYZE and real workload before applying."
                    )
                else:
                    rec = (
                        f"Large sequential scan on '{relation}' with a filter "
                        f"(estimated cost {node_cost:.0f}); an appropriate index may "
                        f"help. Recommendation only."
                    )
                issues.append(
                    PlanIssue(
                        type="large_seq_scan_with_filter",
                        detail=(
                            f"Seq Scan on '{relation}' has estimated total cost "
                            f"{node_cost:.0f} with filter {filter_expr}."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=rec,
                    )
                )
        elif ntype in ("Index Scan", "Index Only Scan", "Bitmap Index Scan"):
            if relation:
                index_scans.append(relation)

    total_cost = root.get("Total Cost")

    return PlanAnalysis(
        node_types=node_types,
        total_estimated_cost=total_cost,
        seq_scans=seq_scans,
        index_scans=index_scans,
        issues=issues,
        explain_time_ms=explain_time_ms,
        raw_plan=plan_json,
    )


def plan_summary(analysis: PlanAnalysis) -> Dict[str, Any]:
    """Compact summary suitable for feeding to the LLM advisory layer (§7)."""
    return {
        "node_types": analysis.node_types,
        "total_estimated_cost": analysis.total_estimated_cost,
        "seq_scans": analysis.seq_scans,
        "index_scans": analysis.index_scans,
        "issues": [
            {"type": i.type, "detail": i.detail, "recommendation": i.recommendation}
            for i in analysis.issues
        ],
    }
