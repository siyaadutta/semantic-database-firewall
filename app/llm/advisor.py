"""LLM advisory layer (project-instructions.md §7).

STRICT ROLE:
- Advisory only. NEVER the security authority.
- Produces human-readable explanations and optimization recommendations.
- Returns STRUCTURED JSON parsed into LLMAdvisory.
- Any SQL it suggests (a rewrite) is UNTRUSTED TEXT. It is passed back through
  the deterministic SecurityEngine for validation and is NEVER auto-executed.
- Must degrade gracefully: on disabled/unavailable/error/timeout/invalid JSON,
  return a deterministic fallback advisory built from the plan analysis.

The LLM receives: normalized SQL, schema info, plan summary, detected concerns.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx

from app.config import Settings, get_settings
from app.models.schemas import LLMAdvisory, PlanAnalysis
from app.optimizer.analyzer import plan_summary
from app.security.engine import SecurityEngine

_SYSTEM_PROMPT = (
    "You are a PostgreSQL query optimization ADVISOR. You do not make security "
    "decisions and you never execute SQL. Given a normalized SQL query, schema "
    "context, and its query-plan summary, respond with STRICT JSON only, using "
    "exactly these keys: risk_assessment, performance_assessment, explanation, "
    "optimization_recommendation, suggested_index, suggested_rewrite. "
    "suggested_index and suggested_rewrite may be null. Do not include any prose "
    "outside the JSON object."
)


def build_prompt(
    normalized_sql: str,
    schema_info: str,
    analysis: PlanAnalysis,
) -> List[Dict[str, str]]:
    summary = plan_summary(analysis)
    user_payload = {
        "normalized_sql": normalized_sql,
        "schema": schema_info,
        "plan_summary": summary,
        "detected_concerns": [i.type for i in analysis.issues],
    }
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(user_payload, default=str)},
    ]


class LLMAdvisor:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        security: Optional[SecurityEngine] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.security = security or SecurityEngine()
        self._client = client

    # --- public API --------------------------------------------------------

    def advise(
        self,
        normalized_sql: str,
        analysis: PlanAnalysis,
        schema_info: str = "",
    ) -> LLMAdvisory:
        """Return an LLMAdvisory. Never raises: falls back deterministically."""
        if not self.settings.llm_enabled or not self.settings.llm_api_key:
            return self._fallback(analysis, reason="LLM disabled")

        try:
            raw = self._call_llm(build_prompt(normalized_sql, schema_info, analysis))
            advisory = self._parse_response(raw)
        except Exception:  # noqa: BLE001 — any failure degrades to fallback
            return self._fallback(analysis, reason="LLM call/parse failed")

        # Validate any suggested rewrite through the deterministic engine.
        # The rewrite is NEVER executed here; we only annotate whether it would
        # pass policy, so a human can decide.
        if advisory.suggested_rewrite:
            advisory.rewrite_validation = self.security.evaluate(advisory.suggested_rewrite)
        return advisory

    # --- internals ---------------------------------------------------------

    def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        """Call an OpenAI-compatible chat completions endpoint. Returns content str."""
        client = self._client or httpx.Client(timeout=self.settings.llm_timeout_seconds)
        resp = client.post(
            f"{self.settings.llm_base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.settings.llm_api_key}"},
            json={
                "model": self.settings.llm_model,
                "messages": messages,
                "temperature": 0,
                "response_format": {"type": "json_object"},
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def _parse_response(self, raw: str) -> LLMAdvisory:
        data = json.loads(raw)
        return LLMAdvisory(
            risk_assessment=str(data.get("risk_assessment", "")),
            performance_assessment=str(data.get("performance_assessment", "")),
            explanation=str(data.get("explanation", "")),
            optimization_recommendation=str(data.get("optimization_recommendation", "")),
            suggested_index=data.get("suggested_index") or None,
            suggested_rewrite=data.get("suggested_rewrite") or None,
            source="llm",
        )

    def _fallback(self, analysis: PlanAnalysis, reason: str) -> LLMAdvisory:
        """Deterministic advisory derived from plan analysis (no LLM)."""
        if analysis.issues:
            issue = analysis.issues[0]
            perf = f"Detected: {issue.type}. {issue.detail}"
            rec = issue.recommendation
            suggested_index = None
            # Reuse the analyzer's index suggestion if present in the text.
            for i in analysis.issues:
                if "index on" in i.recommendation:
                    # e.g. "... index on users(email) ..."
                    start = i.recommendation.find("index on ") + len("index on ")
                    frag = i.recommendation[start:].split()[0]
                    suggested_index = frag.rstrip(".,;")
                    break
        else:
            perf = "No obvious plan-level performance concerns detected."
            rec = "No index recommendation. Query plan looks acceptable."
            suggested_index = None

        return LLMAdvisory(
            risk_assessment="Not assessed by LLM (advisory fallback).",
            performance_assessment=perf,
            explanation=(
                f"Advisory generated deterministically from the query plan "
                f"({reason}). This fallback does not use a language model."
            ),
            optimization_recommendation=rec,
            suggested_index=suggested_index,
            suggested_rewrite=None,
            source="fallback",
        )


_advisor: Optional[LLMAdvisor] = None


def get_advisor() -> LLMAdvisor:
    global _advisor
    if _advisor is None:
        _advisor = LLMAdvisor()
    return _advisor
