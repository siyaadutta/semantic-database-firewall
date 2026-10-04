"""Phase 7: LLM advisory layer — structured JSON, fallback, rewrite validation.

External LLM calls are mocked (project-instructions.md §10).
"""
import json

import httpx
import pytest

from app.config import Settings
from app.llm.advisor import LLMAdvisor, build_prompt
from app.models.schemas import PlanAnalysis, PlanIssue, Severity


def _analysis_with_issue():
    return PlanAnalysis(
        node_types=["Seq Scan"],
        total_estimated_cost=2280.0,
        seq_scans=["users"],
        index_scans=[],
        issues=[
            PlanIssue(
                type="large_seq_scan_with_filter",
                detail="Seq Scan on 'users' has estimated total cost 2280 with filter (email = ...).",
                severity=Severity.MEDIUM,
                recommendation="Consider an index on users(email). Recommendation only.",
            )
        ],
    )


def _mock_client(response_json: dict) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_json)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _enabled_settings():
    return Settings(llm_enabled=True, llm_api_key="test-key")


def test_build_prompt_includes_plan_and_concerns():
    msgs = build_prompt("SELECT id FROM users WHERE email = ?", "schema", _analysis_with_issue())
    assert msgs[0]["role"] == "system"
    user = json.loads(msgs[1]["content"])
    assert user["normalized_sql"].startswith("SELECT")
    assert "large_seq_scan_with_filter" in user["detected_concerns"]


def test_structured_json_parsed_into_advisory():
    llm_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "risk_assessment": "low",
                            "performance_assessment": "seq scan on large table",
                            "explanation": "The query filters on an unindexed column.",
                            "optimization_recommendation": "Add an index on email.",
                            "suggested_index": "users(email)",
                            "suggested_rewrite": None,
                        }
                    )
                }
            }
        ]
    }
    advisor = LLMAdvisor(settings=_enabled_settings(), client=_mock_client(llm_payload))
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.source == "llm"
    assert adv.suggested_index == "users(email)"
    assert "index" in adv.optimization_recommendation.lower()


def test_disabled_llm_uses_fallback():
    advisor = LLMAdvisor(settings=Settings(llm_enabled=False))
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.source == "fallback"
    # Fallback still surfaces the deterministic index suggestion.
    assert adv.suggested_index == "users(email)"


def test_llm_http_error_falls_back():
    def handler(request):
        return httpx.Response(500, json={"error": "boom"})

    advisor = LLMAdvisor(
        settings=_enabled_settings(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.source == "fallback"


def test_invalid_json_falls_back():
    payload = {"choices": [{"message": {"content": "this is not json"}}]}
    advisor = LLMAdvisor(settings=_enabled_settings(), client=_mock_client(payload))
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.source == "fallback"


def test_suggested_rewrite_is_validated_not_executed():
    # LLM returns a DANGEROUS rewrite; it must be flagged by the security engine
    # and never executed.
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "risk_assessment": "n/a",
                            "performance_assessment": "n/a",
                            "explanation": "n/a",
                            "optimization_recommendation": "rewrite",
                            "suggested_index": None,
                            "suggested_rewrite": "DROP TABLE users",
                        }
                    )
                }
            }
        ]
    }
    advisor = LLMAdvisor(settings=_enabled_settings(), client=_mock_client(payload))
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.suggested_rewrite == "DROP TABLE users"
    assert adv.rewrite_validation is not None
    assert adv.rewrite_validation.allowed is False  # deterministic engine blocks it


def test_safe_rewrite_validation_marked_allowed():
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "risk_assessment": "n/a",
                            "performance_assessment": "n/a",
                            "explanation": "n/a",
                            "optimization_recommendation": "rewrite",
                            "suggested_index": None,
                            "suggested_rewrite": "SELECT id FROM users WHERE email = 'x'",
                        }
                    )
                }
            }
        ]
    }
    advisor = LLMAdvisor(settings=_enabled_settings(), client=_mock_client(payload))
    adv = advisor.advise("SELECT id FROM users WHERE email = ?", _analysis_with_issue())
    assert adv.rewrite_validation is not None
    assert adv.rewrite_validation.allowed is True
