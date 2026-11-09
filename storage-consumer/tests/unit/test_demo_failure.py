"""
storage-consumer/tests/unit/test_demo_failure.py

Unit tests for Phase 9.8 — deterministic failure scenario and error attribute
mapping through the normalization pipeline.

Requires demo-app/ on PYTHONPATH:

    PYTHONPATH=demo-app python -m pytest storage-consumer/tests/unit/ -q

Covers:
  - FAIL_TRIGGER constant is a non-empty string
  - run_tool(FAIL_TRIGGER) raises ToolExecutionError
  - ToolExecutionError message is descriptive (mentions 'unavailable')
  - Case-insensitive matching: FAIL_TRIGGER.upper() also raises
  - Known technology queries are unaffected (no regression)
  - not_found queries are unaffected (no regression)
  - Empty query is unaffected (no regression)
  - ToolExecutionError is a subclass of RuntimeError
  - normalization.py maps error.type attribute → CanonicalSpanEvent.error_type
  - normalization.py maps error.message attribute → CanonicalSpanEvent.error_message
  - Missing error attributes produce None fields (no spurious error data)
  - status_code="ERROR" is preserved through normalization
  - Unrelated attributes do not contaminate error fields
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agents.tool_agent import (
    FAIL_TRIGGER,
    _FAIL_TRIGGER_NORMALIZED,
    TOOL_NAME,
    ToolExecutionError,
    run_tool,
)
from agents.research import _derive_retrieval_query
from observability.normalization import normalize_span


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _base_span_data(**overrides):
    """Minimal valid span_data dict for normalize_span()."""
    now = _now()
    data = {
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "parent_span_id": None,
        "span_name": "tool.execute",
        "span_kind": "INTERNAL",
        "service_name": "agentops-demo-app",
        "start_time": now,
        "end_time": now,
        "status_code": "OK",
        "status_message": None,
        "attributes": {},
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# FAIL_TRIGGER constant and its normalized form
# ---------------------------------------------------------------------------

class TestFailTriggerConstant:
    def test_is_non_empty_string(self):
        assert isinstance(FAIL_TRIGGER, str)
        assert len(FAIL_TRIGGER) > 0

    def test_is_lowercase(self):
        assert FAIL_TRIGGER == FAIL_TRIGGER.lower()

    def test_normalized_form_exists(self):
        assert isinstance(_FAIL_TRIGGER_NORMALIZED, str)
        assert len(_FAIL_TRIGGER_NORMALIZED) > 0

    def test_normalized_form_replaces_underscores_with_spaces(self):
        # research._tokenize() replaces non-alnum chars (including _) with spaces
        assert "_" not in _FAIL_TRIGGER_NORMALIZED

    def test_normalized_form_matches_research_pipeline(self):
        # _derive_retrieval_query is the exact function the pipeline uses;
        # its output must equal _FAIL_TRIGGER_NORMALIZED so the trigger fires.
        assert _derive_retrieval_query(FAIL_TRIGGER) == _FAIL_TRIGGER_NORMALIZED


# ---------------------------------------------------------------------------
# run_tool() — failure scenario
# ---------------------------------------------------------------------------

class TestRunToolFailureTrigger:
    def test_raises_on_literal_trigger(self):
        """User types FAIL_TRIGGER directly."""
        with pytest.raises(ToolExecutionError):
            run_tool(FAIL_TRIGGER)

    def test_raises_on_pipeline_normalized_form(self):
        """Trigger arrives via LangGraph after research._derive_retrieval_query()."""
        with pytest.raises(ToolExecutionError):
            run_tool(_FAIL_TRIGGER_NORMALIZED)

    def test_end_to_end_normalization_chain(self):
        """Simulate the full pipeline: FAIL_TRIGGER → research → run_tool."""
        normalized = _derive_retrieval_query(FAIL_TRIGGER)
        with pytest.raises(ToolExecutionError):
            run_tool(normalized)

    def test_error_message_mentions_unavailable(self):
        with pytest.raises(ToolExecutionError) as exc_info:
            run_tool(_FAIL_TRIGGER_NORMALIZED)
        assert "unavailable" in str(exc_info.value).lower()

    def test_case_insensitive_match_on_literal(self):
        with pytest.raises(ToolExecutionError):
            run_tool(FAIL_TRIGGER.upper())

    def test_strip_before_match(self):
        with pytest.raises(ToolExecutionError):
            run_tool("  " + FAIL_TRIGGER + "  ")

    def test_is_runtime_error_subclass(self):
        assert issubclass(ToolExecutionError, RuntimeError)


# ---------------------------------------------------------------------------
# run_tool() — non-regression for existing paths
# ---------------------------------------------------------------------------

class TestRunToolNoRegression:
    def test_known_technology_unaffected(self):
        result = run_tool("langgraph")
        assert result.status == "success"
        assert result.tool_name == TOOL_NAME

    def test_another_known_technology_unaffected(self):
        result = run_tool("kafka")
        assert result.status == "success"

    def test_not_found_query_unaffected(self):
        result = run_tool("totally_unknown_service")
        assert result.status == "not_found"

    def test_empty_query_unaffected(self):
        result = run_tool("")
        assert result.status == "not_found"

    def test_whitespace_only_query_unaffected(self):
        result = run_tool("   ")
        assert result.status == "not_found"


# ---------------------------------------------------------------------------
# normalization.py — error attribute mapping
# ---------------------------------------------------------------------------

class TestNormalizationErrorAttributes:
    def test_error_type_attribute_mapped(self):
        data = _base_span_data(
            attributes={"error.type": "ToolExecutionError"}
        )
        event = normalize_span(data)
        assert event.error_type == "ToolExecutionError"

    def test_error_message_attribute_mapped(self):
        data = _base_span_data(
            attributes={
                "error.type": "ToolExecutionError",
                "error.message": (
                    "External service unavailable: "
                    "connection refused to metadata.example.internal"
                ),
            }
        )
        event = normalize_span(data)
        assert "unavailable" in event.error_message

    def test_missing_error_type_gives_none(self):
        data = _base_span_data(attributes={})
        event = normalize_span(data)
        assert event.error_type is None

    def test_missing_error_message_gives_none(self):
        data = _base_span_data(attributes={})
        event = normalize_span(data)
        assert event.error_message is None

    def test_error_status_code_preserved(self):
        data = _base_span_data(status_code="ERROR")
        event = normalize_span(data)
        assert event.status_code == "ERROR"

    def test_error_type_does_not_pollute_other_fields(self):
        data = _base_span_data(
            attributes={"error.type": "ToolExecutionError"}
        )
        event = normalize_span(data)
        assert event.agent_name is None
        assert event.tool_name is None
        assert event.error_message is None

    def test_agent_and_error_attributes_promoted_independently(self):
        data = _base_span_data(
            status_code="ERROR",
            attributes={
                "agent.name": "tool_agent",
                "agent.operation": "execute",
                "error.type": "ToolExecutionError",
                "error.message": "service unavailable",
            },
        )
        event = normalize_span(data)
        assert event.agent_name == "tool_agent"
        assert event.agent_operation == "execute"
        assert event.error_type == "ToolExecutionError"
        assert event.error_message == "service unavailable"
        assert event.status_code == "ERROR"
