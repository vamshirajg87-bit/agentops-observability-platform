"""
tests/unit/test_canonicalizer.py

Unit and contract tests for canonicalizer.py.

Mocked tests (class TestCanonicalizeMocked) patch canonicalizer._normalize_span
and do NOT require demo-app/ on PYTHONPATH.

Integration / contract tests (class TestCanonicalizeContract) call the real
normalize_span() and CanonicalSpanEvent. They are marked @pytest.mark.integration
and skipped automatically when demo-app/ is not on PYTHONPATH.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pydantic
import pytest

import canonicalizer
from canonicalizer import (
    CanonicalizationError,
    CanonicalizationErrorType,
    canonicalize,
)

# ---------------------------------------------------------------------------
# Shared test data — mirrors exactly what otlp_decoder.decode() produces
# ---------------------------------------------------------------------------

TRACE_ID_HEX = "0102030405060708090a0b0c0d0e0f10"
SPAN_ID_HEX = "0102030405060708"
START_NS = 1_700_000_000_000_000_000
END_NS = 1_700_000_001_000_000_000  # +1 second

VALID_SPAN_DICT: dict = {
    "trace_id": TRACE_ID_HEX,
    "span_id": SPAN_ID_HEX,
    "parent_span_id": None,
    "span_name": "test.span",
    "span_kind": "INTERNAL",
    "start_time": datetime.fromtimestamp(START_NS / 1_000_000_000, tz=timezone.utc),
    "end_time": datetime.fromtimestamp(END_NS / 1_000_000_000, tz=timezone.utc),
    "status_code": "OK",
    "status_message": None,
    "service_name": "test-service",
    "attributes": {},
}


def _make_validation_error() -> pydantic.ValidationError:
    """Build a real Pydantic v2 ValidationError for use in mocked tests."""

    class _Stub(pydantic.BaseModel):
        x: int

    try:
        _Stub(x="not-an-int")  # type: ignore[arg-type]
    except pydantic.ValidationError as exc:
        return exc
    raise AssertionError("Expected ValidationError was not raised")


# ---------------------------------------------------------------------------
# Mocked unit tests — no PYTHONPATH required
# ---------------------------------------------------------------------------


class TestCanonicalizeMocked:
    def test_happy_path_returns_normalize_span_result(self, monkeypatch):
        sentinel = object()
        monkeypatch.setattr(canonicalizer, "_normalize_span", lambda _: sentinel)
        assert canonicalize(VALID_SPAN_DICT) is sentinel

    def test_validation_error_raises_canonicalization_error(self, monkeypatch):
        exc = _make_validation_error()

        def _raise(_):
            raise exc

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert info.value.error_type == CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE

    def test_validation_error_preserves_cause(self, monkeypatch):
        exc = _make_validation_error()

        def _raise(_):
            raise exc

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert info.value.__cause__ is exc

    def test_unexpected_exception_raises_canonicalization_error(self, monkeypatch):
        def _raise(_):
            raise RuntimeError("unexpected boom")

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert info.value.error_type == CanonicalizationErrorType.UNEXPECTED_FAILURE

    def test_unexpected_exception_preserves_cause(self, monkeypatch):
        original = RuntimeError("unexpected boom")

        def _raise(_):
            raise original

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert info.value.__cause__ is original

    def test_canonicalization_error_message_is_non_empty(self, monkeypatch):
        def _raise(_):
            raise RuntimeError("something broke")

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert info.value.message

    def test_error_type_attribute_schema_validation(self, monkeypatch):
        exc = _make_validation_error()

        def _raise(_):
            raise exc

        monkeypatch.setattr(canonicalizer, "_normalize_span", _raise)
        with pytest.raises(CanonicalizationError) as info:
            canonicalize(VALID_SPAN_DICT)
        assert isinstance(info.value.error_type, CanonicalizationErrorType)

    def test_canonicalizer_has_no_dlq_import(self):
        """canonicalizer.py must not import from dlq — independence invariant."""
        source = inspect.getsource(canonicalizer)
        assert "import dlq" not in source
        assert "from dlq" not in source

    def test_runtime_error_when_normalize_span_unavailable(self, monkeypatch):
        monkeypatch.setattr(canonicalizer, "_normalize_span", None)
        with pytest.raises(RuntimeError, match="PYTHONPATH"):
            canonicalize(VALID_SPAN_DICT)


# ---------------------------------------------------------------------------
# Contract / integration tests — require demo-app/ on PYTHONPATH
# ---------------------------------------------------------------------------

observability = pytest.importorskip(
    "observability.normalization",
    reason="demo-app/ not on PYTHONPATH — skipping contract tests",
)


class TestCanonicalizeContract:
    """
    These tests call the real normalize_span() and CanonicalSpanEvent.
    They detect drift between the otlp_decoder output contract and the
    canonical schema — if the decoder produces a dict that normalize_span()
    can no longer accept, these tests fail.
    """

    @pytest.mark.integration
    def test_valid_decoder_output_produces_canonical_span_event(self):
        """
        A span dict structured exactly as otlp_decoder.decode() produces
        must pass through normalize_span() and return a CanonicalSpanEvent.
        """
        from schemas.telemetry import CanonicalSpanEvent

        result = canonicalize(VALID_SPAN_DICT)
        assert isinstance(result, CanonicalSpanEvent)

    @pytest.mark.integration
    def test_all_required_fields_preserved(self):
        """Fields written by the decoder survive canonicalization unchanged."""
        result = canonicalize(VALID_SPAN_DICT)
        assert result.trace_id == TRACE_ID_HEX
        assert result.span_id == SPAN_ID_HEX
        assert result.parent_span_id is None
        assert result.span_name == "test.span"
        assert result.span_kind == "INTERNAL"
        assert result.status_code == "OK"
        assert result.status_message is None
        assert result.service_name == "test-service"

    @pytest.mark.integration
    def test_duration_ms_is_computed(self):
        """normalize_span() computes duration_ms; verify it matches the timestamps."""
        result = canonicalize(VALID_SPAN_DICT)
        expected_ms = (
            VALID_SPAN_DICT["end_time"] - VALID_SPAN_DICT["start_time"]
        ).total_seconds() * 1000.0
        assert abs(result.duration_ms - expected_ms) < 1e-6

    @pytest.mark.integration
    def test_end_before_start_raises_canonicalization_error(self):
        """
        A span dict where end_time < start_time must be caught by the
        CanonicalSpanEvent model validator and wrapped as
        CanonicalizationError(SCHEMA_VALIDATION_FAILURE).
        """
        bad = dict(VALID_SPAN_DICT)
        bad["end_time"] = VALID_SPAN_DICT["start_time"]
        bad["start_time"] = VALID_SPAN_DICT["end_time"]  # swap: end < start

        with pytest.raises(CanonicalizationError) as info:
            canonicalize(bad)
        assert info.value.error_type == CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE

    @pytest.mark.integration
    def test_invalid_trace_id_raises_canonicalization_error(self):
        """
        A trace_id that is not 32 hex characters must be rejected by the
        CanonicalSpanEvent field validator and wrapped as
        CanonicalizationError(SCHEMA_VALIDATION_FAILURE).
        """
        bad = dict(VALID_SPAN_DICT)
        bad["trace_id"] = "tooshort"

        with pytest.raises(CanonicalizationError) as info:
            canonicalize(bad)
        assert info.value.error_type == CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE

    @pytest.mark.integration
    def test_attributes_are_passed_through(self):
        """AgentOps-specific attributes in the span dict appear in the result."""
        span = dict(VALID_SPAN_DICT)
        span["attributes"] = {
            "agentops.request_id": "req_abc123",
            "agentops.session_id": "sess_xyz",
            "agent.name": "supervisor",
        }
        result = canonicalize(span)
        assert result.request_id == "req_abc123"
        assert result.session_id == "sess_xyz"
        assert result.agent_name == "supervisor"
