"""
stream-processor/canonicalizer.py

Converts a decoded OTLP span dict (as produced by otlp_decoder.decode())
into a CanonicalSpanEvent by delegating to normalize_span() from the
existing demo-app observability layer.

Requires demo-app/ on PYTHONPATH:
    PYTHONPATH=/path/to/demo-app python ...

This module has NO knowledge of DLQ concepts. It raises
CanonicalizationError which callers may map to DLQ reasons as appropriate.
"""

from __future__ import annotations

import enum
from typing import Any, Callable

import pydantic

# Attempt to import at module load time so unit tests can patch
# canonicalizer._normalize_span via monkeypatch.setattr without needing
# demo-app/ on PYTHONPATH. canonicalize() raises RuntimeError at call time
# if the import failed.
_normalize_span: Callable[[dict[str, Any]], Any] | None = None
try:
    from observability.normalization import normalize_span as _normalize_span
except ImportError:
    pass


class CanonicalizationErrorType(enum.Enum):
    """Classification of why canonicalization failed."""

    SCHEMA_VALIDATION_FAILURE = "SCHEMA_VALIDATION_FAILURE"
    UNEXPECTED_FAILURE = "UNEXPECTED_FAILURE"


class CanonicalizationError(Exception):
    """Raised when a span dict cannot be converted to a CanonicalSpanEvent."""

    def __init__(
        self,
        error_type: CanonicalizationErrorType,
        message: str,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.message = message


def canonicalize(span_dict: dict[str, Any]) -> Any:
    """
    Convert a decoded OTLP span dict into a CanonicalSpanEvent.

    span_dict must satisfy the normalize_span() input contract (all 11
    keys produced by otlp_decoder.decode()):
        trace_id, span_id, parent_span_id, span_name, span_kind,
        start_time, end_time, status_code, status_message,
        service_name, attributes.

    Returns:
        CanonicalSpanEvent (type from demo-app/schemas/telemetry.py)

    Raises:
        RuntimeError: if demo-app/ is not on PYTHONPATH.
        CanonicalizationError: if normalize_span() rejects the span dict.
    """
    if _normalize_span is None:
        raise RuntimeError(
            "canonicalize() requires demo-app/ on PYTHONPATH "
            "(observability.normalization could not be imported at module load)"
        )
    try:
        return _normalize_span(span_dict)
    except pydantic.ValidationError as exc:
        raise CanonicalizationError(
            CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE,
            str(exc),
        ) from exc
    except Exception as exc:
        raise CanonicalizationError(
            CanonicalizationErrorType.UNEXPECTED_FAILURE,
            str(exc),
        ) from exc
