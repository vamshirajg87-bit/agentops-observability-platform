"""
incident-retrieval/incident_document.py

Phase 12.3: Deterministic semantic incident document builder.

Converts one persisted RCA investigation and its ranked evidence into the
locked Phase 12.1 embedding document.  The same input always produces the
same text, byte for byte.

Document format (doc_version 1.0.0):

    anomaly: {anomaly_type}
    signal: {derived_signal}
    service: {service}
    operation: {operation}
    evidence:
      span "{span_name}" service "{service_name}" status {status}{optional} evidence-type {evidence_type}
      ...

    With zero informative evidence the last line is "evidence: none".

    Lines are separated by LF.  There is no trailing newline.

Optional evidence tokens, in this exact order, each preceded by one space:

    direct-subject                  when is_direct_subject is true
    root-span                       when is_root_span is true
    error-type "{error_type}"
    tool "{tool_name}"
    tool-status "{tool_status}"
    agent "{agent_name}"
    agent-op "{agent_operation}"
    retrieval-results {bucket}
    retrieval-relevance {bucket}
    duration {bucket}

Text normalization (every semantic textual value):
    1. Unicode NFC
    2. collapse Unicode whitespace runs to one ASCII space
    3. strip leading/trailing whitespace
    4. an empty result is treated as NULL
    Case is preserved.  The assembled document is NFC-normalized again.

Quoted values are escaped after normalization: \\ -> \\\\ and " -> \\".
Header values are unquoted and are not escaped.

Evidence selection:
    1. rank_position ASC
    2. remove rows where evidence_type == "telemetry" AND evidence_score == 0.0
    3. take the first 5 remaining
    4. preserve that order

Eligibility:
    confidence == "INSUFFICIENT_DATA" is not eligible for embedding; the
    result carries eligible=False and text=None.  Every other confidence is
    eligible, including when no informative evidence remains.

Input validation (ValueError on violation; values are never coerced):
    investigation_id, confidence   str with at least one non-whitespace
                                   character; compared exactly, never
                                   normalized (also the evidence
                                   investigation_id)
    required text                  str (anomaly_type, derived_signal,
                                   evidence_type)
    other text                     str or None
    all semantic text              strict UTF-8 encodable; an unpaired
                                   surrogate is rejected, never repaired
    is_direct_subject, is_root_span  actual bool; truthiness is not used
    rank_position                  int >= 0; unique within the evidence
    retrieval_result_count         None or int >= 0
    evidence_score                 finite int or float
    retrieval_top_relevance_score, trace_duration_fraction
                                   None or finite int or float >= 0
    bool is never accepted as a number.
    For an eligible investigation every supplied evidence row is validated
    before filtering and before the top-5 cut.

derived_signal is supplied by the caller.  This module does not derive it and
does not import any RCA scoring or confidence logic.

Standard library only.  No database access, no I/O, no embedding model.

Public API:
    DOC_VERSION                — version of the document contract ("1.0.0")
    InvestigationRow           — input: one investigation (frozen dataclass)
    EvidenceRow                — input: one evidence row (frozen dataclass)
    IncidentDocument           — output: eligibility and document text
    build_incident_document()  — investigation + evidence + signal → document
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from typing import Optional, Sequence


DOC_VERSION: str = "1.0.0"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UNKNOWN: str = "unknown"

# Investigations with this confidence carry no evidence and are not embedded.
_INELIGIBLE_CONFIDENCE: str = "INSUFFICIENT_DATA"

_MAX_EVIDENCE_LINES: int = 5

# Rows of this type with a score of exactly 0.0 carry no positive evidence.
_UNINFORMATIVE_EVIDENCE_TYPE: str = "telemetry"

_STATUS_CODES: frozenset[str] = frozenset({"OK", "ERROR", "UNSET"})
_UNKNOWN_STATUS: str = "UNKNOWN"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvestigationRow:
    """
    The investigation fields used by the document builder.

    Mirrors a subset of the public.rca_investigations columns readable by the
    incident_retrieval role.
    """

    investigation_id: str
    anomaly_type: str
    service_name: Optional[str]
    operation_name: Optional[str]
    confidence: str


@dataclass(frozen=True)
class EvidenceRow:
    """
    The evidence fields used by the document builder.

    Mirrors the public.rca_evidence columns readable by the incident_retrieval
    role.
    """

    investigation_id: str
    rank_position: int
    evidence_type: str
    evidence_score: float
    span_name: Optional[str]
    service_name: Optional[str]
    status_code: Optional[str]
    error_type: Optional[str]
    tool_name: Optional[str]
    tool_status: Optional[str]
    agent_name: Optional[str]
    agent_operation: Optional[str]
    retrieval_result_count: Optional[int]
    retrieval_top_relevance_score: Optional[float]
    is_direct_subject: bool
    is_root_span: bool
    trace_duration_fraction: Optional[float]


@dataclass(frozen=True)
class IncidentDocument:
    """
    Outcome of one build_incident_document() call.

    Attributes
    ----------
    investigation_id
        Copied from the input investigation.  Never part of the text.
    doc_version
        The document contract version the text was rendered under.
    eligible
        False when the investigation must not be embedded.
    text
        The document text; None when eligible is False.
    """

    investigation_id: str
    doc_version: str
    eligible: bool
    text: Optional[str]


# ---------------------------------------------------------------------------
# Text normalization
# ---------------------------------------------------------------------------

def _normalize_text(value: Optional[str], field_name: str) -> Optional[str]:
    """
    Normalize one semantic textual value.

    NFC, then collapse whitespace runs to one ASCII space and strip the ends.
    Returns None for None and for values that are empty after normalization.
    Raises ValueError when value is neither str nor None; other types are
    never converted to text.  Raises ValueError when value cannot be encoded
    as strict UTF-8 (an unpaired surrogate); such text is never repaired.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be str or None, got {type(value).__name__}"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            f"{field_name} is not UTF-8 encodable (unpaired surrogate)"
        ) from None
    normalized = " ".join(unicodedata.normalize("NFC", value).split())
    return normalized or None


def _required_text(value: str, field_name: str) -> str:
    """Normalize a required str; ValueError when not a str or nothing remains."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be str, got {type(value).__name__}")
    normalized = _normalize_text(value, field_name)
    if normalized is None:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _text_or_unknown(value: Optional[str], field_name: str) -> str:
    """Normalize a value; 'unknown' when nothing remains."""
    normalized = _normalize_text(value, field_name)
    return _UNKNOWN if normalized is None else normalized


def _quote(normalized: str) -> str:
    """Escape backslash and double quote, then wrap in double quotes."""
    escaped = normalized.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _normalize_status(status_code: Optional[str]) -> str:
    """Exact, case-sensitive mapping; anything unrecognised is UNKNOWN."""
    normalized = _normalize_text(status_code, "status_code")
    return normalized if normalized in _STATUS_CODES else _UNKNOWN_STATUS


def _exact_identity(value: str, field_name: str) -> str:
    """
    Return a str holding at least one non-whitespace character, unchanged.

    Used for values that are compared exactly (investigation_id, confidence).
    These are deliberately not normalized: strip() is used only to detect an
    empty or whitespace-only value, and the original value is returned.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be str, got {type(value).__name__}")
    if value.strip() == "":
        raise ValueError(f"{field_name} must not be empty or whitespace-only")
    return value


# ---------------------------------------------------------------------------
# Typed value validation
# ---------------------------------------------------------------------------

def _require_bool(value: bool, field_name: str) -> bool:
    """Return an actual bool unchanged; truthiness is never used."""
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be bool, got {type(value).__name__}")
    return value


def _non_negative_int(value: int, field_name: str) -> int:
    """Return an actual int >= 0 unchanged; bool and float are rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0, got {value!r}")
    return value


def _finite_real(value: float, field_name: str) -> float:
    """Return a finite int or float unchanged; bool, NaN and infinity are rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            f"{field_name} must be a real number, got {type(value).__name__}"
        )
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field_name} must be finite, got {value!r}")
    return value


def _non_negative_real(value: float, field_name: str) -> float:
    """Return a finite int or float >= 0 unchanged."""
    value = _finite_real(value, field_name)
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------

def _retrieval_results_bucket(count: Optional[int]) -> Optional[str]:
    if count is None:
        return None
    count = _non_negative_int(count, "retrieval_result_count")
    if count == 0:
        return "zero"
    if count < 3:
        return "very-few"
    if count < 10:
        return "few"
    return "some"


def _retrieval_relevance_bucket(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    score = _non_negative_real(score, "retrieval_top_relevance_score")
    if score < 0.2:
        return "very-low"
    if score < 0.4:
        return "low"
    if score < 0.6:
        return "moderate"
    return "high"


def _duration_bucket(fraction: Optional[float]) -> Optional[str]:
    if fraction is None:
        return None
    fraction = _non_negative_real(fraction, "trace_duration_fraction")
    if fraction < 0.25:
        return "minor"
    if fraction < 0.5:
        return "moderate"
    if fraction < 0.75:
        return "significant"
    if fraction <= 1.0:
        return "dominant"
    return "anomalous"


# ---------------------------------------------------------------------------
# Evidence rendering
# ---------------------------------------------------------------------------

def _render_evidence_line(row: EvidenceRow, evidence_type: str) -> str:
    """
    Render one evidence line.

    evidence_type is the already-normalized value.  Raises ValueError when a
    text field is not str/None, a flag is not a bool, or a bucket input has
    the wrong type, is negative, or is not finite.
    """
    tokens: list[str] = [
        " ",  # joined with single spaces, this yields the two-space indent
        "span", _quote(_text_or_unknown(row.span_name, "span_name")),
        "service", _quote(_text_or_unknown(row.service_name, "service_name")),
        "status", _normalize_status(row.status_code),
    ]

    if _require_bool(row.is_direct_subject, "is_direct_subject"):
        tokens.append("direct-subject")
    if _require_bool(row.is_root_span, "is_root_span"):
        tokens.append("root-span")

    for label, field_name, value in (
        ("error-type", "error_type", row.error_type),
        ("tool", "tool_name", row.tool_name),
        ("tool-status", "tool_status", row.tool_status),
        ("agent", "agent_name", row.agent_name),
        ("agent-op", "agent_operation", row.agent_operation),
    ):
        normalized = _normalize_text(value, field_name)
        if normalized is not None:
            tokens.extend((label, _quote(normalized)))

    for label, bucket in (
        ("retrieval-results", _retrieval_results_bucket(row.retrieval_result_count)),
        ("retrieval-relevance", _retrieval_relevance_bucket(row.retrieval_top_relevance_score)),
        ("duration", _duration_bucket(row.trace_duration_fraction)),
    ):
        if bucket is not None:
            tokens.extend((label, bucket))

    tokens.extend(("evidence-type", evidence_type))
    return " ".join(tokens)


def _evidence_lines(
    investigation_id: str,
    evidence: Sequence[EvidenceRow],
) -> list[str]:
    """
    Validate every supplied row, then select and render the evidence lines.

    Validation covers all rows, including rows that are later filtered out or
    fall beyond the first five.
    """
    seen_ranks: set[int] = set()
    for row in evidence:
        row_investigation_id = _exact_identity(
            row.investigation_id, "evidence investigation_id"
        )
        if row_investigation_id != investigation_id:
            raise ValueError(
                "evidence row does not belong to the investigation "
                f"(rank_position={row.rank_position!r})"
            )
        rank_position = _non_negative_int(row.rank_position, "rank_position")
        if rank_position in seen_ranks:
            raise ValueError(f"duplicate rank_position {rank_position!r}")
        seen_ranks.add(rank_position)

    # Rendering every row performs the remaining per-row validation
    # (text types, evidence_type present, flags, bucket inputs).
    rendered: list[tuple[int, bool, str]] = []
    for row in evidence:
        evidence_score = _finite_real(row.evidence_score, "evidence_score")
        evidence_type = _required_text(row.evidence_type, "evidence_type")
        informative = not (
            evidence_type == _UNINFORMATIVE_EVIDENCE_TYPE
            and evidence_score == 0.0
        )
        rendered.append(
            (row.rank_position, informative, _render_evidence_line(row, evidence_type))
        )

    rendered.sort(key=lambda item: item[0])
    lines = [line for _, informative, line in rendered if informative]
    return lines[:_MAX_EVIDENCE_LINES]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_incident_document(
    investigation: InvestigationRow,
    evidence: Sequence[EvidenceRow],
    *,
    derived_signal: str,
) -> IncidentDocument:
    """
    Build the semantic incident document for one investigation.

    Parameters
    ----------
    investigation
        The investigation to describe.
    evidence
        Evidence rows of that investigation, in any order.
    derived_signal
        The canonical signal name for the anomaly, supplied by the caller.

    Returns
    -------
    IncidentDocument
        eligible=False and text=None when confidence is exactly
        'INSUFFICIENT_DATA'; the header fields and the evidence are not
        inspected in that case.  Otherwise eligible=True and text holds the
        document.

    Raises
    ------
    ValueError
        investigation_id or confidence is not a str, or is empty or
        whitespace-only (checked before eligibility is decided).

        For an eligible investigation, additionally: anomaly_type,
        derived_signal, or any evidence_type is not a str or is empty after
        normalization; any other text field is neither str nor None; any
        text contains an unpaired surrogate; an evidence investigation_id is
        not a str, is whitespace-only, or belongs to another investigation; rank_position is not
        an int >= 0 or is duplicated; a flag is not a bool; evidence_score is
        not a finite real number; or a bucket input has the wrong type, is
        negative, NaN, or infinite.  bool is never accepted as a number.
    """
    investigation_id = _exact_identity(
        investigation.investigation_id, "investigation_id"
    )
    confidence = _exact_identity(investigation.confidence, "confidence")

    # Exact comparison: confidence is deliberately not normalized.
    if confidence == _INELIGIBLE_CONFIDENCE:
        return IncidentDocument(
            investigation_id=investigation_id,
            doc_version=DOC_VERSION,
            eligible=False,
            text=None,
        )

    header = [
        f"anomaly: {_required_text(investigation.anomaly_type, 'anomaly_type')}",
        f"signal: {_required_text(derived_signal, 'derived_signal')}",
        f"service: {_text_or_unknown(investigation.service_name, 'service_name')}",
        f"operation: {_text_or_unknown(investigation.operation_name, 'operation_name')}",
    ]

    evidence_lines = _evidence_lines(investigation_id, evidence)
    if evidence_lines:
        lines = header + ["evidence:"] + evidence_lines
    else:
        lines = header + ["evidence: none"]

    text = unicodedata.normalize("NFC", "\n".join(lines))

    return IncidentDocument(
        investigation_id=investigation_id,
        doc_version=DOC_VERSION,
        eligible=True,
        text=text,
    )
