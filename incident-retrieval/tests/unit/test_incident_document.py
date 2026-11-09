"""
incident-retrieval/tests/unit/test_incident_document.py

Unit tests for incident_document.py.

All tests are pure Python — no database, no network, no I/O beyond reading
the module source for the import-boundary check.

Test inventory:
    D01  DOC_VERSION and the public data models
    D02  Header: exact lines, derived_signal input, required text
    D03  Text normalization: NFC, whitespace collapse, case preservation
    D04  Quote and backslash escaping
    D05  Output format: LF only, no trailing newline, no trailing spaces
    D06  'unknown' placeholders
    D07  Optional text fields: omission and ordering
    D08  Boolean flags
    D09  Status normalization
    D10  Evidence sorting, telemetry-zero filtering, top-5 cap
    D11  Evidence validation: duplicate rank, investigation mismatch
    D12  Bucket boundaries
    D13  Numeric rejection: negative, NaN, infinity
    D14  Eligibility: INSUFFICIENT_DATA early return
    D15  'evidence: none'
    D16  Determinism, input-order independence, no input mutation
    D17  Excluded information never leaks into the document
    D18  Golden documents
    D19  Purity / import boundary
    D20  Input hardening: identity, text, flag, and numeric types
    D21  Whitespace-only identity values
    D22  UTF-8 encodability: unpaired surrogates rejected
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import math
import os
import random
import unicodedata

import pytest

import incident_document
from incident_document import (
    DOC_VERSION,
    EvidenceRow,
    IncidentDocument,
    InvestigationRow,
    build_incident_document,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INV_ID = "a" * 64
_OTHER_INV_ID = "b" * 64

_MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "incident_document.py")
)


def _make_investigation(
    investigation_id: str = _INV_ID,
    anomaly_type: str = "latency",
    service_name: str | None = "checkout",
    operation_name: str | None = "research/plan",
    confidence: str = "HIGH",
) -> InvestigationRow:
    return InvestigationRow(
        investigation_id=investigation_id,
        anomaly_type=anomaly_type,
        service_name=service_name,
        operation_name=operation_name,
        confidence=confidence,
    )


def _make_evidence(
    rank_position: int = 1,
    investigation_id: str = _INV_ID,
    evidence_type: str = "duration",
    evidence_score: float = 0.5,
    span_name: str | None = "research.plan",
    service_name: str | None = "checkout",
    status_code: str | None = "OK",
    error_type: str | None = None,
    tool_name: str | None = None,
    tool_status: str | None = None,
    agent_name: str | None = None,
    agent_operation: str | None = None,
    retrieval_result_count: int | None = None,
    retrieval_top_relevance_score: float | None = None,
    is_direct_subject: bool = False,
    is_root_span: bool = False,
    trace_duration_fraction: float | None = None,
) -> EvidenceRow:
    return EvidenceRow(
        investigation_id=investigation_id,
        rank_position=rank_position,
        evidence_type=evidence_type,
        evidence_score=evidence_score,
        span_name=span_name,
        service_name=service_name,
        status_code=status_code,
        error_type=error_type,
        tool_name=tool_name,
        tool_status=tool_status,
        agent_name=agent_name,
        agent_operation=agent_operation,
        retrieval_result_count=retrieval_result_count,
        retrieval_top_relevance_score=retrieval_top_relevance_score,
        is_direct_subject=is_direct_subject,
        is_root_span=is_root_span,
        trace_duration_fraction=trace_duration_fraction,
    )


def _build(investigation=None, evidence=(), derived_signal="agent_latency"):
    return build_incident_document(
        investigation if investigation is not None else _make_investigation(),
        evidence,
        derived_signal=derived_signal,
    )


def _text(investigation=None, evidence=(), derived_signal="agent_latency") -> str:
    doc = _build(investigation, evidence, derived_signal)
    assert doc.eligible is True
    assert doc.text is not None
    doc.text.encode("utf-8")  # every eligible document must be UTF-8 encodable
    return doc.text


def _evidence_lines(text: str) -> list[str]:
    """The lines following the 'evidence:' line."""
    lines = text.split("\n")
    assert lines[4] == "evidence:"
    return lines[5:]


def _only_line(**evidence_kwargs) -> str:
    """Render a single evidence row and return its line."""
    lines = _evidence_lines(_text(evidence=[_make_evidence(**evidence_kwargs)]))
    assert len(lines) == 1
    return lines[0]


def _below(x: float) -> float:
    """The largest float strictly less than x."""
    return math.nextafter(x, -math.inf)


def _above(x: float) -> float:
    """The smallest float strictly greater than x."""
    return math.nextafter(x, math.inf)


# ---------------------------------------------------------------------------
# D01  DOC_VERSION and the public data models
# ---------------------------------------------------------------------------

class TestVersionAndModels:

    def test_doc_version_is_1_0_0(self):
        assert DOC_VERSION == "1.0.0"

    def test_result_carries_doc_version(self):
        assert _build().doc_version == "1.0.0"

    def test_result_carries_investigation_id(self):
        assert _build().investigation_id == _INV_ID

    def test_result_is_incident_document(self):
        assert isinstance(_build(), IncidentDocument)

    @pytest.mark.parametrize("cls", [InvestigationRow, EvidenceRow, IncidentDocument])
    def test_models_are_frozen_dataclasses(self, cls):
        assert dataclasses.is_dataclass(cls)
        assert cls.__dataclass_params__.frozen is True

    def test_investigation_row_is_immutable(self):
        row = _make_investigation()
        with pytest.raises(dataclasses.FrozenInstanceError):
            row.confidence = "LOW"  # type: ignore[misc]

    def test_evidence_row_is_immutable(self):
        row = _make_evidence()
        with pytest.raises(dataclasses.FrozenInstanceError):
            row.rank_position = 2  # type: ignore[misc]

    def test_incident_document_is_immutable(self):
        doc = _build()
        with pytest.raises(dataclasses.FrozenInstanceError):
            doc.text = "tampered"  # type: ignore[misc]

    def test_investigation_row_fields_exact(self):
        assert [f.name for f in dataclasses.fields(InvestigationRow)] == [
            "investigation_id",
            "anomaly_type",
            "service_name",
            "operation_name",
            "confidence",
        ]

    def test_evidence_row_fields_exact(self):
        assert [f.name for f in dataclasses.fields(EvidenceRow)] == [
            "investigation_id",
            "rank_position",
            "evidence_type",
            "evidence_score",
            "span_name",
            "service_name",
            "status_code",
            "error_type",
            "tool_name",
            "tool_status",
            "agent_name",
            "agent_operation",
            "retrieval_result_count",
            "retrieval_top_relevance_score",
            "is_direct_subject",
            "is_root_span",
            "trace_duration_fraction",
        ]

    def test_incident_document_fields_exact(self):
        assert [f.name for f in dataclasses.fields(IncidentDocument)] == [
            "investigation_id",
            "doc_version",
            "eligible",
            "text",
        ]

    def test_derived_signal_is_keyword_only(self):
        with pytest.raises(TypeError):
            build_incident_document(_make_investigation(), [], "agent_latency")  # type: ignore[misc]

    def test_derived_signal_is_required(self):
        with pytest.raises(TypeError):
            build_incident_document(_make_investigation(), [])  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# D02  Header
# ---------------------------------------------------------------------------

class TestHeader:

    def test_exact_header_lines_in_order(self):
        text = _text(evidence=[_make_evidence()])
        assert text.split("\n")[:5] == [
            "anomaly: latency",
            "signal: agent_latency",
            "service: checkout",
            "operation: research/plan",
            "evidence:",
        ]

    def test_signal_comes_from_derived_signal_argument(self):
        text = _text(derived_signal="trace_latency")
        assert text.split("\n")[1] == "signal: trace_latency"

    @pytest.mark.parametrize(
        "anomaly_type, operation_name",
        [
            ("latency", "trace"),
            ("latency", "tool.execute"),
            ("latency", None),
            ("tool_failure", "tool.execute/ToolExecutionError"),
        ],
    )
    def test_signal_is_never_derived_from_other_fields(self, anomaly_type, operation_name):
        """Whatever the anomaly looks like, the signal line echoes the argument."""
        inv = _make_investigation(anomaly_type=anomaly_type, operation_name=operation_name)
        text = _text(inv, derived_signal="caller-supplied-signal")
        assert text.split("\n")[1] == "signal: caller-supplied-signal"

    def test_header_values_are_unquoted(self):
        header = _text().split("\n")[:4]
        assert all('"' not in line for line in header)

    def test_header_values_are_not_escaped(self):
        inv = _make_investigation(service_name='svc"a\\b', operation_name='op\\"x')
        lines = _text(inv, derived_signal='sig"\\').split("\n")
        assert lines[1] == 'signal: sig"\\'
        assert lines[2] == 'service: svc"a\\b'
        assert lines[3] == 'operation: op\\"x'

    def test_header_values_are_normalized(self):
        inv = _make_investigation(
            anomaly_type="  tool_failure ",
            service_name="pay\t\tments  api",
            operation_name="\n tool.execute/Err \n",
        )
        lines = _text(inv, derived_signal="  tool_failure\u00a0").split("\n")
        assert lines[:4] == [
            "anomaly: tool_failure",
            "signal: tool_failure",
            "service: pay ments api",
            "operation: tool.execute/Err",
        ]

    @pytest.mark.parametrize("value", ["", "   ", "\t\n", "\u00a0\u2003"])
    def test_empty_anomaly_type_raises(self, value):
        with pytest.raises(ValueError, match="anomaly_type"):
            _build(_make_investigation(anomaly_type=value))

    @pytest.mark.parametrize("value", ["", "   ", "\t\n", "\u00a0\u2003"])
    def test_empty_derived_signal_raises(self, value):
        with pytest.raises(ValueError, match="derived_signal"):
            _build(derived_signal=value)

    def test_none_anomaly_type_raises(self):
        with pytest.raises(ValueError, match="anomaly_type"):
            _build(_make_investigation(anomaly_type=None))  # type: ignore[arg-type]

    def test_none_derived_signal_raises(self):
        with pytest.raises(ValueError, match="derived_signal"):
            _build(derived_signal=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# D03  Text normalization
# ---------------------------------------------------------------------------

class TestNormalization:

    def test_nfc_composes_decomposed_span_name(self):
        line = _only_line(span_name="cafe\u0301.search")
        assert 'span "caf\u00e9.search"' in line
        assert "\u0301" not in line

    def test_nfc_applied_to_header(self):
        inv = _make_investigation(service_name="cafe\u0301")
        assert _text(inv).split("\n")[2] == "service: caf\u00e9"

    def test_nfc_equivalent_inputs_produce_identical_documents(self):
        composed = _text(evidence=[_make_evidence(span_name="caf\u00e9", agent_name="\u00c5ngstr\u00f6m")])
        decomposed = _text(evidence=[_make_evidence(span_name="cafe\u0301", agent_name="A\u030angstro\u0308m")])
        assert composed == decomposed

    def test_whole_document_is_nfc(self):
        text = _text(
            _make_investigation(service_name="e\u0301", operation_name="o\u0308p"),
            [_make_evidence(span_name="a\u030a", error_type="n\u0303")],
            derived_signal="u\u0308",
        )
        assert text == unicodedata.normalize("NFC", text)

    def test_nfc_does_not_apply_compatibility_folding(self):
        """NFC, not NFKC: the ligature and full-width forms are preserved."""
        line = _only_line(span_name="\ufb01le\uff21")
        assert 'span "\ufb01le\uff21"' in line

    @pytest.mark.parametrize(
        "raw",
        [
            "tool   execute",
            "tool\texecute",
            "tool\nexecute",
            "tool\r\nexecute",
            "tool \t\r\n execute",
            "tool\u00a0execute",        # no-break space
            "tool\u2003execute",        # em space
            "tool\u2028execute",        # line separator
            "tool\u3000execute",        # ideographic space
            "  tool execute  ",
            "\n\ttool execute\u00a0",
        ],
    )
    def test_whitespace_runs_collapse_to_one_ascii_space(self, raw):
        assert 'span "tool execute"' in _only_line(span_name=raw)

    def test_embedded_newlines_never_add_document_lines(self):
        text = _text(
            _make_investigation(service_name="a\nb", operation_name="c\r\nd"),
            [_make_evidence(span_name="x\ny", error_type="p\n\nq", agent_name="m\rn")],
            derived_signal="s\nt",
        )
        assert len(text.split("\n")) == 6
        assert "\r" not in text

    def test_case_is_preserved(self):
        line = _only_line(
            span_name="Tool.Execute",
            service_name="CheckOut-API",
            error_type="ToolExecutionError",
            agent_name="Tool_Agent",
            evidence_type="Mixed",
        )
        assert line == (
            '  span "Tool.Execute" service "CheckOut-API" status OK '
            'error-type "ToolExecutionError" agent "Tool_Agent" evidence-type Mixed'
        )

    def test_header_case_is_preserved(self):
        inv = _make_investigation(anomaly_type="Latency", service_name="CheckOut", operation_name="Research/Plan")
        assert _text(inv, derived_signal="Agent_Latency").split("\n")[:4] == [
            "anomaly: Latency",
            "signal: Agent_Latency",
            "service: CheckOut",
            "operation: Research/Plan",
        ]

    def test_evidence_type_is_normalized(self):
        assert _only_line(evidence_type="  direct_subject\t").endswith(
            " evidence-type direct_subject"
        )


# ---------------------------------------------------------------------------
# D04  Quote and backslash escaping
# ---------------------------------------------------------------------------

class TestEscaping:

    def test_double_quote_is_escaped(self):
        assert 'span "say \\"hi\\""' in _only_line(span_name='say "hi"')

    def test_backslash_is_escaped(self):
        assert 'span "C:\\\\tools\\\\run"' in _only_line(span_name="C:\\tools\\run")

    def test_backslash_then_quote(self):
        # raw value:  a\"b   →  rendered:  a\\\"b
        assert 'span "a\\\\\\"b"' in _only_line(span_name='a\\"b')

    def test_backslash_is_escaped_before_quote(self):
        """A lone quote yields exactly one backslash, not two."""
        line = _only_line(span_name='"')
        assert 'span "\\""' in line
        assert 'span "\\\\"' not in line

    @pytest.mark.parametrize(
        "field, label",
        [
            ("span_name", "span"),
            ("service_name", "service"),
            ("error_type", "error-type"),
            ("tool_name", "tool"),
            ("tool_status", "tool-status"),
            ("agent_name", "agent"),
            ("agent_operation", "agent-op"),
        ],
    )
    def test_every_quoted_field_is_escaped(self, field, label):
        line = _only_line(**{field: 'x"y\\z'})
        assert f' {label} "x\\"y\\\\z"' in line

    def test_escaping_happens_after_normalization(self):
        assert 'span "a \\" b"' in _only_line(span_name='  a   "   b  ')

    def test_text_with_quotes_and_backslashes_is_not_rejected(self):
        doc = _build(evidence=[_make_evidence(span_name='"\\"', error_type='\\\\""')])
        assert doc.eligible is True

    def test_evidence_type_is_not_quoted_or_escaped(self):
        assert _only_line(evidence_type='ty"pe\\x').endswith(' evidence-type ty"pe\\x')


# ---------------------------------------------------------------------------
# D05  Output format
# ---------------------------------------------------------------------------

def _full_row(rank: int = 1) -> EvidenceRow:
    return _make_evidence(
        rank_position=rank,
        evidence_type="mixed",
        evidence_score=0.9,
        span_name="tool.execute",
        service_name="agentops-demo-app",
        status_code="ERROR",
        error_type="ToolExecutionError",
        tool_name="web_search",
        tool_status="error",
        agent_name="tool_agent",
        agent_operation="execute",
        retrieval_result_count=0,
        retrieval_top_relevance_score=0.25,
        is_direct_subject=True,
        is_root_span=True,
        trace_duration_fraction=0.9,
    )


class TestOutputFormat:

    @pytest.fixture(params=["none", "one", "many"])
    def text(self, request) -> str:
        evidence = {
            "none": [],
            "one": [_full_row()],
            "many": [_full_row(1), _make_evidence(rank_position=2), _make_evidence(rank_position=3)],
        }[request.param]
        return _text(evidence=evidence)

    def test_text_is_str(self, text):
        assert isinstance(text, str)

    def test_lf_only_no_carriage_return(self, text):
        assert "\r" not in text

    def test_no_trailing_newline(self, text):
        assert not text.endswith("\n")

    def test_no_leading_newline(self, text):
        assert not text.startswith("\n")

    def test_no_blank_lines(self, text):
        assert all(line != "" for line in text.split("\n"))

    def test_no_trailing_spaces_on_any_line(self, text):
        assert all(line == line.rstrip() for line in text.split("\n"))

    def test_no_tabs(self, text):
        assert "\t" not in text

    def test_utf8_encodable(self, text):
        assert text.encode("utf-8").decode("utf-8") == text

    def test_evidence_lines_start_with_exactly_two_spaces(self, text):
        for line in text.split("\n")[5:]:
            assert line.startswith("  span ")
            assert not line.startswith("   ")

    def test_tokens_separated_by_exactly_one_space(self, text):
        for line in text.split("\n")[5:]:
            assert "  " not in line[2:]

    def test_header_lines_have_no_double_spaces(self, text):
        for line in text.split("\n")[:5]:
            assert "  " not in line

    def test_evidence_header_line_is_bare_when_rows_follow(self):
        assert _text(evidence=[_make_evidence()]).split("\n")[4] == "evidence:"


# ---------------------------------------------------------------------------
# D06  'unknown' placeholders
# ---------------------------------------------------------------------------

_BLANKS = [None, "", "   ", "\t\n", "\u00a0\u2003"]


class TestUnknownPlaceholders:

    @pytest.mark.parametrize("value", _BLANKS)
    def test_header_service_unknown(self, value):
        assert _text(_make_investigation(service_name=value)).split("\n")[2] == "service: unknown"

    @pytest.mark.parametrize("value", _BLANKS)
    def test_header_operation_unknown(self, value):
        assert _text(_make_investigation(operation_name=value)).split("\n")[3] == "operation: unknown"

    @pytest.mark.parametrize("value", _BLANKS)
    def test_evidence_span_name_unknown(self, value):
        assert _only_line(span_name=value).startswith('  span "unknown" service "checkout"')

    @pytest.mark.parametrize("value", _BLANKS)
    def test_evidence_service_name_unknown(self, value):
        assert _only_line(service_name=value).startswith('  span "research.plan" service "unknown"')

    def test_header_placeholders_are_unquoted(self):
        lines = _text(_make_investigation(service_name=None, operation_name=None)).split("\n")
        assert lines[2:4] == ["service: unknown", "operation: unknown"]

    def test_evidence_placeholders_are_quoted(self):
        assert _only_line(span_name=None, service_name=None) == (
            '  span "unknown" service "unknown" status OK evidence-type duration'
        )

    @pytest.mark.parametrize("value", _BLANKS)
    def test_empty_evidence_type_raises(self, value):
        with pytest.raises(ValueError, match="evidence_type"):
            _build(evidence=[_make_evidence(evidence_type=value)])


# ---------------------------------------------------------------------------
# D07  Optional text fields
# ---------------------------------------------------------------------------

_OPTIONAL_TEXT = [
    ("error_type", "error-type"),
    ("tool_name", "tool"),
    ("tool_status", "tool-status"),
    ("agent_name", "agent"),
    ("agent_operation", "agent-op"),
]


class TestOptionalTextFields:

    def test_minimal_line(self):
        assert _only_line() == (
            '  span "research.plan" service "checkout" status OK evidence-type duration'
        )

    @pytest.mark.parametrize("field, label", _OPTIONAL_TEXT)
    @pytest.mark.parametrize("value", _BLANKS)
    def test_optional_text_omitted_when_blank(self, field, label, value):
        line = _only_line(**{field: value})
        assert f" {label} " not in line
        assert line == '  span "research.plan" service "checkout" status OK evidence-type duration'

    @pytest.mark.parametrize("field, label", _OPTIONAL_TEXT)
    def test_optional_text_rendered_alone(self, field, label):
        assert _only_line(**{field: "value-x"}) == (
            f'  span "research.plan" service "checkout" status OK {label} "value-x" '
            "evidence-type duration"
        )

    def test_all_optional_fields_in_locked_order(self):
        assert _evidence_lines(_text(evidence=[_full_row()])) == [
            '  span "tool.execute" service "agentops-demo-app" status ERROR '
            'direct-subject root-span error-type "ToolExecutionError" tool "web_search" '
            'tool-status "error" agent "tool_agent" agent-op "execute" '
            "retrieval-results zero retrieval-relevance low duration dominant "
            "evidence-type mixed"
        ]

    def test_optional_token_order_by_position(self):
        line = _evidence_lines(_text(evidence=[_full_row()]))[0]
        labels = [
            " status ",
            " direct-subject ",
            " root-span ",
            " error-type ",
            " tool ",
            " tool-status ",
            " agent ",
            " agent-op ",
            " retrieval-results ",
            " retrieval-relevance ",
            " duration ",
            " evidence-type ",
        ]
        positions = [line.index(label) for label in labels]
        assert positions == sorted(positions)
        assert len(set(positions)) == len(positions)

    def test_evidence_type_is_always_last(self):
        line = _evidence_lines(_text(evidence=[_full_row()]))[0]
        assert line.endswith(" evidence-type mixed")
        assert line.count(" evidence-type ") == 1

    def test_bucket_values_are_bare(self):
        line = _only_line(
            retrieval_result_count=5,
            retrieval_top_relevance_score=0.5,
            trace_duration_fraction=0.6,
        )
        assert line == (
            '  span "research.plan" service "checkout" status OK '
            "retrieval-results few retrieval-relevance moderate duration significant "
            "evidence-type duration"
        )

    def test_subset_of_optional_fields_keeps_relative_order(self):
        line = _only_line(
            agent_operation="execute",
            error_type="Boom",
            trace_duration_fraction=0.1,
            is_root_span=True,
        )
        assert line == (
            '  span "research.plan" service "checkout" status OK root-span '
            'error-type "Boom" agent-op "execute" duration minor evidence-type duration'
        )


# ---------------------------------------------------------------------------
# D08  Boolean flags
# ---------------------------------------------------------------------------

class TestBooleanFlags:

    def test_neither_flag(self):
        line = _only_line(is_direct_subject=False, is_root_span=False)
        assert "direct-subject" not in line
        assert "root-span" not in line

    def test_direct_subject_only(self):
        assert _only_line(is_direct_subject=True) == (
            '  span "research.plan" service "checkout" status OK direct-subject '
            "evidence-type duration"
        )

    def test_root_span_only(self):
        assert _only_line(is_root_span=True) == (
            '  span "research.plan" service "checkout" status OK root-span '
            "evidence-type duration"
        )

    def test_both_flags_direct_subject_first(self):
        assert _only_line(is_direct_subject=True, is_root_span=True) == (
            '  span "research.plan" service "checkout" status OK direct-subject root-span '
            "evidence-type duration"
        )

    def test_false_is_never_rendered(self):
        line = _only_line(is_direct_subject=False, is_root_span=False)
        assert "false" not in line.lower()
        assert "true" not in _only_line(is_direct_subject=True, is_root_span=True).lower()

    def test_flags_are_bare_not_quoted(self):
        line = _only_line(is_direct_subject=True, is_root_span=True)
        assert '"direct-subject"' not in line
        assert '"root-span"' not in line


# ---------------------------------------------------------------------------
# D09  Status normalization
# ---------------------------------------------------------------------------

class TestStatusNormalization:

    @pytest.mark.parametrize("status", ["OK", "ERROR", "UNSET"])
    def test_known_status_passes_through(self, status):
        assert f" status {status} " in _only_line(status_code=status)

    @pytest.mark.parametrize(
        "status",
        [
            None, "", "   ",
            "ok", "Ok", "error", "Error", "unset", "Unset",
            "OKAY", "ERR", "FAILED", "UNKNOWN", "STATUS_CODE_OK", "0", "2",
            "O K", "OK ERROR",
        ],
    )
    def test_anything_else_is_unknown(self, status):
        assert " status UNKNOWN " in _only_line(status_code=status)

    @pytest.mark.parametrize("status", ["  OK", "ERROR\n", "\tUNSET\u00a0"])
    def test_status_matched_after_normalization(self, status):
        assert f" status {status.strip()} " in _only_line(status_code=status)

    def test_status_is_bare_not_quoted(self):
        assert ' status "' not in _only_line(status_code="OK")


# ---------------------------------------------------------------------------
# D10  Evidence sorting, filtering, top-5
# ---------------------------------------------------------------------------

def _named(rank: int, **kwargs) -> EvidenceRow:
    kwargs.setdefault("span_name", f"span-{rank}")
    return _make_evidence(rank_position=rank, **kwargs)


def _span_names(text: str) -> list[str]:
    return [line.split('"')[1] for line in _evidence_lines(text)]


class TestEvidenceSelection:

    def test_sorted_by_rank_position_ascending(self):
        text = _text(evidence=[_named(3), _named(1), _named(2)])
        assert _span_names(text) == ["span-1", "span-2", "span-3"]

    def test_rank_gaps_are_allowed(self):
        text = _text(evidence=[_named(40), _named(7), _named(1000)])
        assert _span_names(text) == ["span-7", "span-40", "span-1000"]

    def test_sorted_numerically_not_lexically(self):
        text = _text(evidence=[_named(10), _named(9), _named(2)])
        assert _span_names(text) == ["span-2", "span-9", "span-10"]

    def test_telemetry_with_zero_score_is_removed(self):
        text = _text(evidence=[
            _named(1),
            _named(2, evidence_type="telemetry", evidence_score=0.0),
            _named(3),
        ])
        assert _span_names(text) == ["span-1", "span-3"]

    def test_telemetry_with_negative_zero_score_is_removed(self):
        text = _text(evidence=[_named(1), _named(2, evidence_type="telemetry", evidence_score=-0.0)])
        assert _span_names(text) == ["span-1"]

    def test_telemetry_with_positive_score_is_kept(self):
        text = _text(evidence=[_named(1, evidence_type="telemetry", evidence_score=1e-12)])
        assert _span_names(text) == ["span-1"]

    @pytest.mark.parametrize(
        "evidence_type",
        ["mixed", "duration", "error", "direct_subject", "retrieval",
         "tool_error_match", "signal_specific", "Telemetry", "TELEMETRY", "telemetry2"],
    )
    def test_other_types_with_zero_score_are_kept(self, evidence_type):
        text = _text(evidence=[_named(1, evidence_type=evidence_type, evidence_score=0.0)])
        assert _span_names(text) == ["span-1"]

    def test_filter_is_applied_before_top_five(self):
        evidence = [
            _named(1, evidence_type="telemetry", evidence_score=0.0),
            _named(2, evidence_type="telemetry", evidence_score=0.0),
            _named(3), _named(4), _named(5), _named(6), _named(7), _named(8),
        ]
        assert _span_names(_text(evidence=evidence)) == [
            "span-3", "span-4", "span-5", "span-6", "span-7",
        ]

    def test_interleaved_filtered_rows(self):
        evidence = [
            _named(1),
            _named(2, evidence_type="telemetry", evidence_score=0.0),
            _named(3),
            _named(4, evidence_type="telemetry", evidence_score=0.0),
            _named(5), _named(6), _named(7), _named(8),
        ]
        assert _span_names(_text(evidence=evidence)) == [
            "span-1", "span-3", "span-5", "span-6", "span-7",
        ]

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_up_to_five_rows_all_rendered(self, count):
        text = _text(evidence=[_named(r) for r in range(1, count + 1)])
        assert _span_names(text) == [f"span-{r}" for r in range(1, count + 1)]

    @pytest.mark.parametrize("count", [6, 7, 20])
    def test_more_than_five_rows_capped_at_first_five(self, count):
        text = _text(evidence=[_named(r) for r in range(count, 0, -1)])
        assert _span_names(text) == ["span-1", "span-2", "span-3", "span-4", "span-5"]

    def test_evidence_score_does_not_affect_order(self):
        evidence = [
            _named(1, evidence_score=0.1),
            _named(2, evidence_score=0.9),
            _named(3, evidence_score=0.5),
        ]
        assert _span_names(_text(evidence=evidence)) == ["span-1", "span-2", "span-3"]

    def test_accepts_tuple_and_list(self):
        rows = [_named(2), _named(1)]
        assert _text(evidence=rows) == _text(evidence=tuple(rows))

    def test_filter_uses_normalized_evidence_type(self):
        text = _text(evidence=[_named(1), _named(2, evidence_type=" telemetry\n", evidence_score=0.0)])
        assert _span_names(text) == ["span-1"]


# ---------------------------------------------------------------------------
# D11  Evidence validation
# ---------------------------------------------------------------------------

class TestEvidenceValidation:

    def test_duplicate_rank_raises(self):
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[_named(1), _named(2), _make_evidence(rank_position=2, span_name="dup")])

    def test_duplicate_rank_raises_even_when_rows_are_identical(self):
        row = _named(1)
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[row, row])

    def test_duplicate_rank_raises_when_duplicate_would_be_filtered(self):
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=0.0),
                _named(2, evidence_type="telemetry", evidence_score=0.0),
            ])

    def test_duplicate_rank_raises_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(8)]
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=evidence)

    def test_investigation_mismatch_raises(self):
        with pytest.raises(ValueError, match="investigation"):
            _build(evidence=[_named(1), _named(2, investigation_id=_OTHER_INV_ID)])

    def test_investigation_mismatch_raises_when_row_would_be_filtered(self):
        with pytest.raises(ValueError, match="investigation"):
            _build(evidence=[
                _named(1),
                _named(2, investigation_id=_OTHER_INV_ID,
                       evidence_type="telemetry", evidence_score=0.0),
            ])

    def test_investigation_mismatch_raises_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, investigation_id=_OTHER_INV_ID)]
        with pytest.raises(ValueError, match="investigation"):
            _build(evidence=evidence)

    def test_investigation_id_match_is_exact(self):
        with pytest.raises(ValueError, match="investigation"):
            _build(evidence=[_named(1, investigation_id=_INV_ID.upper())])

    def test_invalid_number_raises_when_row_would_be_filtered(self):
        with pytest.raises(ValueError, match="trace_duration_fraction"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=0.0,
                       trace_duration_fraction=-0.1),
            ])

    def test_invalid_number_raises_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [
            _named(9, retrieval_top_relevance_score=float("nan"))
        ]
        with pytest.raises(ValueError, match="retrieval_top_relevance_score"):
            _build(evidence=evidence)

    def test_empty_evidence_type_raises_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, evidence_type=" ")]
        with pytest.raises(ValueError, match="evidence_type"):
            _build(evidence=evidence)


# ---------------------------------------------------------------------------
# D12  Bucket boundaries
# ---------------------------------------------------------------------------

class TestRetrievalResultsBucket:

    def test_none_is_omitted(self):
        assert "retrieval-results" not in _only_line(retrieval_result_count=None)

    @pytest.mark.parametrize(
        "count, bucket",
        [
            (0, "zero"),
            (1, "very-few"),
            (2, "very-few"),
            (3, "few"),
            (4, "few"),
            (9, "few"),
            (10, "some"),
            (11, "some"),
            (1_000_000, "some"),
        ],
    )
    def test_bucket(self, count, bucket):
        assert f" retrieval-results {bucket} " in _only_line(retrieval_result_count=count)


class TestRetrievalRelevanceBucket:

    def test_none_is_omitted(self):
        assert "retrieval-relevance" not in _only_line(retrieval_top_relevance_score=None)

    @pytest.mark.parametrize(
        "score, bucket",
        [
            (0.0, "very-low"),
            (0.1, "very-low"),
            (_below(0.2), "very-low"),
            (0.2, "low"),
            (0.3, "low"),
            (_below(0.4), "low"),
            (0.4, "moderate"),
            (0.5, "moderate"),
            (_below(0.6), "moderate"),
            (0.6, "high"),
            (0.9, "high"),
            (1.0, "high"),
            (_above(1.0), "high"),
            (1.5, "high"),
            (1e9, "high"),
        ],
    )
    def test_bucket(self, score, bucket):
        assert f" retrieval-relevance {bucket} " in _only_line(retrieval_top_relevance_score=score)

    def test_integer_score_accepted(self):
        assert " retrieval-relevance very-low " in _only_line(retrieval_top_relevance_score=0)
        assert " retrieval-relevance high " in _only_line(retrieval_top_relevance_score=1)


class TestDurationBucket:

    def test_none_is_omitted(self):
        assert " duration " not in _only_line(trace_duration_fraction=None)

    @pytest.mark.parametrize(
        "fraction, bucket",
        [
            (0.0, "minor"),
            (0.1, "minor"),
            (_below(0.25), "minor"),
            (0.25, "moderate"),
            (0.3, "moderate"),
            (_below(0.5), "moderate"),
            (0.5, "significant"),
            (0.6, "significant"),
            (_below(0.75), "significant"),
            (0.75, "dominant"),
            (0.9, "dominant"),
            (_below(1.0), "dominant"),
            (1.0, "dominant"),
            (_above(1.0), "anomalous"),
            (1.5, "anomalous"),
            (1e9, "anomalous"),
        ],
    )
    def test_bucket(self, fraction, bucket):
        assert f" duration {bucket} " in _only_line(trace_duration_fraction=fraction)

    def test_fraction_above_one_does_not_raise(self):
        assert _build(evidence=[_make_evidence(trace_duration_fraction=2.5)]).eligible is True

    def test_duration_label_does_not_collide_with_evidence_type_duration(self):
        line = _only_line(trace_duration_fraction=0.9, evidence_type="duration")
        assert line.endswith(" duration dominant evidence-type duration")


# ---------------------------------------------------------------------------
# D13  Numeric rejection
# ---------------------------------------------------------------------------

_BUCKET_FIELDS = [
    "retrieval_result_count",
    "retrieval_top_relevance_score",
    "trace_duration_fraction",
]


class TestNumericRejection:

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    @pytest.mark.parametrize("value", [-1, -0.5, -1e-12, -1e9])
    def test_negative_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: value})])

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    def test_nan_raises(self, field):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: float("nan")})])

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    def test_positive_infinity_raises(self, field):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: float("inf")})])

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    def test_negative_infinity_raises(self, field):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: float("-inf")})])

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    def test_zero_is_valid(self, field):
        assert _build(evidence=[_make_evidence(**{field: 0})]).eligible is True

    @pytest.mark.parametrize("field", _BUCKET_FIELDS)
    def test_none_is_valid(self, field):
        assert _build(evidence=[_make_evidence(**{field: None})]).eligible is True

    def test_no_partial_document_on_error(self):
        """The call raises; it never returns a document for invalid input."""
        with pytest.raises(ValueError):
            _build(evidence=[_named(1), _named(2, trace_duration_fraction=float("nan"))])


# ---------------------------------------------------------------------------
# D14  Eligibility: INSUFFICIENT_DATA
# ---------------------------------------------------------------------------

class TestInsufficientData:

    def _inv(self) -> InvestigationRow:
        return _make_investigation(confidence="INSUFFICIENT_DATA")

    def test_not_eligible(self):
        assert _build(self._inv()).eligible is False

    def test_text_is_none(self):
        assert _build(self._inv()).text is None

    def test_exact_result(self):
        assert _build(self._inv()) == IncidentDocument(
            investigation_id=_INV_ID,
            doc_version="1.0.0",
            eligible=False,
            text=None,
        )

    def test_not_eligible_even_with_informative_evidence(self):
        doc = _build(self._inv(), [_named(1), _named(2)])
        assert doc.eligible is False
        assert doc.text is None

    def test_evidence_is_not_inspected(self):
        """Evidence that would raise for an eligible investigation is ignored."""
        bad_evidence = [
            _named(1),
            _named(1),                                           # duplicate rank
            _named(2, investigation_id=_OTHER_INV_ID),           # mismatch
            _named(3, trace_duration_fraction=float("nan")),     # invalid number
            _named(4, evidence_type=""),                         # empty required text
        ]
        doc = _build(self._inv(), bad_evidence)
        assert doc.eligible is False
        assert doc.text is None

    def test_same_bad_evidence_raises_when_eligible(self):
        with pytest.raises(ValueError):
            _build(_make_investigation(confidence="HIGH"), [_named(1), _named(1)])

    @pytest.mark.parametrize(
        "confidence",
        ["insufficient_data", "Insufficient_Data", " INSUFFICIENT_DATA",
         "INSUFFICIENT_DATA ", "INSUFFICIENT DATA", "INSUFFICIENT_DATA\n"],
    )
    def test_match_is_exact(self, confidence):
        assert _build(_make_investigation(confidence=confidence)).eligible is True

    @pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM", "LOW"])
    def test_other_confidences_are_eligible(self, confidence):
        doc = _build(_make_investigation(confidence=confidence), [_named(1)])
        assert doc.eligible is True
        assert doc.text is not None


# ---------------------------------------------------------------------------
# D15  'evidence: none'
# ---------------------------------------------------------------------------

_NONE_DOCUMENT = (
    "anomaly: latency\n"
    "signal: agent_latency\n"
    "service: checkout\n"
    "operation: research/plan\n"
    "evidence: none"
)


class TestEvidenceNone:

    @pytest.mark.parametrize("evidence", [[], ()])
    def test_no_rows(self, evidence):
        assert _text(evidence=evidence) == _NONE_DOCUMENT

    def test_all_rows_filtered_out(self):
        evidence = [
            _named(r, evidence_type="telemetry", evidence_score=0.0) for r in range(1, 8)
        ]
        assert _text(evidence=evidence) == _NONE_DOCUMENT

    @pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM", "LOW"])
    def test_eligible_for_every_other_confidence(self, confidence):
        doc = _build(_make_investigation(confidence=confidence))
        assert doc.eligible is True
        assert doc.text == _NONE_DOCUMENT

    def test_exactly_five_lines(self):
        assert len(_text().split("\n")) == 5

    def test_no_bare_evidence_line(self):
        assert "evidence:\n" not in _text()
        assert not _text().endswith("evidence:")

    def test_none_not_emitted_when_rows_remain(self):
        assert "evidence: none" not in _text(evidence=[_named(1)])


# ---------------------------------------------------------------------------
# D16  Determinism
# ---------------------------------------------------------------------------

def _varied_evidence() -> list[EvidenceRow]:
    return [
        _full_row(1),
        _named(2, evidence_type="telemetry", evidence_score=0.0),
        _named(3, status_code="UNSET", agent_name="retrieval", agent_operation="search",
               retrieval_result_count=0, trace_duration_fraction=0.0006),
        _named(4, status_code="weird", error_type='E"rr', is_root_span=True),
        _named(5, span_name=None, service_name="  ", trace_duration_fraction=1.2),
        _named(6, retrieval_top_relevance_score=0.61),
        _named(7), _named(8),
    ]


class TestDeterminism:

    def test_same_input_twice_is_identical(self):
        assert _text(evidence=_varied_evidence()) == _text(evidence=_varied_evidence())

    def test_repeated_calls_on_same_objects_are_identical(self):
        inv, evidence = _make_investigation(), _varied_evidence()
        results = {_text(inv, evidence) for _ in range(25)}
        assert len(results) == 1

    def test_equal_inputs_give_equal_results(self):
        assert _build(evidence=_varied_evidence()) == _build(evidence=_varied_evidence())

    def test_evidence_input_order_does_not_matter(self):
        evidence = _varied_evidence()
        expected = _text(evidence=evidence)
        rng = random.Random(1203)
        for _ in range(20):
            shuffled = list(evidence)
            rng.shuffle(shuffled)
            assert _text(evidence=shuffled) == expected

    def test_reversed_evidence_gives_same_document(self):
        evidence = _varied_evidence()
        assert _text(evidence=list(reversed(evidence))) == _text(evidence=evidence)

    def test_evidence_list_is_not_mutated(self):
        evidence = list(reversed(_varied_evidence()))
        snapshot = copy.deepcopy(evidence)
        _build(evidence=evidence)
        assert evidence == snapshot
        assert [r.rank_position for r in evidence] == [r.rank_position for r in snapshot]

    def test_investigation_is_not_mutated(self):
        inv = _make_investigation(service_name="  a  b ")
        snapshot = copy.deepcopy(inv)
        _build(inv, _varied_evidence())
        assert inv == snapshot

    def test_text_bytes_are_stable(self):
        a = _text(evidence=_varied_evidence()).encode("utf-8")
        b = _text(evidence=_varied_evidence()).encode("utf-8")
        assert a == b


# ---------------------------------------------------------------------------
# D17  Excluded information never leaks
# ---------------------------------------------------------------------------

class TestExcludedInformation:

    def test_investigation_id_never_in_text(self):
        inv_id = "0123456789abcdef" * 4
        inv = _make_investigation(investigation_id=inv_id)
        text = _text(inv, [_make_evidence(investigation_id=inv_id)])
        assert inv_id not in text
        assert inv_id[:16] not in text

    @pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM", "LOW"])
    def test_confidence_never_in_text(self, confidence):
        text = _text(_make_investigation(confidence=confidence), [_full_row()])
        assert confidence not in text
        assert "confidence" not in text.lower()

    def test_rank_position_never_in_text(self):
        text = _text(evidence=[_make_evidence(rank_position=987654)])
        assert "987654" not in text
        assert "rank" not in text.lower()

    def test_evidence_score_never_in_text(self):
        text = _text(evidence=[_make_evidence(evidence_score=0.424242)])
        assert "0.424242" not in text
        assert "424242" not in text
        assert "score" not in text.lower()

    def test_raw_bucket_inputs_never_in_text(self):
        text = _text(evidence=[_make_evidence(
            retrieval_result_count=7777,
            retrieval_top_relevance_score=0.123456,
            trace_duration_fraction=0.654321,
        )])
        assert "7777" not in text
        assert "123456" not in text
        assert "654321" not in text

    def test_no_digits_from_numeric_fields(self):
        """With digit-free text inputs the document contains no digits at all."""
        inv = _make_investigation(
            investigation_id="f" * 64,
            anomaly_type="latency",
            service_name="checkout",
            operation_name="plan",
        )
        evidence = [
            _make_evidence(
                investigation_id="f" * 64,
                rank_position=r,
                span_name="span",
                evidence_score=0.5 + r / 100,
                retrieval_result_count=r,
                retrieval_top_relevance_score=r / 10,
                trace_duration_fraction=r / 10,
            )
            for r in range(1, 6)
        ]
        text = _text(inv, evidence, derived_signal="agent_latency")
        assert not any(ch.isdigit() for ch in text)

    @pytest.mark.parametrize(
        "label",
        [
            "investigation", "anomaly_id", "analyzer", "version", "investigated_at",
            "event_time", "trace_id", "span_id", "parent_span_id", "subject_span_id",
            "trace_span_count", "observed_value", "baseline", "anomaly_score",
            "severity", "confidence", "summary", "limitations", "error_message",
            "error-message", "explanation", "duration_ms", "depth", "evidence_score",
            "evidence-score", "breakdown", "rank", "is_error_span",
        ],
    )
    def test_no_excluded_field_label_in_text(self, label):
        text = _text(evidence=_varied_evidence())
        assert label not in text.lower()

    def test_doc_version_never_in_text(self):
        assert DOC_VERSION not in _text(evidence=[_full_row()])

    @pytest.mark.parametrize(
        "excluded",
        [
            "anomaly_id", "analyzer_version", "investigated_at", "trace_id",
            "subject_span_id", "observed_value", "baseline_median", "anomaly_score",
            "severity", "event_time", "summary", "limitations", "trace_span_count",
        ],
    )
    def test_investigation_row_has_no_excluded_field(self, excluded):
        assert excluded not in {f.name for f in dataclasses.fields(InvestigationRow)}

    @pytest.mark.parametrize(
        "excluded",
        [
            "error_message", "explanation", "id", "span_id", "parent_span_id",
            "is_error_span", "duration_ms", "depth", "evidence_score_breakdown",
        ],
    )
    def test_evidence_row_has_no_excluded_field(self, excluded):
        assert excluded not in {f.name for f in dataclasses.fields(EvidenceRow)}

    def test_only_expected_line_prefixes(self):
        text = _text(evidence=_varied_evidence())
        prefixes = [line.split(":")[0] if not line.startswith("  ") else "  span"
                    for line in text.split("\n")]
        assert prefixes[:5] == ["anomaly", "signal", "service", "operation", "evidence"]
        assert set(prefixes[5:]) == {"  span"}


# ---------------------------------------------------------------------------
# D18  Golden documents
# ---------------------------------------------------------------------------

class TestGoldenDocuments:

    def test_tool_failure_modelled_on_live_investigation(self):
        inv = _make_investigation(
            anomaly_type="tool_failure",
            service_name="agentops-demo-app",
            operation_name="tool.execute/ToolExecutionError",
            confidence="HIGH",
        )
        svc = "agentops-demo-app"
        evidence = [
            _make_evidence(
                rank_position=1, evidence_type="mixed", evidence_score=0.9010260195752193,
                span_name="tool.execute", service_name=svc, status_code="ERROR",
                error_type="ToolExecutionError", agent_name="tool_agent",
                agent_operation="execute", is_direct_subject=True,
                trace_duration_fraction=0.0103,
            ),
            _make_evidence(
                rank_position=2, evidence_type="mixed", evidence_score=0.5,
                span_name="agentops.request", service_name=svc, status_code="ERROR",
                is_root_span=True, trace_duration_fraction=1.0,
            ),
            _make_evidence(
                rank_position=3, evidence_type="duration", evidence_score=5.975675485670096e-05,
                span_name="retrieval.search", service_name=svc, status_code="UNSET",
                agent_name="retrieval", agent_operation="search",
                retrieval_result_count=0, trace_duration_fraction=0.0006,
            ),
            _make_evidence(
                rank_position=4, evidence_type="duration", evidence_score=1.3669845882251851e-05,
                span_name="research.plan", service_name=svc, status_code="UNSET",
                agent_name="research", agent_operation="plan",
                trace_duration_fraction=0.0001,
            ),
            _make_evidence(
                rank_position=5, evidence_type="duration", evidence_score=8.20190752935111e-06,
                span_name="supervisor.start", service_name=svc, status_code="UNSET",
                agent_name="supervisor", agent_operation="start",
                trace_duration_fraction=0.0001,
            ),
        ]
        assert _text(inv, evidence, derived_signal="tool_failure") == "\n".join([
            "anomaly: tool_failure",
            "signal: tool_failure",
            "service: agentops-demo-app",
            "operation: tool.execute/ToolExecutionError",
            "evidence:",
            '  span "tool.execute" service "agentops-demo-app" status ERROR direct-subject '
            'error-type "ToolExecutionError" agent "tool_agent" agent-op "execute" '
            "duration minor evidence-type mixed",
            '  span "agentops.request" service "agentops-demo-app" status ERROR root-span '
            "duration dominant evidence-type mixed",
            '  span "retrieval.search" service "agentops-demo-app" status UNSET '
            'agent "retrieval" agent-op "search" retrieval-results zero duration minor '
            "evidence-type duration",
            '  span "research.plan" service "agentops-demo-app" status UNSET '
            'agent "research" agent-op "plan" duration minor evidence-type duration',
            '  span "supervisor.start" service "agentops-demo-app" status UNSET '
            'agent "supervisor" agent-op "start" duration minor evidence-type duration',
        ])

    def test_trace_latency(self):
        inv = _make_investigation(
            anomaly_type="latency", service_name="checkout", operation_name="trace",
            confidence="MEDIUM",
        )
        evidence = [
            _make_evidence(
                rank_position=2, evidence_type="telemetry", evidence_score=0.0,
                span_name="checkout.request", is_root_span=True, trace_duration_fraction=1.0,
            ),
            _make_evidence(
                rank_position=1, evidence_type="duration", evidence_score=0.48,
                span_name="llm.generate", status_code="OK", agent_name="writer",
                agent_operation="draft", trace_duration_fraction=0.8,
            ),
            _make_evidence(
                rank_position=3, evidence_type="duration", evidence_score=0.06,
                span_name="cache.lookup", status_code="UNSET", trace_duration_fraction=0.1,
            ),
        ]
        assert _text(inv, evidence, derived_signal="trace_latency") == "\n".join([
            "anomaly: latency",
            "signal: trace_latency",
            "service: checkout",
            "operation: trace",
            "evidence:",
            '  span "llm.generate" service "checkout" status OK agent "writer" '
            'agent-op "draft" duration dominant evidence-type duration',
            '  span "cache.lookup" service "checkout" status UNSET duration minor '
            "evidence-type duration",
        ])

    def test_retrieval_quality(self):
        inv = _make_investigation(
            anomaly_type="retrieval_quality", service_name="search-api",
            operation_name=None, confidence="HIGH",
        )
        evidence = [
            _make_evidence(
                rank_position=1, evidence_type="mixed", evidence_score=0.72,
                span_name="retrieval.search", service_name="search-api", status_code="OK",
                agent_name="retrieval", agent_operation="search",
                retrieval_result_count=2, retrieval_top_relevance_score=0.15,
                is_direct_subject=True, trace_duration_fraction=0.3,
            ),
            _make_evidence(
                rank_position=2, evidence_type="retrieval", evidence_score=0.2,
                span_name="retrieval.rerank", service_name="search-api", status_code="OK",
                retrieval_result_count=12, retrieval_top_relevance_score=0.45,
                trace_duration_fraction=0.05,
            ),
        ]
        assert _text(inv, evidence, derived_signal="retrieval_quality") == "\n".join([
            "anomaly: retrieval_quality",
            "signal: retrieval_quality",
            "service: search-api",
            "operation: unknown",
            "evidence:",
            '  span "retrieval.search" service "search-api" status OK direct-subject '
            'agent "retrieval" agent-op "search" retrieval-results very-few '
            "retrieval-relevance very-low duration moderate evidence-type mixed",
            '  span "retrieval.rerank" service "search-api" status OK '
            "retrieval-results some retrieval-relevance moderate duration minor "
            "evidence-type retrieval",
        ])

    def test_error_rate_with_unusual_text(self):
        inv = _make_investigation(
            anomaly_type="error_rate", service_name=None,
            operation_name="  payment\tauthorize ", confidence="LOW",
        )
        evidence = [
            _make_evidence(
                rank_position=1, evidence_type="error", evidence_score=0.5,
                span_name='charge "card"', service_name="pay\\ments", status_code="error",
                error_type="Time\u0301out", tool_name="  ", tool_status="failed",
            ),
        ]
        assert _text(inv, evidence, derived_signal="error_rate") == "\n".join([
            "anomaly: error_rate",
            "signal: error_rate",
            "service: unknown",
            "operation: payment authorize",
            "evidence:",
            '  span "charge \\"card\\"" service "pay\\\\ments" status UNKNOWN '
            'error-type "Tim\u00e9out" tool-status "failed" evidence-type error',
        ])

    def test_zero_informative_evidence(self):
        inv = _make_investigation(
            anomaly_type="latency", service_name="checkout",
            operation_name="tool.execute", confidence="LOW",
        )
        evidence = [
            _make_evidence(rank_position=1, evidence_type="telemetry", evidence_score=0.0),
            _make_evidence(rank_position=2, evidence_type="telemetry", evidence_score=0.0),
        ]
        assert _text(inv, evidence, derived_signal="tool_latency") == (
            "anomaly: latency\n"
            "signal: tool_latency\n"
            "service: checkout\n"
            "operation: tool.execute\n"
            "evidence: none"
        )


# ---------------------------------------------------------------------------
# D20  Input hardening
# ---------------------------------------------------------------------------

_NON_STR = [123, 1.5, True, False, b"text", ["text"], ("text",), {"a": 1}, object()]
_NON_STR_IDS = ["int", "float", "true", "false", "bytes", "list", "tuple", "dict", "object"]

_EVIDENCE_REQUIRED_TEXT = ["evidence_type"]
_EVIDENCE_OPTIONAL_TEXT = [
    "span_name", "service_name", "status_code", "error_type",
    "tool_name", "tool_status", "agent_name", "agent_operation",
]


class TestIdentityHardening:

    @pytest.mark.parametrize("value", [None] + _NON_STR, ids=["none"] + _NON_STR_IDS)
    def test_confidence_non_string_raises(self, value):
        with pytest.raises(ValueError, match="confidence"):
            _build(_make_investigation(confidence=value))

    def test_confidence_none_raises(self):
        with pytest.raises(ValueError, match="confidence"):
            _build(_make_investigation(confidence=None))  # type: ignore[arg-type]

    def test_confidence_empty_raises(self):
        with pytest.raises(ValueError, match="confidence"):
            _build(_make_investigation(confidence=""))

    @pytest.mark.parametrize("value", [None] + _NON_STR, ids=["none"] + _NON_STR_IDS)
    def test_investigation_id_non_string_raises(self, value):
        with pytest.raises(ValueError, match="investigation_id"):
            _build(_make_investigation(investigation_id=value))

    def test_investigation_id_empty_raises(self):
        with pytest.raises(ValueError, match="investigation_id"):
            _build(_make_investigation(investigation_id=""))

    @pytest.mark.parametrize("value", [None, 123, ""], ids=["none", "int", "empty"])
    def test_investigation_id_checked_before_ineligible_return(self, value):
        inv = _make_investigation(investigation_id=value, confidence="INSUFFICIENT_DATA")
        with pytest.raises(ValueError, match="investigation_id"):
            _build(inv)

    def test_confidence_is_not_normalized_for_comparison(self):
        for confidence in (" INSUFFICIENT_DATA", "insufficient_data"):
            doc = _build(_make_investigation(confidence=confidence))
            assert doc.eligible is True
            assert doc.text is not None

    def test_exact_insufficient_data_is_still_ineligible(self):
        doc = _build(_make_investigation(confidence="INSUFFICIENT_DATA"))
        assert doc == IncidentDocument(
            investigation_id=_INV_ID, doc_version="1.0.0", eligible=False, text=None,
        )

    def test_ineligible_return_skips_header_validation(self):
        """Document-only header fields are not validated for INSUFFICIENT_DATA."""
        inv = InvestigationRow(
            investigation_id=_INV_ID,
            anomaly_type=None,        # type: ignore[arg-type]
            service_name=123,         # type: ignore[arg-type]
            operation_name=["op"],    # type: ignore[arg-type]
            confidence="INSUFFICIENT_DATA",
        )
        doc = build_incident_document(inv, [], derived_signal=None)  # type: ignore[arg-type]
        assert doc.eligible is False
        assert doc.text is None

    def test_ineligible_return_ignores_malformed_evidence(self):
        inv = _make_investigation(confidence="INSUFFICIENT_DATA")
        malformed = [
            _make_evidence(rank_position=1, investigation_id=None),
            _make_evidence(rank_position=True),
            _make_evidence(rank_position=-5, evidence_score=float("nan")),
            _make_evidence(rank_position=2, is_root_span="no", span_name=42),
            _make_evidence(rank_position=2, retrieval_result_count=2.0),
            object(),
        ]
        doc = _build(inv, malformed)
        assert doc.eligible is False
        assert doc.text is None

    def test_ineligible_return_does_not_touch_evidence_container(self):
        inv = _make_investigation(confidence="INSUFFICIENT_DATA")
        doc = build_incident_document(inv, None, derived_signal="x")  # type: ignore[arg-type]
        assert doc.eligible is False

    @pytest.mark.parametrize("value", [None, 123, b"a" * 64, True], ids=["none", "int", "bytes", "bool"])
    def test_evidence_investigation_id_non_string_raises(self, value):
        with pytest.raises(ValueError, match="investigation_id"):
            _build(evidence=[_make_evidence(investigation_id=value)])

    def test_evidence_investigation_id_mismatch_still_raises(self):
        with pytest.raises(ValueError, match="investigation"):
            _build(evidence=[_make_evidence(investigation_id=_OTHER_INV_ID)])


class TestEvidenceScoreHardening:

    @pytest.mark.parametrize(
        "value",
        [float("nan"), float("inf"), float("-inf")],
        ids=["nan", "+inf", "-inf"],
    )
    def test_non_finite_raises(self, value):
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=[_make_evidence(evidence_score=value)])

    @pytest.mark.parametrize("value", [True, False])
    def test_bool_raises(self, value):
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=[_make_evidence(evidence_score=value)])

    @pytest.mark.parametrize(
        "value", [None, "0.5", b"0.5", [0.5], 1 + 0j],
        ids=["none", "str", "bytes", "list", "complex"],
    )
    def test_non_numeric_raises(self, value):
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=[_make_evidence(evidence_score=value)])

    def test_bool_false_is_not_treated_as_zero_score(self):
        """False == 0.0 in Python; it must raise rather than filter the row."""
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=[_make_evidence(evidence_type="telemetry", evidence_score=False)])

    def test_validated_before_filtering(self):
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=float("nan")),
            ])

    def test_validated_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, evidence_score=float("inf"))]
        with pytest.raises(ValueError, match="evidence_score"):
            _build(evidence=evidence)

    @pytest.mark.parametrize("value", [-0.3, -5, 1.0, 5.0, 7, 1e300])
    def test_no_range_is_imposed(self, value):
        text = _text(evidence=[_named(1, evidence_score=value)])
        assert _span_names(text) == ["span-1"]

    def test_integer_zero_score_filters_telemetry(self):
        text = _text(evidence=[_named(1), _named(2, evidence_type="telemetry", evidence_score=0)])
        assert _span_names(text) == ["span-1"]


class TestTextTypeHardening:

    @pytest.mark.parametrize("field", _EVIDENCE_REQUIRED_TEXT + _EVIDENCE_OPTIONAL_TEXT)
    @pytest.mark.parametrize("value", _NON_STR, ids=_NON_STR_IDS)
    def test_evidence_non_string_text_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: value})])

    @pytest.mark.parametrize("field", ["anomaly_type", "service_name", "operation_name"])
    @pytest.mark.parametrize("value", _NON_STR, ids=_NON_STR_IDS)
    def test_header_non_string_text_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(_make_investigation(**{field: value}))

    @pytest.mark.parametrize("value", _NON_STR, ids=_NON_STR_IDS)
    def test_derived_signal_non_string_raises(self, value):
        with pytest.raises(ValueError, match="derived_signal"):
            _build(derived_signal=value)

    @pytest.mark.parametrize("field", _EVIDENCE_OPTIONAL_TEXT)
    def test_evidence_optional_text_still_accepts_none(self, field):
        assert _build(evidence=[_make_evidence(**{field: None})]).eligible is True

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    def test_header_optional_text_still_accepts_none(self, field):
        assert _build(_make_investigation(**{field: None})).eligible is True

    def test_numbers_are_never_rendered_as_text(self):
        """An int span_name raises; it is not converted to '42'."""
        with pytest.raises(ValueError, match="span_name"):
            _build(evidence=[_make_evidence(span_name=42)])

    def test_str_subclass_is_accepted(self):
        class Name(str):
            pass

        assert 'span "tool.execute"' in _only_line(span_name=Name("tool.execute"))

    def test_validated_before_filtering(self):
        with pytest.raises(ValueError, match="agent_name"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=0.0, agent_name=7),
            ])

    def test_validated_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, tool_name=3.5)]
        with pytest.raises(ValueError, match="tool_name"):
            _build(evidence=evidence)


class TestFlagTypeHardening:

    @pytest.mark.parametrize("field", ["is_direct_subject", "is_root_span"])
    @pytest.mark.parametrize(
        "value",
        [1, 0, "true", "false", "no", "", None, 1.0, 0.0, [], [True]],
        ids=["1", "0", "'true'", "'false'", "'no'", "empty", "none", "1.0", "0.0",
             "empty-list", "list"],
    )
    def test_non_bool_flag_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: value})])

    @pytest.mark.parametrize("field, token", [
        ("is_direct_subject", "direct-subject"),
        ("is_root_span", "root-span"),
    ])
    def test_actual_bools_still_work(self, field, token):
        assert f" {token} " in _only_line(**{field: True})
        assert token not in _only_line(**{field: False})

    def test_validated_before_filtering(self):
        with pytest.raises(ValueError, match="is_root_span"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=0.0, is_root_span=1),
            ])

    def test_validated_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, is_direct_subject="true")]
        with pytest.raises(ValueError, match="is_direct_subject"):
            _build(evidence=evidence)


class TestNumericTypeHardening:

    @pytest.mark.parametrize(
        "field",
        ["rank_position", "retrieval_result_count",
         "retrieval_top_relevance_score", "trace_duration_fraction"],
    )
    @pytest.mark.parametrize("value", [True, False])
    def test_bool_numeric_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: value})])

    @pytest.mark.parametrize("value", [2.0, 0.0, 2.5, 10.0, 1e3])
    def test_float_retrieval_result_count_raises(self, value):
        with pytest.raises(ValueError, match="retrieval_result_count"):
            _build(evidence=[_make_evidence(retrieval_result_count=value)])

    @pytest.mark.parametrize(
        "value", ["3", b"3", [3], 3 + 0j], ids=["str", "bytes", "list", "complex"],
    )
    def test_non_numeric_retrieval_result_count_raises(self, value):
        with pytest.raises(ValueError, match="retrieval_result_count"):
            _build(evidence=[_make_evidence(retrieval_result_count=value)])

    @pytest.mark.parametrize(
        "value", [1.0, 1.5, "1", None, b"1", [1], 1 + 0j, float("nan")],
        ids=["1.0", "1.5", "str", "none", "bytes", "list", "complex", "nan"],
    )
    def test_invalid_rank_position_type_raises(self, value):
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[_make_evidence(rank_position=value)])

    @pytest.mark.parametrize("value", [-1, -2, -1_000_000])
    def test_negative_rank_position_raises(self, value):
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[_make_evidence(rank_position=value)])

    def test_rank_position_zero_is_valid(self):
        text = _text(evidence=[_named(1), _named(0)])
        assert _span_names(text) == ["span-0", "span-1"]

    def test_invalid_rank_raises_even_when_row_would_be_filtered(self):
        with pytest.raises(ValueError, match="rank_position"):
            _build(evidence=[
                _named(1),
                _make_evidence(rank_position=-1, evidence_type="telemetry", evidence_score=0.0),
            ])

    @pytest.mark.parametrize(
        "field", ["retrieval_top_relevance_score", "trace_duration_fraction"],
    )
    @pytest.mark.parametrize(
        "value", ["0.5", b"0.5", [0.5], 0.5 + 0j, object()],
        ids=["str", "bytes", "list", "complex", "object"],
    )
    def test_non_numeric_real_bucket_input_raises(self, field, value):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: value})])

    @pytest.mark.parametrize(
        "count, bucket",
        [(0, "zero"), (1, "very-few"), (2, "very-few"), (3, "few"), (9, "few"),
         (10, "some"), (10 ** 400, "some")],
    )
    def test_valid_int_counts_still_bucket(self, count, bucket):
        assert f" retrieval-results {bucket} " in _only_line(retrieval_result_count=count)

    @pytest.mark.parametrize(
        "score, bucket", [(0, "very-low"), (1, "high"), (2, "high"), (10 ** 400, "high")],
    )
    def test_valid_int_relevance_still_buckets(self, score, bucket):
        assert f" retrieval-relevance {bucket} " in _only_line(retrieval_top_relevance_score=score)

    @pytest.mark.parametrize(
        "fraction, bucket",
        [(0, "minor"), (1, "dominant"), (2, "anomalous"), (10 ** 400, "anomalous")],
    )
    def test_valid_int_fraction_still_buckets(self, fraction, bucket):
        assert f" duration {bucket} " in _only_line(trace_duration_fraction=fraction)

    def test_relevance_above_one_still_high(self):
        assert " retrieval-relevance high " in _only_line(retrieval_top_relevance_score=1.7)

    def test_duration_above_one_still_anomalous(self):
        assert " duration anomalous " in _only_line(trace_duration_fraction=1.7)

    def test_type_errors_are_value_errors_not_type_errors(self):
        """Wrong types surface as ValueError, never as an incidental TypeError."""
        bad_rows = [
            _make_evidence(span_name=1),
            _make_evidence(is_root_span=1),
            _make_evidence(rank_position="1"),
            _make_evidence(retrieval_result_count="1"),
            _make_evidence(trace_duration_fraction="1"),
            _make_evidence(evidence_score="1"),
        ]
        for row in bad_rows:
            with pytest.raises(ValueError):
                _build(evidence=[row])


# ---------------------------------------------------------------------------
# D21  Whitespace-only identity values
# ---------------------------------------------------------------------------

_WHITESPACE_ONLY = [" ", "   ", "\t\n", "\r\n", " ", " 　", " \t \n "]
_WHITESPACE_ONLY_IDS = ["space", "spaces", "tab-lf", "crlf", "nbsp", "em-ideographic", "mixed"]


class TestWhitespaceOnlyIdentity:

    @pytest.mark.parametrize("value", _WHITESPACE_ONLY, ids=_WHITESPACE_ONLY_IDS)
    def test_whitespace_only_investigation_id_raises(self, value):
        with pytest.raises(ValueError, match="investigation_id"):
            _build(_make_investigation(investigation_id=value))

    @pytest.mark.parametrize("value", _WHITESPACE_ONLY, ids=_WHITESPACE_ONLY_IDS)
    def test_whitespace_only_confidence_raises(self, value):
        with pytest.raises(ValueError, match="confidence"):
            _build(_make_investigation(confidence=value))

    @pytest.mark.parametrize("value", _WHITESPACE_ONLY, ids=_WHITESPACE_ONLY_IDS)
    def test_whitespace_only_evidence_investigation_id_raises(self, value):
        with pytest.raises(ValueError, match="investigation_id"):
            _build(evidence=[_make_evidence(investigation_id=value)])

    @pytest.mark.parametrize("value", ["", " ", "\t\n"], ids=["empty", "space", "tab-lf"])
    def test_whitespace_only_evidence_id_raises_even_if_investigation_id_matches(self, value):
        """The evidence id is validated on its own, before the comparison."""
        with pytest.raises(ValueError, match="investigation_id"):
            _build(
                _make_investigation(investigation_id="x"),
                [_make_evidence(investigation_id=value)],
            )

    @pytest.mark.parametrize("value", [" ", "\t\n"], ids=["space", "tab-lf"])
    def test_whitespace_only_investigation_id_raises_before_ineligible_return(self, value):
        inv = _make_investigation(investigation_id=value, confidence="INSUFFICIENT_DATA")
        with pytest.raises(ValueError, match="investigation_id"):
            _build(inv)

    @pytest.mark.parametrize(
        "confidence",
        [" INSUFFICIENT_DATA", "INSUFFICIENT_DATA ", "\tINSUFFICIENT_DATA\n", " HIGH ", "HIGH\n"],
    )
    def test_padded_confidence_is_valid_and_eligible(self, confidence):
        """Padding is not stripped, so the value never exact-matches INSUFFICIENT_DATA."""
        doc = _build(_make_investigation(confidence=confidence))
        assert doc.eligible is True
        assert doc.text is not None

    def test_exact_insufficient_data_still_ineligible(self):
        doc = _build(_make_investigation(confidence="INSUFFICIENT_DATA"))
        assert doc.eligible is False
        assert doc.text is None

    @pytest.mark.parametrize(
        "investigation_id",
        [" " + _INV_ID, _INV_ID + " ", "\t" + _INV_ID + "\n", "  a b  "],
        ids=["leading", "trailing", "both", "inner"],
    )
    def test_padded_investigation_id_is_returned_unmodified(self, investigation_id):
        inv = _make_investigation(investigation_id=investigation_id)
        doc = _build(inv, [_make_evidence(investigation_id=investigation_id)])
        assert doc.eligible is True
        assert doc.investigation_id == investigation_id

    def test_padded_investigation_id_returned_unmodified_when_ineligible(self):
        padded = " " + _INV_ID + " "
        doc = _build(_make_investigation(investigation_id=padded, confidence="INSUFFICIENT_DATA"))
        assert doc.eligible is False
        assert doc.investigation_id == padded

    @pytest.mark.parametrize(
        "evidence_id",
        [" " + _INV_ID, _INV_ID + " ", _INV_ID + "\n"],
        ids=["leading", "trailing", "newline"],
    )
    def test_padded_evidence_id_is_not_stripped_for_comparison(self, evidence_id):
        """Valid as input, but it does not exact-match the unpadded investigation id."""
        with pytest.raises(ValueError, match="does not belong"):
            _build(evidence=[_make_evidence(investigation_id=evidence_id)])

    def test_padded_ids_match_only_when_identical(self):
        padded = " " + _INV_ID
        with pytest.raises(ValueError, match="does not belong"):
            _build(
                _make_investigation(investigation_id=padded),
                [_make_evidence(investigation_id=_INV_ID)],
            )


# ---------------------------------------------------------------------------
# D22  UTF-8 encodability
# ---------------------------------------------------------------------------

_HIGH_SURROGATE = "\ud83d"
_LOW_SURROGATE = "\ude00"

_SURROGATE_TEXTS = [
    _HIGH_SURROGATE,
    _LOW_SURROGATE,
    "abc" + _HIGH_SURROGATE,
    _LOW_SURROGATE + "abc",
    "a" + _HIGH_SURROGATE + "b",
    "a " + _LOW_SURROGATE + " b",
    _LOW_SURROGATE + _HIGH_SURROGATE,
    _HIGH_SURROGATE + _HIGH_SURROGATE,
    "\udfff",
    "\ud800",
]
_SURROGATE_IDS = [
    "lone-high", "lone-low", "trailing-high", "leading-low", "inner-high",
    "spaced-low", "reversed-pair", "two-highs", "last-low", "first-high",
]

_EVIDENCE_TEXT_FIELDS = _EVIDENCE_REQUIRED_TEXT + _EVIDENCE_OPTIONAL_TEXT
_HEADER_TEXT_FIELDS = ["anomaly_type", "service_name", "operation_name"]

_ROCKET = "\U0001F680"
_GRINNING = "\U0001F600"
_CJK_EXT_B = "\U00020000"


class TestUtf8Encodability:

    def test_surrogate_fixtures_are_not_encodable(self):
        for text in _SURROGATE_TEXTS:
            with pytest.raises(UnicodeEncodeError):
                text.encode("utf-8")

    @pytest.mark.parametrize("field", _EVIDENCE_TEXT_FIELDS)
    @pytest.mark.parametrize("text", [_HIGH_SURROGATE, "a" + _HIGH_SURROGATE + "b"],
                             ids=["lone-high", "inner-high"])
    def test_evidence_lone_high_surrogate_raises(self, field, text):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: text})])

    @pytest.mark.parametrize("field", _EVIDENCE_TEXT_FIELDS)
    @pytest.mark.parametrize("text", [_LOW_SURROGATE, "a" + _LOW_SURROGATE + "b"],
                             ids=["lone-low", "inner-low"])
    def test_evidence_lone_low_surrogate_raises(self, field, text):
        with pytest.raises(ValueError, match=field):
            _build(evidence=[_make_evidence(**{field: text})])

    @pytest.mark.parametrize("field", _HEADER_TEXT_FIELDS)
    @pytest.mark.parametrize("text", [_HIGH_SURROGATE, _LOW_SURROGATE],
                             ids=["lone-high", "lone-low"])
    def test_header_lone_surrogate_raises(self, field, text):
        with pytest.raises(ValueError, match=field):
            _build(_make_investigation(**{field: "svc" + text}))

    @pytest.mark.parametrize("text", [_HIGH_SURROGATE, _LOW_SURROGATE],
                             ids=["lone-high", "lone-low"])
    def test_derived_signal_lone_surrogate_raises(self, text):
        with pytest.raises(ValueError, match="derived_signal"):
            _build(derived_signal="sig" + text)

    @pytest.mark.parametrize("text", _SURROGATE_TEXTS, ids=_SURROGATE_IDS)
    def test_every_surrogate_shape_raises(self, text):
        with pytest.raises(ValueError, match="span_name"):
            _build(evidence=[_make_evidence(span_name=text)])

    def test_error_is_value_error_not_unicode_encode_error(self):
        """UnicodeEncodeError is itself a ValueError; the builder raises a plain one."""
        with pytest.raises(ValueError) as excinfo:
            _build(evidence=[_make_evidence(span_name=_HIGH_SURROGATE)])
        assert type(excinfo.value) is ValueError

    def test_surrogate_is_not_replaced_or_removed(self):
        """No document is produced; the bad character is never repaired."""
        for text in ("ok" + _HIGH_SURROGATE, _LOW_SURROGATE):
            with pytest.raises(ValueError):
                _build(evidence=[_make_evidence(agent_name=text)])

    def test_surrogate_validated_before_filtering(self):
        with pytest.raises(ValueError, match="tool_name"):
            _build(evidence=[
                _named(1),
                _named(2, evidence_type="telemetry", evidence_score=0.0,
                       tool_name=_LOW_SURROGATE),
            ])

    def test_surrogate_validated_beyond_top_five(self):
        evidence = [_named(r) for r in range(1, 9)] + [_named(9, error_type=_HIGH_SURROGATE)]
        with pytest.raises(ValueError, match="error_type"):
            _build(evidence=evidence)

    def test_surrogate_in_header_ignored_for_insufficient_data(self):
        """Document-only fields are not inspected on the ineligible path."""
        inv = _make_investigation(anomaly_type=_HIGH_SURROGATE, confidence="INSUFFICIENT_DATA")
        doc = _build(inv, [_make_evidence(span_name=_LOW_SURROGATE)], derived_signal=_LOW_SURROGATE)
        assert doc.eligible is False
        assert doc.text is None

    @pytest.mark.parametrize("field", _EVIDENCE_OPTIONAL_TEXT)
    @pytest.mark.parametrize("text", [_ROCKET, "launch " + _GRINNING, _CJK_EXT_B + "x"],
                             ids=["emoji", "text-emoji", "cjk-ext-b"])
    def test_evidence_non_bmp_text_accepted(self, field, text):
        doc_text = _text(evidence=[_make_evidence(**{field: text})])
        assert doc_text.encode("utf-8").decode("utf-8") == doc_text

    def test_non_bmp_text_is_preserved_in_document(self):
        inv = _make_investigation(service_name="pay " + _ROCKET, operation_name=_CJK_EXT_B)
        text = _text(
            inv,
            [_make_evidence(span_name="deploy " + _ROCKET, agent_name=_GRINNING,
                            evidence_type="mixed" + _ROCKET)],
            derived_signal="sig" + _GRINNING,
        )
        assert text == "\n".join([
            "anomaly: latency",
            "signal: sig" + _GRINNING,
            "service: pay " + _ROCKET,
            "operation: " + _CJK_EXT_B,
            "evidence:",
            '  span "deploy ' + _ROCKET + '" service "checkout" status OK '
            'agent "' + _GRINNING + '" evidence-type mixed' + _ROCKET,
        ])

    def test_non_bmp_text_is_still_nfc_normalized(self):
        line = _only_line(span_name="café " + _ROCKET)
        assert 'span "café ' + _ROCKET + '"' in line

    def test_non_bmp_document_round_trips_through_utf8(self):
        text = _text(evidence=[_make_evidence(span_name=_ROCKET + _GRINNING + _CJK_EXT_B)])
        encoded = text.encode("utf-8")
        assert encoded.decode("utf-8") == text
        assert _ROCKET.encode("utf-8") in encoded

    @pytest.mark.parametrize(
        "investigation, evidence, derived_signal",
        [
            (_make_investigation(), [], "agent_latency"),
            (_make_investigation(service_name=None, operation_name=None), [], "s"),
            (_make_investigation(), _varied_evidence(), "agent_latency"),
            (_make_investigation(service_name="café " + _ROCKET), [_full_row()], "x"),
            (_make_investigation(anomaly_type="åäö", operation_name="日本語"),
             [_named(1, span_name='q"\\' + _GRINNING, error_type="Ж")], "σ"),
            (_make_investigation(confidence="LOW"),
             [_named(r, evidence_type="telemetry", evidence_score=0.0) for r in range(1, 4)], "s"),
        ],
        ids=["none", "unknowns", "varied", "full-row", "multilingual", "all-filtered"],
    )
    def test_every_eligible_document_is_utf8_encodable(self, investigation, evidence, derived_signal):
        doc = _build(investigation, evidence, derived_signal)
        assert doc.eligible is True
        encoded = doc.text.encode("utf-8")
        assert encoded.decode("utf-8") == doc.text


# ---------------------------------------------------------------------------
# D19  Purity / import boundary
# ---------------------------------------------------------------------------

_ALLOWED_IMPORTS = {"__future__", "dataclasses", "math", "typing", "unicodedata"}


@pytest.fixture(scope="module")
def module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestPurityBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(incident_document.__file__) == _MODULE_PATH

    def test_imports_are_standard_library_allowlist_only(self, module_tree):
        assert _imported_modules(module_tree) <= _ALLOWED_IMPORTS

    @pytest.mark.parametrize(
        "forbidden",
        [
            "psycopg", "psycopg2", "sqlalchemy",
            "rca_confidence", "rca_ranker", "rca_models", "rca_source",
            "rca_persist", "rca_orchestrator", "rca_evidence", "rca_trace",
            "sentence_transformers", "transformers", "torch", "numpy",
            "huggingface_hub", "openai", "anthropic",
            "os", "sys", "io", "pathlib", "socket", "subprocess", "urllib",
            "requests", "logging", "datetime", "time", "random",
        ],
    )
    def test_forbidden_module_not_imported(self, module_tree, forbidden):
        assert forbidden not in _imported_modules(module_tree)

    def test_no_io_or_dynamic_import_calls(self, module_tree):
        forbidden_calls = {"open", "print", "input", "exec", "eval", "__import__", "compile"}
        called = {
            node.func.id
            for node in ast.walk(module_tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert called.isdisjoint(forbidden_calls)

    def test_no_signal_derivation_logic(self, module_tree):
        """derived_signal is an input; the module defines no derive function."""
        names = {
            node.name
            for node in ast.walk(module_tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert not any("derive" in name for name in names)

    def test_public_names(self):
        public = {
            name for name in vars(incident_document)
            if not name.startswith("_")
            and getattr(vars(incident_document)[name], "__module__", "incident_document")
            == "incident_document"
            and name not in {"annotations", "math", "unicodedata"}
        }
        assert public == {
            "DOC_VERSION",
            "InvestigationRow",
            "EvidenceRow",
            "IncidentDocument",
            "build_incident_document",
        }
