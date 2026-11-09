"""
incident-retrieval/tests/unit/test_historical_context_cli.py

Unit tests for historical_context_cli.py.

No database, no model, no network.  retrieval_db.connect and
get_historical_context are replaced, and stdout / stderr are captured.

Test inventory:
    CL01  Arguments
    CL02  Identity from the locked constants; service call
    CL03  Report: golden output for each retrieval status
    CL04  Report: display rules (similarity, none, whitespace, order)
    CL05  Disclaimer and wording
    CL06  Exit codes
    CL07  Connection ownership: rollback + close, never commit
    CL08  Boundaries: no SQL, no driver import, no model, argparse only
"""

from __future__ import annotations

import ast
import datetime
import os
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

import historical_context_cli as cli
import retrieval_db
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity
from historical_context import (
    HISTORICAL_CONTEXT_DISCLAIMER,
    HistoricalContext,
    HistoricalMatch,
    InvestigationContext,
)
from historical_context_cli import main, render_historical_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "historical_context_cli.py")

_INV = "a" * 64
_B, _C = ("b" * 64, "c" * 64)
_EMB = "9" * 64

_T0 = datetime.datetime(2026, 9, 28, 14, 2, 11, tzinfo=datetime.timezone.utc)
_T1 = datetime.datetime(2026, 9, 21, 9, 40, 3, tzinfo=datetime.timezone.utc)

_NOTE = (
    "Note: Historical similarity provides context only. It does not prove that the "
    "current incident has the same root cause as any historical investigation."
)


def _investigation(investigation_id: str = _INV, **overrides) -> InvestigationContext:
    kwargs = dict(
        investigation_id=investigation_id,
        anomaly_type="tool_failure",
        service_name="agentops-demo-app",
        operation_name="tool.execute/ToolExecutionError",
        confidence="HIGH",
        severity="CRITICAL",
        event_time=_T0,
        summary="Span 'tool.execute' showed the strongest contributing evidence.",
        limitations=("tool_name_absent",),
    )
    kwargs.update(overrides)
    return InvestigationContext(**kwargs)


def _context(status: str = "ok", matches=(), top_k: int = 5, current=None, embedding_id=_EMB) -> HistoricalContext:
    return HistoricalContext(
        status=status,
        embedding_id=embedding_id,
        top_k=top_k,
        current=current if current is not None else _investigation(),
        matches=tuple(matches),
        disclaimer=HISTORICAL_CONTEXT_DISCLAIMER,
    )


def _match(investigation_id: str, similarity: float, **overrides) -> HistoricalMatch:
    return HistoricalMatch(similarity, _investigation(investigation_id, **overrides))


_CURRENT_BLOCK = "\n".join([
    "Current investigation",
    f"  investigation: {_INV}",
    "  anomaly:       tool_failure",
    "  service:       agentops-demo-app",
    "  operation:     tool.execute/ToolExecutionError",
    "  severity:      CRITICAL",
    "  confidence:    HIGH",
    "  event time:    2026-09-28T14:02:11+00:00",
    "  limitations:   tool_name_absent",
    "  summary:       Span 'tool.execute' showed the strongest contributing evidence.",
])


class Harness:
    """Replaces the connection factory and the service inside the CLI module."""

    def __init__(self, monkeypatch) -> None:
        self.conn = MagicMock(name="connection")
        self.connect_calls = 0
        self.connect_error: BaseException | None = None
        self.service_calls: list[tuple] = []
        self.service_result: HistoricalContext | None = _context()
        self.service_error: BaseException | None = None
        monkeypatch.setattr(cli.retrieval_db, "connect", self._connect)
        monkeypatch.setattr(cli, "get_historical_context", self._service)

    def _connect(self):
        self.connect_calls += 1
        if self.connect_error is not None:
            raise self.connect_error
        return self.conn

    def _service(self, conn, identity, investigation_id, *, top_k):
        self.service_calls.append((conn, identity, investigation_id, top_k))
        if self.service_error is not None:
            raise self.service_error
        return self.service_result


@pytest.fixture
def harness(monkeypatch) -> Harness:
    return Harness(monkeypatch)


# ---------------------------------------------------------------------------
# CL01  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    def test_investigation_id_is_required(self, harness, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main([])
        assert excinfo.value.code == 2
        assert harness.connect_calls == 0

    def test_investigation_id_passed_to_the_service(self, harness):
        main([_INV])
        assert harness.service_calls[0][2] == _INV

    def test_default_top_k_is_five(self, harness):
        main([_INV])
        assert harness.service_calls[0][3] == 5

    @pytest.mark.parametrize("value", ["1", "2", "5", "49", "50"])
    def test_valid_top_k(self, harness, value):
        assert main([_INV, "--top-k", value]) == 0
        assert harness.service_calls[0][3] == int(value)
        assert type(harness.service_calls[0][3]) is int

    def test_top_k_equals_form(self, harness):
        assert main([_INV, "--top-k=7"]) == 0
        assert harness.service_calls[0][3] == 7

    def test_option_before_positional(self, harness):
        assert main(["--top-k", "3", _INV]) == 0
        assert harness.service_calls[0][2:] == (_INV, 3)

    @pytest.mark.parametrize("value", ["0", "51", "-1", "100", "abc", "5.0", "", "1e1", "True"])
    def test_invalid_top_k_is_a_usage_error(self, harness, capsys, value):
        with pytest.raises(SystemExit) as excinfo:
            main([_INV, f"--top-k={value}"])
        assert excinfo.value.code == 2
        assert "between 1 and 50" in capsys.readouterr().err
        assert harness.connect_calls == 0
        assert harness.service_calls == []

    def test_top_k_is_never_clamped(self, harness):
        for value in ("0", "51"):
            with pytest.raises(SystemExit):
                main([_INV, "--top-k", value])
        assert harness.service_calls == []

    @pytest.mark.parametrize("value", ["", "   ", "\t"])
    def test_blank_investigation_id_is_a_usage_error(self, harness, capsys, value):
        with pytest.raises(SystemExit) as excinfo:
            main([value])
        assert excinfo.value.code == 2
        assert harness.connect_calls == 0

    def test_unknown_option_is_a_usage_error(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            main([_INV, "--json"])
        assert excinfo.value.code == 2
        assert harness.connect_calls == 0

    def test_extra_positional_is_a_usage_error(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            main([_INV, _B])
        assert excinfo.value.code == 2

    def test_help_exits_zero_and_mentions_context_only(self, harness, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "--top-k" in out and "investigation_id" in out
        assert "context only" in out
        assert harness.connect_calls == 0

    def test_only_two_arguments_are_defined(self):
        options = [
            node.args[0].value for node in ast.walk(ast.parse(open(_MODULE_PATH, encoding="utf-8").read()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ]
        assert options == ["investigation_id", "--top-k"]


# ---------------------------------------------------------------------------
# CL02  Identity and service call
# ---------------------------------------------------------------------------

class TestIdentityAndServiceCall:

    def test_identity_is_built_from_the_locked_constants(self, harness):
        main([_INV])
        assert harness.service_calls[0][1] == EmbeddingModelIdentity(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            dimension=384,
        )

    def test_identity_uses_the_backend_module_constants(self):
        import sentence_transformer_backend as backend
        identity = cli._locked_identity()
        assert identity.model_name is backend.MODEL_NAME
        assert identity.model_revision is backend.MODEL_REVISION
        assert identity.dimension == backend.EMBEDDING_DIMENSION

    def test_service_called_exactly_once_with_the_open_connection(self, harness):
        main([_INV])
        assert len(harness.service_calls) == 1
        assert harness.service_calls[0][0] is harness.conn
        assert harness.connect_calls == 1

    def test_model_library_is_not_loaded(self, harness):
        watched = ("sentence_transformers", "torch", "transformers")
        before = {m for m in watched if m in sys.modules}
        main([_INV])
        assert {m for m in watched if m in sys.modules} == before

    def test_importing_and_running_help_loads_no_model_library(self):
        code = (
            "import sys; sys.argv=['historical_context_cli.py','--help']\n"
            "import historical_context_cli as c\n"
            "c._locked_identity()\n"
            "print(sorted(m for m in ('sentence_transformers','torch','transformers',"
            "'tokenizers','huggingface_hub','numpy') if m in sys.modules))\n"
        )
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=_COMPONENT_DIR, env=env,
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "[]"


# ---------------------------------------------------------------------------
# CL03  Golden reports
# ---------------------------------------------------------------------------

class TestGoldenReports:

    def test_ok_with_matches(self, harness, capsys):
        harness.service_result = _context(
            top_k=2,
            matches=[
                _match(_B, 0.8214, confidence="MEDIUM", severity="WARNING",
                       event_time=_T1, limitations=(), summary="First historical summary."),
                _match(_C, 0.763, anomaly_type="latency", service_name=None,
                       operation_name=None, confidence="LOW", severity="INFO",
                       event_time=_T1, limitations=("partial_trace", "no_error_spans"),
                       summary="Second historical summary."),
            ],
        )
        assert main([_INV, "--top-k", "2"]) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == "\n".join([
            _CURRENT_BLOCK,
            "",
            "Retrieval status: ok",
            "  2 historical matches (top-k 2), ordered by similarity.",
            "",
            "Historical matches",
            "",
            f"1. investigation: {_B}",
            "   similarity:    0.8214",
            "   anomaly:       tool_failure",
            "   service:       agentops-demo-app",
            "   operation:     tool.execute/ToolExecutionError",
            "   severity:      WARNING",
            "   confidence:    MEDIUM",
            "   event time:    2026-09-21T09:40:03+00:00",
            "   limitations:   (none)",
            "   summary:       First historical summary.",
            "",
            f"2. investigation: {_C}",
            "   similarity:    0.7630",
            "   anomaly:       latency",
            "   service:       (none)",
            "   operation:     (none)",
            "   severity:      INFO",
            "   confidence:    LOW",
            "   event time:    2026-09-21T09:40:03+00:00",
            "   limitations:   partial_trace, no_error_spans",
            "   summary:       Second historical summary.",
            "",
            _NOTE,
        ]) + "\n"

    def test_ok_with_zero_matches(self, harness, capsys):
        harness.service_result = _context()
        assert main([_INV]) == 0
        assert capsys.readouterr().out == "\n".join([
            _CURRENT_BLOCK,
            "",
            "Retrieval status: ok",
            "  No historical matches were found.",
            "",
            _NOTE,
        ]) + "\n"

    def test_query_not_embedded(self, harness, capsys):
        harness.service_result = _context(status="query_not_embedded")
        assert main([_INV]) == 0
        assert capsys.readouterr().out == "\n".join([
            _CURRENT_BLOCK,
            "",
            "Retrieval status: query_not_embedded",
            "  This investigation has no stored embedding for the current model and "
            "document version, so it cannot be compared. Nothing was embedded or written.",
            "",
            _NOTE,
        ]) + "\n"

    def test_not_eligible(self, harness, capsys):
        current = _investigation(
            confidence="INSUFFICIENT_DATA", limitations=("no_trace_id",),
            summary="Insufficient telemetry was available for evidence analysis: "
                    "no trace ID was associated with this anomaly.",
        )
        harness.service_result = _context(status="not_eligible", current=current, embedding_id=None)
        assert main([_INV]) == 0
        assert capsys.readouterr().out == "\n".join([
            "Current investigation",
            f"  investigation: {_INV}",
            "  anomaly:       tool_failure",
            "  service:       agentops-demo-app",
            "  operation:     tool.execute/ToolExecutionError",
            "  severity:      CRITICAL",
            "  confidence:    INSUFFICIENT_DATA",
            "  event time:    2026-09-28T14:02:11+00:00",
            "  limitations:   no_trace_id",
            "  summary:       Insufficient telemetry was available for evidence analysis: "
            "no trace ID was associated with this anomaly.",
            "",
            "Retrieval status: not_eligible",
            "  Investigations with confidence INSUFFICIENT_DATA are not compared.",
            "",
            _NOTE,
        ]) + "\n"

    def test_text_mismatch(self, harness, capsys):
        harness.service_result = _context(status="text_mismatch")
        assert main([_INV]) == 0
        assert capsys.readouterr().out == "\n".join([
            _CURRENT_BLOCK,
            "",
            "Retrieval status: text_mismatch",
            "  The stored embedding of this investigation no longer matches its current "
            "incident document, so it was not used for comparison.",
            "",
            _NOTE,
        ]) + "\n"

    def test_single_match_uses_singular_wording(self, harness, capsys):
        harness.service_result = _context(matches=[_match(_B, 0.5)])
        main([_INV])
        assert "  1 historical match (top-k 5), ordered by similarity." in capsys.readouterr().out

    def test_render_has_no_trailing_newline_and_main_adds_one(self, harness, capsys):
        text = render_historical_context(_context())
        assert not text.endswith("\n")
        main([_INV])
        assert capsys.readouterr().out == text + "\n"

    def test_output_is_deterministic(self, harness, capsys):
        harness.service_result = _context(matches=[_match(_B, 0.9), _match(_C, 0.8)])
        main([_INV])
        first = capsys.readouterr().out
        main([_INV])
        assert capsys.readouterr().out == first
        assert render_historical_context(harness.service_result) + "\n" == first


# ---------------------------------------------------------------------------
# CL04  Display rules
# ---------------------------------------------------------------------------

class TestDisplayRules:

    @pytest.mark.parametrize(
        "value, shown",
        [
            (0.8214567890123456, "0.8215"),
            (0.82144, "0.8214"),
            (1.0, "1.0000"),
            (0.0, "0.0000"),
            (-0.25, "-0.2500"),
            (-1.0, "-1.0000"),
            (0.5, "0.5000"),
            (1.0000005, "1.0000"),
            (0.99996, "1.0000"),
            (1e-12, "0.0000"),
        ],
    )
    def test_similarity_shown_to_exactly_four_decimals(self, value, shown):
        text = render_historical_context(_context(matches=[_match(_B, value)]))
        assert f"   similarity:    {shown}\n" in text

    def test_raw_similarity_is_unchanged_by_rendering(self):
        value = 0.8214567890123456
        context = _context(matches=[_match(_B, value)])
        render_historical_context(context)
        assert context.matches[0].similarity == value
        assert repr(context.matches[0].similarity) == repr(value)

    def test_similarity_label_is_similarity_only(self):
        text = render_historical_context(_context(matches=[_match(_B, 0.9)]))
        line = next(l for l in text.split("\n") if "0.9000" in l)
        assert line.strip().startswith("similarity:")

    def test_no_similarity_bands_or_percentages(self):
        text = render_historical_context(
            _context(matches=[_match(_B, 0.99), _match(_C, 0.01)]),
        ).lower()
        for word in ("%", "strong match", "weak match", "high similarity",
                     "low similarity", "medium similarity", "likely", "probab",
                     "threshold", "score:"):
            assert word not in text

    def test_low_and_negative_similarity_are_still_shown(self):
        text = render_historical_context(
            _context(matches=[_match(_B, 0.01), _match(_C, -0.4)]),
        )
        assert "0.0100" in text and "-0.4000" in text
        assert text.count("investigation: ") == 3

    def test_match_order_is_preserved(self):
        text = render_historical_context(
            _context(matches=[_match(_C, 0.1), _match(_B, 0.9)]),
        )
        assert text.index(f"1. investigation: {_C}") < text.index(f"2. investigation: {_B}")

    def test_matches_are_not_re_sorted_by_similarity(self):
        text = render_historical_context(
            _context(matches=[_match(_B, 0.2), _match(_C, 0.8)]),
        )
        assert text.index("0.2000") < text.index("0.8000")

    def test_two_digit_rank_keeps_field_alignment(self):
        matches = [_match(f"{i:064x}", 0.5) for i in range(1, 11)]
        lines = render_historical_context(_context(matches=matches, top_k=10)).split("\n")
        index = lines.index(f"10. investigation: {10:064x}")
        assert lines[index + 1] == "    similarity:    0.5000"
        assert lines[index + 2] == "    anomaly:       tool_failure"

    def test_null_service_and_operation_shown_as_none(self):
        text = render_historical_context(
            _context(current=_investigation(service_name=None, operation_name=None)),
        )
        assert "  service:       (none)\n" in text
        assert "  operation:     (none)\n" in text

    def test_empty_limitations_shown_as_none(self):
        text = render_historical_context(_context(current=_investigation(limitations=())))
        assert "  limitations:   (none)\n" in text

    def test_limitations_joined_with_comma(self):
        text = render_historical_context(
            _context(current=_investigation(limitations=("a_code", "b_code", "c_code"))),
        )
        assert "  limitations:   a_code, b_code, c_code\n" in text

    def test_event_time_is_iso_8601(self):
        text = render_historical_context(_context())
        assert "  event time:    2026-09-28T14:02:11+00:00\n" in text

    def test_stored_whitespace_is_collapsed_for_display_only(self):
        current = _investigation(summary="  line one\n  line two\tend  ", service_name=" svc\r\nname ")
        context = _context(current=current)
        text = render_historical_context(context)
        assert "  summary:       line one line two end\n" in text
        assert "  service:       svc name\n" in text
        assert context.current.summary == "  line one\n  line two\tend  "

    def test_stored_newlines_cannot_add_report_lines(self):
        plain = render_historical_context(_context())
        noisy = render_historical_context(
            _context(current=_investigation(summary="a\nb\nc", limitations=("x\ny",))),
        )
        assert len(noisy.split("\n")) == len(plain.split("\n"))

    def test_blank_text_shown_as_none(self):
        text = render_historical_context(_context(current=_investigation(summary="   ")))
        assert "  summary:       (none)\n" in text

    def test_no_trailing_whitespace_and_lf_only(self):
        text = render_historical_context(
            _context(matches=[_match(_B, 0.9, service_name=None, limitations=())]),
        )
        assert "\r" not in text
        assert all(line == line.rstrip() for line in text.split("\n"))

    def test_only_presentation_fields_are_shown(self):
        text = render_historical_context(_context(matches=[_match(_B, 0.9)])).lower()
        for label in ("trace_span_count", "trace id", "trace_id", "anomaly_id",
                      "investigated", "embedding", "model", "revision", "doc_version",
                      "evidence score", "rank_position"):
            assert label not in text

    def test_embedding_id_and_model_identity_are_not_printed(self):
        text = render_historical_context(_context())
        assert _EMB not in text
        assert "all-MiniLM" not in text

    def test_non_ascii_text_is_written(self, harness, capsys):
        harness.service_result = _context(current=_investigation(summary="café → \U0001F680"))
        assert main([_INV]) == 0
        assert "café → \U0001F680" in capsys.readouterr().out

    def test_unencodable_text_does_not_crash_the_writer(self):
        import io

        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="ascii", errors="strict", newline="\n")
        cli._write(stream, "summary → café")
        stream.flush()
        assert buffer.getvalue() == b"summary \\u2192 caf\\xe9\n"


# ---------------------------------------------------------------------------
# CL05  Disclaimer and wording
# ---------------------------------------------------------------------------

_ALL_STATUS_CONTEXTS = {
    "ok-with-matches": lambda: _context(matches=[_match(_B, 0.9)]),
    "ok-empty": lambda: _context(),
    "not_eligible": lambda: _context(status="not_eligible", embedding_id=None),
    "query_not_embedded": lambda: _context(status="query_not_embedded"),
    "text_mismatch": lambda: _context(status="text_mismatch"),
}


class TestDisclaimerAndWording:

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_disclaimer_is_always_the_last_line(self, harness, capsys, name):
        harness.service_result = _ALL_STATUS_CONTEXTS[name]()
        assert main([_INV]) == 0
        assert capsys.readouterr().out.rstrip("\n").split("\n")[-1] == _NOTE

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_disclaimer_appears_exactly_once(self, name):
        text = render_historical_context(_ALL_STATUS_CONTEXTS[name]())
        assert text.count(HISTORICAL_CONTEXT_DISCLAIMER) == 1

    def test_disclaimer_comes_from_the_result(self):
        context = dataclass_replace_disclaimer(_context(), "A different fixed statement.")
        assert render_historical_context(context).endswith("Note: A different fixed statement.")

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_root_cause_appears_only_in_the_disclaimer(self, name):
        text = render_historical_context(_ALL_STATUS_CONTEXTS[name]())
        body = text.replace(HISTORICAL_CONTEXT_DISCLAIMER, "")
        assert "root cause" not in body.lower()
        assert text.lower().count("root cause") == 1

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_no_causal_or_advisory_wording_is_added(self, name):
        body = render_historical_context(_ALL_STATUS_CONTEXTS[name]()).replace(
            HISTORICAL_CONTEXT_DISCLAIMER, "",
        ).lower()
        for phrase in ("caused by", "because of", "responsible for", "same cause",
                       "likely cause", "probable", "recommend", "you should",
                       "fix", "remediat", "diagnos"):
            assert phrase not in body

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_status_is_printed_verbatim(self, name):
        context = _ALL_STATUS_CONTEXTS[name]()
        assert f"\nRetrieval status: {context.status}\n" in render_historical_context(context)

    def test_every_retrieval_status_has_wording(self):
        import similarity_search
        for status in similarity_search.RETRIEVAL_STATUSES:
            render_historical_context(_context(status=status))

    def test_confidence_label_refers_only_to_the_rca_field(self):
        text = render_historical_context(
            _context(matches=[_match(_B, 0.97, confidence="LOW")]),
        )
        confidence_lines = [l.strip() for l in text.split("\n") if "confidence:" in l]
        assert confidence_lines == ["confidence:    HIGH", "confidence:    LOW"]

    def test_module_documentation_states_the_disclaimer(self):
        doc = " ".join(cli.__doc__.split())
        assert "Historical similarity provides context only." in doc
        assert "does not prove" in doc


def dataclass_replace_disclaimer(context: HistoricalContext, text: str) -> HistoricalContext:
    import dataclasses
    return dataclasses.replace(context, disclaimer=text)


# ---------------------------------------------------------------------------
# CL06  Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_exit_code_constants(self):
        assert (cli.EXIT_OK, cli.EXIT_NOT_FOUND, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION,
                cli.EXIT_DATABASE, cli.EXIT_DATA_INTEGRITY, cli.EXIT_INTERRUPTED) == (
            0, 1, 2, 3, 4, 6, 130,
        )

    def test_exit_code_five_is_not_used(self):
        constants = {
            name: value for name, value in vars(cli).items() if name.startswith("EXIT_")
        }
        assert 5 not in constants.values()
        assert sorted(constants.values()) == [0, 1, 2, 3, 4, 6, 130]

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_every_retrieval_status_exits_zero(self, harness, capsys, name):
        harness.service_result = _ALL_STATUS_CONTEXTS[name]()
        assert main([_INV]) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out.startswith("Current investigation\n")

    def test_investigation_not_found_exits_one(self, harness, capsys):
        harness.service_error = InvestigationNotFoundError(_INV)
        assert main([_INV]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"error: investigation not found: {_INV!r}\n"

    def test_usage_error_exits_two(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            main([_INV, "--top-k", "0"])
        assert excinfo.value.code == 2

    def test_missing_password_exits_three(self, harness, capsys):
        harness.connect_error = RuntimeError(
            "INCIDENT_RETRIEVAL_DB_PASSWORD environment variable is not set"
        )
        assert main([_INV]) == 3
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "error: configuration: INCIDENT_RETRIEVAL_DB_PASSWORD environment variable is not set\n"
        )
        assert harness.service_calls == []

    def test_connection_failure_exits_four(self, harness, capsys):
        harness.connect_error = retrieval_db.DatabaseError("connection refused")
        assert main([_INV]) == 4
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error: database: connection refused\n"
        assert harness.service_calls == []

    def test_database_error_during_retrieval_exits_four(self, harness, capsys):
        import psycopg
        harness.service_error = psycopg.OperationalError("server closed the connection")
        assert main([_INV]) == 4
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error: database: server closed the connection\n"

    @pytest.mark.parametrize(
        "error",
        [
            RuntimeError("context of historical investigation 'x' is missing"),
            RuntimeError("similarity for investigation 'x' is not finite; a stored embedding is corrupt"),
            ValueError("duplicate rank_position 2"),
        ],
        ids=["missing-context", "corrupt-embedding", "builder-rejects-data"],
    )
    def test_data_integrity_error_exits_six(self, harness, capsys, error):
        harness.service_error = error
        assert main([_INV]) == 6
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"error: data integrity: {error}\n"

    def test_unknown_status_from_the_service_exits_six(self, harness, capsys):
        harness.service_result = _context(status="something_new")
        assert main([_INV]) == 6
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "unknown retrieval status" in captured.err

    def test_keyboard_interrupt_exits_130(self, harness, capsys):
        harness.service_error = KeyboardInterrupt()
        assert main([_INV]) == 130
        assert capsys.readouterr().out == ""

    def test_not_found_is_not_treated_as_data_integrity(self, harness):
        """InvestigationNotFoundError is a ValueError; it must still map to 1."""
        harness.service_error = InvestigationNotFoundError(_INV)
        assert main([_INV]) == 1

    def test_database_error_is_not_treated_as_data_integrity(self, harness):
        harness.service_error = retrieval_db.DatabaseError("boom")
        assert main([_INV]) == 4

    def test_error_message_is_one_line(self, harness, capsys):
        harness.service_error = RuntimeError("line one\nline two\n\tline three")
        main([_INV])
        assert capsys.readouterr().err == "error: data integrity: line one line two line three\n"

    def test_unexpected_programming_error_is_not_swallowed(self, harness):
        harness.service_error = KeyError("unexpected")
        with pytest.raises(KeyError):
            main([_INV])

    def test_errors_go_to_stderr_and_reports_to_stdout(self, harness, capsys):
        main([_INV])
        ok = capsys.readouterr()
        harness.service_error = InvestigationNotFoundError(_INV)
        main([_INV])
        failed = capsys.readouterr()
        assert ok.out and not ok.err
        assert failed.err and not failed.out


# ---------------------------------------------------------------------------
# CL07  Connection ownership
# ---------------------------------------------------------------------------

_SERVICE_ERRORS = {
    "not-found": lambda: InvestigationNotFoundError(_INV),
    "database": lambda: retrieval_db.DatabaseError("boom"),
    "runtime": lambda: RuntimeError("boom"),
    "value": lambda: ValueError("boom"),
    "interrupt": lambda: KeyboardInterrupt(),
}


class TestConnectionOwnership:

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS))
    def test_rollback_then_close_on_every_successful_outcome(self, harness, name):
        harness.service_result = _ALL_STATUS_CONTEXTS[name]()
        main([_INV])
        assert [c[0] for c in harness.conn.mock_calls] == ["rollback", "close"]

    @pytest.mark.parametrize("name", sorted(_SERVICE_ERRORS))
    def test_rollback_then_close_on_every_error(self, harness, name):
        harness.service_error = _SERVICE_ERRORS[name]()
        main([_INV])
        assert [c[0] for c in harness.conn.mock_calls] == ["rollback", "close"]

    def test_cleanup_also_runs_for_an_unexpected_error(self, harness):
        harness.service_error = KeyError("unexpected")
        with pytest.raises(KeyError):
            main([_INV])
        assert [c[0] for c in harness.conn.mock_calls] == ["rollback", "close"]

    @pytest.mark.parametrize("name", sorted(_ALL_STATUS_CONTEXTS) + sorted(_SERVICE_ERRORS))
    def test_never_commits(self, harness, name):
        if name in _ALL_STATUS_CONTEXTS:
            harness.service_result = _ALL_STATUS_CONTEXTS[name]()
        else:
            harness.service_error = _SERVICE_ERRORS[name]()
        main([_INV])
        harness.conn.commit.assert_not_called()

    def test_rollback_and_close_called_exactly_once(self, harness):
        main([_INV])
        harness.conn.rollback.assert_called_once_with()
        harness.conn.close.assert_called_once_with()

    def test_close_is_attempted_when_rollback_fails(self, harness, capsys):
        harness.conn.rollback.side_effect = retrieval_db.DatabaseError("rollback broke")
        assert main([_INV]) == 0
        harness.conn.close.assert_called_once_with()
        captured = capsys.readouterr()
        assert "error: rollback failed during cleanup: rollback broke\n" in captured.err
        assert captured.out.startswith("Current investigation\n")

    def test_close_failure_does_not_change_the_result(self, harness, capsys):
        harness.conn.close.side_effect = retrieval_db.DatabaseError("close broke")
        assert main([_INV]) == 0
        captured = capsys.readouterr()
        assert "error: close failed during cleanup: close broke\n" in captured.err
        assert captured.out.startswith("Current investigation\n")

    def test_both_cleanup_steps_failing_keeps_the_exit_code(self, harness, capsys):
        harness.conn.rollback.side_effect = RuntimeError("r")
        harness.conn.close.side_effect = RuntimeError("c")
        harness.service_error = InvestigationNotFoundError(_INV)
        assert main([_INV]) == 1
        err = capsys.readouterr().err
        assert "rollback failed during cleanup" in err and "close failed during cleanup" in err
        harness.conn.close.assert_called_once_with()

    def test_cleanup_happens_before_the_report_is_printed(self, harness, capsys):
        events = []
        harness.conn.close.side_effect = lambda: events.append("close")
        original_write = cli._write

        def recording_write(stream, text):
            if stream is sys.stdout:
                events.append("report")
            original_write(stream, text)

        cli._write = recording_write
        try:
            main([_INV])
        finally:
            cli._write = original_write
        assert events == ["close", "report"]

    def test_no_connection_when_connect_fails(self, harness):
        harness.connect_error = RuntimeError("no password")
        assert main([_INV]) == 3
        assert harness.conn.mock_calls == []

    def test_no_connection_is_opened_for_a_usage_error(self, harness):
        with pytest.raises(SystemExit):
            main([_INV, "--top-k", "99"])
        assert harness.connect_calls == 0
        assert harness.conn.mock_calls == []

    def test_exactly_one_connection_per_run(self, harness):
        main([_INV])
        assert harness.connect_calls == 1

    def test_connection_is_used_only_for_cleanup_by_the_cli(self, harness):
        """The CLI hands the connection to the service and otherwise only cleans up."""
        main([_INV])
        assert {c[0] for c in harness.conn.mock_calls} == {"rollback", "close"}


# ---------------------------------------------------------------------------
# CL08  Boundaries
# ---------------------------------------------------------------------------

def _module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules() -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestBoundaries:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(cli.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "argparse", "sys", "typing",
            "retrieval_db", "embedding_pipeline", "embedding_provider",
            "historical_context", "sentence_transformer_backend", "similarity_search",
        }

    def test_does_not_import_the_database_driver(self):
        assert "psycopg" not in _imported_modules()

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "psycopg2", "embedding_store", "sentence_transformers", "torch",
         "transformers", "numpy", "click", "typer", "rich", "docopt", "fire",
         "json", "logging", "socket", "subprocess", "os", "incident_document",
         "embedding_record", "incident_signal", "rca_models"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    def test_database_errors_are_caught_through_retrieval_db(self):
        tree = _module_tree()
        caught = [
            ast.unparse(handler.type) for handler in ast.walk(tree)
            if isinstance(handler, ast.ExceptHandler) and handler.type is not None
        ]
        assert caught.count("retrieval_db.DatabaseError") == 2
        assert not any("psycopg" in name for name in caught)

    def test_cli_contains_no_sql(self):
        tree = _module_tree()
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"execute", "executemany", "cursor"})
        strings = [
            n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" not in n.value
        ]
        for text in strings:
            words = set(text.upper().replace(",", " ").split())
            assert words.isdisjoint({"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE"}), text

    def test_cli_never_commits_or_writes(self):
        tree = _module_tree()
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert "commit" not in attributes
        assert {"rollback", "close"} <= attributes
        referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | attributes
        for forbidden in ("insert_embedding", "embed_investigation", "embed",
                          "create_default_provider", "load", "find_similar_investigations"):
            assert forbidden not in referenced

    def test_only_constants_are_imported_from_the_model_backend(self):
        imported = []
        for node in ast.walk(_module_tree()):
            if isinstance(node, ast.ImportFrom) and node.module == "sentence_transformer_backend":
                imported.extend(alias.name for alias in node.names)
        assert sorted(imported) == ["EMBEDDING_DIMENSION", "MODEL_NAME", "MODEL_REVISION"]

    def test_only_argparse_is_used_for_arguments(self):
        tree = _module_tree()
        parsers = [
            ast.unparse(node.func) for node in ast.walk(tree)
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("ArgumentParser")
        ]
        assert parsers == ["argparse.ArgumentParser"]

    def test_no_json_output_option(self):
        source = open(_MODULE_PATH, encoding="utf-8").read()
        assert "--json" not in source
        assert "json" not in _imported_modules()

    def test_script_entry_point_exists(self):
        source = open(_MODULE_PATH, encoding="utf-8").read()
        assert 'if __name__ == "__main__":' in source
        assert "sys.exit(main())" in source

    def test_no_reasoning_or_generation_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("root_cause", "diagnos", "infer", "predict", "recommend",
                     "remediat", "summar", "generate", "explain", "threshold", "backfill"):
            assert not any(word in name for name in names)
