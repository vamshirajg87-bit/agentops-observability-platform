"""
alerting/tests/unit/test_alert_guardrail_cli.py

Unit tests for alert_guardrail_cli.py.

No live PostgreSQL and no network.  alert_db.connect, run_guardrails and the
clock are replaced; the policy file and the detector configuration are real
files in a temporary directory, read by the real loaders.

Test inventory:
    GC01  Arguments
    GC02  Wiring: policy, detector configuration, clock, connection
    GC03  Golden output
    GC04  Exit codes
    GC05  Connection ownership
    GC06  Nothing sensitive is printed
    GC07  Keyboard interrupt
    GC08  Unexpected internal error
    GC09  End to end with the real guardrails and an in-memory store
    GC10  Module boundaries
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import psycopg
import psycopg.errors
import pytest

import alert_guardrail_cli as cli
import alert_guardrail_store
from alert_guardrails import (
    DETAIL_OK,
    GUARDRAIL_CODES,
    GuardrailEvaluationError,
    GuardrailResult,
    violation_detail,
)
from alert_identity import compute_attempt_id
from alert_models import GuardrailFinding, GuardrailStatus
from alert_policy import AlertPolicy


_NOW = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)

_GROUP = ("trace_latency", "agentops-demo-app", "agentops.request")
_GROUP_ID = '["trace_latency","agentops-demo-app","agentops.request"]'

_POLICY_DOCUMENT = {
    "policy_schema_version": "1.0.0",
    "policy_version": "1.0.0",
    "evaluation": {},
    "delivery": {"channels": [{"name": "log", "type": "log", "enabled": True}]},
    "guardrails": {},
}

_DETECTOR_DOCUMENT = {
    "run": {"overlap_minutes": 5, "initial_lookback_hours": 24},
    "groups": [{
        "signal_path": _GROUP[0],
        "service_name": _GROUP[1],
        "operation_name": _GROUP[2],
    }],
}

_ALL_OK_LINES = [f"{code} OK count=0" for code in GUARDRAIL_CODES]


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _result(code: str, count: int = 0, ids=None) -> GuardrailResult:
    """A consistent result with `count` violations."""
    if count == 0:
        return GuardrailResult(
            GuardrailFinding(code, GuardrailStatus.OK, 0, DETAIL_OK), (),
        )
    if ids is None:
        ids = [_hex(f"{code}-{n}") for n in range(count)]
    shown = tuple(ids[:20])
    return GuardrailResult(
        GuardrailFinding(
            code, GuardrailStatus.VIOLATION, count,
            violation_detail(count, len(shown)),
        ),
        shown,
    )


def _results(*counts: int) -> tuple[GuardrailResult, ...]:
    counts = counts or (0, 0, 0, 0)
    return tuple(_result(code, count) for code, count in zip(GUARDRAIL_CODES, counts))


class Harness:
    def __init__(self, monkeypatch, tmp_path, *, fake_run: bool = True) -> None:
        self.tmp_path = tmp_path
        self.policy_path = str(tmp_path / "policy.json")
        self.detector_path = str(tmp_path / "runner_config.json")
        self.write_policy(_POLICY_DOCUMENT)
        self.write_detector(_DETECTOR_DOCUMENT)
        self.conn = MagicMock(name="connection")
        self.connect_calls: list[dict] = []
        self.connect_error: BaseException | None = None
        self.run_calls: list[tuple] = []
        self.results = _results()
        self.run_error: BaseException | None = None
        self.clock_calls = 0
        monkeypatch.setattr(cli.alert_db, "connect", self._connect)
        monkeypatch.setattr(cli, "_utc_now", self._now)
        if fake_run:
            monkeypatch.setattr(cli, "run_guardrails", self._run_guardrails)

    @staticmethod
    def _write(path: str, document) -> None:
        text = document if isinstance(document, str) else json.dumps(document)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def write_policy(self, document) -> None:
        self._write(self.policy_path, document)

    def write_detector(self, document) -> None:
        self._write(self.detector_path, document)

    def _now(self) -> datetime:
        self.clock_calls += 1
        return _NOW

    def _connect(self, **kwargs):
        self.connect_calls.append(kwargs)
        if self.connect_error is not None:
            raise self.connect_error
        return self.conn

    def _run_guardrails(self, conn, **kwargs):
        self.run_calls.append((conn, kwargs))
        if self.run_error is not None:
            raise self.run_error
        return self.results

    def main(self, *extra: str) -> int:
        return cli.main([
            "--policy", self.policy_path,
            "--detector-config", self.detector_path,
            *extra,
        ])

    def released(self) -> bool:
        """The connection was rolled back, then closed, and never committed."""
        names = [call[0] for call in self.conn.method_calls]
        return names == ["rollback", "close"]


@pytest.fixture
def harness(monkeypatch, tmp_path) -> Harness:
    return Harness(monkeypatch, tmp_path)


def _out(capsys) -> tuple[str, str]:
    captured = capsys.readouterr()
    return captured.out, captured.err


# ---------------------------------------------------------------------------
# GC01  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    @pytest.mark.parametrize("argv", [
        [],
        ["--policy", "p.json"],
        ["--detector-config", "d.json"],
    ])
    def test_both_paths_are_required(self, harness, capsys, argv):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(argv)
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == []
        assert _out(capsys)[0] == ""

    @pytest.mark.parametrize("option", [
        "--fix", "--retry", "--write", "--remediate", "--daemon", "--watch",
        "--json", "--backdate", "--dry-run", "--now", "--limit",
    ])
    def test_there_is_no_other_option(self, harness, capsys, option):
        with pytest.raises(SystemExit) as excinfo:
            harness.main(option)
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == [] and harness.run_calls == []
        assert _out(capsys)[0] == ""

    def test_positional_argument_is_rejected(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            harness.main("extra")
        assert excinfo.value.code == cli.EXIT_USAGE

    def test_declared_options_are_exactly_two(self):
        tree = ast.parse(inspect.getsource(cli))
        flags = [
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ]
        assert flags == ["--policy", "--detector-config"]


# ---------------------------------------------------------------------------
# GC02  Wiring
# ---------------------------------------------------------------------------

class TestWiring:

    def test_one_read_only_connection(self, harness):
        assert harness.main() == cli.EXIT_OK
        assert harness.connect_calls == [{"read_only": True}]

    def test_run_receives_policy_groups_and_the_one_clock_value(self, harness):
        harness.main()
        ((conn, kwargs),) = harness.run_calls
        assert conn is harness.conn
        assert set(kwargs) == {"policy", "expected_groups", "now"}
        assert isinstance(kwargs["policy"], AlertPolicy)
        assert kwargs["policy"].policy_version == "1.0.0"
        assert kwargs["expected_groups"] == (_GROUP,)
        assert kwargs["now"] is _NOW
        assert harness.clock_calls == 1

    def test_clock_is_utc(self):
        now = cli._utc_now()
        assert now.tzinfo is timezone.utc

    def test_missing_operation_name_is_the_empty_string(self, harness):
        harness.write_detector({"groups": [
            {"signal_path": "tool_latency", "service_name": "svc"},
            {"signal_path": "retrieval", "service_name": "svc", "operation_name": None},
        ]})
        harness.main()
        assert harness.run_calls[0][1]["expected_groups"] == (
            ("tool_latency", "svc", ""), ("retrieval", "svc", ""),
        )

    def test_configuration_is_loaded_before_the_clock_and_the_connection(self, harness):
        harness.write_detector("{}")
        assert harness.main() == cli.EXIT_CONFIGURATION
        assert harness.clock_calls == 0
        assert harness.connect_calls == []


# ---------------------------------------------------------------------------
# GC03  Golden output
# ---------------------------------------------------------------------------

class TestOutput:

    def test_all_ok(self, harness, capsys):
        assert harness.main() == cli.EXIT_OK
        out, err = _out(capsys)
        assert out == "\n".join(_ALL_OK_LINES) + "\n"
        assert err == ""

    def test_violations_list_their_identifiers(self, harness, capsys):
        pair = f"{_hex('decision')}/log"
        harness.results = (
            _result("detector_checkpoint_stale", 1, [_GROUP_ID]),
            _result("uninvestigated_anomalies", 2, [_hex("a"), _hex("b")]),
            _result("delivery_uncertain"),
            _result("delivery_exhausted", 1, [pair]),
        )
        assert harness.main() == cli.EXIT_VIOLATION
        out, err = _out(capsys)
        assert out.splitlines() == [
            "detector_checkpoint_stale VIOLATION count=1",
            f"  {_GROUP_ID}",
            "uninvestigated_anomalies VIOLATION count=2",
            f"  {_hex('a')}",
            f"  {_hex('b')}",
            "delivery_uncertain OK count=0",
            "delivery_exhausted VIOLATION count=1",
            f"  {pair}",
        ]
        assert err == ""

    def test_more_than_twenty_shows_twenty_and_the_remainder(self, harness, capsys):
        harness.results = _results(0, 23, 0, 0)
        assert harness.main() == cli.EXIT_VIOLATION
        lines = _out(capsys)[0].splitlines()
        assert lines[1] == "uninvestigated_anomalies VIOLATION count=23"
        assert lines[2:22] == [
            f"  {_hex(f'uninvestigated_anomalies-{n}')}" for n in range(20)
        ]
        assert lines[22] == "  (+3 more)"
        assert lines[23:] == _ALL_OK_LINES[2:]

    def test_exactly_twenty_has_no_remainder_line(self, harness, capsys):
        harness.results = _results(20, 0, 0, 0)
        harness.main()
        out = _out(capsys)[0]
        assert "more)" not in out
        assert len(out.splitlines()) == 4 + 20

    def test_four_headers_in_fixed_order(self, harness, capsys):
        harness.results = _results(3, 25, 1, 40)
        harness.main()
        headers = [
            line for line in _out(capsys)[0].splitlines() if not line.startswith("  ")
        ]
        assert [line.split(" ")[0] for line in headers] == list(GUARDRAIL_CODES)
        assert [line.split(" ", 1)[1] for line in headers] == [
            "VIOLATION count=3", "VIOLATION count=25",
            "VIOLATION count=1", "VIOLATION count=40",
        ]

    def test_the_fixed_detail_text_is_not_printed(self, harness, capsys):
        harness.results = _results(0, 23, 0, 0)
        harness.main()
        out = _out(capsys)[0]
        assert DETAIL_OK not in out
        assert "violation(s)" not in out and "showing" not in out

    def test_render_is_pure_and_has_no_trailing_newline(self):
        text = cli.render_results(_results(0, 1, 0, 0))
        assert not text.endswith("\n")
        assert text == cli.render_results(_results(0, 1, 0, 0))

    def test_unencodable_identifier_does_not_fail_the_write(self):
        class Ascii:
            encoding = "ascii"

            def __init__(self) -> None:
                self.written: list[str] = []

            def write(self, text: str) -> None:
                text.encode("ascii")
                self.written.append(text)

        stream = Ascii()
        cli._write(stream, "café")
        assert stream.written == ["caf\\xe9\n"]


# ---------------------------------------------------------------------------
# GC04  Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_values(self):
        assert (
            cli.EXIT_OK, cli.EXIT_INTERNAL, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION,
            cli.EXIT_DATABASE, cli.EXIT_VIOLATION, cli.EXIT_INTERRUPTED,
        ) == (0, 1, 2, 3, 4, 6, 130)
        assert not hasattr(cli, "EXIT_POLICY_CONFLICT")

    @pytest.mark.parametrize("counts", [
        (1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1), (5, 5, 5, 5),
    ])
    def test_any_violation_is_six(self, harness, counts):
        harness.results = _results(*counts)
        assert harness.main() == 6

    def test_missing_policy_file(self, harness, capsys):
        harness.policy_path = str(harness.tmp_path / "absent.json")
        assert harness.main() == 3
        assert _out(capsys) == (
            "", "error: configuration: cannot read the policy file (FileNotFoundError)\n",
        )

    @pytest.mark.parametrize("document, error_type", [
        ("{not json", "JSONDecodeError"),
        ({"policy_version": "1.0.0"}, "PolicyValidationError"),
        ('{"a": 1, "a": 2}', "PolicyValidationError"),
        ("[]", "PolicyValidationError"),
    ])
    def test_invalid_policy(self, harness, capsys, document, error_type):
        harness.write_policy(document)
        assert harness.main() == 3
        assert _out(capsys) == (
            "", f"error: configuration: invalid policy ({error_type})\n",
        )

    def test_policy_that_is_not_utf8(self, harness, capsys):
        with open(harness.policy_path, "wb") as fh:
            fh.write(b"\xff\xfe{}")
        assert harness.main() == 3
        assert _out(capsys)[1] == (
            "error: configuration: invalid policy (UnicodeDecodeError)\n"
        )

    def test_recursion_error_in_the_policy_is_a_configuration_error(
        self, harness, capsys, monkeypatch,
    ):
        def too_deep(path):
            raise RecursionError("maximum recursion depth exceeded in PRIVATE")

        monkeypatch.setattr(cli, "load_policy", too_deep)
        assert harness.main() == 3
        assert _out(capsys) == (
            "", "error: configuration: invalid policy (RecursionError)\n",
        )
        assert harness.connect_calls == []

    def test_deeply_nested_policy_file_is_a_configuration_error(self, harness, capsys):
        harness.write_policy("[" * 200_000 + "]" * 200_000)
        assert harness.main() == 3
        out, err = _out(capsys)
        assert out == ""
        assert err == "error: configuration: invalid policy (RecursionError)\n"

    def test_missing_detector_config_file(self, harness, capsys):
        harness.detector_path = str(harness.tmp_path / "absent.json")
        assert harness.main() == 3
        assert _out(capsys) == (
            "",
            "error: configuration: cannot read the detector config file "
            "(FileNotFoundError)\n",
        )

    @pytest.mark.parametrize("document, phrase", [
        ("{not json", "the file is not valid UTF-8 JSON"),
        ("[]", "the top level must be a JSON object"),
        ({"run": {}}, "'groups' is required"),
        ({"groups": {}}, "'groups' must be a list"),
        ({"groups": []}, "'groups' must hold at least one group"),
        ({"groups": [_DETECTOR_DOCUMENT["groups"][0]] * 2},
         "group 1 repeats an earlier group"),
        ({"groups": [{"signal_path": "x", "service_name": "y", "extra": 1}]},
         "group 0 has an unknown key"),
        ({"groups": [{"service_name": "y"}]}, "group 0: 'signal_path' is required"),
        ('{"groups": [], "groups": []}', "a JSON object repeats a key"),
        ('{"groups": [NaN]}', "the file holds NaN or Infinity"),
    ])
    def test_invalid_detector_config(self, harness, capsys, document, phrase):
        harness.write_detector(document)
        assert harness.main() == 3
        assert _out(capsys) == (
            "", f"error: configuration: invalid detector config: {phrase}\n",
        )
        assert harness.connect_calls == []

    def test_deeply_nested_detector_config(self, harness, capsys):
        harness.write_detector("[" * 200_000 + "]" * 200_000)
        assert harness.main() == 3
        assert _out(capsys)[1] == (
            "error: configuration: invalid detector config: "
            "the file is not valid UTF-8 JSON\n"
        )

    def test_missing_database_password(self, harness, capsys):
        harness.connect_error = RuntimeError(
            "ALERT_EVALUATOR_DB_PASSWORD environment variable is not set"
        )
        assert harness.main() == 3
        assert _out(capsys) == (
            "",
            "error: configuration: ALERT_EVALUATOR_DB_PASSWORD environment "
            "variable is not set\n",
        )
        assert harness.run_calls == []

    def test_connection_failure(self, harness, capsys):
        harness.connect_error = psycopg.OperationalError("connection refused")
        assert harness.main() == 4
        assert _out(capsys) == ("", "error: database: OperationalError\n")
        assert harness.run_calls == []

    def test_database_error_during_the_run(self, harness, capsys):
        harness.run_error = psycopg.errors.InsufficientPrivilege("permission denied")
        assert harness.main() == 4
        assert _out(capsys) == (
            "", "error: database: InsufficientPrivilege (SQLSTATE 42501)\n",
        )

    @pytest.mark.parametrize("codes, reason, text", [
        (("detector_checkpoint_stale",), "invalid_checkpoint_data",
         "detector_checkpoint_stale: invalid_checkpoint_data"),
        (("uninvestigated_anomalies",), "invalid_anomaly_data",
         "uninvestigated_anomalies: invalid_anomaly_data"),
        (("delivery_uncertain", "delivery_exhausted"), "invalid_delivery_data",
         "delivery_uncertain,delivery_exhausted: invalid_delivery_data"),
    ])
    def test_malformed_stored_data(self, harness, capsys, codes, reason, text):
        harness.run_error = GuardrailEvaluationError(codes, reason)
        assert harness.main() == 4
        assert _out(capsys) == ("", f"error: guardrail evaluation failed: {text}\n")

    def test_a_violation_is_not_an_error(self, harness, capsys):
        harness.results = _results(1, 1, 1, 1)
        assert harness.main() == 6
        assert _out(capsys)[1] == ""


# ---------------------------------------------------------------------------
# GC05  Connection ownership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    def test_success_rolls_back_then_closes(self, harness):
        harness.main()
        assert harness.released()

    def test_violation_rolls_back_then_closes(self, harness):
        harness.results = _results(1, 0, 0, 0)
        harness.main()
        assert harness.released()

    @pytest.mark.parametrize("error", [
        psycopg.OperationalError("lost"),
        GuardrailEvaluationError(("uninvestigated_anomalies",), "invalid_anomaly_data"),
        KeyboardInterrupt(),
        RuntimeError("defect"),
    ])
    def test_every_failure_rolls_back_then_closes(self, harness, error):
        harness.run_error = error
        harness.main()
        assert harness.released()

    def test_never_commits(self, harness):
        for counts in ((0, 0, 0, 0), (1, 2, 3, 4)):
            harness.results = _results(*counts)
            harness.main()
        assert harness.conn.commit.call_count == 0

    def test_output_is_written_after_the_connection_is_released(self, harness, monkeypatch):
        order: list[str] = []
        harness.conn.rollback.side_effect = lambda: order.append("rollback")
        harness.conn.close.side_effect = lambda: order.append("close")
        monkeypatch.setattr(cli, "_write", lambda stream, text: order.append("write"))
        harness.main()
        assert order == ["rollback", "close", "write"]

    def test_close_is_attempted_when_rollback_fails(self, harness, capsys):
        harness.conn.rollback.side_effect = psycopg.OperationalError("PRIVATE")
        assert harness.main() == cli.EXIT_OK
        assert harness.conn.close.call_count == 1
        out, err = _out(capsys)
        assert out == "\n".join(_ALL_OK_LINES) + "\n"
        assert err == "error: rollback failed during cleanup: OperationalError\n"

    def test_close_failure_does_not_change_the_exit_code(self, harness, capsys):
        harness.results = _results(0, 0, 1, 0)
        harness.conn.close.side_effect = psycopg.OperationalError("PRIVATE")
        assert harness.main() == cli.EXIT_VIOLATION
        assert _out(capsys)[1] == "error: close failed during cleanup: OperationalError\n"

    def test_no_connection_is_opened_on_a_configuration_error(self, harness):
        harness.write_policy("{")
        harness.main()
        assert harness.connect_calls == []
        assert harness.conn.method_calls == []

    def test_nothing_to_release_when_connecting_fails(self, harness):
        harness.connect_error = psycopg.OperationalError("refused")
        harness.main()
        assert harness.conn.method_calls == []


# ---------------------------------------------------------------------------
# GC06  Nothing sensitive is printed
# ---------------------------------------------------------------------------

_PRIVATE = "PRIVATE-token-https://secret.example/hook?key=abc SELECT summary"


class TestNothingSensitive:

    def test_database_message_is_not_printed(self, harness, capsys):
        harness.run_error = psycopg.errors.UniqueViolation(_PRIVATE)
        harness.main()
        out, err = _out(capsys)
        assert out == ""
        assert err == "error: database: UniqueViolation (SQLSTATE 23505)\n"

    def test_connection_message_is_not_printed(self, harness, capsys):
        harness.connect_error = psycopg.OperationalError(_PRIVATE)
        harness.main()
        assert "PRIVATE" not in "".join(_out(capsys))

    def test_paths_are_not_printed(self, harness, capsys):
        harness.policy_path = str(harness.tmp_path / "PRIVATE-policy.json")
        harness.main()
        harness.policy_path = str(harness.tmp_path / "policy.json")
        harness.detector_path = str(harness.tmp_path / "PRIVATE-detector.json")
        harness.main()
        out, err = _out(capsys)
        assert out == ""
        assert "PRIVATE" not in err and str(harness.tmp_path) not in err
        assert len(err.splitlines()) == 2

    def test_policy_values_are_not_printed(self, harness, capsys):
        harness.write_policy({**_POLICY_DOCUMENT, "PRIVATE-key": "PRIVATE-value"})
        assert harness.main() == 3
        assert "PRIVATE" not in "".join(_out(capsys))

    def test_detector_config_values_are_not_printed(self, harness, capsys):
        harness.write_detector({"groups": [
            {"signal_path": "PRIVATE-signal", "service_name": "PRIVATE-service",
             "operation_name": 5, "PRIVATE-key": 1},
        ]})
        assert harness.main() == 3
        assert "PRIVATE" not in "".join(_out(capsys))

    @pytest.mark.parametrize("error", [
        psycopg.OperationalError(_PRIVATE),
        GuardrailEvaluationError(("delivery_uncertain", "delivery_exhausted"),
                                 "invalid_delivery_data"),
        RuntimeError(_PRIVATE),
        KeyboardInterrupt(),
    ])
    def test_no_finding_is_printed_when_the_run_fails(self, harness, capsys, error):
        harness.results = _results(1, 1, 1, 1)
        harness.run_error = error
        harness.main()
        out, err = _out(capsys)
        assert out == ""
        assert "PRIVATE" not in err and "Traceback" not in err
        assert len(err.splitlines()) <= 1

    def test_error_text_is_one_line(self, capsys):
        cli._error("first\nsecond\tthird   fourth")
        assert _out(capsys)[1] == "error: first second third fourth\n"


# ---------------------------------------------------------------------------
# GC07  Keyboard interrupt
# ---------------------------------------------------------------------------

class TestInterrupt:

    def test_during_the_run(self, harness, capsys):
        harness.run_error = KeyboardInterrupt()
        assert harness.main() == 130
        assert _out(capsys) == ("", "")
        assert harness.released()

    def test_while_connecting(self, harness, capsys):
        harness.connect_error = KeyboardInterrupt()
        assert harness.main() == 130
        assert _out(capsys) == ("", "")
        assert harness.conn.method_calls == []

    def test_while_loading_the_policy(self, harness, capsys, monkeypatch):
        def interrupted(path):
            raise KeyboardInterrupt()

        monkeypatch.setattr(cli, "load_policy", interrupted)
        assert harness.main() == 130
        assert _out(capsys) == ("", "")
        assert harness.connect_calls == []

    def test_while_loading_the_detector_config(self, harness, capsys, monkeypatch):
        def interrupted(path):
            raise KeyboardInterrupt()

        monkeypatch.setattr(cli, "load_expected_groups", interrupted)
        assert harness.main() == 130
        assert _out(capsys) == ("", "")
        assert harness.connect_calls == []

    def test_is_not_reported_as_an_internal_error(self, harness, capsys):
        harness.run_error = KeyboardInterrupt()
        assert harness.main() != cli.EXIT_INTERNAL
        assert "internal" not in _out(capsys)[1]


# ---------------------------------------------------------------------------
# GC08  Unexpected internal error
# ---------------------------------------------------------------------------

class TestInternalError:

    @pytest.mark.parametrize("error, name", [
        (RuntimeError(_PRIVATE), "RuntimeError"),
        (ValueError(_PRIVATE), "ValueError"),
        (KeyError(_PRIVATE), "KeyError"),
        (TypeError(_PRIVATE), "TypeError"),
        (ZeroDivisionError(_PRIVATE), "ZeroDivisionError"),
        (OSError(_PRIVATE), "OSError"),
    ])
    def test_unexpected_error_in_the_run_is_sanitized(self, harness, capsys, error, name):
        harness.run_error = error
        assert harness.main() == 1
        out, err = _out(capsys)
        assert out == ""
        assert err == f"error: internal: {name}\n"
        assert harness.released()

    def test_unexpected_error_before_the_connection(self, harness, capsys, monkeypatch):
        def broken_clock():
            raise ZeroDivisionError(_PRIVATE)

        monkeypatch.setattr(cli, "_utc_now", broken_clock)
        assert harness.main() == 1
        assert _out(capsys) == ("", "error: internal: ZeroDivisionError\n")
        assert harness.connect_calls == []

    def test_unexpected_error_while_printing(self, harness, capsys, monkeypatch):
        real_write = cli._write

        def broken(stream, text):
            if stream is cli.sys.stdout:
                raise BrokenPipeError(_PRIVATE)
            real_write(stream, text)

        monkeypatch.setattr(cli, "_write", broken)
        assert harness.main() == 1
        assert _out(capsys) == ("", "error: internal: BrokenPipeError\n")
        assert harness.released()

    def test_no_traceback_and_no_chained_message(self, harness, capsys):
        try:
            raise ValueError(_PRIVATE)
        except ValueError as inner:
            outer = RuntimeError("outer PRIVATE")
            outer.__cause__ = inner
        harness.run_error = outer
        harness.main()
        err = _out(capsys)[1]
        assert "Traceback" not in err and "PRIVATE" not in err
        assert err == "error: internal: RuntimeError\n"

    def test_system_exit_is_not_caught(self, harness):
        harness.run_error = SystemExit(7)
        with pytest.raises(SystemExit) as excinfo:
            harness.main()
        assert excinfo.value.code == 7
        assert harness.released()

    def test_other_base_exceptions_are_not_caught(self, harness):
        harness.run_error = GeneratorExit()
        with pytest.raises(GeneratorExit):
            harness.main()

    @pytest.mark.parametrize("error, code", [
        (psycopg.OperationalError("lost"), 4),
        (psycopg.errors.InsufficientPrivilege("denied"), 4),
        (GuardrailEvaluationError(("uninvestigated_anomalies",),
                                  "invalid_anomaly_data"), 4),
    ])
    def test_known_run_failures_keep_their_exit_code(self, harness, capsys, error, code):
        harness.run_error = error
        assert harness.main() == code
        assert "internal" not in _out(capsys)[1]

    def test_known_configuration_failures_keep_their_exit_code(self, harness, capsys):
        harness.write_policy("{")
        assert harness.main() == 3
        harness.write_policy(_POLICY_DOCUMENT)
        harness.write_detector({"groups": []})
        assert harness.main() == 3
        harness.write_detector(_DETECTOR_DOCUMENT)
        harness.connect_error = RuntimeError(
            "ALERT_EVALUATOR_DB_PORT environment variable must be an integer"
        )
        assert harness.main() == 3
        assert "internal" not in _out(capsys)[1]

    def test_only_exception_is_contained(self):
        tree = ast.parse(inspect.getsource(cli.main))
        caught = [
            handler.type.id for handler in ast.walk(tree)
            if isinstance(handler, ast.ExceptHandler)
        ]
        assert caught == ["KeyboardInterrupt", "Exception"]
        assert "BaseException" not in inspect.getsource(cli.main)


# ---------------------------------------------------------------------------
# GC09  End to end with the real guardrails and an in-memory store
# ---------------------------------------------------------------------------

def _dec(n) -> str:
    return _hex(f"decision-{n}")


def _attempt(n, attempt_no, outcome) -> dict:
    started = _NOW - timedelta(minutes=5)
    return {
        "attempt_id": compute_attempt_id(_dec(n), "log", attempt_no),
        "decision_id": _dec(n),
        "channel_name": "log",
        "channel_type": "log",
        "attempt_no": attempt_no,
        "trigger": "auto",
        "summary_included": False,
        "payload_sha256": "f" * 64,
        "started_at": started,
        "outcome": outcome,
        "recorded_at": started if outcome is not None else None,
    }


class FakeStore:
    def __init__(self, monkeypatch) -> None:
        self.checkpoints: list[dict] = []
        self.anomalies: list[dict] = []
        self.decisions: list[dict] = []
        self.history: list[dict] = []
        self.calls: list[str] = []
        for name in ("fetch_checkpoints", "fetch_uninvestigated_anomalies",
                     "fetch_alert_decisions", "fetch_delivery_history"):
            monkeypatch.setattr(alert_guardrail_store, name, getattr(self, name))

    def fetch_checkpoints(self, conn):
        self.calls.append("checkpoints")
        return list(self.checkpoints)

    def fetch_uninvestigated_anomalies(self, conn):
        self.calls.append("anomalies")
        return list(self.anomalies)

    def fetch_alert_decisions(self, conn, *, lookback_start):
        self.calls.append("decisions")
        return list(self.decisions)

    def fetch_delivery_history(self, conn, *, decision_ids, channel_names):
        self.calls.append("history")
        return [
            row for row in self.history
            if row["decision_id"] in decision_ids and row["channel_name"] in channel_names
        ]


@pytest.fixture
def end_to_end(monkeypatch, tmp_path):
    harness = Harness(monkeypatch, tmp_path, fake_run=False)
    return harness, FakeStore(monkeypatch)


def _fresh_checkpoint() -> dict:
    return {
        "signal_path": _GROUP[0], "service_name": _GROUP[1],
        "operation_name": _GROUP[2], "updated_at": _NOW - timedelta(minutes=5),
    }


class TestEndToEnd:

    def test_all_ok(self, end_to_end, capsys):
        harness, store = end_to_end
        store.checkpoints = [_fresh_checkpoint()]
        assert harness.main() == 0
        assert _out(capsys) == ("\n".join(_ALL_OK_LINES) + "\n", "")
        assert store.calls == ["checkpoints", "anomalies", "decisions", "history"]
        assert harness.released()

    def test_all_four_violated(self, end_to_end, capsys):
        harness, store = end_to_end
        anomaly_id = _hex("anomaly")
        store.anomalies = [
            {"anomaly_id": anomaly_id, "detected_at": _NOW - timedelta(days=2)},
        ]
        evaluated = _NOW - timedelta(minutes=10)
        store.decisions = [
            {"decision_id": _dec(1), "evaluated_at": evaluated},
            {"decision_id": _dec(2), "evaluated_at": evaluated},
        ]
        store.history = [
            _attempt(1, 1, "UNCERTAIN"), _attempt(2, 1, "FAILED_PERMANENT"),
        ]
        assert harness.main() == 6
        out, err = _out(capsys)
        assert out.splitlines() == [
            "detector_checkpoint_stale VIOLATION count=1",
            f"  {_GROUP_ID}",
            "uninvestigated_anomalies VIOLATION count=1",
            f"  {anomaly_id}",
            "delivery_uncertain VIOLATION count=1",
            f"  {_dec(1)}/log",
            "delivery_exhausted VIOLATION count=1",
            f"  {_dec(2)}/log",
        ]
        assert err == ""
        assert harness.conn.commit.call_count == 0

    def test_no_enabled_channel_skips_the_delivery_reads(self, end_to_end, capsys):
        harness, store = end_to_end
        harness.write_policy({**_POLICY_DOCUMENT, "delivery": {"channels": []}})
        store.checkpoints = [_fresh_checkpoint()]
        assert harness.main() == 0
        assert store.calls == ["checkpoints", "anomalies"]
        assert _out(capsys)[0] == "\n".join(_ALL_OK_LINES) + "\n"

    @pytest.mark.parametrize("corrupt, text", [
        (lambda store: store.checkpoints.append(
            {**_fresh_checkpoint(), "updated_at": "PRIVATE"}),
         "detector_checkpoint_stale: invalid_checkpoint_data"),
        (lambda store: store.anomalies.append(
            {"anomaly_id": "PRIVATE", "detected_at": _NOW}),
         "uninvestigated_anomalies: invalid_anomaly_data"),
        (lambda store: store.history.append(_attempt(1, 2, "PRIVATE")),
         "delivery_uncertain,delivery_exhausted: invalid_delivery_data"),
    ])
    def test_malformed_stored_data_prints_no_finding(
        self, end_to_end, capsys, corrupt, text,
    ):
        harness, store = end_to_end
        # Violations exist too; none may be printed.
        store.anomalies = [
            {"anomaly_id": _hex("anomaly"), "detected_at": _NOW - timedelta(days=2)},
        ]
        store.decisions = [
            {"decision_id": _dec(1), "evaluated_at": _NOW - timedelta(minutes=10)},
        ]
        corrupt(store)
        assert harness.main() == 4
        assert _out(capsys) == ("", f"error: guardrail evaluation failed: {text}\n")
        assert harness.released()

    def test_database_error_from_the_store(self, end_to_end, capsys, monkeypatch):
        harness, _ = end_to_end

        def denied(conn):
            raise psycopg.errors.InsufficientPrivilege(_PRIVATE)

        monkeypatch.setattr(alert_guardrail_store, "fetch_checkpoints", denied)
        assert harness.main() == 4
        assert _out(capsys) == (
            "", "error: database: InsufficientPrivilege (SQLSTATE 42501)\n",
        )


# ---------------------------------------------------------------------------
# GC10  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(cli))

    def test_imports(self, tree):
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "argparse", "sys", "datetime", "typing",
            "alert_db", "alert_guardrails", "alert_models", "alert_policy",
        }

    def test_no_driver_and_no_statement(self):
        source = inspect.getsource(cli)
        for word in ("psycopg", "SELECT ", "INSERT ", "UPDATE ", "DELETE ",
                     "execute(", "cursor(", ".commit("):
            assert word not in source, word

    def test_no_environment_network_file_or_remediation(self, tree):
        source = inspect.getsource(cli)
        for word in ("socket", "urllib", "requests", "subprocess", "open(",
                     "alert_notifier", "alert_channels", "alert_delivery_store",
                     "alert_store", "alert_evaluator", "retry_delivery"):
            assert word not in source, word
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes.isdisjoint({"environ", "getenv", "commit", "send"})

    def test_clock_is_read_in_one_place(self, tree):
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "now"
        ]
        assert len(calls) == 1

    def test_connection_is_only_rolled_back_and_closed(self, tree):
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "conn"
        }
        assert used == {"rollback", "close"}
