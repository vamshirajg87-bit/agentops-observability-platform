"""
alerting/tests/unit/test_alert_evaluate_cli.py

Unit tests for alert_evaluate_cli.py.

No live PostgreSQL and no network.  alert_db.connect, run_evaluation and the
clock are replaced; the policy file is a real file in a temporary directory,
read by the real loader.

Test inventory:
    EC01  Arguments
    EC02  Wiring: policy, clock, connection, evaluator
    EC03  Golden output
    EC04  Exit codes
    EC05  Connection ownership
    EC06  Nothing sensitive is printed
    EC07  End to end with the real evaluator and an in-memory store
    EC08  Module boundaries
"""

from __future__ import annotations

import ast
import inspect
import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import psycopg
import pytest

import alert_evaluate_cli as cli
import alert_store
from alert_evaluator import (
    POLICY_ALREADY_REGISTERED,
    POLICY_NOT_REGISTERED,
    POLICY_REGISTERED,
    STATUS_ALREADY_DECIDED,
    STATUS_DRY_RUN,
    STATUS_FAILURE,
    STATUS_PERSISTED,
    EvaluationReport,
    EvaluationResult,
    PolicyVersionConflictError,
)
from alert_models import Decision, ReasonCode
from alert_policy import AlertPolicy, load_policy


_NOW = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_NOW_TEXT = "2026-10-05T19:00:00.000000Z"

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_DA = "1" * 64
_DB = "2" * 64
_DC = "3" * 64

_REPO_POLICY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "policy.json")
)

_POLICY_DOCUMENT = {
    "policy_schema_version": "1.0.0",
    "policy_version": "1.0.0",
    "evaluation": {},
    "delivery": {"channels": []},
    "guardrails": {},
}


def _result(investigation_id, status, decision_id=None, decision=None,
            reason=None, related=None, hypothetical=False, error=None):
    return EvaluationResult(
        investigation_id=investigation_id, status=status, decision_id=decision_id,
        decision=decision, reason_code=reason, related_decision_id=related,
        related_is_hypothetical=hypothetical, error=error,
    )


def _alert(investigation_id=_A, decision_id=_DA, status=STATUS_PERSISTED):
    return _result(investigation_id, status, decision_id, Decision.ALERT,
                   ReasonCode.SEVERITY_MET)


def _cooldown(investigation_id=_B, decision_id=_DB, related=_DA,
              status=STATUS_PERSISTED, hypothetical=False):
    return _result(investigation_id, status, decision_id, Decision.SUPPRESSED,
                   ReasonCode.COOLDOWN, related, hypothetical)


def _failure(investigation_id=_C, error="ValueError: severity is not a known Severity value"):
    return _result(investigation_id, STATUS_FAILURE, error=error)


class Harness:
    def __init__(self, monkeypatch, tmp_path) -> None:
        self.tmp_path = tmp_path
        self.policy_path = str(tmp_path / "policy.json")
        self.write_policy(_POLICY_DOCUMENT)
        self.conn = MagicMock(name="connection")
        self.connect_calls: list[dict] = []
        self.connect_error: BaseException | None = None
        self.run_calls: list[tuple] = []
        self.results: list[EvaluationResult] = []
        self.policy_status = POLICY_REGISTERED
        self.run_error: BaseException | None = None
        self.error_after: int | None = None
        self.clock_calls = 0
        monkeypatch.setattr(cli.alert_db, "connect", self._connect)
        monkeypatch.setattr(cli, "run_evaluation", self._run_evaluation)
        monkeypatch.setattr(cli, "_utc_now", self._now)

    def write_policy(self, document) -> None:
        text = document if isinstance(document, str) else json.dumps(document)
        with open(self.policy_path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _now(self) -> datetime:
        self.clock_calls += 1
        return _NOW

    def _connect(self, **kwargs):
        self.connect_calls.append(kwargs)
        if self.connect_error is not None:
            raise self.connect_error
        return self.conn

    def _run_evaluation(self, conn, policy, *, evaluated_at, dry_run=False, on_result=None):
        self.run_calls.append((conn, policy, evaluated_at, dry_run, on_result))
        emitted = []
        for index, result in enumerate(self.results):
            if self.run_error is not None and index == self.error_after:
                raise self.run_error
            emitted.append(result)
            if on_result is not None:
                on_result(result)
        if self.run_error is not None and self.error_after in (None, len(self.results)):
            raise self.run_error
        return EvaluationReport(tuple(emitted), self.policy_status, dry_run)

    def main(self, *extra: str) -> int:
        return cli.main(["--policy", self.policy_path, *extra])


@pytest.fixture
def harness(monkeypatch, tmp_path) -> Harness:
    return Harness(monkeypatch, tmp_path)


def _header(sha256: str, dry_run: bool = False) -> list[str]:
    title = "Alert evaluation"
    if dry_run:
        title += " (dry run: nothing is written)"
    return [
        title,
        "  policy version: 1.0.0",
        f"  policy sha256:  {sha256}",
        f"  evaluated at:   {_NOW_TEXT}",
        "",
        "Investigations",
    ]


def _summary(policy, total, alert, suppressed, not_alertable, already, failures,
             result_line) -> list[str]:
    return [
        "",
        "Summary",
        f"  policy:          {policy}",
        f"  investigations:  {total}",
        f"  alert:           {alert}",
        f"  suppressed:      {suppressed}",
        f"  not_alertable:   {not_alertable}",
        f"  already_decided: {already}",
        f"  failures:        {failures}",
        "",
        result_line,
    ]


def _sha256(harness: Harness) -> str:
    return load_policy(harness.policy_path).policy_sha256


# ---------------------------------------------------------------------------
# EC01  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    def test_policy_is_required(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            cli.main([])
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == []

    @pytest.mark.parametrize("argv", [
        ["--policy"],
        ["--policy", "p.json", "extra"],
        ["--policy", "p.json", "--evaluated-at", "2026-01-01T00:00:00Z"],
        ["--policy", "p.json", "--now", "x"],
        ["--policy", "p.json", "--force"],
        ["--policy", "p.json", "--dry-run=yes"],
        ["evaluate", "--policy", "p.json"],
    ])
    def test_anything_else_is_a_usage_error(self, harness, argv):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(argv)
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == [] and harness.run_calls == []

    def test_help_exits_zero_without_connecting(self, harness, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--help"])
        assert excinfo.value.code == 0
        out = " ".join(capsys.readouterr().out.split())
        assert "--policy PATH" in out and "--dry-run" in out
        assert harness.connect_calls == []

    def test_only_the_two_options_are_defined(self):
        args = cli._parse_args(["--policy", "p.json"])
        assert vars(args) == {"policy": "p.json", "dry_run": False}
        args = cli._parse_args(["--policy", "p.json", "--dry-run"])
        assert vars(args) == {"policy": "p.json", "dry_run": True}

    def test_there_is_no_option_to_set_the_evaluation_time(self):
        source = inspect.getsource(cli._parse_args)
        assert source.count("add_argument(") == 2
        assert "evaluated" not in source and "backdate" not in source


# ---------------------------------------------------------------------------
# EC02  Wiring
# ---------------------------------------------------------------------------

class TestWiring:

    def test_evaluator_receives_connection_policy_and_time(self, harness):
        assert harness.main() == cli.EXIT_OK
        ((conn, policy, evaluated_at, dry_run, on_result),) = harness.run_calls
        assert conn is harness.conn
        assert isinstance(policy, AlertPolicy)
        assert policy == load_policy(harness.policy_path)
        assert evaluated_at == _NOW
        assert dry_run is False
        assert callable(on_result)

    def test_clock_is_read_exactly_once(self, harness):
        harness.results = [_alert(), _cooldown(), _failure()]
        harness.main()
        assert harness.clock_calls == 1

    def test_clock_is_utc_and_read_in_one_place(self):
        source = inspect.getsource(cli)
        assert source.count("datetime.now(") == 1
        assert "datetime.now(timezone.utc)" in source
        assert source.count("_utc_now()") == 2      # its definition and one call

    def test_real_run_opens_a_writable_session(self, harness):
        harness.main()
        assert harness.connect_calls == [{"read_only": False}]

    def test_dry_run_opens_a_read_only_session(self, harness):
        harness.main("--dry-run")
        assert harness.connect_calls == [{"read_only": True}]
        assert harness.run_calls[0][3] is True

    def test_one_connection_and_one_evaluation_per_run(self, harness):
        harness.main()
        assert len(harness.connect_calls) == 1 and len(harness.run_calls) == 1

    def test_policy_is_loaded_before_connecting(self, harness):
        harness.write_policy("{ not json")
        assert harness.main() == cli.EXIT_CONFIGURATION
        assert harness.connect_calls == [] and harness.clock_calls == 0

    def test_repository_policy_file_is_accepted(self, harness):
        assert cli.main(["--policy", _REPO_POLICY]) == cli.EXIT_OK
        assert harness.run_calls[0][1].policy_version == "1.0.0"


# ---------------------------------------------------------------------------
# EC03  Golden output
# ---------------------------------------------------------------------------

class TestGoldenOutput:

    def test_real_run(self, harness, capsys):
        harness.results = [
            _alert(),
            _cooldown(),
            _result(_C, STATUS_PERSISTED, _DC, Decision.NOT_ALERTABLE, ReasonCode.STALE),
        ]
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == "\n".join([
            *_header(_sha256(harness)),
            f"  {_A}  {_DA}  ALERT  severity_met",
            f"  {_B}  {_DB}  SUPPRESSED  cooldown  related={_DA}",
            f"  {_C}  {_DC}  NOT_ALERTABLE  stale",
            *_summary("registered", 3, 1, 1, 1, 0, 0, "Result: completed"),
        ]) + "\n"

    def test_dry_run(self, harness, capsys):
        harness.policy_status = POLICY_NOT_REGISTERED
        harness.results = [
            _alert(status=STATUS_DRY_RUN),
            _cooldown(status=STATUS_DRY_RUN, hypothetical=True),
        ]
        assert harness.main("--dry-run") == cli.EXIT_OK
        assert capsys.readouterr().out == "\n".join([
            *_header(_sha256(harness), dry_run=True),
            f"  {_A}  {_DA}  ALERT  severity_met",
            f"  {_B}  {_DB}  SUPPRESSED  cooldown  related={_DA} (not stored)",
            *_summary(
                "not_registered (a real run would register it)", 2, 1, 1, 0, 0, 0,
                "Result: dry run completed; nothing was written",
            ),
        ]) + "\n"

    def test_no_investigations(self, harness, capsys):
        harness.policy_status = POLICY_ALREADY_REGISTERED
        assert harness.main() == cli.EXIT_OK
        assert capsys.readouterr().out == "\n".join([
            *_header(_sha256(harness)),
            "  (none)",
            *_summary("already_registered", 0, 0, 0, 0, 0, 0, "Result: completed"),
        ]) + "\n"

    def test_failure_and_already_decided(self, harness, capsys):
        harness.results = [
            _alert(),
            _result(_B, STATUS_ALREADY_DECIDED, _DB),
            _failure(),
        ]
        assert harness.main() == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert captured.out == "\n".join([
            *_header(_sha256(harness)),
            f"  {_A}  {_DA}  ALERT  severity_met",
            f"  {_B}  {_DB}  already_decided",
            f"  {_C}  failure  ValueError: severity is not a known Severity value",
            *_summary(
                "registered", 3, 1, 0, 0, 1, 1,
                "Result: completed with problems (1 failed). Nothing was overwritten.",
            ),
        ]) + "\n"

    def test_escalation_line_names_the_related_decision(self, harness, capsys):
        harness.results = [_result(
            _A, STATUS_PERSISTED, _DA, Decision.ALERT, ReasonCode.ESCALATION, _DB,
        )]
        harness.main()
        assert f"  {_A}  {_DA}  ALERT  escalation  related={_DB}\n" in capsys.readouterr().out

    def test_failure_message_is_one_line(self, harness, capsys):
        harness.results = [_failure(error="ValueError: line one\nline   two")]
        harness.main()
        assert f"  {_C}  failure  ValueError: line one line two\n" in capsys.readouterr().out

    def test_failure_with_an_unusable_investigation_id(self, harness, capsys):
        harness.results = [_failure(investigation_id=None)]
        assert harness.main() == cli.EXIT_INCOMPLETE
        assert "  None  failure  ValueError:" in capsys.readouterr().out

    def test_lines_are_written_as_results_arrive(self, harness, capsys):
        harness.results = [_alert(), _cooldown()]
        harness.run_error = psycopg.OperationalError("down")
        harness.error_after = 1
        assert harness.main() == cli.EXIT_DATABASE
        out = capsys.readouterr().out
        assert f"  {_A}  {_DA}  ALERT  severity_met\n" in out
        assert _DB not in out and "Summary" not in out

    def test_output_is_deterministic(self, harness, capsys):
        harness.results = [_alert(), _cooldown(), _failure()]
        harness.main()
        first = capsys.readouterr().out
        harness.main()
        assert capsys.readouterr().out == first

    def test_no_trailing_whitespace_and_lf_only(self, harness, capsys):
        harness.results = [_alert(), _cooldown(), _failure()]
        harness.main()
        out = capsys.readouterr().out
        assert "\r" not in out
        assert all(line == line.rstrip() for line in out.split("\n"))

    def test_unencodable_text_does_not_crash(self, harness, monkeypatch):
        written = []

        class _AsciiStream:
            encoding = "ascii"

            def write(self, text):
                text.encode("ascii")
                written.append(text)

        monkeypatch.setattr(cli.sys, "stdout", _AsciiStream())
        harness.results = [_failure(error="ValueError: café")]
        assert harness.main() == cli.EXIT_INCOMPLETE
        assert any("caf\\xe9" in text for text in written)


# ---------------------------------------------------------------------------
# EC04  Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_exit_code_constants(self):
        assert (
            cli.EXIT_OK, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION, cli.EXIT_DATABASE,
            cli.EXIT_POLICY_CONFLICT, cli.EXIT_INCOMPLETE, cli.EXIT_INTERRUPTED,
        ) == (0, 2, 3, 4, 5, 6, 130)

    def test_only_the_locked_exit_codes_exist(self):
        codes = {
            name: value for name, value in vars(cli).items() if name.startswith("EXIT_")
        }
        assert sorted(codes.values()) == [0, 2, 3, 4, 5, 6, 130]
        assert "EXIT_NOT_FOUND" not in codes

    @pytest.mark.parametrize("results", [
        [],
        [_alert()],
        [_alert(), _cooldown()],
        [_result(_B, STATUS_ALREADY_DECIDED, _DB)],
        [_alert(), _result(_B, STATUS_ALREADY_DECIDED, _DB)],
    ])
    def test_clean_run_exits_zero(self, harness, results):
        harness.results = results
        assert harness.main() == cli.EXIT_OK

    def test_zero_candidates_exit_zero_in_a_dry_run(self, harness):
        assert harness.main("--dry-run") == cli.EXIT_OK

    def test_already_decided_alone_does_not_force_six(self, harness):
        harness.results = [_result(_A, STATUS_ALREADY_DECIDED, _DA)] * 3
        assert harness.main() == cli.EXIT_OK

    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_candidate_failure_exits_six(self, harness, capsys, extra):
        harness.results = [_alert(), _failure()]
        assert harness.main(*extra) == cli.EXIT_INCOMPLETE
        assert "completed with problems (1 failed)" in capsys.readouterr().out

    def test_missing_policy_file_exits_three(self, harness, capsys):
        code = cli.main(["--policy", str(harness.tmp_path / "absent.json")])
        assert code == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.startswith("error: configuration: cannot read the policy file")
        assert harness.connect_calls == []

    def test_policy_path_is_a_directory_exits_three(self, harness):
        assert cli.main(["--policy", str(harness.tmp_path)]) == cli.EXIT_CONFIGURATION

    @pytest.mark.parametrize("document", [
        "{ not json",
        "[]",
        json.dumps({**_POLICY_DOCUMENT, "policy_version": "bad version!"}),
        json.dumps({**_POLICY_DOCUMENT, "policy_schema_version": "9.9.9"}),
        json.dumps({**_POLICY_DOCUMENT, "evaluation": {"cooldown_minutes": -1}}),
        json.dumps({**_POLICY_DOCUMENT, "unknown": 1}),
        '{"policy_version": "1.0.0", "policy_version": "1.0.0"}',
    ])
    def test_invalid_policy_exits_three(self, harness, capsys, document):
        harness.write_policy(document)
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.startswith("error: configuration: invalid policy:")
        assert captured.err.count("\n") == 1
        assert harness.connect_calls == []

    def test_policy_with_invalid_encoding_exits_three(self, harness):
        with open(harness.policy_path, "wb") as fh:
            fh.write(b"\xff\xfe\x00{")
        assert harness.main() == cli.EXIT_CONFIGURATION

    def test_missing_password_exits_three(self, harness, capsys):
        harness.connect_error = RuntimeError(
            "ALERT_EVALUATOR_DB_PASSWORD environment variable is not set"
        )
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "error: configuration: ALERT_EVALUATOR_DB_PASSWORD environment "
            "variable is not set\n"
        )
        assert harness.run_calls == []

    def test_connection_failure_exits_four(self, harness, capsys):
        harness.connect_error = psycopg.OperationalError("connection refused")
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error: database: OperationalError\n"
        assert harness.run_calls == []

    @pytest.mark.parametrize("error_after", [None, 0, 1])
    def test_database_error_during_the_run_exits_four(self, harness, capsys, error_after):
        harness.results = [_alert(), _cooldown()]
        harness.run_error = psycopg.OperationalError("server closed the connection")
        harness.error_after = error_after
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert captured.err == "error: database: OperationalError\n"
        assert "Summary" not in captured.out

    def test_database_error_takes_precedence_over_earlier_failures(self, harness):
        harness.results = [_failure(), _alert()]
        harness.run_error = psycopg.OperationalError("down")
        harness.error_after = 1
        assert harness.main() == cli.EXIT_DATABASE

    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_policy_conflict_exits_five(self, harness, capsys, extra):
        harness.run_error = PolicyVersionConflictError("1.0.0", "e" * 64, "f" * 64)
        assert harness.main(*extra) == cli.EXIT_POLICY_CONFLICT
        captured = capsys.readouterr()
        assert captured.err.startswith("error: policy version conflict:")
        assert "e" * 64 in captured.err and "f" * 64 in captured.err
        assert "Summary" not in captured.out
        assert f"  {_A}" not in captured.out

    def test_keyboard_interrupt_exits_130(self, harness, capsys):
        harness.results = [_alert(), _cooldown()]
        harness.run_error = KeyboardInterrupt()
        harness.error_after = 1
        assert harness.main() == cli.EXIT_INTERRUPTED
        assert "Summary" not in capsys.readouterr().out

    def test_unexpected_error_is_not_swallowed(self, harness):
        harness.run_error = AssertionError("bug")
        with pytest.raises(AssertionError):
            harness.main()
        harness.conn.close.assert_called_once_with()


# ---------------------------------------------------------------------------
# EC05  Connection ownership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_rollback_then_close_after_every_run(self, harness, extra):
        harness.results = [_alert()]
        harness.main(*extra)
        names = [call[0] for call in harness.conn.method_calls]
        assert names == ["rollback", "close"]

    @pytest.mark.parametrize("error", [
        psycopg.OperationalError("down"),
        PolicyVersionConflictError("1.0.0", "e" * 64, "f" * 64),
        KeyboardInterrupt(),
    ])
    def test_rollback_then_close_on_error(self, harness, error):
        harness.run_error = error
        harness.main()
        names = [call[0] for call in harness.conn.method_calls]
        assert names == ["rollback", "close"]

    def test_cli_itself_never_commits(self, harness):
        harness.results = [_alert(), _cooldown()]
        harness.main()
        harness.conn.commit.assert_not_called()
        assert "commit" not in inspect.getsource(cli).replace("committed", "")

    def test_close_is_attempted_when_rollback_fails(self, harness, capsys):
        harness.conn.rollback.side_effect = psycopg.OperationalError("gone")
        assert harness.main() == cli.EXIT_OK
        harness.conn.close.assert_called_once_with()
        assert "error: rollback failed during cleanup: OperationalError" in capsys.readouterr().err

    def test_cleanup_failure_does_not_change_the_exit_code(self, harness, capsys):
        harness.conn.rollback.side_effect = psycopg.OperationalError("gone")
        harness.conn.close.side_effect = psycopg.OperationalError("gone")
        harness.results = [_failure()]
        assert harness.main() == cli.EXIT_INCOMPLETE
        err = capsys.readouterr().err
        assert "rollback failed during cleanup" in err
        assert "close failed during cleanup" in err

    def test_no_connection_means_no_cleanup(self, harness):
        harness.connect_error = RuntimeError("missing")
        harness.main()
        assert harness.conn.method_calls == []


# ---------------------------------------------------------------------------
# EC06  Nothing sensitive is printed
# ---------------------------------------------------------------------------

class TestNothingSensitive:

    def test_database_message_is_not_printed(self, harness, capsys):
        # A driver message can quote a stored row, including an RCA summary.
        harness.run_error = psycopg.IntegrityError(
            'new row violates check constraint\n'
            'DETAIL: Failing row contains (..., PRIVATE-SUMMARY-TEXT, ...)'
        )
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert "PRIVATE-SUMMARY-TEXT" not in captured.out + captured.err
        assert captured.err == "error: database: IntegrityError\n"

    def test_sqlstate_is_printed_when_the_driver_gives_one(self, harness, capsys):
        class _WithState(psycopg.OperationalError):
            sqlstate = "57P01"

        harness.run_error = _WithState("terminating connection")
        harness.main()
        assert capsys.readouterr().err == (
            "error: database: _WithState (SQLSTATE 57P01)\n"
        )

    def test_connection_error_does_not_print_connection_details(self, harness, capsys):
        harness.connect_error = psycopg.OperationalError(
            'connection to server at "db.internal" failed: password=hunter2'
        )
        harness.main()
        err = capsys.readouterr().err
        assert "hunter2" not in err and "db.internal" not in err

    def test_environment_is_not_read_or_printed(self, harness, capsys, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "s3cret-pw")
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/secret")
        harness.results = [_alert(), _failure()]
        harness.main()
        captured = capsys.readouterr()
        assert "s3cret-pw" not in captured.out + captured.err
        assert "hooks.example" not in captured.out + captured.err
        source = inspect.getsource(cli)
        assert "os.environ" not in source and "getenv" not in source

    def test_result_line_has_no_field_for_a_summary(self):
        source = inspect.getsource(cli)
        assert ".summary" not in source and "payload" not in source


# ---------------------------------------------------------------------------
# EC07  End to end with the real evaluator and an in-memory store
# ---------------------------------------------------------------------------

class _MemoryStore:
    """A minimal store: two investigations of one incident stream."""

    def __init__(self) -> None:
        self.policies: dict = {}
        self.decisions: list = []
        self.pending: list = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.investigations = [
            {
                "investigation_id": _A, "anomaly_id": "d" * 64,
                "anomaly_type": "latency", "service_name": "svc",
                "operation_name": "op",
                "event_time": datetime(2026, 10, 5, 18, 30, tzinfo=timezone.utc),
                "severity": "WARNING", "confidence": "HIGH", "limitations": [],
                "summary": "PRIVATE-SUMMARY-ONE",
            },
            {
                "investigation_id": _B, "anomaly_id": "e" * 64,
                "anomaly_type": "latency", "service_name": "svc",
                "operation_name": "op",
                "event_time": datetime(2026, 10, 5, 18, 40, tzinfo=timezone.utc),
                "severity": "WARNING", "confidence": "LOW", "limitations": ["x"],
                "summary": "PRIVATE-SUMMARY-TWO",
            },
        ]

    # connection
    def commit(self):
        self.decisions.extend(self.pending)
        self.pending = []
        self.commits += 1

    def rollback(self):
        self.pending = []
        self.rollbacks += 1

    def close(self):
        self.closed = True

    # store
    def fetch_policy_sha256(self, conn, policy_version):
        row = self.policies.get(policy_version)
        return None if row is None else row["policy_sha256"]

    def insert_policy(self, conn, *, policy_version, policy_sha256, policy_json):
        if policy_version in self.policies:
            return False
        self.policies[policy_version] = {"policy_sha256": policy_sha256}
        return True

    def fetch_candidates(self, conn, policy_version):
        decided = {d.investigation_id for d in self.decisions
                   if d.policy_version == policy_version}
        return [dict(r) for r in self.investigations
                if r["investigation_id"] not in decided]

    def fetch_alert_history(self, conn, *, anomaly_id, dedup_key, event_time,
                            cooldown_start, storm_start):
        return [
            {"decision_id": d.decision_id, "anomaly_id": d.anomaly_id,
             "dedup_key": d.dedup_key, "event_time": d.event_time,
             "severity": d.severity.value, "decision": d.decision.value}
            for d in self.decisions
            if d.decision is Decision.ALERT and storm_start < d.event_time <= event_time
        ]

    def insert_decision(self, conn, decision):
        self.pending.append(decision)
        return True


@pytest.fixture
def memory(monkeypatch, tmp_path):
    store = _MemoryStore()
    for name in ("fetch_policy_sha256", "insert_policy", "fetch_candidates",
                 "fetch_alert_history", "insert_decision"):
        monkeypatch.setattr(alert_store, name, getattr(store, name))
    opened = []

    def connect(*, read_only=False):
        opened.append(read_only)
        return store

    monkeypatch.setattr(cli.alert_db, "connect", connect)
    monkeypatch.setattr(cli, "_utc_now", lambda: _NOW)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        **_POLICY_DOCUMENT, "evaluation": {"persist_summary": True},
    }), encoding="utf-8")
    store.opened = opened
    store.path = str(path)
    return store


class TestEndToEnd:

    def test_dry_run_then_real_run_then_rerun(self, memory, capsys):
        assert cli.main(["--policy", memory.path, "--dry-run"]) == cli.EXIT_OK
        dry = capsys.readouterr().out
        assert memory.decisions == [] and memory.policies == {}
        assert memory.commits == 0
        assert "not_registered" in dry
        assert "(not stored)" in dry

        assert cli.main(["--policy", memory.path]) == cli.EXIT_OK
        real = capsys.readouterr().out
        assert [d.decision for d in memory.decisions] == [
            Decision.ALERT, Decision.SUPPRESSED,
        ]
        assert memory.decisions[0].summary == "PRIVATE-SUMMARY-ONE"
        assert {d.evaluated_at for d in memory.decisions} == {_NOW}

        def lines(text):
            return [line.replace(" (not stored)", "") for line in text.split("\n")
                    if line.startswith(f"  {_A}") or line.startswith(f"  {_B}")]

        assert lines(dry) == lines(real)
        assert len(lines(real)) == 2
        assert "ALERT  severity_met" in lines(real)[0]
        assert "SUPPRESSED  cooldown  related=" in lines(real)[1]

        assert cli.main(["--policy", memory.path]) == cli.EXIT_OK
        rerun = capsys.readouterr().out
        assert "  (none)" in rerun and "already_registered" in rerun
        assert len(memory.decisions) == 2
        assert memory.opened == [True, False, False]
        assert memory.closed is True

    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_summary_text_is_never_printed(self, memory, capsys, extra):
        cli.main(["--policy", memory.path, *extra])
        captured = capsys.readouterr()
        assert "PRIVATE-SUMMARY" not in captured.out + captured.err

    def test_conflicting_policy_exits_five_and_decides_nothing(self, memory, capsys, tmp_path):
        memory.policies["1.0.0"] = {"policy_sha256": "0" * 64}
        assert cli.main(["--policy", memory.path]) == cli.EXIT_POLICY_CONFLICT
        assert memory.decisions == [] and memory.pending == []
        assert memory.closed is True
        assert capsys.readouterr().err.startswith("error: policy version conflict:")


# ---------------------------------------------------------------------------
# EC08  Module boundaries
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
            "alert_db", "alert_evaluator", "alert_policy",
        }

    def test_no_driver_statement_or_store_access(self):
        source = inspect.getsource(cli)
        for word in ("psycopg", "alert_store", "INSERT", "UPDATE", "DELETE",
                     "execute(", "cursor("):
            assert word not in source, word

    def test_no_network_file_output_or_notification(self, tree):
        source = inspect.getsource(cli).lower()
        for word in ("socket", "urllib", "requests", "http", "webhook", "smtp",
                     "subprocess", "guardrail"):
            assert word not in source, word
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert "open" not in names and "print" not in names

    def test_main_returns_an_int_and_takes_argv(self):
        signature = inspect.signature(cli.main)
        assert list(signature.parameters) == ["argv"]
        assert signature.parameters["argv"].default is None
