"""
alerting/tests/unit/test_alert_admin_cli.py

Unit tests for alert_admin_cli.py.

No live PostgreSQL and no network.  alert_notifier_db.connect and the clock
are replaced; the store is the in-memory fake of test_alert_notifier; the
policy file is a real file in a temporary directory.

Test inventory:
    AC01  Arguments
    AC02  list
    AC03  show
    AC04  retry: attempts and exit codes
    AC05  retry: refusals
    AC06  retry: channel lookup and preflight
    AC07  retry: dry run
    AC08  Errors common to all commands
    AC09  Nothing sensitive is printed
    AC10  Module boundaries
"""

from __future__ import annotations

import ast
import inspect
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import alert_admin_cli as cli
import alert_channels
import alert_delivery_store
from alert_identity import compute_attempt_id
from alert_models import DeliveryOutcome

from .test_alert_notifier import FakeDb, _decision, _id, _payload, _STORE_FUNCTIONS
from .test_alert_notify_cli import (
    _LOG,
    _Connection,
    _file_channel,
    _hook_channel,
    _line,
    _policy_document,
)


O = DeliveryOutcome

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_NOW = _T0 + timedelta(minutes=5)

_ENV = ["ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_TOKEN", "ALERT_NOTIFIER_DB_PASSWORD"]


class Harness:
    def __init__(self, monkeypatch, tmp_path) -> None:
        self.tmp_path = tmp_path
        self.policy_path = str(tmp_path / "policy.json")
        self.db = FakeDb()
        self.connect_calls: list[dict] = []
        self.connect_error: BaseException | None = None
        self.clock_calls = 0
        for name in _STORE_FUNCTIONS:
            monkeypatch.setattr(alert_delivery_store, name, getattr(self.db, name))
        monkeypatch.setattr(cli.alert_notifier_db, "connect", self._connect)
        monkeypatch.setattr(cli, "_utc_now", self._now)
        for name in _ENV:
            monkeypatch.delenv(name, raising=False)
        self.write_policy([_LOG])

    def write_policy(self, channels, **kwargs) -> None:
        document = (
            channels if isinstance(channels, str)
            else json.dumps(_policy_document(channels, **kwargs))
        )
        with open(self.policy_path, "w", encoding="utf-8") as fh:
            fh.write(document)

    def _now(self) -> datetime:
        self.clock_calls += 1
        return _NOW

    def _connect(self, **kwargs):
        self.connect_calls.append(kwargs)
        if self.connect_error is not None:
            raise self.connect_error
        self.db.read_only = kwargs.get("read_only", False)
        return self.db

    def run(self, command: str, *args: str) -> int:
        return cli.main([command, "--policy", self.policy_path, *args])

    def retry(self, n, *args: str, channel: str = "log") -> int:
        return self.run("retry", _id(n), "--channel", channel, *args)

    def seed_exhausted(self, n=1, channel="log") -> None:
        for number in (1, 2, 3):
            self.db.seed_attempt(n, channel, number, O.FAILED_RETRYABLE)


@pytest.fixture
def harness(monkeypatch, tmp_path) -> Harness:
    return Harness(monkeypatch, tmp_path)


@pytest.fixture
def webhook(monkeypatch) -> _Connection:
    connection = _Connection()
    monkeypatch.setattr(alert_channels, "_open_connection", lambda *a, **k: connection)
    monkeypatch.setenv(
        "ALERT_WEBHOOK_URL", "https://hooks.example.com/services/SECRETPATH?token=SECRETQUERY",
    )
    return connection


# ---------------------------------------------------------------------------
# AC01  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    @pytest.mark.parametrize("argv", [
        [],
        ["--policy", "p.json"],
        ["notify", "--policy", "p.json"],
        ["list"],
        ["show", "--policy", "p.json"],
        ["retry", "--policy", "p.json", "d" * 64],
        ["retry", "--policy", "p.json", "--channel", "log"],
        ["show", "--policy", "p.json", "not-a-digest"],
        ["show", "--policy", "p.json", "D" * 64],
        ["show", "--policy", "p.json", "d" * 63],
        ["retry", "--policy", "p.json", "short", "--channel", "log"],
        ["list", "--policy", "p.json", "--limit", "0"],
        ["list", "--policy", "p.json", "--limit", "501"],
        ["list", "--policy", "p.json", "--limit", "-1"],
        ["list", "--policy", "p.json", "--limit", "abc"],
        ["list", "--policy", "p.json", "--limit", "1.5"],
        ["list", "--policy", "p.json", "--severity", "CRITICAL"],
        ["list", "--policy", "p.json", "--channel", "log"],
        ["list", "--policy", "p.json", "--dry-run"],
        ["show", "--policy", "p.json", "d" * 64, "--show-summary"],
        ["show", "--policy", "p.json", "d" * 64, "--confirm-resend"],
        ["retry", "--policy", "p.json", "d" * 64, "--channel", "log", "--force"],
        ["retry", "--policy", "p.json", "d" * 64, "e" * 64, "--channel", "log"],
    ])
    def test_usage_errors(self, harness, argv):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(argv)
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == []

    def test_list_defaults(self):
        args = cli._parse_args(["list", "--policy", "p.json"])
        assert vars(args) == {"command": "list", "policy": "p.json", "limit": 50}
        assert (cli.DEFAULT_LIMIT, cli.MIN_LIMIT, cli.MAX_LIMIT) == (50, 1, 500)

    @pytest.mark.parametrize("limit", [1, 50, 500])
    def test_list_limit_bounds_are_accepted(self, limit):
        args = cli._parse_args(["list", "--policy", "p.json", "--limit", str(limit)])
        assert args.limit == limit

    def test_show_arguments(self):
        args = cli._parse_args(["show", "--policy", "p.json", "d" * 64])
        assert vars(args) == {
            "command": "show", "policy": "p.json", "decision_id": "d" * 64,
        }

    def test_retry_arguments(self):
        args = cli._parse_args(
            ["retry", "--policy", "p.json", "d" * 64, "--channel", "hook"],
        )
        assert vars(args) == {
            "command": "retry", "policy": "p.json", "decision_id": "d" * 64,
            "channel": "hook", "confirm_resend": False, "dry_run": False,
        }
        args = cli._parse_args([
            "retry", "--policy", "p.json", "d" * 64, "--channel", "hook",
            "--confirm-resend", "--dry-run",
        ])
        assert (args.confirm_resend, args.dry_run) == (True, True)

    def test_help_exits_zero(self, harness, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "list" in out and "show" in out and "retry" in out


# ---------------------------------------------------------------------------
# AC02  list
# ---------------------------------------------------------------------------

class TestList:

    def test_report(self, harness, capsys, tmp_path):
        harness.write_policy([_LOG, _file_channel(tmp_path / "a.jsonl")])
        harness.db.decisions = [_decision(1, 0), _decision(2, 2), _decision(3, 1)]
        harness.db.seed_attempt(2, "log", 1, O.SENT)
        harness.db.seed_attempt(3, "file", 1, O.FAILED_PERMANENT, channel_type="file")
        assert harness.run("list") == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == "\n".join([
            "Alerts (newest first, limit 50)",
            f"  {_id(2)}  2026-10-05T19:02:00.000000Z  CRITICAL  latency  svc"
            "  log=SENT  file=NEVER_ATTEMPTED",
            f"  {_id(3)}  2026-10-05T19:01:00.000000Z  CRITICAL  latency  svc"
            "  log=NEVER_ATTEMPTED  file=PERMANENTLY_FAILED",
            f"  {_id(1)}  2026-10-05T19:00:00.000000Z  CRITICAL  latency  svc"
            "  log=NEVER_ATTEMPTED  file=NEVER_ATTEMPTED",
        ]) + "\n"

    def test_empty(self, harness, capsys):
        assert harness.run("list") == cli.EXIT_OK
        assert capsys.readouterr().out == "Alerts (newest first, limit 50)\n  (none)\n"

    def test_default_limit_is_fifty(self, harness, capsys):
        harness.db.decisions = [_decision(n, n) for n in range(60)]
        assert harness.run("list") == cli.EXIT_OK
        assert ("fetch_recent_alert_decisions", 50) in harness.db.events
        assert len(capsys.readouterr().out.splitlines()) == 51

    @pytest.mark.parametrize("limit", [1, 7, 500])
    def test_limit_is_passed_through(self, harness, capsys, limit):
        harness.db.decisions = [_decision(n, n) for n in range(12)]
        assert harness.run("list", "--limit", str(limit)) == cli.EXIT_OK
        assert ("fetch_recent_alert_decisions", limit) in harness.db.events
        out = capsys.readouterr().out
        assert out.startswith(f"Alerts (newest first, limit {limit})\n")
        assert len(out.splitlines()) == 1 + min(limit, 12)

    def test_only_alert_decisions(self, harness, capsys):
        harness.db.decisions = [
            _decision(1), _decision(2, 1, verdict="SUPPRESSED"),
            _decision(3, 2, verdict="NOT_ALERTABLE"),
        ]
        harness.run("list")
        out = capsys.readouterr().out
        assert _id(1) in out and _id(2) not in out and _id(3) not in out

    def test_states_for_enabled_channels_only(self, harness, capsys):
        harness.write_policy([_LOG, {**_hook_channel(), "enabled": False}])
        harness.db.decisions = [_decision(1)]
        harness.run("list")
        out = capsys.readouterr().out
        assert "log=NEVER_ATTEMPTED" in out and "hook=" not in out

    def test_expired_and_invalid_states_are_shown(self, harness, capsys):
        harness.db.decisions = [_decision(1, -600), _decision(2, 0)]
        harness.db.seed_attempt(2, "log", 3, O.SENT)
        harness.run("list")
        out = capsys.readouterr().out
        assert f"{_id(1)}  2026-10-05T09:00:00.000000Z" in out
        assert "log=EXPIRED" in out and "log=INVALID" in out

    def test_never_prints_a_summary(self, harness, capsys):
        harness.db.decisions = [_decision(1, summary="PRIVATE-SUMMARY")]
        harness.run("list")
        captured = capsys.readouterr()
        assert "PRIVATE" not in captured.out + captured.err

    def test_read_only_session_and_no_writes(self, harness):
        harness.db.decisions = [_decision(1)]
        assert harness.run("list") == cli.EXIT_OK
        assert harness.connect_calls == [{"read_only": True}]
        assert harness.db.attempts == {} and harness.db.commits == 0
        assert harness.db.closes == 1

    def test_needs_no_channel_environment(self, harness, capsys):
        harness.write_policy([_hook_channel()])
        harness.db.decisions = [_decision(1)]
        assert harness.run("list") == cli.EXIT_OK
        assert "hook=NEVER_ATTEMPTED" in capsys.readouterr().out

    def test_missing_payload_does_not_crash(self, harness, capsys):
        harness.db.decisions = [_decision(1, payload=None)]
        assert harness.run("list") == cli.EXIT_OK
        assert f"  {_id(1)}  2026-10-05T19:00:00.000000Z  -  -  -  log=" in capsys.readouterr().out

    def test_no_additional_filters_exist(self):
        source = inspect.getsource(cli._parse_args)
        list_part = source.split('"list"')[1].split('"show"')[0]
        assert list_part.count("add_argument(") == 1


# ---------------------------------------------------------------------------
# AC03  show
# ---------------------------------------------------------------------------

class TestShow:

    def test_report(self, harness, capsys):
        harness.write_policy([_LOG, _hook_channel()])
        row = _decision(1, summary="PRIVATE-SUMMARY", truncated=True)
        row["payload"] = {
            **_payload(1), "limitations": ["no trace", "short window"],
            "service_name": None, "unexpected_key": "NOT-PRINTED",
        }
        harness.db.decisions = [row]
        harness.db.seed_attempt(1, "hook", 1, O.FAILED_RETRYABLE, detail="http_503",
                                channel_type="webhook")
        harness.db.seed_attempt(1, "hook", 2, None, started=_NOW, trigger="operator",
                                channel_type="webhook")
        harness.db.seed_attempt(1, "old", 1, O.SENT, detail="log_written")
        assert harness.run("show", _id(1)) == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.err == ""
        sha = "f" * 64
        assert captured.out == "\n".join([
            f"Alert {_id(1)}",
            "  policy version: 1.0.0",
            "  reason code:    severity_met",
            "  evaluated at:   2026-10-05T19:00:00.000000Z",
            "  summary stored: truncated",
            "",
            "Payload",
            "  payload_version: 1.0.0",
            f"  decision_id: {_id(1)}",
            "  anomaly_type: latency",
            "  service_name: -",
            "  severity: CRITICAL",
            "  limitations: no trace, short window",
            "",
            "Delivery state",
            "  log: NEVER_ATTEMPTED",
            "  hook: IN_FLIGHT",
            "",
            "Attempts",
            f"  hook  #1  webhook  auto  started 2026-10-05T19:00:00.000000Z"
            f"  summary_included=no  sha256={sha}"
            "  ->  FAILED_RETRYABLE  http_503  recorded 2026-10-05T19:00:00.000000Z",
            f"  hook  #2  webhook  operator  started 2026-10-05T19:05:00.000000Z"
            f"  summary_included=no  sha256={sha}  ->  (no outcome)",
            f"  old  #1  log  auto  started 2026-10-05T19:00:00.000000Z"
            f"  summary_included=no  sha256={sha}"
            "  ->  SENT  log_written  recorded 2026-10-05T19:00:00.000000Z",
        ]) + "\n"

    def test_summary_is_reported_as_stored_only(self, harness, capsys):
        for summary, truncated, expected in [
            (None, False, "no"), ("PRIVATE-SUMMARY", False, "yes"),
            ("PRIVATE-SUMMARY", True, "truncated"),
        ]:
            harness.db.decisions = [_decision(1, summary=summary, truncated=truncated)]
            assert harness.run("show", _id(1)) == cli.EXIT_OK
            captured = capsys.readouterr()
            assert f"  summary stored: {expected}\n" in captured.out
            assert "PRIVATE" not in captured.out + captured.err

    def test_only_contract_payload_fields_are_printed(self, harness, capsys):
        row = _decision(1)
        row["payload"] = {**_payload(1), "extra": "NOT-PRINTED", "trace_id": "NOT-PRINTED"}
        harness.db.decisions = [row]
        harness.run("show", _id(1))
        assert "NOT-PRINTED" not in capsys.readouterr().out
        assert len(cli._PAYLOAD_KEYS) == 15
        assert "summary" not in cli._PAYLOAD_KEYS

    def test_no_attempts_and_no_enabled_channel(self, harness, capsys):
        harness.write_policy([{**_LOG, "enabled": False}])
        harness.db.decisions = [_decision(1)]
        assert harness.run("show", _id(1)) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "Delivery state\n  (no enabled channel)\n" in out
        assert out.endswith("Attempts\n  (none)\n")

    def test_history_of_a_channel_that_is_no_longer_enabled(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "old", 1, O.SENT, detail="log_written")
        harness.run("show", _id(1))
        out = capsys.readouterr().out
        assert "  old  #1  log  auto" in out
        assert "  old: " not in out
        assert "  log: NEVER_ATTEMPTED\n" in out

    def test_invalid_history_is_shown_as_invalid(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 2, O.SENT)
        assert harness.run("show", _id(1)) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "  log: INVALID\n" in out and "  log  #2  log  auto" in out

    def test_unavailable_payload(self, harness, capsys):
        harness.db.decisions = [_decision(1, payload=None)]
        assert harness.run("show", _id(1)) == cli.EXIT_OK
        assert "Payload\n  (unavailable)\n" in capsys.readouterr().out

    def test_not_found(self, harness, capsys):
        assert harness.run("show", _id(404)) == cli.EXIT_NOT_FOUND
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"error: alert not found: {_id(404)}\n"

    @pytest.mark.parametrize("verdict", ["SUPPRESSED", "NOT_ALERTABLE"])
    def test_non_alert_decision_is_not_found(self, harness, capsys, verdict):
        harness.db.decisions = [_decision(1, verdict=verdict)]
        assert harness.run("show", _id(1)) == cli.EXIT_NOT_FOUND
        assert capsys.readouterr().out == ""

    def test_read_only_session_and_no_writes(self, harness):
        harness.db.decisions = [_decision(1)]
        assert harness.run("show", _id(1)) == cli.EXIT_OK
        assert harness.connect_calls == [{"read_only": True}]
        assert harness.db.attempts == {} and harness.db.commits == 0
        assert harness.db.closes == 1


# ---------------------------------------------------------------------------
# AC04  retry: attempts and exit codes
# ---------------------------------------------------------------------------

class TestRetry:

    def test_delivered_exits_zero(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.seed_exhausted()
        assert harness.retry(1) == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out.encode() == _line(1)
        assert captured.err == f"{_id(1)}  log  attempt 4  SENT  log_written\n"
        latest = harness.db.history(1, "log")[-1]
        assert (latest["attempt_no"], latest["trigger"], latest["outcome"]) == (
            4, "operator", "SENT",
        )
        assert harness.connect_calls == [{"read_only": False}]

    def test_status_is_on_stderr_and_stdout_is_the_log_channel(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.FAILED_PERMANENT)
        harness.retry(1)
        captured = capsys.readouterr()
        assert [json.loads(line) for line in captured.out.splitlines()] == [_payload(1)]
        assert "attempt 2" in captured.err

    def test_not_delivered_exits_six(self, harness, capsys, tmp_path):
        harness.write_policy([_file_channel(tmp_path / "missing" / "a.jsonl")])
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "file", 1, O.FAILED_PERMANENT, channel_type="file")
        assert harness.retry(1, channel="file") == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert captured.err == (
            f"{_id(1)}  file  attempt 2  FAILED_PERMANENT  file_path_unusable\n"
        )
        assert captured.out == ""

    def test_webhook_retry(self, harness, capsys, webhook):
        harness.write_policy([_hook_channel()])
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "hook", 1, O.FAILED_PERMANENT, channel_type="webhook")
        assert harness.retry(1, channel="hook") == cli.EXIT_OK
        assert webhook.requests[0][3]["X-AgentOps-Attempt"] == "2"
        webhook.status = 500
        harness.db.outcomes[compute_attempt_id(_id(1), "hook", 2)]["outcome"] = (
            "FAILED_PERMANENT"
        )
        assert harness.retry(1, channel="hook") == cli.EXIT_INCOMPLETE

    def test_expired_delivery_can_be_retried(self, harness, capsys):
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1) == cli.EXIT_OK
        assert harness.db.history(1, "log")[0]["trigger"] == "operator"

    def test_only_the_selected_channel_is_attempted(self, harness, capsys, tmp_path):
        path = tmp_path / "a.jsonl"
        harness.write_policy([_LOG, _file_channel(path)])
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1, channel="file") == cli.EXIT_OK
        assert capsys.readouterr().out == ""
        assert path.read_bytes() == _line(1)
        assert [row["channel_name"] for row in harness.db.attempts.values()] == ["file"]

    def test_decision_not_found(self, harness, capsys):
        assert harness.retry(404) == cli.EXIT_NOT_FOUND
        captured = capsys.readouterr()
        assert captured.err == f"error: alert not found: {_id(404)}\n"
        assert captured.out == "" and harness.db.attempts == {}

    def test_non_alert_decision_is_not_found(self, harness, capsys):
        harness.db.decisions = [_decision(1, verdict="SUPPRESSED")]
        assert harness.retry(1, "--confirm-resend") == cli.EXIT_NOT_FOUND
        assert harness.db.attempts == {}

    def test_lost_race_exits_six(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.FAILED_PERMANENT)
        harness.db.before_insert_attempt = lambda values: harness.db.attempts.setdefault(
            "other", {**values, "attempt_id": "other", "started_at": _NOW},
        )
        assert harness.retry(1) == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert captured.err == f"{_id(1)}  log  lost_race  attempt 2\n"
        assert captured.out == ""

    def test_invalid_data_exits_six(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 5, O.FAILED_PERMANENT)
        assert harness.retry(1) == cli.EXIT_INCOMPLETE
        assert "invalid_data  invalid_history" in capsys.readouterr().err

    def test_exit_code_constants(self):
        assert (
            cli.EXIT_OK, cli.EXIT_NOT_FOUND, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION,
            cli.EXIT_DATABASE, cli.EXIT_INCOMPLETE, cli.EXIT_INTERRUPTED,
        ) == (0, 1, 2, 3, 4, 6, 130)
        codes = sorted(
            value for name, value in vars(cli).items() if name.startswith("EXIT_")
        )
        assert codes == [0, 1, 2, 3, 4, 6, 130]


# ---------------------------------------------------------------------------
# AC05  retry: refusals
# ---------------------------------------------------------------------------

class TestRetryRefusals:

    def _refused(self, harness, capsys, *args) -> str:
        before = harness.db.snapshot()
        assert harness.retry(1, *args) == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert captured.out == ""
        assert harness.db.snapshot() == before and harness.db.commits == 0
        return captured.err

    def test_uncertain_without_confirmation(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.UNCERTAIN)
        err = self._refused(harness, capsys)
        assert err == f"{_id(1)}  log  refused  UNCERTAIN  confirm_resend_required\n"

    def test_uncertain_from_a_missing_outcome_without_confirmation(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, None, started=_T0 - timedelta(hours=1))
        assert "confirm_resend_required" in self._refused(harness, capsys)

    def test_uncertain_with_confirmation_is_sent(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.UNCERTAIN)
        assert harness.retry(1, "--confirm-resend") == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out.encode() == _line(1)
        assert "attempt 2  SENT  log_written" in captured.err

    @pytest.mark.parametrize("confirm", [[], ["--confirm-resend"]])
    def test_already_sent(self, harness, capsys, confirm):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.SENT)
        assert "refused  SENT  already_sent" in self._refused(harness, capsys, *confirm)

    @pytest.mark.parametrize("confirm", [[], ["--confirm-resend"]])
    def test_in_flight(self, harness, capsys, confirm):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, None, started=_NOW)
        assert "refused  IN_FLIGHT  in_flight" in self._refused(harness, capsys, *confirm)

    @pytest.mark.parametrize("confirm", [[], ["--confirm-resend"]])
    def test_never_attempted_and_retryable_belong_to_notify(self, harness, capsys, confirm):
        harness.db.decisions = [_decision(1)]
        err = self._refused(harness, capsys, *confirm)
        assert "refused  NEVER_ATTEMPTED  use_notify" in err
        harness.db.seed_attempt(1, "log", 1, O.FAILED_RETRYABLE)
        assert "refused  RETRYABLE  use_notify" in self._refused(harness, capsys, *confirm)


# ---------------------------------------------------------------------------
# AC06  retry: channel lookup and preflight
# ---------------------------------------------------------------------------

class TestRetryChannel:

    def test_unknown_channel_exits_one_without_connecting(self, harness, capsys):
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1, channel="nope") == cli.EXIT_NOT_FOUND
        captured = capsys.readouterr()
        assert captured.err == "error: channel not found in the policy: nope\n"
        assert captured.out == ""
        assert harness.connect_calls == [] and harness.db.events == []

    @pytest.mark.parametrize("extra", [[], ["--confirm-resend"], ["--dry-run"]])
    def test_disabled_channel_exits_six_without_connecting(self, harness, capsys, extra):
        harness.write_policy([{**_LOG, "enabled": False}])
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1, *extra) == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert captured.err == f"{_id(1)}  log  refused  channel_disabled\n"
        assert captured.out == ""
        assert harness.connect_calls == [] and harness.db.events == []

    def test_disabled_webhook_needs_no_environment(self, harness, capsys):
        harness.write_policy([{**_hook_channel(), "enabled": False}])
        assert harness.retry(1, channel="hook") == cli.EXIT_INCOMPLETE
        assert "channel_disabled" in capsys.readouterr().err

    def test_preflight_failure_exits_three_without_connecting(self, harness, capsys):
        harness.write_policy([_hook_channel()])
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1, channel="hook") == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.err == (
            "error: configuration: channel 'hook': environment variable "
            "ALERT_WEBHOOK_URL is not set\n"
        )
        assert harness.connect_calls == [] and harness.db.attempts == {}

    def test_only_the_selected_channel_is_preflighted(self, harness, capsys):
        # The webhook is unusable, but the retry targets the log channel.
        harness.write_policy([_hook_channel(), _LOG])
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1) == cli.EXIT_OK

    def test_dry_run_preflights_too(self, harness):
        harness.write_policy([_hook_channel()])
        assert harness.retry(1, "--dry-run", channel="hook") == cli.EXIT_CONFIGURATION
        assert harness.connect_calls == []


# ---------------------------------------------------------------------------
# AC07  retry: dry run
# ---------------------------------------------------------------------------

class TestRetryDryRun:

    def test_reports_the_attempt_number_and_writes_nothing(self, harness, capsys, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("a dry run must not deliver")

        monkeypatch.setattr(alert_channels, "_send_log", forbidden)
        harness.db.decisions = [_decision(1)]
        harness.seed_exhausted()
        before = harness.db.snapshot()
        assert harness.retry(1, "--dry-run") == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"{_id(1)}  log  would attempt 4\n"
        assert compute_attempt_id(_id(1), "log", 4) not in captured.err
        assert harness.db.snapshot() == before and harness.db.commits == 0
        assert harness.connect_calls == [{"read_only": True}]

    def test_refusal_exits_six(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.seed_attempt(1, "log", 1, O.UNCERTAIN)
        assert harness.retry(1, "--dry-run") == cli.EXIT_INCOMPLETE
        assert "confirm_resend_required" in capsys.readouterr().err
        assert harness.retry(1, "--dry-run", "--confirm-resend") == cli.EXIT_OK
        assert "would attempt 2" in capsys.readouterr().err

    def test_predicted_oversized_body_exits_six(self, harness, capsys, webhook):
        harness.write_policy([_hook_channel()])
        big = {**_payload(1), "limitations": ["x" * 20000]}
        harness.db.decisions = [_decision(1, -600, payload=big)]
        assert harness.retry(1, "--dry-run", channel="hook") == cli.EXIT_INCOMPLETE
        assert "would attempt 1  would fail body_too_large" in capsys.readouterr().err
        assert webhook.requests == []

    def test_no_file_is_opened(self, harness, capsys, tmp_path):
        path = tmp_path / "a.jsonl"
        harness.write_policy([_file_channel(path)])
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1, "--dry-run", channel="file") == cli.EXIT_OK
        assert not path.exists()


# ---------------------------------------------------------------------------
# AC08  Errors common to all commands
# ---------------------------------------------------------------------------

def _commands(n=1) -> list[tuple]:
    return [("list",), ("show", _id(n)), ("retry", _id(n), "--channel", "log")]


class TestCommonErrors:

    @pytest.mark.parametrize("command", _commands())
    def test_missing_policy_file_exits_three(self, harness, capsys, command):
        code = cli.main([
            command[0], "--policy", str(harness.tmp_path / "absent.json"), *command[1:],
        ])
        assert code == cli.EXIT_CONFIGURATION
        assert capsys.readouterr().err.startswith(
            "error: configuration: cannot read the policy file"
        )
        assert harness.connect_calls == []

    @pytest.mark.parametrize("command", _commands())
    def test_invalid_policy_exits_three(self, harness, capsys, command):
        harness.write_policy("{ not json")
        assert harness.run(*command) == cli.EXIT_CONFIGURATION
        assert harness.connect_calls == []

    @pytest.mark.parametrize("command", _commands())
    def test_missing_password_exits_three(self, harness, capsys, command):
        harness.db.decisions = [_decision(1, -600)]
        harness.connect_error = RuntimeError(
            "ALERT_NOTIFIER_DB_PASSWORD environment variable is not set"
        )
        assert harness.run(*command) == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert "ALERT_NOTIFIER_DB_PASSWORD" in captured.err and captured.out == ""

    @pytest.mark.parametrize("command", _commands())
    def test_connection_failure_exits_four(self, harness, capsys, command):
        harness.connect_error = psycopg.OperationalError("refused at db.internal")
        assert harness.run(*command) == cli.EXIT_DATABASE
        assert capsys.readouterr().err == "error: database: OperationalError\n"

    @pytest.mark.parametrize("command, function", [
        (("list",), "fetch_recent_alert_decisions"),
        (("list",), "fetch_delivery_history"),
        (("show", _id(1)), "fetch_decision"),
        (("show", _id(1)), "fetch_delivery_history"),
        (("retry", _id(1), "--channel", "log"), "fetch_decision"),
        (("retry", _id(1), "--channel", "log"), "insert_attempt"),
        (("retry", _id(1), "--channel", "log"), "insert_outcome"),
    ])
    def test_database_error_exits_four(self, harness, capsys, command, function):
        harness.db.decisions = [_decision(1, -600)]
        harness.db.fail(function, psycopg.OperationalError("down"))
        assert harness.run(*command) == cli.EXIT_DATABASE
        assert capsys.readouterr().err.endswith("error: database: OperationalError\n")
        assert harness.db.closes == 1

    @pytest.mark.parametrize("command, function", [
        (("list",), "fetch_recent_alert_decisions"),
        (("show", _id(1)), "fetch_decision"),
        (("retry", _id(1), "--channel", "log"), "fetch_channel_history"),
    ])
    def test_keyboard_interrupt_exits_130(self, harness, capsys, command, function):
        harness.db.decisions = [_decision(1, -600)]
        harness.db.fail(function, KeyboardInterrupt())
        assert harness.run(*command) == cli.EXIT_INTERRUPTED
        assert harness.db.closes == 1 and harness.db.attempts == {}

    def test_interrupt_during_a_retry_delivery_leaves_no_outcome(
        self, harness, capsys, monkeypatch,
    ):
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(alert_channels, "_send_log", interrupt)
        harness.db.decisions = [_decision(1, -600)]
        assert harness.retry(1) == cli.EXIT_INTERRUPTED
        assert len(harness.db.attempts) == 1 and harness.db.outcomes == {}
        assert harness.db.closes == 1

    @pytest.mark.parametrize("command", _commands())
    def test_clock_is_read_once(self, harness, command):
        harness.db.decisions = [_decision(1, -600)]
        harness.run(*command)
        assert harness.clock_calls == 1

    @pytest.mark.parametrize("command", _commands())
    def test_rollback_then_close(self, harness, command):
        harness.db.decisions = [_decision(1, -600)]
        harness.run(*command)
        assert harness.db.closes == 1
        assert harness.db.events[-1] == ("rollback",)


# ---------------------------------------------------------------------------
# AC09  Nothing sensitive is printed
# ---------------------------------------------------------------------------

class TestNothingSensitive:

    def test_retry_never_prints_url_token_response_or_exception(
        self, harness, capsys, webhook, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", "SECRETTOKEN")
        harness.write_policy([_hook_channel(token_env="ALERT_WEBHOOK_TOKEN")])
        harness.db.decisions = [_decision(1, -600, summary="PRIVATE-SUMMARY")]
        webhook.status = 500
        assert harness.retry(1, channel="hook") == cli.EXIT_INCOMPLETE
        webhook.connect_error = OSError("https://hooks.example.com/SECRETPATH failed")
        harness.retry(1, channel="hook")
        captured = capsys.readouterr()
        for text in (captured.out, captured.err):
            assert "SECRET" not in text and "PRIVATE" not in text
            assert "hooks.example" not in text
        assert "FAILED_RETRYABLE  http_500" in captured.err

    def test_database_message_is_not_printed(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.fail("fetch_decision", psycopg.DataError(
            "DETAIL: Failing row contains (PRIVATE-ROW-TEXT)"
        ))
        assert harness.run("show", _id(1)) == cli.EXIT_DATABASE
        assert "PRIVATE" not in capsys.readouterr().err

    def test_show_does_not_print_the_webhook_endpoint(self, harness, capsys, webhook):
        harness.write_policy([_hook_channel()])
        harness.db.decisions = [_decision(1)]
        harness.run("show", _id(1))
        captured = capsys.readouterr()
        assert "hooks.example" not in captured.out and "SECRET" not in captured.out

    def test_no_command_can_print_a_summary(self):
        tree = ast.parse(inspect.getsource(cli))
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert "summary" not in attributes and "summary_truncated" not in attributes
        assert "summary_stored" in attributes
        assert "summary" not in cli._PAYLOAD_KEYS


# ---------------------------------------------------------------------------
# AC10  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    def test_imports(self):
        tree = ast.parse(inspect.getsource(cli))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "argparse", "os", "sys", "datetime", "typing",
            "alert_notifier_db", "alert_channels", "alert_evaluator",
            "alert_identity", "alert_notifier", "alert_policy",
        }

    def test_no_driver_statement_or_store_access(self):
        source = inspect.getsource(cli)
        for word in ("psycopg", "alert_delivery_store", "alert_store", "alert_db.",
                     "INSERT", "UPDATE", "DELETE", "execute(", "cursor(",
                     "conn.commit"):
            assert word not in source, word

    def test_all_commands_use_the_notifier_connection(self):
        source = inspect.getsource(cli)
        assert source.count("alert_notifier_db.connect(") == 1
        assert "_connect(read_only=True)" in inspect.getsource(cli._list)
        assert "_connect(read_only=True)" in inspect.getsource(cli._show)
        assert "_connect(read_only=args.dry_run)" in inspect.getsource(cli._retry)

    def test_retry_uses_the_notifier_machinery(self):
        source = inspect.getsource(cli._retry)
        assert "retry_delivery(" in source
        assert "confirm_resend=args.confirm_resend" in source
        assert "insert_attempt" not in source and "alert_channels.send" not in source

    def test_environment_is_only_handed_to_preflight(self):
        source = inspect.getsource(cli)
        assert source.count("os.environ") == 1 and "getenv" not in source

    def test_clock_is_utc_and_called_once_per_command(self):
        source = inspect.getsource(cli)
        assert source.count("datetime.now(") == 1
        assert "datetime.now(timezone.utc)" in source
        for command in (cli._list, cli._show, cli._retry):
            assert inspect.getsource(command).count("_utc_now()") == 1
