"""
alerting/tests/unit/test_alert_notify_cli.py

Unit tests for alert_notify_cli.py.

No live PostgreSQL and no network.  alert_notifier_db.connect and the clock
are replaced; the store is the in-memory fake of test_alert_notifier; the
policy file is a real file in a temporary directory.  The log and file
channels are the real ones; a webhook channel talks to an injected
connection object.

Test inventory:
    NC01  Arguments
    NC02  Kill switch: no enabled channel
    NC03  Preflight: all channels or nothing
    NC04  A real run: stdout is the log channel, stderr is the report
    NC05  Exit codes
    NC06  Dry run
    NC07  Connection ownership and clock
    NC08  Nothing sensitive is printed
    NC09  Module boundaries
"""

from __future__ import annotations

import ast
import inspect
import io
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import alert_channels
import alert_delivery_store
import alert_notify_cli as cli
from alert_channels import build_body
from alert_identity import compute_attempt_id
from alert_models import DeliveryOutcome

from .test_alert_notifier import FakeDb, _decision, _id, _payload, _STORE_FUNCTIONS


O = DeliveryOutcome

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_NOW = _T0 + timedelta(minutes=5)
_NOW_TEXT = "2026-10-05T19:05:00.000000Z"

_ENV = [
    "ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_TOKEN", "ALERT_NOTIFIER_DB_PASSWORD",
]

_LOG = {"name": "log", "type": "log", "enabled": True}


def _file_channel(path, **extra) -> dict:
    return {"name": "file", "type": "file", "enabled": True, "path": str(path), **extra}


def _hook_channel(**extra) -> dict:
    return {
        "name": "hook", "type": "webhook", "enabled": True,
        "url_env": "ALERT_WEBHOOK_URL", **extra,
    }


def _policy_document(channels, *, persist_summary=False, max_age=60) -> dict:
    return {
        "policy_schema_version": "1.0.0",
        "policy_version": "1.0.0",
        "evaluation": {"persist_summary": persist_summary},
        "delivery": {"max_delivery_age_minutes": max_age, "channels": list(channels)},
        "guardrails": {},
    }


def _line(n, **summary) -> bytes:
    return build_body(
        _payload(n), summary.get("summary"), summary.get("truncated", False),
        include_summary="summary" in summary,
    ).data + b"\n"


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

    def main(self, *extra: str) -> int:
        return cli.main(["--policy", self.policy_path, *extra])


@pytest.fixture
def harness(monkeypatch, tmp_path) -> Harness:
    return Harness(monkeypatch, tmp_path)


class _Connection:
    """Injected webhook connection."""

    def __init__(self, status=200, connect_error=None) -> None:
        self.status = status
        self.connect_error = connect_error
        self.requests: list[tuple] = []

    def connect(self) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    def request(self, method, target, body=None, headers=None) -> None:
        self.requests.append((method, target, body, dict(headers)))

    def getresponse(self):
        return self

    def read(self, amount=None) -> bytes:
        return b"SECRET-RESPONSE-BODY"

    def close(self) -> None:
        pass


@pytest.fixture
def webhook(monkeypatch) -> _Connection:
    connection = _Connection()
    monkeypatch.setattr(alert_channels, "_open_connection", lambda *a, **k: connection)
    monkeypatch.setenv(
        "ALERT_WEBHOOK_URL", "https://hooks.example.com/services/SECRETPATH?token=SECRETQUERY",
    )
    return connection


# ---------------------------------------------------------------------------
# NC01  Arguments
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
        ["--policy", "p.json", "--now", "x"],
        ["--policy", "p.json", "--confirm-resend"],
        ["--policy", "p.json", "--channel", "log"],
        ["--policy", "p.json", "--force"],
        ["notify", "--policy", "p.json"],
    ])
    def test_anything_else_is_a_usage_error(self, harness, argv):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(argv)
        assert excinfo.value.code == cli.EXIT_USAGE
        assert harness.connect_calls == []

    def test_only_two_options_are_defined(self):
        assert vars(cli._parse_args(["--policy", "p.json"])) == {
            "policy": "p.json", "dry_run": False,
        }
        assert vars(cli._parse_args(["--policy", "p.json", "--dry-run"])) == {
            "policy": "p.json", "dry_run": True,
        }
        assert inspect.getsource(cli._parse_args).count("add_argument(") == 2


# ---------------------------------------------------------------------------
# NC02  Kill switch
# ---------------------------------------------------------------------------

class TestKillSwitch:

    @pytest.mark.parametrize("channels", [
        [],
        [{**_LOG, "enabled": False}],
        [{**_LOG, "enabled": False}, {**_hook_channel(), "enabled": False}],
    ])
    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_no_enabled_channel_is_a_successful_no_op(
        self, harness, capsys, channels, extra,
    ):
        harness.db.decisions = [_decision(1)]
        harness.write_policy(channels)
        assert harness.main(*extra) == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Alert notification: no channel is enabled; nothing to do\n"
        assert harness.connect_calls == []
        assert harness.db.events == [] and harness.db.attempts == {}

    def test_needs_no_database_password_and_no_webhook_variable(self, harness):
        harness.connect_error = RuntimeError("password not set")
        harness.write_policy([{**_hook_channel(), "enabled": False}])
        assert harness.main() == cli.EXIT_OK

    def test_disabled_channel_is_skipped_and_not_checked(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([{**_hook_channel(), "enabled": False}, _LOG])
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out.encode() == _line(1)
        assert "hook" not in captured.err
        assert [row["channel_name"] for row in harness.db.attempts.values()] == ["log"]


# ---------------------------------------------------------------------------
# NC03  Preflight
# ---------------------------------------------------------------------------

class TestPreflight:

    def test_one_unusable_channel_stops_everything(self, harness, capsys, tmp_path):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        path = tmp_path / "alerts.jsonl"
        harness.write_policy([_LOG, _file_channel(path), _hook_channel()])
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "error: configuration: channel 'hook': environment variable "
            "ALERT_WEBHOOK_URL is not set\n"
        )
        assert harness.connect_calls == []
        assert harness.db.events == [] and harness.db.attempts == {}
        assert not path.exists()

    def test_order_of_the_channels_does_not_matter(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel(), _LOG])
        assert harness.main() == cli.EXIT_CONFIGURATION
        assert capsys.readouterr().out == ""
        assert harness.connect_calls == []

    @pytest.mark.parametrize("url", [
        "http://hooks.example.com/SECRETPATH",
        "https://user:SECRETPW@hooks.example.com/",
        "http://localhost:8080/SECRETPATH",
        "https://hooks.example.com/x#SECRETFRAGMENT",
        "not a url SECRETTEXT",
    ])
    def test_invalid_url_is_reported_without_its_value(
        self, harness, capsys, monkeypatch, url,
    ):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", url)
        harness.write_policy([_LOG, _hook_channel()])
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert "ALERT_WEBHOOK_URL" in captured.err and "'hook'" in captured.err
        assert "SECRET" not in captured.err and "hooks.example" not in captured.err
        assert captured.out == "" and harness.connect_calls == []

    @pytest.mark.parametrize("token", [None, "", "has space", "line\nbreak"])
    def test_missing_or_invalid_token(self, harness, capsys, monkeypatch, token):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/")
        if token is not None:
            monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", token)
        harness.write_policy([_LOG, _hook_channel(token_env="ALERT_WEBHOOK_TOKEN")])
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert "ALERT_WEBHOOK_TOKEN" in captured.err
        assert captured.out == "" and harness.connect_calls == []

    def test_dry_run_performs_the_same_preflight(self, harness, capsys):
        harness.write_policy([_LOG, _hook_channel()])
        assert harness.main("--dry-run") == cli.EXIT_CONFIGURATION
        assert harness.connect_calls == []

    def test_preflight_happens_before_the_connection(self, harness):
        harness.connect_error = AssertionError("connected before preflight")
        harness.write_policy([_hook_channel()])
        assert harness.main() == cli.EXIT_CONFIGURATION

    def test_file_channel_is_not_touched_by_preflight(self, harness, tmp_path):
        missing = tmp_path / "missing-dir" / "alerts.jsonl"
        harness.write_policy([_file_channel(missing)])
        assert harness.main() == cli.EXIT_OK        # no decisions: nothing to send
        assert not missing.parent.exists()


# ---------------------------------------------------------------------------
# NC04  A real run
# ---------------------------------------------------------------------------

class TestRealRun:

    def test_stdout_holds_only_the_log_channel_lines(self, harness, capsys):
        harness.db.decisions = [_decision(1), _decision(2, 1), _decision(3, 2)]
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out.encode() == _line(1) + _line(2) + _line(3)
        assert [json.loads(line) for line in captured.out.splitlines()] == [
            _payload(1), _payload(2), _payload(3),
        ]

    def test_report_goes_to_stderr(self, harness, capsys):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        harness.db.seed_attempt(2, "log", 1, O.SENT)
        assert harness.main() == cli.EXIT_OK
        assert capsys.readouterr().err == "\n".join([
            "Alert notification",
            f"  run time:         {_NOW_TEXT}",
            "  max delivery age: 60 minutes",
            "  channel:          log (log)",
            "",
            "Deliveries",
            f"  {_id(1)}  log  attempt 1  SENT  log_written",
            f"  {_id(2)}  log  blocked  SENT  already_sent",
            "",
            "Summary",
            "  deliveries:    2",
            "  attempted:     1",
            "  sent:          1",
            "  not sent:      0",
            "  blocked:       1",
            "  lost race:     0",
            "  invalid data:  0",
            "",
            "Result: completed",
        ]) + "\n"

    def test_no_decisions(self, harness, capsys):
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Deliveries\n  (none)\n" in captured.err
        assert captured.err.endswith("Result: completed\n")

    def test_log_and_file_channels_deliver_the_same_bytes(self, harness, capsys, tmp_path):
        path = tmp_path / "alerts.jsonl"
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_LOG, _file_channel(path)])
        assert harness.main() == cli.EXIT_OK
        assert capsys.readouterr().out.encode() == _line(1)
        assert path.read_bytes() == _line(1)
        assert len(harness.db.attempts) == len(harness.db.outcomes) == 2

    def test_webhook_channel(self, harness, capsys, webhook):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel()])
        assert harness.main() == cli.EXIT_OK
        (request,) = webhook.requests
        assert request[0] == "POST" and request[2] == _line(1)[:-1]
        assert request[3]["Idempotency-Key"] == _id(1)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert f"  {_id(1)}  hook  attempt 1  SENT  http_200\n" in captured.err
        assert "  channel:          hook (webhook) https://hooks.example.com:443\n" in captured.err

    def test_summary_reaches_only_a_channel_that_includes_it(self, harness, capsys, tmp_path):
        path = tmp_path / "alerts.jsonl"
        harness.db.decisions = [_decision(1, summary="PRIVATE-SUMMARY")]
        harness.write_policy(
            [_LOG, _file_channel(path, include_summary=True)], persist_summary=True,
        )
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out.encode() == _line(1)
        assert "PRIVATE" not in captured.out and "PRIVATE" not in captured.err
        assert path.read_bytes() == _line(1, summary="PRIVATE-SUMMARY")

    def test_rerun_delivers_nothing_more(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.main()
        capsys.readouterr()
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "blocked  SENT  already_sent" in captured.err
        assert len(harness.db.attempts) == 1

    def test_text_stdout_without_a_binary_buffer_still_gets_the_line(
        self, harness, monkeypatch,
    ):
        stream = io.StringIO()
        monkeypatch.setattr(cli.sys, "stdout", stream)
        harness.db.decisions = [_decision(1)]
        assert harness.main() == cli.EXIT_OK
        assert stream.getvalue().encode("ascii") == _line(1)

    def test_output_is_deterministic(self, harness, capsys):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        harness.main("--dry-run")
        first = capsys.readouterr()
        harness.main("--dry-run")
        assert capsys.readouterr() == first


# ---------------------------------------------------------------------------
# NC05  Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_exit_code_constants(self):
        assert (
            cli.EXIT_OK, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION, cli.EXIT_DATABASE,
            cli.EXIT_INCOMPLETE, cli.EXIT_INTERRUPTED,
        ) == (0, 2, 3, 4, 6, 130)
        codes = sorted(
            value for name, value in vars(cli).items() if name.startswith("EXIT_")
        )
        assert codes == [0, 2, 3, 4, 6, 130]

    def test_all_sent_exits_zero(self, harness):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        assert harness.main() == cli.EXIT_OK

    def test_pre_existing_blocked_states_exit_zero(self, harness):
        harness.db.decisions = [_decision(n, n) for n in range(1, 5)]
        harness.db.seed_attempt(1, "log", 1, O.UNCERTAIN)
        harness.db.seed_attempt(2, "log", 1, O.FAILED_PERMANENT)
        harness.db.seed_attempt(3, "log", 1, None, started=_NOW)
        harness.db.decisions.append(_decision(9, -900))
        assert harness.main() == cli.EXIT_OK

    def test_failed_attempt_exits_six(self, harness, capsys, tmp_path):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_file_channel(tmp_path / "missing" / "a.jsonl"), _LOG])
        assert harness.main() == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert "attempt 1  FAILED_PERMANENT  file_path_unusable" in captured.err
        assert "Result: completed with problems (1). Nothing was overwritten." in captured.err
        assert captured.out.encode() == _line(1)

    def test_retryable_and_uncertain_attempts_exit_six(self, harness, monkeypatch, webhook):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel()])
        webhook.status = 503
        assert harness.main() == cli.EXIT_INCOMPLETE
        webhook.status = 199
        assert harness.main() == cli.EXIT_INCOMPLETE
        outcomes = sorted(row["outcome"] for row in harness.db.outcomes.values())
        assert outcomes == ["FAILED_RETRYABLE", "UNCERTAIN"]

    def test_invalid_data_exits_six(self, harness, capsys):
        harness.db.decisions = [_decision(1, payload=None), _decision(2, 1)]
        assert harness.main() == cli.EXIT_INCOMPLETE
        assert "invalid_data  invalid_decision" in capsys.readouterr().err

    def test_lost_race_exits_six(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.before_insert_attempt = lambda values: harness.db.attempts.setdefault(
            "other", {**values, "attempt_id": "other", "started_at": _NOW},
        )
        assert harness.main() == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert "lost_race  attempt 1" in captured.err
        assert captured.out == ""

    def test_missing_policy_file_exits_three(self, harness, capsys):
        assert cli.main(["--policy", str(harness.tmp_path / "absent.json")]) == 3
        captured = capsys.readouterr()
        assert captured.err.startswith("error: configuration: cannot read the policy file")
        assert harness.connect_calls == [] and harness.clock_calls == 0

    @pytest.mark.parametrize("document", [
        "{ not json",
        "[]",
        json.dumps({**_policy_document([_LOG]), "unknown": 1}),
        json.dumps(_policy_document([{**_LOG, "path": "x"}])),
        json.dumps(_policy_document([{"name": "f", "type": "file", "enabled": True}])),
        json.dumps(_policy_document([{**_LOG, "include_summary": True}])),
    ])
    def test_invalid_policy_exits_three(self, harness, capsys, document):
        harness.write_policy(document)
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.err.startswith("error: configuration: invalid policy:")
        assert captured.out == "" and harness.connect_calls == []

    def test_missing_password_exits_three(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.connect_error = RuntimeError(
            "ALERT_NOTIFIER_DB_PASSWORD environment variable is not set"
        )
        assert harness.main() == cli.EXIT_CONFIGURATION
        captured = capsys.readouterr()
        assert captured.err == (
            "error: configuration: ALERT_NOTIFIER_DB_PASSWORD environment "
            "variable is not set\n"
        )
        assert captured.out == ""

    def test_connection_failure_exits_four(self, harness, capsys):
        harness.connect_error = psycopg.OperationalError("refused at db.internal")
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert captured.err == "error: database: OperationalError\n"
        assert captured.out == ""

    @pytest.mark.parametrize("function", [
        "fetch_alert_decisions", "fetch_channel_history", "insert_attempt",
        "insert_outcome",
    ])
    def test_database_error_during_the_run_exits_four(self, harness, capsys, function):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        harness.db.fail(function, psycopg.OperationalError("down"))
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert captured.err.endswith("error: database: OperationalError\n")
        assert "Summary" not in captured.err
        assert harness.db.closes == 1

    def test_database_error_after_a_delivery_keeps_the_attempt(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.fail("insert_outcome", psycopg.OperationalError("down"))
        assert harness.main() == cli.EXIT_DATABASE
        assert capsys.readouterr().out.encode() == _line(1)
        assert len(harness.db.attempts) == 1 and harness.db.outcomes == {}

    def test_keyboard_interrupt_exits_130(self, harness, capsys, monkeypatch):
        harness.db.decisions = [_decision(1), _decision(2, 1)]

        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(alert_channels, "_send_log", interrupt)
        assert harness.main() == cli.EXIT_INTERRUPTED
        captured = capsys.readouterr()
        assert "Summary" not in captured.err
        assert len(harness.db.attempts) == 1 and harness.db.outcomes == {}
        assert harness.db.closes == 1
        assert "insert_outcome" not in [event[0] for event in harness.db.events]

    def test_unexpected_error_is_not_swallowed(self, harness, monkeypatch):
        harness.db.decisions = [_decision(1)]
        harness.db.fail("fetch_alert_decisions", AssertionError("bug"))
        with pytest.raises(AssertionError):
            harness.main()
        assert harness.db.closes == 1


# ---------------------------------------------------------------------------
# NC06  Dry run
# ---------------------------------------------------------------------------

class TestDryRun:

    def test_opens_a_read_only_session(self, harness):
        harness.main("--dry-run")
        assert harness.connect_calls == [{"read_only": True}]

    def test_real_run_opens_a_writable_session(self, harness):
        harness.main()
        assert harness.connect_calls == [{"read_only": False}]

    def test_writes_sends_and_opens_nothing(self, harness, capsys, tmp_path, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("a dry run must not deliver")

        for name in ("_os_open", "_open_connection", "_send_log"):
            monkeypatch.setattr(alert_channels, name, forbidden)
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/")
        path = tmp_path / "alerts.jsonl"
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        harness.write_policy([_LOG, _file_channel(path), _hook_channel()])

        assert harness.main("--dry-run") == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert not path.exists()
        assert harness.db.attempts == {} and harness.db.outcomes == {}
        assert harness.db.commits == 0

    def test_report(self, harness, capsys):
        harness.db.decisions = [_decision(1), _decision(2, 1)]
        harness.db.seed_attempt(2, "log", 1, O.FAILED_RETRYABLE)
        assert harness.main("--dry-run") == cli.EXIT_OK
        assert capsys.readouterr().err == "\n".join([
            "Alert notification (dry run: nothing is written or sent)",
            f"  run time:         {_NOW_TEXT}",
            "  max delivery age: 60 minutes",
            "  channel:          log (log)",
            "",
            "Deliveries",
            f"  {_id(1)}  log  would attempt 1",
            f"  {_id(2)}  log  would attempt 2",
            "",
            "Summary",
            "  deliveries:    2",
            "  would attempt: 2",
            "  blocked:       0",
            "  lost race:     0",
            "  invalid data:  0",
            "",
            "Result: dry run completed; nothing was written or sent",
        ]) + "\n"

    def test_shows_no_attempt_identity(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.main("--dry-run")
        err = capsys.readouterr().err
        assert compute_attempt_id(_id(1), "log", 1) not in err
        assert "would attempt 1" in err

    def test_predicted_oversized_webhook_body_exits_six(self, harness, capsys, webhook):
        big = {**_payload(1), "limitations": ["x" * 20000]}
        harness.db.decisions = [_decision(1, payload=big)]
        harness.write_policy([_hook_channel()])
        assert harness.main("--dry-run") == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert "would attempt 1  would fail body_too_large" in captured.err
        assert webhook.requests == []

    def test_invalid_data_exits_six(self, harness):
        harness.db.decisions = [_decision(1, payload="text")]
        assert harness.main("--dry-run") == cli.EXIT_INCOMPLETE


# ---------------------------------------------------------------------------
# NC07  Connection ownership and clock
# ---------------------------------------------------------------------------

class TestOwnership:

    @pytest.mark.parametrize("extra", [[], ["--dry-run"]])
    def test_rollback_then_close_after_every_run(self, harness, extra):
        harness.db.decisions = [_decision(1)]
        harness.main(*extra)
        assert harness.db.closes == 1
        assert harness.db.events[-1] == ("rollback",)

    def test_one_connection_per_run(self, harness):
        harness.db.decisions = [_decision(n, n) for n in range(4)]
        harness.main()
        assert len(harness.connect_calls) == 1

    def test_clock_is_read_exactly_once(self, harness):
        harness.db.decisions = [_decision(n, n) for n in range(4)]
        harness.main()
        assert harness.clock_calls == 1

    def test_clock_is_utc_and_read_in_one_place(self):
        source = inspect.getsource(cli)
        assert source.count("datetime.now(") == 1
        assert "datetime.now(timezone.utc)" in source
        assert source.count("_utc_now()") == 2

    def test_the_one_time_reaches_every_state(self, harness, capsys):
        # At the injected time this decision is exactly at the age limit.
        harness.db.decisions = [_decision(1, -55)]
        assert harness.main("--dry-run") == cli.EXIT_OK
        assert "would attempt 1" in capsys.readouterr().err

    def test_cleanup_failure_does_not_change_the_exit_code(self, harness, capsys, monkeypatch):
        def broken():
            raise psycopg.OperationalError("gone")

        monkeypatch.setattr(harness.db, "close", broken)
        assert harness.main() == cli.EXIT_OK
        assert "error: close failed during cleanup: OperationalError" in capsys.readouterr().err

    def test_cli_itself_never_commits_or_sends(self):
        source = inspect.getsource(cli)
        for word in ("conn.commit", "alert_channels.send", "insert_attempt",
                     "insert_outcome"):
            assert word not in source, word


# ---------------------------------------------------------------------------
# NC08  Nothing sensitive is printed
# ---------------------------------------------------------------------------

class TestNothingSensitive:

    def test_url_path_query_and_token_never_appear(self, harness, capsys, webhook, monkeypatch):
        monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", "SECRETTOKEN")
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel(token_env="ALERT_WEBHOOK_TOKEN")])
        assert harness.main() == cli.EXIT_OK
        captured = capsys.readouterr()
        assert webhook.requests[0][3]["Authorization"] == "Bearer SECRETTOKEN"
        for text in (captured.out, captured.err):
            assert "SECRET" not in text and "token" not in text.lower()
        assert "https://hooks.example.com:443" in captured.err

    def test_response_body_never_appears(self, harness, capsys, webhook):
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel()])
        webhook.status = 500
        harness.main()
        captured = capsys.readouterr()
        assert "SECRET-RESPONSE" not in captured.out + captured.err
        assert "FAILED_RETRYABLE  http_500" in captured.err

    def test_exception_text_never_appears(self, harness, capsys, webhook):
        webhook.connect_error = OSError(
            "cannot reach https://hooks.example.com/services/SECRETPATH"
        )
        harness.db.decisions = [_decision(1)]
        harness.write_policy([_hook_channel()])
        assert harness.main() == cli.EXIT_INCOMPLETE
        captured = capsys.readouterr()
        assert "SECRETPATH" not in captured.err and "cannot reach" not in captured.err
        assert "FAILED_RETRYABLE  connect_failed" in captured.err
        assert {row["detail"] for row in harness.db.outcomes.values()} == {"connect_failed"}

    def test_database_message_is_not_printed(self, harness, capsys):
        harness.db.decisions = [_decision(1)]
        harness.db.fail("insert_attempt", psycopg.IntegrityError(
            "DETAIL: Failing row contains (..., PRIVATE-ROW-TEXT, ...)"
        ))
        assert harness.main() == cli.EXIT_DATABASE
        captured = capsys.readouterr()
        assert "PRIVATE-ROW-TEXT" not in captured.err
        assert captured.err.endswith("error: database: IntegrityError\n")

    def test_summary_never_reaches_stderr(self, harness, capsys):
        harness.db.decisions = [_decision(1, summary="PRIVATE-SUMMARY")]
        harness.write_policy(
            [{**_LOG, "include_summary": True}], persist_summary=True,
        )
        harness.main()
        captured = capsys.readouterr()
        assert "PRIVATE-SUMMARY" in captured.out          # the delivery itself
        assert "PRIVATE-SUMMARY" not in captured.err


# ---------------------------------------------------------------------------
# NC09  Module boundaries
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
            "alert_notifier", "alert_policy",
        }

    def test_no_driver_statement_or_store_access(self):
        source = inspect.getsource(cli)
        for word in ("psycopg", "alert_delivery_store", "alert_store", "alert_db.",
                     "INSERT", "UPDATE", "DELETE", "execute(", "cursor("):
            assert word not in source, word

    def test_environment_is_only_handed_to_preflight(self):
        source = inspect.getsource(cli)
        assert source.count("os.environ") == 1
        assert "preflight_channel(channel, os.environ)" in source
        assert "getenv" not in source

    def test_report_is_written_to_stderr_only(self):
        source = inspect.getsource(cli)
        assert "print(" not in source
        assert source.count("sys.stdout") == 2          # both in _stdout_binary
        assert "_write(sys.stdout" not in source
