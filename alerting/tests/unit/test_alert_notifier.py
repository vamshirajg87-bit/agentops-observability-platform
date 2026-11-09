"""
alerting/tests/unit/test_alert_notifier.py

Unit tests for alert_notifier.py.

No live PostgreSQL and no network.  alert_delivery_store is replaced by an
in-memory fake with real transaction behaviour: writes are pending until
commit() and are discarded by rollback().  alert_channels.send is replaced
by a recorder, except where a test uses the real log or file channel.  The
locked state machine, identity and model modules are used unchanged.

Test inventory:
    NT01  Discovery: every ALERT, order, no version filter, expiry derived
    NT02  One attempt: T1, delivery, T2
    NT03  Attempt row contents: numbering, identity, body hash, summary
    NT04  Blocked states and one attempt per run
    NT05  Kill switch and disabled channels
    NT06  Lost race and changed eligibility
    NT07  Failures: T1, T2, sender, interrupt
    NT08  Invalid data
    NT09  Operator retry
    NT10  Dry run
    NT11  Report
    NT12  Read-only views
    NT13  format_result
    NT14  Module boundaries
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import io
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import alert_channels
import alert_delivery_store
import alert_notifier
from alert_channels import (
    PreparedChannel,
    SendResult,
    WebhookEndpoint,
    build_body,
)
from alert_delivery_state import DeliveryState
from alert_identity import compute_attempt_id
from alert_models import ChannelType, DeliveryOutcome
from alert_notifier import (
    REASON_CHANNEL_DISABLED,
    REASON_INVALID_DECISION,
    REASON_INVALID_HISTORY,
    REASON_OUTCOME_EXISTS,
    STATE_INVALID,
    STATUS_ATTEMPTED,
    STATUS_BLOCKED,
    STATUS_INVALID_DATA,
    STATUS_LOST_RACE,
    STATUS_REFUSED,
    STATUS_WOULD_ATTEMPT,
    DecisionNotFoundError,
    DeliveryResult,
    NotifyReport,
    format_result,
    list_alerts,
    retry_delivery,
    run_notify,
    show_alert,
)
from alert_policy import ChannelConfig, DeliveryPolicy


O = DeliveryOutcome
S = DeliveryState

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_NOW = _T0 + timedelta(minutes=5)

_STORE_FUNCTIONS = (
    "fetch_alert_decisions", "fetch_recent_alert_decisions", "fetch_decision",
    "fetch_delivery_history", "fetch_channel_history", "insert_attempt",
    "insert_outcome",
)

_SENT = {
    ChannelType.LOG: "log_written",
    ChannelType.FILE: "file_appended",
    ChannelType.WEBHOOK: "http_200",
}


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _id(n) -> str:
    return _hex(f"decision-{n}")


def _payload(n) -> dict:
    return {
        "payload_version": "1.0.0",
        "decision_id": _id(n),
        "severity": "CRITICAL",
        "anomaly_type": "latency",
        "service_name": "svc",
    }


def _decision(n, minutes: float = 0, *, summary=None, truncated=False,
              version="1.0.0", verdict="ALERT", **overrides) -> dict:
    row = {
        "decision_id": _id(n),
        "decision": verdict,
        "reason_code": "severity_met",
        "policy_version": version,
        "evaluated_at": _T0 + timedelta(minutes=minutes),
        "payload": _payload(n) if verdict == "ALERT" else None,
        "summary": summary,
        "summary_truncated": truncated,
    }
    row.update(overrides)
    return row


def _log(name="log", **config) -> PreparedChannel:
    return PreparedChannel(
        ChannelConfig(name=name, type=ChannelType.LOG, enabled=True, **config),
    )


def _file(name="file", path="alerts.jsonl", **config) -> PreparedChannel:
    return PreparedChannel(ChannelConfig(
        name=name, type=ChannelType.FILE, enabled=True, path=path, **config,
    ))


def _hook(name="hook", **config) -> PreparedChannel:
    config.setdefault("enabled", True)
    return PreparedChannel(
        ChannelConfig(
            name=name, type=ChannelType.WEBHOOK, url_env="ALERT_WEBHOOK_URL",
            **config,
        ),
        WebhookEndpoint("https", "hooks.example.com", 443, "/p?token=SECRETQUERY"),
    )


def _delivery(*channels: PreparedChannel, max_age: int = 60) -> DeliveryPolicy:
    return DeliveryPolicy(
        channels=tuple(channel.config for channel in channels),
        max_delivery_age_minutes=max_age,
    )


class FakeDb:
    """In-memory stand-in for the connection and for alert_delivery_store."""

    def __init__(self) -> None:
        self.decisions: list[dict] = []
        self.attempts: dict[str, dict] = {}
        self.outcomes: dict[str, dict] = {}
        self._pending_attempts: dict[str, dict] = {}
        self._pending_outcomes: dict[str, dict] = {}
        self.clock = _NOW
        self.read_only = False
        self.in_transaction = False
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self.events: list[tuple] = []
        self.errors: dict[str, list] = {}
        self.before_insert_attempt = None
        self.after_history_read = None

    # -- test controls ------------------------------------------------------

    def fail(self, function: str, error: BaseException, *, on_call: int = 1) -> None:
        self.errors.setdefault(function, []).append([on_call, error])

    def _maybe_fail(self, function: str) -> None:
        for entry in self.errors.get(function, []):
            entry[0] -= 1
            if entry[0] == 0:
                raise entry[1]

    def seed_attempt(self, n, channel: str, attempt_no: int, outcome=None, *,
                     started=None, trigger="auto", detail=None,
                     channel_type="log", attempt_id=None) -> str:
        decision_id = _id(n)
        attempt_id = attempt_id or compute_attempt_id(decision_id, channel, attempt_no)
        self.attempts[attempt_id] = {
            "attempt_id": attempt_id,
            "decision_id": decision_id,
            "channel_name": channel,
            "channel_type": channel_type,
            "attempt_no": attempt_no,
            "trigger": trigger,
            "summary_included": False,
            "payload_sha256": "f" * 64,
            "started_at": started if started is not None else _T0,
        }
        if outcome is not None:
            self.outcomes[attempt_id] = {
                "outcome": outcome.value if isinstance(outcome, O) else outcome,
                "detail": detail,
                "recorded_at": _T0,
            }
        return attempt_id

    def snapshot(self):
        return (dict(self.attempts), dict(self.outcomes))

    def history(self, n, channel: str) -> list[dict]:
        return [
            row for row in self._rows()
            if row["decision_id"] == _id(n) and row["channel_name"] == channel
        ]

    # -- connection ---------------------------------------------------------

    def commit(self) -> None:
        self._maybe_fail("commit")
        assert not self.read_only, "commit() in a read-only session"
        self.attempts.update(self._pending_attempts)
        self.outcomes.update(self._pending_outcomes)
        self._pending_attempts.clear()
        self._pending_outcomes.clear()
        self.in_transaction = False
        self.commits += 1
        self.events.append(("commit",))

    def rollback(self) -> None:
        self._pending_attempts.clear()
        self._pending_outcomes.clear()
        self.in_transaction = False
        self.rollbacks += 1
        self.events.append(("rollback",))

    def close(self) -> None:
        self.closes += 1

    # -- store --------------------------------------------------------------

    def _begin(self, name: str, *detail) -> None:
        self.in_transaction = True
        self.events.append((name, *detail))
        self._maybe_fail(name)

    def _rows(self) -> list[dict]:
        attempts = {**self.attempts, **self._pending_attempts}
        outcomes = {**self.outcomes, **self._pending_outcomes}
        rows = []
        for attempt_id, attempt in attempts.items():
            outcome = outcomes.get(attempt_id)
            rows.append({
                **attempt,
                "outcome": outcome["outcome"] if outcome else None,
                "detail": outcome["detail"] if outcome else None,
                "recorded_at": outcome["recorded_at"] if outcome else None,
            })
        return sorted(rows, key=lambda row: (
            str(row["decision_id"]), str(row["channel_name"]), row["attempt_no"],
        ))

    @staticmethod
    def _when(row) -> datetime:
        value = row["evaluated_at"]
        return value if isinstance(value, datetime) and value.tzinfo else _T0

    def fetch_alert_decisions(self, conn):
        assert conn is self
        self._begin("fetch_alert_decisions")
        rows = [dict(row) for row in self.decisions if row["decision"] == "ALERT"]
        return sorted(rows, key=lambda row: (self._when(row), str(row["decision_id"])))

    def fetch_recent_alert_decisions(self, conn, limit):
        assert conn is self
        self._begin("fetch_recent_alert_decisions", limit)
        rows = [dict(row) for row in self.decisions if row["decision"] == "ALERT"]
        rows.sort(key=lambda row: str(row["decision_id"]))
        rows.sort(key=self._when, reverse=True)
        return rows[:limit]

    def fetch_decision(self, conn, decision_id):
        assert conn is self
        self._begin("fetch_decision", decision_id)
        for row in self.decisions:
            if row["decision_id"] == decision_id:
                return dict(row)
        return None

    def fetch_delivery_history(self, conn, decision_ids):
        assert conn is self
        self._begin("fetch_delivery_history")
        wanted = set(decision_ids)
        return [dict(row) for row in self._rows() if row["decision_id"] in wanted]

    def fetch_channel_history(self, conn, decision_id, channel_name):
        assert conn is self
        self._begin("fetch_channel_history", decision_id, channel_name)
        if self.after_history_read is not None:
            self.after_history_read(decision_id, channel_name)
        return [
            dict(row) for row in self._rows()
            if row["decision_id"] == decision_id and row["channel_name"] == channel_name
        ]

    def insert_attempt(self, conn, **values):
        assert conn is self
        assert not self.read_only, "attempt insert in a read-only session"
        self._begin("insert_attempt", values["attempt_id"])
        if self.before_insert_attempt is not None:
            self.before_insert_attempt(values)
        for existing in {**self.attempts, **self._pending_attempts}.values():
            if (
                existing["decision_id"], existing["channel_name"],
                existing["attempt_no"],
            ) == (values["decision_id"], values["channel_name"], values["attempt_no"]):
                return False
        self._pending_attempts[values["attempt_id"]] = {
            **values, "started_at": self.clock,
        }
        return True

    def insert_outcome(self, conn, *, attempt_id, result):
        assert conn is self
        assert not self.read_only, "outcome insert in a read-only session"
        assert isinstance(result, SendResult)
        self._begin("insert_outcome", attempt_id)
        if attempt_id in self.outcomes or attempt_id in self._pending_outcomes:
            return False
        self._pending_outcomes[attempt_id] = {
            "outcome": result.outcome.value, "detail": result.detail,
            "recorded_at": self.clock,
        }
        return True


class Sender:
    """Replaces alert_channels.send and records every delivery."""

    def __init__(self, db: FakeDb) -> None:
        self.db = db
        self.calls: list[dict] = []
        self.results: dict = {}
        self.error: BaseException | None = None

    def __call__(self, prepared, body, *, decision_id, attempt_no, log_stream):
        attempt_id = compute_attempt_id(decision_id, prepared.config.name, attempt_no)
        self.calls.append({
            "channel": prepared.config.name,
            "decision_id": decision_id,
            "attempt_no": attempt_no,
            "body": body,
            "log_stream": log_stream,
            "in_transaction": self.db.in_transaction,
            "attempt_committed": attempt_id in self.db.attempts,
            "pending": bool(self.db._pending_attempts or self.db._pending_outcomes),
            "outcome_exists": attempt_id in self.db.outcomes,
        })
        self.db.events.append(("send", decision_id, prepared.config.name))
        if self.error is not None:
            raise self.error
        configured = self.results.get(
            (decision_id, prepared.config.name),
            self.results.get(prepared.config.name),
        )
        if configured is None:
            configured = (O.SENT, _SENT[prepared.config.type])
        return SendResult(prepared.config.type, *configured)

    def pairs(self) -> list[tuple]:
        return [(call["decision_id"], call["channel"]) for call in self.calls]


@pytest.fixture
def db(monkeypatch) -> FakeDb:
    fake = FakeDb()
    for name in _STORE_FUNCTIONS:
        monkeypatch.setattr(alert_delivery_store, name, getattr(fake, name))
    return fake


@pytest.fixture
def sender(monkeypatch, db) -> Sender:
    recorder = Sender(db)
    monkeypatch.setattr(alert_channels, "send", recorder)
    return recorder


def _run(db, *channels, now=_NOW, dry_run=False, max_age=60, **kwargs) -> NotifyReport:
    db.read_only = dry_run
    return run_notify(
        db, list(channels), _delivery(*channels, max_age=max_age),
        now=now, dry_run=dry_run, **kwargs,
    )


def _retry(db, channel, n, *, now=_NOW, max_age=60, dry_run=False, **kwargs) -> DeliveryResult:
    db.read_only = dry_run
    return retry_delivery(
        db, channel, _delivery(channel, max_age=max_age), _id(n),
        now=now, dry_run=dry_run, **kwargs,
    )


def _summary(report: NotifyReport) -> list[tuple]:
    return [
        (r.decision_id, r.channel_name, r.status, r.outcome) for r in report.results
    ]


# ---------------------------------------------------------------------------
# NT01  Discovery
# ---------------------------------------------------------------------------

class TestDiscovery:

    def test_every_alert_decision_is_delivered(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1), _decision(3, 2)]
        report = _run(db, _log())
        assert [r.status for r in report.results] == [STATUS_ATTEMPTED] * 3
        assert sender.pairs() == [(_id(n), "log") for n in (1, 2, 3)]

    def test_non_alert_decisions_are_never_delivered(self, db, sender):
        db.decisions = [
            _decision(1, verdict="SUPPRESSED"),
            _decision(2, verdict="NOT_ALERTABLE"),
            _decision(3),
        ]
        report = _run(db, _log())
        assert sender.pairs() == [(_id(3), "log")]
        assert report.total == 1

    def test_order_is_evaluated_at_then_decision_id(self, db, sender):
        rows = [_decision(n, minutes) for n, minutes in
                [(1, 3), (2, 0), (3, 1), (4, 1), (5, 0), (6, 2)]]
        db.decisions = list(reversed(rows))
        _run(db, _log())
        expected = [
            row["decision_id"] for row in
            sorted(rows, key=lambda r: (r["evaluated_at"], r["decision_id"]))
        ]
        assert [call["decision_id"] for call in sender.calls] == expected

    def test_order_does_not_use_the_payload_event_time(self, db, sender):
        early, late = _decision(1, 0), _decision(2, 1)
        early["payload"]["event_time"] = "2026-10-05T23:00:00.000000Z"
        late["payload"]["event_time"] = "2026-10-05T01:00:00.000000Z"
        db.decisions = [late, early]
        _run(db, _log())
        assert [call["decision_id"] for call in sender.calls] == [_id(1), _id(2)]

    def test_channels_are_processed_in_policy_order(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        _run(db, _hook("zeta"), _log("alpha"), _file("mid"))
        assert sender.pairs() == [
            (_id(1), "zeta"), (_id(1), "alpha"), (_id(1), "mid"),
            (_id(2), "zeta"), (_id(2), "alpha"), (_id(2), "mid"),
        ]

    def test_policy_version_does_not_restrict_delivery(self, db, sender):
        db.decisions = [
            _decision(1, version="0.1.0"), _decision(2, 1, version="1.0.0"),
            _decision(3, 2, version="9.9.9-other"),
        ]
        report = _run(db, _log())
        assert report.sent == 3

    def test_old_decisions_are_discovered_and_derive_expired(self, db, sender):
        db.decisions = [_decision(1, -600), _decision(2, 0)]
        report = _run(db, _log(), max_age=60)
        old, fresh = report.results
        assert (old.status, old.state, old.reason) == (
            STATUS_BLOCKED, S.EXPIRED, "not_auto_eligible",
        )
        assert fresh.status == STATUS_ATTEMPTED
        assert sender.pairs() == [(_id(2), "log")]
        assert db.history(1, "log") == []

    def test_expiry_boundary_through_a_run(self, db, sender):
        db.decisions = [_decision(1)]
        at_limit = _run(db, _log(), now=_T0 + timedelta(minutes=60), dry_run=True)
        past = _run(
            db, _log(), dry_run=True,
            now=_T0 + timedelta(minutes=60, microseconds=1),
        )
        assert at_limit.results[0].status == STATUS_WOULD_ATTEMPT
        assert past.results[0].state is S.EXPIRED

    def test_discovery_is_read_once_and_ended_before_the_first_attempt(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        _run(db, _log())
        names = [event[0] for event in db.events]
        assert names[:3] == [
            "fetch_alert_decisions", "fetch_delivery_history", "rollback",
        ]
        assert names.count("fetch_alert_decisions") == 1
        assert names.count("fetch_delivery_history") == 1

    def test_no_decisions(self, db, sender):
        report = _run(db, _log())
        assert report.results == () and report.succeeded is True
        assert sender.calls == []

    def test_database_error_during_discovery_propagates(self, db, sender):
        db.fail("fetch_alert_decisions", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        assert db.events[-1] == ("rollback",)
        assert sender.calls == []


# ---------------------------------------------------------------------------
# NT02  One attempt
# ---------------------------------------------------------------------------

class TestOneAttempt:

    def test_sequence_t1_send_t2(self, db, sender):
        db.decisions = [_decision(1)]
        _run(db, _log())
        names = [event[0] for event in db.events][3:]
        assert names == [
            "fetch_channel_history", "insert_attempt", "commit",
            "send",
            "insert_outcome", "commit",
        ]

    def test_attempt_is_durable_before_the_delivery(self, db, sender):
        db.decisions = [_decision(1)]
        _run(db, _log())
        (call,) = sender.calls
        assert call["attempt_committed"] is True
        assert call["outcome_exists"] is False

    def test_no_transaction_is_open_during_the_delivery(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        _run(db, _log(), _hook())
        assert len(sender.calls) == 4
        assert all(call["in_transaction"] is False for call in sender.calls)
        assert all(call["pending"] is False for call in sender.calls)

    def test_outcome_is_recorded_after_the_delivery(self, db, sender):
        db.decisions = [_decision(1)]
        sender.results["hook"] = (O.FAILED_RETRYABLE, "http_503")
        report = _run(db, _hook())
        (row,) = db.history(1, "hook")
        assert (row["outcome"], row["detail"]) == ("FAILED_RETRYABLE", "http_503")
        (result,) = report.results
        assert (result.status, result.outcome, result.detail) == (
            STATUS_ATTEMPTED, O.FAILED_RETRYABLE, "http_503",
        )
        assert result.attempt_id == compute_attempt_id(_id(1), "hook", 1)

    def test_each_attempt_has_two_commits(self, db, sender):
        db.decisions = [_decision(n, n) for n in range(4)]
        _run(db, _log())
        assert db.commits == 8
        assert len(db.attempts) == len(db.outcomes) == 4

    def test_real_log_and_file_channels(self, db, tmp_path):
        db.decisions = [_decision(1)]
        stream = io.BytesIO()
        path = tmp_path / "alerts.jsonl"
        report = _run(db, _log(), _file(path=str(path)), log_stream=stream)
        assert [r.detail for r in report.results] == ["log_written", "file_appended"]
        expected = build_body(_payload(1), None, False, include_summary=False).data
        assert stream.getvalue() == expected + b"\n"
        assert path.read_bytes() == expected + b"\n"
        assert {row["payload_sha256"] for row in db.attempts.values()} == {
            hashlib.sha256(expected).hexdigest(),
        }

    def test_log_stream_is_passed_through(self, db, sender):
        db.decisions = [_decision(1)]
        stream = io.BytesIO()
        _run(db, _log(), log_stream=stream)
        assert sender.calls[0]["log_stream"] is stream

    def test_callback_gets_each_result_as_it_is_known(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        seen = []
        report = _run(db, _log(), on_result=lambda r: seen.append((r, len(db.outcomes))))
        assert tuple(result for result, _ in seen) == report.results
        assert [count for _, count in seen] == [1, 2]

    def test_connection_is_never_closed(self, db, sender):
        db.decisions = [_decision(1)]
        _run(db, _log())
        assert db.closes == 0


# ---------------------------------------------------------------------------
# NT03  Attempt row contents
# ---------------------------------------------------------------------------

class TestAttemptRow:

    def test_first_attempt(self, db, sender):
        db.decisions = [_decision(1)]
        _run(db, _hook())
        (row,) = db.history(1, "hook")
        assert row["attempt_no"] == 1
        assert row["attempt_id"] == compute_attempt_id(_id(1), "hook", 1)
        assert row["channel_type"] == "webhook"
        assert row["trigger"] == "auto"
        assert row["started_at"] == db.clock
        assert sender.calls[0]["attempt_no"] == 1

    def test_attempt_number_increments(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "hook", 1, O.FAILED_RETRYABLE, channel_type="webhook")
        db.seed_attempt(1, "hook", 2, O.FAILED_RETRYABLE, channel_type="webhook")
        _run(db, _hook())
        rows = db.history(1, "hook")
        assert [row["attempt_no"] for row in rows] == [1, 2, 3]
        assert rows[2]["attempt_id"] == compute_attempt_id(_id(1), "hook", 3)
        assert sender.calls[0]["attempt_no"] == 3

    def test_numbering_is_per_channel(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "hook", 1, O.FAILED_RETRYABLE, channel_type="webhook")
        _run(db, _hook(), _log())
        assert [call["attempt_no"] for call in sender.calls] == [2, 1]

    def test_hash_is_of_the_exact_bytes_delivered(self, db, sender):
        db.decisions = [_decision(1)]
        _run(db, _log())
        (row,) = db.history(1, "log")
        body = sender.calls[0]["body"]
        assert row["payload_sha256"] == body.sha256 == hashlib.sha256(body.data).hexdigest()
        assert json.loads(body.data) == _payload(1)

    def test_body_is_the_persisted_payload_only(self, db, sender):
        db.decisions = [_decision(1, summary="PRIVATE-SUMMARY")]
        _run(db, _log())
        body = sender.calls[0]["body"]
        assert json.loads(body.data) == _payload(1)
        assert b"PRIVATE" not in body.data
        assert db.history(1, "log")[0]["summary_included"] is False

    def test_summary_is_added_only_where_the_channel_includes_it(self, db, sender):
        db.decisions = [_decision(1, summary="the summary", truncated=True)]
        _run(db, _log("plain"), _log("full", include_summary=True))
        plain, full = (call["body"] for call in sender.calls)
        assert json.loads(plain.data) == _payload(1)
        assert json.loads(full.data) == {
            **_payload(1), "summary": "the summary", "summary_truncated": True,
        }
        assert db.history(1, "plain")[0]["summary_included"] is False
        assert db.history(1, "full")[0]["summary_included"] is True
        assert plain.sha256 != full.sha256

    def test_summary_included_is_false_when_none_is_stored(self, db, sender):
        db.decisions = [_decision(1, summary=None)]
        _run(db, _log("full", include_summary=True))
        assert db.history(1, "full")[0]["summary_included"] is False
        assert "summary" not in json.loads(sender.calls[0]["body"].data)

    def test_stored_payload_is_not_modified(self, db, sender):
        row = _decision(1, summary="s")
        db.decisions = [row]
        before = json.dumps(row["payload"], sort_keys=True)
        _run(db, _log("full", include_summary=True))
        assert json.dumps(row["payload"], sort_keys=True) == before

    def test_identity_function_is_the_locked_one(self):
        import alert_identity
        assert alert_notifier.compute_attempt_id is alert_identity.compute_attempt_id


# ---------------------------------------------------------------------------
# NT04  Blocked states; one attempt per run
# ---------------------------------------------------------------------------

class TestBlockedStates:

    @pytest.mark.parametrize("outcomes, started, state, reason", [
        ((O.SENT,), None, S.SENT, "already_sent"),
        ((None,), _NOW, S.IN_FLIGHT, "in_flight"),
        ((None,), _T0 - timedelta(hours=1), S.UNCERTAIN, "not_auto_eligible"),
        ((O.UNCERTAIN,), None, S.UNCERTAIN, "not_auto_eligible"),
        ((O.FAILED_PERMANENT,), None, S.PERMANENTLY_FAILED, "not_auto_eligible"),
        ((O.FAILED_RETRYABLE,) * 3, None, S.EXHAUSTED, "not_auto_eligible"),
    ])
    def test_automatic_run_does_not_touch_it(self, db, sender, outcomes, started,
                                             state, reason):
        db.decisions = [_decision(1)]
        for number, outcome in enumerate(outcomes, start=1):
            db.seed_attempt(1, "log", number, outcome, started=started)
        before = db.snapshot()
        report = _run(db, _log())
        (result,) = report.results
        assert (result.status, result.state, result.reason) == (
            STATUS_BLOCKED, state, reason,
        )
        assert sender.calls == [] and db.snapshot() == before
        assert db.commits == 0
        assert report.succeeded is True

    def test_blocked_state_opens_no_attempt_transaction(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, O.SENT)
        _run(db, _log())
        assert "fetch_channel_history" not in [event[0] for event in db.events]

    def test_retryable_is_attempted_again(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, O.FAILED_RETRYABLE)
        report = _run(db, _log())
        assert report.results[0].state is S.RETRYABLE
        assert report.results[0].attempt_no == 2

    def test_one_attempt_per_decision_and_channel_per_run(self, db, sender):
        db.decisions = [_decision(1)]
        sender.results["hook"] = (O.FAILED_RETRYABLE, "http_503")
        report = _run(db, _hook(max_attempts=5))
        assert report.attempted == 1 and len(sender.calls) == 1
        assert len(db.history(1, "hook")) == 1

    def test_retry_happens_only_on_a_later_run_until_exhausted(self, db, sender):
        db.decisions = [_decision(1)]
        sender.results["hook"] = (O.FAILED_RETRYABLE, "http_503")
        for _ in range(5):
            _run(db, _hook(max_attempts=3))
        assert len(sender.calls) == 3
        assert [row["attempt_no"] for row in db.history(1, "hook")] == [1, 2, 3]
        final = _run(db, _hook(max_attempts=3))
        assert final.results[0].state is S.EXHAUSTED

    def test_rerun_after_sent_delivers_nothing(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        _run(db, _log(), _hook())
        before = db.snapshot()
        sender.calls.clear()
        report = _run(db, _log(), _hook())
        assert sender.calls == [] and db.snapshot() == before
        assert {r.status for r in report.results} == {STATUS_BLOCKED}

    def test_failure_on_one_channel_does_not_stop_the_others(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        sender.results["hook"] = (O.FAILED_PERMANENT, "http_404")
        report = _run(db, _hook(), _log())
        assert _summary(report) == [
            (_id(1), "hook", STATUS_ATTEMPTED, O.FAILED_PERMANENT),
            (_id(1), "log", STATUS_ATTEMPTED, O.SENT),
            (_id(2), "hook", STATUS_ATTEMPTED, O.FAILED_PERMANENT),
            (_id(2), "log", STATUS_ATTEMPTED, O.SENT),
        ]
        assert report.succeeded is False

    def test_source_never_waits_or_loops_on_a_delivery(self):
        source = inspect.getsource(alert_notifier)
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.While) for node in ast.walk(tree))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert "sleep" not in names | attributes
        assert source.count("alert_channels.send(") == 1


# ---------------------------------------------------------------------------
# NT05  Kill switch and disabled channels
# ---------------------------------------------------------------------------

class TestKillSwitch:

    def test_no_channels_touches_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        report = run_notify(db, [], DeliveryPolicy(channels=()), now=_NOW)
        assert report.results == () and report.succeeded is True
        assert db.events == [] and sender.calls == []

    def test_every_channel_disabled_touches_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        channels = [_hook("a", enabled=False), _hook("b", enabled=False)]
        report = run_notify(db, channels, _delivery(*channels), now=_NOW)
        assert report.results == ()
        assert db.events == [] and sender.calls == []
        assert db.attempts == {} and db.outcomes == {}

    def test_disabled_channel_is_never_attempted(self, db, sender):
        db.decisions = [_decision(1)]
        channels = [_hook("off", enabled=False), _log("on")]
        report = run_notify(
            db, channels, _delivery(*channels), now=_NOW, log_stream=io.BytesIO(),
        )
        assert sender.pairs() == [(_id(1), "on")]
        assert [r.channel_name for r in report.results] == ["on"]

    def test_evaluation_switch_is_not_consulted(self):
        source = inspect.getsource(alert_notifier)
        assert "evaluation" not in source.replace("evaluation time", "").replace(
            "oldest evaluation", "",
        )


# ---------------------------------------------------------------------------
# NT06  Lost race and changed eligibility
# ---------------------------------------------------------------------------

class TestRaces:

    def test_lost_attempt_number_sends_nothing(self, db, sender):
        db.decisions = [_decision(1)]

        def other_writer(values):
            db.attempts["other"] = {
                **values, "attempt_id": "other", "started_at": db.clock,
            }
            db.before_insert_attempt = None

        db.before_insert_attempt = other_writer
        report = _run(db, _hook())
        (result,) = report.results
        assert (result.status, result.attempt_no, result.attempt_id) == (
            STATUS_LOST_RACE, 1, None,
        )
        assert sender.calls == []
        assert list(db.attempts) == ["other"] and db.outcomes == {}
        assert report.succeeded is False and report.lost_races == 1

    def test_lost_race_does_not_take_another_number(self, db, sender):
        db.decisions = [_decision(1)]
        db.before_insert_attempt = lambda values: db.attempts.setdefault(
            "other", {**values, "attempt_id": "other", "started_at": db.clock},
        )
        _run(db, _hook())
        names = [event[0] for event in db.events]
        assert names.count("insert_attempt") == 1
        assert names[names.index("insert_attempt") + 1] == "rollback"
        assert "insert_outcome" not in names

    def test_lost_race_does_not_stop_the_batch(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]

        def other_writer(values):
            if values["decision_id"] == _id(1):
                db.attempts["other"] = {
                    **values, "attempt_id": "other", "started_at": db.clock,
                }

        db.before_insert_attempt = other_writer
        report = _run(db, _log())
        assert [r.status for r in report.results] == [STATUS_LOST_RACE, STATUS_ATTEMPTED]
        assert sender.pairs() == [(_id(2), "log")]

    def test_state_is_derived_again_inside_t1(self, db, sender):
        # Between discovery and T1 another process starts an attempt.
        db.decisions = [_decision(1)]

        def other_process(decision_id, channel_name):
            db.after_history_read = None
            db.seed_attempt(1, "log", 1, None, started=_NOW)

        db.after_history_read = other_process
        report = _run(db, _log())
        (result,) = report.results
        assert (result.status, result.state, result.reason) == (
            STATUS_BLOCKED, S.IN_FLIGHT, "in_flight",
        )
        assert sender.calls == []
        assert len(db.attempts) == 1
        assert "insert_attempt" not in [event[0] for event in db.events]

    def test_delivered_meanwhile_is_not_sent_again(self, db, sender):
        db.decisions = [_decision(1)]

        def other_process(decision_id, channel_name):
            db.after_history_read = None
            db.seed_attempt(1, "log", 1, O.SENT)

        db.after_history_read = other_process
        report = _run(db, _log())
        assert report.results[0].state is S.SENT
        assert sender.calls == []


# ---------------------------------------------------------------------------
# NT07  Failures
# ---------------------------------------------------------------------------

class TestFailures:

    @pytest.mark.parametrize("function", ["fetch_channel_history", "insert_attempt"])
    def test_t1_database_error_sends_nothing(self, db, sender, function):
        db.decisions = [_decision(1), _decision(2, 1)]
        db.fail(function, psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        assert sender.calls == []
        assert db.attempts == {} and db._pending_attempts == {}
        assert db.events[-1] == ("rollback",)

    def test_t1_commit_failure_sends_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        db.fail("commit", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        assert sender.calls == [] and db.attempts == {}

    @pytest.mark.parametrize("function, on_call", [
        ("insert_outcome", 1), ("commit", 2),
    ])
    def test_t2_failure_leaves_the_attempt_without_an_outcome(
        self, db, sender, function, on_call,
    ):
        db.decisions = [_decision(1), _decision(2, 1)]
        db.fail(function, psycopg.OperationalError("down"), on_call=on_call)
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        assert sender.pairs() == [(_id(1), "log")]
        assert len(db.attempts) == 1 and db.outcomes == {}
        assert db._pending_outcomes == {}
        assert db.events[-1] == ("rollback",)

    def test_after_a_t2_failure_the_delivery_is_in_flight_then_uncertain(self, db, sender):
        db.decisions = [_decision(1)]
        db.fail("insert_outcome", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        sender.calls.clear()

        soon = _run(db, _log(), now=_NOW + timedelta(seconds=20))
        later = _run(db, _log(), now=_NOW + timedelta(minutes=10))
        assert soon.results[0].state is S.IN_FLIGHT
        assert later.results[0].state is S.UNCERTAIN
        assert sender.calls == [] and len(db.attempts) == 1

    def test_no_second_delivery_after_a_t2_failure(self, db, sender):
        db.decisions = [_decision(1)]
        db.fail("insert_outcome", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db, _log())
        assert len(sender.calls) == 1

    def test_unexpected_sender_error_is_recorded_as_uncertain(self, db, monkeypatch):
        db.decisions = [_decision(1), _decision(2, 1)]

        def explode(*args):
            raise RuntimeError("https://secret.example/?token=abc")

        monkeypatch.setattr(alert_channels, "_send_log", explode)
        report = _run(db, _log(), log_stream=io.BytesIO())
        assert [(r.outcome, r.detail) for r in report.results] == [
            (O.UNCERTAIN, "unexpected_error"),
        ] * 2
        assert {row["detail"] for row in db.outcomes.values()} == {"unexpected_error"}
        assert "secret" not in repr(report)
        assert report.succeeded is False

    def test_keyboard_interrupt_during_delivery_leaves_no_outcome(self, db, sender):
        db.decisions = [_decision(1), _decision(2, 1)]
        sender.error = KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            _run(db, _log())
        assert len(sender.calls) == 1
        assert len(db.attempts) == 1 and db.outcomes == {}
        names = [event[0] for event in db.events]
        assert "insert_outcome" not in names
        assert names[-1] == "send"

    def test_keyboard_interrupt_before_t1_commit_leaves_no_attempt(self, db, sender):
        db.decisions = [_decision(1)]
        db.fail("insert_attempt", KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            _run(db, _log())
        assert db.attempts == {} and sender.calls == []

    def test_keyboard_interrupt_in_t2_writes_no_outcome(self, db, sender):
        db.decisions = [_decision(1)]
        db.fail("insert_outcome", KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            _run(db, _log())
        assert db.outcomes == {} and len(db.attempts) == 1

    def test_existing_outcome_for_the_own_attempt_is_invalid_data(
        self, db, sender, monkeypatch,
    ):
        db.decisions = [_decision(1)]
        original = db.insert_outcome

        def already_there(conn, *, attempt_id, result):
            db.outcomes[attempt_id] = {
                "outcome": "SENT", "detail": "log_written", "recorded_at": _T0,
            }
            return original(conn, attempt_id=attempt_id, result=result)

        monkeypatch.setattr(alert_delivery_store, "insert_outcome", already_there)
        report = _run(db, _log())
        (result,) = report.results
        assert (result.status, result.reason) == (
            STATUS_INVALID_DATA, REASON_OUTCOME_EXISTS,
        )
        assert next(iter(db.outcomes.values()))["outcome"] == "SENT"
        assert report.succeeded is False
        assert db.events[-1] == ("rollback",)

    @pytest.mark.parametrize("now", [datetime(2026, 10, 5, 19, 5), None, "now"])
    def test_invalid_now_is_rejected_before_the_database_is_used(self, db, sender, now):
        db.decisions = [_decision(1)]
        with pytest.raises(ValueError, match="now"):
            run_notify(db, [_log()], _delivery(_log()), now=now)
        assert db.events == [] and sender.calls == []

    def test_wrong_delivery_type_is_rejected(self, db):
        with pytest.raises(ValueError, match="DeliveryPolicy"):
            run_notify(db, [_log()], {"channels": []}, now=_NOW)
        assert db.events == []

    def test_now_is_required_and_keyword_only(self):
        for function in (run_notify, retry_delivery, list_alerts, show_alert):
            parameter = inspect.signature(function).parameters["now"]
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
            assert parameter.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# NT08  Invalid data
# ---------------------------------------------------------------------------

class TestInvalidData:

    @pytest.mark.parametrize("payload", [None, "text", [1, 2], 5])
    def test_payload_that_is_not_an_object(self, db, sender, payload):
        db.decisions = [_decision(1, payload=payload), _decision(2, 1)]
        report = _run(db, _log())
        bad, good = report.results
        assert (bad.status, bad.reason) == (STATUS_INVALID_DATA, REASON_INVALID_DECISION)
        assert good.status == STATUS_ATTEMPTED
        assert sender.pairs() == [(_id(2), "log")]
        assert db.history(1, "log") == []
        assert report.succeeded is False and report.invalid == 1

    def test_payload_with_a_summary_key(self, db, sender):
        db.decisions = [_decision(1, payload={**_payload(1), "summary": "x"})]
        report = _run(db, _log())
        assert report.results[0].status == STATUS_INVALID_DATA
        assert sender.calls == [] and db.attempts == {}

    @pytest.mark.parametrize("overrides", [
        {"decision_id": "not-a-digest"},
        {"evaluated_at": datetime(2026, 10, 5, 19, 0)},
        {"evaluated_at": "2026-10-05T19:00:00Z"},
        {"evaluated_at": None},
    ])
    def test_malformed_decision_row(self, db, sender, overrides):
        db.decisions = [_decision(1, **overrides)]
        report = _run(db, _log())
        assert (report.results[0].status, report.results[0].reason) == (
            STATUS_INVALID_DATA, REASON_INVALID_DECISION,
        )
        assert sender.calls == [] and db.attempts == {}

    def test_summary_of_the_wrong_type(self, db, sender):
        db.decisions = [_decision(1, summary=123)]
        report = _run(db, _log("full", include_summary=True))
        assert report.results[0].status == STATUS_INVALID_DATA
        assert sender.calls == []

    def test_gap_in_attempt_numbers(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 2, O.FAILED_RETRYABLE)
        before = db.snapshot()
        report = _run(db, _log())
        assert (report.results[0].status, report.results[0].reason) == (
            STATUS_INVALID_DATA, REASON_INVALID_HISTORY,
        )
        assert sender.calls == [] and db.snapshot() == before

    def test_attempt_with_a_foreign_identity(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(
            1, "log", 1, O.FAILED_RETRYABLE,
            attempt_id=compute_attempt_id(_id(1), "log", 7),
        )
        report = _run(db, _log())
        assert report.results[0].reason == REASON_INVALID_HISTORY
        assert sender.calls == []

    @pytest.mark.parametrize("field, value", [
        ("channel_type", "pager"),
        ("trigger", "cron"),
        ("attempt_no", 0),
        ("attempt_no", "1"),
        ("summary_included", "yes"),
        ("payload_sha256", "short"),
        ("started_at", datetime(2026, 10, 5, 19, 0)),
        ("started_at", None),
    ])
    def test_malformed_attempt_row(self, db, sender, field, value):
        db.decisions = [_decision(1)]
        attempt_id = db.seed_attempt(1, "log", 1, O.FAILED_RETRYABLE)
        db.attempts[attempt_id][field] = value
        report = _run(db, _log())
        assert report.results[0].reason == REASON_INVALID_HISTORY
        assert sender.calls == []

    @pytest.mark.parametrize("outcome", ["DELIVERED", "sent", ""])
    def test_unknown_outcome_value(self, db, sender, outcome):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, outcome)
        report = _run(db, _log())
        assert report.results[0].reason == REASON_INVALID_HISTORY
        assert sender.calls == []

    def test_invalid_history_is_never_treated_as_sent_or_retryable(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, O.SENT)
        db.seed_attempt(1, "log", 3, O.FAILED_RETRYABLE)
        report = _run(db, _log())
        assert report.results[0].status == STATUS_INVALID_DATA
        assert report.results[0].state is None

    def test_invalid_data_on_one_channel_does_not_affect_another(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "bad", 5, O.FAILED_RETRYABLE)
        report = _run(db, _log("bad"), _log("good"))
        assert [r.status for r in report.results] == [
            STATUS_INVALID_DATA, STATUS_ATTEMPTED,
        ]

    def test_history_becoming_invalid_inside_t1_sends_nothing(self, db, sender):
        db.decisions = [_decision(1)]

        def corrupt(decision_id, channel_name):
            db.after_history_read = None
            db.seed_attempt(1, "log", 4, O.FAILED_RETRYABLE)

        db.after_history_read = corrupt
        report = _run(db, _log())
        assert report.results[0].reason == REASON_INVALID_HISTORY
        assert sender.calls == []
        assert "insert_attempt" not in [event[0] for event in db.events]


# ---------------------------------------------------------------------------
# NT09  Operator retry
# ---------------------------------------------------------------------------

def _seed_state(db, state: DeliveryState, channel="log") -> None:
    if state is S.SENT:
        db.seed_attempt(1, channel, 1, O.SENT)
    elif state is S.IN_FLIGHT:
        db.seed_attempt(1, channel, 1, None, started=_NOW)
    elif state is S.UNCERTAIN:
        db.seed_attempt(1, channel, 1, O.UNCERTAIN)
    elif state is S.PERMANENTLY_FAILED:
        db.seed_attempt(1, channel, 1, O.FAILED_PERMANENT)
    elif state is S.RETRYABLE:
        db.seed_attempt(1, channel, 1, O.FAILED_RETRYABLE)
    elif state is S.EXHAUSTED:
        for number in (1, 2, 3):
            db.seed_attempt(1, channel, number, O.FAILED_RETRYABLE)


class TestOperatorRetry:

    @pytest.mark.parametrize("state", [S.EXHAUSTED, S.PERMANENTLY_FAILED])
    def test_allowed_states(self, db, sender, state):
        db.decisions = [_decision(1)]
        _seed_state(db, state)
        result = _retry(db, _log(), 1)
        assert (result.status, result.state, result.outcome) == (
            STATUS_ATTEMPTED, state, O.SENT,
        )
        latest = db.history(1, "log")[-1]
        assert latest["trigger"] == "operator" and latest["outcome"] == "SENT"
        assert sender.pairs() == [(_id(1), "log")]

    def test_expired_is_allowed(self, db, sender):
        db.decisions = [_decision(1, -600)]
        result = _retry(db, _log(), 1)
        assert (result.status, result.state, result.attempt_no) == (
            STATUS_ATTEMPTED, S.EXPIRED, 1,
        )

    def test_uncertain_without_confirmation_writes_and_sends_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        _seed_state(db, S.UNCERTAIN)
        before = db.snapshot()
        result = _retry(db, _log(), 1)
        assert (result.status, result.state, result.reason) == (
            STATUS_REFUSED, S.UNCERTAIN, "confirm_resend_required",
        )
        assert result.is_problem is True
        assert sender.calls == [] and db.snapshot() == before and db.commits == 0

    def test_uncertain_from_a_missing_outcome_needs_confirmation(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, None, started=_T0 - timedelta(hours=2))
        assert _retry(db, _log(), 1).reason == "confirm_resend_required"
        assert sender.calls == []

    def test_uncertain_with_confirmation(self, db, sender):
        db.decisions = [_decision(1)]
        _seed_state(db, S.UNCERTAIN)
        result = _retry(db, _log(), 1, confirm_resend=True)
        assert (result.status, result.attempt_no, result.outcome) == (
            STATUS_ATTEMPTED, 2, O.SENT,
        )
        assert db.history(1, "log")[-1]["trigger"] == "operator"

    @pytest.mark.parametrize("confirm", [True, False])
    @pytest.mark.parametrize("state, reason", [
        (S.SENT, "already_sent"),
        (S.IN_FLIGHT, "in_flight"),
        (S.NEVER_ATTEMPTED, "use_notify"),
        (S.RETRYABLE, "use_notify"),
    ])
    def test_refused_states(self, db, sender, state, reason, confirm):
        db.decisions = [_decision(1)]
        _seed_state(db, state)
        before = db.snapshot()
        result = _retry(db, _log(), 1, confirm_resend=confirm)
        assert (result.status, result.state, result.reason) == (
            STATUS_REFUSED, state, reason,
        )
        assert sender.calls == [] and db.snapshot() == before and db.commits == 0

    def test_disabled_channel_is_refused_before_the_database_is_used(self, db, sender):
        db.decisions = [_decision(1)]
        channel = _hook(enabled=False)
        result = _retry(db, channel, 1, confirm_resend=True)
        assert (result.status, result.reason, result.is_problem) == (
            STATUS_REFUSED, REASON_CHANNEL_DISABLED, True,
        )
        assert db.events == [] and sender.calls == []

    def test_unknown_decision(self, db, sender):
        with pytest.raises(DecisionNotFoundError) as excinfo:
            _retry(db, _log(), 99)
        assert excinfo.value.decision_id == _id(99)
        assert sender.calls == [] and db.attempts == {}

    @pytest.mark.parametrize("verdict", ["SUPPRESSED", "NOT_ALERTABLE"])
    def test_non_alert_decision_is_not_found(self, db, sender, verdict):
        db.decisions = [_decision(1, verdict=verdict)]
        with pytest.raises(DecisionNotFoundError):
            _retry(db, _log(), 1)
        assert sender.calls == []

    def test_operator_attempt_counts_toward_max_attempts(self, db, sender):
        db.decisions = [_decision(1)]
        _seed_state(db, S.EXHAUSTED)
        sender.results["log"] = (O.UNCERTAIN, "log_write_failed")
        _retry(db, _log(), 1)
        assert [row["attempt_no"] for row in db.history(1, "log")] == [1, 2, 3, 4]
        again = _retry(db, _log(), 1)
        assert again.reason == "confirm_resend_required"

    def test_operator_uncertain_retry_can_hand_back_to_the_automatic_run(self, db, sender):
        db.decisions = [_decision(1)]
        channel = _hook(max_attempts=3)
        db.seed_attempt(1, "hook", 1, O.UNCERTAIN, channel_type="webhook")
        sender.results["hook"] = (O.FAILED_RETRYABLE, "http_503")
        result = _retry(db, channel, 1, confirm_resend=True)
        assert (result.attempt_no, result.outcome) == (2, O.FAILED_RETRYABLE)

        sender.results["hook"] = (O.SENT, "http_200")
        report = _run(db, channel)
        (automatic,) = report.results
        assert (automatic.state, automatic.attempt_no, automatic.outcome) == (
            S.RETRYABLE, 3, O.SENT,
        )
        assert [row["trigger"] for row in db.history(1, "hook")] == [
            "auto", "operator", "auto",
        ]

    def test_retry_uses_the_same_t1_send_t2_sequence(self, db, sender):
        db.decisions = [_decision(1)]
        _seed_state(db, S.PERMANENTLY_FAILED)
        _retry(db, _log(), 1)
        assert [event[0] for event in db.events] == [
            "fetch_decision", "rollback",
            "fetch_channel_history", "insert_attempt", "commit",
            "send",
            "insert_outcome", "commit",
        ]
        assert sender.calls[0]["in_transaction"] is False
        assert sender.calls[0]["attempt_committed"] is True

    def test_lost_race_on_retry(self, db, sender):
        db.decisions = [_decision(1)]
        _seed_state(db, S.PERMANENTLY_FAILED)
        db.before_insert_attempt = lambda values: db.attempts.setdefault(
            "other", {**values, "attempt_id": "other", "started_at": db.clock},
        )
        result = _retry(db, _log(), 1)
        assert result.status == STATUS_LOST_RACE and result.is_problem
        assert sender.calls == []

    def test_confirmation_is_enforced_below_the_cli(self):
        source = inspect.getsource(alert_notifier._attempt)
        assert "check_eligibility(state, trigger, confirm_resend=confirm_resend)" in source
        assert source.index("check_eligibility(") < source.index("insert_attempt(")


# ---------------------------------------------------------------------------
# NT10  Dry run
# ---------------------------------------------------------------------------

class TestDryRun:

    @pytest.fixture
    def no_side_effects(self, monkeypatch, db):
        def forbidden(*args, **kwargs):
            raise AssertionError("a dry run must not deliver or compute an identity")

        monkeypatch.setattr(alert_channels, "send", forbidden)
        monkeypatch.setattr(alert_notifier, "compute_attempt_id", forbidden)
        for name in ("_os_open", "_os_write", "_open_connection", "_send_log"):
            monkeypatch.setattr(alert_channels, name, forbidden)
        return db

    def test_writes_nothing_and_never_commits(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1), _decision(2, 1)]
        db.seed_attempt(2, "log", 1, O.FAILED_RETRYABLE)
        before = db.snapshot()
        report = _run(db, _log(), _hook(), dry_run=True, log_stream=io.BytesIO())
        assert db.snapshot() == before
        assert db.commits == 0 and db._pending_attempts == {}
        names = {event[0] for event in db.events}
        assert names == {
            "fetch_alert_decisions", "fetch_delivery_history",
            "fetch_channel_history", "rollback",
        }
        assert report.dry_run is True and report.total == 4

    def test_reports_the_hypothetical_attempt_number_only(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 1, O.FAILED_RETRYABLE)
        db.seed_attempt(1, "log", 2, O.FAILED_RETRYABLE)
        report = _run(db, _log(), _hook(), dry_run=True)
        retry, first = report.results
        assert (retry.status, retry.attempt_no, retry.state) == (
            STATUS_WOULD_ATTEMPT, 3, S.RETRYABLE,
        )
        assert (first.status, first.attempt_no, first.state) == (
            STATUS_WOULD_ATTEMPT, 1, S.NEVER_ATTEMPTED,
        )
        assert retry.attempt_id is None and first.attempt_id is None
        assert retry.outcome is None and retry.is_problem is False

    def test_blocked_states_are_reported(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1), _decision(2, -600)]
        db.seed_attempt(1, "log", 1, O.SENT)
        report = _run(db, _log(), dry_run=True)
        assert [(r.status, r.state) for r in report.results] == [
            (STATUS_BLOCKED, S.EXPIRED), (STATUS_BLOCKED, S.SENT),
        ]
        assert report.succeeded is True

    def test_predicts_an_oversized_webhook_body(self, no_side_effects):
        db = no_side_effects
        big = {**_payload(1), "limitations": ["x" * 20000]}
        db.decisions = [_decision(1, payload=big)]
        report = _run(db, _hook(), _log(), _file(), dry_run=True)
        hook, log, file = report.results
        assert (hook.status, hook.detail, hook.is_problem) == (
            STATUS_WOULD_ATTEMPT, "body_too_large", True,
        )
        assert (log.detail, file.detail) == (None, None)
        assert report.succeeded is False

    def test_invalid_data_is_reported_like_a_real_run(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1, payload=None)]
        report = _run(db, _log(), dry_run=True)
        assert report.results[0].status == STATUS_INVALID_DATA
        assert report.succeeded is False

    def test_each_item_ends_with_a_rollback(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1), _decision(2, 1)]
        _run(db, _log(), dry_run=True)
        names = [event[0] for event in db.events][3:]
        assert names == ["fetch_channel_history", "rollback"] * 2

    def test_same_verdicts_as_the_real_run_would_act_on(self, db, sender):
        db.decisions = [_decision(n, n) for n in range(5)]
        db.seed_attempt(1, "log", 1, O.SENT)
        db.seed_attempt(2, "log", 1, O.FAILED_PERMANENT)
        db.seed_attempt(3, "log", 1, O.FAILED_RETRYABLE)
        dry = _run(db, _log(), dry_run=True)
        real = _run(db, _log())
        assert [r.decision_id for r in dry.results] == [r.decision_id for r in real.results]
        for planned, done in zip(dry.results, real.results):
            assert (planned.status == STATUS_WOULD_ATTEMPT) == (
                done.status == STATUS_ATTEMPTED
            )
            assert planned.attempt_no == done.attempt_no
            assert planned.state is done.state

    def test_retry_dry_run(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1)]
        _seed_state(db, S.EXHAUSTED)
        before = db.snapshot()
        result = _retry(db, _log(), 1, dry_run=True)
        assert (result.status, result.attempt_no, result.attempt_id) == (
            STATUS_WOULD_ATTEMPT, 4, None,
        )
        assert db.snapshot() == before and db.commits == 0

    def test_retry_dry_run_refusal(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1)]
        _seed_state(db, S.UNCERTAIN)
        result = _retry(db, _log(), 1, dry_run=True)
        assert (result.status, result.reason, result.is_problem) == (
            STATUS_REFUSED, "confirm_resend_required", True,
        )
        confirmed = _retry(db, _log(), 1, dry_run=True, confirm_resend=True)
        assert (confirmed.status, confirmed.attempt_no) == (STATUS_WOULD_ATTEMPT, 2)

    def test_no_summary_in_dry_run_results(self, no_side_effects):
        db = no_side_effects
        db.decisions = [_decision(1, summary="PRIVATE-SUMMARY")]
        report = _run(db, _log("full", include_summary=True), dry_run=True)
        assert "PRIVATE" not in repr(report)


# ---------------------------------------------------------------------------
# NT11  Report
# ---------------------------------------------------------------------------

class TestReport:

    def test_counts(self, db, sender):
        db.decisions = [_decision(n, n) for n in range(1, 6)]
        db.seed_attempt(1, "log", 1, O.SENT)
        db.seed_attempt(2, "log", 4, O.FAILED_RETRYABLE)
        sender.results[(_id(3), "log")] = (O.UNCERTAIN, "log_write_failed")
        report = _run(db, _log())
        assert report.total == 5
        assert (report.attempted, report.sent, report.not_sent) == (3, 2, 1)
        assert (report.blocked, report.invalid, report.lost_races) == (1, 1, 0)
        assert report.problems == 2 and report.succeeded is False
        assert report.dry_run is False

    @pytest.mark.parametrize("result, problem", [
        (DeliveryResult("d", "c", STATUS_ATTEMPTED, outcome=O.SENT), False),
        (DeliveryResult("d", "c", STATUS_ATTEMPTED, outcome=O.FAILED_RETRYABLE), True),
        (DeliveryResult("d", "c", STATUS_ATTEMPTED, outcome=O.FAILED_PERMANENT), True),
        (DeliveryResult("d", "c", STATUS_ATTEMPTED, outcome=O.UNCERTAIN), True),
        (DeliveryResult("d", "c", STATUS_BLOCKED, state=S.SENT), False),
        (DeliveryResult("d", "c", STATUS_BLOCKED, state=S.UNCERTAIN), False),
        (DeliveryResult("d", "c", STATUS_REFUSED), True),
        (DeliveryResult("d", "c", STATUS_LOST_RACE), True),
        (DeliveryResult("d", "c", STATUS_INVALID_DATA), True),
        (DeliveryResult("d", "c", STATUS_WOULD_ATTEMPT, attempt_no=1), False),
        (DeliveryResult("d", "c", STATUS_WOULD_ATTEMPT, detail="body_too_large"), True),
    ])
    def test_what_counts_as_a_problem(self, result, problem):
        assert result.is_problem is problem

    def test_pre_existing_blocked_states_are_not_problems(self, db, sender):
        db.decisions = [_decision(n, n) for n in range(1, 5)]
        db.seed_attempt(1, "log", 1, O.UNCERTAIN)
        db.seed_attempt(2, "log", 1, O.FAILED_PERMANENT)
        db.seed_attempt(3, "log", 1, None, started=_NOW)
        report = _run(db, _log())
        assert report.blocked == 3 and report.sent == 1
        assert report.succeeded is True

    def test_results_are_immutable_and_hold_no_summary_field(self):
        result = DeliveryResult("d", "c", STATUS_BLOCKED)
        with pytest.raises(Exception):
            result.status = "x"
        names = set(DeliveryResult.__dataclass_fields__)
        assert names == {
            "decision_id", "channel_name", "status", "state", "attempt_no",
            "attempt_id", "outcome", "detail", "reason",
        }


# ---------------------------------------------------------------------------
# NT12  Read-only views
# ---------------------------------------------------------------------------

def _configs(*channels: PreparedChannel) -> list[ChannelConfig]:
    return [channel.config for channel in channels]


class TestViews:

    def test_list_is_newest_first_with_states(self, db, sender):
        db.decisions = [_decision(1, 0), _decision(2, 5), _decision(3, 2)]
        db.seed_attempt(2, "log", 1, O.SENT)
        db.seed_attempt(3, "hook", 1, O.FAILED_PERMANENT, channel_type="webhook")
        channels = (_log(), _hook())
        views = list_alerts(
            db, _configs(*channels), _delivery(*channels),
            now=_T0 + timedelta(minutes=6), limit=50,
        )
        assert [view.decision_id for view in views] == [_id(2), _id(3), _id(1)]
        assert views[0].states == (("log", "SENT"), ("hook", "NEVER_ATTEMPTED"))
        assert views[1].states == (("log", "NEVER_ATTEMPTED"), ("hook", "PERMANENTLY_FAILED"))
        assert all(view.attempts == () for view in views)

    def test_list_passes_the_limit_and_shows_alerts_only(self, db, sender):
        db.decisions = [_decision(n, n) for n in range(10)]
        db.decisions.append(_decision(99, 50, verdict="SUPPRESSED"))
        views = list_alerts(db, [], DeliveryPolicy(channels=()), now=_NOW, limit=3)
        assert [view.decision_id for view in views] == [_id(9), _id(8), _id(7)]
        assert ("fetch_recent_alert_decisions", 3) in db.events

    def test_list_tie_break_is_decision_id_ascending(self, db, sender):
        db.decisions = [_decision(n, 0) for n in range(6)]
        views = list_alerts(db, [], DeliveryPolicy(channels=()), now=_NOW, limit=50)
        assert [view.decision_id for view in views] == sorted(_id(n) for n in range(6))

    def test_list_writes_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        db.read_only = True
        before = db.snapshot()
        list_alerts(db, _configs(_log()), _delivery(_log()), now=_NOW, limit=50)
        assert db.snapshot() == before and db.commits == 0
        assert db.events[-1] == ("rollback",)
        assert sender.calls == []

    def test_views_never_hold_summary_text(self, db, sender):
        db.decisions = [
            _decision(1, 0, summary="PRIVATE-ONE"),
            _decision(2, 1, summary="PRIVATE-TWO", truncated=True),
            _decision(3, 2, summary=None),
        ]
        views = list_alerts(db, [], DeliveryPolicy(channels=()), now=_NOW, limit=50)
        assert [view.summary_stored for view in views] == ["no", "truncated", "yes"]
        assert "PRIVATE" not in repr(views)
        shown = show_alert(db, [], DeliveryPolicy(channels=()), _id(1), now=_NOW)
        assert "PRIVATE" not in repr(shown) and shown.summary_stored == "yes"

    def test_show_lists_every_attempt_with_its_outcome(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "hook", 1, O.FAILED_RETRYABLE, detail="http_503",
                        channel_type="webhook")
        db.seed_attempt(1, "hook", 2, None, trigger="operator", started=_NOW,
                        channel_type="webhook")
        db.seed_attempt(1, "old", 1, O.SENT, detail="log_written")
        view = show_alert(db, _configs(_hook()), _delivery(_hook()), _id(1), now=_NOW)
        assert view.states == (("hook", "IN_FLIGHT"),)
        assert [(a.channel_name, a.attempt_no, a.outcome, a.detail) for a in view.attempts] == [
            ("hook", 1, "FAILED_RETRYABLE", "http_503"),
            ("hook", 2, None, None),
            ("old", 1, "SENT", "log_written"),
        ]
        assert view.payload == _payload(1)
        assert (view.policy_version, view.reason_code) == ("1.0.0", "severity_met")

    def test_show_gives_no_state_for_a_channel_that_is_not_enabled(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "old", 1, O.SENT)
        view = show_alert(db, _configs(_log()), _delivery(_log()), _id(1), now=_NOW)
        assert [name for name, _ in view.states] == ["log"]
        assert [a.channel_name for a in view.attempts] == ["old"]

    def test_invalid_history_is_shown_as_invalid(self, db, sender):
        db.decisions = [_decision(1)]
        db.seed_attempt(1, "log", 3, O.SENT)
        view = show_alert(db, _configs(_log()), _delivery(_log()), _id(1), now=_NOW)
        assert view.states == (("log", STATE_INVALID),)
        assert len(view.attempts) == 1
        listed = list_alerts(db, _configs(_log()), _delivery(_log()), now=_NOW, limit=5)
        assert listed[0].states == (("log", "INVALID"),)

    def test_show_unknown_or_non_alert_decision(self, db, sender):
        db.decisions = [_decision(1, verdict="SUPPRESSED")]
        for n in (1, 2):
            with pytest.raises(DecisionNotFoundError):
                show_alert(db, [], DeliveryPolicy(channels=()), _id(n), now=_NOW)

    def test_show_writes_nothing(self, db, sender):
        db.decisions = [_decision(1)]
        db.read_only = True
        show_alert(db, _configs(_log()), _delivery(_log()), _id(1), now=_NOW)
        assert db.commits == 0 and db.events[-1] == ("rollback",)
        assert not {"insert_attempt", "insert_outcome"} & {e[0] for e in db.events}

    def test_payload_view_is_a_copy(self, db, sender):
        row = _decision(1)
        db.decisions = [row]
        view = show_alert(db, [], DeliveryPolicy(channels=()), _id(1), now=_NOW)
        view.payload["severity"] = "changed"
        assert row["payload"]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# NT13  format_result
# ---------------------------------------------------------------------------

class TestFormatResult:

    @pytest.mark.parametrize("result, expected", [
        (DeliveryResult("d1", "hook", STATUS_ATTEMPTED, state=S.NEVER_ATTEMPTED,
                        attempt_no=1, attempt_id="a" * 64, outcome=O.SENT,
                        detail="http_200"),
         "d1  hook  attempt 1  SENT  http_200"),
        (DeliveryResult("d1", "hook", STATUS_ATTEMPTED, attempt_no=3,
                        outcome=O.UNCERTAIN, detail="request_timeout"),
         "d1  hook  attempt 3  UNCERTAIN  request_timeout"),
        (DeliveryResult("d1", "log", STATUS_BLOCKED, state=S.SENT, reason="already_sent"),
         "d1  log  blocked  SENT  already_sent"),
        (DeliveryResult("d1", "log", STATUS_REFUSED, state=S.UNCERTAIN,
                        reason="confirm_resend_required"),
         "d1  log  refused  UNCERTAIN  confirm_resend_required"),
        (DeliveryResult("d1", "log", STATUS_REFUSED, state=S.RETRYABLE, reason="use_notify"),
         "d1  log  refused  RETRYABLE  use_notify  (the automatic run handles this state)"),
        (DeliveryResult("d1", "log", STATUS_REFUSED, reason="channel_disabled"),
         "d1  log  refused  channel_disabled"),
        (DeliveryResult("d1", "log", STATUS_LOST_RACE, attempt_no=2),
         "d1  log  lost_race  attempt 2"),
        (DeliveryResult("d1", "log", STATUS_INVALID_DATA, reason="invalid_history"),
         "d1  log  invalid_data  invalid_history"),
        (DeliveryResult("d1", "log", STATUS_WOULD_ATTEMPT, attempt_no=2),
         "d1  log  would attempt 2"),
        (DeliveryResult("d1", "hook", STATUS_WOULD_ATTEMPT, attempt_no=1,
                        detail="body_too_large"),
         "d1  hook  would attempt 1  would fail body_too_large"),
    ])
    def test_lines(self, result, expected):
        assert format_result(result) == expected

    def test_attempt_identity_is_never_printed(self):
        result = DeliveryResult(
            "d1", "hook", STATUS_ATTEMPTED, attempt_no=1, attempt_id="a" * 64,
            outcome=O.SENT, detail="http_200",
        )
        assert "a" * 64 not in format_result(result)

    def test_one_line_even_for_odd_identifiers(self):
        result = DeliveryResult("d\n1", "ho\tok", STATUS_INVALID_DATA, reason="x\ny")
        assert "\n" not in format_result(result) and "\t" not in format_result(result)

    def test_malformed_decision_id_does_not_crash(self):
        assert format_result(
            DeliveryResult(None, "log", STATUS_INVALID_DATA, reason="invalid_decision"),
        ) == "None  log  invalid_data  invalid_decision"


# ---------------------------------------------------------------------------
# NT14  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(alert_notifier))

    def test_imports(self, tree):
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "dataclasses", "datetime", "typing",
            "alert_channels", "alert_delivery_store", "alert_delivery_state",
            "alert_identity", "alert_models", "alert_policy",
        }

    def test_no_driver_statement_clock_environment_or_output(self, tree):
        source = inspect.getsource(alert_notifier)
        for word in ("psycopg", "SELECT", "INSERT INTO", "ON CONFLICT", "execute(",
                     "cursor(", "os.environ", "getenv", "print(", "open("):
            assert word not in source, word
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert {"now", "utcnow", "today", "time"}.isdisjoint(attributes)

    def test_no_rca_evaluation_or_other_component(self):
        source = inspect.getsource(alert_notifier)
        for word in ("alert_store", "alert_evaluator", "alert_engine", "alert_db",
                     "rca_investigations", "rca_evidence", "embedding",
                     "telemetry_spans", "anomaly_events", "decide("):
            assert word not in source, word

    def test_connection_is_only_committed_or_rolled_back(self, tree):
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "conn"
        }
        assert used == {"commit", "rollback"}

    def test_store_functions_used(self, tree):
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "alert_delivery_store"
        }
        assert used == set(_STORE_FUNCTIONS)

    def test_statuses(self):
        assert (
            STATUS_ATTEMPTED, STATUS_BLOCKED, STATUS_REFUSED, STATUS_LOST_RACE,
            STATUS_INVALID_DATA, STATUS_WOULD_ATTEMPT,
        ) == (
            "attempted", "blocked", "refused", "lost_race", "invalid_data",
            "would_attempt",
        )
