"""
alerting/tests/unit/test_alert_evaluator.py

Unit tests for alert_evaluator.py.

No live PostgreSQL and no network.  alert_store is replaced by an in-memory
fake that applies the same predicates as the real statements and has real
transaction behaviour: writes are pending until commit() and are discarded by
rollback().  The locked engine, identity, model and policy modules are used
unchanged.

Test inventory:
    EV01  Policy registration
    EV02  Candidate discovery
    EV03  History: bounds, duplicate, cooldown, storm, de-duplication
    EV04  Same-run history (real run)
    EV05  Dry run
    EV06  Dry run equals a real sequential run
    EV07  Persistence and first-write-wins
    EV08  Failure model
    EV09  Payload
    EV10  Summary
    EV11  Informational isolation
    EV12  Clock
    EV13  Report and callback
    EV14  Module boundaries
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import inspect
import json
import random
from datetime import datetime, timedelta, timezone, tzinfo

import psycopg
import pytest

import alert_evaluator
import alert_store
from alert_engine import STORM_WINDOW, AlertSubject
from alert_evaluator import (
    ADVISORY,
    EVALUATION_STATUSES,
    POLICY_ALREADY_REGISTERED,
    POLICY_NOT_REGISTERED,
    POLICY_REGISTERED,
    STATUS_ALREADY_DECIDED,
    STATUS_DRY_RUN,
    STATUS_FAILURE,
    STATUS_PERSISTED,
    SUMMARY_MAX_CODE_POINTS,
    EvaluationReport,
    EvaluationResult,
    PolicyVersionConflictError,
    build_payload,
    format_timestamp,
    persisted_summary,
    run_evaluation,
)
from alert_identity import compute_decision_id, compute_dedup_key
from alert_models import (
    AlertDecision,
    Confidence,
    Decision,
    ReasonCode,
    Severity,
)
from alert_policy import evaluation_hash_object, validate_policy
from alert_version import PAYLOAD_VERSION


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_VERSION = "1.0.0"
_KEY = ("latency", "svc", "op")
_OTHER_KEYS = [("error_rate", "svc", "op"), ("latency", "other", "op"),
               ("tool_failure", "svc", None), ("latency", None, None)]
_NEVER_STALE = 10_000_000

_STORE_FUNCTIONS = (
    "fetch_policy_sha256", "insert_policy", "fetch_candidates",
    "fetch_alert_history", "insert_decision",
)

_PAYLOAD_KEYS = [
    "payload_version", "decision_id", "investigation_id", "anomaly_id",
    "anomaly_type", "service_name", "operation_name", "event_time",
    "evaluated_at", "severity", "confidence", "limitations", "reason_code",
    "policy_version", "advisory",
]


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _at(minutes: float = 0, **extra) -> datetime:
    return _T0 + timedelta(minutes=minutes, **extra)


def _policy(version: str = _VERSION, **evaluation):
    evaluation.setdefault("max_alert_age_minutes", _NEVER_STALE)
    return validate_policy({
        "policy_schema_version": "1.0.0",
        "policy_version": version,
        "evaluation": evaluation,
        "delivery": {"channels": [
            {"name": "log", "type": "log", "enabled": True},
        ]},
        "guardrails": {},
    })


def _inv(
    n,
    minutes: float = 0,
    *,
    severity: str = "WARNING",
    key=_KEY,
    anomaly=None,
    confidence: str = "HIGH",
    limitations=(),
    summary="summary text",
    event_time=None,
) -> dict:
    return {
        "investigation_id": _hex(f"investigation-{n}"),
        "anomaly_id": anomaly or _hex(f"anomaly-{n}"),
        "anomaly_type": key[0],
        "service_name": key[1],
        "operation_name": key[2],
        "event_time": event_time if event_time is not None else _at(minutes),
        "severity": severity,
        "confidence": confidence,
        "limitations": list(limitations),
        "summary": summary,
    }


def _decision_id(n, version: str = _VERSION) -> str:
    return compute_decision_id(_hex(f"investigation-{n}"), version)


class FakeDb:
    """
    In-memory stand-in for the connection and for alert_store.

    Reads see committed and pending rows; commit() makes pending rows
    durable; rollback() discards them.
    """

    def __init__(self) -> None:
        self.investigations: list[dict] = []
        self.policies: dict[str, dict] = {}
        self.decisions: dict[str, AlertDecision] = {}
        self._pending_policies: dict[str, dict] = {}
        self._pending_decisions: dict[str, AlertDecision] = {}
        self.read_only = False
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self.events: list[tuple] = []
        self.history_calls: list[dict] = []
        self.errors: dict[str, list] = {}
        self.before_insert = None
        self.history_filter = None

    # -- test controls ------------------------------------------------------

    def fail(self, function: str, error: BaseException, *, on_call: int = 1) -> None:
        self.errors.setdefault(function, []).append([on_call, error])

    def _maybe_fail(self, function: str) -> None:
        for entry in self.errors.get(function, []):
            entry[0] -= 1
            if entry[0] == 0:
                raise entry[1]

    def seed_alert(
        self, n, minutes: float = 0, *, key=_KEY, severity: str = "WARNING",
        version: str = "0.9.0", anomaly=None, event_time=None,
        decision: Decision = Decision.ALERT,
    ) -> AlertDecision:
        investigation_id = _hex(f"seed-investigation-{n}")
        is_alert = decision is Decision.ALERT
        record = AlertDecision(
            decision_id=compute_decision_id(investigation_id, version),
            investigation_id=investigation_id,
            policy_version=version,
            anomaly_id=anomaly or _hex(f"seed-anomaly-{n}"),
            anomaly_type=key[0],
            service_name=key[1],
            operation_name=key[2],
            event_time=event_time if event_time is not None else _at(minutes),
            severity=Severity(severity),
            confidence=Confidence.HIGH,
            limitations=(),
            dedup_key=compute_dedup_key(*key),
            decision=decision,
            reason_code=(
                ReasonCode.SEVERITY_MET if is_alert
                else ReasonCode.KILL_SWITCH if decision is Decision.SUPPRESSED
                else ReasonCode.STALE
            ),
            related_decision_id=None,
            evaluated_at=_T0,
            payload={"seed": True} if is_alert else None,
        )
        self.decisions[record.decision_id] = record
        return record

    def snapshot(self):
        return (dict(self.policies), dict(self.decisions))

    def clone(self) -> "FakeDb":
        """An independent database with the same committed rows."""
        other = FakeDb()
        other.investigations = [dict(row) for row in self.investigations]
        other.policies = copy.deepcopy(self.policies)
        other.decisions = dict(self.decisions)      # decisions are immutable
        return other

    # -- connection ---------------------------------------------------------

    def commit(self) -> None:
        self._maybe_fail("commit")
        assert not self.read_only, "commit() in a read-only session"
        self.policies.update(self._pending_policies)
        self.decisions.update(self._pending_decisions)
        self._pending_policies.clear()
        self._pending_decisions.clear()
        self.commits += 1
        self.events.append(("commit",))

    def rollback(self) -> None:
        self._pending_policies.clear()
        self._pending_decisions.clear()
        self.rollbacks += 1
        self.events.append(("rollback",))

    def close(self) -> None:
        self.closes += 1

    # -- store --------------------------------------------------------------

    def _visible_decisions(self) -> list[AlertDecision]:
        return [*self.decisions.values(), *self._pending_decisions.values()]

    def fetch_policy_sha256(self, conn, policy_version):
        assert conn is self
        self.events.append(("fetch_policy_sha256", policy_version))
        self._maybe_fail("fetch_policy_sha256")
        row = self._pending_policies.get(policy_version) or self.policies.get(policy_version)
        return None if row is None else row["policy_sha256"]

    def insert_policy(self, conn, *, policy_version, policy_sha256, policy_json):
        assert conn is self
        assert not self.read_only, "policy insert in a read-only session"
        self.events.append(("insert_policy", policy_version))
        self._maybe_fail("insert_policy")
        if policy_version in self.policies or policy_version in self._pending_policies:
            return False
        self._pending_policies[policy_version] = {
            "policy_sha256": policy_sha256, "policy_json": dict(policy_json),
        }
        return True

    def fetch_candidates(self, conn, policy_version):
        assert conn is self
        self.events.append(("fetch_candidates", policy_version))
        self._maybe_fail("fetch_candidates")
        decided = {
            d.investigation_id for d in self._visible_decisions()
            if d.policy_version == policy_version
        }
        rows = [
            dict(row) for row in self.investigations
            if row["investigation_id"] not in decided
        ]

        def order(row):
            when = row["event_time"]
            comparable = when if isinstance(when, datetime) and when.tzinfo else _T0
            return (comparable, str(row["investigation_id"]))

        return sorted(rows, key=order)

    def fetch_alert_history(
        self, conn, *, anomaly_id, dedup_key, event_time, cooldown_start, storm_start,
    ):
        assert conn is self
        self.events.append(("fetch_alert_history", anomaly_id))
        self.history_calls.append(dict(
            anomaly_id=anomaly_id, dedup_key=dedup_key, event_time=event_time,
            cooldown_start=cooldown_start, storm_start=storm_start,
        ))
        self._maybe_fail("fetch_alert_history")
        found = {}
        for d in self._visible_decisions():
            if d.decision is not Decision.ALERT:
                continue
            duplicate = d.anomaly_id == anomaly_id
            cooldown = (
                d.dedup_key == dedup_key
                and cooldown_start < d.event_time <= event_time
            )
            storm = storm_start < d.event_time <= event_time
            if duplicate or cooldown or storm:
                found[d.decision_id] = {
                    "decision_id": d.decision_id,
                    "anomaly_id": d.anomaly_id,
                    "dedup_key": d.dedup_key,
                    "event_time": d.event_time,
                    "severity": d.severity.value,
                    "decision": d.decision.value,
                }
        rows = [found[key] for key in sorted(found)]
        if self.history_filter is not None:
            rows = self.history_filter(rows)
        return rows

    def insert_decision(self, conn, decision):
        assert conn is self
        assert not self.read_only, "decision insert in a read-only session"
        assert isinstance(decision, AlertDecision)
        self.events.append(("insert_decision", decision.decision_id))
        self._maybe_fail("insert_decision")
        if self.before_insert is not None:
            self.before_insert(decision)
        for existing in self._visible_decisions():
            if (existing.investigation_id, existing.policy_version) == (
                decision.investigation_id, decision.policy_version,
            ):
                return False
        self._pending_decisions[decision.decision_id] = decision
        return True


def _install(monkeypatch, fake: FakeDb) -> FakeDb:
    for name in _STORE_FUNCTIONS:
        monkeypatch.setattr(alert_store, name, getattr(fake, name))
    return fake


@pytest.fixture
def db(monkeypatch) -> FakeDb:
    return _install(monkeypatch, FakeDb())


def _run(db: FakeDb, policy=None, *, evaluated_at=_T0, dry_run=False, on_result=None):
    # As the CLI does: a dry run gets a read-only session.
    db.read_only = dry_run
    return run_evaluation(
        db, policy if policy is not None else _policy(),
        evaluated_at=evaluated_at, dry_run=dry_run, on_result=on_result,
    )


def _verdicts(report: EvaluationReport) -> list[tuple]:
    return [
        (r.decision, r.reason_code, r.related_decision_id) for r in report.results
    ]


def _by_n(report: EvaluationReport, n) -> EvaluationResult:
    wanted = _hex(f"investigation-{n}")
    (result,) = [r for r in report.results if r.investigation_id == wanted]
    return result


_ALERT = (Decision.ALERT, ReasonCode.SEVERITY_MET, None)


# ---------------------------------------------------------------------------
# EV01  Policy registration
# ---------------------------------------------------------------------------

class TestPolicyRegistration:

    def test_absent_version_is_registered(self, db):
        policy = _policy()
        report = _run(db, policy)
        assert report.policy_status == POLICY_REGISTERED
        assert db.policies[_VERSION]["policy_sha256"] == policy.policy_sha256

    def test_stored_document_is_the_hashed_evaluation_object(self, db):
        policy = _policy(cooldown_minutes=45)
        _run(db, policy)
        stored = db.policies[_VERSION]["policy_json"]
        assert stored == evaluation_hash_object(
            policy.policy_schema_version, policy.policy_version, policy.evaluation,
        )
        assert set(stored) == {"policy_schema_version", "policy_version", "evaluation"}
        assert "delivery" not in stored and "guardrails" not in stored
        assert stored["evaluation"]["cooldown_minutes"] == 45

    def test_registration_is_committed_before_discovery(self, db):
        db.investigations = [_inv(1)]
        _run(db)
        names = [event[0] for event in db.events]
        assert names[:4] == [
            "insert_policy", "fetch_policy_sha256", "commit", "fetch_candidates",
        ]

    def test_same_version_same_hash_is_accepted(self, db):
        _run(db)
        before = copy.deepcopy(db.policies)
        report = _run(db)
        assert report.policy_status == POLICY_ALREADY_REGISTERED
        assert db.policies == before

    def test_delivery_change_keeps_the_same_registration(self, db):
        _run(db)
        changed = validate_policy({
            "policy_schema_version": "1.0.0",
            "policy_version": _VERSION,
            "evaluation": {"max_alert_age_minutes": _NEVER_STALE},
            "delivery": {"max_delivery_age_minutes": 5, "channels": []},
            "guardrails": {"delivery_lookback_hours": 1},
        })
        assert _run(db, changed).policy_status == POLICY_ALREADY_REGISTERED

    def test_same_version_different_hash_is_a_conflict(self, db):
        _run(db, _policy(cooldown_minutes=30))
        db.investigations = [_inv(1)]
        before = db.snapshot()
        db.events.clear()
        changed = _policy(cooldown_minutes=31)
        with pytest.raises(PolicyVersionConflictError) as excinfo:
            _run(db, changed)
        assert excinfo.value.policy_version == _VERSION
        assert excinfo.value.stored_sha256 == _policy(cooldown_minutes=30).policy_sha256
        assert excinfo.value.policy_sha256 == changed.policy_sha256
        assert db.snapshot() == before

    def test_conflict_stops_before_discovery_and_rolls_back(self, db):
        _run(db, _policy(enabled=True))
        db.investigations = [_inv(1)]
        db.events.clear()
        with pytest.raises(PolicyVersionConflictError):
            _run(db, _policy(enabled=False))
        names = [event[0] for event in db.events]
        assert names == ["insert_policy", "fetch_policy_sha256", "rollback"]
        assert db.decisions == {}

    def test_conflict_is_not_a_value_error(self):
        assert not issubclass(PolicyVersionConflictError, ValueError)

    def test_registered_even_with_no_candidates(self, db):
        report = _run(db)
        assert report.total == 0
        assert _VERSION in db.policies

    def test_database_error_during_registration_rolls_back_and_propagates(self, db):
        db.fail("insert_policy", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db)
        assert db.rollbacks == 1 and db.commits == 0
        assert db.policies == {}

    def test_missing_row_after_registration_is_an_error(self, db, monkeypatch):
        monkeypatch.setattr(alert_store, "fetch_policy_sha256", lambda conn, v: None)
        with pytest.raises(RuntimeError):
            _run(db)
        assert db.policies == {}

    # -- dry run ------------------------------------------------------------

    def test_dry_run_absent_version_is_not_written(self, db):
        db.investigations = [_inv(1)]
        report = _run(db, dry_run=True)
        assert report.policy_status == POLICY_NOT_REGISTERED
        assert db.policies == {}
        assert report.total == 1

    def test_dry_run_same_hash(self, db):
        _run(db)
        assert _run(db, dry_run=True).policy_status == POLICY_ALREADY_REGISTERED

    def test_dry_run_conflict(self, db):
        _run(db, _policy(cooldown_minutes=30))
        with pytest.raises(PolicyVersionConflictError):
            _run(db, _policy(cooldown_minutes=5), dry_run=True)

    def test_dry_run_only_looks_the_policy_up(self, db):
        _run(db, dry_run=True)
        names = [event[0] for event in db.events]
        assert names[:2] == ["fetch_policy_sha256", "rollback"]
        assert "insert_policy" not in names


# ---------------------------------------------------------------------------
# EV02  Candidate discovery
# ---------------------------------------------------------------------------

class TestDiscovery:

    def test_already_decided_under_the_current_version_is_skipped(self, db):
        db.investigations = [_inv(1), _inv(2, 90)]
        first = _run(db)
        assert first.total == 2
        second = _run(db)
        assert second.total == 0
        assert len(db.decisions) == 2

    def test_any_verdict_counts_as_decided(self, db):
        db.investigations = [_inv(1, severity="INFO")]
        assert _verdicts(_run(db)) == [
            (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None),
        ]
        assert _run(db).total == 0

    def test_decision_under_another_version_does_not_exclude(self, db):
        db.investigations = [_inv(1)]
        _run(db, _policy("1.0.0"))
        report = _run(db, _policy("2.0.0"))
        assert report.total == 1
        assert _by_n(report, 1).decision_id == _decision_id(1, "2.0.0")
        assert set(db.decisions) == {_decision_id(1, "1.0.0"), _decision_id(1, "2.0.0")}

    def test_order_is_event_time_then_investigation_id(self, db):
        rows = [_inv(n, minutes) for n, minutes in
                [(1, 200), (2, 0), (3, 100), (4, 100), (5, 0), (6, 300)]]
        random.Random(7).shuffle(rows)
        db.investigations = rows
        report = _run(db, _policy(cooldown_minutes=0, max_alerts_per_hour=1000))
        got = [r.investigation_id for r in report.results]
        expected = [
            row["investigation_id"] for row in
            sorted(rows, key=lambda r: (r["event_time"], r["investigation_id"]))
        ]
        assert got == expected

    def test_stale_investigation_is_discovered_and_recorded(self, db):
        db.investigations = [_inv(1, 0, severity="CRITICAL")]
        report = _run(
            db, _policy(max_alert_age_minutes=60), evaluated_at=_at(61),
        )
        assert _verdicts(report) == [(Decision.NOT_ALERTABLE, ReasonCode.STALE, None)]
        stored = db.decisions[_decision_id(1)]
        assert stored.decision is Decision.NOT_ALERTABLE
        assert stored.payload is None

    def test_exactly_max_age_old_is_not_stale(self, db):
        db.investigations = [_inv(1, 0)]
        report = _run(
            db, _policy(max_alert_age_minutes=60), evaluated_at=_at(60),
        )
        assert _verdicts(report) == [_ALERT]

    def test_low_severity_is_discovered_and_recorded(self, db):
        db.investigations = [_inv(1, severity="INFO")]
        _run(db)
        assert db.decisions[_decision_id(1)].reason_code is ReasonCode.BELOW_MIN_SEVERITY

    def test_kill_switch_records_a_decision_for_every_candidate(self, db):
        db.investigations = [_inv(1), _inv(2, 5, severity="CRITICAL"), _inv(3, 9, severity="INFO")]
        report = _run(db, _policy(enabled=False))
        assert _verdicts(report) == [
            (Decision.SUPPRESSED, ReasonCode.KILL_SWITCH, None),
        ] * 3
        assert len(db.decisions) == 3

    def test_zero_candidates(self, db):
        report = _run(db)
        assert report.results == ()
        assert report.total == 0
        assert report.succeeded is True
        assert db.decisions == {}

    def test_discovery_transaction_is_ended_before_the_first_candidate(self, db):
        db.investigations = [_inv(1)]
        _run(db)
        names = [event[0] for event in db.events]
        start = names.index("fetch_candidates")
        assert names[start + 1] == "rollback"
        assert names[start + 2] == "fetch_alert_history"

    def test_candidates_are_fetched_once_per_run(self, db):
        db.investigations = [_inv(n, n) for n in range(5)]
        _run(db)
        assert [e[0] for e in db.events].count("fetch_candidates") == 1

    def test_database_error_during_discovery_propagates(self, db):
        db.fail("fetch_candidates", psycopg.OperationalError("down"))
        with pytest.raises(psycopg.OperationalError):
            _run(db)
        assert db.events[-1] == ("rollback",)
        assert db.decisions == {}


# ---------------------------------------------------------------------------
# EV03  History
# ---------------------------------------------------------------------------

class _ShiftZone(tzinfo):
    """A zone whose UTC offset changes from -4h to -5h at local 01:00."""

    _SWITCH = datetime(2026, 11, 1, 1, 0)

    def utcoffset(self, dt):
        naive = dt.replace(tzinfo=None)
        return timedelta(hours=-4 if naive < self._SWITCH else -5)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "SHIFT"


class TestHistoryBounds:

    def test_bounds_for_the_default_windows(self, db):
        db.investigations = [_inv(1, 15)]
        _run(db, _policy(cooldown_minutes=30))
        (call,) = db.history_calls
        assert call["anomaly_id"] == _hex("anomaly-1")
        assert call["dedup_key"] == compute_dedup_key(*_KEY)
        assert call["event_time"] == _at(15)
        assert call["cooldown_start"] == _at(15 - 30)
        assert call["storm_start"] == _at(15) - STORM_WINDOW

    def test_storm_window_is_the_engine_constant(self, db):
        db.investigations = [_inv(1)]
        _run(db, _policy(cooldown_minutes=5))
        assert db.history_calls[0]["storm_start"] == _at(-60)

    def test_cooldown_longer_than_the_storm_window(self, db):
        db.investigations = [_inv(1)]
        _run(db, _policy(cooldown_minutes=180))
        call = db.history_calls[0]
        assert call["cooldown_start"] == _at(-180)
        assert call["cooldown_start"] < call["storm_start"]

    def test_zero_cooldown_gives_an_empty_window(self, db):
        db.investigations = [_inv(1)]
        _run(db, _policy(cooldown_minutes=0))
        call = db.history_calls[0]
        assert call["cooldown_start"] == call["event_time"]

    def test_bounds_are_utc_for_a_non_utc_event_time(self, db):
        zone = timezone(timedelta(hours=5, minutes=30))
        local = _at(0).astimezone(zone)
        db.investigations = [_inv(1, event_time=local)]
        _run(db, _policy(cooldown_minutes=30))
        call = db.history_calls[0]
        for name in ("event_time", "cooldown_start", "storm_start"):
            assert call[name].tzinfo is timezone.utc
        assert call["event_time"] == _at(0)
        assert call["cooldown_start"] == _at(-30)

    def test_window_arithmetic_is_done_in_utc_not_wall_clock(self, db):
        # Local 01:10 is just after the offset change.  Wall-clock arithmetic
        # would put the 30-minute bound at local 00:40 with the old offset,
        # one hour too early.
        local = datetime(2026, 11, 1, 1, 10, tzinfo=_ShiftZone())
        db.investigations = [_inv(1, event_time=local)]
        _run(db, _policy(cooldown_minutes=30))
        call = db.history_calls[0]
        utc = datetime(2026, 11, 1, 6, 10, tzinfo=timezone.utc)
        assert call["event_time"] == utc
        assert call["cooldown_start"] == utc - timedelta(minutes=30)
        assert call["storm_start"] == utc - timedelta(minutes=60)
        assert call["cooldown_start"].tzinfo is timezone.utc

    def test_window_start_that_underflows_is_clamped(self, db):
        minutes = 3000 * 366 * 24 * 60
        db.investigations = [_inv(1)]
        report = _run(db, _policy(cooldown_minutes=minutes))
        earliest = datetime.min.replace(tzinfo=timezone.utc)
        assert db.history_calls[0]["cooldown_start"] == earliest
        assert _verdicts(report) == [_ALERT]

    def test_cooldown_too_large_for_a_duration_is_clamped_then_rejected(self, db):
        db.investigations = [_inv(1)]
        report = _run(db, _policy(cooldown_minutes=10 ** 18))
        earliest = datetime.min.replace(tzinfo=timezone.utc)
        assert db.history_calls[0]["cooldown_start"] == earliest
        # The engine refuses a duration it cannot represent: no decision.
        assert report.results[0].status == STATUS_FAILURE
        assert db.decisions == {}

    def test_history_is_fetched_once_per_candidate(self, db):
        db.investigations = [_inv(n, n * 100) for n in range(4)]
        _run(db)
        assert len(db.history_calls) == 4


class TestDuplicateHistory:

    def test_duplicate_under_another_policy_version(self, db):
        seed = db.seed_alert(1, 0, anomaly=_hex("anomaly-1"), version="0.1.0")
        db.investigations = [_inv(1, 5, key=_OTHER_KEYS[0])]
        assert _verdicts(_run(db)) == [
            (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, seed.decision_id),
        ]

    def test_duplicate_has_no_time_bound(self, db):
        seed = db.seed_alert(
            1, -60 * 24 * 400, anomaly=_hex("anomaly-1"), key=_OTHER_KEYS[1],
        )
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db)) == [
            (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, seed.decision_id),
        ]

    def test_duplicate_with_a_future_event_time_still_counts(self, db):
        seed = db.seed_alert(1, 60 * 24 * 5, anomaly=_hex("anomaly-1"))
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db)) == [
            (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, seed.decision_id),
        ]

    def test_non_alert_decision_for_the_same_anomaly_is_not_a_duplicate(self, db):
        db.seed_alert(1, 0, anomaly=_hex("anomaly-1"), decision=Decision.SUPPRESSED)
        db.seed_alert(2, 0, anomaly=_hex("anomaly-1"), decision=Decision.NOT_ALERTABLE)
        db.investigations = [_inv(1, 5)]
        assert _verdicts(_run(db)) == [_ALERT]

    def test_two_investigations_of_one_anomaly_in_the_same_run(self, db):
        shared = _hex("shared-anomaly")
        db.investigations = [_inv(1, 0, anomaly=shared), _inv(2, 0, anomaly=shared)]
        report = _run(db)
        first, second = report.results
        assert (first.decision, first.reason_code) == (
            Decision.ALERT, ReasonCode.SEVERITY_MET,
        )
        assert (second.decision, second.reason_code, second.related_decision_id) == (
            Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, first.decision_id,
        )


class TestCooldownHistory:

    def test_alert_inside_the_window_suppresses(self, db):
        seed = db.seed_alert(1, -10)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, seed.decision_id),
        ]

    def test_exact_lower_boundary_is_outside(self, db):
        db.seed_alert(1, -30)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [_ALERT]

    def test_one_microsecond_inside_the_lower_boundary(self, db):
        seed = db.seed_alert(1, -30, event_time=_at(-30, microseconds=1))
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, seed.decision_id),
        ]

    def test_same_event_time_is_inside(self, db):
        seed = db.seed_alert(1, 0)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, seed.decision_id),
        ]

    def test_cooldown_longer_than_sixty_minutes(self, db):
        seed = db.seed_alert(1, -120)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=180))) == [
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, seed.decision_id),
        ]

    def test_long_cooldown_exact_lower_boundary(self, db):
        db.seed_alert(1, -180)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=180))) == [_ALERT]

    def test_future_alert_of_the_same_key_has_no_effect(self, db):
        db.seed_alert(1, 1)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [_ALERT]

    def test_alert_of_another_key_does_not_cool_down(self, db):
        db.seed_alert(1, -5, key=_OTHER_KEYS[0])
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=30))) == [_ALERT]

    def test_cooldown_spans_policy_versions(self, db):
        seed = db.seed_alert(1, -5, version="0.0.1")
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db))[0][2] == seed.decision_id

    def test_zero_cooldown_never_suppresses(self, db):
        db.seed_alert(1, 0)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(cooldown_minutes=0))) == [_ALERT]

    def test_escalation_over_a_persisted_alert(self, db):
        seed = db.seed_alert(1, -10, severity="WARNING")
        db.investigations = [_inv(1, severity="CRITICAL")]
        assert _verdicts(_run(db)) == [
            (Decision.ALERT, ReasonCode.ESCALATION, seed.decision_id),
        ]


class TestStormHistory:

    def test_storm_counts_every_dedup_key(self, db):
        db.seed_alert(1, -10, key=_OTHER_KEYS[0])
        db.seed_alert(2, -20, key=_OTHER_KEYS[1])
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=2))) == [
            (Decision.SUPPRESSED, ReasonCode.STORM_CAP, None),
        ]

    def test_storm_spans_policy_versions(self, db):
        db.seed_alert(1, -10, key=_OTHER_KEYS[0], version="0.1.0")
        db.seed_alert(2, -20, key=_OTHER_KEYS[1], version="0.2.0")
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=2)))[0][1] is ReasonCode.STORM_CAP

    def test_exact_lower_boundary_is_outside(self, db):
        db.seed_alert(1, -60, key=_OTHER_KEYS[0])
        db.seed_alert(2, -10, key=_OTHER_KEYS[1])
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=2))) == [_ALERT]

    def test_one_microsecond_inside_the_lower_boundary(self, db):
        db.seed_alert(1, 0, key=_OTHER_KEYS[0], event_time=_at(-60, microseconds=1))
        db.seed_alert(2, -10, key=_OTHER_KEYS[1])
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=2)))[0][1] is ReasonCode.STORM_CAP

    def test_future_alerts_are_not_counted(self, db):
        db.seed_alert(1, 1, key=_OTHER_KEYS[0])
        db.seed_alert(2, 2, key=_OTHER_KEYS[1])
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=1))) == [_ALERT]

    def test_non_alert_decisions_are_not_counted(self, db):
        db.seed_alert(1, -10, key=_OTHER_KEYS[0], decision=Decision.SUPPRESSED)
        db.seed_alert(2, -20, key=_OTHER_KEYS[1], decision=Decision.NOT_ALERTABLE)
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db, _policy(max_alerts_per_hour=1))) == [_ALERT]


class TestHistoryDeduplication:

    def test_repeated_rows_from_the_store_reach_the_engine_once(self, db):
        seed = db.seed_alert(1, -10)
        db.history_filter = lambda rows: rows + [dict(row) for row in rows]
        db.investigations = [_inv(1)]
        assert _verdicts(_run(db)) == [
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, seed.decision_id),
        ]

    def test_engine_receives_unique_sorted_decision_ids(self, db, monkeypatch):
        for n in range(6):
            db.seed_alert(n, -n - 1, key=_OTHER_KEYS[n % 4])
        db.history_filter = lambda rows: list(reversed(rows)) + rows
        db.investigations = [_inv(1)]
        seen = []
        real_decide = alert_evaluator.decide

        def spy(subject, history, evaluation, evaluated_at):
            seen.append(history)
            return real_decide(subject, history, evaluation, evaluated_at)

        monkeypatch.setattr(alert_evaluator, "decide", spy)
        _run(db)
        (history,) = seen
        ids = [alert.decision_id for alert in history]
        assert isinstance(history, tuple)
        assert len(ids) == len(set(ids)) == 6
        assert ids == sorted(ids)

    def test_merge_prefers_the_persisted_alert(self):
        from alert_engine import PriorAlert

        def alert(decision_id, severity):
            return PriorAlert(
                decision_id=decision_id, anomaly_id="a" * 64, dedup_key="b" * 64,
                event_time=_T0, severity=severity, decision=Decision.ALERT,
            )

        persisted = [alert("2" * 64, Severity.CRITICAL), alert("1" * 64, Severity.INFO)]
        hypothetical = [alert("2" * 64, Severity.INFO), alert("0" * 64, Severity.INFO)]
        merged = alert_evaluator._merge_history(persisted, hypothetical)
        assert [a.decision_id for a in merged] == ["0" * 64, "1" * 64, "2" * 64]
        assert merged[2].severity is Severity.CRITICAL

    def test_malformed_history_row_fails_only_that_candidate(self, db):
        db.seed_alert(1, -10)

        def corrupt(rows):
            return [dict(row, severity="SEVERE") for row in rows]

        db.history_filter = corrupt
        db.investigations = [_inv(1), _inv(2, 500, key=_OTHER_KEYS[0])]
        report = _run(db)
        assert report.results[0].status == STATUS_FAILURE
        assert "SEVERE" not in report.results[0].error
        assert report.results[1].status == STATUS_PERSISTED


# ---------------------------------------------------------------------------
# EV04  Same-run history (real run)
# ---------------------------------------------------------------------------

class TestSameRunHistory:

    def test_committed_alert_suppresses_a_later_candidate(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10)]
        report = _run(db)
        assert _verdicts(report) == [
            _ALERT,
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, _decision_id(1)),
        ]
        assert report.results[1].related_is_hypothetical is False

    def test_each_decision_is_committed_before_the_next_history_read(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10), _inv(3, 20)]
        _run(db)
        names = [event[0] for event in db.events]
        loop = names[names.index("fetch_candidates") + 2:]
        assert loop == ["fetch_alert_history", "insert_decision", "commit"] * 3

    def test_later_candidate_sees_only_committed_rows(self, db, monkeypatch):
        db.investigations = [_inv(1, 0), _inv(2, 10)]
        observed = []
        original = db.fetch_alert_history

        def watching(conn, **kwargs):
            observed.append((len(db.decisions), len(db._pending_decisions)))
            return original(conn, **kwargs)

        monkeypatch.setattr(alert_store, "fetch_alert_history", watching)
        _run(db)
        assert observed == [(0, 0), (1, 0)]

    def test_escalation_within_one_run(self, db):
        db.investigations = [_inv(1, 0, severity="WARNING"), _inv(2, 10, severity="CRITICAL")]
        report = _run(db)
        assert _verdicts(report)[1] == (
            Decision.ALERT, ReasonCode.ESCALATION, _decision_id(1),
        )

    def test_storm_cap_within_one_run(self, db):
        db.investigations = [
            _inv(n, n, key=key) for n, key in enumerate([_KEY, *_OTHER_KEYS[:3]])
        ]
        report = _run(db, _policy(max_alerts_per_hour=2))
        assert [v[1] for v in _verdicts(report)] == [
            ReasonCode.SEVERITY_MET, ReasonCode.SEVERITY_MET,
            ReasonCode.STORM_CAP, ReasonCode.STORM_CAP,
        ]

    def test_suppressed_decision_of_the_run_does_not_cool_down(self, db):
        # 2 is suppressed by 1; 3 falls outside 1's window and inside 2's.
        db.investigations = [_inv(1, 0), _inv(2, 10), _inv(3, 35)]
        report = _run(db, _policy(cooldown_minutes=30))
        assert [v[0] for v in _verdicts(report)] == [
            Decision.ALERT, Decision.SUPPRESSED, Decision.ALERT,
        ]


# ---------------------------------------------------------------------------
# EV05  Dry run
# ---------------------------------------------------------------------------

class TestDryRun:

    def test_writes_nothing_and_never_commits(self, db):
        db.seed_alert(1, -500)
        db.investigations = [_inv(n, n * 7) for n in range(6)]
        before = db.snapshot()
        report = _run(db, dry_run=True)
        assert db.snapshot() == before
        assert db.commits == 0
        assert db._pending_decisions == {} and db._pending_policies == {}
        assert report.total == 6
        assert report.dry_run is True

    def test_no_insert_function_is_called(self, db):
        db.investigations = [_inv(1), _inv(2, 10)]
        _run(db, dry_run=True)
        names = {event[0] for event in db.events}
        assert names == {
            "fetch_policy_sha256", "fetch_candidates", "fetch_alert_history",
            "rollback",
        }

    def test_every_candidate_ends_with_a_rollback(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 100)]
        _run(db, dry_run=True)
        names = [event[0] for event in db.events]
        loop = names[names.index("fetch_candidates") + 2:]
        assert loop == ["fetch_alert_history", "rollback"] * 2

    def test_status_is_dry_run(self, db):
        db.investigations = [_inv(1), _inv(2, 10), _inv(3, 20, severity="INFO")]
        report = _run(db, dry_run=True)
        assert {r.status for r in report.results} == {STATUS_DRY_RUN}

    def test_hypothetical_alert_affects_a_later_candidate(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10)]
        report = _run(db, dry_run=True)
        assert _verdicts(report) == [
            _ALERT,
            (Decision.SUPPRESSED, ReasonCode.COOLDOWN, _decision_id(1)),
        ]
        assert report.results[0].related_is_hypothetical is False
        assert report.results[1].related_is_hypothetical is True

    def test_hypothetical_alert_is_a_duplicate_source(self, db):
        shared = _hex("shared")
        db.investigations = [
            _inv(1, 0, anomaly=shared), _inv(2, 500, anomaly=shared, key=_OTHER_KEYS[0]),
        ]
        report = _run(db, dry_run=True)
        assert _verdicts(report)[1] == (
            Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, _decision_id(1),
        )

    def test_hypothetical_alerts_count_toward_the_storm_cap(self, db):
        db.investigations = [
            _inv(n, n, key=key) for n, key in enumerate([_KEY, *_OTHER_KEYS[:2]])
        ]
        report = _run(db, _policy(max_alerts_per_hour=2), dry_run=True)
        assert [v[1] for v in _verdicts(report)] == [
            ReasonCode.SEVERITY_MET, ReasonCode.SEVERITY_MET, ReasonCode.STORM_CAP,
        ]

    def test_hypothetical_suppressed_does_not_enter_history(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10), _inv(3, 35)]
        report = _run(db, _policy(cooldown_minutes=30), dry_run=True)
        assert [v[0] for v in _verdicts(report)] == [
            Decision.ALERT, Decision.SUPPRESSED, Decision.ALERT,
        ]

    def test_hypothetical_not_alertable_does_not_enter_history(self, db):
        db.investigations = [_inv(1, 0, severity="INFO"), _inv(2, 5)]
        report = _run(db, dry_run=True)
        assert _verdicts(report) == [
            (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None),
            _ALERT,
        ]

    def test_only_alerts_are_remembered(self, db, monkeypatch):
        db.investigations = [
            _inv(1, 0), _inv(2, 10), _inv(3, 20, severity="INFO"), _inv(4, 500),
        ]
        sizes = []
        real_decide = alert_evaluator.decide

        def spy(subject, history, evaluation, evaluated_at):
            sizes.append(len(history))
            return real_decide(subject, history, evaluation, evaluated_at)

        monkeypatch.setattr(alert_evaluator, "decide", spy)
        _run(db, dry_run=True)
        assert sizes == [0, 1, 1, 1]

    def test_persisted_and_hypothetical_history_are_combined(self, db):
        db.seed_alert(1, -10, key=_OTHER_KEYS[0])
        db.investigations = [_inv(1, 0), _inv(2, 5, key=_OTHER_KEYS[1])]
        report = _run(db, _policy(max_alerts_per_hour=2), dry_run=True)
        assert [v[1] for v in _verdicts(report)] == [
            ReasonCode.SEVERITY_MET, ReasonCode.STORM_CAP,
        ]

    def test_hypothetical_decision_id_is_the_real_identity(self, db):
        db.investigations = [_inv(1)]
        report = _run(db, dry_run=True)
        assert report.results[0].decision_id == _decision_id(1)

    def test_candidate_failure_is_reported_like_a_real_run(self, db):
        db.investigations = [_inv(1, severity="LOUD"), _inv(2, 5)]
        report = _run(db, dry_run=True)
        assert [r.status for r in report.results] == [STATUS_FAILURE, STATUS_DRY_RUN]
        assert report.succeeded is False

    def test_results_hold_no_summary(self, db):
        db.investigations = [_inv(1, summary="TOP-SECRET-SUMMARY")]
        report = _run(db, _policy(persist_summary=True), dry_run=True)
        assert "TOP-SECRET-SUMMARY" not in repr(report)
        assert "summary" not in {f.name for f in dataclasses.fields(EvaluationResult)}

    def test_running_twice_gives_the_same_report(self, db):
        db.investigations = [_inv(n, n * 9, key=_OTHER_KEYS[n % 4]) for n in range(10)]
        policy = _policy(max_alerts_per_hour=3)
        assert _run(db, policy, dry_run=True) == _run(db, policy, dry_run=True)


# ---------------------------------------------------------------------------
# EV06  Dry run equals a real sequential run
# ---------------------------------------------------------------------------

def _random_state(seed: int):
    rng = random.Random(seed)
    keys = [_KEY, *_OTHER_KEYS]
    severities = ["INFO", "WARNING", "WARNING", "CRITICAL"]
    anomalies = [_hex(f"random-anomaly-{seed}-{i}") for i in range(14)]

    fake = FakeDb()
    for n in range(rng.randint(0, 6)):
        fake.seed_alert(
            f"{seed}-{n}", rng.randint(-200, 260), key=rng.choice(keys),
            severity=rng.choice(severities), anomaly=rng.choice(anomalies),
            version=rng.choice(["0.8.0", "0.9.0"]),
        )
    fake.investigations = [
        _inv(
            f"{seed}-{n}", rng.choice([0, 5, 10, 30, 31, 60, 61, 90, 120, 180, 181, 240]),
            severity=rng.choice(severities), key=rng.choice(keys),
            anomaly=rng.choice(anomalies),
            confidence=rng.choice([c.value for c in Confidence]),
        )
        for n in range(rng.randint(8, 24))
    ]
    policy = _policy(
        cooldown_minutes=rng.choice([0, 30, 90, 180]),
        max_alerts_per_hour=rng.choice([1, 2, 3, 10]),
        escalation_breaks_cooldown=rng.choice([True, False]),
        min_severity=rng.choice(["INFO", "WARNING", "CRITICAL"]),
        max_alert_age_minutes=rng.choice([60, _NEVER_STALE]),
        enabled=rng.random() > 0.05,
    )
    return fake, policy


class TestDryRunEqualsRealRun:

    @pytest.mark.parametrize("seed", range(60))
    def test_same_verdicts_from_the_same_initial_state(self, monkeypatch, seed):
        template, policy = _random_state(seed)
        evaluated_at = _at(200)

        dry_db = template.clone()
        _install(monkeypatch, dry_db)
        before = dry_db.snapshot()
        dry = _run(dry_db, policy, evaluated_at=evaluated_at, dry_run=True)
        assert dry_db.snapshot() == before

        real_db = template.clone()
        _install(monkeypatch, real_db)
        real = _run(real_db, policy, evaluated_at=evaluated_at)

        assert [r.investigation_id for r in dry.results] == [
            r.investigation_id for r in real.results
        ]
        assert [r.decision_id for r in dry.results] == [
            r.decision_id for r in real.results
        ]
        assert _verdicts(dry) == _verdicts(real)
        assert {r.status for r in real.results} <= {STATUS_PERSISTED}
        assert {r.status for r in dry.results} <= {STATUS_DRY_RUN}
        assert (dry.alerts, dry.suppressed, dry.not_alertable) == (
            real.alerts, real.suppressed, real.not_alertable,
        )

    def test_the_generated_cases_exercise_every_reason(self, monkeypatch):
        reasons = set()
        for seed in range(60):
            fake, policy = _random_state(seed)
            _install(monkeypatch, fake)
            report = _run(fake, policy, evaluated_at=_at(200), dry_run=True)
            reasons.update(r.reason_code for r in report.results)
        assert reasons == set(ReasonCode)


# ---------------------------------------------------------------------------
# EV07  Persistence and first-write-wins
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_stored_record_fields(self, db):
        row = _inv(
            1, 3, severity="CRITICAL", confidence="LOW",
            limitations=("no baseline", "short trace"),
        )
        db.investigations = [row]
        _run(db, evaluated_at=_at(9))
        (stored,) = db.decisions.values()
        assert stored.decision_id == compute_decision_id(row["investigation_id"], _VERSION)
        assert stored.investigation_id == row["investigation_id"]
        assert stored.policy_version == _VERSION
        assert stored.anomaly_id == row["anomaly_id"]
        assert (stored.anomaly_type, stored.service_name, stored.operation_name) == _KEY
        assert stored.event_time == _at(3)
        assert stored.severity is Severity.CRITICAL
        assert stored.confidence is Confidence.LOW
        assert stored.limitations == ("no baseline", "short trace")
        assert stored.dedup_key == compute_dedup_key(*_KEY)
        assert stored.decision is Decision.ALERT
        assert stored.reason_code is ReasonCode.SEVERITY_MET
        assert stored.related_decision_id is None
        assert stored.evaluated_at == _at(9)
        assert stored.summary is None and stored.summary_truncated is False

    def test_decision_id_has_no_time_or_random_component(self, db, monkeypatch):
        db.investigations = [_inv(1)]
        first = _run(db, evaluated_at=_at(1), dry_run=True).results[0].decision_id
        second = _run(db, evaluated_at=_at(50), dry_run=True).results[0].decision_id
        assert first == second == _decision_id(1)

    def test_identity_functions_are_the_locked_ones(self):
        import alert_identity
        assert alert_evaluator.compute_decision_id is alert_identity.compute_decision_id
        source = inspect.getsource(alert_evaluator)
        assert "hashlib" not in source and "hexdigest" not in source

    def test_none_service_and_operation_are_kept(self, db):
        db.investigations = [_inv(1, key=("latency", None, None))]
        _run(db)
        (stored,) = db.decisions.values()
        assert stored.service_name is None and stored.operation_name is None
        assert stored.dedup_key == compute_dedup_key("latency", None, None)

    def test_related_decision_is_stored_for_cooldown(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10)]
        _run(db)
        assert db.decisions[_decision_id(2)].related_decision_id == _decision_id(1)

    def test_one_commit_per_decision_plus_registration(self, db):
        db.investigations = [_inv(n, n * 100) for n in range(5)]
        _run(db)
        assert db.commits == 1 + 5
        assert len(db.decisions) == 5

    def test_connection_is_never_closed(self, db):
        db.investigations = [_inv(1)]
        _run(db)
        assert db.closes == 0

    def test_rerun_writes_nothing_new(self, db):
        db.investigations = [_inv(n, n * 7) for n in range(6)]
        _run(db)
        before = db.snapshot()
        report = _run(db, evaluated_at=_at(999))
        assert report.total == 0
        assert db.snapshot() == before

    # -- first-write-wins ---------------------------------------------------

    def test_lost_race_at_insert_is_already_decided(self, db):
        db.investigations = [_inv(1, severity="CRITICAL")]
        winner = AlertDecision(
            decision_id=_decision_id(1),
            investigation_id=_hex("investigation-1"),
            policy_version=_VERSION,
            anomaly_id=_hex("anomaly-1"),
            anomaly_type="latency", service_name="svc", operation_name="op",
            event_time=_at(0), severity=Severity.CRITICAL,
            confidence=Confidence.HIGH, limitations=(),
            dedup_key=compute_dedup_key(*_KEY),
            decision=Decision.SUPPRESSED, reason_code=ReasonCode.STORM_CAP,
            related_decision_id=None, evaluated_at=_at(-1), payload=None,
        )

        def other_writer(decision):
            db.decisions[winner.decision_id] = winner
            db.before_insert = None

        db.before_insert = other_writer
        report = _run(db)
        (result,) = report.results
        assert result.status == STATUS_ALREADY_DECIDED
        assert result.decision_id == _decision_id(1)
        assert (result.decision, result.reason_code, result.error) == (None, None, None)
        assert db.decisions[_decision_id(1)] is winner
        assert report.succeeded is True
        assert report.already_decided == 1 and report.alerts == 0

    def test_lost_race_does_not_stop_the_batch(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 500)]

        def other_writer(decision):
            if decision.decision_id == _decision_id(1):
                db.decisions[decision.decision_id] = decision

        db.before_insert = other_writer
        report = _run(db)
        assert [r.status for r in report.results] == [
            STATUS_ALREADY_DECIDED, STATUS_PERSISTED,
        ]

    def test_own_decision_already_in_history_is_already_decided(self, db):
        # Another writer stored this investigation's ALERT after discovery.
        db.investigations = [_inv(1)]
        own = _decision_id(1)

        def with_own_decision(rows):
            return rows + [{
                "decision_id": own, "anomaly_id": _hex("anomaly-1"),
                "dedup_key": compute_dedup_key(*_KEY), "event_time": _at(0),
                "severity": "WARNING", "decision": "ALERT",
            }]

        db.history_filter = with_own_decision
        report = _run(db)
        assert report.results[0].status == STATUS_ALREADY_DECIDED
        assert "insert_decision" not in {event[0] for event in db.events}
        assert report.succeeded is True

    def test_evaluator_source_never_updates_or_deletes(self):
        tree = ast.parse(inspect.getsource(alert_evaluator))
        store_calls = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "alert_store"
        }
        assert store_calls == set(_STORE_FUNCTIONS)


# ---------------------------------------------------------------------------
# EV08  Failure model
# ---------------------------------------------------------------------------

_MALFORMED = {
    "investigation_id not a digest": {"investigation_id": "not-a-digest"},
    "investigation_id None": {"investigation_id": None},
    "anomaly_id None": {"anomaly_id": None},
    "anomaly_id upper case": {"anomaly_id": "A" * 64},
    "anomaly_type empty": {"anomaly_type": ""},
    "anomaly_type None": {"anomaly_type": None},
    "service_name not text": {"service_name": 5},
    "operation_name not text": {"operation_name": b"op"},
    "event_time naive": {"event_time": datetime(2026, 10, 5, 19, 0)},
    "event_time text": {"event_time": "2026-10-05T19:00:00Z"},
    "event_time None": {"event_time": None},
    "severity unknown": {"severity": "FATAL"},
    "severity None": {"severity": None},
    "confidence unknown": {"confidence": "CERTAIN"},
    "confidence None": {"confidence": None},
    "limitations None": {"limitations": None},
    "limitations text": {"limitations": "one"},
    "limitations holds a non-text item": {"limitations": ["ok", None]},
    "summary not text": {"summary": 123},
}


class TestFailureModel:

    @pytest.mark.parametrize("label", sorted(_MALFORMED))
    def test_malformed_candidate_is_a_failure_and_the_batch_continues(self, db, label):
        bad = dict(_inv(1, 0), **_MALFORMED[label])
        good = _inv(2, 500, key=_OTHER_KEYS[0])
        db.investigations = [bad, good]
        report = _run(db)
        by_status = {r.status: r for r in report.results}
        assert set(by_status) == {STATUS_FAILURE, STATUS_PERSISTED}
        failure = by_status[STATUS_FAILURE]
        assert failure.error.startswith("ValueError: ")
        assert (failure.decision, failure.reason_code, failure.decision_id) == (
            None, None, None,
        )
        assert by_status[STATUS_PERSISTED].investigation_id == good["investigation_id"]
        assert list(db.decisions) == [_decision_id(2)]
        assert report.failures == 1 and report.succeeded is False

    def test_failed_candidate_is_rolled_back(self, db):
        db.investigations = [_inv(1, severity="FATAL")]
        _run(db)
        assert db.events[-1] == ("rollback",)
        assert db._pending_decisions == {}

    def test_failed_candidate_stays_undecided_and_is_retried(self, db):
        db.investigations = [_inv(1, severity="FATAL"), _inv(2, 500)]
        _run(db)
        report = _run(db)
        assert [r.status for r in report.results] == [STATUS_FAILURE]

    def test_failure_keeps_the_stored_investigation_id(self, db):
        db.investigations = [dict(_inv(1), confidence="CERTAIN")]
        (result,) = _run(db).results
        assert result.investigation_id == _hex("investigation-1")

    def test_error_text_does_not_quote_stored_values(self, db):
        db.investigations = [
            dict(_inv(1, summary="PRIVATE-SUMMARY-TEXT"), confidence="PRIVATE-VALUE"),
        ]
        (result,) = _run(db, _policy(persist_summary=True)).results
        assert "PRIVATE" not in result.error

    def test_several_failures_are_all_recorded(self, db):
        db.investigations = [
            _inv(1, 0, severity="X"), _inv(2, 100), _inv(3, 200, confidence="Y"),
            _inv(4, 300),
        ]
        report = _run(db)
        assert [r.status for r in report.results] == [
            STATUS_FAILURE, STATUS_PERSISTED, STATUS_FAILURE, STATUS_PERSISTED,
        ]
        assert report.failures == 2

    @pytest.mark.parametrize("function", [
        "fetch_alert_history", "insert_decision", "commit",
    ])
    def test_database_error_stops_the_run(self, db, function):
        db.investigations = [_inv(1, 0), _inv(2, 500), _inv(3, 1000)]
        # commit: call 1 is the policy registration.
        on_call = 3 if function == "commit" else 2
        db.fail(function, psycopg.OperationalError("down"), on_call=on_call)
        with pytest.raises(psycopg.OperationalError):
            _run(db)
        assert list(db.decisions) == [_decision_id(1)]
        assert db.events[-1] == ("rollback",)
        assert db._pending_decisions == {}
        assert ("fetch_alert_history", _hex("anomaly-3")) not in db.events

    def test_integrity_error_is_not_treated_as_a_candidate_failure(self, db):
        db.investigations = [_inv(1), _inv(2, 500)]
        db.fail("insert_decision", psycopg.IntegrityError("check violated"))
        with pytest.raises(psycopg.IntegrityError):
            _run(db)
        assert db.decisions == {}

    def test_unexpected_error_is_not_swallowed(self, db):
        db.investigations = [_inv(1)]
        db.fail("fetch_alert_history", AssertionError("bug"))
        with pytest.raises(AssertionError):
            _run(db)
        assert db.events[-1] == ("rollback",)

    def test_keyboard_interrupt_propagates(self, db):
        db.investigations = [_inv(1), _inv(2, 500)]
        db.fail("fetch_alert_history", KeyboardInterrupt(), on_call=2)
        with pytest.raises(KeyboardInterrupt):
            _run(db)
        assert list(db.decisions) == [_decision_id(1)]

    def test_wrong_policy_type_is_rejected_before_the_database_is_used(self, db):
        with pytest.raises(ValueError, match="AlertPolicy"):
            run_evaluation(db, _policy().evaluation, evaluated_at=_T0)
        assert db.events == []


# ---------------------------------------------------------------------------
# EV09  Payload
# ---------------------------------------------------------------------------

_FORBIDDEN_PAYLOAD_KEYS = {
    "summary", "summary_truncated", "related_decision_id", "decision",
    "evidence", "error_message", "explanation", "trace_id", "span_id",
    "attributes", "telemetry", "embedding", "similarity", "channel",
    "webhook", "url", "token", "dedup_key", "decided_at",
}


class TestPayload:

    def _stored(self, db, **inv):
        db.investigations = [_inv(1, 3, **inv)]
        _run(db, evaluated_at=_at(9))
        return db.decisions[_decision_id(1)]

    def test_exact_keys_in_contract_order(self, db):
        payload = self._stored(db).payload
        assert list(payload) == _PAYLOAD_KEYS
        assert len(payload) == 15

    def test_values(self, db):
        payload = dict(self._stored(
            db, severity="CRITICAL", confidence="INSUFFICIENT_DATA",
            limitations=("no trace",),
        ).payload)
        assert payload == {
            "payload_version": PAYLOAD_VERSION,
            "decision_id": _decision_id(1),
            "investigation_id": _hex("investigation-1"),
            "anomaly_id": _hex("anomaly-1"),
            "anomaly_type": "latency",
            "service_name": "svc",
            "operation_name": "op",
            "event_time": "2026-10-05T19:03:00.000000Z",
            "evaluated_at": "2026-10-05T19:09:00.000000Z",
            "severity": "CRITICAL",
            "confidence": "INSUFFICIENT_DATA",
            "limitations": ["no trace"],
            "reason_code": "severity_met",
            "policy_version": _VERSION,
            "advisory": ADVISORY,
        }

    def test_advisory_is_the_frozen_sentence(self):
        assert ADVISORY == (
            "Automated detection. Advisory only; no action has been taken. "
            "RCA confidence describes evidence quality, not cause."
        )

    def test_payload_version_is_the_locked_constant(self, db):
        assert self._stored(db).payload["payload_version"] == "1.0.0"

    def test_payload_is_json_serialisable_plain_data(self, db):
        payload = dict(self._stored(db, limitations=("a", "b")).payload)
        assert json.loads(json.dumps(payload)) == payload
        assert type(payload["limitations"]) is list

    def test_none_service_and_operation_are_null(self, db):
        payload = self._stored(db, key=("latency", None, None)).payload
        assert payload["service_name"] is None and payload["operation_name"] is None

    def test_timestamps_are_utc_for_a_non_utc_event_time(self, db):
        zone = timezone(timedelta(hours=-7))
        local = datetime(2026, 10, 5, 12, 0, 0, 123, tzinfo=zone)
        payload = self._stored(db, event_time=local).payload
        assert payload["event_time"] == "2026-10-05T19:00:00.000123Z"

    def test_no_forbidden_field(self, db):
        payload = self._stored(db, summary="PRIVATE-SUMMARY").payload
        assert _FORBIDDEN_PAYLOAD_KEYS.isdisjoint(payload)
        assert "PRIVATE-SUMMARY" not in json.dumps(dict(payload))

    def test_summary_is_never_in_the_payload_even_when_persisted(self, db):
        db.investigations = [_inv(1, summary="PRIVATE-SUMMARY")]
        _run(db, _policy(persist_summary=True))
        stored = db.decisions[_decision_id(1)]
        assert stored.summary == "PRIVATE-SUMMARY"
        assert "PRIVATE-SUMMARY" not in json.dumps(dict(stored.payload))
        assert "summary" not in stored.payload

    def test_escalation_payload_does_not_name_the_related_decision(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10, severity="CRITICAL")]
        _run(db)
        stored = db.decisions[_decision_id(2)]
        assert stored.related_decision_id == _decision_id(1)
        assert list(stored.payload) == _PAYLOAD_KEYS
        assert stored.payload["reason_code"] == "escalation"
        assert _decision_id(1) not in json.dumps(dict(stored.payload))

    @pytest.mark.parametrize("inv, policy_kwargs, decision", [
        (dict(severity="INFO"), {}, Decision.NOT_ALERTABLE),
        ({}, dict(enabled=False), Decision.SUPPRESSED),
    ])
    def test_non_alert_has_no_payload(self, db, inv, policy_kwargs, decision):
        db.investigations = [_inv(1, **inv)]
        _run(db, _policy(**policy_kwargs))
        stored = db.decisions[_decision_id(1)]
        assert stored.decision is decision
        assert stored.payload is None

    def test_cooldown_suppressed_has_no_payload(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10)]
        _run(db)
        assert db.decisions[_decision_id(1)].payload is not None
        assert db.decisions[_decision_id(2)].payload is None

    def test_build_payload_is_keyword_only_and_pure(self):
        kwargs = dict(
            decision_id="d" * 64, investigation_id="i" * 64, anomaly_id="a" * 64,
            anomaly_type="latency", service_name=None, operation_name=None,
            event_time=_T0, evaluated_at=_T0, severity=Severity.WARNING,
            confidence=Confidence.HIGH, limitations=("x",),
            reason_code=ReasonCode.SEVERITY_MET, policy_version=_VERSION,
        )
        assert build_payload(**kwargs) == build_payload(**kwargs)
        with pytest.raises(TypeError):
            build_payload(*kwargs.values())
        assert set(inspect.signature(build_payload).parameters) == set(_PAYLOAD_KEYS) - {
            "payload_version", "advisory",
        }


class TestFormatTimestamp:

    @pytest.mark.parametrize("value, expected", [
        (datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc),
         "2026-10-05T19:00:00.000000Z"),
        (datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=timezone.utc),
         "2026-01-02T03:04:05.000006Z"),
        (datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
         "2026-12-31T23:59:59.999999Z"),
        (datetime(2026, 10, 6, 0, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
         "2026-10-05T19:00:00.000000Z"),
        (datetime(2026, 10, 5, 12, 0, tzinfo=timezone(timedelta(hours=-7))),
         "2026-10-05T19:00:00.000000Z"),
        (datetime(987, 6, 5, 4, 3, 2, 1, tzinfo=timezone.utc),
         "0987-06-05T04:03:02.000001Z"),
    ])
    def test_format(self, value, expected):
        assert format_timestamp(value) == expected

    def test_shape_is_fixed(self):
        text = format_timestamp(_T0)
        assert len(text) == 27
        assert text.endswith("Z") and "+" not in text

    @pytest.mark.parametrize("value", [
        datetime(2026, 10, 5, 19, 0), "2026-10-05T19:00:00Z", None, 0,
    ])
    def test_rejects_anything_but_an_aware_datetime(self, value):
        with pytest.raises(ValueError):
            format_timestamp(value)


# ---------------------------------------------------------------------------
# EV10  Summary
# ---------------------------------------------------------------------------

class TestSummary:

    def test_limit_is_two_thousand_code_points(self):
        assert SUMMARY_MAX_CODE_POINTS == 2000

    def test_not_persisted_by_default(self):
        assert persisted_summary("text", Decision.ALERT, False) == (None, False)

    def test_persisted_for_an_alert(self):
        assert persisted_summary("text", Decision.ALERT, True) == ("text", False)

    def test_empty_summary_is_kept(self):
        assert persisted_summary("", Decision.ALERT, True) == ("", False)

    def test_exactly_at_the_limit_is_not_cut(self):
        source = "x" * 2000
        assert persisted_summary(source, Decision.ALERT, True) == (source, False)

    def test_one_over_the_limit_is_cut(self):
        source = "x" * 1999 + "yz"
        assert persisted_summary(source, Decision.ALERT, True) == ("x" * 1999 + "y", True)

    @pytest.mark.parametrize("char", ["é", "漢", "\U0001F600", "\U0001F1EF"])
    def test_limit_counts_code_points_not_bytes(self, char):
        source = char * 2000
        assert len(source.encode("utf-8")) > 2000
        assert persisted_summary(source, Decision.ALERT, True) == (source, False)
        stored, cut = persisted_summary(source + char, Decision.ALERT, True)
        assert cut is True
        assert stored == source and len(stored) == 2000

    def test_cut_keeps_the_first_code_points(self):
        source = "".join(chr(0x4E00 + (i % 500)) for i in range(2500))
        stored, cut = persisted_summary(source, Decision.ALERT, True)
        assert (stored, cut) == (source[:2000], True)
        stored.encode("utf-8")

    def test_none_source(self):
        assert persisted_summary(None, Decision.ALERT, True) == (None, False)

    @pytest.mark.parametrize("decision", [Decision.SUPPRESSED, Decision.NOT_ALERTABLE])
    @pytest.mark.parametrize("persist", [True, False])
    def test_never_for_a_non_alert(self, decision, persist):
        assert persisted_summary("x" * 5000, decision, persist) == (None, False)

    @pytest.mark.parametrize("persist", [True, False])
    def test_non_text_source_is_rejected(self, persist):
        with pytest.raises(ValueError):
            persisted_summary(123, Decision.ALERT, persist)

    # -- through a run ------------------------------------------------------

    def test_run_with_persist_summary_false(self, db):
        db.investigations = [_inv(1, summary="text")]
        _run(db, _policy(persist_summary=False))
        stored = db.decisions[_decision_id(1)]
        assert (stored.summary, stored.summary_truncated) == (None, False)

    def test_run_with_persist_summary_true(self, db):
        db.investigations = [_inv(1, summary="text")]
        _run(db, _policy(persist_summary=True))
        stored = db.decisions[_decision_id(1)]
        assert (stored.summary, stored.summary_truncated) == ("text", False)

    def test_run_cuts_a_long_summary(self, db):
        db.investigations = [_inv(1, summary="\U0001F600" * 2001)]
        _run(db, _policy(persist_summary=True))
        stored = db.decisions[_decision_id(1)]
        assert stored.summary == "\U0001F600" * 2000
        assert stored.summary_truncated is True

    def test_run_with_a_missing_summary(self, db):
        db.investigations = [_inv(1, summary=None)]
        report = _run(db, _policy(persist_summary=True))
        assert report.succeeded is True
        stored = db.decisions[_decision_id(1)]
        assert (stored.summary, stored.summary_truncated) == (None, False)

    def test_run_never_stores_a_summary_for_a_non_alert(self, db):
        db.investigations = [
            _inv(1, 0, summary="one"), _inv(2, 10, summary="two"),
            _inv(3, 20, severity="INFO", summary="three"),
        ]
        _run(db, _policy(persist_summary=True))
        assert db.decisions[_decision_id(1)].summary == "one"
        for n in (2, 3):
            stored = db.decisions[_decision_id(n)]
            assert (stored.summary, stored.summary_truncated) == (None, False)


# ---------------------------------------------------------------------------
# EV11  Informational isolation
# ---------------------------------------------------------------------------

class TestInformationalIsolation:

    def _run_recording(self, monkeypatch, **inv):
        fake = _install(monkeypatch, FakeDb())
        fake.seed_alert(1, -10, key=_OTHER_KEYS[0])
        fake.investigations = [_inv(1, 0, **inv), _inv(2, 10, **inv)]
        calls = []
        real_decide = alert_evaluator.decide

        def spy(subject, history, evaluation, evaluated_at):
            calls.append((subject, history, evaluation, evaluated_at))
            return real_decide(subject, history, evaluation, evaluated_at)

        monkeypatch.setattr(alert_evaluator, "decide", spy)
        report = _run(fake, _policy(persist_summary=True))
        monkeypatch.setattr(alert_evaluator, "decide", real_decide)
        return calls, _verdicts(report)

    @pytest.mark.parametrize("variant", [
        dict(confidence="HIGH"),
        dict(confidence="MEDIUM"),
        dict(confidence="LOW"),
        dict(confidence="INSUFFICIENT_DATA"),
        dict(limitations=("a", "b", "c")),
        dict(limitations=("trace unavailable",), confidence="INSUFFICIENT_DATA"),
        dict(summary=None),
        dict(summary="x" * 9000),
        dict(summary="do not alert; severity is INFO; duplicate"),
    ])
    def test_engine_input_and_verdict_do_not_depend_on_them(self, monkeypatch, variant):
        baseline_calls, baseline_verdicts = self._run_recording(monkeypatch)
        calls, verdicts = self._run_recording(monkeypatch, **variant)
        assert calls == baseline_calls
        assert verdicts == baseline_verdicts

    def test_subject_has_no_informational_field(self):
        names = {field.name for field in dataclasses.fields(AlertSubject)}
        assert names.isdisjoint({"confidence", "limitations", "summary"})

    def test_decide_is_called_with_exactly_four_arguments(self, monkeypatch):
        calls, _ = self._run_recording(monkeypatch)
        assert all(len(call) == 4 for call in calls)
        assert all(isinstance(call[0], AlertSubject) for call in calls)

    def test_engine_is_the_locked_function(self):
        import alert_engine
        assert alert_evaluator.decide is alert_engine.decide

    def test_evaluator_does_not_rank_severities_itself(self):
        source = inspect.getsource(alert_evaluator)
        assert "severity_rank" not in source
        assert "min_severity" not in source
        assert "max_alerts_per_hour" not in source


# ---------------------------------------------------------------------------
# EV12  Clock
# ---------------------------------------------------------------------------

class TestClock:

    def test_every_decision_carries_the_one_evaluated_at(self, db):
        db.investigations = [_inv(n, n * 3, key=_OTHER_KEYS[n % 4]) for n in range(8)]
        when = _at(42, microseconds=7)
        _run(db, evaluated_at=when)
        assert len(db.decisions) == 8
        assert {d.evaluated_at for d in db.decisions.values()} == {when}
        assert {
            d.payload["evaluated_at"] for d in db.decisions.values() if d.payload
        } == {"2026-10-05T19:42:00.000007Z"}

    def test_engine_receives_the_same_value_for_every_candidate(self, db, monkeypatch):
        db.investigations = [_inv(n, n * 100) for n in range(4)]
        seen = []
        real_decide = alert_evaluator.decide

        def spy(subject, history, evaluation, evaluated_at):
            seen.append(evaluated_at)
            return real_decide(subject, history, evaluation, evaluated_at)

        monkeypatch.setattr(alert_evaluator, "decide", spy)
        _run(db, evaluated_at=_at(5))
        assert seen == [_at(5)] * 4
        assert all(value is seen[0] for value in seen)

    def test_non_utc_value_is_normalised_to_utc(self, db):
        db.investigations = [_inv(1)]
        local = _at(5).astimezone(timezone(timedelta(hours=9)))
        _run(db, evaluated_at=local)
        (stored,) = db.decisions.values()
        assert stored.evaluated_at == _at(5)
        assert stored.evaluated_at.tzinfo is timezone.utc

    @pytest.mark.parametrize("value", [
        datetime(2026, 10, 5, 19, 0), None, "2026-10-05T19:00:00Z", 1_700_000_000,
    ])
    def test_invalid_value_is_rejected_before_the_database_is_used(self, db, value):
        with pytest.raises(ValueError, match="evaluated_at"):
            run_evaluation(db, _policy(), evaluated_at=value)
        assert db.events == []

    def test_evaluated_at_is_required_and_keyword_only(self, db):
        parameter = inspect.signature(run_evaluation).parameters["evaluated_at"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
        with pytest.raises(TypeError):
            run_evaluation(db, _policy())

    def test_module_reads_no_clock(self):
        tree = ast.parse(inspect.getsource(alert_evaluator))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        forbidden = {"now", "utcnow", "today", "time", "monotonic", "perf_counter"}
        assert forbidden.isdisjoint(names | attributes)

    def test_stale_decision_depends_only_on_the_injected_time(self, db):
        db.investigations = [_inv(1, 0)]
        policy = _policy(max_alert_age_minutes=60)
        fresh = _run(db, policy, evaluated_at=_at(60), dry_run=True)
        stale = _run(db, policy, evaluated_at=_at(60, microseconds=1), dry_run=True)
        assert fresh.results[0].decision is Decision.ALERT
        assert stale.results[0].reason_code is ReasonCode.STALE


# ---------------------------------------------------------------------------
# EV13  Report and callback
# ---------------------------------------------------------------------------

class TestReport:

    def test_counts(self, db):
        db.investigations = [
            _inv(1, 0), _inv(2, 10), _inv(3, 20, severity="INFO"),
            _inv(4, 500, severity="BAD"), _inv(5, 900),
        ]
        report = _run(db)
        assert report.total == 5
        assert (report.alerts, report.suppressed, report.not_alertable) == (2, 1, 1)
        assert report.failures == 1 and report.already_decided == 0
        assert report.count(STATUS_PERSISTED) == 4
        assert report.succeeded is False
        assert report.dry_run is False

    def test_statuses_are_known(self, db):
        db.investigations = [_inv(1), _inv(2, 10, severity="BAD")]
        for dry_run in (True, False):
            report = _run(db, dry_run=dry_run)
            assert {r.status for r in report.results} <= EVALUATION_STATUSES
        assert EVALUATION_STATUSES == {
            "persisted", "already_decided", "dry_run", "failure",
        }

    def test_results_and_report_are_immutable(self, db):
        db.investigations = [_inv(1)]
        report = _run(db)
        assert isinstance(report.results, tuple)
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.dry_run = True
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.results[0].status = "x"

    def test_callback_receives_each_result_in_order_as_it_is_known(self, db):
        db.investigations = [_inv(1, 0), _inv(2, 10), _inv(3, 20, severity="BAD")]
        seen = []

        def on_result(result):
            seen.append((result, len(db.decisions)))

        report = _run(db, on_result=on_result)
        assert tuple(result for result, _ in seen) == report.results
        assert [count for _, count in seen] == [1, 2, 2]

    def test_callback_is_optional(self, db):
        db.investigations = [_inv(1)]
        assert _run(db, on_result=None).total == 1


# ---------------------------------------------------------------------------
# EV14  Module boundaries
# ---------------------------------------------------------------------------

_ALLOWED_IMPORTS = {
    "__future__", "dataclasses", "datetime", "typing",
    "alert_store", "alert_engine", "alert_identity", "alert_models",
    "alert_policy", "alert_version",
}

_FORBIDDEN_ROOTS = {
    "psycopg", "psycopg2", "sqlite3", "socket", "ssl", "http", "urllib",
    "requests", "httpx", "smtplib", "subprocess", "logging", "os", "sys",
    "json", "time", "random", "threading", "asyncio",
    # Phase 12 and other components
    "embedding_store", "embedding_pipeline", "embedding_provider",
    "similarity_search", "historical_context", "incident_document",
    "sentence_transformer_backend", "retrieval_db", "rca_db", "rca_persist",
}


class TestModuleBoundaries:

    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(alert_evaluator))

    def _imported(self, tree) -> set[str]:
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        return imported

    def test_imports_are_exactly_the_allowed_set(self, tree):
        assert self._imported(tree) == _ALLOWED_IMPORTS

    def test_no_forbidden_module(self, tree):
        roots = {name.split(".")[0] for name in self._imported(tree)}
        assert roots.isdisjoint(_FORBIDDEN_ROOTS)

    def test_imports_are_all_at_module_level(self, tree):
        nested = [
            node for scope in ast.walk(tree)
            if isinstance(scope, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
            for node in ast.walk(scope)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert nested == []

    def test_no_statement_text_and_no_driver(self):
        source = inspect.getsource(alert_evaluator)
        for word in ("psycopg", "SELECT", "INSERT", "UPDATE", "DELETE",
                     "ON CONFLICT", "execute(", "cursor("):
            assert word not in source, word

    def test_no_file_network_or_output(self, tree):
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert names.isdisjoint({"open", "print", "input", "exec", "eval", "__import__"})

    def test_connection_is_only_committed_or_rolled_back(self, tree):
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "conn"
        }
        assert used == {"commit", "rollback"}

    def test_no_notification_or_guardrail_names(self):
        source = inspect.getsource(alert_evaluator).lower()
        for word in ("webhook", "deliveryattempt", "channelconfig", "guardrail",
                     "attempt_id", "embedding", "similar"):
            assert word not in source, word

    def test_public_names(self):
        for name in (
            "ADVISORY", "SUMMARY_MAX_CODE_POINTS", "STATUS_PERSISTED",
            "STATUS_ALREADY_DECIDED", "STATUS_DRY_RUN", "STATUS_FAILURE",
            "EVALUATION_STATUSES", "POLICY_REGISTERED",
            "POLICY_ALREADY_REGISTERED", "POLICY_NOT_REGISTERED",
            "PolicyVersionConflictError", "format_timestamp", "build_payload",
            "persisted_summary", "EvaluationResult", "EvaluationReport",
            "run_evaluation",
        ):
            assert hasattr(alert_evaluator, name), name
