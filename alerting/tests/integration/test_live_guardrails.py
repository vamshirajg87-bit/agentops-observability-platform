"""
alerting/tests/integration/test_live_guardrails.py

Opt-in integration test of the operational guardrails against live PostgreSQL
(Phase 13.6).  It checks what mocks cannot: the four SELECT statements
themselves, the lookback pre-filter in SQL, the column-level privileges of
the alert_evaluator role, and that a run writes nothing.

This is not the Phase 13 live end-to-end test.  It sends nothing, delivers no
notification, runs no migration, and uses no network other than the database
connection.

Skipped by default.  It runs only when the switch is set:

    ALERTING_RUN_DB_TESTS=1

and an administrator password is supplied through the environment:

    ALERTING_E2E_ADMIN_PASSWORD   required; there is no default
    ALERTING_E2E_ADMIN_USER       default: agentops

Host, port and database come from ALERT_EVALUATOR_DB_HOST / _PORT / _NAME
(defaults localhost / 5432 / agentops).  The alert_evaluator password is NOT
needed.  Migrations 012 and 013 must be applied.

Nothing is ever committed
-------------------------
The whole module runs inside ONE transaction on ONE administrator connection,
and that transaction is rolled back when the module finishes:

  1. Record baseline row counts.
  2. Insert fixture checkpoints, anomalies, investigations, a policy version,
     decisions, attempts and outcomes as the administrator.
  3. SET LOCAL ROLE alert_evaluator.  From here on every statement is
     permission-checked as the restricted role.
  4. Run the real guardrails and store on this same connection.
  5. ROLLBACK, then require the counts to equal the baseline.

The guardrails never commit or roll back, so they are given the connection
itself.  Statements that are expected to be refused run inside a savepoint.

Fixtures
--------
Every fixture time lies in an isolated period (2001-03-01) and the run is
given a `now` in that period.  Seen from there, every real row of the
database is dated in the future, which no guardrail reports; real alerts
have no attempt on the fixture channel.  The findings are therefore exactly
the fixtures.  The module is skipped when the database holds rows dated
before the fixture period ends.  No DELETE, TRUNCATE, or reset is used
anywhere.

The fixture SQL below exists only in this test.  Production SQL lives only in
alert_guardrail_store.py.

Test inventory:
    G01  the statements run as the restricted role
    G02  restricted-role privileges are enforced
    G03  S1 checkpoints
    G04  S2 anomalies without an investigation
    G05  S3 ALERT decisions in or near the lookback
    G06  S4 delivery history
    G07  run_guardrails: all four findings
    G08  no enabled channel
    G09  a run writes nothing
    G10  an inconsistent stored history fails closed
    (teardown) outer rollback restores the baseline
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

_DB_SWITCH = "ALERTING_RUN_DB_TESTS"
_ADMIN_PASSWORD_ENV = "ALERTING_E2E_ADMIN_PASSWORD"
_ADMIN_USER_ENV = "ALERTING_E2E_ADMIN_USER"

pytestmark = pytest.mark.skipif(
    os.environ.get(_DB_SWITCH) != "1",
    reason=(
        f"live-database tests are opt-in; set {_DB_SWITCH}=1 "
        f"and provide {_ADMIN_PASSWORD_ENV}"
    ),
)

import alert_guardrail_store  # noqa: E402
from alert_guardrails import (  # noqa: E402
    GUARDRAIL_CODES,
    GuardrailEvaluationError,
    run_guardrails,
)
from alert_identity import (  # noqa: E402
    compute_attempt_id,
    compute_decision_id,
    compute_dedup_key,
)
from alert_models import GuardrailStatus  # noqa: E402
from alert_policy import validate_policy  # noqa: E402


_ROLE = "alert_evaluator"
_POLICY_VERSION = "phase-13.6-live-test"
_FIXTURE_ANALYZER_VERSION = "phase-13.6-fixture"
_FIXTURE_SIGNAL = "phase-13.6-fixture"
_FIXTURE_SERVICE = "phase-13-6-fixture-service"

_CHANNEL = "fixture-log"
_CHANNEL_OFF = "fixture-off"

_NOW = datetime(2001, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
_PERIOD_END = _NOW + timedelta(days=1)
_US = timedelta(microseconds=1)

_CHECKPOINT_MAX_AGE = 60
_ANOMALY_MAX_AGE = 60
_LOOKBACK_HOURS = 24
_LOOKBACK_START = _NOW - timedelta(hours=_LOOKBACK_HOURS)

_KEY = ("latency", _FIXTURE_SERVICE, "fixture-operation")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ago(**kwargs) -> datetime:
    return _NOW - timedelta(**kwargs)


def _policy(channels=None):
    if channels is None:
        channels = [
            {"name": _CHANNEL, "type": "log", "enabled": True, "max_attempts": 2},
            {"name": _CHANNEL_OFF, "type": "log", "enabled": False},
        ]
    return validate_policy({
        "policy_schema_version": "1.0.0",
        "policy_version": _POLICY_VERSION,
        "evaluation": {},
        "delivery": {"channels": channels, "max_delivery_age_minutes": 60},
        "guardrails": {
            "detector_checkpoint_max_age_minutes": _CHECKPOINT_MAX_AGE,
            "uninvestigated_anomaly_max_age_minutes": _ANOMALY_MAX_AGE,
            "delivery_lookback_hours": _LOOKBACK_HOURS,
        },
    })


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

def _group(operation_name: str) -> tuple[str, str, str]:
    return (_FIXTURE_SIGNAL, _FIXTURE_SERVICE, operation_name)


def _group_id(operation_name: str) -> str:
    return json.dumps(list(_group(operation_name)), separators=(",", ":"))


# operation_name -> updated_at.  "missing" has no row; "unexpected" is not
# an expected group.
_CHECKPOINTS = {
    "fresh": _ago(minutes=10),
    "boundary": _ago(minutes=_CHECKPOINT_MAX_AGE),
    "stale": _ago(minutes=_CHECKPOINT_MAX_AGE) - _US,
    "": _ago(hours=2),
    "unexpected": _ago(days=30),
}
_EXPECTED_GROUPS = tuple(
    _group(name) for name in ("fresh", "boundary", "stale", "", "missing")
)
# signal_path and service_name are equal, so the order is by operation_name.
_STALE_IDS = (_group_id(""), _group_id("missing"), _group_id("stale"))


def _anomaly_id(label: str) -> str:
    return _sha256(f"phase-13.6-fixture-anomaly-{label}")


# label -> detected_at.  None of these has an investigation.
_ANOMALIES = {
    "older": _ago(hours=5),
    "old": _ago(hours=3),
    "boundary": _ago(minutes=_ANOMALY_MAX_AGE),
    "young": _ago(minutes=5),
}
_OVERDUE_IDS = (_anomaly_id("older"), _anomaly_id("old"))


def _decision(name: str, minutes_ago: float, attempts=(), decision: str = "ALERT") -> dict:
    """
    One decision with its own investigated anomaly.

    attempts: (channel, outcome or None, started_at) in attempt order per
    channel.
    """
    anomaly_id = _anomaly_id(f"decision-{name}")
    investigation_id = _sha256(f"{anomaly_id}|{_FIXTURE_ANALYZER_VERSION}")
    evaluated_at = _ago(minutes=minutes_ago)
    return {
        "name": name,
        "anomaly_id": anomaly_id,
        "investigation_id": investigation_id,
        "decision_id": compute_decision_id(investigation_id, _POLICY_VERSION),
        "evaluated_at": evaluated_at,
        "event_time": evaluated_at,
        "detected_at": _ago(hours=10),
        "decision": decision,
        "reason_code": "severity_met" if decision == "ALERT" else "storm_cap",
        "payload": '{"fixture": "phase-13.6"}' if decision == "ALERT" else None,
        "attempts": tuple(attempts),
    }


_RECENT = _ago(minutes=10)

_DECISIONS = {
    d["name"]: d for d in [
        _decision("sent", 30, [
            (_CHANNEL, "FAILED_RETRYABLE", _RECENT), (_CHANNEL, "SENT", _RECENT),
        ]),
        _decision("uncertain", 31, [(_CHANNEL, "UNCERTAIN", _RECENT)]),
        # No outcome, far past the channel timeout: the result is unknown.
        _decision("lost", 32, [(_CHANNEL, None, _RECENT)]),
        _decision("inflight", 33, [(_CHANNEL, None, _ago(seconds=5))]),
        _decision("exhausted", 34, [
            (_CHANNEL, "FAILED_RETRYABLE", _RECENT),
            (_CHANNEL, "FAILED_RETRYABLE", _RECENT),
        ]),
        _decision("permanent", 35, [(_CHANNEL, "FAILED_PERMANENT", _RECENT)]),
        _decision("retryable", 20, [(_CHANNEL, "FAILED_RETRYABLE", _RECENT)]),
        # Never attempted and older than the delivery age.
        _decision("expired", 120),
        # Never attempted on the enabled channel; failed on a disabled one.
        _decision("fresh", 5, [(_CHANNEL_OFF, "FAILED_PERMANENT", _ago(minutes=4))]),
        # Outside the lookback by both rules.
        _decision("old_out", 1800, [(_CHANNEL, "FAILED_PERMANENT", _ago(hours=29))]),
        # Evaluated before the lookback, but its latest attempt is inside it.
        _decision("old_in", 1801, [(_CHANNEL, "FAILED_PERMANENT", _ago(minutes=60))]),
        # Evaluated exactly at the lookback start.
        _decision("boundary", _LOOKBACK_HOURS * 60),
        _decision("suppressed", 120, decision="SUPPRESSED"),
    ]
}
_FIXTURE_DECISION_IDS = {d["decision_id"]: name for name, d in _DECISIONS.items()}


def _pair_ids(*names: str) -> tuple[str, ...]:
    """Identifiers in the reported order: evaluated_at, then decision_id."""
    chosen = sorted(
        (_DECISIONS[name]["evaluated_at"], _DECISIONS[name]["decision_id"])
        for name in names
    )
    return tuple(f"{decision_id}/{_CHANNEL}" for _, decision_id in chosen)


_UNCERTAIN_IDS = _pair_ids("uncertain", "lost")
_EXHAUSTED_IDS = _pair_ids("exhausted", "permanent", "expired", "old_in", "boundary")


def _attempt_rows(decision: dict) -> list[dict]:
    rows = []
    numbers: dict[str, int] = {}
    for channel, outcome, started_at in decision["attempts"]:
        numbers[channel] = numbers.get(channel, 0) + 1
        rows.append({
            "attempt_id": compute_attempt_id(
                decision["decision_id"], channel, numbers[channel],
            ),
            "decision_id": decision["decision_id"],
            "channel_name": channel,
            "attempt_no": numbers[channel],
            "started_at": started_at,
            "outcome": outcome,
            "recorded_at": started_at + timedelta(seconds=1),
        })
    return rows


# ---------------------------------------------------------------------------
# Fixture SQL (administrator; never committed)
# ---------------------------------------------------------------------------

_SQL_BASELINE = {
    "anomaly_detector_runs": "SELECT count(*) FROM public.anomaly_detector_runs",
    "anomaly_events": "SELECT count(*) FROM public.anomaly_events",
    "rca_investigations": "SELECT count(*) FROM public.rca_investigations",
    "alert_policies": "SELECT count(*) FROM public.alert_policies",
    "alert_decisions": "SELECT count(*) FROM public.alert_decisions",
    "alert_delivery_attempts": "SELECT count(*) FROM public.alert_delivery_attempts",
    "alert_delivery_outcomes": "SELECT count(*) FROM public.alert_delivery_outcomes",
    "fixture_checkpoints":
        "SELECT count(*) FROM public.anomaly_detector_runs "
        "WHERE signal_path = 'phase-13.6-fixture'",
    "fixture_anomalies":
        "SELECT count(*) FROM public.anomaly_events "
        "WHERE detector_version = 'phase-13.6-fixture'",
    "fixture_investigations":
        "SELECT count(*) FROM public.rca_investigations "
        "WHERE analyzer_version = 'phase-13.6-fixture'",
    "fixture_policies":
        "SELECT count(*) FROM public.alert_policies "
        "WHERE policy_version = 'phase-13.6-live-test'",
}

# Rows dated inside or before the fixture period would join the findings.
_SQL_ROWS_IN_FIXTURE_PERIOD = {
    "anomaly_events":
        "SELECT count(*) FROM public.anomaly_events WHERE detected_at < %(end)s",
    "alert_decisions":
        "SELECT count(*) FROM public.alert_decisions WHERE evaluated_at < %(end)s",
    "alert_delivery_attempts":
        "SELECT count(*) FROM public.alert_delivery_attempts "
        "WHERE started_at < %(end)s",
}

_SQL_INSERT_CHECKPOINT = """\
INSERT INTO public.anomaly_detector_runs (
    signal_path, service_name, operation_name, checkpoint_at, updated_at
) VALUES (
    %(signal_path)s, %(service_name)s, %(operation_name)s, %(updated_at)s,
    %(updated_at)s
)
"""

_SQL_INSERT_ANOMALY = """\
INSERT INTO public.anomaly_events (
    anomaly_id, anomaly_type, signal_name, detector_name, detector_version,
    service_name, operation_name, observed_value, event_time, severity,
    explanation, detected_at
) VALUES (
    %(anomaly_id)s, 'latency', 'phase-13.6-fixture-signal',
    'phase-13.6-fixture-detector', 'phase-13.6-fixture',
    %(service_name)s, %(operation_name)s, 1.0, %(detected_at)s, 'CRITICAL',
    'Phase 13.6 fixture: temporary validation row, never committed.',
    %(detected_at)s
)
"""

_SQL_INSERT_INVESTIGATION = """\
INSERT INTO public.rca_investigations (
    investigation_id, anomaly_id, analyzer_version, service_name,
    operation_name, event_time, anomaly_type, observed_value, severity,
    confidence, summary, limitations
) VALUES (
    %(investigation_id)s, %(anomaly_id)s, 'phase-13.6-fixture',
    %(service_name)s, %(operation_name)s, %(event_time)s, 'latency', 1.0,
    'CRITICAL', 'MEDIUM',
    'Phase 13.6 fixture: temporary validation row, never committed.',
    '{}'::text[]
)
"""

_SQL_INSERT_POLICY = """\
INSERT INTO public.alert_policies (policy_version, policy_sha256, policy_json)
VALUES (%(policy_version)s, %(policy_sha256)s, '{}'::jsonb)
"""

_SQL_INSERT_DECISION = """\
INSERT INTO public.alert_decisions (
    decision_id, investigation_id, policy_version, anomaly_id, anomaly_type,
    service_name, operation_name, event_time, severity, confidence,
    dedup_key, decision, reason_code, evaluated_at, payload, summary,
    summary_truncated
) VALUES (
    %(decision_id)s, %(investigation_id)s, %(policy_version)s, %(anomaly_id)s,
    'latency', %(service_name)s, %(operation_name)s, %(event_time)s,
    'CRITICAL', 'MEDIUM', %(dedup_key)s, %(decision)s, %(reason_code)s,
    %(evaluated_at)s, %(payload)s::jsonb, NULL, false
)
"""

_SQL_INSERT_ATTEMPT = """\
INSERT INTO public.alert_delivery_attempts (
    attempt_id, decision_id, channel_name, channel_type, attempt_no, trigger,
    summary_included, payload_sha256, started_at
) VALUES (
    %(attempt_id)s, %(decision_id)s, %(channel_name)s, 'log', %(attempt_no)s,
    'auto', false, %(payload_sha256)s, %(started_at)s
)
"""

_SQL_INSERT_OUTCOME = """\
INSERT INTO public.alert_delivery_outcomes (attempt_id, outcome, detail, recorded_at)
VALUES (%(attempt_id)s, %(outcome)s, 'phase-13.6-fixture-detail', %(recorded_at)s)
"""

# Read-only verification SQL (run as the restricted role; granted columns only)
_SQL_ROLE_COUNTS = {
    "anomaly_detector_runs":
        "SELECT count(signal_path) FROM public.anomaly_detector_runs",
    "anomaly_events": "SELECT count(anomaly_id) FROM public.anomaly_events",
    "rca_investigations":
        "SELECT count(investigation_id) FROM public.rca_investigations",
    "alert_policies": "SELECT count(policy_version) FROM public.alert_policies",
    "alert_decisions": "SELECT count(decision_id) FROM public.alert_decisions",
    "alert_delivery_attempts":
        "SELECT count(attempt_id) FROM public.alert_delivery_attempts",
    "alert_delivery_outcomes":
        "SELECT count(attempt_id) FROM public.alert_delivery_outcomes",
}

_DENIED_STATEMENTS = [
    # The guardrails only read: no table they read may be changed.
    "INSERT INTO public.anomaly_detector_runs (signal_path) VALUES ('x')",
    "UPDATE public.anomaly_detector_runs SET updated_at = updated_at WHERE false",
    "DELETE FROM public.anomaly_detector_runs WHERE false",
    "INSERT INTO public.anomaly_events (anomaly_id) VALUES ('x')",
    "UPDATE public.anomaly_events SET detected_at = detected_at WHERE false",
    "DELETE FROM public.anomaly_events WHERE false",
    "INSERT INTO public.rca_investigations (investigation_id) VALUES ('x')",
    "UPDATE public.rca_investigations SET summary = summary WHERE false",
    "DELETE FROM public.rca_investigations WHERE false",
    "UPDATE public.alert_decisions SET summary = summary WHERE false",
    "DELETE FROM public.alert_decisions WHERE false",
    "INSERT INTO public.alert_delivery_attempts (attempt_id) VALUES ('x')",
    "UPDATE public.alert_delivery_attempts SET attempt_no = attempt_no WHERE false",
    "DELETE FROM public.alert_delivery_attempts WHERE false",
    "INSERT INTO public.alert_delivery_outcomes (attempt_id) VALUES ('x')",
    "UPDATE public.alert_delivery_outcomes SET detail = detail WHERE false",
    "DELETE FROM public.alert_delivery_outcomes WHERE false",
    "TRUNCATE public.alert_delivery_attempts",
    # Columns and tables the guardrails have no use for.
    "SELECT checkpoint_at FROM public.anomaly_detector_runs LIMIT 1",
    "SELECT severity FROM public.anomaly_events LIMIT 1",
    "SELECT explanation FROM public.anomaly_events LIMIT 1",
    "SELECT analyzer_version FROM public.rca_investigations LIMIT 1",
    "SELECT explanation FROM public.rca_evidence LIMIT 1",
    "SELECT embedding_id FROM public.rca_investigation_embeddings LIMIT 1",
    "SELECT count(*) FROM public.telemetry_spans",
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

# params is passed through as None when a statement has no parameters, so
# that a literal "%" in the SQL is not read as a placeholder.

def _scalar(conn, sql: str, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def _execute(conn, sql: str, params=None) -> int:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def _read_baseline(conn) -> dict:
    return {name: _scalar(conn, sql) for name, sql in _SQL_BASELINE.items()}


def _role_counts(conn) -> dict:
    return {name: _scalar(conn, sql) for name, sql in _SQL_ROLE_COUNTS.items()}


def _insert_fixtures(real) -> None:
    for operation_name, updated_at in _CHECKPOINTS.items():
        signal_path, service_name, _ = _group(operation_name)
        assert _execute(real, _SQL_INSERT_CHECKPOINT, {
            "signal_path": signal_path, "service_name": service_name,
            "operation_name": operation_name, "updated_at": updated_at,
        }) == 1

    names = {"service_name": _KEY[1], "operation_name": _KEY[2]}
    for label, detected_at in _ANOMALIES.items():
        assert _execute(real, _SQL_INSERT_ANOMALY, {
            **names, "anomaly_id": _anomaly_id(label), "detected_at": detected_at,
        }) == 1

    assert _execute(real, _SQL_INSERT_POLICY, {
        "policy_version": _POLICY_VERSION, "policy_sha256": "0" * 64,
    }) == 1
    for decision in _DECISIONS.values():
        params = {
            **names,
            **{key: value for key, value in decision.items() if key != "attempts"},
            "policy_version": _POLICY_VERSION,
            "dedup_key": compute_dedup_key(*_KEY),
        }
        assert _execute(real, _SQL_INSERT_ANOMALY, params) == 1
        assert _execute(real, _SQL_INSERT_INVESTIGATION, params) == 1
        assert _execute(real, _SQL_INSERT_DECISION, params) == 1
        for attempt in _attempt_rows(decision):
            assert _execute(real, _SQL_INSERT_ATTEMPT, {
                **attempt, "payload_sha256": "f" * 64,
            }) == 1
            if attempt["outcome"] is not None:
                assert _execute(real, _SQL_INSERT_OUTCOME, attempt) == 1


def _run(conn, policy=None):
    return run_guardrails(
        conn,
        policy=policy if policy is not None else _policy(),
        expected_groups=_EXPECTED_GROUPS,
        now=_NOW,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def conn():
    import psycopg

    password = os.environ.get(_ADMIN_PASSWORD_ENV)
    if not password:
        pytest.fail(
            f"{_ADMIN_PASSWORD_ENV} must be set to run the live guardrail "
            "test; there is no default"
        )

    real = psycopg.connect(
        host=os.environ.get("ALERT_EVALUATOR_DB_HOST", "localhost"),
        port=int(os.environ.get("ALERT_EVALUATOR_DB_PORT", "5432")),
        dbname=os.environ.get("ALERT_EVALUATOR_DB_NAME", "agentops"),
        user=os.environ.get(_ADMIN_USER_ENV, "agentops"),
        password=password,
    )
    assert real.autocommit is False

    baseline = None
    after = None
    try:
        # 1. Baseline (this also opens the single outer transaction).
        baseline = _read_baseline(real)
        for name in ("fixture_checkpoints", "fixture_anomalies",
                     "fixture_investigations", "fixture_policies"):
            assert baseline[name] == 0, (
                f"{name} already exist; a previous run leaked rows"
            )
        for name, sql in _SQL_ROWS_IN_FIXTURE_PERIOD.items():
            if _scalar(real, sql, {"end": _PERIOD_END}):
                pytest.skip(f"the database holds {name} inside the fixture period")

        # 2. Fixtures, as the administrator.  Never committed.
        _insert_fixtures(real)

        # 3. Everything after this is permission-checked as the restricted role.
        _execute(real, f"SET LOCAL ROLE {_ROLE}")

        yield real
    finally:
        # 5. Nothing is ever committed.
        real.rollback()
        try:
            after = _read_baseline(real)
        finally:
            real.rollback()
            real.close()

    if baseline is not None and after is not None:
        assert after == baseline, (
            f"the outer rollback did not restore the baseline: "
            f"before={baseline} after={after}"
        )


# ---------------------------------------------------------------------------
# G01  Role
# ---------------------------------------------------------------------------

def test_g01_statements_run_as_the_restricted_role(conn):
    assert _scalar(conn, "SELECT current_user") == _ROLE


# ---------------------------------------------------------------------------
# G02  Privileges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("statement", _DENIED_STATEMENTS)
def test_g02_restricted_role_is_denied(conn, statement):
    import psycopg.errors

    # The savepoint keeps the refused statement from ending the outer
    # transaction, and with it the fixtures.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            _execute(conn, statement)
    assert _scalar(conn, "SELECT current_user") == _ROLE


def test_g02_granted_reads_work(conn):
    counts = _role_counts(conn)
    assert counts["anomaly_detector_runs"] >= len(_CHECKPOINTS)
    assert counts["anomaly_events"] >= len(_ANOMALIES) + len(_DECISIONS)
    assert counts["alert_decisions"] >= len(_DECISIONS)


# ---------------------------------------------------------------------------
# G03  S1 checkpoints
# ---------------------------------------------------------------------------

def test_g03_checkpoints(conn):
    rows = alert_guardrail_store.fetch_checkpoints(conn)
    assert all(
        set(row) == {"signal_path", "service_name", "operation_name", "updated_at"}
        for row in rows
    )
    fixture = {
        row["operation_name"]: row["updated_at"]
        for row in rows if row["signal_path"] == _FIXTURE_SIGNAL
    }
    assert fixture == _CHECKPOINTS
    assert all(row["updated_at"].utcoffset() is not None for row in rows)


# ---------------------------------------------------------------------------
# G04  S2 anomalies without an investigation
# ---------------------------------------------------------------------------

def test_g04_uninvestigated_anomalies(conn):
    rows = alert_guardrail_store.fetch_uninvestigated_anomalies(conn)
    assert all(set(row) == {"anomaly_id", "detected_at"} for row in rows)
    found = {row["anomaly_id"]: row["detected_at"] for row in rows}

    # Of every age: the age threshold is not applied in SQL.
    for label, detected_at in _ANOMALIES.items():
        assert found[_anomaly_id(label)] == detected_at
    # An anomaly with an investigation is not returned, however old.
    for decision in _DECISIONS.values():
        assert decision["anomaly_id"] not in found

    keys = [(row["detected_at"], row["anomaly_id"]) for row in rows]
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# G05  S3 ALERT decisions in or near the lookback
# ---------------------------------------------------------------------------

def test_g05_alert_decisions(conn):
    rows = alert_guardrail_store.fetch_alert_decisions(
        conn, lookback_start=_LOOKBACK_START,
    )
    assert all(set(row) == {"decision_id", "evaluated_at"} for row in rows)
    found = {
        _FIXTURE_DECISION_IDS[row["decision_id"]]: row["evaluated_at"]
        for row in rows if row["decision_id"] in _FIXTURE_DECISION_IDS
    }
    # Not returned: old_out (evaluated and attempted before the lookback) and
    # suppressed (not an alert).  old_in enters through its attempt, boundary
    # through an evaluated_at exactly at the start.
    assert set(found) == set(_DECISIONS) - {"old_out", "suppressed"}
    for name, evaluated_at in found.items():
        assert evaluated_at == _DECISIONS[name]["evaluated_at"]


def test_g05_one_microsecond_later_excludes_the_boundary_decision(conn):
    rows = alert_guardrail_store.fetch_alert_decisions(
        conn, lookback_start=_LOOKBACK_START + _US,
    )
    ids = {row["decision_id"] for row in rows}
    assert _DECISIONS["boundary"]["decision_id"] not in ids
    assert _DECISIONS["old_in"]["decision_id"] in ids


# ---------------------------------------------------------------------------
# G06  S4 delivery history
# ---------------------------------------------------------------------------

_HISTORY_KEYS = {
    "attempt_id", "decision_id", "channel_name", "channel_type", "attempt_no",
    "trigger", "summary_included", "payload_sha256", "started_at", "outcome",
    "recorded_at",
}


def test_g06_delivery_history(conn):
    decision_ids = [d["decision_id"] for d in _DECISIONS.values()]
    rows = alert_guardrail_store.fetch_delivery_history(
        conn, decision_ids=decision_ids, channel_names=[_CHANNEL],
    )
    # The outcome's detail text is never read.
    assert all(set(row) == _HISTORY_KEYS for row in rows)
    assert {row["channel_name"] for row in rows} == {_CHANNEL}

    expected = {
        attempt["attempt_id"]: attempt
        for decision in _DECISIONS.values()
        for attempt in _attempt_rows(decision)
        if attempt["channel_name"] == _CHANNEL
    }
    assert {row["attempt_id"] for row in rows} == set(expected)
    for row in rows:
        attempt = expected[row["attempt_id"]]
        assert row["attempt_no"] == attempt["attempt_no"]
        assert row["started_at"] == attempt["started_at"]
        assert row["outcome"] == attempt["outcome"]
        if attempt["outcome"] is None:
            assert row["recorded_at"] is None
        else:
            assert row["recorded_at"] == attempt["recorded_at"]


def test_g06_other_channels_are_not_read(conn):
    fresh = _DECISIONS["fresh"]["decision_id"]
    on = alert_guardrail_store.fetch_delivery_history(
        conn, decision_ids=[fresh], channel_names=[_CHANNEL],
    )
    off = alert_guardrail_store.fetch_delivery_history(
        conn, decision_ids=[fresh], channel_names=[_CHANNEL_OFF],
    )
    assert on == []
    assert [row["outcome"] for row in off] == ["FAILED_PERMANENT"]


# ---------------------------------------------------------------------------
# G07  run_guardrails
# ---------------------------------------------------------------------------

def test_g07_all_four_findings(conn):
    results = _run(conn)
    assert tuple(result.finding.code for result in results) == GUARDRAIL_CODES
    checkpoints, anomalies, uncertain, exhausted = results

    for result, ids in (
        (checkpoints, _STALE_IDS),
        (anomalies, _OVERDUE_IDS),
        (uncertain, _UNCERTAIN_IDS),
        (exhausted, _EXHAUSTED_IDS),
    ):
        assert result.finding.status is GuardrailStatus.VIOLATION
        assert result.detail_ids == ids
        assert result.finding.count == len(ids)
        assert result.finding.detail == (
            f"{len(ids)} violation(s); showing {len(ids)} of {len(ids)}."
        )


def test_g07_run_is_repeatable(conn):
    assert _run(conn) == _run(conn)


# ---------------------------------------------------------------------------
# G08  No enabled channel
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("channels", [
    [],
    [{"name": _CHANNEL, "type": "log", "enabled": False}],
])
def test_g08_no_enabled_channel(conn, channels):
    checkpoints, anomalies, uncertain, exhausted = _run(conn, _policy(channels))
    assert checkpoints.detail_ids == _STALE_IDS
    assert anomalies.detail_ids == _OVERDUE_IDS
    for result in (uncertain, exhausted):
        assert result.finding.status is GuardrailStatus.OK
        assert result.finding.count == 0 and result.detail_ids == ()


def test_g08_a_channel_without_history_reports_only_expiry(conn):
    # No attempt was ever made on this channel, so nothing is uncertain; the
    # alerts older than the delivery age are expired.
    policy = _policy([{"name": "fixture-new", "type": "log", "enabled": True}])
    _, _, uncertain, exhausted = _run(conn, policy)
    assert uncertain.finding.status is GuardrailStatus.OK
    assert exhausted.detail_ids == tuple(
        identifier.replace(f"/{_CHANNEL}", "/fixture-new")
        for identifier in _pair_ids("expired", "boundary")
    )


# ---------------------------------------------------------------------------
# G09  A run writes nothing
# ---------------------------------------------------------------------------

def test_g09_a_run_writes_nothing(conn):
    before = _role_counts(conn)
    _run(conn)
    _run(conn, _policy([]))
    assert _role_counts(conn) == before


# ---------------------------------------------------------------------------
# G10  An inconsistent stored history fails closed
# ---------------------------------------------------------------------------

def test_g10_inconsistent_history_fails_closed(conn):
    # The table accepts an attempt numbered 2 with no attempt 1; the notifier
    # never writes one.  It is inserted by the administrator inside a
    # savepoint, which the failure itself rolls back.
    decision_id = _DECISIONS["expired"]["decision_id"]
    with pytest.raises(GuardrailEvaluationError) as excinfo:
        with conn.transaction():
            _execute(conn, "RESET ROLE")
            assert _execute(conn, _SQL_INSERT_ATTEMPT, {
                "attempt_id": compute_attempt_id(decision_id, _CHANNEL, 2),
                "decision_id": decision_id,
                "channel_name": _CHANNEL,
                "attempt_no": 2,
                "payload_sha256": "f" * 64,
                "started_at": _RECENT,
            }) == 1
            _execute(conn, f"SET LOCAL ROLE {_ROLE}")
            _run(conn)

    assert excinfo.value.guardrail_codes == ("delivery_uncertain", "delivery_exhausted")
    assert excinfo.value.reason_code == "invalid_delivery_data"
    # The savepoint is gone: the role and the fixtures are as before.
    assert _scalar(conn, "SELECT current_user") == _ROLE
    assert _run(conn)[3].detail_ids == _EXHAUSTED_IDS
