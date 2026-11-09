"""
alerting/tests/integration/test_live_phase13_e2e.py

Opt-in end-to-end validation of Phase 13 against live PostgreSQL (Phase 13.7).

One ordered story through the locked components, each under its own
restricted role:

    fixture anomalies and investigations
      -> run_evaluation            (alert_evaluator)   decisions
      -> run_guardrails            (alert_evaluator)   nothing delivered yet
      -> run_notify                (alert_notifier)    attempts and outcomes
      -> show_alert                (alert_notifier)    derived delivery states
      -> run_guardrails            (alert_evaluator)   failures are visible
      -> replay of both runs                           nothing is repeated
      -> a late investigation      -> evaluated and delivered exactly once
      -> retry_delivery            (alert_notifier)    operator refusals, retries
      -> run_guardrails            (alert_evaluator)   final picture

It adds no feature and replaces nothing: the decision engine, the stores, the
delivery state machine, the channels and the guardrails are the production
ones, called unchanged.

Skipped by default.  It runs only when the switch is set:

    ALERTING_RUN_DB_TESTS=1

and an administrator password is supplied through the environment:

    ALERTING_E2E_ADMIN_PASSWORD   required; there is no default
    ALERTING_E2E_ADMIN_USER       default: agentops

Host, port and database come from ALERT_EVALUATOR_DB_HOST / _PORT / _NAME
(defaults localhost / 5432 / agentops).  The passwords of the restricted
roles are NOT needed.  Migrations 012, 013 and 014 must be applied.

What is production and what is harness
--------------------------------------
PRODUCTION PATH (measured):
    run_evaluation, run_notify, retry_delivery, show_alert, run_guardrails
    and everything they call.  Every decision, attempt and outcome that an
    assertion looks at was written by them.

HARNESS SETUP (not evidence):
    the fixture anomalies, investigations and checkpoints; the policy row,
    written through the production store function before the run so that
    the shield rows below can refer to it; the shield rows; the savepoint
    wrapper; role switching; the injected times; the temporary paths; the
    log stream that cannot be written.

HARNESS OBSERVATION:
    SELECT statements on the stored rows, reading the notification file, and
    the baseline digests.

Anomaly detection and RCA analysis themselves are not run.  Their output is
represented by fixture rows.

Only fixtures are evaluated and delivered
-----------------------------------------
The evaluator decides every investigation that has no decision under the
policy version, and the notifier delivers every ALERT decision.  So that
neither touches a row of the real database:

  - every investigation that existed before the test gets a NOT_ALERTABLE
    shield decision under the fixture policy version, so it is not a
    candidate;
  - every ALERT decision that existed before the test gets a SENT shield
    delivery on each fixture channel, so it is not delivered again.

Shield rows are written by the administrator inside the transaction and
disappear with it.  No assertion about the product is made on them.  Before
every notifier call the test stops if an ALERT decision exists that is
neither a fixture nor shielded.

Nothing is ever committed
-------------------------
The whole module runs inside ONE transaction on ONE administrator connection,
and that transaction is rolled back when the module finishes.  The product
code calls commit() and rollback() itself; it is given a wrapper
(_SavepointConnection) that maps those calls onto a savepoint inside the
outer transaction.  The role is switched with SET LOCAL ROLE before a new
savepoint is opened, so a product rollback never changes the role.

Known limits of this arrangement:
  - one session plays the evaluator, the notifier and the guardrails; what
    one session's commit makes visible to another is not exercised;
  - NOW() is constant inside one transaction, so every started_at,
    recorded_at and decided_at holds the same real time, which is later than
    the injected run times;
  - the connection factories and the command-line programs are not used.

Time
----
Every fixture time and every injected run time lies in an isolated period
around 2001-04-01 12:00 UTC.  No expected value depends on the wall clock.
The module is skipped when the database holds rows dated inside or before
that period.

No network
----------
The channels are two files and the log stream.  No webhook channel is
configured, and while the module runs any attempt to open a socket from
Python fails the test.  The database connection is opened before that.

The fixture SQL below exists only in this test.  Production SQL lives only in
the alerting store modules.

Test inventory:
    E01  each stage runs as its restricted role
    E02  the roles cannot do each other's work
    E03  evaluation: six verdicts
    E04  stored decisions and payloads
    E05  guardrails before any delivery
    E06  notification: one attempt per alert and channel
    E07  stored attempts and outcomes
    E08  the notification file and the body digests
    E09  delivery states seen by an operator
    E10  guardrails after delivery
    E11  evaluation replay decides nothing
    E12  notification replay delivers nothing
    E13  a late investigation is decided and delivered exactly once
    E14  guardrails after the late alert
    E15  operator retries that are refused
    E16  confirmed resend of an uncertain delivery
    E17  operator retry of a permanent failure
    E18  guardrails after the operator's actions
    E19  guardrails are repeatable and write nothing
    (teardown) outer rollback restores every table exactly
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
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

import alert_store  # noqa: E402
from alert_channels import preflight_channel  # noqa: E402
from alert_delivery_state import (  # noqa: E402
    REFUSAL_ALREADY_SENT,
    REFUSAL_CONFIRM_RESEND_REQUIRED,
    REFUSAL_NOT_AUTO_ELIGIBLE,
    DeliveryState,
)
from alert_evaluator import (  # noqa: E402
    ADVISORY,
    POLICY_ALREADY_REGISTERED,
    STATUS_PERSISTED,
    run_evaluation,
)
from alert_guardrails import GUARDRAIL_CODES, run_guardrails  # noqa: E402
from alert_identity import (  # noqa: E402
    compute_attempt_id,
    compute_decision_id,
    compute_dedup_key,
)
from alert_models import (  # noqa: E402
    Decision,
    DeliveryOutcome,
    GuardrailStatus,
    ReasonCode,
)
from alert_notifier import (  # noqa: E402
    STATUS_ATTEMPTED,
    STATUS_BLOCKED,
    STATUS_REFUSED,
    retry_delivery,
    run_notify,
    show_alert,
)
from alert_policy import evaluation_hash_object, validate_policy  # noqa: E402
from alert_version import PAYLOAD_VERSION  # noqa: E402


_EVALUATOR = "alert_evaluator"
_NOTIFIER = "alert_notifier"
_ADMIN = None

_POLICY_VERSION = "phase-13.7-e2e"
_ANALYZER_A = "phase-13.7-fixture-a"
_ANALYZER_B = "phase-13.7-fixture-b"
_FIXTURE_SIGNAL = "phase-13.7-fixture"
_FIXTURE_SERVICE = "phase-13-7-fixture-service"
_FIXTURE_LIMITATION = "phase-13.7 fixture limitation"

_SAVEPOINT = "phase_13_7_product_tx"

_CH_FILE = "phase-13-7-file"
_CH_BROKEN = "phase-13-7-broken"
_CH_LOG = "phase-13-7-log"
_CHANNELS = (_CH_FILE, _CH_BROKEN, _CH_LOG)
_CHANNEL_TYPES = {_CH_FILE: "file", _CH_BROKEN: "file", _CH_LOG: "log"}

#: The centre of the isolated period.
_T = datetime(2001, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
_PERIOD_START = _T - timedelta(days=2)
_PERIOD_END = _T + timedelta(days=1)


def _at(minutes: float) -> datetime:
    return _T + timedelta(minutes=minutes)


# Injected run times, in story order.
_EVALUATED_1 = _at(0)
_GUARD_BEFORE = _at(1)
_NOTIFY_1 = _at(1)
_GUARD_AFTER = _at(2)
_REPLAY = _at(3)
_EVALUATED_LATE = _at(5)
_NOTIFY_LATE = _at(6)
_GUARD_LATE = _at(7)
_OPERATOR = _at(8)
_GUARD_FINAL = _at(9)

_K1 = ("latency", _FIXTURE_SERVICE, "fixture-operation-a")
_K2 = ("error_rate", _FIXTURE_SERVICE, "fixture-operation-b")
_K3 = ("latency", _FIXTURE_SERVICE, "fixture-operation-c")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _anomaly_id(label: str) -> str:
    return _sha256(f"phase-13.7-fixture-anomaly-{label}")


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

def _investigation(name, anomaly, version, minutes, severity, key) -> dict:
    anomaly_id = _anomaly_id(anomaly)
    # The Phase 11 investigation identity formula.
    investigation_id = _sha256(f"{anomaly_id}|{version}")
    return {
        "name": name,
        "anomaly_id": anomaly_id,
        "analyzer_version": version,
        "investigation_id": investigation_id,
        "decision_id": compute_decision_id(investigation_id, _POLICY_VERSION),
        "anomaly_type": key[0],
        "service_name": key[1],
        "operation_name": key[2],
        "event_time": _at(minutes),
        "detected_at": _at(minutes),
        "severity": severity,
    }


_FIXTURES = {
    f["name"]: f for f in [
        _investigation("first", "1", _ANALYZER_A, -20, "WARNING", _K1),
        # The same anomaly as "first", investigated by another analyzer version.
        _investigation("duplicate", "1", _ANALYZER_B, -19, "WARNING", _K1),
        _investigation("cooldown", "3", _ANALYZER_A, -10, "WARNING", _K1),
        _investigation("escalation", "4", _ANALYZER_A, -5, "CRITICAL", _K1),
        _investigation("info", "5", _ANALYZER_A, -8, "INFO", _K2),
        _investigation("stale", "6", _ANALYZER_A, -120, "CRITICAL", _K2),
        # Arrives after the first cycle.
        _investigation("late", "7", _ANALYZER_A, 2, "WARNING", _K3),
    ]
}
_INITIAL = ("first", "duplicate", "cooldown", "escalation", "info", "stale")

# The evaluator processes by event_time, then investigation_id.
_PROCESSING_ORDER = ["stale", "first", "duplicate", "cooldown", "info", "escalation"]

_EXPECTED_VERDICTS = {
    "first": (Decision.ALERT, ReasonCode.SEVERITY_MET, None),
    "duplicate": (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, "first"),
    "cooldown": (Decision.SUPPRESSED, ReasonCode.COOLDOWN, "first"),
    "escalation": (Decision.ALERT, ReasonCode.ESCALATION, "first"),
    "info": (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None),
    "stale": (Decision.NOT_ALERTABLE, ReasonCode.STALE, None),
    "late": (Decision.ALERT, ReasonCode.SEVERITY_MET, None),
}

_NAME_BY_INVESTIGATION = {f["investigation_id"]: name for name, f in _FIXTURES.items()}
_NAME_BY_DECISION = {f["decision_id"]: name for name, f in _FIXTURES.items()}


def _did(name: str) -> str:
    return _FIXTURES[name]["decision_id"]


# Both alerts of the first run share one evaluated_at, so the notifier and the
# guardrails order them by decision_id.
_FIRST_ALERTS = sorted(["first", "escalation"], key=_did)
_ALL_ALERTS = _FIRST_ALERTS + ["late"]
_ALL_ALERT_IDS = {_did(name) for name in _ALL_ALERTS}

_UNINVESTIGATED_ANOMALY = _anomaly_id("uninvestigated")
_UNINVESTIGATED_DETECTED = _at(-180)

_GROUP_FRESH = (_FIXTURE_SIGNAL, _FIXTURE_SERVICE, "fresh")
_GROUP_MISSING = (_FIXTURE_SIGNAL, _FIXTURE_SERVICE, "missing")
_EXPECTED_GROUPS = (_GROUP_FRESH, _GROUP_MISSING)
_MISSING_GROUP_ID = json.dumps(list(_GROUP_MISSING), separators=(",", ":"))


def _pairs(names, channel) -> tuple[str, ...]:
    return tuple(f"{_did(name)}/{channel}" for name in names)


def _policy(file_path: str, broken_path: str):
    return validate_policy({
        "policy_schema_version": "1.0.0",
        "policy_version": _POLICY_VERSION,
        "evaluation": {
            "enabled": True,
            "min_severity": "WARNING",
            "max_alert_age_minutes": 60,
            "cooldown_minutes": 30,
            "escalation_breaks_cooldown": True,
            "max_alerts_per_hour": 10,
            "persist_summary": False,
        },
        "delivery": {
            "max_delivery_age_minutes": 60,
            "channels": [
                {"name": _CH_FILE, "type": "file", "enabled": True, "path": file_path},
                {"name": _CH_BROKEN, "type": "file", "enabled": True,
                 "path": broken_path},
                {"name": _CH_LOG, "type": "log", "enabled": True},
            ],
        },
        "guardrails": {
            "detector_checkpoint_max_age_minutes": 60,
            "uninvestigated_anomaly_max_age_minutes": 60,
            "delivery_lookback_hours": 24,
        },
    })


# ---------------------------------------------------------------------------
# Baseline SQL (administrator, read-only)
# ---------------------------------------------------------------------------

_BASELINE_TABLES = (
    "public.telemetry_spans",
    "public.anomaly_events",
    "public.anomaly_detector_runs",
    "public.rca_investigations",
    "public.rca_evidence",
    "public.rca_investigation_embeddings",
    "public.alert_policies",
    "public.alert_decisions",
    "public.alert_delivery_attempts",
    "public.alert_delivery_outcomes",
)

# The row count and a digest of every whole row, in an order that does not
# depend on storage.  It covers the primary keys and every other column, so a
# changed timestamp or a replaced row is seen as well as a missing one.
_SQL_TABLE_DIGEST = (
    "SELECT count(*), "
    "md5(coalesce(string_agg(md5(t::text), '' ORDER BY md5(t::text)), '')) "
    "FROM {table} AS t"
)

_SQL_MARKERS = {
    "checkpoints":
        "SELECT count(*) FROM public.anomaly_detector_runs "
        "WHERE signal_path = 'phase-13.7-fixture'",
    "anomalies":
        "SELECT count(*) FROM public.anomaly_events "
        "WHERE detector_version = 'phase-13.7-fixture'",
    "investigations":
        "SELECT count(*) FROM public.rca_investigations "
        "WHERE analyzer_version IN ('phase-13.7-fixture-a', 'phase-13.7-fixture-b')",
    "policies":
        "SELECT count(*) FROM public.alert_policies "
        "WHERE policy_version = 'phase-13.7-e2e'",
    "decisions":
        "SELECT count(*) FROM public.alert_decisions "
        "WHERE policy_version = 'phase-13.7-e2e'",
    "attempts":
        "SELECT count(*) FROM public.alert_delivery_attempts "
        "WHERE channel_name IN "
        "('phase-13-7-file', 'phase-13-7-broken', 'phase-13-7-log')",
}

# Rows dated inside or before the fixture period would take part in the
# windows, the lookback or the findings.
_SQL_ROWS_IN_FIXTURE_PERIOD = {
    "anomaly_events":
        "SELECT count(*) FROM public.anomaly_events WHERE detected_at < %(end)s",
    "alert_decisions (evaluated_at)":
        "SELECT count(*) FROM public.alert_decisions WHERE evaluated_at < %(end)s",
    "alert_decisions (event_time)":
        "SELECT count(*) FROM public.alert_decisions "
        "WHERE event_time > %(start)s AND event_time < %(end)s",
    "alert_delivery_attempts":
        "SELECT count(*) FROM public.alert_delivery_attempts "
        "WHERE started_at < %(end)s",
}


# ---------------------------------------------------------------------------
# Fixture SQL (administrator; never committed)
# ---------------------------------------------------------------------------

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
    %(anomaly_id)s, %(anomaly_type)s, 'phase-13.7-fixture-signal',
    'phase-13.7-fixture-detector', 'phase-13.7-fixture',
    %(service_name)s, %(operation_name)s, 1.0, %(event_time)s, %(severity)s,
    'Phase 13.7 fixture: temporary validation row, never committed.',
    %(detected_at)s
)
"""

_SQL_INSERT_INVESTIGATION = """\
INSERT INTO public.rca_investigations (
    investigation_id, anomaly_id, analyzer_version, service_name,
    operation_name, event_time, anomaly_type, observed_value, severity,
    confidence, summary, limitations
) VALUES (
    %(investigation_id)s, %(anomaly_id)s, %(analyzer_version)s,
    %(service_name)s, %(operation_name)s, %(event_time)s, %(anomaly_type)s,
    1.0, %(severity)s, 'MEDIUM',
    'Phase 13.7 fixture summary: temporary validation row, never committed.',
    ARRAY['phase-13.7 fixture limitation']::text[]
)
"""

# -- shields: harness setup only, never asserted on as product behaviour -----

_SQL_EXISTING_INVESTIGATIONS = """\
SELECT investigation_id, anomaly_id, anomaly_type, service_name,
       operation_name, event_time, severity, confidence
FROM public.rca_investigations
"""

_SQL_EXISTING_ALERT_DECISIONS = (
    "SELECT decision_id FROM public.alert_decisions WHERE decision = 'ALERT'"
)

_SQL_INSERT_SHIELD_DECISION = """\
INSERT INTO public.alert_decisions (
    decision_id, investigation_id, policy_version, anomaly_id, anomaly_type,
    service_name, operation_name, event_time, severity, confidence,
    dedup_key, decision, reason_code, evaluated_at, payload, summary,
    summary_truncated
) VALUES (
    %(decision_id)s, %(investigation_id)s, %(policy_version)s, %(anomaly_id)s,
    %(anomaly_type)s, %(service_name)s, %(operation_name)s, %(event_time)s,
    %(severity)s, %(confidence)s, %(dedup_key)s, 'NOT_ALERTABLE', 'stale',
    %(evaluated_at)s, NULL, NULL, false
)
"""

_SQL_INSERT_SHIELD_ATTEMPT = """\
INSERT INTO public.alert_delivery_attempts (
    attempt_id, decision_id, channel_name, channel_type, attempt_no, trigger,
    summary_included, payload_sha256
) VALUES (
    %(attempt_id)s, %(decision_id)s, %(channel_name)s, %(channel_type)s, 1,
    'auto', false, %(payload_sha256)s
)
"""

_SQL_INSERT_SHIELD_OUTCOME = """\
INSERT INTO public.alert_delivery_outcomes (attempt_id, outcome, detail)
VALUES (%(attempt_id)s, 'SENT', 'phase-13.7-shield')
"""

# -- observation (run as a restricted role; granted columns only) ------------

_SQL_ALERT_DECISION_IDS = (
    "SELECT decision_id FROM public.alert_decisions WHERE decision = 'ALERT'"
)

_SQL_FIXTURE_DECISIONS = """\
SELECT
    decision_id, investigation_id, policy_version, anomaly_id, anomaly_type,
    service_name, operation_name, event_time, severity, confidence,
    limitations, dedup_key, decision, reason_code, related_decision_id,
    evaluated_at, payload, summary, summary_truncated
FROM public.alert_decisions
WHERE decision_id = ANY(%(decision_ids)s)
"""

_SQL_PAYLOADS = """\
SELECT decision_id, payload
FROM public.alert_decisions
WHERE decision_id = ANY(%(decision_ids)s)
"""

_SQL_FIXTURE_DELIVERIES = """\
SELECT
    a.attempt_id, a.decision_id, a.channel_name, a.channel_type, a.attempt_no,
    a.trigger, a.summary_included, a.payload_sha256, a.started_at,
    o.outcome, o.detail, o.recorded_at
FROM public.alert_delivery_attempts AS a
LEFT JOIN public.alert_delivery_outcomes AS o
  ON o.attempt_id = a.attempt_id
WHERE a.decision_id = ANY(%(decision_ids)s)
ORDER BY a.decision_id ASC, a.channel_name ASC, a.attempt_no ASC
"""

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

_NOTIFIER_DENIED = [
    "INSERT INTO public.alert_decisions (decision_id) VALUES ('x')",
    "SELECT investigation_id FROM public.rca_investigations LIMIT 1",
]
_EVALUATOR_DENIED = [
    "INSERT INTO public.alert_delivery_attempts (attempt_id) VALUES ('x')",
    "INSERT INTO public.alert_delivery_outcomes (attempt_id) VALUES ('x')",
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _SavepointConnection:
    """
    Gives the product code commit / rollback semantics inside one outer
    transaction that is never committed.

        commit()       release the savepoint and open a new one
        rollback()     roll back to the savepoint (everything written before
                       it survives)
        close()        no-op; the test owns the real connection
        switch_role()  harness only: keep what was done so far, change the
                       role, then open a new savepoint, so that a later
                       product rollback cannot undo the role
    """

    def __init__(self, real) -> None:
        self._real = real
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self._execute(f"SAVEPOINT {_SAVEPOINT}")

    def _execute(self, sql: str) -> None:
        with self._real.cursor() as cur:
            cur.execute(sql)

    def cursor(self, *args, **kwargs):
        return self._real.cursor(*args, **kwargs)

    def commit(self) -> None:
        self.commits += 1
        self._execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
        self._execute(f"SAVEPOINT {_SAVEPOINT}")

    def rollback(self) -> None:
        self.rollbacks += 1
        self._execute(f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}")

    def close(self) -> None:
        self.closes += 1

    def switch_role(self, role) -> None:
        self._execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
        self._execute("RESET ROLE")
        if role is not None:
            self._execute(f"SET LOCAL ROLE {role}")
        self._execute(f"SAVEPOINT {_SAVEPOINT}")


class _UnwritableStream:
    """A log stream that cannot be written, like a closed pipe."""

    def __init__(self) -> None:
        self.write_calls = 0

    def write(self, data: bytes) -> int:
        self.write_calls += 1
        raise OSError("phase-13.7 fixture: the stream cannot be written")

    def flush(self) -> None:
        return None


class _State:
    """Shared between the ordered tests of this module."""

    def __init__(self) -> None:
        self.real = None
        self.conn: _SavepointConnection | None = None
        self.policy = None
        self.prepared: list = []
        self.file_path = None
        self.broken_path = None
        self.unwritable = _UnwritableStream()
        self.shielded_alerts: set[str] = set()
        self.shielded_investigations = 0
        self.file_after_first_run = b""


# params is passed through as None when a statement has no parameters, so
# that a literal "%" in the SQL is not read as a placeholder.

def _scalar(conn, sql: str, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def _rows(conn, sql: str, params=None) -> list[dict]:
    import psycopg.rows

    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]


def _execute(conn, sql: str, params=None) -> int:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def _read_baseline(conn) -> dict:
    baseline = {}
    for table in _BASELINE_TABLES:
        with conn.cursor() as cur:
            cur.execute(_SQL_TABLE_DIGEST.format(table=table))
            baseline[table] = tuple(cur.fetchone())
    for name, sql in _SQL_MARKERS.items():
        baseline[f"marker:{name}"] = _scalar(conn, sql)
    return baseline


def _role_counts(conn) -> dict:
    return {name: _scalar(conn, sql) for name, sql in _SQL_ROLE_COUNTS.items()}


def _insert_investigation(real, fixture: dict, *, with_anomaly: bool) -> None:
    if with_anomaly:
        assert _execute(real, _SQL_INSERT_ANOMALY, fixture) == 1
    assert _execute(real, _SQL_INSERT_INVESTIGATION, fixture) == 1


def _insert_fixtures(real) -> None:
    assert _execute(real, _SQL_INSERT_CHECKPOINT, {
        "signal_path": _GROUP_FRESH[0], "service_name": _GROUP_FRESH[1],
        "operation_name": _GROUP_FRESH[2], "updated_at": _at(-10),
    }) == 1

    assert _execute(real, _SQL_INSERT_ANOMALY, {
        "anomaly_id": _UNINVESTIGATED_ANOMALY, "anomaly_type": _K2[0],
        "service_name": _K2[1], "operation_name": _K2[2],
        "event_time": _UNINVESTIGATED_DETECTED, "severity": "WARNING",
        "detected_at": _UNINVESTIGATED_DETECTED,
    }) == 1

    inserted_anomalies: set[str] = set()
    for name in _INITIAL:
        fixture = _FIXTURES[name]
        _insert_investigation(
            real, fixture,
            with_anomaly=fixture["anomaly_id"] not in inserted_anomalies,
        )
        inserted_anomalies.add(fixture["anomaly_id"])


def _insert_shields(state: _State, investigations, alert_ids) -> None:
    """
    HARNESS SETUP.  Keep every row that existed before the test out of the
    evaluator's candidates and out of the notifier's deliveries.
    """
    for row in investigations:
        assert _execute(state.real, _SQL_INSERT_SHIELD_DECISION, {
            **row,
            "decision_id": compute_decision_id(
                row["investigation_id"], _POLICY_VERSION,
            ),
            "policy_version": _POLICY_VERSION,
            "dedup_key": compute_dedup_key(
                row["anomaly_type"], row["service_name"], row["operation_name"],
            ),
            "evaluated_at": _EVALUATED_1,
        }) == 1
    state.shielded_investigations = len(investigations)

    for decision_id in alert_ids:
        for channel in _CHANNELS:
            attempt_id = compute_attempt_id(decision_id, channel, 1)
            assert _execute(state.real, _SQL_INSERT_SHIELD_ATTEMPT, {
                "attempt_id": attempt_id,
                "decision_id": decision_id,
                "channel_name": channel,
                "channel_type": _CHANNEL_TYPES[channel],
                "payload_sha256": "0" * 64,
            }) == 1
            assert _execute(
                state.real, _SQL_INSERT_SHIELD_OUTCOME, {"attempt_id": attempt_id},
            ) == 1
    state.shielded_alerts = set(alert_ids)


def _no_socket(*args, **kwargs):
    raise AssertionError("Phase 13.7 must not open a network connection")


# -- stage helpers -----------------------------------------------------------

def _as(state: _State, role) -> _SavepointConnection:
    state.conn.switch_role(role)
    if role is not None:
        assert _scalar(state.real, "SELECT current_user") == role
    return state.conn


def _require_only_fixture_alerts(state: _State) -> None:
    """
    Stop before anything is delivered if an ALERT decision exists that is
    neither a fixture nor shielded: it would be written to the test's
    channels.
    """
    present = {
        row["decision_id"] for row in _rows(state.real, _SQL_ALERT_DECISION_IDS)
    }
    foreign = present - _ALL_ALERT_IDS - state.shielded_alerts
    if foreign:
        pytest.fail(
            f"{len(foreign)} ALERT decision(s) outside the fixtures appeared "
            "during the test; nothing was delivered"
        )


def _evaluate(state: _State, evaluated_at: datetime):
    """PRODUCTION PATH: one evaluation run as alert_evaluator."""
    conn = _as(state, _EVALUATOR)
    report = run_evaluation(conn, state.policy, evaluated_at=evaluated_at)
    # Only fixtures may ever be candidates.
    assert {r.investigation_id for r in report.results} <= set(_NAME_BY_INVESTIGATION)
    return report


def _notify(state: _State, now: datetime):
    """PRODUCTION PATH: one automatic notification run as alert_notifier."""
    conn = _as(state, _NOTIFIER)
    _require_only_fixture_alerts(state)
    report = run_notify(
        conn, state.prepared, state.policy.delivery,
        now=now, log_stream=state.unwritable,
    )
    # A decision outside the fixtures is shielded and therefore never attempted.
    for result in report.results:
        if result.decision_id not in _ALL_ALERT_IDS:
            assert result.status == STATUS_BLOCKED
            assert result.reason == REFUSAL_ALREADY_SENT
    return report


def _fixture_results(report) -> dict[tuple[str, str], object]:
    return {
        (_NAME_BY_DECISION[r.decision_id], r.channel_name): r
        for r in report.results if r.decision_id in _ALL_ALERT_IDS
    }


def _retry(state: _State, name: str, channel: str, *, confirm_resend=False,
           log_stream=None):
    """PRODUCTION PATH: one operator retry as alert_notifier."""
    conn = _as(state, _NOTIFIER)
    _require_only_fixture_alerts(state)
    (prepared,) = [p for p in state.prepared if p.config.name == channel]
    return retry_delivery(
        conn, prepared, state.policy.delivery, _did(name),
        now=_OPERATOR, confirm_resend=confirm_resend,
        log_stream=log_stream if log_stream is not None else state.unwritable,
    )


def _states(state: _State, name: str, now: datetime) -> dict[str, str]:
    """PRODUCTION PATH: the operator's view of one alert."""
    conn = _as(state, _NOTIFIER)
    view = show_alert(
        conn, state.policy.delivery.channels, state.policy.delivery, _did(name),
        now=now,
    )
    assert view.decision_id == _did(name)
    return dict(view.states)


def _guardrails(state: _State, now: datetime):
    """PRODUCTION PATH: the four guardrails as alert_evaluator."""
    conn = _as(state, _EVALUATOR)
    results = run_guardrails(
        conn, policy=state.policy, expected_groups=_EXPECTED_GROUPS, now=now,
    )
    assert tuple(result.finding.code for result in results) == GUARDRAIL_CODES
    return results


def _assert_finding(result, ids: tuple[str, ...]) -> None:
    if not ids:
        assert result.finding.status is GuardrailStatus.OK
        assert result.finding.count == 0 and result.detail_ids == ()
        return
    assert result.finding.status is GuardrailStatus.VIOLATION
    assert result.detail_ids == ids
    assert result.finding.count == len(ids)


def _assert_guardrails(results, *, uncertain, exhausted) -> None:
    checkpoints, anomalies, delivery_uncertain, delivery_exhausted = results
    # The checkpoint and anomaly findings do not change during the story.
    _assert_finding(checkpoints, (_MISSING_GROUP_ID,))
    _assert_finding(anomalies, (_UNINVESTIGATED_ANOMALY,))
    _assert_finding(delivery_uncertain, uncertain)
    _assert_finding(delivery_exhausted, exhausted)


def _deliveries(state: _State, names=_ALL_ALERTS) -> dict[tuple[str, str], list[dict]]:
    """OBSERVATION: stored attempts with outcomes, per fixture alert and channel."""
    rows = _rows(
        state.real, _SQL_FIXTURE_DELIVERIES,
        {"decision_ids": [_did(name) for name in names]},
    )
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        key = (_NAME_BY_DECISION[row["decision_id"]], row["channel_name"])
        grouped.setdefault(key, []).append(row)
    return grouped


def _attempt_count(state: _State) -> int:
    return sum(len(rows) for rows in _deliveries(state).values())


def _file_lines(state: _State) -> list[bytes]:
    data = state.file_path.read_bytes()
    assert data.endswith(b"\n")
    return data[:-1].split(b"\n")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def state(tmp_path_factory):
    import psycopg

    password = os.environ.get(_ADMIN_PASSWORD_ENV)
    if not password:
        pytest.fail(
            f"{_ADMIN_PASSWORD_ENV} must be set to run the Phase 13 end-to-end "
            "test; there is no default"
        )

    shared = _State()
    directory = tmp_path_factory.mktemp("phase-13-7")
    shared.file_path = directory / "alerts.jsonl"
    shared.broken_path = directory / "missing-directory" / "alerts.jsonl"
    shared.policy = _policy(str(shared.file_path), str(shared.broken_path))
    # A log or file channel reads nothing from the environment.
    shared.prepared = [
        preflight_channel(config, {}) for config in shared.policy.delivery.channels
    ]

    real = psycopg.connect(
        host=os.environ.get("ALERT_EVALUATOR_DB_HOST", "localhost"),
        port=int(os.environ.get("ALERT_EVALUATOR_DB_PORT", "5432")),
        dbname=os.environ.get("ALERT_EVALUATOR_DB_NAME", "agentops"),
        user=os.environ.get(_ADMIN_USER_ENV, "agentops"),
        password=password,
    )
    assert real.autocommit is False
    shared.real = real

    # From here on nothing in this process may open a network connection.
    guard = pytest.MonkeyPatch()
    guard.setattr(socket.socket, "connect", _no_socket)
    guard.setattr(socket, "create_connection", _no_socket)

    baseline = None
    after = None
    try:
        # 1. Baseline (this also opens the single outer transaction).
        baseline = _read_baseline(real)
        for name in _SQL_MARKERS:
            assert baseline[f"marker:{name}"] == 0, (
                f"{name} of Phase 13.7 already exist; a previous run leaked rows"
            )
        for name, sql in _SQL_ROWS_IN_FIXTURE_PERIOD.items():
            if _scalar(real, sql, {"start": _PERIOD_START, "end": _PERIOD_END}):
                pytest.skip(f"the database holds {name} inside the fixture period")

        # 2. What exists already and must be shielded.
        existing_investigations = _rows(real, _SQL_EXISTING_INVESTIGATIONS)
        existing_alerts = [
            row["decision_id"] for row in _rows(real, _SQL_EXISTING_ALERT_DECISIONS)
        ]

        # 3. Fixtures, as the administrator.  Never committed.
        _insert_fixtures(real)

        # 4. Product code gets savepoint-backed commit / rollback.
        shared.conn = _SavepointConnection(real)

        # 5. HARNESS SETUP: the policy row, written by the production store
        #    function as alert_evaluator, so that the shield decisions can
        #    refer to it.  run_evaluation then finds it already registered.
        conn = _as(shared, _EVALUATOR)
        assert alert_store.insert_policy(
            conn,
            policy_version=_POLICY_VERSION,
            policy_sha256=shared.policy.policy_sha256,
            policy_json=evaluation_hash_object(
                shared.policy.policy_schema_version, _POLICY_VERSION,
                shared.policy.evaluation,
            ),
        ) is True
        conn.commit()

        # 6. HARNESS SETUP: shields, as the administrator.
        _as(shared, _ADMIN)
        _insert_shields(shared, existing_investigations, existing_alerts)
        _as(shared, _EVALUATOR)

        yield shared
    finally:
        guard.undo()
        # 7. Nothing is ever committed.
        real.rollback()
        try:
            after = _read_baseline(real)
        finally:
            real.rollback()
            real.close()

    if baseline is not None and after is not None:
        assert after == baseline, (
            "the outer rollback did not restore the baseline: "
            f"before={baseline} after={after}"
        )
    # Nothing was written outside pytest's temporary directory.
    assert not shared.broken_path.parent.exists()


# ---------------------------------------------------------------------------
# E01  Roles
# ---------------------------------------------------------------------------

def test_e01_each_stage_runs_as_its_restricted_role(state):
    _as(state, _EVALUATOR)
    assert _scalar(state.real, "SELECT current_user") == _EVALUATOR
    _as(state, _NOTIFIER)
    assert _scalar(state.real, "SELECT current_user") == _NOTIFIER
    # A product rollback keeps the role.
    state.conn.rollback()
    assert _scalar(state.real, "SELECT current_user") == _NOTIFIER
    state.conn.commit()
    assert _scalar(state.real, "SELECT current_user") == _NOTIFIER


# ---------------------------------------------------------------------------
# E02  The roles cannot do each other's work
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role, statement", [
    *[(_NOTIFIER, statement) for statement in _NOTIFIER_DENIED],
    *[(_EVALUATOR, statement) for statement in _EVALUATOR_DENIED],
])
def test_e02_cross_role_statement_is_denied(state, role, statement):
    import psycopg.errors

    _as(state, role)
    # The inner savepoint keeps the refused statement from ending the outer
    # transaction, and with it the fixtures.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with state.real.transaction():
            _execute(state.real, statement)
    assert _scalar(state.real, "SELECT current_user") == role


# ---------------------------------------------------------------------------
# E03  Evaluation
# ---------------------------------------------------------------------------

def test_e03_evaluation_gives_the_six_verdicts(state):
    report = _evaluate(state, _EVALUATED_1)

    # The harness registered the policy; the evaluator checked its hash.
    assert report.policy_status == POLICY_ALREADY_REGISTERED
    assert alert_store.fetch_policy_sha256(
        state.conn, _POLICY_VERSION,
    ) == state.policy.policy_sha256

    assert report.dry_run is False and report.failures == 0
    assert [
        _NAME_BY_INVESTIGATION[r.investigation_id] for r in report.results
    ] == _PROCESSING_ORDER
    for result in report.results:
        name = _NAME_BY_INVESTIGATION[result.investigation_id]
        decision, reason, related = _EXPECTED_VERDICTS[name]
        assert result.status == STATUS_PERSISTED, name
        assert result.decision_id == _did(name), name
        assert (result.decision, result.reason_code) == (decision, reason), name
        assert result.related_decision_id == (
            _did(related) if related is not None else None
        ), name
    assert (report.alerts, report.suppressed, report.not_alertable) == (2, 2, 2)


# ---------------------------------------------------------------------------
# E04  Stored decisions
# ---------------------------------------------------------------------------

def test_e04_stored_decisions_and_payloads(state):
    _as(state, _EVALUATOR)
    rows = {
        _NAME_BY_DECISION[row["decision_id"]]: row
        for row in _rows(
            state.real, _SQL_FIXTURE_DECISIONS,
            {"decision_ids": [_did(name) for name in _FIXTURES]},
        )
    }
    assert set(rows) == set(_INITIAL)          # "late" does not exist yet

    for name in _INITIAL:
        fixture, row = _FIXTURES[name], rows[name]
        decision, reason, related = _EXPECTED_VERDICTS[name]
        assert row["investigation_id"] == fixture["investigation_id"]
        assert row["policy_version"] == _POLICY_VERSION
        assert row["anomaly_id"] == fixture["anomaly_id"]
        assert row["severity"] == fixture["severity"]
        assert row["confidence"] == "MEDIUM"
        assert row["limitations"] == [_FIXTURE_LIMITATION]
        assert row["event_time"] == fixture["event_time"]
        assert row["evaluated_at"] == _EVALUATED_1
        assert row["dedup_key"] == compute_dedup_key(
            fixture["anomaly_type"], fixture["service_name"],
            fixture["operation_name"],
        )
        assert (row["decision"], row["reason_code"]) == (decision.value, reason.value)
        assert row["related_decision_id"] == (
            _did(related) if related is not None else None
        )
        # The policy does not persist summaries.
        assert row["summary"] is None and row["summary_truncated"] is False
        assert (row["payload"] is not None) == (decision is Decision.ALERT)

    first = _FIXTURES["first"]
    assert rows["first"]["payload"] == {
        "payload_version": PAYLOAD_VERSION,
        "decision_id": first["decision_id"],
        "investigation_id": first["investigation_id"],
        "anomaly_id": first["anomaly_id"],
        "anomaly_type": "latency",
        "service_name": _FIXTURE_SERVICE,
        "operation_name": "fixture-operation-a",
        "event_time": "2001-04-01T11:40:00.000000Z",
        "evaluated_at": "2001-04-01T12:00:00.000000Z",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "limitations": [_FIXTURE_LIMITATION],
        "reason_code": "severity_met",
        "policy_version": _POLICY_VERSION,
        "advisory": ADVISORY,
    }
    escalation = rows["escalation"]["payload"]
    assert len(escalation) == 15
    assert (escalation["severity"], escalation["reason_code"]) == (
        "CRITICAL", "escalation",
    )


# ---------------------------------------------------------------------------
# E05  Guardrails before any delivery
# ---------------------------------------------------------------------------

def test_e05_guardrails_before_delivery(state):
    # Nothing was attempted and nothing has expired: no delivery finding.
    _assert_guardrails(_guardrails(state, _GUARD_BEFORE), uncertain=(), exhausted=())
    assert _attempt_count(state) == 0
    assert not state.file_path.exists()


# ---------------------------------------------------------------------------
# E06  Notification
# ---------------------------------------------------------------------------

_FIRST_RUN_OUTCOMES = {
    _CH_FILE: (DeliveryOutcome.SENT, "file_appended"),
    _CH_BROKEN: (DeliveryOutcome.FAILED_PERMANENT, "file_path_unusable"),
    _CH_LOG: (DeliveryOutcome.UNCERTAIN, "log_write_failed"),
}


def _assert_first_attempts(results, names) -> None:
    for name in names:
        for channel, (outcome, detail) in _FIRST_RUN_OUTCOMES.items():
            result = results[(name, channel)]
            assert result.status == STATUS_ATTEMPTED, (name, channel)
            assert result.state is DeliveryState.NEVER_ATTEMPTED
            assert result.attempt_no == 1
            assert result.attempt_id == compute_attempt_id(_did(name), channel, 1)
            assert (result.outcome, result.detail) == (outcome, detail)


def test_e06_notification_makes_one_attempt_per_alert_and_channel(state):
    report = _notify(state, _NOTIFY_1)
    results = _fixture_results(report)

    # Only the two alerts are discovered; suppressed and not-alertable
    # decisions never reach the notifier.
    assert set(results) == {
        (name, channel) for name in _FIRST_ALERTS for channel in _CHANNELS
    }
    # Oldest evaluation first, then decision_id; channels in policy order.
    assert [
        (_NAME_BY_DECISION[r.decision_id], r.channel_name)
        for r in report.results if r.decision_id in _ALL_ALERT_IDS
    ] == [(name, channel) for name in _FIRST_ALERTS for channel in _CHANNELS]
    _assert_first_attempts(results, _FIRST_ALERTS)
    assert state.unwritable.write_calls == 2


# ---------------------------------------------------------------------------
# E07  Stored attempts and outcomes
# ---------------------------------------------------------------------------

def test_e07_stored_attempts_and_outcomes(state):
    _as(state, _NOTIFIER)
    deliveries = _deliveries(state)
    assert set(deliveries) == {
        (name, channel) for name in _FIRST_ALERTS for channel in _CHANNELS
    }
    for (name, channel), rows in deliveries.items():
        (row,) = rows
        outcome, detail = _FIRST_RUN_OUTCOMES[channel]
        assert row["attempt_id"] == compute_attempt_id(_did(name), channel, 1)
        assert row["attempt_no"] == 1 and row["trigger"] == "auto"
        assert row["channel_type"] == _CHANNEL_TYPES[channel]
        assert row["summary_included"] is False
        assert (row["outcome"], row["detail"]) == (outcome.value, detail)
        # Database time, not the injected run time.
        assert row["started_at"] is not None and row["recorded_at"] is not None
        assert row["started_at"] > _PERIOD_END


# ---------------------------------------------------------------------------
# E08  The notification file and the body digests
# ---------------------------------------------------------------------------

def test_e08_file_holds_exactly_the_delivered_bodies(state):
    _as(state, _NOTIFIER)
    lines = _file_lines(state)
    state.file_after_first_run = state.file_path.read_bytes()
    assert len(lines) == 2

    payloads = {
        row["decision_id"]: row["payload"]
        for row in _rows(
            state.real, _SQL_PAYLOADS,
            {"decision_ids": [_did(name) for name in _FIRST_ALERTS]},
        )
    }
    deliveries = _deliveries(state)
    for name, line in zip(_FIRST_ALERTS, lines):
        body = json.loads(line)
        # The file holds the stored payload and nothing else.
        assert body == payloads[_did(name)]
        assert body["decision_id"] == _did(name)
        assert "summary" not in body and "summary_truncated" not in body
        # Every channel was given the same bytes, and each attempt recorded
        # their digest before anything was sent.
        digest = hashlib.sha256(line).hexdigest()
        for channel in _CHANNELS:
            assert deliveries[(name, channel)][0]["payload_sha256"] == digest

    # The broken channel created nothing.
    assert not state.broken_path.parent.exists()


# ---------------------------------------------------------------------------
# E09  Delivery states seen by an operator
# ---------------------------------------------------------------------------

_STATES_AFTER_FIRST_RUN = {
    _CH_FILE: "SENT",
    _CH_BROKEN: "PERMANENTLY_FAILED",
    _CH_LOG: "UNCERTAIN",
}


@pytest.mark.parametrize("name", ["first", "escalation"])
def test_e09_delivery_states(state, name):
    assert _states(state, name, _NOTIFY_1) == _STATES_AFTER_FIRST_RUN


# ---------------------------------------------------------------------------
# E10  Guardrails after delivery
# ---------------------------------------------------------------------------

def test_e10_guardrails_after_delivery(state):
    _assert_guardrails(
        _guardrails(state, _GUARD_AFTER),
        uncertain=_pairs(_FIRST_ALERTS, _CH_LOG),
        exhausted=_pairs(_FIRST_ALERTS, _CH_BROKEN),
    )


# ---------------------------------------------------------------------------
# E11  Evaluation replay
# ---------------------------------------------------------------------------

def test_e11_evaluation_replay_decides_nothing(state):
    _as(state, _EVALUATOR)
    before = _role_counts(state.real)

    report = _evaluate(state, _REPLAY)
    assert report.total == 0
    assert report.policy_status == POLICY_ALREADY_REGISTERED
    assert _role_counts(state.real) == before

    # The stored decisions keep the time of the run that made them.
    rows = _rows(
        state.real, _SQL_FIXTURE_DECISIONS,
        {"decision_ids": [_did(name) for name in _INITIAL]},
    )
    assert len(rows) == len(_INITIAL)
    assert {row["evaluated_at"] for row in rows} == {_EVALUATED_1}


# ---------------------------------------------------------------------------
# E12  Notification replay
# ---------------------------------------------------------------------------

_BLOCKED_AFTER_FIRST_RUN = {
    _CH_FILE: (DeliveryState.SENT, REFUSAL_ALREADY_SENT),
    _CH_BROKEN: (DeliveryState.PERMANENTLY_FAILED, REFUSAL_NOT_AUTO_ELIGIBLE),
    _CH_LOG: (DeliveryState.UNCERTAIN, REFUSAL_NOT_AUTO_ELIGIBLE),
}


def _assert_blocked(results, names) -> None:
    for name in names:
        for channel, (delivery_state, reason) in _BLOCKED_AFTER_FIRST_RUN.items():
            result = results[(name, channel)]
            assert result.status == STATUS_BLOCKED, (name, channel)
            assert (result.state, result.reason) == (delivery_state, reason)
            assert result.attempt_no is None and result.attempt_id is None


def test_e12_notification_replay_delivers_nothing(state):
    report = _notify(state, _REPLAY)
    results = _fixture_results(report)
    assert len(results) == 6
    _assert_blocked(results, _FIRST_ALERTS)

    assert report.attempted == 0
    assert _attempt_count(state) == 6
    assert state.file_path.read_bytes() == state.file_after_first_run
    assert state.unwritable.write_calls == 2


# ---------------------------------------------------------------------------
# E13  A late investigation
# ---------------------------------------------------------------------------

def test_e13_late_investigation_is_decided_and_delivered_once(state):
    # HARNESS SETUP: a new investigation arrives.
    _as(state, _ADMIN)
    _insert_investigation(state.real, _FIXTURES["late"], with_anomaly=True)

    # PRODUCTION PATH: it is the only candidate.
    report = _evaluate(state, _EVALUATED_LATE)
    (result,) = report.results
    assert _NAME_BY_INVESTIGATION[result.investigation_id] == "late"
    assert result.status == STATUS_PERSISTED
    assert (result.decision, result.reason_code, result.related_decision_id) == (
        Decision.ALERT, ReasonCode.SEVERITY_MET, None,
    )
    rows = _rows(
        state.real, _SQL_FIXTURE_DECISIONS,
        {"decision_ids": [_did(name) for name in _FIXTURES]},
    )
    assert len(rows) == len(_FIXTURES)
    (late_row,) = [row for row in rows if row["decision_id"] == _did("late")]
    assert late_row["evaluated_at"] == _EVALUATED_LATE
    # Evaluating again finds nothing left.
    assert _evaluate(state, _EVALUATED_LATE).total == 0

    # PRODUCTION PATH: only the new alert is delivered.
    results = _fixture_results(_notify(state, _NOTIFY_LATE))
    assert len(results) == 9
    _assert_first_attempts(results, ["late"])
    _assert_blocked(results, _FIRST_ALERTS)
    assert _attempt_count(state) == 9

    lines = _file_lines(state)
    assert len(lines) == 3
    assert state.file_path.read_bytes().startswith(state.file_after_first_run)
    assert json.loads(lines[2])["decision_id"] == _did("late")
    assert state.unwritable.write_calls == 3
    assert _states(state, "late", _NOTIFY_LATE) == _STATES_AFTER_FIRST_RUN

    # Notifying again delivers nothing.
    again = _fixture_results(_notify(state, _NOTIFY_LATE))
    _assert_blocked(again, _ALL_ALERTS)
    assert _attempt_count(state) == 9
    assert len(_file_lines(state)) == 3


# ---------------------------------------------------------------------------
# E14  Guardrails after the late alert
# ---------------------------------------------------------------------------

def test_e14_guardrails_after_the_late_alert(state):
    # The late alert was evaluated later, so it is listed last.
    _assert_guardrails(
        _guardrails(state, _GUARD_LATE),
        uncertain=_pairs(_ALL_ALERTS, _CH_LOG),
        exhausted=_pairs(_ALL_ALERTS, _CH_BROKEN),
    )


# ---------------------------------------------------------------------------
# E15  Operator retries that are refused
# ---------------------------------------------------------------------------

def test_e15_refused_operator_retries_write_nothing(state):
    file_before = state.file_path.read_bytes()

    # Uncertain: the alert may have arrived, so a resend must be confirmed.
    unconfirmed = _retry(state, "first", _CH_LOG, log_stream=io.BytesIO())
    assert unconfirmed.status == STATUS_REFUSED
    assert unconfirmed.state is DeliveryState.UNCERTAIN
    assert unconfirmed.reason == REFUSAL_CONFIRM_RESEND_REQUIRED

    # Sent: never again, confirmed or not.
    for confirm in (False, True):
        sent = _retry(state, "first", _CH_FILE, confirm_resend=confirm)
        assert sent.status == STATUS_REFUSED
        assert sent.state is DeliveryState.SENT
        assert sent.reason == REFUSAL_ALREADY_SENT

    assert _attempt_count(state) == 9
    assert state.file_path.read_bytes() == file_before
    assert state.unwritable.write_calls == 3


# ---------------------------------------------------------------------------
# E16  Confirmed resend of an uncertain delivery
# ---------------------------------------------------------------------------

def test_e16_confirmed_resend_is_delivered(state):
    stream = io.BytesIO()
    result = _retry(state, "first", _CH_LOG, confirm_resend=True, log_stream=stream)
    assert result.status == STATUS_ATTEMPTED
    assert result.state is DeliveryState.UNCERTAIN
    assert result.attempt_no == 2
    assert (result.outcome, result.detail) == (DeliveryOutcome.SENT, "log_written")

    # The log stream received the same body the file channel was given.
    first_line = _file_lines(state)[_FIRST_ALERTS.index("first")]
    assert stream.getvalue() == first_line + b"\n"

    first, second = _deliveries(state)[("first", _CH_LOG)]
    assert (first["attempt_no"], first["trigger"], first["outcome"]) == (
        1, "auto", "UNCERTAIN",
    )
    assert (second["attempt_no"], second["trigger"], second["outcome"]) == (
        2, "operator", "SENT",
    )
    assert second["attempt_id"] == compute_attempt_id(_did("first"), _CH_LOG, 2)
    assert second["payload_sha256"] == hashlib.sha256(first_line).hexdigest()

    assert _states(state, "first", _OPERATOR)[_CH_LOG] == "SENT"
    assert _attempt_count(state) == 10


# ---------------------------------------------------------------------------
# E17  Operator retry of a permanent failure
# ---------------------------------------------------------------------------

def test_e17_retry_of_a_permanent_failure_fails_again(state):
    result = _retry(state, "escalation", _CH_BROKEN)
    assert result.status == STATUS_ATTEMPTED
    assert result.state is DeliveryState.PERMANENTLY_FAILED
    assert result.attempt_no == 2
    assert (result.outcome, result.detail) == (
        DeliveryOutcome.FAILED_PERMANENT, "file_path_unusable",
    )

    attempts = _deliveries(state)[("escalation", _CH_BROKEN)]
    assert [(row["attempt_no"], row["trigger"], row["outcome"]) for row in attempts] == [
        (1, "auto", "FAILED_PERMANENT"), (2, "operator", "FAILED_PERMANENT"),
    ]
    assert _states(state, "escalation", _OPERATOR) == _STATES_AFTER_FIRST_RUN
    assert _attempt_count(state) == 11
    assert not state.broken_path.parent.exists()

    # The automatic run still leaves everything alone.
    again = _fixture_results(_notify(state, _OPERATOR))
    assert all(result.status == STATUS_BLOCKED for result in again.values())
    assert _attempt_count(state) == 11


# ---------------------------------------------------------------------------
# E18  Guardrails after the operator's actions
# ---------------------------------------------------------------------------

def test_e18_guardrails_after_operator_actions(state):
    still_uncertain = [name for name in _ALL_ALERTS if name != "first"]
    _assert_guardrails(
        _guardrails(state, _GUARD_FINAL),
        # The confirmed resend arrived: that pair is no longer uncertain.
        uncertain=_pairs(still_uncertain, _CH_LOG),
        # A failed retry changes nothing: all three are still reported.
        exhausted=_pairs(_ALL_ALERTS, _CH_BROKEN),
    )


# ---------------------------------------------------------------------------
# E19  Guardrails are repeatable and write nothing
# ---------------------------------------------------------------------------

def test_e19_guardrails_are_repeatable_and_write_nothing(state):
    _as(state, _EVALUATOR)
    before = _role_counts(state.real)
    commits, rollbacks = state.conn.commits, state.conn.rollbacks

    first = _guardrails(state, _GUARD_FINAL)
    second = _guardrails(state, _GUARD_FINAL)

    assert first == second
    assert _role_counts(state.real) == before
    # The guardrails never end a transaction themselves.
    assert (state.conn.commits, state.conn.rollbacks) == (commits, rollbacks)
    assert state.conn.closes == 0
