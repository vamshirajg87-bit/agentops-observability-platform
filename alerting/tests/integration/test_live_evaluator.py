"""
alerting/tests/integration/test_live_evaluator.py

Opt-in integration test of the alert evaluator against live PostgreSQL
(Phase 13.4).  It checks what mocks cannot: the statements themselves, the
window boundaries in SQL, first-write-wins, the table constraints, JSONB and
TEXT[] adaptation, and the privileges of the alert_evaluator role.

This is not the Phase 13 live end-to-end test.  It sends nothing and uses no
network other than the database connection.

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
  2. Insert fixture anomalies and investigations as the administrator.
  3. SET LOCAL ROLE alert_evaluator.  From here on every statement is
     permission-checked as the restricted role.
  4. Run the real evaluator and store on this same connection.
  5. ROLLBACK, then require the counts to equal the baseline.

The product code calls commit() and rollback() itself.  It is given a wrapper
(_SavepointConnection) that maps those calls onto a savepoint inside the
outer transaction, so a product commit never makes anything durable and a
product rollback never discards the fixtures.  Production transaction
semantics are not changed.

Fixtures
--------
Seven investigations, identified by fixture analyzer_version values, with
event times in an isolated period (2001-01-01) so that no real alert falls
into their windows.  investigation_id is computed by the real Phase 11
formula SHA-256(anomaly_id | analyzer_version).  No DELETE, TRUNCATE, or
reset is used anywhere.

The evaluation also processes the real investigations of the database, under
a fixture policy version; those decisions are rolled back with everything
else and are compared only between the dry run and the real run.

The fixture SQL below exists only in this test.  Production SQL lives only in
alert_store.py.

Test inventory:
    L01  the statements run as the restricted role
    L02  restricted-role privileges are enforced
    L03  dry run: expected verdicts, no row written, no commit
    L04  real run: expected verdicts, equal to the dry run
    L05  stored decision and policy rows
    L06  history statements: boundaries, duplicate without time bound
    L07  rerun decides nothing new
    L08  policy version conflict writes nothing
    L09  first-write-wins on (investigation_id, policy_version)
    (teardown) outer rollback restores the baseline
"""

from __future__ import annotations

import hashlib
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

import alert_store  # noqa: E402
from alert_evaluator import (  # noqa: E402
    ADVISORY,
    POLICY_ALREADY_REGISTERED,
    POLICY_NOT_REGISTERED,
    POLICY_REGISTERED,
    STATUS_DRY_RUN,
    STATUS_PERSISTED,
    PolicyVersionConflictError,
    run_evaluation,
)
from alert_identity import compute_decision_id, compute_dedup_key  # noqa: E402
from alert_models import (  # noqa: E402
    AlertDecision,
    Confidence,
    Decision,
    ReasonCode,
    Severity,
)
from alert_policy import evaluation_hash_object, validate_policy  # noqa: E402


_ROLE = "alert_evaluator"
_POLICY_VERSION = "phase-13.4-live-test"
_FIXTURE_VERSION_A = "phase-13.4-fixture-a"
_FIXTURE_VERSION_B = "phase-13.4-fixture-b"
_FIXTURE_DETECTOR_VERSION = "phase-13.4-fixture"
_FIXTURE_SERVICE = "phase-13-4-fixture-service"

_SAVEPOINT = "phase_13_4_product_tx"

_BASE = datetime(2001, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_EVALUATED_AT = _BASE + timedelta(minutes=45)

_KEY = ("latency", _FIXTURE_SERVICE, "fixture-operation-a")
_OTHER_KEY = ("error_rate", _FIXTURE_SERVICE, "fixture-operation-b")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _anomaly_id(label: str) -> str:
    return _sha256(f"phase-13.4-fixture-anomaly-{label}")


def _investigation_id(anomaly_id: str, analyzer_version: str) -> str:
    """The Phase 11 investigation identity formula."""
    return _sha256(f"{anomaly_id}|{analyzer_version}")


def _fixture(name, anomaly, version, minutes, severity, key=_KEY) -> dict:
    anomaly_id = _anomaly_id(anomaly)
    investigation_id = _investigation_id(anomaly_id, version)
    return {
        "name": name,
        "anomaly_id": anomaly_id,
        "analyzer_version": version,
        "investigation_id": investigation_id,
        "decision_id": compute_decision_id(investigation_id, _POLICY_VERSION),
        "anomaly_type": key[0],
        "service_name": key[1],
        "operation_name": key[2],
        "event_time": _BASE + timedelta(minutes=minutes),
        "severity": severity,
    }


# Processing order is event_time, then investigation_id:
#   stale, first, duplicate, info, cooldown, boundary, escalation
_FIXTURES = {
    f["name"]: f for f in [
        _fixture("first", "1", _FIXTURE_VERSION_A, 0, "WARNING"),
        # Same anomaly as "first", investigated by another analyzer version.
        _fixture("duplicate", "1", _FIXTURE_VERSION_B, 1, "WARNING"),
        _fixture("cooldown", "3", _FIXTURE_VERSION_A, 10, "WARNING"),
        # Exactly cooldown_minutes after "first": outside its window.
        _fixture("boundary", "4", _FIXTURE_VERSION_A, 30, "WARNING"),
        _fixture("info", "5", _FIXTURE_VERSION_A, 5, "INFO", _OTHER_KEY),
        _fixture("stale", "6", _FIXTURE_VERSION_A, -120, "CRITICAL", _OTHER_KEY),
        _fixture("escalation", "7", _FIXTURE_VERSION_A, 35, "CRITICAL"),
    ]
}


def _expected_verdicts() -> dict[str, tuple]:
    first = _FIXTURES["first"]["decision_id"]
    boundary = _FIXTURES["boundary"]["decision_id"]
    return {
        "first": (Decision.ALERT, ReasonCode.SEVERITY_MET, None),
        "duplicate": (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, first),
        "cooldown": (Decision.SUPPRESSED, ReasonCode.COOLDOWN, first),
        "boundary": (Decision.ALERT, ReasonCode.SEVERITY_MET, None),
        "info": (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None),
        "stale": (Decision.NOT_ALERTABLE, ReasonCode.STALE, None),
        "escalation": (Decision.ALERT, ReasonCode.ESCALATION, boundary),
    }


def _policy(**evaluation):
    return validate_policy({
        "policy_schema_version": "1.0.0",
        "policy_version": _POLICY_VERSION,
        "evaluation": evaluation,
        "delivery": {"channels": []},
        "guardrails": {},
    })


# ---------------------------------------------------------------------------
# Fixture SQL (administrator; never committed)
# ---------------------------------------------------------------------------

_SQL_BASELINE = {
    "anomaly_events": "SELECT count(*) FROM public.anomaly_events",
    "rca_investigations": "SELECT count(*) FROM public.rca_investigations",
    "rca_evidence": "SELECT count(*) FROM public.rca_evidence",
    "alert_policies": "SELECT count(*) FROM public.alert_policies",
    "alert_decisions": "SELECT count(*) FROM public.alert_decisions",
    "alert_delivery_attempts": "SELECT count(*) FROM public.alert_delivery_attempts",
    "alert_delivery_outcomes": "SELECT count(*) FROM public.alert_delivery_outcomes",
    "fixture_anomalies":
        "SELECT count(*) FROM public.anomaly_events "
        "WHERE detector_version = 'phase-13.4-fixture'",
    "fixture_investigations":
        "SELECT count(*) FROM public.rca_investigations "
        "WHERE analyzer_version LIKE 'phase-13.4-fixture-%'",
    "fixture_policies":
        "SELECT count(*) FROM public.alert_policies "
        "WHERE policy_version = 'phase-13.4-live-test'",
}

_SQL_ALERTS_NEAR_FIXTURES = """\
SELECT count(*)
FROM public.alert_decisions
WHERE event_time > %(start)s
  AND event_time < %(end)s
"""

_SQL_INSERT_ANOMALY = """\
INSERT INTO public.anomaly_events (
    anomaly_id, anomaly_type, signal_name, detector_name, detector_version,
    service_name, operation_name, observed_value, event_time, severity,
    explanation
) VALUES (
    %(anomaly_id)s, %(anomaly_type)s, 'phase-13.4-fixture-signal',
    'phase-13.4-fixture-detector', 'phase-13.4-fixture',
    %(service_name)s, %(operation_name)s, 1.0, %(event_time)s, %(severity)s,
    'Phase 13.4 fixture: temporary validation row, never committed.'
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
    'Phase 13.4 fixture summary: temporary validation row, never committed.',
    ARRAY['phase-13.4 fixture limitation']::text[]
)
"""

# Read-only verification SQL (run as the restricted role)
_SQL_COUNT_DECISIONS = "SELECT count(decision_id) FROM public.alert_decisions"
_SQL_COUNT_POLICIES = "SELECT count(policy_version) FROM public.alert_policies"

_SQL_DECISION_ROW = """\
SELECT
    decision_id, investigation_id, policy_version, anomaly_id, anomaly_type,
    service_name, operation_name, event_time, severity, confidence,
    limitations, dedup_key, decision, reason_code, related_decision_id,
    evaluated_at, payload, summary, summary_truncated,
    decided_at IS NOT NULL AS has_decided_at
FROM public.alert_decisions
WHERE decision_id = %(decision_id)s
"""

_SQL_POLICY_ROW = """\
SELECT policy_sha256, policy_json, registered_at IS NOT NULL AS has_registered_at
FROM public.alert_policies
WHERE policy_version = %(policy_version)s
"""

_DENIED_STATEMENTS = [
    "UPDATE public.alert_decisions SET summary = summary WHERE false",
    "DELETE FROM public.alert_decisions WHERE false",
    "TRUNCATE public.alert_decisions",
    "UPDATE public.alert_policies SET policy_sha256 = policy_sha256 WHERE false",
    "DELETE FROM public.alert_policies WHERE false",
    "UPDATE public.rca_investigations SET summary = summary WHERE false",
    "DELETE FROM public.rca_investigations WHERE false",
    "SELECT analyzer_version FROM public.rca_investigations LIMIT 1",
    "SELECT trace_id FROM public.rca_investigations LIMIT 1",
    "SELECT explanation FROM public.rca_evidence LIMIT 1",
    "SELECT embedding_id FROM public.rca_investigation_embeddings LIMIT 1",
    "SELECT count(*) FROM public.telemetry_spans",
    "SELECT severity FROM public.anomaly_events LIMIT 1",
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

        commit()    release the savepoint and open a new one
        rollback()  roll back to the savepoint (the fixtures, created before
                    it, survive)
        close()     no-op; the test owns the real connection
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


class _State:
    """Shared between the ordered tests of this module."""

    def __init__(self) -> None:
        self.conn = None
        self.baseline: dict = {}
        self.dry = None
        self.real = None
        self.decisions_after_real_run = 0


# params is passed through as None when a statement has no parameters, so
# that a literal "%" in the SQL (LIKE patterns) is not read as a placeholder.

def _scalar(conn, sql: str, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def _row(conn, sql: str, params=None) -> dict | None:
    import psycopg.rows

    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def _execute(conn, sql: str, params=None) -> int:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def _read_baseline(conn) -> dict:
    return {name: _scalar(conn, sql) for name, sql in _SQL_BASELINE.items()}


def _fixture_verdicts(report) -> dict[str, tuple]:
    by_id = {result.investigation_id: result for result in report.results}
    verdicts = {}
    for name, fixture in _FIXTURES.items():
        result = by_id[fixture["investigation_id"]]
        assert result.decision_id == fixture["decision_id"]
        verdicts[name] = (
            result.decision, result.reason_code, result.related_decision_id,
        )
    return verdicts


def _history_ids(conn, **overrides) -> set[str]:
    params = dict(
        anomaly_id=_anomaly_id("no-such-anomaly"),
        dedup_key=compute_dedup_key(*_KEY),
        event_time=_BASE + timedelta(minutes=30),
        cooldown_start=_BASE,
        # An empty storm window, so that only the other statements answer.
        storm_start=_BASE + timedelta(minutes=30),
    )
    params.update(overrides)
    rows = alert_store.fetch_alert_history(conn, **params)
    assert all(row["decision"] == "ALERT" for row in rows)
    fixture_ids = {f["decision_id"] for f in _FIXTURES.values()}
    return {row["decision_id"] for row in rows} & fixture_ids


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def state():
    import psycopg

    password = os.environ.get(_ADMIN_PASSWORD_ENV)
    if not password:
        pytest.fail(
            f"{_ADMIN_PASSWORD_ENV} must be set to run the live evaluator "
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

    shared = _State()
    baseline = None
    after = None
    try:
        # 1. Baseline (this also opens the single outer transaction).
        baseline = _read_baseline(real)
        shared.baseline = baseline
        for name in ("fixture_anomalies", "fixture_investigations", "fixture_policies"):
            assert baseline[name] == 0, (
                f"{name} already exist; a previous run leaked rows"
            )
        nearby = _scalar(real, _SQL_ALERTS_NEAR_FIXTURES, {
            "start": _BASE - timedelta(days=2), "end": _BASE + timedelta(days=2),
        })
        if nearby:
            pytest.skip("the database holds decisions inside the fixture period")

        # 2. Fixtures, as the administrator.  Never committed.
        inserted_anomalies = set()
        for fixture in _FIXTURES.values():
            if fixture["anomaly_id"] not in inserted_anomalies:
                assert _execute(real, _SQL_INSERT_ANOMALY, fixture) == 1
                inserted_anomalies.add(fixture["anomaly_id"])
            assert _execute(real, _SQL_INSERT_INVESTIGATION, fixture) == 1

        # 3. Everything after this is permission-checked as the restricted role.
        _execute(real, f"SET LOCAL ROLE {_ROLE}")

        # 4. Product code gets savepoint-backed commit / rollback.
        shared.conn = _SavepointConnection(real)

        yield shared
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


@pytest.fixture
def conn(state) -> _SavepointConnection:
    return state.conn


# ---------------------------------------------------------------------------
# L01  Role
# ---------------------------------------------------------------------------

def test_l01_statements_run_as_the_restricted_role(conn):
    assert _scalar(conn, "SELECT current_user") == _ROLE


# ---------------------------------------------------------------------------
# L02  Privileges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("statement", _DENIED_STATEMENTS)
def test_l02_restricted_role_is_denied(conn, statement):
    import psycopg.errors

    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _execute(conn, statement)
    finally:
        conn.rollback()


def test_l02_granted_reads_work(conn):
    assert _scalar(conn, _SQL_COUNT_DECISIONS) is not None
    assert _scalar(conn, _SQL_COUNT_POLICIES) is not None
    assert _scalar(
        conn, "SELECT count(investigation_id) FROM public.rca_investigations",
    ) >= len(_FIXTURES)


# ---------------------------------------------------------------------------
# L03  Dry run
# ---------------------------------------------------------------------------

def test_l03_dry_run_writes_nothing(state, conn):
    decisions = _scalar(conn, _SQL_COUNT_DECISIONS)
    policies = _scalar(conn, _SQL_COUNT_POLICIES)
    commits = conn.commits

    report = run_evaluation(
        conn, _policy(), evaluated_at=_EVALUATED_AT, dry_run=True,
    )

    assert report.policy_status == POLICY_NOT_REGISTERED
    assert report.failures == 0
    assert {r.status for r in report.results} == {STATUS_DRY_RUN}
    assert _fixture_verdicts(report) == _expected_verdicts()
    assert conn.commits == commits
    assert _scalar(conn, _SQL_COUNT_DECISIONS) == decisions
    assert _scalar(conn, _SQL_COUNT_POLICIES) == policies
    state.dry = report


def test_l03_candidates_are_ordered_by_event_time_then_id(state):
    fixture_ids = [f["investigation_id"] for f in _FIXTURES.values()]
    seen = [
        r.investigation_id for r in state.dry.results
        if r.investigation_id in fixture_ids
    ]
    expected = [
        f["investigation_id"] for f in sorted(
            _FIXTURES.values(),
            key=lambda f: (f["event_time"], f["investigation_id"]),
        )
    ]
    assert seen == expected


# ---------------------------------------------------------------------------
# L04  Real run
# ---------------------------------------------------------------------------

def test_l04_real_run_matches_the_dry_run(state, conn):
    decisions = _scalar(conn, _SQL_COUNT_DECISIONS)
    policies = _scalar(conn, _SQL_COUNT_POLICIES)
    commits = conn.commits

    report = run_evaluation(conn, _policy(), evaluated_at=_EVALUATED_AT)

    assert report.policy_status == POLICY_REGISTERED
    assert report.failures == 0
    assert {r.status for r in report.results} == {STATUS_PERSISTED}
    assert _fixture_verdicts(report) == _expected_verdicts()

    dry = state.dry
    assert [r.investigation_id for r in report.results] == [
        r.investigation_id for r in dry.results
    ]
    assert [
        (r.decision_id, r.decision, r.reason_code, r.related_decision_id)
        for r in report.results
    ] == [
        (r.decision_id, r.decision, r.reason_code, r.related_decision_id)
        for r in dry.results
    ]

    # One commit for the policy and one for every decision.
    assert conn.commits == commits + 1 + report.total
    assert _scalar(conn, _SQL_COUNT_POLICIES) == policies + 1
    assert _scalar(conn, _SQL_COUNT_DECISIONS) == decisions + report.total
    state.real = report
    state.decisions_after_real_run = decisions + report.total


# ---------------------------------------------------------------------------
# L05  Stored rows
# ---------------------------------------------------------------------------

def test_l05_stored_alert_row(conn):
    fixture = _FIXTURES["first"]
    row = _row(conn, _SQL_DECISION_ROW, {"decision_id": fixture["decision_id"]})

    assert row["investigation_id"] == fixture["investigation_id"]
    assert row["policy_version"] == _POLICY_VERSION
    assert row["anomaly_id"] == fixture["anomaly_id"]
    assert (row["anomaly_type"], row["service_name"], row["operation_name"]) == _KEY
    assert row["event_time"] == _BASE
    assert row["severity"] == "WARNING"
    assert row["confidence"] == "MEDIUM"
    assert row["limitations"] == ["phase-13.4 fixture limitation"]
    assert row["dedup_key"] == compute_dedup_key(*_KEY)
    assert (row["decision"], row["reason_code"]) == ("ALERT", "severity_met")
    assert row["related_decision_id"] is None
    assert row["evaluated_at"] == _EVALUATED_AT
    assert row["has_decided_at"] is True

    # persist_summary is false by default.
    assert row["summary"] is None
    assert row["summary_truncated"] is False

    assert row["payload"] == {
        "payload_version": "1.0.0",
        "decision_id": fixture["decision_id"],
        "investigation_id": fixture["investigation_id"],
        "anomaly_id": fixture["anomaly_id"],
        "anomaly_type": _KEY[0],
        "service_name": _KEY[1],
        "operation_name": _KEY[2],
        "event_time": "2001-01-01T12:00:00.000000Z",
        "evaluated_at": "2001-01-01T12:45:00.000000Z",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "limitations": ["phase-13.4 fixture limitation"],
        "reason_code": "severity_met",
        "policy_version": _POLICY_VERSION,
        "advisory": ADVISORY,
    }


def test_l05_stored_non_alert_rows_have_no_payload(conn):
    for name in ("duplicate", "cooldown", "info", "stale"):
        row = _row(conn, _SQL_DECISION_ROW, {
            "decision_id": _FIXTURES[name]["decision_id"],
        })
        expected = _expected_verdicts()[name]
        assert row["decision"] == expected[0].value
        assert row["reason_code"] == expected[1].value
        assert row["related_decision_id"] == expected[2]
        assert row["payload"] is None
        assert row["summary"] is None and row["summary_truncated"] is False


def test_l05_escalation_row_refers_to_the_alert_it_escalates_over(conn):
    row = _row(conn, _SQL_DECISION_ROW, {
        "decision_id": _FIXTURES["escalation"]["decision_id"],
    })
    assert (row["decision"], row["reason_code"]) == ("ALERT", "escalation")
    assert row["related_decision_id"] == _FIXTURES["boundary"]["decision_id"]
    assert "related_decision_id" not in row["payload"]
    assert len(row["payload"]) == 15


def test_l05_stored_policy_row(conn):
    policy = _policy()
    row = _row(conn, _SQL_POLICY_ROW, {"policy_version": _POLICY_VERSION})
    assert row["policy_sha256"] == policy.policy_sha256
    assert row["policy_json"] == evaluation_hash_object(
        policy.policy_schema_version, policy.policy_version, policy.evaluation,
    )
    assert row["has_registered_at"] is True


# ---------------------------------------------------------------------------
# L06  History statements
# ---------------------------------------------------------------------------

def test_l06_cooldown_lower_bound_is_exclusive(conn):
    first = _FIXTURES["first"]["decision_id"]
    boundary = _FIXTURES["boundary"]["decision_id"]
    # "first" is exactly at cooldown_start.
    assert _history_ids(conn) == {boundary}
    assert _history_ids(
        conn, cooldown_start=_BASE - timedelta(microseconds=1),
    ) == {first, boundary}


def test_l06_upper_bound_is_inclusive_and_later_alerts_are_excluded(conn):
    boundary = _FIXTURES["boundary"]["decision_id"]
    just_before = _BASE + timedelta(minutes=30) - timedelta(microseconds=1)
    assert _history_ids(conn, event_time=just_before, storm_start=just_before) == set()
    assert _history_ids(conn) == {boundary}


def test_l06_cooldown_is_limited_to_the_dedup_key(conn):
    assert _history_ids(conn, dedup_key=compute_dedup_key(*_OTHER_KEY)) == set()


def test_l06_storm_covers_every_dedup_key_with_an_exclusive_lower_bound(conn):
    alerts = {
        _FIXTURES[name]["decision_id"] for name in ("first", "boundary", "escalation")
    }
    wide = dict(
        dedup_key="0" * 64,
        event_time=_BASE + timedelta(minutes=40),
        cooldown_start=_BASE + timedelta(minutes=40),
    )
    assert _history_ids(
        conn, storm_start=_BASE - timedelta(microseconds=1), **wide,
    ) == alerts
    # "first" is exactly at storm_start.
    assert _history_ids(conn, storm_start=_BASE, **wide) == alerts - {
        _FIXTURES["first"]["decision_id"],
    }


def test_l06_duplicate_has_no_time_bound(conn):
    first = _FIXTURES["first"]["decision_id"]
    long_before = _BASE - timedelta(days=365)
    assert _history_ids(
        conn,
        anomaly_id=_FIXTURES["first"]["anomaly_id"],
        dedup_key="0" * 64,
        event_time=long_before,
        cooldown_start=long_before,
        storm_start=long_before,
    ) == {first}


def test_l06_only_alert_decisions_are_history(conn):
    suppressed = _FIXTURES["cooldown"]
    ids = _history_ids(
        conn,
        anomaly_id=suppressed["anomaly_id"],
        event_time=_BASE + timedelta(minutes=40),
        cooldown_start=_BASE - timedelta(minutes=1),
        storm_start=_BASE - timedelta(minutes=1),
    )
    assert suppressed["decision_id"] not in ids
    assert _FIXTURES["info"]["decision_id"] not in ids


# ---------------------------------------------------------------------------
# L07  Rerun
# ---------------------------------------------------------------------------

def test_l07_rerun_decides_nothing_new(state, conn):
    report = run_evaluation(
        conn, _policy(), evaluated_at=_EVALUATED_AT + timedelta(hours=1),
    )
    assert report.policy_status == POLICY_ALREADY_REGISTERED
    assert report.total == 0
    assert _scalar(conn, _SQL_COUNT_DECISIONS) == state.decisions_after_real_run


# ---------------------------------------------------------------------------
# L08  Policy version conflict
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dry_run", [True, False])
def test_l08_policy_version_conflict_writes_nothing(state, conn, dry_run):
    stored = _row(conn, _SQL_POLICY_ROW, {"policy_version": _POLICY_VERSION})
    with pytest.raises(PolicyVersionConflictError):
        run_evaluation(
            conn, _policy(cooldown_minutes=31),
            evaluated_at=_EVALUATED_AT, dry_run=dry_run,
        )
    assert _row(conn, _SQL_POLICY_ROW, {"policy_version": _POLICY_VERSION}) == stored
    assert _scalar(conn, _SQL_COUNT_DECISIONS) == state.decisions_after_real_run


# ---------------------------------------------------------------------------
# L09  First-write-wins
# ---------------------------------------------------------------------------

def test_l09_existing_decision_is_never_overwritten(state, conn):
    fixture = _FIXTURES["first"]
    before = _row(conn, _SQL_DECISION_ROW, {"decision_id": fixture["decision_id"]})

    different = AlertDecision(
        decision_id=fixture["decision_id"],
        investigation_id=fixture["investigation_id"],
        policy_version=_POLICY_VERSION,
        anomaly_id=fixture["anomaly_id"],
        anomaly_type=fixture["anomaly_type"],
        service_name=fixture["service_name"],
        operation_name=fixture["operation_name"],
        event_time=fixture["event_time"],
        severity=Severity.WARNING,
        confidence=Confidence.LOW,
        limitations=(),
        dedup_key=compute_dedup_key(*_KEY),
        decision=Decision.SUPPRESSED,
        reason_code=ReasonCode.STORM_CAP,
        related_decision_id=None,
        evaluated_at=_EVALUATED_AT + timedelta(hours=2),
        payload=None,
    )
    try:
        assert alert_store.insert_decision(conn, different) is False
    finally:
        conn.rollback()

    assert _row(conn, _SQL_DECISION_ROW, {"decision_id": fixture["decision_id"]}) == before
    assert _scalar(conn, _SQL_COUNT_DECISIONS) == state.decisions_after_real_run
