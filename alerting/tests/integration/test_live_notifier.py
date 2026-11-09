"""
alerting/tests/integration/test_live_notifier.py

Opt-in integration test of the alert notifier against live PostgreSQL
(Phase 13.5).  It checks what mocks cannot: the statements themselves, the
privileges of the alert_notifier role, the uniqueness and foreign-key
constraints of the delivery tables, the database-generated timestamps, and
delivery states derived from real rows.

This is not the Phase 13 live end-to-end test.  Deliveries go only to an
in-memory stream, a file in pytest's temporary directory, and an HTTP server
started by the test on 127.0.0.1.  No external network is used.

Skipped by default.  It runs only when the switch is set:

    ALERTING_RUN_DB_TESTS=1

and an administrator password is supplied through the environment:

    ALERTING_E2E_ADMIN_PASSWORD   required; there is no default
    ALERTING_E2E_ADMIN_USER       default: agentops

Host, port and database come from ALERT_NOTIFIER_DB_HOST / _PORT / _NAME
(defaults localhost / 5432 / agentops).  The alert_notifier password is NOT
needed.  Migrations 012 and 014 must be applied.

Nothing is ever committed
-------------------------
The whole module runs inside ONE transaction on ONE administrator connection,
and that transaction is rolled back when the module finishes:

  1. Record baseline row counts.
  2. Insert a fixture policy, anomalies, investigations and decisions as the
     administrator.
  3. SET LOCAL ROLE alert_notifier.  From here on every statement is
     permission-checked as the restricted role.
  4. Run the real notifier and store on this same connection.
  5. ROLLBACK, then require the counts to equal the baseline.

The product code calls commit() and rollback() itself.  It is given a wrapper
(_SavepointConnection) that maps those calls onto a savepoint inside the
outer transaction, so a product commit never makes anything durable and a
product rollback never discards the fixtures.  Production transaction
semantics are not changed.

Fixtures
--------
Four decisions under a fixture policy version, evaluated in an isolated
period (2001-02-01): two fresh alerts (one with a stored summary), one old
alert that is past the delivery age, and one suppressed decision.  The run
time handed to the notifier is in the same period.  Attempt rows get their
started_at from the database, so they are later than that run time.

The notifier also processes any real ALERT decision in the database; those
deliveries go to the test-local channels and are rolled back with everything
else.

The fixture SQL below exists only in this test.  Production SQL lives only in
alert_delivery_store.py.

Test inventory:
    N01  the statements run as the restricted role
    N02  restricted-role privileges are enforced
    N03  discovery: ALERT only, order, granted columns
    N04  dry run: expected actions, no row written, no commit, no delivery
    N05  real run: attempts, deliveries, outcomes
    N06  stored attempt and outcome rows
    N07  rerun delivers nothing more
    N08  uniqueness and foreign key of the delivery tables
    N09  operator retry: expired allowed, sent refused
    N10  states from real rows: retryable-then-expired, in flight, uncertain
    N11  read-only views
    (teardown) outer rollback restores the baseline
"""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import threading
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

import alert_delivery_store  # noqa: E402
from alert_channels import (  # noqa: E402
    SendResult,
    build_body,
    preflight_channel,
)
from alert_delivery_state import DeliveryState  # noqa: E402
from alert_identity import (  # noqa: E402
    compute_attempt_id,
    compute_decision_id,
    compute_dedup_key,
)
from alert_models import ChannelType, DeliveryOutcome  # noqa: E402
from alert_notifier import (  # noqa: E402
    STATUS_ATTEMPTED,
    STATUS_BLOCKED,
    STATUS_REFUSED,
    STATUS_WOULD_ATTEMPT,
    DecisionNotFoundError,
    list_alerts,
    retry_delivery,
    run_notify,
    show_alert,
)
from alert_policy import ChannelConfig, DeliveryPolicy  # noqa: E402


_ROLE = "alert_notifier"
_POLICY_VERSION = "phase-13.5-live-test"
_FIXTURE_ANALYZER_VERSION = "phase-13.5-fixture"
_FIXTURE_DETECTOR_VERSION = "phase-13.5-fixture"
_FIXTURE_SERVICE = "phase-13-5-fixture-service"
_FIXTURE_SUMMARY = "Phase 13.5 fixture summary: temporary row, never committed."

_SAVEPOINT = "phase_13_5_product_tx"

_BASE = datetime(2001, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
_NOW = _BASE + timedelta(minutes=5)
_MUCH_LATER = datetime(2099, 1, 1, tzinfo=timezone.utc)

_KEY = ("latency", _FIXTURE_SERVICE, "fixture-operation")

O = DeliveryOutcome
S = DeliveryState


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fixture(name: str, minutes: float, decision: str, reason: str, summary=None) -> dict:
    anomaly_id = _sha256(f"phase-13.5-fixture-anomaly-{name}")
    investigation_id = _sha256(f"{anomaly_id}|{_FIXTURE_ANALYZER_VERSION}")
    decision_id = compute_decision_id(investigation_id, _POLICY_VERSION)
    evaluated_at = _BASE + timedelta(minutes=minutes)
    payload = None
    if decision == "ALERT":
        payload = {
            "payload_version": "1.0.0",
            "decision_id": decision_id,
            "investigation_id": investigation_id,
            "anomaly_id": anomaly_id,
            "anomaly_type": _KEY[0],
            "service_name": _KEY[1],
            "operation_name": _KEY[2],
            "severity": "CRITICAL",
            "confidence": "MEDIUM",
            "limitations": ["phase-13.5 fixture limitation"],
            "reason_code": reason,
            "policy_version": _POLICY_VERSION,
            "advisory": "phase-13.5 fixture",
        }
    return {
        "name": name,
        "anomaly_id": anomaly_id,
        "investigation_id": investigation_id,
        "decision_id": decision_id,
        "evaluated_at": evaluated_at,
        "event_time": evaluated_at,
        "decision": decision,
        "reason_code": reason,
        "payload": payload,
        "summary": summary,
    }


_FIXTURES = {
    f["name"]: f for f in [
        _fixture("fresh", 0, "ALERT", "severity_met"),
        _fixture("summary", 1, "ALERT", "severity_met", summary=_FIXTURE_SUMMARY),
        _fixture("old", -600, "ALERT", "severity_met"),
        _fixture("suppressed", 0, "SUPPRESSED", "storm_cap"),
    ]
}
_ALERTS = ("old", "fresh", "summary")          # evaluated_at order
_FIXTURE_IDS = {f["decision_id"]: name for name, f in _FIXTURES.items()}


# ---------------------------------------------------------------------------
# Fixture SQL (administrator; never committed)
# ---------------------------------------------------------------------------

_SQL_BASELINE = {
    "anomaly_events": "SELECT count(*) FROM public.anomaly_events",
    "rca_investigations": "SELECT count(*) FROM public.rca_investigations",
    "alert_policies": "SELECT count(*) FROM public.alert_policies",
    "alert_decisions": "SELECT count(*) FROM public.alert_decisions",
    "alert_delivery_attempts": "SELECT count(*) FROM public.alert_delivery_attempts",
    "alert_delivery_outcomes": "SELECT count(*) FROM public.alert_delivery_outcomes",
    "fixture_anomalies":
        "SELECT count(*) FROM public.anomaly_events "
        "WHERE detector_version = 'phase-13.5-fixture'",
    "fixture_investigations":
        "SELECT count(*) FROM public.rca_investigations "
        "WHERE analyzer_version = 'phase-13.5-fixture'",
    "fixture_policies":
        "SELECT count(*) FROM public.alert_policies "
        "WHERE policy_version = 'phase-13.5-live-test'",
}

_SQL_INSERT_POLICY = """\
INSERT INTO public.alert_policies (policy_version, policy_sha256, policy_json)
VALUES (%(policy_version)s, %(policy_sha256)s, '{}'::jsonb)
"""

_SQL_INSERT_ANOMALY = """\
INSERT INTO public.anomaly_events (
    anomaly_id, anomaly_type, signal_name, detector_name, detector_version,
    service_name, operation_name, observed_value, event_time, severity,
    explanation
) VALUES (
    %(anomaly_id)s, 'latency', 'phase-13.5-fixture-signal',
    'phase-13.5-fixture-detector', 'phase-13.5-fixture',
    %(service_name)s, %(operation_name)s, 1.0, %(event_time)s, 'CRITICAL',
    'Phase 13.5 fixture: temporary validation row, never committed.'
)
"""

_SQL_INSERT_INVESTIGATION = """\
INSERT INTO public.rca_investigations (
    investigation_id, anomaly_id, analyzer_version, service_name,
    operation_name, event_time, anomaly_type, observed_value, severity,
    confidence, summary, limitations
) VALUES (
    %(investigation_id)s, %(anomaly_id)s, 'phase-13.5-fixture',
    %(service_name)s, %(operation_name)s, %(event_time)s, 'latency', 1.0,
    'CRITICAL', 'MEDIUM',
    'Phase 13.5 fixture: temporary validation row, never committed.',
    '{}'::text[]
)
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
    %(evaluated_at)s, %(payload)s::jsonb, %(summary)s, false
)
"""

# Read-only verification SQL (run as the restricted role)
_SQL_COUNT_ATTEMPTS = "SELECT count(attempt_id) FROM public.alert_delivery_attempts"
_SQL_COUNT_OUTCOMES = "SELECT count(attempt_id) FROM public.alert_delivery_outcomes"

_SQL_ATTEMPT_ROW = """\
SELECT
    attempt_id, decision_id, channel_name, channel_type, attempt_no, trigger,
    summary_included, payload_sha256, started_at
FROM public.alert_delivery_attempts
WHERE attempt_id = %(attempt_id)s
"""

_SQL_OUTCOME_ROW = """\
SELECT attempt_id, outcome, detail, recorded_at
FROM public.alert_delivery_outcomes
WHERE attempt_id = %(attempt_id)s
"""

_DENIED_STATEMENTS = [
    "SELECT investigation_id FROM public.alert_decisions LIMIT 1",
    "SELECT event_time FROM public.alert_decisions LIMIT 1",
    "SELECT severity FROM public.alert_decisions LIMIT 1",
    "SELECT dedup_key FROM public.alert_decisions LIMIT 1",
    "INSERT INTO public.alert_decisions (decision_id) VALUES ('x')",
    "UPDATE public.alert_decisions SET summary = summary WHERE false",
    "SELECT policy_version FROM public.alert_policies LIMIT 1",
    "INSERT INTO public.alert_policies (policy_version) VALUES ('x')",
    "SELECT investigation_id FROM public.rca_investigations LIMIT 1",
    "SELECT explanation FROM public.rca_evidence LIMIT 1",
    "SELECT anomaly_id FROM public.anomaly_events LIMIT 1",
    "SELECT signal_path FROM public.anomaly_detector_runs LIMIT 1",
    "SELECT embedding_id FROM public.rca_investigation_embeddings LIMIT 1",
    "SELECT count(*) FROM public.telemetry_spans",
    "UPDATE public.alert_delivery_attempts SET attempt_no = attempt_no WHERE false",
    "DELETE FROM public.alert_delivery_attempts WHERE false",
    "TRUNCATE public.alert_delivery_attempts",
    "UPDATE public.alert_delivery_outcomes SET detail = detail WHERE false",
    "DELETE FROM public.alert_delivery_outcomes WHERE false",
    "TRUNCATE public.alert_delivery_outcomes",
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


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.server.requests.append({
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": self.rfile.read(length),
        })
        self.send_response(self.server.status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()


class _State:
    """Shared between the ordered tests of this module."""

    def __init__(self) -> None:
        self.conn = None
        self.server = None
        self.log_stream = io.BytesIO()
        self.file_path = None
        self.channels: list = []
        self.delivery = None
        self.attempts_after_real_run = 0


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


def _body(name: str, *, include_summary: bool = False) -> bytes:
    fixture = _FIXTURES[name]
    return build_body(
        fixture["payload"], fixture["summary"], False,
        include_summary=include_summary,
    ).data


def _fixture_results(report) -> dict[tuple[str, str], object]:
    return {
        (_FIXTURE_IDS[r.decision_id], r.channel_name): r
        for r in report.results if r.decision_id in _FIXTURE_IDS
    }


def _channel(state, name: str):
    (found,) = [c for c in state.channels if c.config.name == name]
    return found


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def state(tmp_path_factory):
    import psycopg

    password = os.environ.get(_ADMIN_PASSWORD_ENV)
    if not password:
        pytest.fail(
            f"{_ADMIN_PASSWORD_ENV} must be set to run the live notifier "
            "test; there is no default"
        )

    shared = _State()

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.requests = []
    httpd.status = 200
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True,
    )
    thread.start()
    shared.server = httpd

    shared.file_path = tmp_path_factory.mktemp("phase-13-5") / "alerts.jsonl"
    configs = [
        ChannelConfig(name="log", type=ChannelType.LOG, enabled=True),
        ChannelConfig(
            name="file", type=ChannelType.FILE, enabled=True,
            path=str(shared.file_path), include_summary=True,
        ),
        ChannelConfig(
            name="hook", type=ChannelType.WEBHOOK, enabled=True,
            url_env="ALERT_WEBHOOK_FIXTURE", allow_insecure_loopback=True,
            timeout_seconds=5,
        ),
    ]
    environ = {
        "ALERT_WEBHOOK_FIXTURE":
            f"http://127.0.0.1:{httpd.server_address[1]}/fixture-hook",
    }
    shared.channels = [preflight_channel(config, environ) for config in configs]
    shared.delivery = DeliveryPolicy(
        channels=tuple(configs), max_delivery_age_minutes=60,
    )

    real = psycopg.connect(
        host=os.environ.get("ALERT_NOTIFIER_DB_HOST", "localhost"),
        port=int(os.environ.get("ALERT_NOTIFIER_DB_PORT", "5432")),
        dbname=os.environ.get("ALERT_NOTIFIER_DB_NAME", "agentops"),
        user=os.environ.get(_ADMIN_USER_ENV, "agentops"),
        password=password,
    )
    assert real.autocommit is False

    baseline = None
    after = None
    try:
        # 1. Baseline (this also opens the single outer transaction).
        baseline = _read_baseline(real)
        for name in ("fixture_anomalies", "fixture_investigations", "fixture_policies"):
            assert baseline[name] == 0, (
                f"{name} already exist; a previous run leaked rows"
            )

        # 2. Fixtures, as the administrator.  Never committed.
        assert _execute(real, _SQL_INSERT_POLICY, {
            "policy_version": _POLICY_VERSION, "policy_sha256": "0" * 64,
        }) == 1
        for fixture in _FIXTURES.values():
            params = {
                **fixture,
                "policy_version": _POLICY_VERSION,
                "service_name": _KEY[1],
                "operation_name": _KEY[2],
                "dedup_key": compute_dedup_key(*_KEY),
                "payload": (
                    None if fixture["payload"] is None
                    else json.dumps(fixture["payload"])
                ),
            }
            assert _execute(real, _SQL_INSERT_ANOMALY, params) == 1
            assert _execute(real, _SQL_INSERT_INVESTIGATION, params) == 1
            assert _execute(real, _SQL_INSERT_DECISION, params) == 1

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
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    if baseline is not None and after is not None:
        assert after == baseline, (
            f"the outer rollback did not restore the baseline: "
            f"before={baseline} after={after}"
        )


@pytest.fixture
def conn(state) -> _SavepointConnection:
    return state.conn


# ---------------------------------------------------------------------------
# N01  Role
# ---------------------------------------------------------------------------

def test_n01_statements_run_as_the_restricted_role(conn):
    assert _scalar(conn, "SELECT current_user") == _ROLE


# ---------------------------------------------------------------------------
# N02  Privileges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("statement", _DENIED_STATEMENTS)
def test_n02_restricted_role_is_denied(conn, statement):
    import psycopg.errors

    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _execute(conn, statement)
    finally:
        conn.rollback()


def test_n02_granted_reads_work(conn):
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) is not None
    assert _scalar(conn, _SQL_COUNT_OUTCOMES) is not None
    assert _scalar(
        conn, "SELECT count(decision_id) FROM public.alert_decisions",
    ) >= len(_FIXTURES)


# ---------------------------------------------------------------------------
# N03  Discovery
# ---------------------------------------------------------------------------

def test_n03_discovery_returns_alerts_only_in_order(conn):
    rows = alert_delivery_store.fetch_alert_decisions(conn)
    conn.rollback()
    assert all(row["decision"] == "ALERT" for row in rows)
    assert [(row["evaluated_at"], row["decision_id"]) for row in rows] == sorted(
        (row["evaluated_at"], row["decision_id"]) for row in rows
    )
    ours = [_FIXTURE_IDS[row["decision_id"]] for row in rows
            if row["decision_id"] in _FIXTURE_IDS]
    assert ours == list(_ALERTS)

    row = next(r for r in rows if r["decision_id"] == _FIXTURES["summary"]["decision_id"])
    assert list(row) == [
        "decision_id", "decision", "reason_code", "policy_version",
        "evaluated_at", "payload", "summary", "summary_truncated",
    ]
    assert row["payload"] == _FIXTURES["summary"]["payload"]
    assert row["summary"] == _FIXTURE_SUMMARY and row["summary_truncated"] is False
    assert row["evaluated_at"] == _FIXTURES["summary"]["evaluated_at"]
    assert row["policy_version"] == _POLICY_VERSION


def test_n03_single_decision_lookup(conn):
    suppressed = alert_delivery_store.fetch_decision(
        conn, _FIXTURES["suppressed"]["decision_id"],
    )
    missing = alert_delivery_store.fetch_decision(conn, "0" * 64)
    conn.rollback()
    assert suppressed["decision"] == "SUPPRESSED" and suppressed["payload"] is None
    assert missing is None


# ---------------------------------------------------------------------------
# N04  Dry run
# ---------------------------------------------------------------------------

def test_n04_dry_run_writes_and_delivers_nothing(state, conn):
    attempts = _scalar(conn, _SQL_COUNT_ATTEMPTS)
    outcomes = _scalar(conn, _SQL_COUNT_OUTCOMES)
    commits = conn.commits

    report = run_notify(
        conn, state.channels, state.delivery, now=_NOW, dry_run=True,
        log_stream=state.log_stream,
    )
    results = _fixture_results(report)

    for channel in ("log", "file", "hook"):
        old = results[("old", channel)]
        assert (old.status, old.state) == (STATUS_BLOCKED, S.EXPIRED)
        for name in ("fresh", "summary"):
            planned = results[(name, channel)]
            assert (planned.status, planned.attempt_no, planned.attempt_id) == (
                STATUS_WOULD_ATTEMPT, 1, None,
            )
    assert ("suppressed", "log") not in results

    assert conn.commits == commits
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts
    assert _scalar(conn, _SQL_COUNT_OUTCOMES) == outcomes
    assert state.log_stream.getvalue() == b""
    assert not state.file_path.exists()
    assert state.server.requests == []


# ---------------------------------------------------------------------------
# N05  Real run
# ---------------------------------------------------------------------------

def test_n05_real_run_delivers_and_records(state, conn):
    attempts = _scalar(conn, _SQL_COUNT_ATTEMPTS)
    outcomes = _scalar(conn, _SQL_COUNT_OUTCOMES)

    report = run_notify(
        conn, state.channels, state.delivery, now=_NOW,
        log_stream=state.log_stream,
    )
    results = _fixture_results(report)

    expected_detail = {"log": "log_written", "file": "file_appended", "hook": "http_200"}
    for name in ("fresh", "summary"):
        for channel, detail in expected_detail.items():
            done = results[(name, channel)]
            assert (done.status, done.outcome, done.detail, done.attempt_no) == (
                STATUS_ATTEMPTED, O.SENT, detail, 1,
            )
            assert done.attempt_id == compute_attempt_id(
                _FIXTURES[name]["decision_id"], channel, 1,
            )
    for channel in expected_detail:
        assert results[("old", channel)].state is S.EXPIRED
    assert not any(result.is_problem for result in results.values())

    made = report.attempted
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts + made
    assert _scalar(conn, _SQL_COUNT_OUTCOMES) == outcomes + made
    state.attempts_after_real_run = attempts + made

    # The same bytes reached every channel; only the file includes summaries.
    log_lines = state.log_stream.getvalue().split(b"\n")
    assert _body("fresh") in log_lines and _body("summary") in log_lines
    assert _FIXTURE_SUMMARY.encode() not in state.log_stream.getvalue()

    file_lines = state.file_path.read_bytes().split(b"\n")
    assert _body("fresh") in file_lines
    assert _body("summary", include_summary=True) in file_lines
    assert _body("summary") not in file_lines

    bodies = [request["body"] for request in state.server.requests]
    assert _body("fresh") in bodies and _body("summary") in bodies
    by_body = {request["body"]: request for request in state.server.requests}
    request = by_body[_body("fresh")]
    assert request["path"] == "/fixture-hook"
    assert request["headers"]["idempotency-key"] == _FIXTURES["fresh"]["decision_id"]
    assert request["headers"]["x-agentops-attempt"] == "1"
    assert request["headers"]["user-agent"] == "AgentOps-Alerting/1.0.0"


# ---------------------------------------------------------------------------
# N06  Stored rows
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("channel, channel_type, summary_included", [
    ("log", "log", False),
    ("file", "file", True),
    ("hook", "webhook", False),
])
def test_n06_stored_attempt_and_outcome(conn, channel, channel_type, summary_included):
    decision_id = _FIXTURES["summary"]["decision_id"]
    attempt_id = compute_attempt_id(decision_id, channel, 1)

    attempt = _row(conn, _SQL_ATTEMPT_ROW, {"attempt_id": attempt_id})
    assert attempt["decision_id"] == decision_id
    assert attempt["channel_name"] == channel
    assert attempt["channel_type"] == channel_type
    assert attempt["attempt_no"] == 1
    assert attempt["trigger"] == "auto"
    assert attempt["summary_included"] is summary_included
    delivered = _body("summary", include_summary=summary_included)
    assert attempt["payload_sha256"] == hashlib.sha256(delivered).hexdigest()
    # started_at is the database's clock, not the run time handed in.
    assert attempt["started_at"] > _NOW + timedelta(days=365)

    outcome = _row(conn, _SQL_OUTCOME_ROW, {"attempt_id": attempt_id})
    assert outcome["outcome"] == "SENT"
    assert outcome["detail"] in ("log_written", "file_appended", "http_200")
    assert outcome["recorded_at"] >= attempt["started_at"]


def test_n06_history_statement_joins_the_outcome(conn):
    decision_id = _FIXTURES["fresh"]["decision_id"]
    rows = alert_delivery_store.fetch_channel_history(conn, decision_id, "hook")
    bulk = alert_delivery_store.fetch_delivery_history(conn, [decision_id])
    conn.rollback()
    (row,) = rows
    assert (row["attempt_no"], row["outcome"], row["detail"]) == (1, "SENT", "http_200")
    assert [(r["channel_name"], r["attempt_no"]) for r in bulk] == [
        ("file", 1), ("hook", 1), ("log", 1),
    ]


# ---------------------------------------------------------------------------
# N07  Rerun
# ---------------------------------------------------------------------------

def test_n07_rerun_delivers_nothing_more(state, conn):
    requests = len(state.server.requests)
    log_size = len(state.log_stream.getvalue())
    report = run_notify(
        conn, state.channels, state.delivery, now=_NOW,
        log_stream=state.log_stream,
    )
    results = _fixture_results(report)
    for name in ("fresh", "summary"):
        for channel in ("log", "file", "hook"):
            again = results[(name, channel)]
            assert (again.status, again.state) == (STATUS_BLOCKED, S.SENT)
    assert report.attempted == 0
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == state.attempts_after_real_run
    assert len(state.server.requests) == requests
    assert len(state.log_stream.getvalue()) == log_size


# ---------------------------------------------------------------------------
# N08  Constraints
# ---------------------------------------------------------------------------

def test_n08_attempt_number_can_be_taken_only_once(state, conn):
    decision_id = _FIXTURES["fresh"]["decision_id"]
    attempt_id = compute_attempt_id(decision_id, "log", 1)
    before = _row(conn, _SQL_ATTEMPT_ROW, {"attempt_id": attempt_id})
    try:
        inserted = alert_delivery_store.insert_attempt(
            conn, attempt_id=attempt_id, decision_id=decision_id,
            channel_name="log", channel_type="log", attempt_no=1,
            trigger="operator", summary_included=True, payload_sha256="0" * 64,
        )
    finally:
        conn.rollback()
    assert inserted is False
    assert _row(conn, _SQL_ATTEMPT_ROW, {"attempt_id": attempt_id}) == before
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == state.attempts_after_real_run


def test_n08_outcome_can_be_recorded_only_once(conn):
    attempt_id = compute_attempt_id(_FIXTURES["fresh"]["decision_id"], "log", 1)
    before = _row(conn, _SQL_OUTCOME_ROW, {"attempt_id": attempt_id})
    try:
        inserted = alert_delivery_store.insert_outcome(
            conn, attempt_id=attempt_id,
            result=SendResult(ChannelType.LOG, O.UNCERTAIN, "log_write_failed"),
        )
    finally:
        conn.rollback()
    assert inserted is False
    assert _row(conn, _SQL_OUTCOME_ROW, {"attempt_id": attempt_id}) == before


def test_n08_attempt_needs_an_existing_decision(conn):
    import psycopg.errors

    unknown = "0" * 64
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            alert_delivery_store.insert_attempt(
                conn, attempt_id=compute_attempt_id(unknown, "log", 1),
                decision_id=unknown, channel_name="log", channel_type="log",
                attempt_no=1, trigger="auto", summary_included=False,
                payload_sha256="0" * 64,
            )
    finally:
        conn.rollback()


def test_n08_outcome_needs_an_existing_attempt(conn):
    import psycopg.errors

    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            alert_delivery_store.insert_outcome(
                conn, attempt_id="0" * 64,
                result=SendResult(ChannelType.LOG, O.SENT, "log_written"),
            )
    finally:
        conn.rollback()


# ---------------------------------------------------------------------------
# N09  Operator retry
# ---------------------------------------------------------------------------

def test_n09_expired_delivery_can_be_retried_by_an_operator(state, conn):
    decision_id = _FIXTURES["old"]["decision_id"]
    result = retry_delivery(
        conn, _channel(state, "log"), state.delivery, decision_id, now=_NOW,
        log_stream=state.log_stream,
    )
    assert (result.status, result.state, result.outcome, result.attempt_no) == (
        STATUS_ATTEMPTED, S.EXPIRED, O.SENT, 1,
    )
    attempt = _row(conn, _SQL_ATTEMPT_ROW, {
        "attempt_id": compute_attempt_id(decision_id, "log", 1),
    })
    assert attempt["trigger"] == "operator"
    assert _body("old") in state.log_stream.getvalue().split(b"\n")


def test_n09_sent_delivery_is_refused(state, conn):
    attempts = _scalar(conn, _SQL_COUNT_ATTEMPTS)
    result = retry_delivery(
        conn, _channel(state, "log"), state.delivery,
        _FIXTURES["fresh"]["decision_id"], now=_NOW, confirm_resend=True,
        log_stream=state.log_stream,
    )
    assert (result.status, result.state, result.reason) == (
        STATUS_REFUSED, S.SENT, "already_sent",
    )
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts


def test_n09_unknown_and_non_alert_decisions_are_not_found(state, conn):
    for decision_id in ("0" * 64, _FIXTURES["suppressed"]["decision_id"]):
        with pytest.raises(DecisionNotFoundError):
            retry_delivery(
                conn, _channel(state, "log"), state.delivery, decision_id,
                now=_NOW, log_stream=state.log_stream,
            )


# ---------------------------------------------------------------------------
# N10  States from real rows
# ---------------------------------------------------------------------------

def test_n10_retryable_failure_of_an_old_alert_stays_expired(state, conn):
    decision_id = _FIXTURES["old"]["decision_id"]
    hook = _channel(state, "hook")

    state.server.status = 503
    try:
        failed = retry_delivery(conn, hook, state.delivery, decision_id, now=_NOW)
    finally:
        state.server.status = 200
    assert (failed.outcome, failed.detail, failed.attempt_no) == (
        O.FAILED_RETRYABLE, "http_503", 1,
    )

    # Retryable and below the limit, but past the delivery age: still EXPIRED,
    # so the automatic run leaves it alone and an operator may try again.
    automatic = _fixture_results(run_notify(
        conn, state.channels, state.delivery, now=_NOW, log_stream=state.log_stream,
    ))[("old", "hook")]
    assert (automatic.status, automatic.state) == (STATUS_BLOCKED, S.EXPIRED)

    second = retry_delivery(conn, hook, state.delivery, decision_id, now=_NOW)
    assert (second.outcome, second.detail, second.attempt_no) == (
        O.SENT, "http_200", 2,
    )


def test_n10_attempt_without_outcome_is_in_flight_then_uncertain(state, conn):
    decision_id = _FIXTURES["old"]["decision_id"]
    file_channel = _channel(state, "file")
    body = build_body(
        _FIXTURES["old"]["payload"], None, False, include_summary=True,
    )
    assert alert_delivery_store.insert_attempt(
        conn, attempt_id=compute_attempt_id(decision_id, "file", 1),
        decision_id=decision_id, channel_name="file", channel_type="file",
        attempt_no=1, trigger="auto", summary_included=False,
        payload_sha256=body.sha256,
    ) is True
    conn.commit()
    attempts = _scalar(conn, _SQL_COUNT_ATTEMPTS)

    # The attempt started (database clock) after the run time: in flight.
    in_flight = retry_delivery(
        conn, file_channel, state.delivery, decision_id, now=_NOW,
        confirm_resend=True,
    )
    assert (in_flight.status, in_flight.state, in_flight.reason) == (
        STATUS_REFUSED, S.IN_FLIGHT, "in_flight",
    )

    # Long after it started and still without an outcome: uncertain.
    unconfirmed = retry_delivery(
        conn, file_channel, state.delivery, decision_id, now=_MUCH_LATER,
    )
    assert (unconfirmed.status, unconfirmed.state, unconfirmed.reason) == (
        STATUS_REFUSED, S.UNCERTAIN, "confirm_resend_required",
    )
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts

    confirmed = retry_delivery(
        conn, file_channel, state.delivery, decision_id, now=_MUCH_LATER,
        confirm_resend=True,
    )
    assert (confirmed.status, confirmed.outcome, confirmed.attempt_no) == (
        STATUS_ATTEMPTED, O.SENT, 2,
    )
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts + 1
    assert body.data in state.file_path.read_bytes().split(b"\n")


# ---------------------------------------------------------------------------
# N11  Read-only views
# ---------------------------------------------------------------------------

def test_n11_show_and_list(state, conn):
    attempts = _scalar(conn, _SQL_COUNT_ATTEMPTS)
    configs = [channel.config for channel in state.channels]

    view = show_alert(
        conn, configs, state.delivery, _FIXTURES["old"]["decision_id"], now=_NOW,
    )
    assert dict(view.states) == {"log": "SENT", "file": "SENT", "hook": "SENT"}
    assert view.payload == _FIXTURES["old"]["payload"]
    assert view.summary_stored == "no"
    assert [(a.channel_name, a.attempt_no, a.outcome) for a in view.attempts] == [
        ("file", 1, None), ("file", 2, "SENT"),
        ("hook", 1, "FAILED_RETRYABLE"), ("hook", 2, "SENT"),
        ("log", 1, "SENT"),
    ]

    summary_view = show_alert(
        conn, configs, state.delivery, _FIXTURES["summary"]["decision_id"], now=_NOW,
    )
    assert summary_view.summary_stored == "yes"
    assert _FIXTURE_SUMMARY not in repr(summary_view)

    with pytest.raises(DecisionNotFoundError):
        show_alert(
            conn, configs, state.delivery,
            _FIXTURES["suppressed"]["decision_id"], now=_NOW,
        )

    listed = list_alerts(conn, configs, state.delivery, now=_NOW, limit=500)
    ours = [_FIXTURE_IDS[v.decision_id] for v in listed if v.decision_id in _FIXTURE_IDS]
    assert ours == ["summary", "fresh", "old"]          # newest first
    assert all(dict(v.states)["log"] == "SENT" for v in listed
               if v.decision_id in _FIXTURE_IDS)
    assert _scalar(conn, _SQL_COUNT_ATTEMPTS) == attempts
