"""
trace-viewer/tests/integration/test_viewer_sql_live.py

Real-PostgreSQL tests of what the trace-viewer unit tests can only simulate.  EVERY test is
skipped unless the disposable loopback target described in conftest.py is approved through
the environment; run_viewer_sql_it.py supplies it, once, when separately authorized.

Three levels, named in each test's marker and prefix:

    sql_level        test_sql_*       statements run directly against PostgreSQL (syntax and
                                      semantics of the SQL, session options, role grants)
    query_level      test_query_*     the trace-viewer query functions (queries.py,
                                      anomaly_queries.py) against the bootstrapped schema
    endpoint_level   test_endpoint_*  the FastAPI application through an in-process client,
                                      with real connections (no network server is started)
    connection_level test_connection_* db.connect() against a local listener that never answers

The data is the MVP demo seed plus deterministic boundary rows (conftest.build_fixtures),
inserted once by the owner role of the disposable database.  The tests then read as the
role trace_viewer_reader, exactly as the viewer does.

Nothing here has been executed against PostgreSQL by its author; the orchestrator's unit
tests check its structure and the guard, not the SQL.  EXPECTED_TESTS in the orchestrator
lists the test functions of this file and a unit test keeps the two in step.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from contextlib import closing
from typing import Any

import psycopg
import psycopg.errors
import psycopg.rows
import pytest
from fastapi.testclient import TestClient

import anomaly_queries
import db
import queries
from app import MAX_EVIDENCE_ROWS, MAX_LIMITATIONS, MAX_SPANS_PER_TRACE, MAX_TEXT_CHARS, app

VIEWER_ROLE = "trace_viewer_reader"
_TIMEOUT_WINDOW = (4.0, 9.0)          # seconds: a 5 s limit, with room for connection and scheduling


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def fixtures(support):
    return support.build_fixtures()


@pytest.fixture(scope="session")
def viewer_env(live_target):
    """Points db.connect() at the disposable database as trace_viewer_reader for the whole session."""
    patch = pytest.MonkeyPatch()
    patch.setenv("TRACE_VIEWER_DB_HOST", live_target.host)
    patch.setenv("TRACE_VIEWER_DB_PORT", str(live_target.port))
    patch.setenv("TRACE_VIEWER_DB_NAME", "agentops")
    patch.setenv("TRACE_VIEWER_DB_USER", VIEWER_ROLE)
    patch.setenv("TRACE_VIEWER_DB_PASSWORD", live_target.viewer_password)
    yield live_target
    patch.undo()


@pytest.fixture(scope="session")
def seeded(live_target, viewer_env, fixtures, support):
    """Inserts the demo seed and the boundary rows with the owner role; refuses a database that is not empty."""
    with closing(psycopg.connect(live_target.admin_dsn, connect_timeout=15)) as admin:
        for table in support.TABLES:
            count = admin.execute(f"SELECT count(*) FROM public.{table}").fetchone()[0]
            assert count == 0, f"public.{table} is not empty: refusing to seed"
        for table in support.TABLES:
            support.insert_rows(admin, table, fixtures.rows[table])
        admin.commit()
    return fixtures


@pytest.fixture()
def viewer(viewer_env):
    with closing(db.connect()) as conn:
        yield conn


@pytest.fixture(scope="module")
def client():
    return TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False)


def _api_text(length: int) -> int:
    return min(length, MAX_TEXT_CHARS)


def _cut(length: int) -> bool:
    return length > MAX_TEXT_CHARS


# ---------------------------------------------------------------------------
# SQL level
# ---------------------------------------------------------------------------

@pytest.mark.sql_level
def test_sql_session_is_read_only_with_five_second_statement_timeout(viewer_env):
    with closing(db.connect()) as conn:
        settings = dict(conn.execute(
            "SELECT name, setting FROM pg_settings WHERE name IN "
            "('default_transaction_read_only', 'transaction_read_only', 'statement_timeout')").fetchall())
        assert settings == {"default_transaction_read_only": "on", "transaction_read_only": "on", "statement_timeout": "5000"}
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "5s"
        assert conn.execute("SELECT current_user").fetchone()[0] == VIEWER_ROLE
        flags = conn.execute("SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
                             "FROM pg_roles WHERE rolname = current_user").fetchone()
        assert flags == (False, False, False, False, False)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("CREATE TABLE public.viewer_it_probe (id integer)")


@pytest.mark.sql_level
@pytest.mark.parametrize("statement", [
    "INSERT INTO public.anomaly_events (anomaly_id) VALUES ('x')",
    "UPDATE public.anomaly_events SET severity = 'INFO'",
    "DELETE FROM public.rca_evidence",
    "TRUNCATE public.rca_investigations",
    "INSERT INTO public.telemetry_spans (trace_id) VALUES ('x')",
    "CREATE TABLE public.viewer_it_probe (id integer)",
    "CREATE ROLE viewer_it_probe_role",
])
def test_sql_role_cannot_write_or_change_the_schema_even_when_read_write_is_forced(viewer_env, statement):
    with closing(db.connect()) as conn:
        conn.execute("SET TRANSACTION READ WRITE")               # defeats the session default on purpose: only the grants remain
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)


@pytest.mark.sql_level
def test_sql_statement_timeout_cancels_a_long_statement(viewer_env):
    with closing(db.connect()) as conn:
        started = time.monotonic()
        with pytest.raises(psycopg.errors.QueryCanceled):
            conn.execute("SELECT pg_sleep(6)")
        elapsed = time.monotonic() - started
    assert _TIMEOUT_WINDOW[0] <= elapsed <= _TIMEOUT_WINDOW[1], elapsed


@pytest.mark.sql_level
def test_sql_role_reads_the_granted_relations_and_nothing_wider(viewer_env):
    readable = ("analytics.stg_telemetry_spans", "analytics.int_trace_spans", "public.anomaly_events",
                "public.rca_investigations", "public.rca_evidence")
    with closing(db.connect()) as conn:
        for relation in readable:
            conn.execute(f"SELECT 1 FROM {relation} LIMIT 1").fetchall()
        grants = conn.execute(
            "SELECT table_schema || '.' || table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = current_user").fetchall()
    by_relation: dict[str, set[str]] = {}
    for relation, privilege in grants:
        by_relation.setdefault(relation, set()).add(privilege)
    assert set(readable) <= set(by_relation), sorted(set(readable) - set(by_relation))
    assert all(privileges == {"SELECT"} for privileges in by_relation.values()), by_relation
    with closing(db.connect()) as conn:                              # the base table the views read is NOT readable
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT 1 FROM public.telemetry_spans LIMIT 1")


@pytest.mark.sql_level
def test_sql_left_counts_characters_not_bytes(viewer_env, support):
    with closing(db.connect()) as conn:
        for case in support.text_cases():
            value, characters = conn.execute("SELECT left(%s::text, 2001), length(left(%s::text, 2001))",
                                             (case.text, case.text)).fetchone()
            assert value == case.text[:2001], case.label
            assert characters == min(case.length, 2001), case.label


_LIMITATIONS_EXPRESSION = re.search(r"ARRAY\(.*?\) AS limitations", anomaly_queries._INVESTIGATION_SELECT, re.S)


@pytest.mark.sql_level
@pytest.mark.parametrize("items", [
    [], ["a"], [f"item {i}" for i in range(50)], [f"item {i}" for i in range(51)], [f"item {i}" for i in range(500)],
    ["x" * 2001, "y" * 5000, "short"], ["first", None, "third"], ["é" * 2001, "\U0001F600" * 2002],
])
def test_sql_limitations_expression_slices_orders_and_shortens(viewer_env, items):
    assert _LIMITATIONS_EXPRESSION is not None
    expression = _LIMITATIONS_EXPRESSION.group(0)
    assert "limitations[1:51]" in expression
    sql = "SELECT " + expression.replace("limitations[1:51]", "(%s::text[])[1:51]")
    with closing(db.connect()) as conn:
        (result,) = conn.execute(sql, (items,)).fetchone()
    assert result == [None if item is None else item[:2001] for item in items[:51]]


@pytest.mark.sql_level
def test_sql_evidence_statement_orders_by_rank_then_span_id_limits_and_counts(viewer_env, seeded):
    for count, investigation_id in seeded.evidence_cases:
        expected = sorted((r["rank_position"], r["span_id"]) for r in seeded.rows["rca_evidence"]
                          if r["investigation_id"] == investigation_id)
        with closing(db.connect()) as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(anomaly_queries._EVIDENCE_SQL, {"investigation_id": investigation_id})
            rows = cur.fetchall()
        assert len(rows) == min(count, anomaly_queries.EVIDENCE_FETCH_ROWS), count
        assert [(r["rank_position"], r["span_id"]) for r in rows] == expected[:anomaly_queries.EVIDENCE_FETCH_ROWS], count
        assert {r["evidence_total"] for r in rows} == ({count} if count else set()), count


# ---------------------------------------------------------------------------
# Query level
# ---------------------------------------------------------------------------

@pytest.mark.query_level
def test_query_span_text_is_shortened_by_the_database_through_the_dbt_view(viewer, seeded):
    spans = {s.span_id: s for s in queries.fetch_trace_spans(viewer, seeded.text_trace_id)}
    assert len(spans) == len(seeded.span_cases) + 1
    for case, span_id in seeded.span_cases:
        span = spans[span_id]
        assert span.error_message == case.text[:queries.TEXT_FETCH_CHARS], case.label
        assert span.status_message == case.text[:queries.TEXT_FETCH_CHARS], case.label
        assert len(span.error_message) == min(case.length, queries.TEXT_FETCH_CHARS), case.label


@pytest.mark.query_level
def test_query_bounded_trace_read_orders_limits_and_reports_truncation(viewer, seeded):
    sizes = {}
    for size, trace in seeded.big_traces.items():
        everything = queries.fetch_trace_spans(viewer, trace)
        result = queries.get_trace_reconstruction(viewer, trace, max_spans=MAX_SPANS_PER_TRACE)
        sizes[size] = (len(everything), result.span_count, result.truncated)
    assert sizes[1000] == (1000, 1000, False)
    assert sizes[1001] == (1001, 1000, True)
    over = queries.fetch_trace_spans(viewer, seeded.big_traces[1001], max_spans=MAX_SPANS_PER_TRACE)
    assert len(over) == 1001                                        # the one extra row that detects "more"
    ordered = [(s.start_time, s.span_id) for s in over]
    assert ordered == sorted(ordered)                              # earliest first, deterministic


@pytest.mark.query_level
def test_query_anomaly_explanation_is_shortened_by_the_database(viewer, seeded):
    listed = {a["anomaly_id"]: a for a in anomaly_queries.list_anomalies(viewer, limit=200).anomalies}
    for case, anomaly_id in seeded.anomaly_cases:
        single = anomaly_queries.get_anomaly(viewer, anomaly_id)
        assert single["explanation"] == case.text[:anomaly_queries.TEXT_FETCH_CHARS], case.label
        assert listed[anomaly_id]["explanation"] == single["explanation"], case.label


@pytest.mark.query_level
def test_query_rca_text_limitations_and_evidence_totals(viewer, seeded):
    for case, investigation_id in seeded.summary_cases:
        result = anomaly_queries.get_rca_investigation(viewer, investigation_id)
        expected = case.text[:anomaly_queries.TEXT_FETCH_CHARS]
        assert result["summary"] == expected and result["limitations"] == [expected], case.label
        (evidence,) = result["evidence"]
        assert evidence["error_message"] == evidence["explanation"] == evidence["evidence_score_breakdown"] == expected, case.label
        assert result["evidence_total"] == 1 and "evidence_total" not in evidence
    for count, investigation_id in seeded.limitation_cases:
        result = anomaly_queries.get_rca_investigation(viewer, investigation_id)
        wanted = [f"limitation {i:04d}" for i in range(count)][:anomaly_queries.LIMITATIONS_FETCH_ITEMS]
        assert result["limitations"] == wanted, count
    assert [len(x) for x in anomaly_queries.get_rca_investigation(viewer, seeded.long_limitation_investigation)["limitations"]] == [2001, 2001, 5]
    assert anomaly_queries.get_rca_investigation(viewer, seeded.null_limitation_investigation)["limitations"] == ["first", None, "third"]
    for count, investigation_id in seeded.evidence_cases:
        result = anomaly_queries.get_rca_investigation(viewer, investigation_id)
        assert len(result["evidence"]) == min(count, anomaly_queries.EVIDENCE_FETCH_ROWS), count
        assert result["evidence_total"] == count, count
        ranks = [(e["rank_position"], e["span_id"]) for e in result["evidence"]]
        assert ranks == sorted(ranks), count


@pytest.mark.query_level
def test_query_latest_investigation_follows_its_anomaly(viewer, seeded, support):
    parent = support.digest("anomaly|limitations-1")
    latest = anomaly_queries.get_latest_rca_for_anomaly(viewer, parent)
    assert latest is not None and latest["anomaly_id"] == parent and latest["limitations"] == ["limitation 0000"]
    assert anomaly_queries.get_latest_rca_for_anomaly(viewer, seeded.anomaly_without_investigation) is None


@pytest.mark.query_level
def test_query_empty_and_missing_results(viewer, seeded):
    assert queries.get_trace_reconstruction(viewer, "0" * 32, max_spans=MAX_SPANS_PER_TRACE).span_count == 0
    assert queries.list_traces(viewer, service_name="no-such-service").total == 0
    assert queries.list_traces(viewer, service_name="no-such-service").traces == []
    assert anomaly_queries.get_anomaly(viewer, "0" * 64) is None
    assert anomaly_queries.get_rca_investigation(viewer, "0" * 64) is None
    assert anomaly_queries.list_anomalies(viewer, service_name="no-such-service").total == 0
    empty = anomaly_queries.get_rca_investigation(viewer, dict(seeded.evidence_cases)[0])
    assert empty["evidence"] == [] and empty["evidence_total"] == 0


# ---------------------------------------------------------------------------
# Endpoint level
# ---------------------------------------------------------------------------

@pytest.mark.endpoint_level
def test_endpoint_readiness_succeeds_against_the_real_server(client, viewer_env):
    ready = client.get("/api/health/ready")
    assert ready.status_code == 200 and ready.json() == {"status": "ok", "database": "ok"}
    assert ready.headers["cache-control"] == "no-store"
    assert client.get("/api/health").json() == {"status": "ok"}


@pytest.mark.endpoint_level
def test_endpoint_readiness_failure_is_sanitized(client, viewer_env, monkeypatch):
    expected = {"status": "unavailable", "database": "unavailable"}
    with socket.socket() as probe:                                    # a loopback port nothing listens on
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    for name, value in (("TRACE_VIEWER_DB_PASSWORD", "wrong-password-for-viewer-it"),
                        ("TRACE_VIEWER_DB_PORT", str(closed_port)), ("TRACE_VIEWER_DB_PORT", "not-a-port")):
        with monkeypatch.context() as patch:
            patch.setenv(name, value)
            response = client.get("/api/health/ready")
        assert response.status_code == 503 and response.json() == expected, name
        lowered = response.text.lower()
        assert value.lower() not in lowered and "password" not in lowered and "authentication" not in lowered
        assert "refused" not in lowered and "traceback" not in lowered
        assert response.headers["cache-control"] == "no-store"
        assert "content-security-policy" in response.headers


@pytest.mark.endpoint_level
def test_endpoint_span_text_and_truncation_metadata(client, seeded):
    body = client.get(f"/api/traces/{seeded.text_trace_id}").json()
    spans = {c["span"]["span_id"]: c["span"] for c in body["roots"][0]["children"]}
    for case, span_id in seeded.span_cases:
        span = spans[span_id]
        assert len(span["error_message"]) == len(span["status_message"]) == _api_text(case.length), case.label
        assert span["truncated_fields"] == (["status_message", "error_message"] if _cut(case.length) else []), case.label
    assert body["truncated"] is False
    over = client.get(f"/api/traces/{seeded.big_traces[1001]}").json()
    exact = client.get(f"/api/traces/{seeded.big_traces[1000]}").json()
    assert (over["span_count"], over["truncated"], over["truncation_reasons"], over["max_spans"]) == (1000, True, ["span_limit"], 1000)
    assert (exact["span_count"], exact["truncated"], exact["truncation_reasons"]) == (1000, False, [])
    listing = client.get(f"/api/traces?search={seeded.text_trace_id[:12]}").json()
    assert listing["total"] == 1 and listing["traces"][0]["trace_id"] == seeded.text_trace_id


@pytest.mark.endpoint_level
def test_endpoint_anomaly_and_rca_bounds_and_metadata(client, seeded):
    for case, anomaly_id in seeded.anomaly_cases:
        body = client.get(f"/api/anomalies/{anomaly_id}").json()
        assert len(body["explanation"]) == _api_text(case.length), case.label
        assert body["truncated_fields"] == (["explanation"] if _cut(case.length) else []), case.label
    for case, investigation_id in seeded.summary_cases:
        body = client.get(f"/api/rca/{investigation_id}").json()
        assert len(body["summary"]) == len(body["limitations"][0]) == _api_text(case.length), case.label
        assert body["truncated_fields"] == (["summary", "limitations"] if _cut(case.length) else []), case.label
        assert body["evidence"][0]["truncated_fields"] == (
            ["error_message", "explanation", "evidence_score_breakdown"] if _cut(case.length) else []), case.label
    for count, investigation_id in seeded.limitation_cases:
        body = client.get(f"/api/rca/{investigation_id}").json()
        assert len(body["limitations"]) == min(count, MAX_LIMITATIONS), count
        assert body["truncated_fields"] == (["limitations"] if count > MAX_LIMITATIONS else []), count
    for count, investigation_id in seeded.evidence_cases:
        body = client.get(f"/api/rca/{investigation_id}").json()
        assert len(body["evidence"]) == min(count, MAX_EVIDENCE_ROWS), count
        assert body["omitted_evidence"] == max(count - MAX_EVIDENCE_ROWS, 0), count
        assert body["truncated_fields"] == (["evidence"] if count > MAX_EVIDENCE_ROWS else []), count
        assert "evidence_total" not in body


@pytest.mark.endpoint_level
def test_endpoint_missing_resources_and_empty_filters(client, seeded):
    assert client.get(f"/api/traces/{'0' * 32}").status_code == 404
    assert client.get(f"/api/anomalies/{'0' * 64}").status_code == 404
    assert client.get(f"/api/rca/{'0' * 64}").status_code == 404
    assert client.get(f"/api/anomalies/{seeded.anomaly_without_investigation}/rca").status_code == 404
    assert client.get("/api/traces?service_name=no-such-service").json()["total"] == 0
    assert client.get("/api/anomalies?service_name=no-such-service").json() == {"total": 0, "limit": 50, "offset": 0, "anomalies": []}
    empty = client.get(f"/api/rca/{dict(seeded.evidence_cases)[0]}").json()
    assert empty["evidence"] == [] and empty["omitted_evidence"] == 0 and empty["truncated_fields"] == []


@pytest.mark.endpoint_level
def test_endpoint_database_errors_are_sanitized(client, viewer_env, monkeypatch):
    def slow_list(conn: Any, **kwargs: Any):
        conn.execute("SELECT pg_sleep(6)")                          # cancelled by the 5 s statement timeout

    monkeypatch.setattr("app.list_traces", slow_list)
    started = time.monotonic()
    response = client.get("/api/traces")
    elapsed = time.monotonic() - started
    assert response.status_code == 503 and response.json() == {"detail": "Database error"}
    assert _TIMEOUT_WINDOW[0] <= elapsed <= _TIMEOUT_WINDOW[1], elapsed
    lowered = response.text.lower()
    assert "pg_sleep" not in lowered and "cancel" not in lowered and "statement" not in lowered
    assert response.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# Connection level
# ---------------------------------------------------------------------------

@pytest.mark.connection_level
def test_connection_timeout_against_a_silent_loopback_listener(monkeypatch):
    held: list[socket.socket] = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(0.2)
    stop = threading.Event()

    def accept() -> None:                                           # accepts connections and never answers
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
                held.append(connection)
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    monkeypatch.setenv("TRACE_VIEWER_DB_HOST", "127.0.0.1")
    monkeypatch.setenv("TRACE_VIEWER_DB_PORT", str(listener.getsockname()[1]))
    monkeypatch.setenv("TRACE_VIEWER_DB_PASSWORD", "not-a-real-password")
    try:
        started = time.monotonic()
        with pytest.raises(psycopg.OperationalError):
            db.connect()
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        thread.join(timeout=2)
        for connection in held:
            connection.close()
        listener.close()
    assert 4.0 <= elapsed <= 8.0, elapsed
