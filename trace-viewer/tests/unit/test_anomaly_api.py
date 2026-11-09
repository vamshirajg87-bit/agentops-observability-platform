"""
trace-viewer/tests/unit/test_anomaly_api.py

Offline tests for the read-only anomaly and RCA endpoints, the SQL in
anomaly_queries.py, and migration 015.  No live database: app.connect is
patched, and the query module is driven through a fake cursor.

Coverage
    1-8    GET /api/anomalies                      — shape, filters, validation
    9-11   GET /api/anomalies/{anomaly_id}         — 200 / 404 / 422
    12-14  GET /api/rca/{investigation_id}         — 200 / 404 / 422
    15-17  GET /api/anomalies/{anomaly_id}/rca     — 200 / 404 / 422
    18-20  Database failure → 503, no leaked internals; connection lifecycle
    21-26  anomaly_queries SQL: parameterized, ordered, bounded, validated
    27-30  Migration 015: exact read-only grants
    31     Existing trace routes unchanged
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from fastapi.testclient import TestClient

import anomaly_queries
from anomaly_queries import AnomalyListResult
from app import app

_DT = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
_ANOMALY_ID = "a" * 64
_INVESTIGATION_ID = "b" * 64
_TRACE_ID = "c" * 32

client = TestClient(app, base_url="http://127.0.0.1")

_MIGRATION = os.path.join(
    os.path.dirname(__file__), "..", "..", "..",
    "storage-consumer", "migrations", "015_grant_trace_viewer_anomaly_rca_read.sql",
)


def _anomaly_row(**overrides) -> dict:
    row = {
        "anomaly_id": _ANOMALY_ID, "anomaly_type": "latency", "signal_name": "span_duration_ms",
        "detector_name": "mad", "detector_version": "1", "trace_id": _TRACE_ID,
        "span_id": "d" * 16, "service_name": "svc", "operation_name": "op",
        "observed_value": 900.0, "event_time": _DT, "baseline_median": 100.0,
        "baseline_mad": 10.0, "baseline_n": 30, "baseline_window_start": _DT,
        "baseline_window_end": _DT, "anomaly_score": 8.5, "severity": "WARNING",
        "explanation": "slow", "detected_at": _DT,
    }
    row.update(overrides)
    return row


def _evidence_row(rank: int = 1, **overrides) -> dict:
    row = {
        "span_id": f"{rank:016x}", "parent_span_id": None, "span_name": "tool.call",
        "service_name": "svc", "duration_ms": 850.0, "status_code": "ERROR",
        "error_type": "Timeout", "error_message": "timed out", "tool_name": None,
        "tool_status": None, "agent_name": None, "agent_operation": None,
        "retrieval_result_count": None, "retrieval_top_relevance_score": None,
        "is_root_span": False, "is_error_span": True, "is_direct_subject": True,
        "depth": 1, "trace_duration_fraction": 0.9, "evidence_type": "direct_subject",
        "evidence_score": 0.9, "evidence_score_breakdown": "a=0.5;b=0.4",
        "explanation": "the slow span", "rank_position": rank,
    }
    row.update(overrides)
    return row


def _rca_row(**overrides) -> dict:
    row = {
        "investigation_id": _INVESTIGATION_ID, "anomaly_id": _ANOMALY_ID,
        "analyzer_version": "1", "investigated_at": _DT, "trace_id": _TRACE_ID,
        "subject_span_id": "d" * 16, "service_name": "svc", "operation_name": "op",
        "event_time": _DT, "trace_span_count": 4, "anomaly_type": "latency",
        "observed_value": 900.0, "baseline_median": 100.0, "anomaly_score": 8.5,
        "severity": "WARNING", "confidence": "HIGH", "summary": "tool timed out",
        "limitations": ["no logs"], "evidence": [_evidence_row(1), _evidence_row(2)],
    }
    row.update(overrides)
    return row


def _patched(**targets):
    """Patch app.connect plus the named app.<function> targets."""
    from contextlib import ExitStack
    stack = ExitStack()
    conn = MagicMock()
    stack.enter_context(patch("app.connect", return_value=conn))
    mocks = {n: stack.enter_context(patch(f"app.{n}", **kw)) for n, kw in targets.items()}
    return stack, conn, mocks


# ---------------------------------------------------------------------------
# 1-8: GET /api/anomalies
# ---------------------------------------------------------------------------


def test_list_anomalies_shape_and_defaults():
    stack, _, m = _patched(list_anomalies={"return_value": AnomalyListResult(1, [_anomaly_row()])})
    with stack:
        resp = client.get("/api/anomalies")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"total", "limit", "offset", "anomalies"}
    assert (body["total"], body["limit"], body["offset"]) == (1, 50, 0)
    assert body["anomalies"][0]["anomaly_id"] == _ANOMALY_ID
    assert body["anomalies"][0]["severity"] == "WARNING"
    kwargs = m["list_anomalies"].call_args.kwargs
    assert kwargs == dict(limit=50, offset=0, severity=None, service_name=None, trace_id=None)


def test_list_anomalies_passes_filters():
    stack, _, m = _patched(list_anomalies={"return_value": AnomalyListResult(0, [])})
    with stack:
        resp = client.get(
            f"/api/anomalies?severity=CRITICAL&service_name=svc&trace_id={_TRACE_ID}&limit=5&offset=10"
        )
    assert resp.status_code == 200
    assert m["list_anomalies"].call_args.kwargs == dict(
        limit=5, offset=10, severity="CRITICAL", service_name="svc", trace_id=_TRACE_ID,
    )
    assert resp.json()["anomalies"] == []


def test_list_anomalies_nullable_columns_serialize():
    row = _anomaly_row(trace_id=None, span_id=None, service_name=None, operation_name=None,
                       baseline_median=None, baseline_mad=None, baseline_n=None,
                       baseline_window_start=None, baseline_window_end=None, anomaly_score=None)
    stack, _, _ = _patched(list_anomalies={"return_value": AnomalyListResult(1, [row])})
    with stack:
        resp = client.get("/api/anomalies")
    assert resp.status_code == 200
    assert resp.json()["anomalies"][0]["baseline_n"] is None


@pytest.mark.parametrize("query", [
    "limit=0", "limit=201", "offset=-1", "severity=BOGUS", "severity=warning",
    "trace_id=short", f"trace_id={'C' * 32}", f"trace_id={_TRACE_ID}0",
])
def test_list_anomalies_invalid_params_422_without_db(query):
    with patch("app.connect") as connect:
        resp = client.get(f"/api/anomalies?{query}")
    assert resp.status_code == 422
    connect.assert_not_called()


def test_list_anomalies_limit_200_accepted():
    stack, _, m = _patched(list_anomalies={"return_value": AnomalyListResult(0, [])})
    with stack:
        assert client.get("/api/anomalies?limit=200").status_code == 200
    assert m["list_anomalies"].call_args.kwargs["limit"] == 200


# ---------------------------------------------------------------------------
# 9-11: GET /api/anomalies/{anomaly_id}
# ---------------------------------------------------------------------------


def test_get_anomaly_200():
    stack, _, m = _patched(get_anomaly={"return_value": _anomaly_row()})
    with stack:
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}")
    assert resp.status_code == 200
    assert resp.json()["anomaly_id"] == _ANOMALY_ID
    assert resp.json()["explanation"] == "slow"
    assert m["get_anomaly"].call_args.args[1] == _ANOMALY_ID


def test_get_anomaly_404():
    stack, _, _ = _patched(get_anomaly={"return_value": None})
    with stack:
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}")
    assert resp.status_code == 404


@pytest.mark.parametrize("bad", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 32])
def test_get_anomaly_bad_id_422_without_db(bad):
    with patch("app.connect") as connect:
        resp = client.get(f"/api/anomalies/{bad}")
    assert resp.status_code == 422
    connect.assert_not_called()


# ---------------------------------------------------------------------------
# 12-14: GET /api/rca/{investigation_id}
# ---------------------------------------------------------------------------


def test_get_rca_200_includes_required_fields_and_ranked_evidence():
    stack, _, m = _patched(get_rca_investigation={"return_value": _rca_row()})
    with stack:
        resp = client.get(f"/api/rca/{_INVESTIGATION_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["confidence"] == "HIGH"
    assert body["summary"] == "tool timed out"
    assert body["limitations"] == ["no logs"]
    assert [e["rank_position"] for e in body["evidence"]] == [1, 2]
    assert {"evidence_score", "explanation", "span_id"} <= set(body["evidence"][0])
    assert m["get_rca_investigation"].call_args.args[1] == _INVESTIGATION_ID


def test_get_rca_404():
    stack, _, _ = _patched(get_rca_investigation={"return_value": None})
    with stack:
        assert client.get(f"/api/rca/{_INVESTIGATION_ID}").status_code == 404


@pytest.mark.parametrize("bad", ["b" * 63, "B" * 64, "z" * 64, _TRACE_ID])
def test_get_rca_bad_id_422_without_db(bad):
    with patch("app.connect") as connect:
        resp = client.get(f"/api/rca/{bad}")
    assert resp.status_code == 422
    connect.assert_not_called()


# ---------------------------------------------------------------------------
# 15-17: GET /api/anomalies/{anomaly_id}/rca
# ---------------------------------------------------------------------------


def test_anomaly_rca_200_returns_latest_with_evidence():
    stack, _, m = _patched(get_latest_rca_for_anomaly={"return_value": _rca_row()})
    with stack:
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}/rca")
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigation_id"] == _INVESTIGATION_ID
    assert body["anomaly_id"] == _ANOMALY_ID
    assert len(body["evidence"]) == 2
    assert m["get_latest_rca_for_anomaly"].call_args.args[1] == _ANOMALY_ID


def test_anomaly_rca_404_when_no_investigation():
    stack, _, _ = _patched(get_latest_rca_for_anomaly={"return_value": None})
    with stack:
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}/rca")
    assert resp.status_code == 404


def test_anomaly_rca_bad_id_422_without_db():
    with patch("app.connect") as connect:
        resp = client.get(f"/api/anomalies/{'x' * 64}/rca")
    assert resp.status_code == 422
    connect.assert_not_called()


# ---------------------------------------------------------------------------
# 18-20: database failure and connection lifecycle
# ---------------------------------------------------------------------------

_SECRET = "s3cret-password-value"


@pytest.mark.parametrize("path,target", [
    ("/api/anomalies", "list_anomalies"),
    (f"/api/anomalies/{_ANOMALY_ID}", "get_anomaly"),
    (f"/api/rca/{_INVESTIGATION_ID}", "get_rca_investigation"),
    (f"/api/anomalies/{_ANOMALY_ID}/rca", "get_latest_rca_for_anomaly"),
])
def test_db_error_returns_503_without_leaking(path, target):
    err = psycopg.OperationalError(f"password={_SECRET} host=db SELECT * FROM public.x")
    stack, _, _ = _patched(**{target: {"side_effect": err}})
    with stack:
        resp = client.get(path)
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Database error"}
    assert _SECRET not in resp.text and "SELECT" not in resp.text


def test_connect_failure_returns_503_without_leaking():
    with patch("app.connect", side_effect=psycopg.OperationalError(f"password={_SECRET}")):
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}")
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Database unavailable"}
    assert _SECRET not in resp.text


def test_connection_closed_on_success_and_on_404():
    stack, conn, _ = _patched(get_anomaly={"return_value": None})
    with stack:
        client.get(f"/api/anomalies/{_ANOMALY_ID}")
    conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# 21-26: anomaly_queries SQL
# ---------------------------------------------------------------------------


class _FakeCursor:
    """Records executed SQL/params; fetchone/fetchall replay queued results."""

    def __init__(self, results):
        self.executed: list[tuple[str, dict]] = []
        self._results = list(results)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._results.pop(0)

    def fetchall(self):
        return self._results.pop(0)


def _conn_with(cursor):
    conn = MagicMock()
    conn.cursor.return_value = cursor
    return conn


def test_list_query_parameterized_ordered_and_bounded():
    cur = _FakeCursor([{"count": 3}, [_anomaly_row()]])
    result = anomaly_queries.list_anomalies(
        _conn_with(cur), limit=10, offset=20,
        severity="INFO", service_name="svc'; DROP TABLE x;--", trace_id=_TRACE_ID,
    )
    assert result.total == 3
    count_sql, page_sql = cur.executed[0][0], cur.executed[1][0]
    params = cur.executed[1][1]
    assert "DROP TABLE" not in count_sql and "DROP TABLE" not in page_sql
    assert params["service_name"] == "svc'; DROP TABLE x;--"
    assert "ORDER BY event_time DESC, anomaly_id ASC" in page_sql
    assert "LIMIT %(limit)s OFFSET %(offset)s" in page_sql
    for fragment in ("severity = %(severity)s", "service_name = %(service_name)s",
                     "trace_id = %(trace_id)s"):
        assert fragment in page_sql and fragment in count_sql


def test_list_query_without_filters_has_no_where():
    cur = _FakeCursor([{"count": 0}, []])
    anomaly_queries.list_anomalies(_conn_with(cur))
    assert all("WHERE" not in sql for sql, _ in cur.executed)


@pytest.mark.parametrize("kwargs", [
    {"limit": 0}, {"offset": -1}, {"severity": "BOGUS"}, {"trace_id": "nope"},
])
def test_list_query_rejects_bad_arguments_before_db(kwargs):
    conn = MagicMock()
    with pytest.raises(ValueError):
        anomaly_queries.list_anomalies(conn, **kwargs)
    conn.cursor.assert_not_called()


@pytest.mark.parametrize("func", [
    anomaly_queries.get_anomaly,
    anomaly_queries.get_rca_investigation,
    anomaly_queries.get_latest_rca_for_anomaly,
])
def test_id_functions_validate_before_db(func):
    conn = MagicMock()
    with pytest.raises(ValueError):
        func(conn, "A" * 64)
    with pytest.raises(ValueError):
        func(conn, "a" * 32)
    conn.cursor.assert_not_called()


def test_rca_evidence_ordered_by_rank_then_span_id():
    cur = _FakeCursor([_rca_row() | {"evidence": None}, [_evidence_row(1)]])
    result = anomaly_queries.get_rca_investigation(_conn_with(cur), _INVESTIGATION_ID)
    assert result["evidence"][0]["rank_position"] == 1
    evidence_sql, evidence_params = cur.executed[1]
    assert "ORDER BY rank_position ASC, span_id ASC" in evidence_sql
    assert evidence_params == {"investigation_id": _INVESTIGATION_ID}


def test_latest_rca_orders_newest_first_deterministically_and_returns_none():
    cur = _FakeCursor([None])
    assert anomaly_queries.get_latest_rca_for_anomaly(_conn_with(cur), _ANOMALY_ID) is None
    sql, params = cur.executed[0]
    assert "ORDER BY investigated_at DESC, investigation_id ASC" in sql
    assert "LIMIT 1" in sql
    assert params == {"anomaly_id": _ANOMALY_ID}
    assert len(cur.executed) == 1  # no evidence query when nothing was found


def test_query_module_only_reads():
    code = _strip_docstrings(open(anomaly_queries.__file__, encoding="utf-8").read())
    assert not re.search(r"(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT)", code)


def _strip_docstrings(src: str) -> str:
    """Module source with the leading module docstring and ``#`` comments removed."""
    body = src.split('"""', 2)[2]
    return "\n".join(line.split("#")[0] for line in body.splitlines())


# ---------------------------------------------------------------------------
# 27-30: migration 015
# ---------------------------------------------------------------------------


def _migration_sql() -> str:
    with open(_MIGRATION, encoding="utf-8") as f:
        text = f.read()
    return "\n".join(line.split("--")[0] for line in text.splitlines())


def _statements() -> list[str]:
    return [" ".join(s.split()) for s in _migration_sql().split(";") if s.strip()]


def test_migration_exact_statements():
    assert _statements() == [
        "GRANT USAGE ON SCHEMA public TO trace_viewer_reader",
        "GRANT SELECT ON public.anomaly_events TO trace_viewer_reader",
        "GRANT SELECT ON public.rca_investigations TO trace_viewer_reader",
        "GRANT SELECT ON public.rca_evidence TO trace_viewer_reader",
    ]


def test_migration_is_read_only_and_narrow():
    sql = _migration_sql().upper()
    for word in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER",
                 "ALL PRIVILEGES", "WITH GRANT OPTION", "CREATE ", "ALTER ", "DROP ",
                 "ALL TABLES", "PUBLIC;", "TO PUBLIC"):
        assert word not in sql, word


def test_migration_grants_only_to_trace_viewer_reader():
    for stmt in _statements():
        assert stmt.endswith(" TO trace_viewer_reader")


def test_migration_has_no_credentials_and_is_015():
    assert os.path.basename(_MIGRATION).startswith("015_")
    assert not re.search(r"PASSWORD|CREATE ROLE", _migration_sql(), re.I)


# ---------------------------------------------------------------------------
# 31: existing routes unchanged
# ---------------------------------------------------------------------------


def test_existing_trace_routes_still_registered():
    paths = {r.path for r in app.routes}
    assert {"/api/health", "/api/traces", "/api/traces/{trace_id}"} <= paths
    assert {"/api/anomalies", "/api/anomalies/{anomaly_id}",
            "/api/anomalies/{anomaly_id}/rca", "/api/rca/{investigation_id}"} <= paths


# ===========================================================================
# Phase 14.6.1: bounded free text and evidence in the anomaly and RCA responses
# ===========================================================================

from app import MAX_EVIDENCE_ROWS, MAX_LIMITATIONS, MAX_TEXT_CHARS


def test_normal_anomaly_is_unchanged_and_reports_no_truncation():
    stack, _, _ = _patched(get_anomaly={"return_value": _anomaly_row()})
    with stack:
        body = client.get(f"/api/anomalies/{_ANOMALY_ID}").json()
    assert body["explanation"] == "slow" and body["truncated_fields"] == []


def test_oversized_anomaly_explanation_is_cut_and_named():
    long = "e" * (MAX_TEXT_CHARS + 1)
    stack, _, _ = _patched(get_anomaly={"return_value": _anomaly_row(explanation=long)})
    with stack:
        body = client.get(f"/api/anomalies/{_ANOMALY_ID}").json()
    assert body["explanation"] == long[:MAX_TEXT_CHARS] and body["truncated_fields"] == ["explanation"]


def test_anomaly_explanation_exactly_at_the_limit_is_kept():
    exact = "e" * MAX_TEXT_CHARS
    stack, _, _ = _patched(get_anomaly={"return_value": _anomaly_row(explanation=exact)})
    with stack:
        body = client.get(f"/api/anomalies/{_ANOMALY_ID}").json()
    assert body["explanation"] == exact and body["truncated_fields"] == []


def test_anomaly_list_bounds_each_row_and_keeps_its_envelope():
    long = "e" * (MAX_TEXT_CHARS * 3)
    rows = [_anomaly_row(), _anomaly_row(explanation=long)]
    stack, _, _ = _patched(list_anomalies={"return_value": AnomalyListResult(2, rows)})
    with stack:
        body = client.get("/api/anomalies").json()
    assert set(body) == {"total", "limit", "offset", "anomalies"}
    assert [a["truncated_fields"] for a in body["anomalies"]] == [[], ["explanation"]]
    assert len(body["anomalies"][1]["explanation"]) == MAX_TEXT_CHARS


def test_empty_anomaly_list_is_unchanged():
    stack, _, _ = _patched(list_anomalies={"return_value": AnomalyListResult(0, [])})
    with stack:
        body = client.get("/api/anomalies").json()
    assert body == {"total": 0, "limit": 50, "offset": 0, "anomalies": []}


def test_the_database_row_is_not_modified_by_the_bound():
    long = "e" * (MAX_TEXT_CHARS + 10)
    row = _anomaly_row(explanation=long)
    stack, _, _ = _patched(get_anomaly={"return_value": row})
    with stack:
        client.get(f"/api/anomalies/{_ANOMALY_ID}")
    assert row["explanation"] == long and "truncated_fields" not in row


def test_normal_rca_is_unchanged_and_reports_no_truncation():
    stack, _, _ = _patched(get_rca_investigation={"return_value": _rca_row()})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert body["summary"] == "tool timed out" and body["limitations"] == ["no logs"]
    assert (body["truncated_fields"], body["omitted_evidence"]) == ([], 0)
    assert [e["rank_position"] for e in body["evidence"]] == [1, 2]
    assert all(e["truncated_fields"] == [] for e in body["evidence"])


def test_rca_without_evidence_is_valid():
    stack, _, _ = _patched(get_rca_investigation={"return_value": _rca_row(evidence=[], limitations=[])})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert body["evidence"] == [] and body["limitations"] == [] and body["omitted_evidence"] == 0


def test_oversized_rca_summary_limitations_and_evidence_text_are_cut_and_named():
    long = "t" * (MAX_TEXT_CHARS + 7)
    row = _rca_row(summary=long, limitations=["ok", long],
                   evidence=[_evidence_row(1, error_message=long, explanation=long, evidence_score_breakdown=long)])
    stack, _, _ = _patched(get_rca_investigation={"return_value": row})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert body["summary"] == long[:MAX_TEXT_CHARS]
    assert body["limitations"] == ["ok", long[:MAX_TEXT_CHARS]]
    assert body["truncated_fields"] == ["summary", "limitations"]
    evidence = body["evidence"][0]
    assert evidence["truncated_fields"] == ["error_message", "explanation", "evidence_score_breakdown"]
    assert all(len(evidence[f]) == MAX_TEXT_CHARS for f in ("error_message", "explanation", "evidence_score_breakdown"))


def test_rca_with_too_many_limitations_keeps_the_first_ones_and_says_so():
    items = [f"limit {i}" for i in range(MAX_LIMITATIONS + 5)]
    stack, _, _ = _patched(get_rca_investigation={"return_value": _rca_row(limitations=items)})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert body["limitations"] == items[:MAX_LIMITATIONS] and body["truncated_fields"] == ["limitations"]


def test_rca_evidence_over_the_row_limit_keeps_the_strongest_and_counts_the_rest():
    rows = [_evidence_row(rank) for rank in range(1, MAX_EVIDENCE_ROWS + 31)]
    stack, _, _ = _patched(get_rca_investigation={"return_value": _rca_row(evidence=rows)})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert len(body["evidence"]) == MAX_EVIDENCE_ROWS
    assert [e["rank_position"] for e in body["evidence"]] == list(range(1, MAX_EVIDENCE_ROWS + 1))
    assert body["omitted_evidence"] == 30 and body["truncated_fields"] == ["evidence"]


def test_rca_evidence_exactly_at_the_row_limit_is_complete():
    rows = [_evidence_row(rank) for rank in range(1, MAX_EVIDENCE_ROWS + 1)]
    stack, _, _ = _patched(get_rca_investigation={"return_value": _rca_row(evidence=rows)})
    with stack:
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert len(body["evidence"]) == MAX_EVIDENCE_ROWS and body["omitted_evidence"] == 0 and body["truncated_fields"] == []


def test_latest_rca_for_an_anomaly_is_bounded_the_same_way():
    long = "t" * (MAX_TEXT_CHARS + 1)
    stack, _, _ = _patched(get_latest_rca_for_anomaly={"return_value": _rca_row(summary=long)})
    with stack:
        body = client.get(f"/api/anomalies/{_ANOMALY_ID}/rca").json()
    assert len(body["summary"]) == MAX_TEXT_CHARS and body["truncated_fields"] == ["summary"]


def test_rca_database_rows_are_not_modified_by_the_bounds():
    long = "t" * (MAX_TEXT_CHARS + 1)
    evidence = _evidence_row(1, explanation=long)
    row = _rca_row(summary=long, limitations=[long], evidence=[evidence])
    stack, _, _ = _patched(get_rca_investigation={"return_value": row})
    with stack:
        client.get(f"/api/rca/{_INVESTIGATION_ID}")
    assert row["summary"] == long and row["limitations"] == [long] and evidence["explanation"] == long
    assert "truncated_fields" not in evidence


def test_anomaly_and_rca_responses_carry_the_headers():
    stack, _, _ = _patched(get_anomaly={"return_value": _anomaly_row()})
    with stack:
        resp = client.get(f"/api/anomalies/{_ANOMALY_ID}")
    assert resp.headers["cache-control"] == "no-store" and resp.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in resp.headers["content-security-policy"]


# ===========================================================================
# Phase 14.6.1 corrections (B3J-414): the bounds are applied by PostgreSQL
#
# The fake cursor below returns what the shortened SQL would return for a stored
# value (db_left), so the real query functions, the real mapping and the real
# endpoints are exercised end to end.  The SQL itself has not been run against
# PostgreSQL (no database connection is allowed in this step).
# ===========================================================================

from app import MAX_EVIDENCE_ROWS as _MAX_EV, MAX_LIMITATIONS as _MAX_LIM, MAX_TEXT_CHARS as _MAX_TXT


def db_left(value: str, n: int = 2001) -> str:
    """What PostgreSQL's left(value, n) returns (n characters, or all of a shorter value)."""
    return value[:n]


def test_the_fetch_sizes_are_the_api_limits_plus_one():
    import queries
    assert anomaly_queries.TEXT_FETCH_CHARS == queries.TEXT_FETCH_CHARS == _MAX_TXT + 1
    assert anomaly_queries.EVIDENCE_FETCH_ROWS == _MAX_EV + 1
    assert anomaly_queries.LIMITATIONS_FETCH_ITEMS == _MAX_LIM + 1


def test_anomaly_sql_shortens_only_the_explanation():
    sql = anomaly_queries._ANOMALY_SELECT
    assert re.findall(r"left\((\w+), (\d+)\)", sql) == [("explanation", "2001")]
    assert "left(explanation, 2001) AS explanation" in sql
    plain = re.sub(r"left\((\w+), \d+\) AS \1", r"\1", sql)
    assert "explanation,\n    detected_at\nFROM public.anomaly_events" in plain


def test_investigation_sql_shortens_the_summary_and_slices_and_shortens_the_limitations_in_order():
    sql = anomaly_queries._INVESTIGATION_SELECT
    assert "left(summary, 2001) AS summary" in sql
    assert "unnest(limitations[1:51]) WITH ORDINALITY AS u(item, ord)" in sql
    assert "SELECT left(item, 2001)" in sql and "ORDER BY ord" in sql
    assert ") AS limitations\nFROM public.rca_investigations" in sql


def test_evidence_sql_limits_rows_deterministically_counts_them_and_shortens_the_text():
    sql = anomaly_queries._EVIDENCE_SQL
    assert sql.rstrip().endswith("ORDER BY rank_position ASC, span_id ASC\nLIMIT 201")
    assert "count(*) OVER () AS evidence_total" in sql
    assert re.findall(r"left\((\w+), (\d+)\)", sql) == [
        ("error_message", "2001"), ("evidence_score_breakdown", "2001"), ("explanation", "2001")]
    assert re.findall(r"%\((\w+)\)s", sql) == ["investigation_id"]          # the only parameter, as before


def test_latest_investigation_sql_keeps_its_order_and_limit_with_the_bounded_columns():
    sql = anomaly_queries._LATEST_INVESTIGATION_SQL
    assert "left(summary, 2001) AS summary" in sql
    assert sql.rstrip().endswith("WHERE anomaly_id = %(anomaly_id)s\nORDER BY investigated_at DESC, investigation_id ASC\nLIMIT 1")


def test_queries_still_use_only_bound_parameters_for_every_user_value():
    cur = _FakeCursor([{"count": 0}, []])
    anomaly_queries.list_anomalies(_conn_with(cur), severity="INFO", service_name="x'; DROP TABLE y;--", trace_id=_TRACE_ID)
    for sql, params in cur.executed:
        assert "DROP TABLE" not in sql
    assert set(cur.executed[1][1]) == {"limit", "offset", "severity", "service_name", "trace_id"}


def test_attach_evidence_reports_the_true_total_and_removes_the_helper_column():
    rows = [_evidence_row(rank) | {"evidence_total": 230} for rank in range(1, 202)]
    cur = _FakeCursor([_rca_row() | {"evidence": None}, rows])
    result = anomaly_queries.get_rca_investigation(_conn_with(cur), _INVESTIGATION_ID)
    assert len(result["evidence"]) == 201 and result["evidence_total"] == 230
    assert all("evidence_total" not in e for e in result["evidence"])
    assert cur.executed[1][1] == {"investigation_id": _INVESTIGATION_ID}


def test_attach_evidence_with_no_rows_has_total_zero():
    cur = _FakeCursor([_rca_row() | {"evidence": None}, []])
    result = anomaly_queries.get_rca_investigation(_conn_with(cur), _INVESTIGATION_ID)
    assert result["evidence"] == [] and result["evidence_total"] == 0


def test_attach_evidence_without_the_total_column_counts_the_rows_it_has():
    cur = _FakeCursor([_rca_row() | {"evidence": None}, [_evidence_row(1), _evidence_row(2)]])
    result = anomaly_queries.get_rca_investigation(_conn_with(cur), _INVESTIGATION_ID)
    assert result["evidence_total"] == 2


# ---- end to end: stored length -> database shortening -> API metadata ---------------------------------------

_LENGTHS = [1, 1999, 2000, 2001, 2002, 5000]


def _expected_text(length: int) -> tuple[int, bool]:
    return min(length, _MAX_TXT), length > _MAX_TXT


@pytest.mark.parametrize("length", _LENGTHS)
def test_anomaly_explanation_exactly_2000_is_whole_and_2001_is_cut_and_named(length):
    stored = "e" * length
    cur = _FakeCursor([_anomaly_row(explanation=db_left(stored))])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/anomalies/{_ANOMALY_ID}").json()
    size, cut = _expected_text(length)
    assert len(body["explanation"]) == size and body["truncated_fields"] == (["explanation"] if cut else [])


@pytest.mark.parametrize("length", _LENGTHS)
def test_anomaly_list_rows_follow_the_same_rule(length):
    cur = _FakeCursor([{"count": 1}, [_anomaly_row(explanation=db_left("e" * length))]])
    with patch("app.connect", return_value=_conn_with(cur)):
        row = client.get("/api/anomalies").json()["anomalies"][0]
    size, cut = _expected_text(length)
    assert len(row["explanation"]) == size and row["truncated_fields"] == (["explanation"] if cut else [])


@pytest.mark.parametrize("length", _LENGTHS)
def test_rca_summary_limitation_and_evidence_text_follow_the_same_rule(length):
    value = db_left("t" * length)
    evidence = _evidence_row(1, error_message=value, explanation=value, evidence_score_breakdown=value) | {"evidence_total": 1}
    cur = _FakeCursor([_rca_row(summary=value, limitations=[value]) | {"evidence": None}, [evidence]])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    size, cut = _expected_text(length)
    assert len(body["summary"]) == size and len(body["limitations"][0]) == size
    assert body["truncated_fields"] == (["summary", "limitations"] if cut else [])
    item = body["evidence"][0]
    assert all(len(item[f]) == size for f in ("error_message", "explanation", "evidence_score_breakdown"))
    assert item["truncated_fields"] == (["error_message", "explanation", "evidence_score_breakdown"] if cut else [])


@pytest.mark.parametrize("total", [0, 1, 199, 200, 201, 202, 230, 5000])
def test_evidence_count_boundaries_use_the_total_from_the_database(total):
    returned = min(total, anomaly_queries.EVIDENCE_FETCH_ROWS)                 # what LIMIT 201 hands over
    rows = [_evidence_row(rank) | {"evidence_total": total} for rank in range(1, returned + 1)]
    cur = _FakeCursor([_rca_row() | {"evidence": None}, rows])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert len(body["evidence"]) == min(total, _MAX_EV)
    assert [e["rank_position"] for e in body["evidence"]] == list(range(1, min(total, _MAX_EV) + 1))
    assert body["omitted_evidence"] == max(total - _MAX_EV, 0)
    assert body["truncated_fields"] == (["evidence"] if total > _MAX_EV else [])
    assert "evidence_total" not in body and all("evidence_total" not in e for e in body["evidence"])


@pytest.mark.parametrize("handed_over", [0, 1, 49, 50, 51])
def test_limitation_count_boundaries_use_the_database_slice_of_fifty_one(handed_over):
    items = [f"limit {i}" for i in range(handed_over)]                          # the SQL slice [1:51] never hands over more than 51
    cur = _FakeCursor([_rca_row(limitations=items) | {"evidence": None}, []])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert body["limitations"] == items[:_MAX_LIM]
    assert body["truncated_fields"] == (["limitations"] if handed_over > _MAX_LIM else [])


def test_span_messages_exactly_2000_and_2001_end_to_end():
    import queries
    rows = []
    from datetime import timedelta
    for i, length in enumerate((2000, 2001, 3000)):
        rows.append({"trace_id": _TRACE_ID, "span_id": f"{i + 1:016x}", "parent_span_id": None if i == 0 else f"{1:016x}",
                     "span_name": "s", "span_kind": None, "service_name": "svc", "start_time": _DT + timedelta(milliseconds=i),
                     "end_time": _DT + timedelta(milliseconds=i + 1), "duration_ms": 1.0, "status_code": "ERROR",
                     "status_message": db_left("m" * length, queries.TEXT_FETCH_CHARS),
                     "error_message": db_left("e" * length, queries.TEXT_FETCH_CHARS), "is_demo_data": False})
    cur = MagicMock()
    cur.fetchall.return_value = rows
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    with patch("app.connect", return_value=conn):
        body = client.get(f"/api/traces/{_TRACE_ID}").json()
    spans = [body["roots"][0]["span"]] + [c["span"] for c in body["roots"][0]["children"]]
    assert [len(s["error_message"]) for s in spans] == [2000, 2000, 2000]
    assert [s["truncated_fields"] for s in spans] == [[], ["status_message", "error_message"], ["status_message", "error_message"]]


def test_response_structure_is_unchanged_except_for_the_documented_additive_fields():
    cur = _FakeCursor([_rca_row() | {"evidence": None}, [_evidence_row(1) | {"evidence_total": 1}]])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    original = {"investigation_id", "anomaly_id", "analyzer_version", "investigated_at", "trace_id", "subject_span_id",
                "service_name", "operation_name", "event_time", "trace_span_count", "anomaly_type", "observed_value",
                "baseline_median", "anomaly_score", "severity", "confidence", "summary", "limitations", "evidence"}
    assert set(body) == original | {"truncated_fields", "omitted_evidence"}
    original_evidence = {"rank_position", "span_id", "parent_span_id", "span_name", "service_name", "duration_ms", "status_code",
                         "error_type", "error_message", "tool_name", "tool_status", "agent_name", "agent_operation",
                         "retrieval_result_count", "retrieval_top_relevance_score", "is_root_span", "is_error_span",
                         "is_direct_subject", "depth", "trace_duration_fraction", "evidence_type", "evidence_score",
                         "evidence_score_breakdown", "explanation"}
    assert set(body["evidence"][0]) == original_evidence | {"truncated_fields"}


def test_evidence_rows_keep_the_query_ranking_in_the_response():
    rows = [_evidence_row(rank) | {"evidence_total": 3} for rank in (1, 2, 3)]
    cur = _FakeCursor([_rca_row() | {"evidence": None}, rows])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert [e["rank_position"] for e in body["evidence"]] == [1, 2, 3]


def test_the_largest_allowed_rca_and_anomaly_responses_are_measured():
    full = "t" * _MAX_TXT
    evidence = [_evidence_row(r, error_message=full, explanation=full, evidence_score_breakdown=full) | {"evidence_total": _MAX_EV}
                for r in range(1, _MAX_EV + 1)]
    row = _rca_row(summary=full, limitations=[full] * _MAX_LIM) | {"evidence": None}
    cur = _FakeCursor([row, evidence])
    with patch("app.connect", return_value=_conn_with(cur)):
        rca = client.get(f"/api/rca/{_INVESTIGATION_ID}")
    assert rca.status_code == 200 and rca.json()["truncated_fields"] == [] and len(rca.json()["evidence"]) == _MAX_EV
    assert 1_000_000 < len(rca.content) < 2_000_000                          # measured about 1.4 MB (regression ceiling)
    cur = _FakeCursor([{"count": 200}, [_anomaly_row(explanation=full)] * 200])
    with patch("app.connect", return_value=_conn_with(cur)):
        listing = client.get("/api/anomalies?limit=200")
    assert listing.status_code == 200 and 400_000 < len(listing.content) < 800_000     # measured about 0.5 MB


def test_a_reported_total_smaller_than_the_rows_in_hand_never_hides_rows():
    # Inconsistent input must not under-report: the rows actually received are the floor.
    rows = [_evidence_row(rank) | {"evidence_total": 3} for rank in range(1, _MAX_EV + 6)]       # 205 rows, total says 3
    cur = _FakeCursor([_rca_row() | {"evidence": None}, rows])
    with patch("app.connect", return_value=_conn_with(cur)):
        body = client.get(f"/api/rca/{_INVESTIGATION_ID}").json()
    assert len(body["evidence"]) == _MAX_EV and body["omitted_evidence"] == 5 and body["truncated_fields"] == ["evidence"]
