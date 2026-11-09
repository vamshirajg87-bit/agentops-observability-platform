"""
trace-viewer/tests/unit/test_app.py

TestClient unit tests for trace-viewer/app.py.

No live database.  All psycopg.Connection objects are MagicMock instances
obtained by patching app.connect.  No dependency_overrides are used — the
DB connection lives inside route bodies, so patching app.connect is both
necessary and sufficient.

The key architectural invariant under test:
    FastAPI validates query/path parameters BEFORE the route body runs.
    Because get_db() is a contextmanager inside the route body (not a
    Depends), malformed requests return 422 without ever calling connect().

Coverage targets
    1-2    GET /api/health
    3-9    GET /api/traces  — success
    10-14  GET /api/traces  — validation + DB error
    15-19  GET /api/traces/{trace_id}  — success + 404
    20-23  GET /api/traces/{trace_id}  — path validation
    24-25  GET /api/traces/{trace_id}  — DB error
    26-31  Connection lifecycle
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import app
from queries import TraceListResult
from reconstruction import SpanRecord, TraceNode, TraceReconstruction

# ---------------------------------------------------------------------------
# Constants and factories
# ---------------------------------------------------------------------------

_DT = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
_VALID_TRACE_ID = "a" * 32

client = TestClient(app, base_url="http://127.0.0.1")


def _make_trace_row(**overrides) -> dict:
    row = {
        "trace_id": _VALID_TRACE_ID,
        "trace_start_time": _DT,
        "trace_end_time": _DT,
        "trace_duration_ms": 100.0,
        "root_span_id": "b" * 32,
        "root_span_name": "root-span",
        "root_service_name": "my-service",
        "request_id": None,
        "session_id": None,
        "span_count": 1,
        "service_count": 1,
        "error_span_count": 0,
        "agent_span_count": 0,
        "tool_span_count": 0,
        "retrieval_span_count": 0,
        "has_error": False,
    }
    row.update(overrides)
    return row


def _make_span_record(**overrides) -> SpanRecord:
    kwargs: dict = dict(
        span_id="c" * 32,
        parent_span_id=None,
        span_name="test-span",
        start_time=_DT,
        end_time=_DT,
        duration_ms=50.0,
        status_code="STATUS_CODE_OK",
    )
    kwargs.update(overrides)
    return SpanRecord(**kwargs)


def _make_reconstruction(span_count: int = 1, **overrides) -> TraceReconstruction:
    node = TraceNode(span=_make_span_record())
    kwargs: dict = dict(
        roots=[node],
        orphans=[],
        cycle_members=[],
        has_cycle=False,
        span_count=span_count,
    )
    kwargs.update(overrides)
    return TraceReconstruction(**kwargs)


# ---------------------------------------------------------------------------
# 1-2: GET /api/health  — no DB dependency
# ---------------------------------------------------------------------------


def test_health_returns_200():
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_health_response_shape():
    resp = client.get("/api/health")
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 3-9: GET /api/traces  — success
# ---------------------------------------------------------------------------


def test_list_traces_default_params():
    """Default params are forwarded to list_traces with all filters None/empty."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces")
    mock_lt.assert_called_once_with(
        mock_conn,
        limit=50, offset=0, has_error=None,
        service_name=None, request_id=None, session_id=None,
        min_duration_ms=None, max_duration_ms=None, search=None,
    )


def test_list_traces_echoes_limit_and_offset():
    """limit and offset from the query string appear in the response body."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=5, traces=[_make_trace_row()])
        resp = client.get("/api/traces?limit=10&offset=20")
    assert resp.status_code == 200
    assert resp.json()["limit"] == 10
    assert resp.json()["offset"] == 20


def test_list_traces_total_in_response():
    """total from TraceListResult is passed through to the response."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=42, traces=[])
        resp = client.get("/api/traces")
    assert resp.status_code == 200
    assert resp.json()["total"] == 42


def test_list_traces_has_error_true():
    """has_error=true is parsed as bool True and forwarded."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=1, traces=[_make_trace_row(has_error=True)])
        client.get("/api/traces?has_error=true")
    mock_lt.assert_called_once_with(
        mock_conn,
        limit=50, offset=0, has_error=True,
        service_name=None, request_id=None, session_id=None,
        min_duration_ms=None, max_duration_ms=None, search=None,
    )


def test_list_traces_has_error_false():
    """has_error=false is parsed as bool False and forwarded."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?has_error=false")
    mock_lt.assert_called_once_with(
        mock_conn,
        limit=50, offset=0, has_error=False,
        service_name=None, request_id=None, session_id=None,
        min_duration_ms=None, max_duration_ms=None, search=None,
    )


def test_list_traces_empty_result():
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        resp = client.get("/api/traces")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0
    assert resp.json()["traces"] == []


def test_list_traces_response_shape():
    """A single trace row is serialized with all expected fields."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=1, traces=[_make_trace_row()])
        resp = client.get("/api/traces")
    assert resp.status_code == 200
    t = resp.json()["traces"][0]
    assert t["trace_id"] == _VALID_TRACE_ID
    assert t["span_count"] == 1
    assert t["has_error"] is False
    assert t["root_span_name"] == "root-span"
    assert t["service_count"] == 1


# ---------------------------------------------------------------------------
# 10-14: GET /api/traces  — validation + DB error
#
# Validation tests (10-13) require NO mock for connect().
# FastAPI validates query params before the route body runs — connect()
# is never called for malformed requests.
# ---------------------------------------------------------------------------


def test_list_traces_limit_zero_returns_422():
    resp = client.get("/api/traces?limit=0")
    assert resp.status_code == 422


def test_list_traces_limit_exceeds_max_returns_422():
    """limit > _MAX_LIMIT (200) returns 422."""
    resp = client.get("/api/traces?limit=201")
    assert resp.status_code == 422


def test_list_traces_negative_offset_returns_422():
    resp = client.get("/api/traces?offset=-1")
    assert resp.status_code == 422


def test_list_traces_invalid_has_error_returns_422():
    """A non-boolean has_error value returns 422."""
    resp = client.get("/api/traces?has_error=notabool")
    assert resp.status_code == 422


def test_list_traces_db_error_returns_503():
    """psycopg.Error raised by list_traces is caught by the global handler → 503."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces", side_effect=psycopg.OperationalError("db down")):
        resp = client.get("/api/traces")
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Database error"


# ---------------------------------------------------------------------------
# 15-19: GET /api/traces/{trace_id}  — success + 404
# ---------------------------------------------------------------------------


def test_get_trace_success():
    """A found trace returns 200 with trace_id, span_count, and has_cycle."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=_make_reconstruction(span_count=3)):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trace_id"] == _VALID_TRACE_ID
    assert body["span_count"] == 3
    assert body["has_cycle"] is False


def test_get_trace_response_shape():
    """The response includes all required top-level keys."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=_make_reconstruction()):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    for key in ("trace_id", "span_count", "has_cycle", "roots", "orphans", "cycle_members"):
        assert key in resp.json(), f"missing key: {key}"


def test_get_trace_span_fields():
    """SpanResponse inside a root node exposes all SpanRecord required fields."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=_make_reconstruction()):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    root = resp.json()["roots"][0]
    span = root["span"]
    assert span["span_id"] == "c" * 32
    assert span["span_name"] == "test-span"
    assert span["status_code"] == "STATUS_CODE_OK"
    assert span["duration_ms"] == 50.0
    assert root["is_cycle_member"] is False


def test_get_trace_children_recursive():
    """Nested children in the tree are serialized recursively."""
    mock_conn = MagicMock()
    child = TraceNode(span=_make_span_record(span_id="d" * 32, parent_span_id="c" * 32))
    parent = TraceNode(span=_make_span_record(), children=[child])
    recon = TraceReconstruction(
        roots=[parent], orphans=[], cycle_members=[], has_cycle=False, span_count=2,
    )
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=recon):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    root = resp.json()["roots"][0]
    assert len(root["children"]) == 1
    assert root["children"][0]["span"]["span_id"] == "d" * 32


def test_get_trace_not_found_returns_404():
    """span_count == 0 in the reconstruction → 404 with trace_id in detail."""
    mock_conn = MagicMock()
    empty_recon = TraceReconstruction(
        roots=[], orphans=[], cycle_members=[], has_cycle=False, span_count=0,
    )
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=empty_recon):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 404
    assert _VALID_TRACE_ID in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 20-23: GET /api/traces/{trace_id}  — path parameter validation
#
# Validation tests require NO mock for connect().
# FastAPI validates path params before the route body runs.
# ---------------------------------------------------------------------------


def test_get_trace_invalid_id_uppercase_returns_422():
    """Uppercase hex characters don't match the lowercase-only pattern → 422."""
    resp = client.get(f"/api/traces/{'A' * 32}")
    assert resp.status_code == 422


def test_get_trace_invalid_id_too_short_returns_422():
    resp = client.get(f"/api/traces/{'a' * 31}")
    assert resp.status_code == 422


def test_get_trace_invalid_id_too_long_returns_422():
    resp = client.get(f"/api/traces/{'a' * 33}")
    assert resp.status_code == 422


def test_get_trace_invalid_id_non_hex_returns_422():
    """31 valid hex chars + 'g' (invalid hex digit) → 422."""
    resp = client.get(f"/api/traces/{'a' * 31}g")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 24-25: GET /api/traces/{trace_id}  — DB error
# ---------------------------------------------------------------------------


def test_get_trace_db_error_returns_503():
    """psycopg.DatabaseError raised by get_trace_reconstruction → 503."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", side_effect=psycopg.DatabaseError("query failed")):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Database error"


def test_get_trace_connection_error_returns_503():
    """psycopg.OperationalError from a dropped connection → 503."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", side_effect=psycopg.OperationalError("dropped")):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# 26-31: Connection lifecycle
# ---------------------------------------------------------------------------


def test_connect_not_called_for_invalid_limit():
    """
    Malformed request (limit=0): FastAPI returns 422 before the route body
    runs — connect() is never called.

    Proves: DB unavailable + malformed request = 422, not 503.
    """
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?limit=0")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_connect_not_called_for_invalid_trace_id():
    """
    Malformed trace_id: FastAPI returns 422 before the route body runs —
    connect() is never called.
    """
    with patch("app.connect") as mock_connect:
        resp = client.get(f"/api/traces/{'A' * 32}")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_connect_raises_psycopg_error_returns_503():
    """psycopg.Error from connect() itself → 503 with a safe, generic message."""
    with patch("app.connect", side_effect=psycopg.OperationalError("connection refused")):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"] == "Database unavailable"
    # No credentials or connection strings in response
    assert "password" not in str(body).lower()
    assert "refused" not in str(body).lower()


def test_connect_fails_no_close_attempt():
    """If connect() fails, get_db never reaches the yield — close() is never called."""
    mock_connect = MagicMock(side_effect=RuntimeError("no password"))
    with patch("app.connect", mock_connect):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 503
    # The connection object that WOULD have been returned was never used
    mock_connect.return_value.close.assert_not_called()


def test_connection_closes_on_success():
    """get_db's finally block calls conn.close() after a successful request."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=_make_reconstruction()):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    mock_conn.close.assert_called_once()


def test_connection_closes_on_query_exception():
    """get_db's finally block calls conn.close() even when a query raises psycopg.Error."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", side_effect=psycopg.DatabaseError("boom")):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 503
    mock_conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# Phase 9.7: New filter params — forwarding
# ---------------------------------------------------------------------------


def test_list_traces_service_name_forwarded():
    """service_name is parsed and forwarded to list_traces."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?service_name=my-svc")
    _, kwargs = mock_lt.call_args
    assert kwargs["service_name"] == "my-svc"


def test_list_traces_request_id_forwarded():
    """request_id is parsed and forwarded to list_traces."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?request_id=req-abc")
    _, kwargs = mock_lt.call_args
    assert kwargs["request_id"] == "req-abc"


def test_list_traces_session_id_forwarded():
    """session_id is parsed and forwarded to list_traces."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?session_id=sess-xyz")
    _, kwargs = mock_lt.call_args
    assert kwargs["session_id"] == "sess-xyz"


def test_list_traces_min_duration_ms_forwarded():
    """min_duration_ms is parsed as float and forwarded."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?min_duration_ms=100")
    _, kwargs = mock_lt.call_args
    assert kwargs["min_duration_ms"] == 100.0


def test_list_traces_max_duration_ms_forwarded():
    """max_duration_ms is parsed as float and forwarded."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?max_duration_ms=5000")
    _, kwargs = mock_lt.call_args
    assert kwargs["max_duration_ms"] == 5000.0


def test_list_traces_duration_range_forwarded():
    """Both min and max duration are forwarded when both are valid."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?min_duration_ms=10&max_duration_ms=500")
    _, kwargs = mock_lt.call_args
    assert kwargs["min_duration_ms"] == 10.0
    assert kwargs["max_duration_ms"] == 500.0


def test_list_traces_search_forwarded():
    """search is parsed and forwarded to list_traces as-is (prefix % appended in queries.py)."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?search=abc123")
    _, kwargs = mock_lt.call_args
    assert kwargs["search"] == "abc123"


def test_list_traces_filters_and_has_error_combined():
    """service_name + has_error together are both forwarded."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        client.get("/api/traces?service_name=svc&has_error=true")
    _, kwargs = mock_lt.call_args
    assert kwargs["service_name"] == "svc"
    assert kwargs["has_error"] is True


# ---------------------------------------------------------------------------
# Phase 9.7: New filter params — validation (connect() never called)
# ---------------------------------------------------------------------------


def test_list_traces_min_gt_max_returns_422():
    """min_duration_ms > max_duration_ms → 422 before DB connection."""
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?min_duration_ms=1000&max_duration_ms=100")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_list_traces_negative_min_duration_returns_422():
    """min_duration_ms < 0 → 422 from FastAPI param validation before DB."""
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?min_duration_ms=-1")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_list_traces_negative_max_duration_returns_422():
    """max_duration_ms < 0 → 422 from FastAPI param validation before DB."""
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?max_duration_ms=-5")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_list_traces_non_numeric_min_duration_returns_422():
    """min_duration_ms=abc → 422 from FastAPI param validation before DB."""
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?min_duration_ms=abc")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_list_traces_non_numeric_max_duration_returns_422():
    """max_duration_ms=xyz → 422 from FastAPI param validation before DB."""
    with patch("app.connect") as mock_connect:
        resp = client.get("/api/traces?max_duration_ms=xyz")
    assert resp.status_code == 422
    mock_connect.assert_not_called()


def test_list_traces_equal_min_max_is_valid():
    """min_duration_ms == max_duration_ms is a valid single-point range."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.list_traces") as mock_lt:
        mock_lt.return_value = TraceListResult(total=0, traces=[])
        resp = client.get("/api/traces?min_duration_ms=100&max_duration_ms=100")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Phase 9.8: Error span data contract — error_type and error_message in response
#
# These tests lock the API data contract that the JS findDeepestErrorSpan relies
# on: the deepest ERROR span in a nested tree must expose error_type and
# error_message so the failure-summary banner can show the originating failure
# rather than a propagated ancestor error.
# ---------------------------------------------------------------------------


def test_get_trace_error_span_exposes_error_type():
    """A span with error_type set serializes that field in the detail response."""
    mock_conn = MagicMock()
    span = _make_span_record(status_code="ERROR", error_type="ToolExecutionError")
    recon = _make_reconstruction(roots=[TraceNode(span=span)])
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=recon):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    assert resp.json()["roots"][0]["span"]["error_type"] == "ToolExecutionError"


def test_get_trace_error_span_exposes_error_message():
    """A span with error_message set serializes that field in the detail response."""
    mock_conn = MagicMock()
    span = _make_span_record(
        status_code="ERROR",
        error_type="ToolExecutionError",
        error_message="External service unavailable: connection refused",
    )
    recon = _make_reconstruction(roots=[TraceNode(span=span)])
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=recon):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    assert resp.json()["roots"][0]["span"]["error_message"] == (
        "External service unavailable: connection refused"
    )


def test_get_trace_healthy_span_error_fields_are_null():
    """Healthy spans serialize error_type and error_message as null."""
    mock_conn = MagicMock()
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=_make_reconstruction()):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    span_json = resp.json()["roots"][0]["span"]
    assert span_json["error_type"] is None
    assert span_json["error_message"] is None


def test_get_trace_nested_error_span_data_contract():
    """Child ERROR span error_type and error_message appear in the nested tree response.

    This locks the data contract required by the JS findDeepestErrorSpan:
    a child span that is the originating failure must carry error_type and
    error_message through the API so the failure-summary banner can display
    'Failed at: tool.execute — ToolExecutionError: ...' rather than the
    propagated error on the parent root span.
    """
    mock_conn = MagicMock()
    child_span = _make_span_record(
        span_id="e" * 32,
        parent_span_id="c" * 32,
        span_name="tool.execute",
        status_code="ERROR",
        error_type="ToolExecutionError",
        error_message=(
            "External service unavailable: "
            "connection refused to metadata.example.internal"
        ),
    )
    parent_span = _make_span_record(span_name="agentops.request", status_code="ERROR")
    recon = TraceReconstruction(
        roots=[TraceNode(span=parent_span, children=[TraceNode(span=child_span)])],
        orphans=[],
        cycle_members=[],
        has_cycle=False,
        span_count=2,
    )
    with patch("app.connect", return_value=mock_conn), \
         patch("app.get_trace_reconstruction", return_value=recon):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 200
    body = resp.json()
    child_json = body["roots"][0]["children"][0]["span"]
    assert child_json["span_name"] == "tool.execute"
    assert child_json["status_code"] == "ERROR"
    assert child_json["error_type"] == "ToolExecutionError"
    assert "unavailable" in child_json["error_message"]


# ===========================================================================
# Phase 14.6.1: offline API hardening
#   A. connection safety   B. readiness   C. security headers   D. response bounds
# All offline: psycopg.connect and app.connect are patched; nothing connects.
# ===========================================================================

import pathlib
import re
from datetime import timedelta

import db
from app import (
    CONTENT_SECURITY_POLICY,
    MAX_SPANS_PER_TRACE,
    MAX_TEXT_CHARS,
    MAX_TREE_DEPTH,
)
from reconstruction import build_trace_tree

_STATIC = pathlib.Path(__file__).resolve().parents[2] / "static"


# ---- A. connection safety --------------------------------------------------


def _connect_env(monkeypatch, **extra):
    for name in ("HOST", "PORT", "NAME", "USER"):
        monkeypatch.delenv(f"TRACE_VIEWER_DB_{name}", raising=False)
    monkeypatch.setenv("TRACE_VIEWER_DB_PASSWORD", "not-a-real-password")
    for name, value in extra.items():
        monkeypatch.setenv(f"TRACE_VIEWER_DB_{name}", value)


def test_connect_is_read_only_by_default_with_a_five_second_statement_timeout(monkeypatch):
    _connect_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        db.connect()
    kwargs = connect.call_args.kwargs
    assert kwargs["options"] == "-c default_transaction_read_only=on -c statement_timeout=5000"
    assert db.STATEMENT_TIMEOUT_MS == 5000
    assert db.SESSION_OPTIONS == kwargs["options"]


def test_connect_bounds_connection_establishment(monkeypatch):
    _connect_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        db.connect()
    assert connect.call_args.kwargs["connect_timeout"] == db.CONNECT_TIMEOUT_SECONDS == 5


def test_connect_keeps_existing_credential_handling_and_defaults(monkeypatch):
    _connect_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        db.connect()
    kwargs = connect.call_args.kwargs
    assert connect.call_args.args == ()
    assert (kwargs["host"], kwargs["port"], kwargs["dbname"], kwargs["user"]) == (
        "localhost", 5432, "agentops", "trace_viewer_reader")
    assert kwargs["password"] == "not-a-real-password"


def test_connect_reads_overrides_from_the_environment(monkeypatch):
    _connect_env(monkeypatch, HOST="db.internal", PORT="6543", NAME="other", USER="someone")
    with patch("db.psycopg.connect") as connect:
        db.connect()
    kwargs = connect.call_args.kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["dbname"], kwargs["user"]) == ("db.internal", 6543, "other", "someone")
    assert kwargs["options"] == db.SESSION_OPTIONS            # the guard cannot be switched off by the environment


@pytest.mark.parametrize("value", [None, ""])
def test_connect_without_a_password_never_connects(monkeypatch, value):
    _connect_env(monkeypatch)
    if value is None:
        monkeypatch.delenv("TRACE_VIEWER_DB_PASSWORD")
    else:
        monkeypatch.setenv("TRACE_VIEWER_DB_PASSWORD", value)
    with patch("db.psycopg.connect") as connect:
        with pytest.raises(RuntimeError, match="TRACE_VIEWER_DB_PASSWORD"):
            db.connect()
    connect.assert_not_called()


def test_session_options_contain_no_credential_and_no_other_setting():
    assert re.fullmatch(r"-c default_transaction_read_only=on -c statement_timeout=\d+", db.SESSION_OPTIONS)


# ---- B. readiness ----------------------------------------------------------


def _ready_conn(row=(1,)):
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = row
    return conn


def test_ready_ok_runs_select_1_and_closes_the_connection():
    conn = _ready_conn()
    with patch("app.connect", return_value=conn):
        resp = client.get("/api/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "database": "ok"}
    conn.execute.assert_called_once_with("SELECT 1")
    conn.close.assert_called_once()
    conn.cursor.assert_not_called()                       # no table access, no cursor row factory


_SECRET = "s3cr3t-pa55w0rd"


@pytest.mark.parametrize("error", [
    psycopg.OperationalError(f"connection to server at db failed: password={_SECRET}"),
    RuntimeError("TRACE_VIEWER_DB_PASSWORD environment variable is not set"),
])
def test_ready_connection_failure_is_a_sanitized_503(error):
    with patch("app.connect", side_effect=error):
        resp = client.get("/api/health/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "unavailable", "database": "unavailable"}
    assert _SECRET not in resp.text and "password" not in resp.text.lower() and "Traceback" not in resp.text


def test_ready_statement_failure_is_a_sanitized_503_and_the_connection_is_closed():
    conn = MagicMock()
    conn.execute.side_effect = psycopg.errors.QueryCanceled(f"canceling statement; SELECT 1 password={_SECRET}")
    with patch("app.connect", return_value=conn):
        resp = client.get("/api/health/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "unavailable", "database": "unavailable"}
    assert _SECRET not in resp.text and "SELECT" not in resp.text
    conn.close.assert_called_once()


@pytest.mark.parametrize("row", [None, (0,), (2,)])
def test_ready_unexpected_result_is_503(row):
    with patch("app.connect", return_value=_ready_conn(row)):
        resp = client.get("/api/health/ready")
    assert resp.status_code == 503 and resp.json()["status"] == "unavailable"


def test_liveness_is_unchanged_and_still_needs_no_database():
    with patch("app.connect") as connect:
        resp = client.get("/api/health")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}
    connect.assert_not_called()


def test_ready_is_not_shadowed_by_a_trace_route():
    with patch("app.connect", return_value=_ready_conn()) as connect:
        assert client.get("/api/health/ready").status_code == 200
    connect.assert_called_once()


# ---- C. security headers ---------------------------------------------------


_ALL_PATHS = ["/", "/static/index.html", "/static/app.js", "/static/styles.css", "/api/health",
              "/api/health/ready", "/api/nowhere", "/nowhere", "/openapi.json"]


@pytest.mark.parametrize("path", _ALL_PATHS)
def test_every_response_carries_the_csp_and_nosniff(path):
    with patch("app.connect", side_effect=RuntimeError("no database")):
        resp = client.get(path)
    assert resp.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert resp.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", ["/api/health", "/api/health/ready", "/api/nowhere", "/api/traces", "/api/anomalies"])
def test_api_responses_are_no_store(path):
    with patch("app.connect", side_effect=RuntimeError("no database")):
        resp = client.get(path)
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/static/styles.css", "/nowhere", "/openapi.json"])
def test_no_store_is_for_api_paths_only(path):
    assert "no-store" not in client.get(path).headers.get("cache-control", "")


def test_api_error_responses_are_no_store_too():
    with patch("app.connect") as connect:
        bad = client.get("/api/traces?limit=0")                    # 422, never reaches the database
    connect.assert_not_called()
    assert bad.status_code == 422 and bad.headers["cache-control"] == "no-store"
    assert bad.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    with patch("app.connect", side_effect=psycopg.OperationalError("x")):
        down = client.get("/api/traces")
    assert down.status_code == 503 and down.headers["cache-control"] == "no-store"


def _directives(policy: str) -> dict[str, list[str]]:
    return {part.split()[0]: part.split()[1:] for part in policy.split("; ") if part}


def test_the_policy_is_same_origin_only_and_has_no_unsafe_source():
    d = _directives(CONTENT_SECURITY_POLICY)
    assert d["default-src"] == ["'none'"]
    for name in ("script-src", "style-src", "img-src", "font-src", "connect-src"):
        assert d[name] == ["'self'"], name
    assert d["base-uri"] == ["'none'"] and d["form-action"] == ["'self'"] and d["frame-ancestors"] == ["'none'"]
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY and "unsafe-eval" not in CONTENT_SECURITY_POLICY
    assert not re.search(r"https?:|\*|data:|blob:", CONTENT_SECURITY_POLICY)


def test_the_existing_ui_needs_nothing_the_policy_forbids():
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    raw_js = (_STATIC / "app.js").read_text(encoding="utf-8")
    # Comments may name a forbidden construct to say it is not used; only code counts.
    js = "\n".join(
        line for line in re.sub(r"/\*.*?\*/", "", raw_js, flags=re.S).splitlines()
        if not line.strip().startswith("//")
    )
    css = (_STATIC / "styles.css").read_text(encoding="utf-8")
    # script and stylesheet: one each, same origin, no inline body
    assert re.findall(r'<script\b[^>]*\bsrc="([^"]+)"', html) == ["/static/app.js"]
    assert not re.search(r"<script\b(?![^>]*\bsrc=)", html)
    assert all(not body.strip() for body in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S))
    assert re.findall(r'<link\b[^>]*\bhref="([^"]+)"', html) == ["/static/styles.css"]
    assert not re.search(r"<style\b", html)
    # no inline style attribute, no inline event handler, no javascript: URL, no external reference
    assert not re.search(r"\sstyle\s*=", html, re.I) and not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert "javascript:" not in html.lower() and not re.search(r"(src|href|action)=\"https?://", html)
    # the script: same-origin requests only, no code from strings, no inline style writes
    assert re.findall(r"fetch\(\s*([^)]*)\)", js)                    # it does use fetch ...
    assert not re.search(r"fetch\(\s*['\"]https?:", js) and not re.search(r"https?://", js)
    for forbidden in ("eval(", "new Function", "innerHTML", "insertAdjacentHTML", "document.write",
                      "setAttribute('style'", 'setAttribute("style"', "cssText", ".style.", "importScripts",
                      "WebSocket", "EventSource", "XMLHttpRequest"):
        assert forbidden not in js, forbidden
    assert "@import" not in css and not re.search(r"url\(\s*['\"]?(https?:|//|data:)", css)


def test_the_ui_assets_are_served_with_the_policy_and_their_own_types():
    for path, kind in (("/", "text/html"), ("/static/app.js", "javascript"), ("/static/styles.css", "text/css")):
        resp = client.get(path)
        assert resp.status_code == 200 and kind in resp.headers["content-type"], path
        assert resp.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_interactive_documentation_pages_that_need_external_scripts_are_not_served():
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 200        # the machine-readable contract stays


# ---- D. response bounds ----------------------------------------------------

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _span(i: int, parent: int | None, **overrides) -> SpanRecord:
    kwargs = dict(
        span_id=f"{i + 1:016x}", parent_span_id=None if parent is None else f"{parent + 1:016x}",
        span_name="s", start_time=_T0 + timedelta(milliseconds=i), end_time=_T0 + timedelta(milliseconds=i + 1),
        duration_ms=1.0, status_code="OK", trace_id=_VALID_TRACE_ID)
    kwargs.update(overrides)
    return SpanRecord(**kwargs)


def _chain(n: int) -> TraceReconstruction:
    return build_trace_tree([_span(i, None if i == 0 else i - 1) for i in range(n)])


def _wide(n: int) -> TraceReconstruction:
    return build_trace_tree([_span(i, None if i == 0 else 0) for i in range(n)])


def _get_trace(result: TraceReconstruction):
    with patch("app.connect", return_value=MagicMock()), patch("app.get_trace_reconstruction", return_value=result) as m:
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    return resp, m


def _depth(nodes: list[dict]) -> int:
    best, stack = 0, [(n, 1) for n in nodes]
    while stack:
        node, d = stack.pop()
        best = max(best, d)
        stack.extend((c, d + 1) for c in node["children"])
    return best


def test_bounds_are_the_documented_values():
    assert (MAX_SPANS_PER_TRACE, MAX_TREE_DEPTH, MAX_TEXT_CHARS) == (1000, 64, 2000)
    assert MAX_TREE_DEPTH < 98                       # the serializer cannot represent a chain of about 98 or more


def test_trace_detail_requests_a_bounded_read():
    resp, m = _get_trace(_make_reconstruction())
    assert resp.status_code == 200
    assert m.call_args.kwargs == {"max_spans": MAX_SPANS_PER_TRACE}


def test_normal_trace_is_complete_and_reports_no_truncation():
    resp, _ = _get_trace(_chain(5))
    body = resp.json()
    assert resp.status_code == 200 and body["span_count"] == 5 and _depth(body["roots"]) == 5
    assert (body["truncated"], body["truncation_reasons"], body["omitted_spans"]) == (False, [], 0)
    assert (body["max_spans"], body["max_depth"]) == (MAX_SPANS_PER_TRACE, MAX_TREE_DEPTH)
    assert all(n["children_truncated"] is False for n in body["roots"])


def test_existing_trace_detail_fields_are_unchanged():
    body = _get_trace(_make_reconstruction())[0].json()
    assert {"trace_id", "span_count", "has_cycle", "roots", "orphans", "cycle_members", "is_demo_data"} <= set(body)
    assert body["roots"][0]["span"]["span_name"] == "test-span" and body["roots"][0]["span"]["truncated_fields"] == []


def test_trace_with_more_spans_than_the_read_limit_says_so():
    result = _wide(10)
    result.truncated = True
    body = _get_trace(result)[0].json()
    assert body["truncated"] is True and body["truncation_reasons"] == ["span_limit"] and body["omitted_spans"] == 0
    assert body["span_count"] == 10                       # spans READ; the trace has more


def test_empty_trace_is_still_a_404_and_not_truncated():
    with patch("app.connect", return_value=MagicMock()), \
         patch("app.get_trace_reconstruction", return_value=build_trace_tree([])):
        resp = client.get(f"/api/traces/{_VALID_TRACE_ID}")
    assert resp.status_code == 404


def test_a_chain_exactly_at_the_depth_limit_is_complete():
    body = _get_trace(_chain(MAX_TREE_DEPTH))[0].json()
    assert _depth(body["roots"]) == MAX_TREE_DEPTH and body["truncated"] is False and body["omitted_spans"] == 0


def test_a_chain_one_over_the_depth_limit_is_cut_and_counted():
    resp, _ = _get_trace(_chain(MAX_TREE_DEPTH + 1))
    body = resp.json()
    assert resp.status_code == 200
    assert _depth(body["roots"]) == MAX_TREE_DEPTH
    assert (body["truncated"], body["truncation_reasons"], body["omitted_spans"]) == (True, ["depth_limit"], 1)
    # the deepest returned span is flagged, the others are not
    node = body["roots"][0]
    while node["children"]:
        assert node["children_truncated"] is False
        node = node["children"][0]
    assert node["children_truncated"] is True


def test_a_very_deep_chain_no_longer_fails_to_serialize():
    # Before the bound, a chain of about 100 or more spans could not be serialized (HTTP 500).
    for size in (200, 999):
        resp, _ = _get_trace(_chain(size))
        body = resp.json()
        assert resp.status_code == 200, size
        assert _depth(body["roots"]) == MAX_TREE_DEPTH
        assert body["omitted_spans"] == size - MAX_TREE_DEPTH and body["truncation_reasons"] == ["depth_limit"]


def test_both_limits_are_reported_together():
    result = _chain(300)
    result.truncated = True
    body = _get_trace(result)[0].json()
    assert body["truncation_reasons"] == ["span_limit", "depth_limit"] and body["truncated"] is True


def test_the_deepest_error_branch_depth_cut_also_applies_to_orphans_and_cycle_members():
    deep = build_trace_tree([_span(i, None if i == 0 else i - 1) for i in range(80)]).roots
    result = TraceReconstruction(roots=[], orphans=deep, cycle_members=deep, has_cycle=True, span_count=160)
    body = _get_trace(result)[0].json()
    assert _depth(body["orphans"]) == MAX_TREE_DEPTH == _depth(body["cycle_members"])
    assert body["omitted_spans"] == 2 * (80 - MAX_TREE_DEPTH)


def test_a_full_size_trace_is_bounded_in_bytes():
    resp, _ = _get_trace(_wide(MAX_SPANS_PER_TRACE))
    assert resp.status_code == 200 and resp.json()["span_count"] == MAX_SPANS_PER_TRACE
    assert len(resp.content) < 1_000_000                        # about 0.6 MB for 1,000 spans of this size


def test_oversized_span_messages_are_cut_and_named():
    long = "x" * (MAX_TEXT_CHARS + 500)
    result = build_trace_tree([_span(0, None, error_message=long, status_message=long)])
    span = _get_trace(result)[0].json()["roots"][0]["span"]
    assert len(span["error_message"]) == MAX_TEXT_CHARS and len(span["status_message"]) == MAX_TEXT_CHARS
    assert span["error_message"] == long[:MAX_TEXT_CHARS]
    assert span["truncated_fields"] == ["status_message", "error_message"]


def test_a_message_exactly_at_the_limit_is_not_cut():
    exact = "y" * MAX_TEXT_CHARS
    span = _get_trace(build_trace_tree([_span(0, None, error_message=exact)]))[0].json()["roots"][0]["span"]
    assert span["error_message"] == exact and span["truncated_fields"] == []


def test_absent_and_empty_messages_are_untouched():
    span = _get_trace(build_trace_tree([_span(0, None, error_message=None, status_message="")]))[0].json()["roots"][0]["span"]
    assert span["error_message"] is None and span["status_message"] == "" and span["truncated_fields"] == []


def test_message_limit_counts_characters_not_bytes():
    text = "é" * MAX_TEXT_CHARS                                  # 2,000 characters, 4,000 bytes: within the limit
    span = _get_trace(build_trace_tree([_span(0, None, error_message=text)]))[0].json()["roots"][0]["span"]
    assert span["error_message"] == text and span["truncated_fields"] == []


def test_trace_list_is_unchanged_by_the_bounds():
    with patch("app.connect", return_value=MagicMock()), patch("app.list_traces") as lt:
        lt.return_value = TraceListResult(total=1, traces=[_make_trace_row()])
        body = client.get("/api/traces").json()
    assert set(body) == {"total", "limit", "offset", "traces"} and body["traces"][0]["trace_id"] == _VALID_TRACE_ID


# ===========================================================================
# Phase 14.6.1 corrections (B3J-414): invalid database port (F1), the bound
# applied in SQL (F3, see test_queries.py and test_anomaly_api.py) and the size of
# the largest allowed responses (F4)
# ===========================================================================

_PORT_SECRET = "p0rt-s3cr3t-value"


@pytest.mark.parametrize("value", [
    "abc", "", "5432x", "54.32", "0", "-1", "65536", "99999", _PORT_SECRET, "0x1538", "5432 5433",
])
def test_an_invalid_port_raises_a_sanitized_runtime_error_and_never_connects(monkeypatch, value):
    _connect_env(monkeypatch, PORT=value)
    with patch("db.psycopg.connect") as connect:
        with pytest.raises(RuntimeError) as caught:
            db.connect()
    connect.assert_not_called()
    assert "TRACE_VIEWER_DB_PORT" in str(caught.value)
    assert value not in str(caught.value) or value == ""            # the raw value is never echoed
    assert "not-a-real-password" not in str(caught.value)


@pytest.mark.parametrize("value, expected", [("1", 1), ("5432", 5432), ("6543", 6543), ("65535", 65535)])
def test_a_valid_port_connects_with_unchanged_options(monkeypatch, value, expected):
    _connect_env(monkeypatch, PORT=value)
    with patch("db.psycopg.connect") as connect:
        db.connect()
    kwargs = connect.call_args.kwargs
    assert kwargs["port"] == expected and isinstance(kwargs["port"], int)
    assert kwargs["options"] == db.SESSION_OPTIONS and kwargs["connect_timeout"] == db.CONNECT_TIMEOUT_SECONDS


def test_the_default_port_is_unchanged(monkeypatch):
    _connect_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        db.connect()
    assert connect.call_args.kwargs["port"] == 5432


def test_the_password_is_still_checked_before_the_port(monkeypatch):
    _connect_env(monkeypatch, PORT="abc")
    monkeypatch.delenv("TRACE_VIEWER_DB_PASSWORD")
    with pytest.raises(RuntimeError, match="PASSWORD"):
        db.connect()


_PLAIN_ERROR_CLIENT = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False)


def _bad_port_env(monkeypatch):
    _connect_env(monkeypatch, PORT=_PORT_SECRET)


def test_invalid_port_gives_a_sanitized_503_on_readiness_with_all_headers(monkeypatch):
    _bad_port_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        resp = _PLAIN_ERROR_CLIENT.get("/api/health/ready")
    connect.assert_not_called()
    assert resp.status_code == 503
    assert resp.json() == {"status": "unavailable", "database": "unavailable"}
    assert _PORT_SECRET not in resp.text and "TRACE_VIEWER_DB_PORT" not in resp.text and "Traceback" not in resp.text
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert resp.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", [
    "/api/traces", f"/api/traces/{_VALID_TRACE_ID}", "/api/anomalies", f"/api/anomalies/{'a' * 64}",
    f"/api/anomalies/{'a' * 64}/rca", f"/api/rca/{'b' * 64}",
])
def test_invalid_port_gives_the_sanitized_database_503_on_every_data_endpoint(monkeypatch, path):
    _bad_port_env(monkeypatch)
    with patch("db.psycopg.connect") as connect:
        resp = _PLAIN_ERROR_CLIENT.get(path)
    connect.assert_not_called()
    assert resp.status_code == 503 and resp.json() == {"detail": "Database unavailable"}
    assert _PORT_SECRET not in resp.text and "TRACE_VIEWER_DB_PORT" not in resp.text
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_malformed_requests_still_fail_validation_before_the_port_is_read(monkeypatch):
    _bad_port_env(monkeypatch)
    resp = _PLAIN_ERROR_CLIENT.get("/api/traces?limit=0")
    assert resp.status_code == 422                                # validation first; no database work at all


def test_unrelated_programming_errors_are_not_hidden_as_database_errors():
    # get_db converts RuntimeError and psycopg.Error only: anything else is still a server error.
    for error in (ValueError("a bug"), KeyError("a bug"), TypeError("a bug")):
        with patch("app.connect", side_effect=error):
            resp = _PLAIN_ERROR_CLIENT.get("/api/health/ready")
        assert resp.status_code == 500, type(error).__name__
        with patch("app.connect", side_effect=error):
            assert _PLAIN_ERROR_CLIENT.get("/api/traces").status_code == 500


def test_get_db_catches_exactly_runtime_and_psycopg_errors():
    import inspect
    source = inspect.getsource(app_module.get_db)
    assert "except (RuntimeError, psycopg.Error)" in source and "except Exception" not in source


# ---- F4: the largest responses the bounds allow ------------------------------------------------------------

import app as app_module                                         # noqa: E402  (module object for getsource)


def _max_text_span(i: int, parent: int | None) -> SpanRecord:
    full = "x" * MAX_TEXT_CHARS
    return _span(i, parent, span_name="tool.execute", status_code="ERROR", service_name="service-name",
                 status_message=full, error_message=full, error_type="ValueError", tool_name="tool", agent_name="agent")


def test_the_largest_allowed_trace_response_is_measured_and_bounded():
    result = build_trace_tree([_max_text_span(i, None if i == 0 else 0) for i in range(MAX_SPANS_PER_TRACE)])
    resp, _ = _get_trace(result)
    body = resp.json()
    assert resp.status_code == 200 and body["span_count"] == MAX_SPANS_PER_TRACE and body["truncated"] is False
    spans = body["roots"][0]["children"]
    assert len(spans) == MAX_SPANS_PER_TRACE - 1
    assert all(len(s["span"]["error_message"]) == MAX_TEXT_CHARS == len(s["span"]["status_message"]) for s in spans)
    assert all(s["span"]["truncated_fields"] == [] for s in spans)          # exactly at the limit: nothing cut
    # Measured 4,702,209 bytes: 1,000 spans x 4,000 characters of text (4.0 MB) plus about 0.7 MB of structure.
    # This is a regression ceiling that documents today's worst case, not a product limit.
    assert 4_000_000 < len(resp.content) < 5_500_000


def test_the_same_trace_with_over_long_text_is_no_larger_than_the_allowed_maximum():
    long = "x" * (MAX_TEXT_CHARS * 10)
    big = build_trace_tree([_span(i, None if i == 0 else 0, error_message=long, status_message=long) for i in range(MAX_SPANS_PER_TRACE)])
    fits = build_trace_tree([_max_text_span(i, None if i == 0 else 0) for i in range(MAX_SPANS_PER_TRACE)])
    over, _ = _get_trace(big)
    allowed, _ = _get_trace(fits)
    # over-long text is cut to the same length, so only the "truncated_fields" metadata differs
    assert len(over.content) < len(allowed.content) * 1.05
    assert all(s["span"]["truncated_fields"] == ["status_message", "error_message"] for s in over.json()["roots"][0]["children"])


def test_the_largest_allowed_chain_is_small_because_of_the_depth_limit():
    result = build_trace_tree([_max_text_span(i, None if i == 0 else i - 1) for i in range(MAX_SPANS_PER_TRACE)])
    resp, _ = _get_trace(result)
    assert resp.status_code == 200 and resp.json()["omitted_spans"] == MAX_SPANS_PER_TRACE - MAX_TREE_DEPTH
    assert len(resp.content) < 600_000                                      # measured 301,095 bytes
