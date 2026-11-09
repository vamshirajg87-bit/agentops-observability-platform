"""
trace-viewer/app.py

FastAPI application for the AgentOps Trace Viewer API.

Routing layer only — no SQL, no trace-tree reconstruction.
All data access is delegated to Phase 9.3 (queries.py).
All tree building is delegated to Phase 9.2 (reconstruction.py).

HTTP request
    ↓
FastAPI validates query/path parameters  ← 422 returned here if malformed
    ↓
Route body: get_db() opens connection    ← 503 returned here if DB unavailable
    ↓
Phase 9.3 query layer  (queries.py)
    ↓
Phase 9.2 reconstruction  (reconstruction.py)
    ↓
JSON response

Dependency-ordering note:
    FastAPI resolves Depends() before validating route-function parameters
    (query/path).  Placing the DB connection in a contextmanager inside the
    route body — rather than as Depends(get_db) — guarantees that a malformed
    request returns 422 before a DB connection is ever attempted.
"""

from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import re
from contextlib import contextmanager
from datetime import datetime
from typing import Annotated, Any, Generator, Literal, Mapping

import psycopg
from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from anomaly_queries import (
    get_anomaly,
    get_latest_rca_for_anomaly,
    get_rca_investigation,
    list_anomalies,
)
from db import connect
from queries import get_trace_reconstruction, list_traces
from reconstruction import SpanRecord, TraceNode, TraceReconstruction

logger = logging.getLogger(__name__)

# Maximum allowed value for the `limit` query parameter.
_MAX_LIMIT: int = 200

# ---------------------------------------------------------------------------
# Response bounds
# ---------------------------------------------------------------------------
#
# Every bound below is reported, never silent: a limited response says so in its
# own `truncated` / `truncated_fields` metadata.  The limits keep one response a
# size a browser can render and keep the response model inside the nesting depth
# the JSON serializer supports (a chain deeper than about 98 spans cannot be
# serialized at all).

#: Spans read and returned for one trace (earliest first).
MAX_SPANS_PER_TRACE: int = 1000
#: Nesting depth of the returned execution tree; deeper spans are omitted and
#: counted.  Kept well below the serializer's limit.
MAX_TREE_DEPTH: int = 64
#: Characters of any free-text field (error and status messages, explanations,
#: summaries, score breakdowns, limitations).
MAX_TEXT_CHARS: int = 2000
#: Evidence rows returned per RCA investigation, and limitation entries.
MAX_EVIDENCE_ROWS: int = 200
MAX_LIMITATIONS: int = 50

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

# The interactive documentation pages (/docs, /redoc) load their scripts from
# external CDNs, which the Content-Security-Policy below does not allow and a
# local-first viewer should not need; the machine-readable /openapi.json stays.
app = FastAPI(
    title="AgentOps Trace Viewer API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)

#: The existing UI is one HTML page, one script and one stylesheet, all served
#: from this origin, with no inline script or style and no external request.
CONTENT_SECURITY_POLICY: str = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """
    Adds the security headers to every HTTP response this application produces
    (static files, API responses and the error responses of its handlers):

        Content-Security-Policy   CONTENT_SECURITY_POLICY
        X-Content-Type-Options    nosniff
        Cache-Control: no-store   API responses only (paths under /api)

    A pure ASGI middleware, so it does not buffer or re-read response bodies.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_api = path == "/api" or path.startswith("/api/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
                headers["X-Content-Type-Options"] = "nosniff"
                if is_api:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
# Host-header allow-list
# ---------------------------------------------------------------------------
#
# The viewer has no authentication and listens on loopback only.  A browser can
# still be steered to it under an attacker's hostname (DNS rebinding), which would
# let that page read traces, anomalies and RCA text.  Only the hostnames below are
# served; any other Host header gets 400 "Invalid host header" before a route, the
# static files or the database is reached.  The port in the header is ignored on
# purpose: the published port (8000 or 8001) is not the one the server listens on
# inside the container.
#
# This is not authentication: a program on the machine can send any Host value.
# Matching is exact and case-sensitive, as in Starlette's TrustedHostMiddleware
# (browsers send the hostname in lower case), and an IPv6 literal such as [::1] is
# not supported.
#
# TRACE_VIEWER_ALLOWED_HOSTS (comma-separated) can ADD exact hostnames.  It cannot
# remove the two loopback names, replace them or switch the check off.

ENV_ALLOWED_HOSTS: str = "TRACE_VIEWER_ALLOWED_HOSTS"
DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")

# One DNS label: 1-63 letters, digits or hyphens, not starting or ending with a hyphen.
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def allowed_hosts_from_environment(environ: Mapping[str, str]) -> list[str]:
    """
    The hostnames the viewer serves: the two loopback names, plus any exact
    hostnames named in TRACE_VIEWER_ALLOWED_HOSTS.

    Unset gives the two defaults.  A value that is set must be a comma-separated
    list of plain ASCII hostnames (letters, digits, hyphens and dots; each label
    1-63 characters, 253 in all; upper case is lowered).  An empty value or entry,
    a wildcard, a port, a scheme, a path, an '@', whitespace inside an entry or any
    other malformed name raises ValueError: the check is never relaxed to cope with
    a bad setting.  The message names the variable and the position of the entry,
    never its text.
    """
    raw = environ.get(ENV_ALLOWED_HOSTS)
    hosts = list(DEFAULT_ALLOWED_HOSTS)
    if raw is None:
        return hosts
    for position, entry in enumerate(raw.split(","), start=1):
        stripped = entry.strip()
        name = stripped.lower() if stripped.isascii() else ""
        if (not name or len(name) > 253
                or not all(_HOST_LABEL.fullmatch(label) for label in name.split("."))):
            raise ValueError(
                f"{ENV_ALLOWED_HOSTS}: entry {position} is not a plain hostname "
                "(it must not be empty, a wildcard, or contain a port, scheme, path or whitespace)"
            )
        if name not in hosts:
            hosts.append(name)
    return hosts


ALLOWED_HOSTS: list[str] = allowed_hosts_from_environment(os.environ)

# Registered first on purpose: Starlette makes the last-added middleware the
# outermost, so SecurityHeadersMiddleware (added next) also wraps the host check's
# 400 response and every rejected request still carries the CSP and nosniff headers.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS, www_redirect=False)
app.add_middleware(SecurityHeadersMiddleware)

_STATIC_DIR = pathlib.Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")

# ---------------------------------------------------------------------------
# Free-text bounds
# ---------------------------------------------------------------------------


def _cap_text(value: str | None, limit: int = MAX_TEXT_CHARS) -> tuple[str | None, bool]:
    """(value limited to `limit` characters, whether it was shortened).  None stays None."""
    if value is None or len(value) <= limit:
        return value, False
    return value[:limit], True


def _capped_row(row: dict[str, Any], text_fields: tuple[str, ...]) -> dict[str, Any]:
    """
    A copy of `row` whose free-text fields are limited to MAX_TEXT_CHARS, with the
    names of the fields that were shortened under "truncated_fields".  The
    database row itself is not changed.
    """
    out = dict(row)
    shortened: list[str] = []
    for name in text_fields:
        out[name], was_cut = _cap_text(out.get(name))
        if was_cut:
            shortened.append(name)
    out["truncated_fields"] = shortened
    return out


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str


class ReadyResponse(BaseModel):
    """Result of GET /api/health/ready."""

    status: str
    database: str


class TraceSummary(BaseModel):
    """One trace row from analytics.int_trace_spans."""

    trace_id: str
    trace_start_time: datetime
    trace_end_time: datetime
    trace_duration_ms: float
    root_span_id: str | None
    root_span_name: str | None
    root_service_name: str | None
    request_id: str | None
    session_id: str | None
    span_count: int
    service_count: int
    error_span_count: int
    agent_span_count: int
    tool_span_count: int
    retrieval_span_count: int
    has_error: bool
    is_demo_data: bool = False      # derived from the demo_seed span attribute


class TraceListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    traces: list[TraceSummary]


class SpanResponse(BaseModel):
    """Serialized SpanRecord — mirrors all 22 Phase 9.2 SpanRecord fields."""

    # Required fields (7)
    span_id: str
    parent_span_id: str | None
    span_name: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    status_code: str
    # Optional fields (15)
    trace_id: str | None = None
    service_name: str | None = None
    span_kind: str | None = None
    status_message: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    gen_ai_operation: str | None = None
    agent_name: str | None = None
    agent_operation: str | None = None
    tool_name: str | None = None
    tool_status: str | None = None
    retrieval_result_count: int | None = None
    retrieval_top_relevance_score: float | None = None
    error_type: str | None = None
    error_message: str | None = None
    is_demo_data: bool = False
    # Names of free-text fields shortened to MAX_TEXT_CHARS (empty when none).
    truncated_fields: list[str] = []

    @classmethod
    def from_span_record(cls, span: SpanRecord) -> SpanResponse:
        status_message, status_cut = _cap_text(span.status_message)
        error_message, error_cut = _cap_text(span.error_message)
        return cls(
            span_id=span.span_id,
            parent_span_id=span.parent_span_id,
            span_name=span.span_name,
            start_time=span.start_time,
            end_time=span.end_time,
            duration_ms=span.duration_ms,
            status_code=span.status_code,
            trace_id=span.trace_id,
            service_name=span.service_name,
            span_kind=span.span_kind,
            status_message=status_message,
            request_id=span.request_id,
            session_id=span.session_id,
            gen_ai_operation=span.gen_ai_operation,
            agent_name=span.agent_name,
            agent_operation=span.agent_operation,
            tool_name=span.tool_name,
            tool_status=span.tool_status,
            retrieval_result_count=span.retrieval_result_count,
            retrieval_top_relevance_score=span.retrieval_top_relevance_score,
            error_type=span.error_type,
            error_message=error_message,
            is_demo_data=span.is_demo_data,
            truncated_fields=[
                name for name, was_cut in (("status_message", status_cut), ("error_message", error_cut)) if was_cut
            ],
        )


def _count_nodes(nodes: list[TraceNode]) -> int:
    """Number of spans in the given subtrees (iterative)."""
    return sum(1 for _ in _walk(nodes))


class TraceNodeResponse(BaseModel):
    """One node in the reconstructed trace tree (recursive)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    span: SpanResponse
    children: list[TraceNodeResponse]
    is_cycle_member: bool
    # True when this node has descendants that were left out because the tree
    # would otherwise be deeper than MAX_TREE_DEPTH.
    children_truncated: bool = False

    @classmethod
    def from_trace_node(
        cls,
        node: TraceNode,
        depth: int = 1,
        omitted: list[int] | None = None,
    ) -> TraceNodeResponse:
        """
        `depth` is this node's depth (a root is 1).  A node at MAX_TREE_DEPTH is
        returned without its children; their span count is added to omitted[0]
        when a one-element list is given.  Recursion is bounded by MAX_TREE_DEPTH.
        """
        if depth >= MAX_TREE_DEPTH and node.children:
            if omitted is not None:
                omitted[0] += _count_nodes(node.children)
            return cls(
                span=SpanResponse.from_span_record(node.span),
                children=[],
                is_cycle_member=node.is_cycle_member,
                children_truncated=True,
            )
        return cls(
            span=SpanResponse.from_span_record(node.span),
            children=[cls.from_trace_node(c, depth + 1, omitted) for c in node.children],
            is_cycle_member=node.is_cycle_member,
        )


# Required for Pydantic v2 to resolve the self-referential `children` field.
TraceNodeResponse.model_rebuild()


def _walk(nodes: list[TraceNode]) -> Generator[TraceNode, None, None]:
    """Every node of the given subtrees (iterative, so a deep trace cannot exhaust the stack)."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.children)


class TraceDetailResponse(BaseModel):
    """Full reconstructed trace returned by GET /api/traces/{trace_id}."""

    trace_id: str
    span_count: int
    has_cycle: bool
    roots: list[TraceNodeResponse]
    orphans: list[TraceNodeResponse]
    cycle_members: list[TraceNodeResponse]
    is_demo_data: bool = False
    # Bounds (see MAX_SPANS_PER_TRACE and MAX_TREE_DEPTH).  span_count is the
    # number of spans READ; when `truncated` the trace has more spans than that.
    # `omitted_spans` counts spans read but left out of the tree by the depth
    # limit.  truncation_reasons lists "span_limit" and/or "depth_limit".
    truncated: bool = False
    truncation_reasons: list[str] = []
    omitted_spans: int = 0
    max_spans: int = MAX_SPANS_PER_TRACE
    max_depth: int = MAX_TREE_DEPTH

    @classmethod
    def from_reconstruction(
        cls,
        trace_id: str,
        result: TraceReconstruction,
    ) -> TraceDetailResponse:
        omitted = [0]
        groups = [
            [TraceNodeResponse.from_trace_node(n, 1, omitted) for n in nodes]
            for nodes in (result.roots, result.orphans, result.cycle_members)
        ]
        reasons: list[str] = []
        if result.truncated is True:
            reasons.append("span_limit")
        if omitted[0]:
            reasons.append("depth_limit")
        return cls(
            trace_id=trace_id,
            span_count=result.span_count,
            has_cycle=result.has_cycle,
            roots=groups[0],
            orphans=groups[1],
            cycle_members=groups[2],
            is_demo_data=any(
                n.span.is_demo_data
                for group in (result.roots, result.orphans, result.cycle_members)
                for n in _walk(group)
            ),
            truncated=bool(reasons),
            truncation_reasons=reasons,
            omitted_spans=omitted[0],
        )


# ---------------------------------------------------------------------------
# DB context manager
# ---------------------------------------------------------------------------


@contextmanager
def get_db() -> Generator[psycopg.Connection, None, None]:
    """
    Context manager that opens a psycopg connection for one request.

    Used inside route bodies (not as Depends) so that FastAPI validates
    query/path parameters before any DB connection is attempted.

    Connection parameters are read from TRACE_VIEWER_DB_* environment
    variables by Phase 9.3 db.connect().

    The connection is always closed in the finally block, whether the
    request succeeds or fails.

    If connect() itself fails (missing password → RuntimeError, or
    PostgreSQL unreachable → psycopg.Error), raises HTTPException(503)
    before yielding — no close() is attempted on a non-existent connection.

    Raises:
        HTTPException(503)  if the connection cannot be established.
    """
    try:
        conn = connect()
    except (RuntimeError, psycopg.Error) as exc:
        logger.error("DB connection failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Database unavailable") from None
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(psycopg.Error)
async def database_error_handler(request: Request, exc: psycopg.Error) -> JSONResponse:
    """
    Catch any psycopg.Error that escapes a route body.

    Returns a generic 503 without leaking the password, connection string,
    SQL text, or internal stack trace.
    """
    logger.error("Database error during request: %s", type(exc).__name__)
    return JSONResponse(status_code=503, content={"detail": "Database error"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness check — does not depend on PostgreSQL."""
    return HealthResponse(status="ok")


@app.get(
    "/api/health/ready",
    response_model=ReadyResponse,
    responses={503: {"model": ReadyResponse, "description": "The database is not reachable"}},
)
def ready() -> ReadyResponse | JSONResponse:
    """
    Readiness check — opens one connection and runs `SELECT 1` (read-only, no
    table access).  200 {"status": "ok", "database": "ok"} when it succeeds.
    Any failure, whether the connection or the statement, returns the same
    sanitized 503 {"status": "unavailable", "database": "unavailable"}: no
    credential, host, SQL text, driver message or stack trace is returned.
    """
    unavailable = JSONResponse(
        status_code=503,
        content={"status": "unavailable", "database": "unavailable"},
    )
    try:
        with get_db() as conn:
            row = conn.execute("SELECT 1").fetchone()
    except HTTPException:
        return unavailable
    except psycopg.Error as exc:
        logger.error("Readiness query failed: %s", type(exc).__name__)
        return unavailable
    if row is None or row[0] != 1:
        logger.error("Readiness query returned an unexpected result")
        return unavailable
    return ReadyResponse(status="ok", database="ok")


# Path type that FastAPI validates before calling the route body.
# A trace_id that does not match returns 422 automatically.
_TraceIdPath = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]


@app.get("/api/traces", response_model=TraceListResponse)
def list_traces_endpoint(
    limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    has_error: Annotated[bool | None, Query()] = None,
    service_name: Annotated[str | None, Query()] = None,
    request_id: Annotated[str | None, Query()] = None,
    session_id: Annotated[str | None, Query()] = None,
    min_duration_ms: Annotated[float | None, Query(ge=0)] = None,
    max_duration_ms: Annotated[float | None, Query(ge=0)] = None,
    search: Annotated[str | None, Query()] = None,
) -> TraceListResponse:
    """
    Return a paginated list of traces from analytics.int_trace_spans.

    Query parameters:
        limit            1–200, default 50
        offset           >= 0, default 0
        has_error        optional boolean filter
        service_name     exact match on root_service_name
        request_id       exact match on request_id
        session_id       exact match on session_id
        min_duration_ms  >= 0; lower bound on trace_duration_ms
        max_duration_ms  >= 0; upper bound on trace_duration_ms
        search           OR-match across trace_id, request_id, session_id

    Response:
        total   — total matching traces before pagination
        limit   — echoed from request
        offset  — echoed from request
        traces  — rows for this page
    """
    if min_duration_ms is not None and max_duration_ms is not None:
        if min_duration_ms > max_duration_ms:
            raise HTTPException(
                status_code=422,
                detail="min_duration_ms must be <= max_duration_ms",
            )
    with get_db() as conn:
        result = list_traces(
            conn,
            limit=limit,
            offset=offset,
            has_error=has_error,
            service_name=service_name,
            request_id=request_id,
            session_id=session_id,
            min_duration_ms=min_duration_ms,
            max_duration_ms=max_duration_ms,
            search=search,
        )
    return TraceListResponse(
        total=result.total,
        limit=limit,
        offset=offset,
        traces=[TraceSummary.model_validate(row) for row in result.traces],
    )


@app.get("/api/traces/{trace_id}", response_model=TraceDetailResponse)
def get_trace_endpoint(
    trace_id: _TraceIdPath,
) -> TraceDetailResponse:
    """
    Return the full reconstructed trace tree for trace_id.

    Delegates to Phase 9.3 fetch + Phase 9.2 reconstruction.
    Returns 404 if the trace_id is syntactically valid but not found.
    """
    with get_db() as conn:
        try:
            result = get_trace_reconstruction(conn, trace_id, max_spans=MAX_SPANS_PER_TRACE)
        except ValueError:
            # Phase 9.3 validation is equivalent to the HTTP path pattern,
            # so this should never be reached via normal API usage.
            # Caught here as a defense-in-depth measure to prevent 500 leaks.
            raise HTTPException(
                status_code=422,
                detail=f"Invalid trace_id: {trace_id}",
            )
    if result.span_count == 0:
        raise HTTPException(
            status_code=404,
            detail=f"Trace not found: {trace_id}",
        )
    return TraceDetailResponse.from_reconstruction(trace_id, result)


# ---------------------------------------------------------------------------
# Anomalies and RCA (read-only)
# ---------------------------------------------------------------------------
#
# Models mirror the columns of public.anomaly_events, public.rca_investigations
# and public.rca_evidence.  anomaly_id and investigation_id are both 64 lowercase
# hex characters; trace_id filters use the 32-character trace-viewer format.


class AnomalyResponse(BaseModel):
    """One row of public.anomaly_events."""

    anomaly_id: str
    anomaly_type: str
    signal_name: str
    detector_name: str
    detector_version: str
    trace_id: str | None
    span_id: str | None
    service_name: str | None
    operation_name: str | None
    observed_value: float
    event_time: datetime
    baseline_median: float | None
    baseline_mad: float | None
    baseline_n: int | None
    baseline_window_start: datetime | None
    baseline_window_end: datetime | None
    anomaly_score: float | None
    severity: str
    explanation: str
    detected_at: datetime
    # Names of free-text fields shortened to MAX_TEXT_CHARS (empty when none).
    truncated_fields: list[str] = []


class AnomalyListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    anomalies: list[AnomalyResponse]


class RcaEvidenceResponse(BaseModel):
    """One ranked row of public.rca_evidence (rank_position 1 is strongest)."""

    rank_position: int
    span_id: str
    parent_span_id: str | None
    span_name: str
    service_name: str
    duration_ms: float
    status_code: str
    error_type: str | None
    error_message: str | None
    tool_name: str | None
    tool_status: str | None
    agent_name: str | None
    agent_operation: str | None
    retrieval_result_count: int | None
    retrieval_top_relevance_score: float | None
    is_root_span: bool
    is_error_span: bool
    is_direct_subject: bool
    depth: int
    trace_duration_fraction: float | None
    evidence_type: str
    evidence_score: float
    evidence_score_breakdown: str
    explanation: str
    # Names of free-text fields shortened to MAX_TEXT_CHARS (empty when none).
    truncated_fields: list[str] = []


class RcaInvestigationResponse(BaseModel):
    """One row of public.rca_investigations plus its evidence, best first."""

    investigation_id: str
    anomaly_id: str
    analyzer_version: str
    investigated_at: datetime
    trace_id: str | None
    subject_span_id: str | None
    service_name: str | None
    operation_name: str | None
    event_time: datetime
    trace_span_count: int
    anomaly_type: str
    observed_value: float
    baseline_median: float | None
    anomaly_score: float | None
    severity: str
    confidence: str
    summary: str
    limitations: list[str]
    evidence: list[RcaEvidenceResponse]
    # Free-text bounds: names of fields shortened ("summary", "limitations",
    # "evidence") and the number of evidence rows left out beyond MAX_EVIDENCE_ROWS.
    truncated_fields: list[str] = []
    omitted_evidence: int = 0


_Id64Path = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


@app.get("/api/anomalies", response_model=AnomalyListResponse)
def list_anomalies_endpoint(
    limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Annotated[Literal["INFO", "WARNING", "CRITICAL"] | None, Query()] = None,
    service_name: Annotated[str | None, Query()] = None,
    trace_id: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
) -> AnomalyListResponse:
    """
    Return a paginated list of anomalies, newest event_time first
    (ties broken by anomaly_id ascending).

    Query parameters:
        limit         1-200, default 50
        offset        >= 0, default 0
        severity      INFO | WARNING | CRITICAL
        service_name  exact match
        trace_id      32 lowercase hex characters, exact match
    """
    with get_db() as conn:
        result = list_anomalies(
            conn,
            limit=limit,
            offset=offset,
            severity=severity,
            service_name=service_name,
            trace_id=trace_id,
        )
    return AnomalyListResponse(
        total=result.total,
        limit=limit,
        offset=offset,
        anomalies=[_anomaly_response(row) for row in result.anomalies],
    )


@app.get("/api/anomalies/{anomaly_id}", response_model=AnomalyResponse)
def get_anomaly_endpoint(anomaly_id: _Id64Path) -> AnomalyResponse:
    """Return one anomaly. 404 if the (valid) anomaly_id does not exist."""
    with get_db() as conn:
        row = get_anomaly(conn, anomaly_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Anomaly not found: {anomaly_id}")
    return _anomaly_response(row)


def _rca_response(row: dict[str, Any]) -> RcaInvestigationResponse:
    """
    The investigation with every free-text field limited to MAX_TEXT_CHARS, at
    most MAX_LIMITATIONS limitation entries and at most MAX_EVIDENCE_ROWS evidence
    rows (the strongest, as ordered by the query); anything left out is reported.
    """
    out = _capped_row(row, ("summary",))
    shortened = list(out["truncated_fields"])

    capped = [_cap_text(item) for item in row.get("limitations") or []]
    out["limitations"] = [text for text, _ in capped[:MAX_LIMITATIONS]]
    if len(capped) > MAX_LIMITATIONS or any(was_cut for _, was_cut in capped):
        shortened.append("limitations")

    evidence_rows = list(row.get("evidence") or [])
    # The query reads at most MAX_EVIDENCE_ROWS + 1 rows and reports the true total
    # beside them; without that figure (older callers) the rows in hand are counted.
    out.pop("evidence_total", None)
    total_evidence = max(row.get("evidence_total", len(evidence_rows)), len(evidence_rows))
    omitted = max(total_evidence - MAX_EVIDENCE_ROWS, 0)
    out["evidence"] = [
        _capped_row(e, ("error_message", "explanation", "evidence_score_breakdown"))
        for e in evidence_rows[:MAX_EVIDENCE_ROWS]
    ]
    if omitted:
        shortened.append("evidence")
    out["omitted_evidence"] = omitted
    out["truncated_fields"] = shortened
    return RcaInvestigationResponse.model_validate(out)


def _anomaly_response(row: dict[str, Any]) -> AnomalyResponse:
    """The anomaly with its explanation limited to MAX_TEXT_CHARS (reported when cut)."""
    return AnomalyResponse.model_validate(_capped_row(row, ("explanation",)))


@app.get("/api/rca/{investigation_id}", response_model=RcaInvestigationResponse)
def get_rca_endpoint(investigation_id: _Id64Path) -> RcaInvestigationResponse:
    """
    Return one RCA investigation with confidence, summary, limitations and
    evidence ordered by rank_position. 404 if it does not exist.
    """
    with get_db() as conn:
        row = get_rca_investigation(conn, investigation_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation not found: {investigation_id}",
        )
    return _rca_response(row)


@app.get("/api/anomalies/{anomaly_id}/rca", response_model=RcaInvestigationResponse)
def get_anomaly_rca_endpoint(anomaly_id: _Id64Path) -> RcaInvestigationResponse:
    """
    Return the most recent RCA investigation (with evidence) for an anomaly.
    404 if the anomaly has no investigation.
    """
    with get_db() as conn:
        row = get_latest_rca_for_anomaly(conn, anomaly_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No RCA investigation for anomaly: {anomaly_id}",
        )
    return _rca_response(row)
