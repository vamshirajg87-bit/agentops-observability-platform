"""
trace-viewer/db.py

PostgreSQL connection factory for the trace viewer.

Reads connection parameters from TRACE_VIEWER_DB_* environment variables.
TRACE_VIEWER_DB_PASSWORD has no default and must be set explicitly before
calling connect().

The returned connection is synchronous (psycopg 3). The caller is responsible
for closing it.
"""

from __future__ import annotations

import os

import psycopg

# Session safety applied to every connection, in addition to the read-only
# grants of the role (migrations 003 and 015):
#   default_transaction_read_only   every transaction starts read-only, so a
#                                   write is refused even if a grant were wider
#                                   than intended
#   statement_timeout               one statement may run at most this long
# Both are ordinary per-session settings that any role may set for itself; they
# are passed as libpq startup options, so no role or migration changes.
STATEMENT_TIMEOUT_MS: int = 5000
CONNECT_TIMEOUT_SECONDS: int = 5
SESSION_OPTIONS: str = (
    f"-c default_transaction_read_only=on -c statement_timeout={STATEMENT_TIMEOUT_MS}"
)


def _port_from_environment() -> int:
    """
    TRACE_VIEWER_DB_PORT as a TCP port (default 5432).

    A value that is not a whole number from 1 to 65535 raises RuntimeError, the
    same exception a missing password raises, which the application reports as a
    sanitized 503.  The message names the variable only, never the value.
    """
    raw = os.environ.get("TRACE_VIEWER_DB_PORT", "5432")
    try:
        port = int(raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise RuntimeError(
            "TRACE_VIEWER_DB_PORT must be a whole number from 1 to 65535"
        )
    return port


def connect() -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for trace viewer queries.

    Environment variables:
        TRACE_VIEWER_DB_HOST      default: localhost
        TRACE_VIEWER_DB_PORT      default: 5432
        TRACE_VIEWER_DB_NAME      default: agentops
        TRACE_VIEWER_DB_USER      default: trace_viewer_reader
        TRACE_VIEWER_DB_PASSWORD  required — no default

    The session is read-only by default and every statement is limited to
    STATEMENT_TIMEOUT_MS; establishing the connection is limited to
    CONNECT_TIMEOUT_SECONDS.

    Raises:
        RuntimeError            if TRACE_VIEWER_DB_PASSWORD is not set, or
                                TRACE_VIEWER_DB_PORT is not a valid port.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("TRACE_VIEWER_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "TRACE_VIEWER_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("TRACE_VIEWER_DB_HOST", "localhost")
    port = _port_from_environment()
    dbname = os.environ.get("TRACE_VIEWER_DB_NAME", "agentops")
    user = os.environ.get("TRACE_VIEWER_DB_USER", "trace_viewer_reader")

    return psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        options=SESSION_OPTIONS,
    )
