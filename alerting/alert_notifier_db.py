"""
alerting/alert_notifier_db.py

Phase 13.5: PostgreSQL connection factory for the alert notifier.

Reads connection parameters from ALERT_NOTIFIER_DB_* environment variables.
ALERT_NOTIFIER_DB_PASSWORD has no default and must be set explicitly before
calling connect().

The notifier connects as its own role (migration 014), which is separate
from the evaluator's: it can read the persisted decision snapshot and append
delivery records, and nothing else.

The returned connection is synchronous (psycopg 3).  The caller is
responsible for closing it.

DatabaseError is the driver's base error type.  Callers that own a connection
catch it through this name, so they do not need to import the driver.
"""

from __future__ import annotations

import os

import psycopg


#: Base class of every error raised by the database driver.
DatabaseError = psycopg.Error


def connect(*, read_only: bool = False) -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for alert notification.

    Environment variables:
        ALERT_NOTIFIER_DB_HOST      default: localhost
        ALERT_NOTIFIER_DB_PORT      default: 5432
        ALERT_NOTIFIER_DB_NAME      default: agentops
        ALERT_NOTIFIER_DB_USER      default: alert_notifier
        ALERT_NOTIFIER_DB_PASSWORD  required — no default

    Args:
        read_only: when True, every transaction of the session is read-only,
                   so the database itself rejects any write.  Used by dry
                   runs and by the read-only admin commands.

    Raises:
        RuntimeError              if ALERT_NOTIFIER_DB_PASSWORD is not set,
                                  or ALERT_NOTIFIER_DB_PORT is not an integer.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("ALERT_NOTIFIER_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "ALERT_NOTIFIER_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("ALERT_NOTIFIER_DB_HOST", "localhost")
    port_text = os.environ.get("ALERT_NOTIFIER_DB_PORT", "5432")
    try:
        port = int(port_text)
    except ValueError:
        raise RuntimeError(
            "ALERT_NOTIFIER_DB_PORT environment variable must be an integer"
        ) from None
    dbname = os.environ.get("ALERT_NOTIFIER_DB_NAME", "agentops")
    user = os.environ.get("ALERT_NOTIFIER_DB_USER", "alert_notifier")

    conn = psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )
    if read_only:
        try:
            conn.read_only = True
        except Exception:
            conn.close()
            raise
    return conn
