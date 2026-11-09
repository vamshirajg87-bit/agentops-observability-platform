"""
alerting/alert_db.py

Phase 13.4: PostgreSQL connection factory for the alert evaluator.

Reads connection parameters from ALERT_EVALUATOR_DB_* environment variables.
ALERT_EVALUATOR_DB_PASSWORD has no default and must be set explicitly before
calling connect().

The returned connection is synchronous (psycopg 3).  The caller is
responsible for closing it.

DatabaseError is the driver's base error type.  Callers that own a connection
catch it through this name, so they do not need to import the driver.

This module and alert_store.py are the only alerting modules that import the
database driver.
"""

from __future__ import annotations

import os

import psycopg


#: Base class of every error raised by the database driver.
DatabaseError = psycopg.Error


def connect(*, read_only: bool = False) -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for alert evaluation.

    Environment variables:
        ALERT_EVALUATOR_DB_HOST      default: localhost
        ALERT_EVALUATOR_DB_PORT      default: 5432
        ALERT_EVALUATOR_DB_NAME      default: agentops
        ALERT_EVALUATOR_DB_USER      default: alert_evaluator
        ALERT_EVALUATOR_DB_PASSWORD  required — no default

    Args:
        read_only: when True, every transaction of the session is read-only,
                   so the database itself rejects any write.  Used by the
                   evaluator's dry run.

    Raises:
        RuntimeError              if ALERT_EVALUATOR_DB_PASSWORD is not set,
                                  or ALERT_EVALUATOR_DB_PORT is not an integer.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("ALERT_EVALUATOR_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "ALERT_EVALUATOR_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("ALERT_EVALUATOR_DB_HOST", "localhost")
    port_text = os.environ.get("ALERT_EVALUATOR_DB_PORT", "5432")
    try:
        port = int(port_text)
    except ValueError:
        raise RuntimeError(
            "ALERT_EVALUATOR_DB_PORT environment variable must be an integer"
        ) from None
    dbname = os.environ.get("ALERT_EVALUATOR_DB_NAME", "agentops")
    user = os.environ.get("ALERT_EVALUATOR_DB_USER", "alert_evaluator")

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
