"""
incident-retrieval/retrieval_db.py

PostgreSQL connection factory for incident retrieval.

Reads connection parameters from INCIDENT_RETRIEVAL_DB_* environment
variables.  INCIDENT_RETRIEVAL_DB_PASSWORD has no default and must be set
explicitly before calling connect().

The returned connection is synchronous (psycopg 3). The caller is responsible
for closing it.

DatabaseError is the driver's base error type.  Callers that own a connection
catch it through this name, so they do not need to import the driver.
"""

from __future__ import annotations

import os

import psycopg


#: Base class of every error raised by the database driver.
DatabaseError = psycopg.Error


def connect() -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for incident retrieval operations.

    Environment variables:
        INCIDENT_RETRIEVAL_DB_HOST      default: localhost
        INCIDENT_RETRIEVAL_DB_PORT      default: 5432
        INCIDENT_RETRIEVAL_DB_NAME      default: agentops
        INCIDENT_RETRIEVAL_DB_USER      default: incident_retrieval
        INCIDENT_RETRIEVAL_DB_PASSWORD  required — no default

    Raises:
        RuntimeError              if INCIDENT_RETRIEVAL_DB_PASSWORD is not set.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("INCIDENT_RETRIEVAL_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "INCIDENT_RETRIEVAL_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("INCIDENT_RETRIEVAL_DB_HOST", "localhost")
    port = int(os.environ.get("INCIDENT_RETRIEVAL_DB_PORT", "5432"))
    dbname = os.environ.get("INCIDENT_RETRIEVAL_DB_NAME", "agentops")
    user = os.environ.get("INCIDENT_RETRIEVAL_DB_USER", "incident_retrieval")

    return psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )
