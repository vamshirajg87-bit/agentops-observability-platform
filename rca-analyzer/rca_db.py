"""
rca-analyzer/rca_db.py

PostgreSQL connection factory for the RCA analyzer.

Reads connection parameters from RCA_ANALYZER_DB_* environment variables.
RCA_ANALYZER_DB_PASSWORD has no default and must be set explicitly before
calling connect().

The returned connection is synchronous (psycopg 3). The caller is responsible
for closing it.
"""

from __future__ import annotations

import os

import psycopg


def connect() -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for RCA analyzer operations.

    Environment variables:
        RCA_ANALYZER_DB_HOST      default: localhost
        RCA_ANALYZER_DB_PORT      default: 5432
        RCA_ANALYZER_DB_NAME      default: agentops
        RCA_ANALYZER_DB_USER      default: rca_analyzer
        RCA_ANALYZER_DB_PASSWORD  required — no default

    Raises:
        RuntimeError              if RCA_ANALYZER_DB_PASSWORD is not set.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("RCA_ANALYZER_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "RCA_ANALYZER_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("RCA_ANALYZER_DB_HOST", "localhost")
    port = int(os.environ.get("RCA_ANALYZER_DB_PORT", "5432"))
    dbname = os.environ.get("RCA_ANALYZER_DB_NAME", "agentops")
    user = os.environ.get("RCA_ANALYZER_DB_USER", "rca_analyzer")

    return psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )
