"""
anomaly-detector/db.py

PostgreSQL connection factory for the anomaly detector.

Reads connection parameters from ANOMALY_DETECTOR_DB_* environment variables.
ANOMALY_DETECTOR_DB_PASSWORD has no default and must be set explicitly before
calling connect().

The returned connection is synchronous (psycopg 3). The caller is responsible
for closing it.
"""

from __future__ import annotations

import os

import psycopg


def connect() -> psycopg.Connection:
    """
    Return a new psycopg 3 connection for anomaly detector operations.

    Environment variables:
        ANOMALY_DETECTOR_DB_HOST      default: localhost
        ANOMALY_DETECTOR_DB_PORT      default: 5432
        ANOMALY_DETECTOR_DB_NAME      default: agentops
        ANOMALY_DETECTOR_DB_USER      default: anomaly_detector
        ANOMALY_DETECTOR_DB_PASSWORD  required — no default

    Raises:
        RuntimeError              if ANOMALY_DETECTOR_DB_PASSWORD is not set.
        psycopg.OperationalError  if the connection attempt fails.
    """
    password = os.environ.get("ANOMALY_DETECTOR_DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "ANOMALY_DETECTOR_DB_PASSWORD environment variable is not set"
        )

    host = os.environ.get("ANOMALY_DETECTOR_DB_HOST", "localhost")
    port = int(os.environ.get("ANOMALY_DETECTOR_DB_PORT", "5432"))
    dbname = os.environ.get("ANOMALY_DETECTOR_DB_NAME", "agentops")
    user = os.environ.get("ANOMALY_DETECTOR_DB_USER", "anomaly_detector")

    return psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )
