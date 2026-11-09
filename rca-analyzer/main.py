"""
rca-analyzer/main.py

Phase 11.6: CLI entry point for the RCA analyzer.

Runs one RCA investigation for a single anomaly ID and logs the result.

Usage:
    python main.py --anomaly-id <UUID>

Exit codes:
    0  success
    1  anomaly not found (AnomalyNotFoundError)
    2  source data integrity error (SourceDataIntegrityError)
    3  configuration error — missing environment variable (RuntimeError)
    4  database connectivity error (psycopg.OperationalError)
   130 keyboard interrupt (SIGINT)

Unexpected programming errors (AssertionError, plain ValueError, etc.)
propagate as unhandled exceptions with full traceback.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

import psycopg

from rca_db import connect
from rca_orchestrator import (
    AnomalyNotFoundError,
    SourceDataIntegrityError,
    run_investigation,
)

logger = logging.getLogger(__name__)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an RCA investigation for a single anomaly.",
    )
    parser.add_argument(
        "--anomaly-id",
        required=True,
        metavar="UUID",
        help="Primary key of the anomaly in public.anomaly_events.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)-7s %(message)s",
        level=logging.INFO,
    )
    args = _parse_args(argv)
    anomaly_id = args.anomaly_id

    try:
        conn = connect()
    except RuntimeError as exc:
        logger.error("Configuration error: %s", exc)
        return 3
    except psycopg.OperationalError as exc:
        logger.error("Database error: %s", exc)
        return 4

    try:
        result, pr = run_investigation(conn, anomaly_id)
    except AnomalyNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except SourceDataIntegrityError as exc:
        logger.error("Data integrity error: %s", exc)
        return 2
    except psycopg.OperationalError as exc:
        logger.error("Database error: %s", exc)
        return 4
    finally:
        conn.close()

    logger.info(
        "investigation_id=%s confidence=%s evidence=%d inserted=%s",
        pr.investigation_id,
        result.confidence,
        pr.evidence_rows_inserted,
        pr.investigation_inserted,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
