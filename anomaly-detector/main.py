"""
anomaly-detector/main.py

One-shot operational entry point for the anomaly detector.

Loads a RunConfig JSON file, opens a database connection, invokes
run_all_groups() once, logs structured per-group and summary output,
and exits with a code that reflects the outcome.

Usage:
    python main.py --config runner_config.json

    # Windows PowerShell (from repo root):
    $env:ANOMALY_DETECTOR_DB_PASSWORD = "..."
    python anomaly-detector/main.py --config anomaly-detector/runner_config.json

Environment variables (consumed by db.connect):
    ANOMALY_DETECTOR_DB_HOST      default: localhost
    ANOMALY_DETECTOR_DB_PORT      default: 5432
    ANOMALY_DETECTOR_DB_NAME      default: agentops
    ANOMALY_DETECTOR_DB_USER      default: anomaly_detector
    ANOMALY_DETECTOR_DB_PASSWORD  required — no default

Exit codes:
    0   All groups completed successfully (completed_all_groups=True,
        groups_error=0, groups_uncertain=0)
    1   Run completed but one or more groups have status "error" or "uncertain"
    2   Run terminated early (completed_all_groups=False)
    3   Configuration error: missing file, invalid JSON, or invalid RunConfig
    4   Database/connection startup failure (initial connection could not be
        established — see db.py for the exact exception types raised)
    130 Interrupted by Ctrl+C (KeyboardInterrupt)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

import psycopg

import db
from run_config import load_config
from runner import RunGroupResult, RunResult, run_all_groups


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    _configure_logging()

    logging.info("anomaly-detector starting")
    logging.info("  config : %s", args.config)

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        logging.error("Config file not found: %s", exc)
        sys.exit(3)
    except json.JSONDecodeError as exc:
        logging.error("Config JSON is malformed: %s", exc)
        sys.exit(3)
    except ValueError as exc:
        logging.error("Configuration is invalid: %s", exc)
        sys.exit(3)

    logging.info("  groups       : %d", len(config.groups))
    logging.info("  overlap_min  : %d", config.overlap_minutes)
    logging.info("  lookback_hrs : %d", config.initial_lookback_hours)

    try:
        result = run_all_groups(config, db.connect)
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
        sys.exit(130)
    except (psycopg.OperationalError, RuntimeError) as exc:
        # run_all_groups() propagates the initial connect_fn() exception directly
        # to the caller (runner.py: "Initial connection — fail loudly; caller
        # receives the raw exception.").  db.connect() raises RuntimeError for a
        # missing password (db.py:35-38) and psycopg.OperationalError for a
        # failed connection attempt.  Those are the only exceptions that reach here.
        logging.error(
            "Database startup failure (%s): verify ANOMALY_DETECTOR_DB_* environment variables",
            type(exc).__name__,
        )
        sys.exit(4)

    _log_result(result)
    sys.exit(_exit_code(result))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anomaly-detector",
        description="Run one anomaly detection pass for all configured groups.",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Path to the runner JSON configuration file.",
    )
    return parser.parse_args(argv)


def _configure_logging() -> None:
    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)-7s %(message)s",
        level=logging.INFO,
    )


def _log_result(result: RunResult) -> None:
    for gr in result.group_results:
        _log_group_result(gr)
    _log_run_summary(result)


def _log_group_result(gr: RunGroupResult) -> None:
    logging.info("[%s / %s / %s]", gr.signal_path, gr.service_name, gr.operation_name)
    logging.info("  status              : %s", gr.status)
    logging.info("  history_start       : %s", gr.history_start)
    logging.info("  candidate_after     : %s", gr.candidate_after)
    logging.info("  query_end           : %s", gr.query_end)
    logging.info("  prior_checkpoint    : %s", gr.prior_checkpoint)
    logging.info("  new_checkpoint      : %s", gr.new_checkpoint)
    logging.info("  checkpoint_advanced : %s", gr.checkpoint_advanced)
    logging.info("  candidates          : %d", gr.candidate_count)
    logging.info("  emitted             : %d", gr.anomaly_events_emitted)
    logging.info("  inserted            : %d", gr.anomaly_events_inserted)
    logging.info("  duplicate           : %d", gr.anomaly_events_duplicate)
    logging.info("  duration_ms         : %.1f", gr.duration_ms)
    if gr.error:
        logging.error("  error               : %s", gr.error)


def _log_run_summary(result: RunResult) -> None:
    logging.info("run complete")
    logging.info("  groups_attempted    : %d", result.groups_attempted)
    logging.info("  groups_ok           : %d", result.groups_ok)
    logging.info("  groups_uncertain    : %d", result.groups_uncertain)
    logging.info("  groups_error        : %d", result.groups_error)
    logging.info("  total_candidates    : %d", result.total_candidates)
    logging.info("  total_emitted       : %d", result.total_anomalies_emitted)
    logging.info("  total_inserted      : %d", result.total_anomalies_inserted)
    logging.info("  total_duplicate     : %d", result.total_anomalies_duplicate)
    logging.info("  completed_all_groups: %s", result.completed_all_groups)
    if result.terminal_error:
        logging.error("  terminal_error      : %s", result.terminal_error)


def _exit_code(result: RunResult) -> int:
    if not result.completed_all_groups:
        return 2
    if result.groups_error > 0 or result.groups_uncertain > 0:
        return 1
    return 0


if __name__ == "__main__":
    main()
