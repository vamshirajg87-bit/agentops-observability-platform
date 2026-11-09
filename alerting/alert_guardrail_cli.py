"""
alerting/alert_guardrail_cli.py

Phase 13.6: One-shot CLI for the operational guardrails.

Runs four report-only checks and prints their findings:

    detector_checkpoint_stale   an expected detection group has no recent
                                checkpoint
    uninvestigated_anomalies    an anomaly has had no investigation for too
                                long
    delivery_uncertain          an alert delivery may or may not have arrived
    delivery_exhausted          an alert delivery will not be made
                                automatically

This program only reads and reports.  It writes nothing, sends nothing,
retries nothing and changes nothing; it has no option to do so.

Usage:
    python alert_guardrail_cli.py --policy PATH --detector-config PATH

    --policy PATH            the alert policy file (JSON); its guardrails
                             section gives the thresholds
    --detector-config PATH   the anomaly detector's runner configuration
                             (JSON); its "groups" say which checkpoints
                             should exist

Connection parameters come from the ALERT_EVALUATOR_DB_* environment
variables (see alert_db.py).  The session is read-only.

The time of the run is read from the clock once and used for every check.

Output:
    stdout   exactly four findings, in fixed order, and only when all four
             were evaluated completely:

                 <code> <OK|VIOLATION> count=<number of violations>
                   <identifier>                  one line per violation shown
                   (+<n> more)                   when more exist than shown

             At most 20 identifiers are shown per finding; count is always
             the full number.
    stderr   one line when the run fails.  It names a fixed reason and an
             error type, never a path, a configured value, a stored value or
             an error message.

Exit codes:
    0  all four findings are OK
    1  internal error — a defect of this program; stderr names its type only
    2  usage or argument error
    3  configuration error — policy file, detector configuration, or a
       missing environment variable
    4  database error, or stored data that could not be evaluated
    6  one or more findings are VIOLATION
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Any, Optional, Sequence, TextIO

import alert_db
from alert_guardrails import (
    DetectorConfigError,
    GuardrailEvaluationError,
    GuardrailResult,
    load_expected_groups,
    run_guardrails,
)
from alert_models import GuardrailStatus
from alert_policy import load_policy


EXIT_OK: int = 0
EXIT_INTERNAL: int = 1
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_VIOLATION: int = 6
EXIT_INTERRUPTED: int = 130


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the four report-only operational guardrails and print their "
            "findings. Reads only; writes, sends and changes nothing."
        ),
    )
    parser.add_argument(
        "--policy",
        required=True,
        metavar="PATH",
        help="Path to the alert policy JSON file.",
    )
    parser.add_argument(
        "--detector-config",
        required=True,
        metavar="PATH",
        help="Path to the anomaly detector's runner configuration JSON file.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Clock
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """The current time in UTC.  Called once per run."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------

def render_results(results: Sequence[GuardrailResult]) -> str:
    """
    The findings report.  Lines are separated by LF; no trailing newline.
    The finding's fixed detail text is not printed.
    """
    lines: list[str] = []
    for result in results:
        finding = result.finding
        lines.append(
            f"{finding.code} {finding.status.value} count={finding.count}"
        )
        lines.extend(f"  {detail_id}" for detail_id in result.detail_ids)
        remaining = finding.count - len(result.detail_ids)
        if remaining > 0:
            lines.append(f"  (+{remaining} more)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _write(stream: TextIO, text: str) -> None:
    """Write text and a newline; never fail on an unencodable character."""
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="backslashreplace").decode(encoding)
        stream.write(safe + "\n")


def _error(message: str) -> None:
    _write(sys.stderr, f"error: {' '.join(str(message).split())}")


def _database_error(exc: BaseException) -> None:
    """
    Report a database error by type and SQLSTATE only.  The driver's message
    can quote a stored row, so it is not printed.
    """
    detail = type(exc).__name__
    sqlstate = getattr(exc, "sqlstate", None)
    if sqlstate:
        detail += f" (SQLSTATE {sqlstate})"
    _error(f"database: {detail}")


def _cleanup(conn: Any) -> None:
    """
    Release the connection this program opened: roll back, then close.

    Nothing was written, so the rollback only ends the read transaction.
    close() is attempted even when rollback() fails.  A cleanup failure is
    reported on stderr and does not change the exit code.
    """
    try:
        conn.rollback()
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
        _error(f"rollback failed during cleanup: {type(exc).__name__}")
    try:
        conn.close()
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
        _error(f"close failed during cleanup: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _run(args: argparse.Namespace) -> int:
    # Configuration errors are reported by type only: a message could quote
    # a path or a configured value.
    try:
        policy = load_policy(args.policy)
    except OSError as exc:
        _error(
            f"configuration: cannot read the policy file ({type(exc).__name__})"
        )
        return EXIT_CONFIGURATION
    except (ValueError, RecursionError) as exc:
        # Invalid JSON, invalid encoding, an invalid policy, or a file nested
        # too deeply to read.
        _error(f"configuration: invalid policy ({type(exc).__name__})")
        return EXIT_CONFIGURATION

    try:
        expected_groups = load_expected_groups(args.detector_config)
    except OSError as exc:
        _error(
            "configuration: cannot read the detector config file "
            f"({type(exc).__name__})"
        )
        return EXIT_CONFIGURATION
    except DetectorConfigError as exc:
        # The message is a fixed phrase.
        _error(f"configuration: invalid detector config: {exc}")
        return EXIT_CONFIGURATION

    # The one time of this run.
    now = _utc_now()

    try:
        conn = alert_db.connect(read_only=True)
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION
    except alert_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE

    try:
        results = run_guardrails(
            conn, policy=policy, expected_groups=expected_groups, now=now,
        )
    except GuardrailEvaluationError as exc:
        _error(
            "guardrail evaluation failed: "
            f"{','.join(exc.guardrail_codes)}: {exc.reason_code}"
        )
        return EXIT_DATABASE
    except alert_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    finally:
        # Also on a keyboard interrupt and on an unexpected error; main()
        # turns those into an exit code afterwards.
        _cleanup(conn)

    # Printed only now: all four findings exist and the connection is released.
    _write(sys.stdout, render_results(results))
    violated = any(
        result.finding.status is GuardrailStatus.VIOLATION for result in results
    )
    return EXIT_VIOLATION if violated else EXIT_OK


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:  # noqa: BLE001 - last line of containment
        # Anything not handled above is a defect of this program.  Only its
        # type is reported: no traceback and no message.
        _error(f"internal: {type(exc).__name__}")
        return EXIT_INTERNAL


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
