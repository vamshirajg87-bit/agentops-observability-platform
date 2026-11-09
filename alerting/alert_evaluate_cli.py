"""
alerting/alert_evaluate_cli.py

Phase 13.4: One-shot CLI for alert evaluation.

Evaluates every RCA investigation that has no decision under the policy's
version and records one decision for each.  Nothing is ever overwritten,
changed, or removed, so the program is safe to run again: a rerun finds
nothing left to decide.

This program decides and records.  It sends no notification.

Usage:
    python alert_evaluate_cli.py --policy PATH [--dry-run]

    --policy PATH   the policy file (JSON)
    --dry-run       compute and print the decisions a run would make, and
                    write nothing

Connection parameters come from the ALERT_EVALUATOR_DB_* environment
variables (see alert_db.py).  A dry run opens a read-only session.

The evaluation time is read from the clock once, when the program starts,
and is used for every investigation of the run.

Output:
    A plain-text report on stdout: the policy identity, one line per
    investigation as it is processed, and a summary.  Each line holds the
    investigation_id, the decision_id, the decision, the reason code and,
    when there is one, the related decision.  The RCA summary is never
    printed.  Errors are written to stderr as one line.

Exit codes:
    0  completed; this includes a run with nothing to evaluate
    2  usage or argument error
    3  configuration error — policy file missing or invalid, or a missing
       environment variable
    4  database error
    5  the policy version is already registered with a different hash
    6  completed, but one or more investigations could not be evaluated
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Any, Optional, TextIO

import alert_db
from alert_evaluator import (
    POLICY_NOT_REGISTERED,
    STATUS_ALREADY_DECIDED,
    STATUS_FAILURE,
    EvaluationReport,
    EvaluationResult,
    PolicyVersionConflictError,
    format_timestamp,
    run_evaluation,
)
from alert_policy import AlertPolicy, load_policy


EXIT_OK: int = 0
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_POLICY_CONFLICT: int = 5
EXIT_INCOMPLETE: int = 6
EXIT_INTERRUPTED: int = 130


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate every RCA investigation that has no alert decision "
            "under the policy's version. Safe to rerun; nothing is "
            "overwritten. Sends no notification."
        ),
    )
    parser.add_argument(
        "--policy",
        required=True,
        metavar="PATH",
        help="Path to the alert policy JSON file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the decisions a run would make and write nothing.",
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

def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def render_header(
    policy: AlertPolicy, evaluated_at: datetime, dry_run: bool,
) -> str:
    title = "Alert evaluation"
    if dry_run:
        title += " (dry run: nothing is written)"
    return "\n".join([
        title,
        f"  policy version: {_one_line(policy.policy_version)}",
        f"  policy sha256:  {policy.policy_sha256}",
        f"  evaluated at:   {format_timestamp(evaluated_at)}",
        "",
        "Investigations",
    ])


def render_result(result: EvaluationResult) -> str:
    """One line for one investigation."""
    line = f"  {_one_line(result.investigation_id)}"
    if result.status == STATUS_FAILURE:
        line += f"  {result.status}"
        if result.error is not None:
            line += f"  {_one_line(result.error)}"
        return line

    line += f"  {_one_line(result.decision_id)}"
    if result.status == STATUS_ALREADY_DECIDED:
        return line + f"  {result.status}"

    line += f"  {result.decision.value}  {result.reason_code.value}"
    if result.related_decision_id is not None:
        line += f"  related={result.related_decision_id}"
        if result.related_is_hypothetical:
            line += " (not stored)"
    return line


def render_summary(report: EvaluationReport) -> str:
    lines = []
    if report.total == 0:
        lines.append("  (none)")

    policy_status = report.policy_status
    if policy_status == POLICY_NOT_REGISTERED:
        policy_status += " (a real run would register it)"
    lines.extend([
        "",
        "Summary",
        f"  policy:          {policy_status}",
        f"  investigations:  {report.total}",
        f"  alert:           {report.alerts}",
        f"  suppressed:      {report.suppressed}",
        f"  not_alertable:   {report.not_alertable}",
        f"  already_decided: {report.already_decided}",
        f"  failures:        {report.failures}",
        "",
    ])

    if not report.succeeded:
        lines.append(
            f"Result: completed with problems ({report.failures} failed). "
            "Nothing was overwritten."
        )
    elif report.dry_run:
        lines.append("Result: dry run completed; nothing was written")
    else:
        lines.append("Result: completed")
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
    _write(sys.stderr, f"error: {_one_line(message)}")


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

    Every investigation has already been committed or rolled back by the
    evaluator, so the rollback only ends a transaction left open by an
    interrupted run.  close() is attempted even when rollback() fails.  A
    cleanup failure is reported on stderr and does not change the exit code.
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

def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except OSError as exc:
        _error(f"configuration: cannot read the policy file: {exc}")
        return EXIT_CONFIGURATION
    except ValueError as exc:
        # Invalid JSON, invalid encoding, or an invalid policy.
        _error(f"configuration: invalid policy: {exc}")
        return EXIT_CONFIGURATION

    # The one evaluation time of this run.
    evaluated_at = _utc_now()

    try:
        conn = alert_db.connect(read_only=args.dry_run)
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION
    except alert_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE

    try:
        _write(sys.stdout, render_header(policy, evaluated_at, args.dry_run))
        report = run_evaluation(
            conn,
            policy,
            evaluated_at=evaluated_at,
            dry_run=args.dry_run,
            on_result=lambda result: _write(sys.stdout, render_result(result)),
        )
    except PolicyVersionConflictError as exc:
        _error(f"policy version conflict: {exc}")
        return EXIT_POLICY_CONFLICT
    except alert_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _write(sys.stdout, render_summary(report))
    return EXIT_OK if report.succeeded else EXIT_INCOMPLETE


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
