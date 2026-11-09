"""
alerting/alert_notify_cli.py

Phase 13.5: One-shot CLI for alert notification.

Delivers every persisted ALERT decision to every enabled channel of the
policy that still needs it, and records each attempt and its outcome.  It
makes at most one attempt per alert and channel, never waits and never
repeats, so it is meant to be run again later for retryable failures.

This program delivers.  It evaluates nothing and reads no RCA data.

Usage:
    python alert_notify_cli.py --policy PATH [--dry-run]

    --policy PATH   the policy file (JSON); its delivery section is used
    --dry-run       report what a run would do; write and send nothing

Connection parameters come from the ALERT_NOTIFIER_DB_* environment
variables (see alert_notifier_db.py).  A webhook channel reads its URL, and
its token when one is configured, from the environment variables named in
the policy.

Every enabled channel is checked before anything else happens.  If one of
them cannot be used as configured, the program stops: nothing is delivered
to any channel and nothing is written.

When no channel is enabled the program does nothing and exits 0 without
connecting to the database.

Output:
    stdout   only what the log channel delivers: one JSON line per alert
    stderr   the report of this run, and errors

    The report names decisions, channels, states and fixed result codes.
    It never shows a summary, a URL, a token or a response.

Exit codes:
    0  completed; every attempt made by this run was delivered.  This
       includes a run that had nothing to attempt
    2  usage or argument error
    3  configuration error — policy file, channel configuration, or a
       missing environment variable
    4  database error
    6  completed, but an attempt made by this run was not delivered, an
       attempt number was taken by another writer, or stored data was invalid
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any, BinaryIO, Optional, Sequence, TextIO

import alert_notifier_db
from alert_channels import (
    ChannelConfigurationError,
    PreparedChannel,
    preflight_channel,
)
from alert_evaluator import format_timestamp
from alert_notifier import NotifyReport, format_result, run_notify
from alert_policy import AlertPolicy, load_policy


EXIT_OK: int = 0
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_INCOMPLETE: int = 6
EXIT_INTERRUPTED: int = 130


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Deliver persisted alerts to the enabled channels of the policy. "
            "One attempt per alert and channel; run again for retryable "
            "failures."
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
        help="Report what a run would do; write and send nothing.",
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
    policy: AlertPolicy,
    channels: Sequence[PreparedChannel],
    now: datetime,
    dry_run: bool,
) -> str:
    title = "Alert notification"
    if dry_run:
        title += " (dry run: nothing is written or sent)"
    lines = [
        title,
        f"  run time:         {format_timestamp(now)}",
        f"  max delivery age: {policy.delivery.max_delivery_age_minutes} minutes",
    ]
    for prepared in channels:
        line = (
            f"  channel:          {_one_line(prepared.config.name)} "
            f"({prepared.config.type.value})"
        )
        if prepared.endpoint is not None:
            line += f" {prepared.endpoint.identity}"
        lines.append(line)
    lines += ["", "Deliveries"]
    return "\n".join(lines)


def render_summary(report: NotifyReport) -> str:
    lines = []
    if report.total == 0:
        lines.append("  (none)")
    lines += ["", "Summary", f"  deliveries:    {report.total}"]
    if report.dry_run:
        lines.append(f"  would attempt: {report.would_attempt}")
    else:
        lines += [
            f"  attempted:     {report.attempted}",
            f"  sent:          {report.sent}",
            f"  not sent:      {report.not_sent}",
        ]
    lines += [
        f"  blocked:       {report.blocked}",
        f"  lost race:     {report.lost_races}",
        f"  invalid data:  {report.invalid}",
        "",
    ]

    if not report.succeeded:
        lines.append(
            f"Result: completed with problems ({report.problems}). "
            "Nothing was overwritten."
        )
    elif report.dry_run:
        lines.append("Result: dry run completed; nothing was written or sent")
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


def _status(text: str) -> None:
    """Report text goes to stderr; stdout belongs to the log channel."""
    _write(sys.stderr, text)


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


class _TextAsBinary:
    """Binary view of a text stream that has no buffer; the body is ASCII."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, data: bytes) -> int:
        self._stream.write(data.decode("ascii"))
        return len(data)

    def flush(self) -> None:
        self._stream.flush()


def _stdout_binary() -> BinaryIO:
    """The binary standard output stream, for the log channel."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        return buffer
    return _TextAsBinary(sys.stdout)  # type: ignore[return-value]


def _cleanup(conn: Any) -> None:
    """
    Release the connection this program opened: roll back, then close.

    Every attempt and outcome has already been committed or rolled back by
    the notifier, so the rollback only ends a transaction left open by an
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

    # The one time of this run.
    now = _utc_now()

    # No enabled channel is the notification kill switch.
    enabled = [channel for channel in policy.delivery.channels if channel.enabled]
    if not enabled:
        _status("Alert notification: no channel is enabled; nothing to do")
        return EXIT_OK

    # Every enabled channel is checked before anything is delivered.
    try:
        channels = [preflight_channel(channel, os.environ) for channel in enabled]
    except ChannelConfigurationError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION

    try:
        conn = alert_notifier_db.connect(read_only=args.dry_run)
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE

    try:
        _status(render_header(policy, channels, now, args.dry_run))
        report = run_notify(
            conn,
            channels,
            policy.delivery,
            now=now,
            dry_run=args.dry_run,
            log_stream=_stdout_binary(),
            on_result=lambda result: _status("  " + format_result(result)),
        )
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _status(render_summary(report))
    return EXIT_OK if report.succeeded else EXIT_INCOMPLETE


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
