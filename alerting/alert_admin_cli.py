"""
alerting/alert_admin_cli.py

Phase 13.5: Operator CLI for alerts.

Three commands, all using the notifier's database role:

    list    the newest alerts with their delivery state per enabled channel
    show    one alert: its stored fields, every attempt, and its states
    retry   one operator attempt for one alert on one channel

Usage:
    python alert_admin_cli.py list  --policy PATH [--limit N]
    python alert_admin_cli.py show  --policy PATH <decision_id>
    python alert_admin_cli.py retry --policy PATH <decision_id>
                                    --channel NAME
                                    [--confirm-resend] [--dry-run]

    --policy PATH      the policy file (JSON); its delivery section is used
    --limit N          list: number of alerts, 1..500 (default 50)
    --channel NAME     retry: the channel to deliver to
    --confirm-resend   retry: required when the earlier delivery is
                       UNCERTAIN, because the alert may already have arrived
    --dry-run          retry: report what would happen; write and send
                       nothing

list and show are read-only: they open a read-only session and send nothing.

retry uses the same attempt and outcome records as the automatic run.  It is
allowed only for a delivery the automatic run will not touch: EXHAUSTED,
PERMANENTLY_FAILED, EXPIRED, or UNCERTAIN with --confirm-resend.  A refused
retry writes nothing and sends nothing.

Connection parameters come from the ALERT_NOTIFIER_DB_* environment
variables (see alert_notifier_db.py).

Output:
    list, show   a plain-text report on stdout
    retry        its report on stderr; stdout carries only what the log
                 channel delivers
    Errors are written to stderr as one line.  No command ever shows a
    summary, a URL, a token or a response.

Exit codes:
    0  list, show: success.  retry: the attempt was delivered
    1  show, retry: no ALERT decision has that decision_id.
       retry: the channel is not in the policy
    2  usage or argument error
    3  configuration error — policy file, channel configuration, or a
       missing environment variable
    4  database error
    6  retry: the attempt was not delivered, or the retry was refused (the
       state does not allow it, --confirm-resend is missing, or the channel
       is disabled), or the attempt number was taken by another writer, or
       stored data was invalid
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any, BinaryIO, Optional, Sequence, TextIO

import alert_notifier_db
from alert_channels import ChannelConfigurationError, preflight_channel
from alert_evaluator import format_timestamp
from alert_identity import is_sha256_hex
from alert_notifier import (
    REASON_CHANNEL_DISABLED,
    STATUS_REFUSED,
    AlertView,
    DecisionNotFoundError,
    DeliveryResult,
    format_result,
    list_alerts,
    retry_delivery,
    show_alert,
)
from alert_policy import AlertPolicy, load_policy


EXIT_OK: int = 0
EXIT_NOT_FOUND: int = 1
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_INCOMPLETE: int = 6
EXIT_INTERRUPTED: int = 130

DEFAULT_LIMIT: int = 50
MIN_LIMIT: int = 1
MAX_LIMIT: int = 500

_NONE: str = "-"

#: The fields of the persisted payload, in contract order.  Only these are
#: ever printed.
_PAYLOAD_KEYS: tuple[str, ...] = (
    "payload_version",
    "decision_id",
    "investigation_id",
    "anomaly_id",
    "anomaly_type",
    "service_name",
    "operation_name",
    "event_time",
    "evaluated_at",
    "severity",
    "confidence",
    "limitations",
    "reason_code",
    "policy_version",
    "advisory",
)


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _decision_id_argument(value: str) -> str:
    if not is_sha256_hex(value):
        raise argparse.ArgumentTypeError(
            "must be 64 lowercase hexadecimal characters"
        )
    return value


def _limit_argument(value: str) -> int:
    message = f"must be an integer between {MIN_LIMIT} and {MAX_LIMIT}"
    try:
        limit = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(message) from None
    if not MIN_LIMIT <= limit <= MAX_LIMIT:
        raise argparse.ArgumentTypeError(message)
    return limit


def _add_policy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy",
        required=True,
        metavar="PATH",
        help="Path to the alert policy JSON file.",
    )


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List alerts, show one alert, or retry one delivery.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    list_parser = commands.add_parser(
        "list", help="List the newest alerts with their delivery states.",
    )
    _add_policy(list_parser)
    list_parser.add_argument(
        "--limit",
        type=_limit_argument,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=(
            f"Number of alerts, {MIN_LIMIT}..{MAX_LIMIT} "
            f"(default {DEFAULT_LIMIT})."
        ),
    )

    show_parser = commands.add_parser(
        "show", help="Show one alert with its attempts and delivery states.",
    )
    _add_policy(show_parser)
    show_parser.add_argument("decision_id", type=_decision_id_argument)

    retry_parser = commands.add_parser(
        "retry", help="Make one operator attempt for one alert on one channel.",
    )
    _add_policy(retry_parser)
    retry_parser.add_argument("decision_id", type=_decision_id_argument)
    retry_parser.add_argument(
        "--channel",
        required=True,
        metavar="NAME",
        help="Name of the channel to deliver to.",
    )
    retry_parser.add_argument(
        "--confirm-resend",
        action="store_true",
        help=(
            "Required when the earlier delivery is UNCERTAIN: the alert may "
            "already have arrived."
        ),
    )
    retry_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would happen; write and send nothing.",
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


def _text(value: Any) -> str:
    if value is None:
        return _NONE
    if isinstance(value, (list, tuple)):
        return ", ".join(_one_line(item) for item in value) or _NONE
    return _one_line(value) or _NONE


def _time(value: Any) -> str:
    try:
        return format_timestamp(value)
    except ValueError:
        return _text(value)


def _payload_field(view: AlertView, key: str) -> str:
    if view.payload is None:
        return _NONE
    return _text(view.payload.get(key))


def render_list(views: Sequence[AlertView], limit: int) -> str:
    """The list report.  Lines are separated by LF; no trailing newline."""
    lines = [f"Alerts (newest first, limit {limit})"]
    for view in views:
        parts = [
            _text(view.decision_id),
            _time(view.evaluated_at),
            _payload_field(view, "severity"),
            _payload_field(view, "anomaly_type"),
            _payload_field(view, "service_name"),
        ]
        parts += [f"{_one_line(name)}={state}" for name, state in view.states]
        lines.append("  " + "  ".join(parts))
    if not views:
        lines.append("  (none)")
    return "\n".join(lines)


def render_show(view: AlertView) -> str:
    """The show report.  Lines are separated by LF; no trailing newline."""
    lines = [
        f"Alert {_text(view.decision_id)}",
        f"  policy version: {_text(view.policy_version)}",
        f"  reason code:    {_text(view.reason_code)}",
        f"  evaluated at:   {_time(view.evaluated_at)}",
        f"  summary stored: {view.summary_stored}",
        "",
        "Payload",
    ]
    if view.payload is None:
        lines.append("  (unavailable)")
    else:
        for key in _PAYLOAD_KEYS:
            if key in view.payload:
                lines.append(f"  {key}: {_text(view.payload[key])}")

    lines += ["", "Delivery state"]
    for name, state in view.states:
        lines.append(f"  {_one_line(name)}: {state}")
    if not view.states:
        lines.append("  (no enabled channel)")

    lines += ["", "Attempts"]
    for attempt in view.attempts:
        line = (
            f"  {_text(attempt.channel_name)}  #{_text(attempt.attempt_no)}"
            f"  {_text(attempt.channel_type)}  {_text(attempt.trigger)}"
            f"  started {_time(attempt.started_at)}"
            f"  summary_included={'yes' if attempt.summary_included is True else 'no'}"
            f"  sha256={_text(attempt.payload_sha256)}"
        )
        if attempt.outcome is None:
            line += "  ->  (no outcome)"
        else:
            line += (
                f"  ->  {_text(attempt.outcome)}  {_text(attempt.detail)}"
                f"  recorded {_time(attempt.recorded_at)}"
            )
        lines.append(line)
    if not view.attempts:
        lines.append("  (none)")
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
    """retry reports on stderr; stdout belongs to the log channel."""
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


def _connect(read_only: bool) -> tuple[Optional[Any], int]:
    """Open the connection, or report why not: (connection, exit code)."""
    try:
        return alert_notifier_db.connect(read_only=read_only), EXIT_OK
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return None, EXIT_CONFIGURATION
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return None, EXIT_DATABASE


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _list(args: argparse.Namespace, policy: AlertPolicy) -> int:
    now = _utc_now()
    channels = [channel for channel in policy.delivery.channels if channel.enabled]
    conn, code = _connect(read_only=True)
    if conn is None:
        return code

    try:
        views = list_alerts(
            conn, channels, policy.delivery, now=now, limit=args.limit,
        )
        report = render_list(views, args.limit)
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _write(sys.stdout, report)
    return EXIT_OK


def _show(args: argparse.Namespace, policy: AlertPolicy) -> int:
    now = _utc_now()
    channels = [channel for channel in policy.delivery.channels if channel.enabled]
    conn, code = _connect(read_only=True)
    if conn is None:
        return code

    try:
        view = show_alert(
            conn, channels, policy.delivery, args.decision_id, now=now,
        )
        report = render_show(view)
    except DecisionNotFoundError as exc:
        _error(f"alert not found: {exc.decision_id}")
        return EXIT_NOT_FOUND
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _write(sys.stdout, report)
    return EXIT_OK


def _retry(args: argparse.Namespace, policy: AlertPolicy) -> int:
    config = next(
        (
            channel for channel in policy.delivery.channels
            if channel.name == args.channel
        ),
        None,
    )
    if config is None:
        _error(f"channel not found in the policy: {args.channel}")
        return EXIT_NOT_FOUND

    now = _utc_now()

    if not config.enabled:
        _status(format_result(DeliveryResult(
            decision_id=args.decision_id,
            channel_name=config.name,
            status=STATUS_REFUSED,
            reason=REASON_CHANNEL_DISABLED,
        )))
        return EXIT_INCOMPLETE

    try:
        prepared = preflight_channel(config, os.environ)
    except ChannelConfigurationError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION

    conn, code = _connect(read_only=args.dry_run)
    if conn is None:
        return code

    try:
        result = retry_delivery(
            conn,
            prepared,
            policy.delivery,
            args.decision_id,
            now=now,
            confirm_resend=args.confirm_resend,
            dry_run=args.dry_run,
            log_stream=_stdout_binary(),
        )
    except DecisionNotFoundError as exc:
        _error(f"alert not found: {exc.decision_id}")
        return EXIT_NOT_FOUND
    except alert_notifier_db.DatabaseError as exc:
        _database_error(exc)
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _status(format_result(result))
    return EXIT_INCOMPLETE if result.is_problem else EXIT_OK


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

    if args.command == "list":
        return _list(args, policy)
    if args.command == "show":
        return _show(args, policy)
    return _retry(args, policy)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
