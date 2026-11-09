"""
alerting/alert_channels.py

Phase 13.5: Notification channels.

Builds the exact bytes of a notification and delivers them to one channel:

    log      one line on the standard output stream
    file     one line appended to a local file
    webhook  one HTTP POST to a configured endpoint

Body
----
The body is a copy of the payload persisted with the decision.  When the
channel includes summaries and a summary was persisted, exactly two keys are
added: "summary" and "summary_truncated".  Nothing else is ever added and
nothing is read from any other source.

The canonical bytes are the compact, key-sorted, ASCII-only JSON text of the
body.  All three channels deliver the same bytes; the log and file channels
append one newline, which is not part of the body or of its hash.

Results
-------
Every delivery ends in a SendResult: a channel type, an outcome, and a detail
code.  The detail codes form a closed set (see _FIXED_DETAILS and
http_detail()); a SendResult with any other combination cannot be built, so
free text such as an exception message can never be recorded.

Whether a failure may be retried depends on whether anything can have been
delivered:

    nothing was delivered         FAILED_RETRYABLE or FAILED_PERMANENT
    something may have been       UNCERTAIN

Webhook rules
-------------
The URL and the optional bearer token are read from environment variables
named by the policy; neither is ever printed or recorded.  HTTPS is required.
Plain HTTP is accepted only when the channel allows it and the host is a
literal loopback address (127.0.0.0/8 or ::1); a host name such as
"localhost" does not qualify.  Redirects are not followed and no proxy is
used.  Certificate verification is always on.

send() never raises for an ordinary error: an unforeseen exception inside a
channel is reported as UNCERTAIN / unexpected_error.  KeyboardInterrupt is
not caught.

Standard library and the locked alerting contracts only.  No database access.

Public API:
    WEBHOOK_MAX_BODY_BYTES, RESPONSE_READ_LIMIT, USER_AGENT
    DeliveryBody             — canonical bytes, their hash, summary_included
    build_body()
    SendResult               — validated (channel type, outcome, detail)
    http_detail()            — "http_<status>"
    classify_http_status()   — outcome of a response status, or None
    ChannelConfigurationError
    WebhookEndpoint          — a validated endpoint; shows scheme/host/port
    parse_webhook_url()
    PreparedChannel          — a channel with its run-time configuration
    preflight_channel()      — validate a channel before anything is sent
    exceeds_webhook_limit()
    send()                   — deliver one body to one channel
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Mapping, Optional
from urllib.parse import urlsplit

from alert_models import ChannelType, DeliveryOutcome
from alert_policy import ChannelConfig


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: A webhook request body may be at most this many bytes.
WEBHOOK_MAX_BODY_BYTES: int = 16384

#: At most this many bytes of a webhook response body are read, then dropped.
RESPONSE_READ_LIMIT: int = 4096

USER_AGENT: str = "AgentOps-Alerting/1.0.0"

SUMMARY_KEY: str = "summary"
SUMMARY_TRUNCATED_KEY: str = "summary_truncated"

DETAIL_UNEXPECTED_ERROR: str = "unexpected_error"
DETAIL_BODY_TOO_LARGE: str = "body_too_large"

#: Detail codes that are fixed words, per channel type and outcome.
_FIXED_DETAILS: Mapping[ChannelType, Mapping[DeliveryOutcome, frozenset[str]]] = {
    ChannelType.WEBHOOK: {
        DeliveryOutcome.SENT: frozenset(),
        DeliveryOutcome.FAILED_RETRYABLE: frozenset({
            "dns_failure",
            "connection_refused",
            "connect_timeout",
            "connect_failed",
            "tls_handshake_failed",
        }),
        DeliveryOutcome.FAILED_PERMANENT: frozenset({
            "tls_verify_failed",
            DETAIL_BODY_TOO_LARGE,
        }),
        DeliveryOutcome.UNCERTAIN: frozenset({
            "request_timeout",
            "connection_lost",
            "response_invalid",
            DETAIL_UNEXPECTED_ERROR,
        }),
    },
    ChannelType.FILE: {
        DeliveryOutcome.SENT: frozenset({"file_appended"}),
        DeliveryOutcome.FAILED_RETRYABLE: frozenset({
            "file_open_failed",
            "file_write_failed",
        }),
        DeliveryOutcome.FAILED_PERMANENT: frozenset({"file_path_unusable"}),
        DeliveryOutcome.UNCERTAIN: frozenset({
            "file_partial_write",
            "file_sync_failed",
            "file_close_failed",
            DETAIL_UNEXPECTED_ERROR,
        }),
    },
    ChannelType.LOG: {
        DeliveryOutcome.SENT: frozenset({"log_written"}),
        DeliveryOutcome.FAILED_RETRYABLE: frozenset(),
        DeliveryOutcome.FAILED_PERMANENT: frozenset(),
        DeliveryOutcome.UNCERTAIN: frozenset({
            "log_write_failed",
            DETAIL_UNEXPECTED_ERROR,
        }),
    },
}

# fullmatch is used: "$" would also match before a trailing newline.
_HTTP_DETAIL_RE = re.compile(r"http_([1-9][0-9]{2})")

_RETRYABLE_4XX = frozenset({408, 425, 429})

_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.ip_address("::1")

_UNUSABLE_PATH_ERRNOS = frozenset({
    errno.ENAMETOOLONG,
    errno.ELOOP,
    errno.EINVAL,
})

# Indirection so that tests can replace the calls without touching os itself.
_os_open = os.open
_os_write = os.write
_os_fsync = os.fsync
_os_close = os.close


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

def classify_http_status(status: Any) -> Optional[DeliveryOutcome]:
    """
    Outcome of a webhook response status, or None when the status is not a
    valid response status in 200..599.

        2xx                 SENT
        3xx                 FAILED_PERMANENT   (redirects are not followed)
        408, 425, 429       FAILED_RETRYABLE
        other 4xx           FAILED_PERMANENT
        5xx                 FAILED_RETRYABLE
    """
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    if 200 <= status <= 299:
        return DeliveryOutcome.SENT
    if 300 <= status <= 399:
        return DeliveryOutcome.FAILED_PERMANENT
    if status in _RETRYABLE_4XX:
        return DeliveryOutcome.FAILED_RETRYABLE
    if 400 <= status <= 499:
        return DeliveryOutcome.FAILED_PERMANENT
    if 500 <= status <= 599:
        return DeliveryOutcome.FAILED_RETRYABLE
    return None


def http_detail(status: int) -> str:
    """
    The detail code of a webhook response status: "http_<status>".

    Raises:
        ValueError  if status is not an int in 200..599.
    """
    if classify_http_status(status) is None:
        raise ValueError("status must be an integer in 200..599")
    return f"http_{status}"


@dataclass(frozen=True)
class SendResult:
    """
    The result of one delivery to one channel.

    Only the combinations of the closed detail contract can be constructed.
    """

    channel_type: ChannelType
    outcome: DeliveryOutcome
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.channel_type, ChannelType):
            raise ValueError(
                "channel_type must be ChannelType, "
                f"got {type(self.channel_type).__name__}"
            )
        if not isinstance(self.outcome, DeliveryOutcome):
            raise ValueError(
                f"outcome must be DeliveryOutcome, got {type(self.outcome).__name__}"
            )
        if not isinstance(self.detail, str):
            raise ValueError(
                f"detail must be str, got {type(self.detail).__name__}"
            )
        if self.detail in _FIXED_DETAILS[self.channel_type][self.outcome]:
            return

        matched = _HTTP_DETAIL_RE.fullmatch(self.detail)
        if (
            matched is not None
            and self.channel_type is ChannelType.WEBHOOK
            and classify_http_status(int(matched.group(1))) is self.outcome
        ):
            return
        raise ValueError(
            "detail is not a permitted code for "
            f"{self.channel_type.value} / {self.outcome.value}"
        )


# ---------------------------------------------------------------------------
# Body
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeliveryBody:
    """
    The exact bytes of one notification.

    data is the canonical body, sha256 its SHA-256 in lowercase hexadecimal,
    and summary_included whether data holds the summary.
    """

    data: bytes
    sha256: str
    summary_included: bool


def build_body(
    payload: Any,
    summary: Optional[str],
    summary_truncated: bool,
    *,
    include_summary: bool,
) -> DeliveryBody:
    """
    Build the canonical body from a persisted payload.

    payload is copied, never changed.  The summary keys are added exactly
    when include_summary is true and summary is not None.

    Raises:
        ValueError  if payload is not a JSON object, already holds a summary
                    key, or cannot be written as JSON; or if summary is
                    neither a str nor None; or if a flag is not a bool.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    if not isinstance(include_summary, bool):
        raise ValueError("include_summary must be bool")
    if summary is not None and not isinstance(summary, str):
        raise ValueError("summary must be str or None")
    if SUMMARY_KEY in payload or SUMMARY_TRUNCATED_KEY in payload:
        raise ValueError("payload must not hold a summary key")

    body = dict(payload)
    summary_included = include_summary and summary is not None
    if summary_included:
        if not isinstance(summary_truncated, bool):
            raise ValueError("summary_truncated must be bool")
        body[SUMMARY_KEY] = summary
        body[SUMMARY_TRUNCATED_KEY] = summary_truncated

    try:
        text = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise ValueError("payload cannot be written as JSON") from None

    data = text.encode("utf-8")
    return DeliveryBody(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        summary_included=summary_included,
    )


# ---------------------------------------------------------------------------
# Run-time configuration
# ---------------------------------------------------------------------------

class ChannelConfigurationError(RuntimeError):
    """
    Raised when a channel cannot be used as configured.  The message names
    the channel and the environment variable, never a value.
    """


@dataclass(frozen=True)
class WebhookEndpoint:
    """
    A validated webhook endpoint.

    target is the request path with its query; it may hold a secret and is
    not part of the text form.
    """

    scheme: str
    host: str
    port: int
    target: str = field(repr=False)

    @property
    def identity(self) -> str:
        """scheme, host and port: the only parts that may be printed."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def parse_webhook_url(url: Any, *, allow_insecure_loopback: bool) -> WebhookEndpoint:
    """
    Validate a webhook URL.

    Raises:
        ValueError  with a fixed phrase that does not quote the URL.
    """
    if not isinstance(url, str) or url == "":
        raise ValueError("is empty")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in url):
        raise ValueError("holds whitespace, control or non-ASCII characters")
    if "#" in url:
        raise ValueError("must not have a fragment")

    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise ValueError("is not a valid URL") from None

    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise ValueError("must use https")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError("must not hold user information")
    if not host:
        raise ValueError("has no host")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("has an invalid port")

    if scheme == "http":
        if not allow_insecure_loopback:
            raise ValueError("must use https")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(
                "may use http only with a literal loopback address"
            ) from None
        loopback = (
            address in _LOOPBACK_V4 if address.version == 4
            else address == _LOOPBACK_V6
        )
        if not loopback:
            raise ValueError("may use http only with a literal loopback address")

    if port is None:
        port = 443 if scheme == "https" else 80
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return WebhookEndpoint(scheme=scheme, host=host, port=port, target=target)


@dataclass(frozen=True)
class PreparedChannel:
    """
    A channel together with what it needs at run time.

    endpoint and token are set for a webhook channel only.  The token is not
    part of the text form.
    """

    config: ChannelConfig
    endpoint: Optional[WebhookEndpoint] = None
    token: Optional[str] = field(default=None, repr=False)


def preflight_channel(
    channel: ChannelConfig,
    environ: Mapping[str, str],
) -> PreparedChannel:
    """
    Validate everything a channel needs before anything is sent.

    A webhook channel needs its URL, and its token when one is configured,
    in environ.  A log or file channel needs nothing; the file system is not
    touched.

    Raises:
        ChannelConfigurationError  if a required variable is missing or
                                   empty, the URL is not acceptable, or the
                                   token holds anything but visible ASCII.
    """
    if not isinstance(channel, ChannelConfig):
        raise ValueError(
            f"channel must be ChannelConfig, got {type(channel).__name__}"
        )
    if channel.type is not ChannelType.WEBHOOK:
        return PreparedChannel(config=channel)

    where = f"channel {channel.name!r}"
    url = environ.get(channel.url_env)
    if not url:
        raise ChannelConfigurationError(
            f"{where}: environment variable {channel.url_env} is not set"
        )
    try:
        endpoint = parse_webhook_url(
            url, allow_insecure_loopback=channel.allow_insecure_loopback,
        )
    except ValueError as exc:
        raise ChannelConfigurationError(
            f"{where}: the URL in {channel.url_env} {exc}"
        ) from None

    token = None
    if channel.token_env is not None:
        token = environ.get(channel.token_env)
        if not token:
            raise ChannelConfigurationError(
                f"{where}: environment variable {channel.token_env} is not set"
            )
        if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in token):
            raise ChannelConfigurationError(
                f"{where}: the token in {channel.token_env} must consist of "
                "visible ASCII characters only"
            )
    return PreparedChannel(config=channel, endpoint=endpoint, token=token)


def exceeds_webhook_limit(prepared: PreparedChannel, body: DeliveryBody) -> bool:
    """True when body is too large to be sent to this channel."""
    return (
        prepared.config.type is ChannelType.WEBHOOK
        and len(body.data) > WEBHOOK_MAX_BODY_BYTES
    )


# ---------------------------------------------------------------------------
# Log channel
# ---------------------------------------------------------------------------

def _log_result(outcome: DeliveryOutcome, detail: str) -> SendResult:
    return SendResult(ChannelType.LOG, outcome, detail)


def _send_log(stream: BinaryIO, data: bytes) -> SendResult:
    """Write the body and one newline to stream, then flush."""
    line = data + b"\n"
    try:
        written = stream.write(line)
        if written is not None and written != len(line):
            return _log_result(DeliveryOutcome.UNCERTAIN, "log_write_failed")
        stream.flush()
    except Exception:  # noqa: BLE001 - how much was written is unknown
        return _log_result(DeliveryOutcome.UNCERTAIN, "log_write_failed")
    return _log_result(DeliveryOutcome.SENT, "log_written")


# ---------------------------------------------------------------------------
# File channel
# ---------------------------------------------------------------------------

def _file_result(outcome: DeliveryOutcome, detail: str) -> SendResult:
    return SendResult(ChannelType.FILE, outcome, detail)


def _close_quietly(descriptor: int) -> None:
    try:
        _os_close(descriptor)
    except OSError:
        pass


def _send_file(path: str, data: bytes) -> SendResult:
    """
    Append the body and one newline to the file at path.

    The file is created when absent; its directory is not.  Nothing is ever
    truncated.  A relative path is resolved against the working directory.
    """
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    try:
        descriptor = _os_open(path, flags, 0o600)
    except (
        FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError,
        ValueError,
    ):
        return _file_result(DeliveryOutcome.FAILED_PERMANENT, "file_path_unusable")
    except OSError as exc:
        if exc.errno in _UNUSABLE_PATH_ERRNOS:
            return _file_result(
                DeliveryOutcome.FAILED_PERMANENT, "file_path_unusable",
            )
        return _file_result(DeliveryOutcome.FAILED_RETRYABLE, "file_open_failed")

    line = data + b"\n"
    written = 0
    try:
        while written < len(line):
            count = _os_write(descriptor, line[written:])
            if count <= 0:
                break
            written += count
    except OSError:
        pass

    if written < len(line):
        _close_quietly(descriptor)
        if written == 0:
            return _file_result(
                DeliveryOutcome.FAILED_RETRYABLE, "file_write_failed",
            )
        return _file_result(DeliveryOutcome.UNCERTAIN, "file_partial_write")

    try:
        _os_fsync(descriptor)
    except OSError:
        _close_quietly(descriptor)
        return _file_result(DeliveryOutcome.UNCERTAIN, "file_sync_failed")

    try:
        _os_close(descriptor)
    except OSError:
        return _file_result(DeliveryOutcome.UNCERTAIN, "file_close_failed")
    return _file_result(DeliveryOutcome.SENT, "file_appended")


# ---------------------------------------------------------------------------
# Webhook channel
# ---------------------------------------------------------------------------

def _webhook_result(outcome: DeliveryOutcome, detail: str) -> SendResult:
    return SendResult(ChannelType.WEBHOOK, outcome, detail)


def _tls_context() -> ssl.SSLContext:
    """Default context: certificate and host name verification are on."""
    return ssl.create_default_context()


def _open_connection(
    endpoint: WebhookEndpoint, timeout: int,
) -> http.client.HTTPConnection:
    """
    Create, without connecting, the connection for an endpoint.  The client
    used here follows no redirect and reads no proxy setting.
    """
    if endpoint.scheme == "https":
        return http.client.HTTPSConnection(
            endpoint.host, endpoint.port, timeout=timeout, context=_tls_context(),
        )
    return http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)


def _send_webhook(
    prepared: PreparedChannel,
    data: bytes,
    *,
    decision_id: str,
    attempt_no: int,
) -> SendResult:
    if len(data) > WEBHOOK_MAX_BODY_BYTES:
        return _webhook_result(
            DeliveryOutcome.FAILED_PERMANENT, DETAIL_BODY_TOO_LARGE,
        )

    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": decision_id,
        "User-Agent": USER_AGENT,
        "X-AgentOps-Attempt": str(attempt_no),
        "Connection": "close",
    }
    if prepared.token is not None:
        headers["Authorization"] = f"Bearer {prepared.token}"

    connection = _open_connection(prepared.endpoint, prepared.config.timeout_seconds)
    try:
        # Phase A: resolve, connect, handshake.  Nothing has been sent yet,
        # so every failure here is definite.
        try:
            connection.connect()
        except socket.gaierror:
            return _webhook_result(DeliveryOutcome.FAILED_RETRYABLE, "dns_failure")
        except ConnectionRefusedError:
            return _webhook_result(
                DeliveryOutcome.FAILED_RETRYABLE, "connection_refused",
            )
        except TimeoutError:
            return _webhook_result(
                DeliveryOutcome.FAILED_RETRYABLE, "connect_timeout",
            )
        except ssl.SSLCertVerificationError:
            return _webhook_result(
                DeliveryOutcome.FAILED_PERMANENT, "tls_verify_failed",
            )
        except ssl.SSLError:
            return _webhook_result(
                DeliveryOutcome.FAILED_RETRYABLE, "tls_handshake_failed",
            )
        except OSError:
            return _webhook_result(DeliveryOutcome.FAILED_RETRYABLE, "connect_failed")

        # Phase B: the request may have left, so every failure is uncertain.
        try:
            connection.request(
                "POST", prepared.endpoint.target, body=data, headers=headers,
            )
            response = connection.getresponse()
            status = response.status
        except TimeoutError:
            return _webhook_result(DeliveryOutcome.UNCERTAIN, "request_timeout")
        except (ConnectionError, ssl.SSLError):
            return _webhook_result(DeliveryOutcome.UNCERTAIN, "connection_lost")
        except http.client.HTTPException:
            return _webhook_result(DeliveryOutcome.UNCERTAIN, "response_invalid")
        except OSError:
            return _webhook_result(DeliveryOutcome.UNCERTAIN, "connection_lost")

        outcome = classify_http_status(status)
        if outcome is None:
            return _webhook_result(DeliveryOutcome.UNCERTAIN, "response_invalid")
        result = _webhook_result(outcome, http_detail(status))

        # Phase C: the status decides.  The body is read and dropped.
        try:
            response.read(RESPONSE_READ_LIMIT)
        except Exception:  # noqa: BLE001 - the status is already known
            pass
        return result
    finally:
        try:
            connection.close()
        except Exception:  # noqa: BLE001 - closing cannot change the result
            pass


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def send(
    prepared: PreparedChannel,
    body: DeliveryBody,
    *,
    decision_id: str,
    attempt_no: int,
    log_stream: Optional[BinaryIO],
) -> SendResult:
    """
    Deliver one body to one channel, once.

    Parameters
    ----------
    prepared
        The channel, from preflight_channel().
    body
        The canonical body, from build_body().
    decision_id, attempt_no
        Identify the attempt to a webhook endpoint.
    log_stream
        Binary stream of the log channel.

    Returns
    -------
    SendResult
        Always, for any ordinary error.  An unforeseen exception inside a
        channel gives UNCERTAIN / unexpected_error; its text is dropped.

    KeyboardInterrupt is not caught.
    """
    channel_type = prepared.config.type
    try:
        if channel_type is ChannelType.LOG:
            return _send_log(log_stream, body.data)
        if channel_type is ChannelType.FILE:
            return _send_file(prepared.config.path, body.data)
        return _send_webhook(
            prepared, body.data, decision_id=decision_id, attempt_no=attempt_no,
        )
    except Exception:  # noqa: BLE001 - delivery cannot be proven absent
        return SendResult(
            channel_type, DeliveryOutcome.UNCERTAIN, DETAIL_UNEXPECTED_ERROR,
        )
