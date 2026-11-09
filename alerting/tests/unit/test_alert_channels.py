"""
alerting/tests/unit/test_alert_channels.py

Unit tests for alert_channels.py.

No database and no external network.  Webhook tests talk to an HTTP server
started by the test on 127.0.0.1, or to an injected connection object.  File
tests write only below pytest's temporary directory.

Test inventory:
    CH01  Body: copy, summary keys, canonical bytes, hash
    CH02  SendResult: the closed detail contract
    CH03  HTTP status classification
    CH04  Log channel
    CH05  File channel
    CH06  Webhook URL validation
    CH07  Preflight
    CH08  Webhook request and response (loopback server)
    CH09  Webhook failures before the request is sent
    CH10  Webhook failures after the request may have been sent
    CH11  Webhook: no redirect, no proxy, verification on
    CH12  send(): dispatch, unexpected errors, interrupts
    CH13  Module boundary
"""

from __future__ import annotations

import ast
import errno
import hashlib
import http.client
import http.server
import inspect
import io
import json
import os
import socket
import ssl
import threading
import time

import pytest

import alert_channels
from alert_channels import (
    DETAIL_BODY_TOO_LARGE,
    DETAIL_UNEXPECTED_ERROR,
    RESPONSE_READ_LIMIT,
    USER_AGENT,
    WEBHOOK_MAX_BODY_BYTES,
    ChannelConfigurationError,
    DeliveryBody,
    PreparedChannel,
    SendResult,
    WebhookEndpoint,
    build_body,
    classify_http_status,
    exceeds_webhook_limit,
    http_detail,
    parse_webhook_url,
    preflight_channel,
    send,
)
from alert_models import ChannelType, DeliveryOutcome
from alert_policy import ChannelConfig


O = DeliveryOutcome
LOG, FILE, WEBHOOK = ChannelType.LOG, ChannelType.FILE, ChannelType.WEBHOOK

_DEC = "d" * 64

_PAYLOAD = {
    "payload_version": "1.0.0",
    "decision_id": _DEC,
    "severity": "CRITICAL",
    "service_name": None,
    "limitations": ["no trace", "short window"],
    "advisory": "Automated detection.",
}


def _body(payload=None, summary=None, truncated=False, include=False) -> DeliveryBody:
    return build_body(
        _PAYLOAD if payload is None else payload, summary, truncated,
        include_summary=include,
    )


def _log_channel() -> PreparedChannel:
    return PreparedChannel(ChannelConfig(name="log", type=LOG, enabled=True))


def _file_channel(path) -> PreparedChannel:
    return PreparedChannel(
        ChannelConfig(name="file", type=FILE, enabled=True, path=str(path)),
    )


def _webhook_config(**overrides) -> ChannelConfig:
    values = dict(
        name="hook", type=WEBHOOK, enabled=True, url_env="ALERT_WEBHOOK_URL",
        allow_insecure_loopback=True, timeout_seconds=5,
    )
    values.update(overrides)
    return ChannelConfig(**values)


def _send(prepared, body=None, *, attempt_no=1, log_stream=None) -> SendResult:
    return send(
        prepared, body if body is not None else _body(),
        decision_id=_DEC, attempt_no=attempt_no, log_stream=log_stream,
    )


# ---------------------------------------------------------------------------
# CH01  Body
# ---------------------------------------------------------------------------

class TestBody:

    def test_canonical_bytes(self):
        body = _body()
        assert body.data == json.dumps(
            _PAYLOAD, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        assert body.data == (
            b'{"advisory":"Automated detection.","decision_id":"' + _DEC.encode()
            + b'","limitations":["no trace","short window"],'
            b'"payload_version":"1.0.0","service_name":null,"severity":"CRITICAL"}'
        )

    def test_hash_is_sha256_of_exactly_the_bytes(self):
        body = _body()
        assert body.sha256 == hashlib.sha256(body.data).hexdigest()
        assert len(body.sha256) == 64 and body.sha256 == body.sha256.lower()

    def test_no_newline_in_the_body(self):
        body = _body({"text": "line one\nline two\r\n end"})
        assert b"\n" not in body.data and b"\r" not in body.data
        assert body.sha256 == hashlib.sha256(body.data).hexdigest()

    def test_bytes_are_pure_ascii(self):
        body = _body({"text": "café 漢字 \U0001F600"})
        body.data.decode("ascii")
        assert json.loads(body.data)["text"] == "café 漢字 \U0001F600"

    def test_key_order_does_not_matter(self):
        reordered = dict(reversed(list(_PAYLOAD.items())))
        assert list(reordered) != list(_PAYLOAD)
        assert _body(reordered) == _body()

    def test_deterministic(self):
        assert _body() == _body()
        assert _body(summary="s", include=True) == _body(summary="s", include=True)

    def test_payload_is_copied_not_modified(self):
        payload = dict(_PAYLOAD)
        before = json.dumps(payload, sort_keys=True)
        _body(payload, summary="text", truncated=True, include=True)
        assert json.dumps(payload, sort_keys=True) == before
        assert "summary" not in payload

    def test_summary_off(self):
        body = _body(summary="PRIVATE", include=False)
        assert body.summary_included is False
        assert b"PRIVATE" not in body.data
        assert set(json.loads(body.data)) == set(_PAYLOAD)
        assert body == _body()

    def test_summary_on_and_present(self):
        body = _body(summary="the summary", truncated=True, include=True)
        decoded = json.loads(body.data)
        assert body.summary_included is True
        assert set(decoded) - set(_PAYLOAD) == {"summary", "summary_truncated"}
        assert decoded["summary"] == "the summary"
        assert decoded["summary_truncated"] is True

    def test_summary_on_but_not_stored(self):
        body = _body(summary=None, include=True)
        assert body.summary_included is False
        assert body == _body()
        assert "summary" not in json.loads(body.data)

    def test_empty_summary_is_still_a_summary(self):
        body = _body(summary="", include=True)
        assert body.summary_included is True
        assert json.loads(body.data)["summary"] == ""

    def test_summary_changes_the_hash(self):
        assert _body(summary="a", include=True).sha256 != _body().sha256
        assert _body(summary="a", include=True).sha256 != _body(summary="b", include=True).sha256

    @pytest.mark.parametrize("payload", [None, "text", 5, [1, 2], b"{}"])
    def test_payload_must_be_an_object(self, payload):
        with pytest.raises(ValueError, match="JSON object"):
            build_body(payload, None, False, include_summary=False)

    @pytest.mark.parametrize("key", ["summary", "summary_truncated"])
    @pytest.mark.parametrize("include", [True, False])
    def test_payload_may_not_already_hold_a_summary_key(self, key, include):
        with pytest.raises(ValueError, match="summary key"):
            build_body({**_PAYLOAD, key: "x"}, None, False, include_summary=include)

    def test_summary_must_be_text(self):
        with pytest.raises(ValueError):
            build_body(_PAYLOAD, 123, False, include_summary=True)

    def test_summary_truncated_must_be_bool_when_included(self):
        with pytest.raises(ValueError):
            build_body(_PAYLOAD, "s", "yes", include_summary=True)

    def test_include_summary_must_be_bool(self):
        with pytest.raises(ValueError):
            build_body(_PAYLOAD, "s", False, include_summary=1)

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    def test_non_finite_numbers_are_rejected(self, value):
        with pytest.raises(ValueError, match="JSON"):
            build_body({"x": value}, None, False, include_summary=False)

    def test_unserialisable_value_is_rejected_without_echo(self):
        with pytest.raises(ValueError) as excinfo:
            build_body({"x": {"SECRET-OBJECT"}}, None, False, include_summary=False)
        assert "SECRET" not in str(excinfo.value)

    def test_include_summary_is_keyword_only(self):
        with pytest.raises(TypeError):
            build_body(_PAYLOAD, None, False, True)  # noqa: FBT003

    def test_webhook_limit_is_checked_for_webhook_only(self):
        big = _body({"x": "y" * WEBHOOK_MAX_BODY_BYTES})
        hook = PreparedChannel(
            _webhook_config(), WebhookEndpoint("https", "example.com", 443, "/"),
        )
        assert exceeds_webhook_limit(hook, big) is True
        assert exceeds_webhook_limit(hook, _body()) is False
        assert exceeds_webhook_limit(_log_channel(), big) is False
        assert exceeds_webhook_limit(_file_channel("x.jsonl"), big) is False


# ---------------------------------------------------------------------------
# CH02  SendResult
# ---------------------------------------------------------------------------

_FIXED = {
    WEBHOOK: {
        O.SENT: set(),
        O.FAILED_RETRYABLE: {
            "dns_failure", "connection_refused", "connect_timeout",
            "connect_failed", "tls_handshake_failed",
        },
        O.FAILED_PERMANENT: {"tls_verify_failed", "body_too_large"},
        O.UNCERTAIN: {
            "request_timeout", "connection_lost", "response_invalid",
            "unexpected_error",
        },
    },
    FILE: {
        O.SENT: {"file_appended"},
        O.FAILED_RETRYABLE: {"file_open_failed", "file_write_failed"},
        O.FAILED_PERMANENT: {"file_path_unusable"},
        O.UNCERTAIN: {
            "file_partial_write", "file_sync_failed", "file_close_failed",
            "unexpected_error",
        },
    },
    LOG: {
        O.SENT: {"log_written"},
        O.FAILED_RETRYABLE: set(),
        O.FAILED_PERMANENT: set(),
        O.UNCERTAIN: {"log_write_failed", "unexpected_error"},
    },
}

_ALL_FIXED = {
    detail for by_outcome in _FIXED.values() for details in by_outcome.values()
    for detail in details
}


def _expected_http_outcome(status: int):
    if 200 <= status <= 299:
        return O.SENT
    if 300 <= status <= 399:
        return O.FAILED_PERMANENT
    if status in (408, 425, 429):
        return O.FAILED_RETRYABLE
    if 400 <= status <= 499:
        return O.FAILED_PERMANENT
    if 500 <= status <= 599:
        return O.FAILED_RETRYABLE
    return None


class TestSendResultContract:

    def test_module_table_equals_the_frozen_contract(self):
        table = alert_channels._FIXED_DETAILS
        assert {
            channel: {outcome: set(details) for outcome, details in by.items()}
            for channel, by in table.items()
        } == _FIXED

    def test_every_fixed_combination_is_accepted(self):
        for channel, by_outcome in _FIXED.items():
            for outcome, details in by_outcome.items():
                for detail in details:
                    result = SendResult(channel, outcome, detail)
                    assert (result.channel_type, result.outcome, result.detail) == (
                        channel, outcome, detail,
                    )

    def test_every_other_fixed_combination_is_rejected(self):
        rejected = 0
        for channel in ChannelType:
            for outcome in DeliveryOutcome:
                for detail in _ALL_FIXED - _FIXED[channel][outcome]:
                    with pytest.raises(ValueError):
                        SendResult(channel, outcome, detail)
                    rejected += 1
        assert rejected > 150

    def test_http_details_for_every_status(self):
        for status in range(100, 1000):
            detail = f"http_{status}"
            expected = _expected_http_outcome(status)
            for outcome in DeliveryOutcome:
                if outcome is expected:
                    assert SendResult(WEBHOOK, outcome, detail).detail == detail
                else:
                    with pytest.raises(ValueError):
                        SendResult(WEBHOOK, outcome, detail)

    @pytest.mark.parametrize("channel", [LOG, FILE])
    def test_http_details_are_webhook_only(self, channel):
        for outcome in DeliveryOutcome:
            with pytest.raises(ValueError):
                SendResult(channel, outcome, "http_200")

    @pytest.mark.parametrize("detail", [
        "", " ", "ok", "sent", "http_", "http_20", "http_2000", "http_099",
        "http_2xx", "HTTP_200", "http_200 ", " http_200", "http_200\n",
        "http_-20", "http_+200", "log_written ", "LOG_WRITTEN",
        "https://hooks.example/secret?token=abc",
        "ConnectionRefusedError: [Errno 111] Connection refused",
        "timed out", "connection_refused; DROP TABLE x",
    ])
    def test_arbitrary_text_is_rejected_for_every_combination(self, detail):
        for channel in ChannelType:
            for outcome in DeliveryOutcome:
                with pytest.raises(ValueError):
                    SendResult(channel, outcome, detail)

    @pytest.mark.parametrize("detail", [None, 200, b"http_200", ["http_200"]])
    def test_detail_must_be_text(self, detail):
        with pytest.raises(ValueError):
            SendResult(WEBHOOK, O.SENT, detail)

    def test_types_are_checked(self):
        with pytest.raises(ValueError):
            SendResult("webhook", O.SENT, "http_200")
        with pytest.raises(ValueError):
            SendResult(WEBHOOK, "SENT", "http_200")

    def test_error_message_does_not_echo_the_detail(self):
        with pytest.raises(ValueError) as excinfo:
            SendResult(WEBHOOK, O.UNCERTAIN, "https://secret.example/?t=1")
        assert "secret.example" not in str(excinfo.value)

    def test_result_is_immutable_and_has_three_fields(self):
        result = SendResult(LOG, O.SENT, "log_written")
        with pytest.raises(Exception):
            result.detail = "x"
        assert [f for f in result.__dataclass_fields__] == [
            "channel_type", "outcome", "detail",
        ]

    def test_unexpected_error_is_uncertain_only(self):
        for channel in ChannelType:
            SendResult(channel, O.UNCERTAIN, DETAIL_UNEXPECTED_ERROR)
            for outcome in (O.SENT, O.FAILED_RETRYABLE, O.FAILED_PERMANENT):
                with pytest.raises(ValueError):
                    SendResult(channel, outcome, DETAIL_UNEXPECTED_ERROR)


# ---------------------------------------------------------------------------
# CH03  HTTP status classification
# ---------------------------------------------------------------------------

class TestHttpClassification:

    @pytest.mark.parametrize("status", [200, 201, 202, 204, 299])
    def test_2xx_sent(self, status):
        assert classify_http_status(status) is O.SENT

    @pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308, 399])
    def test_3xx_permanent(self, status):
        assert classify_http_status(status) is O.FAILED_PERMANENT

    @pytest.mark.parametrize("status", [408, 425, 429])
    def test_retryable_4xx(self, status):
        assert classify_http_status(status) is O.FAILED_RETRYABLE

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 409, 410, 413, 422, 499])
    def test_other_4xx_permanent(self, status):
        assert classify_http_status(status) is O.FAILED_PERMANENT

    @pytest.mark.parametrize("status", [500, 501, 502, 503, 504, 599])
    def test_5xx_retryable(self, status):
        assert classify_http_status(status) is O.FAILED_RETRYABLE

    @pytest.mark.parametrize("status", [
        0, 99, 100, 101, 199, 600, 700, 999, -200, None, "200", 200.0, True,
    ])
    def test_anything_else_is_not_a_status(self, status):
        assert classify_http_status(status) is None

    def test_whole_range_matches_the_reference(self):
        for status in range(0, 1000):
            assert classify_http_status(status) is _expected_http_outcome(status)

    def test_http_detail(self):
        assert http_detail(200) == "http_200"
        assert http_detail(503) == "http_503"
        for status in (199, 600, "200", None, True):
            with pytest.raises(ValueError):
                http_detail(status)


# ---------------------------------------------------------------------------
# CH04  Log channel
# ---------------------------------------------------------------------------

class _SpyStream(io.BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def write(self, data):
        self.calls.append("write")
        return super().write(data)

    def flush(self):
        self.calls.append("flush")
        return super().flush()


class TestLogChannel:

    def test_writes_exactly_the_body_and_one_newline(self):
        stream = _SpyStream()
        body = _body()
        result = _send(_log_channel(), body, log_stream=stream)
        assert result == SendResult(LOG, O.SENT, "log_written")
        assert stream.getvalue() == body.data + b"\n"

    def test_one_write_then_flush(self):
        stream = _SpyStream()
        _send(_log_channel(), log_stream=stream)
        assert stream.calls == ["write", "flush"]

    def test_no_prefix_and_each_line_is_the_json_body(self):
        stream = io.BytesIO()
        first, second = _body(), _body({"k": "v"})
        _send(_log_channel(), first, log_stream=stream)
        _send(_log_channel(), second, log_stream=stream)
        lines = stream.getvalue().split(b"\n")
        assert lines == [first.data, second.data, b""]
        assert [json.loads(line) for line in lines[:2]] == [_PAYLOAD, {"k": "v"}]

    def test_newline_is_not_part_of_the_hash(self):
        stream = io.BytesIO()
        body = _body()
        _send(_log_channel(), body, log_stream=stream)
        assert hashlib.sha256(stream.getvalue()[:-1]).hexdigest() == body.sha256
        assert hashlib.sha256(stream.getvalue()).hexdigest() != body.sha256

    def test_summary_only_through_the_body(self):
        stream = io.BytesIO()
        _send(_log_channel(), _body(summary="PRIVATE", include=False), log_stream=stream)
        assert b"PRIVATE" not in stream.getvalue()
        _send(_log_channel(), _body(summary="PRIVATE", include=True), log_stream=stream)
        assert b"PRIVATE" in stream.getvalue()

    def test_stream_without_a_write_count_is_accepted(self):
        class _NoCount:
            def __init__(self):
                self.data = b""

            def write(self, data):
                self.data += data

            def flush(self):
                pass

        stream = _NoCount()
        assert _send(_log_channel(), log_stream=stream).outcome is O.SENT
        assert stream.data.endswith(b"\n")

    @pytest.mark.parametrize("error", [
        BrokenPipeError("pipe"), OSError("disk"), ValueError("closed file"),
    ])
    def test_write_failure_is_uncertain(self, error):
        class _Failing:
            def write(self, data):
                raise error

            def flush(self):
                raise AssertionError("flush after a failed write")

        result = _send(_log_channel(), log_stream=_Failing())
        assert result == SendResult(LOG, O.UNCERTAIN, "log_write_failed")

    def test_flush_failure_is_uncertain(self):
        class _FlushFails(io.BytesIO):
            def flush(self):
                raise OSError("flush")

        assert _send(_log_channel(), log_stream=_FlushFails()) == SendResult(
            LOG, O.UNCERTAIN, "log_write_failed",
        )

    def test_short_write_is_uncertain(self):
        class _Short:
            flushed = False

            def write(self, data):
                return len(data) - 1

            def flush(self):
                self.flushed = True

        stream = _Short()
        assert _send(_log_channel(), log_stream=stream) == SendResult(
            LOG, O.UNCERTAIN, "log_write_failed",
        )

    def test_missing_stream_is_uncertain_not_a_crash(self):
        result = _send(_log_channel(), log_stream=None)
        assert result.outcome is O.UNCERTAIN
        assert result.detail in ("log_write_failed", "unexpected_error")

    def test_log_never_reports_a_retryable_failure(self):
        assert _FIXED[LOG][O.FAILED_RETRYABLE] == set()
        assert _FIXED[LOG][O.FAILED_PERMANENT] == set()


# ---------------------------------------------------------------------------
# CH05  File channel
# ---------------------------------------------------------------------------

class _OsSpy:
    """Wraps the real descriptor calls and can make one of them fail."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list[tuple] = []
        self.fail: dict[str, BaseException] = {}
        self.write_plan: list = []
        self._real = {
            name: getattr(alert_channels, f"_os_{name}")
            for name in ("open", "write", "fsync", "close")
        }
        for name in self._real:
            monkeypatch.setattr(alert_channels, f"_os_{name}", getattr(self, name))

    def _maybe_fail(self, name: str) -> None:
        if name in self.fail:
            raise self.fail[name]

    def open(self, path, flags, mode):
        self.calls.append(("open", path, flags, mode))
        self._maybe_fail("open")
        return self._real["open"](path, flags, mode)

    def write(self, descriptor, data):
        self.calls.append(("write", len(data)))
        if self.write_plan:
            step = self.write_plan.pop(0)
            if isinstance(step, BaseException):
                raise step
            if step == 0:
                return 0
            return self._real["write"](descriptor, data[:step])
        self._maybe_fail("write")
        return self._real["write"](descriptor, data)

    def fsync(self, descriptor):
        self.calls.append(("fsync",))
        self._maybe_fail("fsync")
        return self._real["fsync"](descriptor)

    def close(self, descriptor):
        self.calls.append(("close",))
        result = self._real["close"](descriptor)
        self._maybe_fail("close")
        return result

    def names(self) -> list[str]:
        return [call[0] for call in self.calls]


@pytest.fixture
def os_spy(monkeypatch) -> _OsSpy:
    return _OsSpy(monkeypatch)


class TestFileChannel:

    def test_creates_the_file_and_appends_one_line(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        body = _body()
        result = _send(_file_channel(path), body)
        assert result == SendResult(FILE, O.SENT, "file_appended")
        assert path.read_bytes() == body.data + b"\n"

    def test_appends_without_touching_existing_content(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        path.write_bytes(b'{"earlier":1}\n')
        first, second = _body(), _body({"k": "v"})
        _send(_file_channel(path), first)
        _send(_file_channel(path), second)
        assert path.read_bytes() == (
            b'{"earlier":1}\n' + first.data + b"\n" + second.data + b"\n"
        )

    def test_newline_is_a_single_lf_and_outside_the_hash(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        body = _body()
        _send(_file_channel(path), body)
        content = path.read_bytes()
        assert content.endswith(b"\n") and b"\r" not in content
        assert hashlib.sha256(content[:-1]).hexdigest() == body.sha256

    def test_content_is_ascii_json_lines(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        _send(_file_channel(path), _body({"text": "café\nx"}))
        (line,) = path.read_text(encoding="ascii").splitlines()
        assert json.loads(line) == {"text": "café\nx"}

    def test_open_flags_and_mode(self, tmp_path, os_spy):
        _send(_file_channel(tmp_path / "a.jsonl"))
        _, _, flags, mode = os_spy.calls[0]
        assert mode == 0o600
        assert flags & os.O_APPEND and flags & os.O_CREAT and flags & os.O_WRONLY
        assert not flags & os.O_TRUNC
        assert not flags & getattr(os, "O_EXCL", 0)
        assert flags & getattr(os, "O_BINARY", 0) == getattr(os, "O_BINARY", 0)

    def test_write_then_fsync_then_close(self, tmp_path, os_spy):
        _send(_file_channel(tmp_path / "a.jsonl"))
        assert os_spy.names() == ["open", "write", "fsync", "close"]

    def test_short_writes_are_continued_until_complete(self, tmp_path, os_spy):
        path = tmp_path / "a.jsonl"
        body = _body()
        os_spy.write_plan = [3, 5, 1]
        result = _send(_file_channel(path), body)
        assert result.outcome is O.SENT
        assert path.read_bytes() == body.data + b"\n"
        assert os_spy.names().count("write") == 4

    def test_relative_path_resolves_against_the_working_directory(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        body = _body()
        assert _send(_file_channel("relative.jsonl"), body).outcome is O.SENT
        assert (tmp_path / "relative.jsonl").read_bytes() == body.data + b"\n"

    def test_missing_parent_directory_is_not_created(self, tmp_path):
        path = tmp_path / "missing" / "alerts.jsonl"
        result = _send(_file_channel(path))
        assert result == SendResult(FILE, O.FAILED_PERMANENT, "file_path_unusable")
        assert not (tmp_path / "missing").exists()

    def test_directory_as_target(self, tmp_path):
        result = _send(_file_channel(tmp_path))
        assert result == SendResult(FILE, O.FAILED_PERMANENT, "file_path_unusable")

    def test_parent_that_is_a_file(self, tmp_path):
        (tmp_path / "plain").write_bytes(b"x")
        result = _send(_file_channel(tmp_path / "plain" / "alerts.jsonl"))
        assert result == SendResult(FILE, O.FAILED_PERMANENT, "file_path_unusable")
        assert (tmp_path / "plain").read_bytes() == b"x"

    @pytest.mark.parametrize("error", [
        FileNotFoundError(errno.ENOENT, "x"),
        PermissionError(errno.EACCES, "x"),
        IsADirectoryError(errno.EISDIR, "x"),
        NotADirectoryError(errno.ENOTDIR, "x"),
        OSError(errno.ENAMETOOLONG, "x"),
        OSError(errno.ELOOP, "x"),
        OSError(errno.EINVAL, "x"),
        ValueError("embedded null byte"),
    ])
    def test_unusable_path_is_permanent(self, tmp_path, os_spy, error):
        os_spy.fail["open"] = error
        result = _send(_file_channel(tmp_path / "a.jsonl"))
        assert result == SendResult(FILE, O.FAILED_PERMANENT, "file_path_unusable")
        assert os_spy.names() == ["open"]

    @pytest.mark.parametrize("code", [errno.EMFILE, errno.ENFILE, errno.ENOSPC, errno.EIO])
    def test_other_open_failure_is_retryable(self, tmp_path, os_spy, code):
        os_spy.fail["open"] = OSError(code, "x")
        result = _send(_file_channel(tmp_path / "a.jsonl"))
        assert result == SendResult(FILE, O.FAILED_RETRYABLE, "file_open_failed")
        assert not (tmp_path / "a.jsonl").exists()

    def test_write_failure_before_any_byte_is_retryable(self, tmp_path, os_spy):
        path = tmp_path / "a.jsonl"
        os_spy.write_plan = [OSError(errno.ENOSPC, "full")]
        result = _send(_file_channel(path))
        assert result == SendResult(FILE, O.FAILED_RETRYABLE, "file_write_failed")
        assert path.read_bytes() == b""
        assert os_spy.names() == ["open", "write", "close"]

    def test_zero_byte_write_at_the_start_is_retryable(self, tmp_path, os_spy):
        os_spy.write_plan = [0]
        result = _send(_file_channel(tmp_path / "a.jsonl"))
        assert result == SendResult(FILE, O.FAILED_RETRYABLE, "file_write_failed")

    def test_failure_after_some_bytes_is_uncertain(self, tmp_path, os_spy):
        path = tmp_path / "a.jsonl"
        os_spy.write_plan = [4, OSError(errno.EIO, "io")]
        result = _send(_file_channel(path))
        assert result == SendResult(FILE, O.UNCERTAIN, "file_partial_write")
        assert path.read_bytes() == _body().data[:4]
        assert "fsync" not in os_spy.names()
        assert os_spy.names()[-1] == "close"

    def test_stall_after_some_bytes_is_uncertain(self, tmp_path, os_spy):
        os_spy.write_plan = [4, 0]
        result = _send(_file_channel(tmp_path / "a.jsonl"))
        assert result == SendResult(FILE, O.UNCERTAIN, "file_partial_write")

    def test_fsync_failure_is_uncertain(self, tmp_path, os_spy):
        path = tmp_path / "a.jsonl"
        os_spy.fail["fsync"] = OSError(errno.EIO, "io")
        result = _send(_file_channel(path))
        assert result == SendResult(FILE, O.UNCERTAIN, "file_sync_failed")
        assert os_spy.names() == ["open", "write", "fsync", "close"]

    def test_close_failure_after_the_append_is_uncertain(self, tmp_path, os_spy):
        os_spy.fail["close"] = OSError(errno.EIO, "io")
        result = _send(_file_channel(tmp_path / "a.jsonl"))
        assert result == SendResult(FILE, O.UNCERTAIN, "file_close_failed")

    def test_close_error_does_not_replace_an_earlier_outcome(self, tmp_path, os_spy):
        os_spy.fail["close"] = OSError(errno.EIO, "io")
        os_spy.write_plan = [OSError(errno.ENOSPC, "full")]
        assert _send(_file_channel(tmp_path / "a.jsonl")).detail == "file_write_failed"

        os_spy.write_plan = [2, OSError(errno.EIO, "io")]
        assert _send(_file_channel(tmp_path / "b.jsonl")).detail == "file_partial_write"

        os_spy.fail["fsync"] = OSError(errno.EIO, "io")
        assert _send(_file_channel(tmp_path / "c.jsonl")).detail == "file_sync_failed"

    def test_descriptor_is_always_closed(self, tmp_path, os_spy):
        for plan, failing in [
            ([OSError(errno.EIO, "x")], None),
            ([1, OSError(errno.EIO, "x")], None),
            ([], "fsync"),
            ([], None),
        ]:
            os_spy.calls.clear()
            os_spy.fail.clear()
            os_spy.write_plan = list(plan)
            if failing:
                os_spy.fail[failing] = OSError(errno.EIO, "x")
            _send(_file_channel(tmp_path / "a.jsonl"))
            assert os_spy.names().count("close") == 1

    def test_no_large_body_limit_for_files(self, tmp_path):
        path = tmp_path / "a.jsonl"
        body = _body({"x": "y" * (WEBHOOK_MAX_BODY_BYTES * 2)})
        assert _send(_file_channel(path), body).outcome is O.SENT
        assert path.stat().st_size == len(body.data) + 1

    def test_source_never_truncates_or_creates_directories(self):
        source = inspect.getsource(alert_channels)
        for word in ("O_TRUNC", "makedirs", "mkdir", "truncate(", "lockf", "flock",
                     "msvcrt", "unlink", "remove(", "rename"):
            assert word not in source, word


# ---------------------------------------------------------------------------
# CH06  Webhook URL validation
# ---------------------------------------------------------------------------

class TestWebhookUrl:

    @pytest.mark.parametrize("url, allow, expected", [
        ("https://example.com/hook", False, ("https", "example.com", 443, "/hook")),
        ("https://example.com", False, ("https", "example.com", 443, "/")),
        ("https://example.com:8443/a/b?x=1&y=2", False,
         ("https", "example.com", 8443, "/a/b?x=1&y=2")),
        ("HTTPS://EXAMPLE.com/Hook", False, ("https", "example.com", 443, "/Hook")),
        ("https://[2001:db8::1]:444/x", False, ("https", "2001:db8::1", 444, "/x")),
        ("https://127.0.0.1/x", False, ("https", "127.0.0.1", 443, "/x")),
        ("https://localhost/x", False, ("https", "localhost", 443, "/x")),
        ("https://example.com/hook", True, ("https", "example.com", 443, "/hook")),
        ("http://127.0.0.1:8080/hook", True, ("http", "127.0.0.1", 8080, "/hook")),
        ("http://127.0.0.1", True, ("http", "127.0.0.1", 80, "/")),
        ("http://127.255.255.254:9/x?k=v", True, ("http", "127.255.255.254", 9, "/x?k=v")),
        ("http://[::1]:9000/x", True, ("http", "::1", 9000, "/x")),
    ])
    def test_accepted(self, url, allow, expected):
        endpoint = parse_webhook_url(url, allow_insecure_loopback=allow)
        assert (endpoint.scheme, endpoint.host, endpoint.port, endpoint.target) == expected

    @pytest.mark.parametrize("url, allow", [
        ("http://example.com/hook", True),
        ("http://example.com/hook", False),
        ("http://localhost/hook", True),
        ("http://localhost:8080/hook", True),
        ("http://127.0.0.1/hook", False),
        ("http://[::1]/hook", False),
        ("http://128.0.0.1/hook", True),
        ("http://10.0.0.1/hook", True),
        ("http://0.0.0.0/hook", True),
        ("http://[::ffff:127.0.0.1]/hook", True),
        ("http://[::2]/hook", True),
        ("http://2130706433/hook", True),
        ("http://127.1/hook", True),
        ("ftp://example.com/hook", True),
        ("file:///etc/passwd", True),
        ("ws://127.0.0.1/hook", True),
        ("example.com/hook", False),
        ("//example.com/hook", False),
        ("https://user:pw@example.com/hook", False),
        ("https://user@example.com/hook", False),
        ("https://@example.com/hook", False),
        ("http://user@127.0.0.1/hook", True),
        ("https:///hook", False),
        ("https://:443/hook", False),
        ("https://example.com:0/hook", False),
        ("https://example.com:99999/hook", False),
        ("https://example.com:abc/hook", False),
        ("https://example.com/hook#frag", False),
        ("https://example.com/hook#", False),
        ("https://example.com/a b", False),
        ("https://example.com/hook\n", False),
        (" https://example.com/hook", False),
        ("https://exämple.com/hook", False),
        ("https://example.com/ ", False),
        ("https://[::1/hook", False),
        ("", False),
    ])
    def test_rejected_without_quoting_the_url(self, url, allow):
        with pytest.raises(ValueError) as excinfo:
            parse_webhook_url(url, allow_insecure_loopback=allow)
        message = str(excinfo.value)
        if len(url) > 3:
            assert url not in message
        for fragment in ("example.com", "127.0.0.1", "user@", "pw@", "#", "/hook"):
            assert fragment not in message

    @pytest.mark.parametrize("url", [None, 5, b"https://example.com/"])
    def test_non_text_is_rejected(self, url):
        with pytest.raises(ValueError):
            parse_webhook_url(url, allow_insecure_loopback=True)

    def test_identity_shows_only_scheme_host_and_port(self):
        endpoint = parse_webhook_url(
            "https://hooks.example.com/services/T0/B0/SECRETPATH?token=SECRETQUERY",
            allow_insecure_loopback=False,
        )
        assert endpoint.identity == "https://hooks.example.com:443"
        for text in (endpoint.identity, repr(endpoint), str(endpoint)):
            assert "SECRET" not in text and "token" not in text
        assert endpoint.target == "/services/T0/B0/SECRETPATH?token=SECRETQUERY"

    def test_identity_of_an_ipv6_host(self):
        endpoint = parse_webhook_url("http://[::1]:9000/x", allow_insecure_loopback=True)
        assert endpoint.identity == "http://[::1]:9000"

    def test_allow_flag_is_keyword_only(self):
        with pytest.raises(TypeError):
            parse_webhook_url("https://example.com/", False)  # noqa: FBT003


# ---------------------------------------------------------------------------
# CH07  Preflight
# ---------------------------------------------------------------------------

class TestPreflight:

    def test_webhook_with_url(self):
        prepared = preflight_channel(
            _webhook_config(), {"ALERT_WEBHOOK_URL": "https://example.com/h?k=SECRET"},
        )
        assert prepared.endpoint.identity == "https://example.com:443"
        assert prepared.token is None
        assert "SECRET" not in repr(prepared)

    def test_webhook_with_token(self):
        config = _webhook_config(token_env="ALERT_WEBHOOK_TOKEN")
        prepared = preflight_channel(config, {
            "ALERT_WEBHOOK_URL": "https://example.com/h",
            "ALERT_WEBHOOK_TOKEN": "s3cr3t-TOKEN.value_~+/=",
        })
        assert prepared.token == "s3cr3t-TOKEN.value_~+/="
        assert "s3cr3t" not in repr(prepared) and "s3cr3t" not in str(prepared)

    @pytest.mark.parametrize("environ", [{}, {"ALERT_WEBHOOK_URL": ""}])
    def test_missing_url_variable(self, environ):
        with pytest.raises(ChannelConfigurationError) as excinfo:
            preflight_channel(_webhook_config(), environ)
        message = str(excinfo.value)
        assert "'hook'" in message and "ALERT_WEBHOOK_URL" in message

    def test_invalid_url_names_the_variable_not_the_value(self):
        with pytest.raises(ChannelConfigurationError) as excinfo:
            preflight_channel(
                _webhook_config(),
                {"ALERT_WEBHOOK_URL": "http://internal.example/hook?token=SECRET"},
            )
        message = str(excinfo.value)
        assert "ALERT_WEBHOOK_URL" in message and "'hook'" in message
        assert "internal.example" not in message and "SECRET" not in message

    def test_loopback_http_needs_the_channel_setting(self):
        environ = {"ALERT_WEBHOOK_URL": "http://127.0.0.1:8080/hook"}
        assert preflight_channel(_webhook_config(), environ).endpoint.scheme == "http"
        with pytest.raises(ChannelConfigurationError):
            preflight_channel(_webhook_config(allow_insecure_loopback=False), environ)

    @pytest.mark.parametrize("environ", [
        {"ALERT_WEBHOOK_URL": "https://example.com/h"},
        {"ALERT_WEBHOOK_URL": "https://example.com/h", "ALERT_WEBHOOK_TOKEN": ""},
    ])
    def test_missing_token_variable(self, environ):
        config = _webhook_config(token_env="ALERT_WEBHOOK_TOKEN")
        with pytest.raises(ChannelConfigurationError, match="ALERT_WEBHOOK_TOKEN"):
            preflight_channel(config, environ)

    @pytest.mark.parametrize("token", [
        "with space", "tab\there", "line\nbreak", "cr\rhere", "nul\x00", "del\x7f",
        "café", " ", " leading", "trailing ",
    ])
    def test_token_must_be_visible_ascii(self, token):
        config = _webhook_config(token_env="ALERT_WEBHOOK_TOKEN")
        with pytest.raises(ChannelConfigurationError) as excinfo:
            preflight_channel(config, {
                "ALERT_WEBHOOK_URL": "https://example.com/h",
                "ALERT_WEBHOOK_TOKEN": token,
            })
        assert "ALERT_WEBHOOK_TOKEN" in str(excinfo.value)
        assert token not in str(excinfo.value)

    def test_token_variable_is_not_read_when_not_configured(self):
        prepared = preflight_channel(_webhook_config(), {
            "ALERT_WEBHOOK_URL": "https://example.com/h",
            "ALERT_WEBHOOK_TOKEN": "unused",
        })
        assert prepared.token is None

    def test_only_the_named_variables_are_read(self):
        read = []

        class _Environ(dict):
            def get(self, key, default=None):
                read.append(key)
                return super().get(key, default)

        environ = _Environ({
            "ALERT_WEBHOOK_URL": "https://example.com/h",
            "ALERT_WEBHOOK_TOKEN": "tok",
            "HTTPS_PROXY": "http://proxy.example:3128",
        })
        preflight_channel(_webhook_config(token_env="ALERT_WEBHOOK_TOKEN"), environ)
        assert read == ["ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_TOKEN"]

    def test_log_and_file_need_nothing_and_touch_no_file(self, tmp_path, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("preflight must not touch the file system")

        for name in ("_os_open", "_os_write", "_os_fsync", "_os_close"):
            monkeypatch.setattr(alert_channels, name, forbidden)
        missing = tmp_path / "no-such-dir" / "alerts.jsonl"
        log = preflight_channel(ChannelConfig(name="log", type=LOG, enabled=True), {})
        file = preflight_channel(
            ChannelConfig(name="file", type=FILE, enabled=True, path=str(missing)), {},
        )
        assert (log.endpoint, log.token, file.endpoint, file.token) == (None,) * 4
        assert not missing.parent.exists()

    def test_preflight_opens_no_connection(self, monkeypatch):
        monkeypatch.setattr(
            alert_channels, "_open_connection",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")),
        )
        preflight_channel(_webhook_config(), {"ALERT_WEBHOOK_URL": "https://example.com/"})

    def test_non_channel_is_rejected(self):
        with pytest.raises(ValueError):
            preflight_channel({"name": "x"}, {})

    def test_configuration_error_is_a_runtime_error(self):
        assert issubclass(ChannelConfigurationError, RuntimeError)
        assert not issubclass(ChannelConfigurationError, ValueError)


# ---------------------------------------------------------------------------
# Loopback HTTP server
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.server.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": self.rfile.read(length),
        })

    def _respond(self) -> None:
        behaviour = self.server.behaviour
        self._record()
        if behaviour.get("delay"):
            time.sleep(behaviour["delay"])
        if behaviour.get("raw") is not None:
            self.wfile.write(behaviour["raw"])
            self.wfile.flush()
            self.close_connection = True
            return
        if behaviour.get("drop"):
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        body = behaviour.get("body", b"")
        self.send_response(behaviour.get("status", 200))
        for name, value in behaviour.get("headers", {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_POST = _respond
    do_GET = _respond


@pytest.fixture
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.requests = []
    httpd.behaviour = {}
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True,
    )
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _hook(server, *, path="/hook", token=None, **config) -> PreparedChannel:
    environ = {
        "ALERT_WEBHOOK_URL": f"http://127.0.0.1:{server.server_address[1]}{path}",
    }
    if token is not None:
        config["token_env"] = "ALERT_WEBHOOK_TOKEN"
        environ["ALERT_WEBHOOK_TOKEN"] = token
    return preflight_channel(_webhook_config(**config), environ)


# ---------------------------------------------------------------------------
# CH08  Webhook request and response
# ---------------------------------------------------------------------------

class TestWebhookRequest:

    def test_post_with_the_exact_body(self, server):
        body = _body(summary="s", include=True)
        result = _send(_hook(server), body, attempt_no=3)
        assert result == SendResult(WEBHOOK, O.SENT, "http_200")
        (request,) = server.requests
        assert request["method"] == "POST"
        assert request["path"] == "/hook"
        assert request["body"] == body.data
        assert hashlib.sha256(request["body"]).hexdigest() == body.sha256

    def test_headers(self, server):
        body = _body()
        _send(_hook(server), body, attempt_no=7)
        headers = server.requests[0]["headers"]
        assert headers["content-type"] == "application/json"
        assert headers["idempotency-key"] == _DEC
        assert headers["user-agent"] == "AgentOps-Alerting/1.0.0" == USER_AGENT
        assert headers["x-agentops-attempt"] == "7"
        assert headers["connection"] == "close"
        assert headers["content-length"] == str(len(body.data))
        assert "authorization" not in headers

    def test_bearer_token(self, server):
        _send(_hook(server, token="tok-123"))
        assert server.requests[0]["headers"]["authorization"] == "Bearer tok-123"

    def test_query_string_is_sent_as_configured(self, server):
        _send(_hook(server, path="/hook/a?key=SECRETQUERY&x=1"))
        assert server.requests[0]["path"] == "/hook/a?key=SECRETQUERY&x=1"

    def test_one_request_per_send(self, server):
        _send(_hook(server))
        assert len(server.requests) == 1

    @pytest.mark.parametrize("status, outcome", [
        (200, O.SENT), (201, O.SENT), (202, O.SENT), (204, O.SENT), (299, O.SENT),
        (301, O.FAILED_PERMANENT), (302, O.FAILED_PERMANENT),
        (307, O.FAILED_PERMANENT), (308, O.FAILED_PERMANENT),
        (400, O.FAILED_PERMANENT), (401, O.FAILED_PERMANENT),
        (403, O.FAILED_PERMANENT), (404, O.FAILED_PERMANENT),
        (410, O.FAILED_PERMANENT), (422, O.FAILED_PERMANENT),
        (408, O.FAILED_RETRYABLE), (425, O.FAILED_RETRYABLE),
        (429, O.FAILED_RETRYABLE),
        (500, O.FAILED_RETRYABLE), (502, O.FAILED_RETRYABLE),
        (503, O.FAILED_RETRYABLE), (504, O.FAILED_RETRYABLE),
        (599, O.FAILED_RETRYABLE),
    ])
    def test_status_classification(self, server, status, outcome):
        server.behaviour = {"status": status}
        result = _send(_hook(server))
        assert result == SendResult(WEBHOOK, outcome, f"http_{status}")

    @pytest.mark.parametrize("status", [199, 600, 999])
    def test_status_outside_200_599_is_uncertain(self, server, status):
        server.behaviour = {"raw": f"HTTP/1.1 {status} Odd\r\nContent-Length: 0\r\n\r\n".encode()}
        result = _send(_hook(server))
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, "response_invalid")

    def test_response_body_is_never_surfaced(self, server):
        server.behaviour = {"status": 500, "body": b"SECRET-RESPONSE-BODY " * 50}
        result = _send(_hook(server))
        assert result == SendResult(WEBHOOK, O.FAILED_RETRYABLE, "http_500")
        assert "SECRET" not in repr(result)

    def test_large_response_body_is_not_read_in_full(self, server, monkeypatch):
        server.behaviour = {"status": 200, "body": b"x" * (RESPONSE_READ_LIMIT * 20)}
        reads = []
        real_read = http.client.HTTPResponse.read

        def spy(self, amt=None):
            reads.append(amt)
            return real_read(self, amt)

        monkeypatch.setattr(http.client.HTTPResponse, "read", spy)
        assert _send(_hook(server)).outcome is O.SENT
        assert reads == [RESPONSE_READ_LIMIT] == [4096]

    def test_response_headers_are_ignored(self, server):
        server.behaviour = {"status": 200, "headers": {"X-Secret": "SECRET-HEADER"}}
        assert "SECRET" not in repr(_send(_hook(server)))

    def test_body_at_the_limit_is_sent(self, server):
        padding = WEBHOOK_MAX_BODY_BYTES - len(_body({"x": ""}).data)
        body = _body({"x": "y" * padding})
        assert len(body.data) == WEBHOOK_MAX_BODY_BYTES == 16384
        assert _send(_hook(server), body).outcome is O.SENT
        assert server.requests[0]["body"] == body.data

    def test_body_over_the_limit_opens_no_connection(self, server, monkeypatch):
        padding = WEBHOOK_MAX_BODY_BYTES - len(_body({"x": ""}).data) + 1
        body = _body({"x": "y" * padding})
        assert len(body.data) == WEBHOOK_MAX_BODY_BYTES + 1
        opened = []
        real_open = alert_channels._open_connection
        monkeypatch.setattr(
            alert_channels, "_open_connection",
            lambda *a, **k: opened.append(a) or real_open(*a, **k),
        )
        result = _send(_hook(server), body)
        assert result == SendResult(WEBHOOK, O.FAILED_PERMANENT, "body_too_large")
        assert result.detail == DETAIL_BODY_TOO_LARGE
        assert opened == [] and server.requests == []


# ---------------------------------------------------------------------------
# Injected connections
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status=200, read_error=None) -> None:
        self.status = status
        self._read_error = read_error
        self.read_calls: list = []

    def read(self, amount=None):
        self.read_calls.append(amount)
        if self._read_error is not None:
            raise self._read_error
        return b"SECRET-RESPONSE"


class _FakeConnection:
    def __init__(self, *, connect=None, request=None, getresponse=None,
                 response=None, close=None) -> None:
        self.errors = {
            "connect": connect, "request": request, "getresponse": getresponse,
            "close": close,
        }
        self.response = response or _FakeResponse()
        self.calls: list[str] = []
        self.request_args = None

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.errors[name] is not None:
            raise self.errors[name]

    def connect(self) -> None:
        self._step("connect")

    def request(self, method, target, body=None, headers=None) -> None:
        self.request_args = (method, target, body, dict(headers))
        self._step("request")

    def getresponse(self):
        self._step("getresponse")
        return self.response

    def close(self) -> None:
        self._step("close")


def _injected(monkeypatch, connection, **config) -> PreparedChannel:
    monkeypatch.setattr(alert_channels, "_open_connection", lambda *a, **k: connection)
    return preflight_channel(
        _webhook_config(**config),
        {"ALERT_WEBHOOK_URL": "https://hooks.example.com/path?token=SECRETQUERY"},
    )


# ---------------------------------------------------------------------------
# CH09  Failures before the request is sent
# ---------------------------------------------------------------------------

class TestWebhookBeforeSend:

    @pytest.mark.parametrize("error, outcome, detail", [
        (socket.gaierror(-2, "Name or service not known"),
         O.FAILED_RETRYABLE, "dns_failure"),
        (ConnectionRefusedError(111, "refused"),
         O.FAILED_RETRYABLE, "connection_refused"),
        (TimeoutError("timed out"), O.FAILED_RETRYABLE, "connect_timeout"),
        (socket.timeout("timed out"), O.FAILED_RETRYABLE, "connect_timeout"),
        (ssl.SSLCertVerificationError(1, "certificate verify failed"),
         O.FAILED_PERMANENT, "tls_verify_failed"),
        (ssl.SSLError(1, "wrong version number"),
         O.FAILED_RETRYABLE, "tls_handshake_failed"),
        (ssl.SSLZeroReturnError(6, "closed"),
         O.FAILED_RETRYABLE, "tls_handshake_failed"),
        (ConnectionResetError(104, "reset"), O.FAILED_RETRYABLE, "connect_failed"),
        (OSError(101, "Network is unreachable"), O.FAILED_RETRYABLE, "connect_failed"),
    ])
    def test_connect_failures(self, monkeypatch, error, outcome, detail):
        connection = _FakeConnection(connect=error)
        result = _send(_injected(monkeypatch, connection))
        assert result == SendResult(WEBHOOK, outcome, detail)
        assert connection.calls == ["connect", "close"]
        assert connection.request_args is None

    def test_none_of_them_is_uncertain(self, monkeypatch):
        for error in (socket.gaierror(), ConnectionRefusedError(), TimeoutError(),
                      ssl.SSLError(), OSError()):
            result = _send(_injected(monkeypatch, _FakeConnection(connect=error)))
            assert result.outcome is O.FAILED_RETRYABLE

    def test_exception_text_is_never_surfaced(self, monkeypatch):
        error = OSError("https://hooks.example.com/path?token=SECRETQUERY failed")
        result = _send(_injected(monkeypatch, _FakeConnection(connect=error)))
        assert result.detail == "connect_failed"
        assert "SECRET" not in repr(result) and "hooks.example" not in repr(result)

    def test_real_refused_connection(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        prepared = preflight_channel(
            _webhook_config(timeout_seconds=20),
            {"ALERT_WEBHOOK_URL": f"http://127.0.0.1:{port}/hook"},
        )
        assert _send(prepared) == SendResult(
            WEBHOOK, O.FAILED_RETRYABLE, "connection_refused",
        )

    def test_connection_gets_the_channel_timeout(self, monkeypatch):
        seen = []

        def opener(endpoint, timeout):
            seen.append((endpoint.identity, timeout))
            return _FakeConnection()

        monkeypatch.setattr(alert_channels, "_open_connection", opener)
        prepared = preflight_channel(
            _webhook_config(timeout_seconds=17),
            {"ALERT_WEBHOOK_URL": "https://hooks.example.com:8443/p"},
        )
        _send(prepared)
        assert seen == [("https://hooks.example.com:8443", 17)]


# ---------------------------------------------------------------------------
# CH10  Failures after the request may have been sent
# ---------------------------------------------------------------------------

class TestWebhookAfterSend:

    @pytest.mark.parametrize("step", ["request", "getresponse"])
    @pytest.mark.parametrize("error, detail", [
        (TimeoutError("timed out"), "request_timeout"),
        (socket.timeout("timed out"), "request_timeout"),
        (ConnectionResetError(104, "reset"), "connection_lost"),
        (BrokenPipeError(32, "pipe"), "connection_lost"),
        (ConnectionAbortedError(103, "aborted"), "connection_lost"),
        (http.client.RemoteDisconnected("closed without response"), "connection_lost"),
        (ssl.SSLError(1, "decryption failed"), "connection_lost"),
        (ssl.SSLEOFError(8, "EOF"), "connection_lost"),
        (OSError(5, "io"), "connection_lost"),
        (http.client.BadStatusLine("garbage"), "response_invalid"),
        (http.client.LineTooLong("header"), "response_invalid"),
        (http.client.IncompleteRead(b""), "response_invalid"),
        (http.client.CannotSendRequest(), "response_invalid"),
    ])
    def test_every_failure_is_uncertain(self, monkeypatch, step, error, detail):
        connection = _FakeConnection(**{step: error})
        result = _send(_injected(monkeypatch, connection))
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, detail)
        assert connection.calls[-1] == "close"

    @pytest.mark.parametrize("status", [None, "200", 0, 100, 199, 600, True])
    def test_invalid_status_is_uncertain(self, monkeypatch, status):
        connection = _FakeConnection(response=_FakeResponse(status=status))
        result = _send(_injected(monkeypatch, connection))
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, "response_invalid")

    def test_real_request_timeout(self, server):
        server.behaviour = {"delay": 2.5}
        result = _send(_hook(server, timeout_seconds=1))
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, "request_timeout")
        assert len(server.requests) == 1

    def test_real_garbage_response(self, server):
        server.behaviour = {"raw": b"THIS IS NOT HTTP\r\n\r\n"}
        assert _send(_hook(server)) == SendResult(
            WEBHOOK, O.UNCERTAIN, "response_invalid",
        )

    def test_real_dropped_connection(self, server):
        server.behaviour = {"drop": True}
        result = _send(_hook(server))
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, "connection_lost")

    @pytest.mark.parametrize("read_error", [
        OSError("reset"), TimeoutError(), http.client.IncompleteRead(b""),
        ValueError("x"),
    ])
    def test_error_while_dropping_the_body_keeps_the_status(self, monkeypatch, read_error):
        response = _FakeResponse(status=503, read_error=read_error)
        result = _send(_injected(monkeypatch, _FakeConnection(response=response)))
        assert result == SendResult(WEBHOOK, O.FAILED_RETRYABLE, "http_503")

    def test_close_error_does_not_change_the_result(self, monkeypatch):
        connection = _FakeConnection(close=OSError("close"))
        assert _send(_injected(monkeypatch, connection)) == SendResult(
            WEBHOOK, O.SENT, "http_200",
        )
        failing = _FakeConnection(connect=TimeoutError(), close=OSError("close"))
        assert _send(_injected(monkeypatch, failing)).detail == "connect_timeout"

    def test_body_is_read_once_with_the_limit(self, monkeypatch):
        response = _FakeResponse(status=200)
        _send(_injected(monkeypatch, _FakeConnection(response=response)))
        assert response.read_calls == [RESPONSE_READ_LIMIT]

    def test_request_line_and_headers_on_the_injected_connection(self, monkeypatch):
        connection = _FakeConnection()
        prepared = _injected(monkeypatch, connection)
        body = _body()
        _send(prepared, body, attempt_no=4)
        method, target, sent, headers = connection.request_args
        assert (method, target, sent) == ("POST", "/path?token=SECRETQUERY", body.data)
        assert headers == {
            "Content-Type": "application/json",
            "Idempotency-Key": _DEC,
            "User-Agent": "AgentOps-Alerting/1.0.0",
            "X-AgentOps-Attempt": "4",
            "Connection": "close",
        }
        assert connection.calls == ["connect", "request", "getresponse", "close"]

    def test_connect_is_a_separate_step_before_the_request(self):
        source = inspect.getsource(alert_channels._send_webhook)
        assert source.index("connection.connect()") < source.index("connection.request(")


# ---------------------------------------------------------------------------
# CH11  No redirect, no proxy, verification on
# ---------------------------------------------------------------------------

class TestWebhookTransportRules:

    def test_redirect_is_not_followed(self, server):
        port = server.server_address[1]
        server.behaviour = {
            "status": 302,
            "headers": {"Location": f"http://127.0.0.1:{port}/elsewhere"},
        }
        result = _send(_hook(server))
        assert result == SendResult(WEBHOOK, O.FAILED_PERMANENT, "http_302")
        assert [request["path"] for request in server.requests] == ["/hook"]

    def test_proxy_variables_are_ignored(self, server, monkeypatch):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                     "https_proxy", "all_proxy"):
            monkeypatch.setenv(name, "http://127.0.0.1:9")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        assert _send(_hook(server)) == SendResult(WEBHOOK, O.SENT, "http_200")
        assert len(server.requests) == 1

    def test_https_endpoint_uses_a_verifying_tls_connection(self):
        endpoint = WebhookEndpoint("https", "example.com", 443, "/")
        connection = alert_channels._open_connection(endpoint, 5)
        assert isinstance(connection, http.client.HTTPSConnection)
        assert (connection.host, connection.port, connection.timeout) == (
            "example.com", 443, 5,
        )
        context = alert_channels._tls_context()
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_http_endpoint_uses_a_plain_connection(self):
        endpoint = WebhookEndpoint("http", "127.0.0.1", 8080, "/")
        connection = alert_channels._open_connection(endpoint, 5)
        assert type(connection) is http.client.HTTPConnection

    def test_no_way_to_weaken_verification_or_add_a_ca(self):
        source = inspect.getsource(alert_channels)
        for word in (
            "CERT_NONE", "check_hostname = False", "_create_unverified_context",
            "load_verify_locations", "load_cert_chain", "cafile", "capath",
            "verify_mode", "set_tunnel", "urllib.request", "ProxyHandler",
            "getproxies", "Location",
        ):
            assert word not in source, word


# ---------------------------------------------------------------------------
# CH12  send()
# ---------------------------------------------------------------------------

class TestSend:

    def test_dispatches_by_channel_type(self, tmp_path, server):
        stream = io.BytesIO()
        assert _send(_log_channel(), log_stream=stream).channel_type is LOG
        assert _send(_file_channel(tmp_path / "a.jsonl")).channel_type is FILE
        assert _send(_hook(server)).channel_type is WEBHOOK
        assert stream.getvalue() and (tmp_path / "a.jsonl").exists()
        assert len(server.requests) == 1

    def test_same_bytes_reach_every_channel(self, tmp_path, server):
        body = _body(summary="s", include=True)
        stream = io.BytesIO()
        _send(_log_channel(), body, log_stream=stream)
        _send(_file_channel(tmp_path / "a.jsonl"), body)
        _send(_hook(server), body)
        assert stream.getvalue() == body.data + b"\n"
        assert (tmp_path / "a.jsonl").read_bytes() == body.data + b"\n"
        assert server.requests[0]["body"] == body.data

    @pytest.mark.parametrize("error", [
        RuntimeError("https://secret.example/?token=abc"),
        ValueError("unexpected"), KeyError("x"), AssertionError("bug"),
        UnicodeEncodeError("ascii", "x", 0, 1, "bad"),
    ])
    def test_unexpected_webhook_error_is_uncertain(self, monkeypatch, error):
        def opener(*args, **kwargs):
            raise error

        monkeypatch.setattr(alert_channels, "_open_connection", opener)
        prepared = preflight_channel(
            _webhook_config(), {"ALERT_WEBHOOK_URL": "https://example.com/"},
        )
        result = _send(prepared)
        assert result == SendResult(WEBHOOK, O.UNCERTAIN, "unexpected_error")
        assert "secret" not in repr(result)

    def test_unexpected_file_error_is_uncertain(self, monkeypatch, tmp_path):
        def explode(*args):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(alert_channels, "_os_open", explode)
        assert _send(_file_channel(tmp_path / "a.jsonl")) == SendResult(
            FILE, O.UNCERTAIN, "unexpected_error",
        )

    def test_unexpected_log_error_is_uncertain(self, monkeypatch):
        def explode(*args):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(alert_channels, "_send_log", explode)
        assert _send(_log_channel(), log_stream=io.BytesIO()) == SendResult(
            LOG, O.UNCERTAIN, "unexpected_error",
        )

    @pytest.mark.parametrize("step", ["connect", "request", "getresponse"])
    def test_keyboard_interrupt_is_not_converted(self, monkeypatch, step):
        connection = _FakeConnection(**{step: KeyboardInterrupt()})
        with pytest.raises(KeyboardInterrupt):
            _send(_injected(monkeypatch, connection))
        assert connection.calls[-1] == "close"

    def test_keyboard_interrupt_from_the_log_stream_is_not_converted(self):
        class _Interrupting:
            def write(self, data):
                raise KeyboardInterrupt

            def flush(self):
                pass

        with pytest.raises(KeyboardInterrupt):
            _send(_log_channel(), log_stream=_Interrupting())

    def test_system_exit_is_not_converted(self, monkeypatch, tmp_path):
        def leave(*args):
            raise SystemExit(1)

        monkeypatch.setattr(alert_channels, "_os_open", leave)
        with pytest.raises(SystemExit):
            _send(_file_channel(tmp_path / "a.jsonl"))

    def test_send_makes_one_attempt_and_never_waits(self):
        source = inspect.getsource(alert_channels)
        assert "sleep" not in source
        assert "while written < len(line)" in source
        assert source.count("connection.request(") == 1
        assert source.count("connection.connect()") == 1

    def test_arguments_are_keyword_only(self):
        with pytest.raises(TypeError):
            send(_log_channel(), _body(), _DEC, 1, io.BytesIO())


# ---------------------------------------------------------------------------
# CH13  Module boundary
# ---------------------------------------------------------------------------

class TestModuleBoundary:

    def test_imports(self):
        tree = ast.parse(inspect.getsource(alert_channels))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "errno", "hashlib", "http.client", "ipaddress", "json",
            "os", "re", "socket", "ssl", "dataclasses", "typing", "urllib.parse",
            "alert_models", "alert_policy",
        }

    def test_no_database_no_third_party_client_no_environment_read(self):
        source = inspect.getsource(alert_channels)
        for word in ("psycopg", "requests", "httpx", "urllib3", "os.environ",
                     "getenv", "logging", "print("):
            assert word not in source, word

    def test_no_statement_text(self):
        source = inspect.getsource(alert_channels)
        for word in ("SELECT", "INSERT INTO", "ON CONFLICT", "UPDATE ", "DELETE "):
            assert word not in source, word

    def test_constants(self):
        assert WEBHOOK_MAX_BODY_BYTES == 16384
        assert RESPONSE_READ_LIMIT == 4096
        assert USER_AGENT == "AgentOps-Alerting/1.0.0"
        assert alert_channels.SUMMARY_KEY == "summary"
        assert alert_channels.SUMMARY_TRUNCATED_KEY == "summary_truncated"
