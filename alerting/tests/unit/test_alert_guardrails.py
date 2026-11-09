"""
alerting/tests/unit/test_alert_guardrails.py

Unit tests for alert_guardrails.py.

No database, no network, no clock.  The evaluation functions are called with
plain rows; run_guardrails is given a recording stand-in for
alert_guardrail_store.  Expected values are written out by hand, not computed
with the production helpers.

Test inventory:
    GR01  Vocabulary and constants
    GR02  GuardrailResult contract
    GR03  Detector configuration reader
    GR04  detector_checkpoint_stale
    GR05  uninvestigated_anomalies
    GR06  Delivery states: which are reported where
    GR07  Delivery lookback
    GR08  Channel scope and current settings
    GR09  Delivery data that cannot be evaluated
    GR10  Order and cap
    GR11  Delivery state is the Phase 13.5 function
    GR12  run_guardrails
    GR13  Evaluation errors
    GR14  Module boundaries
    GR15  Defective time zones and unreadable rows fail closed
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import random
from datetime import datetime, timedelta, timezone, tzinfo

import psycopg
import pytest

import alert_delivery_state
import alert_guardrail_store
import alert_guardrails
from alert_delivery_state import DeliveryState
from alert_guardrails import (
    DETAIL_OK,
    GUARDRAIL_CODES,
    MAX_DETAIL_IDS,
    REASON_CODES,
    DetectorConfigError,
    GuardrailEvaluationError,
    GuardrailResult,
    evaluate_checkpoints,
    evaluate_deliveries,
    evaluate_uninvestigated,
    load_expected_groups,
    parse_expected_groups,
    run_guardrails,
)
from alert_identity import compute_attempt_id
from alert_models import ChannelType, GuardrailFinding, GuardrailStatus
from alert_policy import ChannelConfig, DeliveryPolicy, GuardrailPolicy, validate_policy


OK = GuardrailStatus.OK
VIOLATION = GuardrailStatus.VIOLATION
S = DeliveryState

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_US = timedelta(microseconds=1)

_GROUP = ("trace_latency", "agentops-demo-app", "agentops.request")
_GROUP_ID = '["trace_latency","agentops-demo-app","agentops.request"]'


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _dec(n) -> str:
    return _hex(f"decision-{n}")


def _anomaly(n) -> str:
    return _hex(f"anomaly-{n}")


def _ago(**kwargs) -> datetime:
    return _T0 - timedelta(**kwargs)


def _finding(result: GuardrailResult) -> tuple:
    return (result.finding.status, result.finding.count, result.detail_ids)


# -- rows -------------------------------------------------------------------

def _checkpoint(group=_GROUP, updated_at=_T0) -> dict:
    return {
        "signal_path": group[0], "service_name": group[1],
        "operation_name": group[2], "updated_at": updated_at,
    }


def _anomaly_row(n, detected_at) -> dict:
    return {"anomaly_id": _anomaly(n), "detected_at": detected_at}


def _decision(n, evaluated_at=None) -> dict:
    return {
        "decision_id": _dec(n),
        "evaluated_at": evaluated_at if evaluated_at is not None else _ago(minutes=10),
    }


def _attempt(n, channel, attempt_no, outcome=None, *, started=None, **overrides) -> dict:
    row = {
        "attempt_id": compute_attempt_id(_dec(n), channel, attempt_no),
        "decision_id": _dec(n),
        "channel_name": channel,
        "channel_type": "log",
        "attempt_no": attempt_no,
        "trigger": "auto",
        "summary_included": False,
        "payload_sha256": "f" * 64,
        "started_at": started if started is not None else _ago(minutes=5),
        "outcome": outcome,
        "recorded_at": _ago(minutes=5) if outcome is not None else None,
    }
    row.update(overrides)
    return row


def _history(n, channel, *outcomes, started=None) -> list[dict]:
    """Attempts 1..n of one pair; None is an attempt without an outcome."""
    return [
        _attempt(n, channel, number, outcome, started=started)
        for number, outcome in enumerate(outcomes, start=1)
    ]


# -- policy -----------------------------------------------------------------

def _channel(name="log", *, enabled=True, max_attempts=3, timeout_seconds=10) -> ChannelConfig:
    return ChannelConfig(
        name=name, type=ChannelType.LOG, enabled=enabled,
        max_attempts=max_attempts, timeout_seconds=timeout_seconds,
    )


def _deliveries(decisions, history, channels=None, *, now=_T0, max_age=60,
                lookback_hours=24):
    channels = [_channel()] if channels is None else channels
    return evaluate_deliveries(
        decisions, history, channels,
        DeliveryPolicy(channels=tuple(channels), max_delivery_age_minutes=max_age),
        now=now, lookback_hours=lookback_hours,
    )


def _policy(channels=None, **guardrails):
    if channels is None:
        channels = [{"name": "log", "type": "log", "enabled": True}]
    return validate_policy({
        "policy_schema_version": "1.0.0",
        "policy_version": "1.0.0",
        "evaluation": {},
        "delivery": {"channels": channels},
        "guardrails": guardrails,
    })


def _pair(n, channel="log") -> str:
    return f"{_dec(n)}/{channel}"


# ---------------------------------------------------------------------------
# GR01  Vocabulary
# ---------------------------------------------------------------------------

class TestVocabulary:

    def test_codes_and_their_order(self):
        assert GUARDRAIL_CODES == (
            "detector_checkpoint_stale",
            "uninvestigated_anomalies",
            "delivery_uncertain",
            "delivery_exhausted",
        )

    def test_cap_and_fixed_text(self):
        assert MAX_DETAIL_IDS == 20
        assert DETAIL_OK == "No violations."
        assert alert_guardrails.violation_detail(23, 20) == (
            "23 violation(s); showing 20 of 23."
        )
        assert alert_guardrails.violation_detail(1, 1) == (
            "1 violation(s); showing 1 of 1."
        )

    def test_reason_codes_are_a_closed_set(self):
        assert REASON_CODES == {
            "invalid_checkpoint_data", "invalid_anomaly_data",
            "invalid_delivery_data",
        }

    def test_policy_thresholds_are_the_locked_fields_and_defaults(self):
        thresholds = GuardrailPolicy()
        assert thresholds.detector_checkpoint_max_age_minutes == 1440
        assert thresholds.uninvestigated_anomaly_max_age_minutes == 60
        assert thresholds.delivery_lookback_hours == 24
        source = inspect.getsource(alert_guardrails.run_guardrails)
        for name in ("detector_checkpoint_max_age_minutes",
                     "uninvestigated_anomaly_max_age_minutes",
                     "delivery_lookback_hours"):
            assert name in source


# ---------------------------------------------------------------------------
# GR02  GuardrailResult
# ---------------------------------------------------------------------------

def _make(status, count, detail, ids, code="delivery_uncertain") -> GuardrailResult:
    return GuardrailResult(
        finding=GuardrailFinding(code=code, status=status, count=count, detail=detail),
        detail_ids=ids,
    )


class TestResultContract:

    def test_ok(self):
        result = _make(OK, 0, "No violations.", ())
        assert _finding(result) == (OK, 0, ())

    def test_violation_below_the_cap(self):
        result = _make(VIOLATION, 2, "2 violation(s); showing 2 of 2.", ("a", "b"))
        assert result.detail_ids == ("a", "b")

    def test_violation_at_the_cap(self):
        ids = tuple(str(i) for i in range(20))
        assert _make(VIOLATION, 20, "20 violation(s); showing 20 of 20.", ids).detail_ids == ids

    def test_violation_above_the_cap(self):
        ids = tuple(str(i) for i in range(20))
        result = _make(VIOLATION, 100, "100 violation(s); showing 20 of 100.", ids)
        assert result.finding.count == 100 and len(result.detail_ids) == 20

    @pytest.mark.parametrize("status, count, detail, ids", [
        (OK, 0, "No violations.", ("a",)),                      # ids on OK
        (OK, 0, "", ()),                                        # wrong OK text
        (OK, 0, "0 violation(s); showing 0 of 0.", ()),         # violation text on OK
        (VIOLATION, 0, "No violations.", ()),                   # count 0
        (VIOLATION, 0, "0 violation(s); showing 0 of 0.", ()),
        (VIOLATION, 2, "2 violation(s); showing 2 of 2.", ("a",)),          # too few
        (VIOLATION, 1, "1 violation(s); showing 1 of 1.", ("a", "b")),      # too many
        (VIOLATION, 2, "No violations.", ("a", "b")),           # OK text
        (VIOLATION, 2, "2 violations", ("a", "b")),             # free text
        (VIOLATION, 2, "3 violation(s); showing 2 of 3.", ("a", "b")),      # wrong count
        (VIOLATION, 2, "2 violation(s); showing 1 of 2.", ("a", "b")),      # wrong shown
        (VIOLATION, 30, "30 violation(s); showing 30 of 30.",
         tuple(str(i) for i in range(30))),                     # over the cap
        (VIOLATION, 30, "30 violation(s); showing 19 of 30.",
         tuple(str(i) for i in range(19))),                     # under the cap
    ])
    def test_inconsistent_combinations_are_rejected(self, status, count, detail, ids):
        with pytest.raises(ValueError):
            _make(status, count, detail, ids)

    def test_locked_model_already_rejects_ok_with_a_count(self):
        with pytest.raises(ValueError):
            GuardrailFinding(code="x", status=OK, count=1, detail="No violations.")

    @pytest.mark.parametrize("ids", [["a"], "a", None, (1,), (None,)])
    def test_detail_ids_must_be_a_tuple_of_text(self, ids):
        with pytest.raises(ValueError):
            _make(VIOLATION, 1, "1 violation(s); showing 1 of 1.", ids)

    def test_finding_must_be_the_locked_model(self):
        with pytest.raises(ValueError):
            GuardrailResult(finding={"code": "delivery_uncertain"}, detail_ids=())

    def test_unknown_code_is_rejected(self):
        with pytest.raises(ValueError):
            _make(OK, 0, "No violations.", (), code="delivery_disabled")

    def test_result_is_immutable_and_has_two_fields(self):
        result = _make(OK, 0, "No violations.", ())
        with pytest.raises(Exception):
            result.detail_ids = ("a",)
        assert list(GuardrailResult.__dataclass_fields__) == ["finding", "detail_ids"]

    def test_locked_models_are_reused_not_redefined(self):
        import alert_models
        assert alert_guardrails.GuardrailFinding is alert_models.GuardrailFinding
        assert alert_guardrails.GuardrailStatus is alert_models.GuardrailStatus
        assert [status.value for status in GuardrailStatus] == ["OK", "VIOLATION"]


# ---------------------------------------------------------------------------
# GR03  Detector configuration
# ---------------------------------------------------------------------------

def _config(groups, **top) -> str:
    return json.dumps({"groups": groups, **top})


_VALID_GROUP = {
    "signal_path": "trace_latency",
    "service_name": "agentops-demo-app",
    "operation_name": "agentops.request",
}


class TestDetectorConfig:

    def test_shipped_runner_config_shape(self):
        text = _config([_VALID_GROUP], run={"overlap_minutes": 10,
                                            "initial_lookback_hours": 24})
        assert parse_expected_groups(text) == (_GROUP,)

    def test_multiple_groups_keep_file_order(self):
        groups = [
            {"signal_path": "tool_failure", "service_name": "svc-b"},
            {"signal_path": "error_rate", "service_name": "svc-a", "operation_name": "op"},
            _VALID_GROUP,
        ]
        assert parse_expected_groups(_config(groups)) == (
            ("tool_failure", "svc-b", ""),
            ("error_rate", "svc-a", "op"),
            _GROUP,
        )

    @pytest.mark.parametrize("group", [
        {"signal_path": "retrieval", "service_name": "svc"},
        {"signal_path": "retrieval", "service_name": "svc", "operation_name": None},
        {"signal_path": "retrieval", "service_name": "svc", "operation_name": ""},
    ])
    def test_missing_null_and_empty_operation_are_the_empty_string(self, group):
        assert parse_expected_groups(_config([group])) == (("retrieval", "svc", ""),)

    def test_values_are_not_trimmed(self):
        group = {"signal_path": " trace_latency", "service_name": "svc ",
                 "operation_name": " op "}
        assert parse_expected_groups(_config([group])) == (
            (" trace_latency", "svc ", " op "),
        )

    def test_signal_path_is_not_checked_against_the_detector_list(self):
        group = {"signal_path": "not_a_known_signal", "service_name": "svc"}
        assert parse_expected_groups(_config([group])) == (
            ("not_a_known_signal", "svc", ""),
        )
        source = inspect.getsource(alert_guardrails)
        for name in ("agent_latency", "tool_latency", "error_rate", "tool_failure"):
            assert name not in source

    def test_other_top_level_keys_are_ignored_and_not_validated(self):
        text = _config([_VALID_GROUP], run="not even an object", extra=[1, 2])
        assert parse_expected_groups(text) == (_GROUP,)

    def test_result_is_an_immutable_tuple_of_tuples(self):
        result = parse_expected_groups(_config([_VALID_GROUP]))
        assert type(result) is tuple and type(result[0]) is tuple

    @pytest.mark.parametrize("text, phrase", [
        ("{ not json", "the file is not valid UTF-8 JSON"),
        ("", "the file is not valid UTF-8 JSON"),
        ("[]", "the top level must be a JSON object"),
        ('"groups"', "the top level must be a JSON object"),
        ("{}", "'groups' is required"),
        ('{"run": {}}', "'groups' is required"),
        ('{"groups": {}}', "'groups' must be a list"),
        ('{"groups": null}', "'groups' must be a list"),
        ('{"groups": []}', "'groups' must hold at least one group"),
        ('{"groups": ["x"]}', "group 0 must be a JSON object"),
        ('{"groups": [null]}', "group 0 must be a JSON object"),
        ('{"groups": [{"signal_path": "a", "service_name": "b", "service": "c"}]}',
         "group 0 has an unknown key"),
        ('{"groups": [{"service_name": "b"}]}', "group 0: 'signal_path' is required"),
        ('{"groups": [{"signal_path": 5, "service_name": "b"}]}',
         "group 0: 'signal_path' must be a string"),
        ('{"groups": [{"signal_path": null, "service_name": "b"}]}',
         "group 0: 'signal_path' must be a string"),
        ('{"groups": [{"signal_path": "", "service_name": "b"}]}',
         "group 0: 'signal_path' must not be empty or whitespace-only"),
        ('{"groups": [{"signal_path": "  ", "service_name": "b"}]}',
         "group 0: 'signal_path' must not be empty or whitespace-only"),
        ('{"groups": [{"signal_path": "a"}]}', "group 0: 'service_name' is required"),
        ('{"groups": [{"signal_path": "a", "service_name": ["b"]}]}',
         "group 0: 'service_name' must be a string"),
        ('{"groups": [{"signal_path": "a", "service_name": ""}]}',
         "group 0: 'service_name' must not be empty or whitespace-only"),
        ('{"groups": [{"signal_path": "a", "service_name": "\\t"}]}',
         "group 0: 'service_name' must not be empty or whitespace-only"),
        ('{"groups": [{"signal_path": "a", "service_name": "b", "operation_name": 7}]}',
         "group 0: 'operation_name' must be a string or null"),
        ('{"groups": [{"signal_path": "a", "service_name": "b", "operation_name": " "}]}',
         "group 0: 'operation_name' must not be whitespace-only"),
        ('{"groups": [{"signal_path": "a", "service_name": "b"},'
         ' {"signal_path": "a", "service_name": "b"}]}',
         "group 1 repeats an earlier group"),
        ('{"groups": [{"signal_path": "a", "service_name": "b", "operation_name": ""},'
         ' {"signal_path": "a", "service_name": "b", "operation_name": null}]}',
         "group 1 repeats an earlier group"),
        ('{"groups": [], "groups": [{"signal_path": "a", "service_name": "b"}]}',
         "a JSON object repeats a key"),
        ('{"groups": [{"signal_path": "a", "signal_path": "c", "service_name": "b"}]}',
         "a JSON object repeats a key"),
        ('{"run": {"x": 1, "x": 2}, "groups": [{"signal_path": "a", "service_name": "b"}]}',
         "a JSON object repeats a key"),
        ('{"groups": [{"signal_path": "a", "service_name": "b"}], "run": NaN}',
         "the file holds NaN or Infinity"),
        ('{"groups": [{"signal_path": "a", "service_name": "b"}], "run": Infinity}',
         "the file holds NaN or Infinity"),
        ('{"groups": [{"signal_path": "a", "service_name": "b"}], "run": -Infinity}',
         "the file holds NaN or Infinity"),
    ])
    def test_rejected_with_a_fixed_phrase(self, text, phrase):
        with pytest.raises(DetectorConfigError) as excinfo:
            parse_expected_groups(text)
        assert str(excinfo.value) == phrase

    def test_second_group_is_named_by_its_index(self):
        text = _config([_VALID_GROUP, {"signal_path": "a"}])
        with pytest.raises(DetectorConfigError, match="^group 1: 'service_name' is required$"):
            parse_expected_groups(text)

    @pytest.mark.parametrize("text", [
        '{"groups": [{"signal_path": "SECRET-SIGNAL", "service_name": 5}]}',
        '{"groups": [{"signal_path": "a", "service_name": "b", "SECRET-KEY": 1}]}',
        '{"groups": [{"signal_path": "SECRET-A", "service_name": "SECRET-B"},'
        ' {"signal_path": "SECRET-A", "service_name": "SECRET-B"}]}',
        '{"groups": "SECRET-VALUE"}',
        '{"SECRET-KEY": 1, "SECRET-KEY": 2}',
        '{"groups": [SECRET-TOKEN]}',
    ])
    def test_messages_never_quote_a_value(self, text):
        with pytest.raises(DetectorConfigError) as excinfo:
            parse_expected_groups(text)
        assert "SECRET" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ or excinfo.value.__context__ is None

    @pytest.mark.parametrize("text", [None, 5, b"{}"])
    def test_non_text_is_rejected(self, text):
        with pytest.raises(DetectorConfigError):
            parse_expected_groups(text)

    def test_error_is_a_value_error(self):
        assert issubclass(DetectorConfigError, ValueError)

    # -- file loader --------------------------------------------------------

    def test_load_from_a_file(self, tmp_path):
        path = tmp_path / "runner_config.json"
        path.write_text(_config([_VALID_GROUP]), encoding="utf-8")
        assert load_expected_groups(path) == (_GROUP,)
        assert load_expected_groups(str(path)) == (_GROUP,)

    def test_load_reads_non_ascii_names(self, tmp_path):
        path = tmp_path / "runner_config.json"
        group = {"signal_path": "trace_latency", "service_name": "café"}
        path.write_text(json.dumps({"groups": [group]}, ensure_ascii=False),
                        encoding="utf-8")
        assert load_expected_groups(path) == (("trace_latency", "café", ""),)

    def test_load_rejects_bytes_that_are_not_utf8(self, tmp_path):
        path = tmp_path / "runner_config.json"
        path.write_bytes(b'{"groups": [{"signal_path": "\xff", "service_name": "b"}]}')
        with pytest.raises(DetectorConfigError, match="not valid UTF-8 JSON"):
            load_expected_groups(path)

    def test_load_missing_file_is_an_os_error(self, tmp_path):
        with pytest.raises(OSError):
            load_expected_groups(tmp_path / "absent.json")

    def test_load_error_does_not_quote_the_path(self, tmp_path):
        path = tmp_path / "SECRET-NAME.json"
        path.write_text("{", encoding="utf-8")
        with pytest.raises(DetectorConfigError) as excinfo:
            load_expected_groups(path)
        assert "SECRET" not in str(excinfo.value)

    def test_loader_does_not_import_the_detector(self):
        source = inspect.getsource(alert_guardrails)
        for word in ("run_config", "anomaly_detector", "anomaly-detector",
                     "importlib", "sys.path"):
            assert word not in source, word


# ---------------------------------------------------------------------------
# GR04  detector_checkpoint_stale
# ---------------------------------------------------------------------------

def _checkpoints(rows, expected=(_GROUP,), *, now=_T0, max_age=1440) -> GuardrailResult:
    return evaluate_checkpoints(rows, expected, now=now, max_age_minutes=max_age)


class TestCheckpoints:

    def test_fresh(self):
        result = _checkpoints([_checkpoint(updated_at=_ago(hours=1))])
        assert result.finding.code == "detector_checkpoint_stale"
        assert _finding(result) == (OK, 0, ())
        assert result.finding.detail == "No violations."

    def test_exactly_at_the_threshold_is_fresh(self):
        result = _checkpoints([_checkpoint(updated_at=_ago(minutes=1440))])
        assert _finding(result) == (OK, 0, ())

    def test_one_microsecond_past_the_threshold_is_stale(self):
        result = _checkpoints(
            [_checkpoint(updated_at=_ago(minutes=1440) - _US)],
        )
        assert _finding(result) == (VIOLATION, 1, (_GROUP_ID,))
        assert result.finding.detail == "1 violation(s); showing 1 of 1."

    def test_future_updated_at_is_fresh(self):
        result = _checkpoints([_checkpoint(updated_at=_T0 + timedelta(days=3))])
        assert _finding(result) == (OK, 0, ())

    def test_missing_checkpoint_is_a_violation(self):
        assert _finding(_checkpoints([])) == (VIOLATION, 1, (_GROUP_ID,))

    def test_threshold_setting_is_used(self):
        row = _checkpoint(updated_at=_ago(minutes=30))
        assert _checkpoints([row], max_age=30).finding.status is OK
        assert _checkpoints([row], max_age=29).finding.status is VIOLATION

    def test_other_time_zones_are_normalised(self):
        zone = timezone(timedelta(hours=5, minutes=30))
        row = _checkpoint(updated_at=_ago(minutes=1440).astimezone(zone))
        now = _T0.astimezone(timezone(timedelta(hours=-8)))
        assert _checkpoints([row], now=now).finding.status is OK
        assert _checkpoints([row], now=now + _US).finding.status is VIOLATION

    def test_multiple_expected_groups(self):
        fresh = ("trace_latency", "svc", "op-fresh")
        stale = ("trace_latency", "svc", "op-stale")
        missing = ("tool_failure", "svc", "")
        rows = [
            _checkpoint(fresh, _ago(hours=1)),
            _checkpoint(stale, _ago(days=3)),
        ]
        result = _checkpoints(rows, expected=(fresh, stale, missing))
        assert _finding(result) == (VIOLATION, 2, (
            '["tool_failure","svc",""]',
            '["trace_latency","svc","op-stale"]',
        ))

    def test_unexpected_database_rows_are_ignored(self):
        rows = [
            _checkpoint(updated_at=_ago(hours=1)),
            _checkpoint(("retired_signal", "old-svc", ""), _ago(days=900)),
            _checkpoint(("trace_latency", "agentops-demo-app", "other.op"), _ago(days=900)),
        ]
        assert _finding(_checkpoints(rows)) == (OK, 0, ())

    def test_match_is_exact_on_all_three_parts(self):
        rows = [
            _checkpoint(("trace_latency", "agentops-demo-app", ""), _T0),
            _checkpoint(("trace_latency", "agentops-demo-app", "agentops.request "), _T0),
            _checkpoint(("Trace_latency", "agentops-demo-app", "agentops.request"), _T0),
        ]
        assert _finding(_checkpoints(rows)) == (VIOLATION, 1, (_GROUP_ID,))

    def test_identifier_is_compact_ascii_json_and_unambiguous(self):
        tricky = [("a,b", "c", ""), ("a", "b,c", ""), ("a", "b", "c d/e\"f"),
                  ("a", "café\n", "")]
        result = _checkpoints([], expected=tricky)
        assert result.detail_ids == (
            '["a","b","c d/e\\"f"]',
            '["a","b,c",""]',
            '["a","caf\\u00e9\\n",""]',
            '["a,b","c",""]',
        )
        assert [tuple(json.loads(item)) for item in result.detail_ids] == sorted(tricky)
        assert all(item.isascii() and "\n" not in item for item in result.detail_ids)

    def test_identifiers_come_from_the_configuration_not_from_rows(self):
        rows = [_checkpoint(("PRIVATE-ROW-VALUE", "x", ""), _ago(days=900))]
        result = _checkpoints(rows)
        assert "PRIVATE" not in repr(result)

    def test_order_does_not_depend_on_input_order(self):
        groups = [("s2", "b", "x"), ("s1", "b", "y"), ("s1", "a", "z"), ("s1", "b", "")]
        expected_ids = (
            '["s1","a","z"]', '["s1","b",""]', '["s1","b","y"]', '["s2","b","x"]',
        )
        for seed in range(5):
            shuffled = list(groups)
            random.Random(seed).shuffle(shuffled)
            assert _checkpoints([], expected=shuffled).detail_ids == expected_ids

    def test_repeated_expected_group_is_counted_once(self):
        assert _checkpoints([], expected=(_GROUP, _GROUP)).finding.count == 1

    def test_more_than_twenty(self):
        groups = [("signal", "svc", f"op-{i:03d}") for i in range(45)]
        result = _checkpoints([], expected=list(reversed(groups)))
        assert result.finding.count == 45
        assert result.finding.detail == "45 violation(s); showing 20 of 45."
        assert result.detail_ids == tuple(
            f'["signal","svc","op-{i:03d}"]' for i in range(20)
        )

    def test_unrepresentable_threshold_means_no_age_violation(self):
        huge = 10 ** 18
        stale_by_any_measure = [_checkpoint(updated_at=_ago(days=50000))]
        assert _checkpoints(stale_by_any_measure, max_age=huge).finding.status is OK
        assert _checkpoints([], max_age=huge).finding.status is VIOLATION

    @pytest.mark.parametrize("override", [
        {"updated_at": datetime(2026, 10, 5, 19, 0)},
        {"updated_at": "2026-10-05T19:00:00Z"},
        {"updated_at": None},
        {"signal_path": None},
        {"service_name": 5},
        {"operation_name": None},
    ])
    def test_malformed_row_fails_closed(self, override):
        rows = [{**_checkpoint(), **override}]
        with pytest.raises(GuardrailEvaluationError) as excinfo:
            _checkpoints(rows)
        assert excinfo.value.guardrail_codes == ("detector_checkpoint_stale",)
        assert excinfo.value.reason_code == "invalid_checkpoint_data"

    def test_malformed_unexpected_row_also_fails_closed(self):
        rows = [_checkpoint(), {**_checkpoint(("x", "y", "z")), "updated_at": None}]
        with pytest.raises(GuardrailEvaluationError):
            _checkpoints(rows)

    def test_duplicate_group_rows_fail_closed(self):
        with pytest.raises(GuardrailEvaluationError) as excinfo:
            _checkpoints([_checkpoint(), _checkpoint(updated_at=_ago(days=9))])
        assert excinfo.value.reason_code == "invalid_checkpoint_data"

    @pytest.mark.parametrize("now", [datetime(2026, 10, 5, 19, 0), None, "now"])
    def test_invalid_now_is_a_value_error(self, now):
        with pytest.raises(ValueError):
            _checkpoints([_checkpoint()], now=now)

    @pytest.mark.parametrize("expected", [
        (), [], None, "abc", [("a", "b")], [("a", "b", None)], [["a", "b", 3]],
    ])
    def test_unusable_expected_groups_are_a_value_error(self, expected):
        with pytest.raises(ValueError):
            _checkpoints([], expected=expected)


# ---------------------------------------------------------------------------
# GR05  uninvestigated_anomalies
# ---------------------------------------------------------------------------

def _anomalies(rows, *, now=_T0, max_age=60) -> GuardrailResult:
    return evaluate_uninvestigated(rows, now=now, max_age_minutes=max_age)


class TestUninvestigated:

    def test_young_anomaly_is_not_a_violation(self):
        result = _anomalies([_anomaly_row(1, _ago(minutes=5))])
        assert result.finding.code == "uninvestigated_anomalies"
        assert _finding(result) == (OK, 0, ())

    def test_exactly_at_the_threshold_is_not_a_violation(self):
        assert _finding(_anomalies([_anomaly_row(1, _ago(minutes=60))])) == (OK, 0, ())

    def test_one_microsecond_past_the_threshold_is_a_violation(self):
        result = _anomalies([_anomaly_row(1, _ago(minutes=60) - _US)])
        assert _finding(result) == (VIOLATION, 1, (_anomaly(1),))

    def test_future_detected_at_is_not_a_violation(self):
        assert _finding(
            _anomalies([_anomaly_row(1, _T0 + timedelta(hours=5))]),
        ) == (OK, 0, ())

    def test_no_rows(self):
        assert _finding(_anomalies([])) == (OK, 0, ())

    def test_threshold_setting_is_used(self):
        row = _anomaly_row(1, _ago(minutes=10))
        assert _anomalies([row], max_age=10).finding.status is OK
        assert _anomalies([row], max_age=9).finding.status is VIOLATION

    def test_only_what_the_store_returns_is_judged(self):
        # Investigated anomalies never reach the evaluation: the store's
        # statement excludes them, whatever the investigation's confidence.
        sql = alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES
        assert "NOT EXISTS" in sql and "confidence" not in sql
        parameters = inspect.signature(evaluate_uninvestigated).parameters
        assert list(parameters) == ["rows", "now", "max_age_minutes"]

    def test_order_is_detected_at_then_anomaly_id(self):
        rows = [
            _anomaly_row(1, _ago(hours=2)),
            _anomaly_row(2, _ago(hours=9)),
            _anomaly_row(3, _ago(hours=5)),
            _anomaly_row(4, _ago(hours=5)),
            _anomaly_row(5, _ago(minutes=1)),
        ]
        tied = sorted([_anomaly(3), _anomaly(4)])
        expected = (_anomaly(2), tied[0], tied[1], _anomaly(1))
        for seed in range(5):
            shuffled = list(rows)
            random.Random(seed).shuffle(shuffled)
            assert _anomalies(shuffled).detail_ids == expected
        assert _anomalies(rows).finding.count == 4

    def test_more_than_twenty_shows_the_oldest(self):
        rows = [_anomaly_row(n, _ago(hours=2, minutes=n)) for n in range(33)]
        result = _anomalies(rows)
        assert result.finding.count == 33
        assert result.finding.detail == "33 violation(s); showing 20 of 33."
        assert result.detail_ids == tuple(_anomaly(n) for n in range(32, 12, -1))

    def test_unrepresentable_threshold_means_no_violation(self):
        rows = [_anomaly_row(1, _ago(days=50000))]
        assert _anomalies(rows, max_age=10 ** 18).finding.status is OK

    @pytest.mark.parametrize("override", [
        {"anomaly_id": "not-a-digest"},
        {"anomaly_id": "A" * 64},
        {"anomaly_id": None},
        {"anomaly_id": 7},
        {"detected_at": datetime(2026, 10, 5, 18, 0)},
        {"detected_at": "2026-10-05"},
        {"detected_at": None},
    ])
    def test_malformed_row_fails_closed(self, override):
        rows = [{**_anomaly_row(1, _ago(minutes=5)), **override}]
        with pytest.raises(GuardrailEvaluationError) as excinfo:
            _anomalies(rows)
        assert excinfo.value.guardrail_codes == ("uninvestigated_anomalies",)
        assert excinfo.value.reason_code == "invalid_anomaly_data"

    def test_malformed_young_row_still_fails_closed(self):
        rows = [_anomaly_row(1, _ago(hours=5)), {"anomaly_id": "x", "detected_at": _T0}]
        with pytest.raises(GuardrailEvaluationError):
            _anomalies(rows)

    def test_duplicate_anomaly_fails_closed(self):
        rows = [_anomaly_row(1, _ago(hours=5)), _anomaly_row(1, _ago(hours=6))]
        with pytest.raises(GuardrailEvaluationError) as excinfo:
            _anomalies(rows)
        assert excinfo.value.reason_code == "invalid_anomaly_data"

    def test_invalid_now_is_a_value_error(self):
        with pytest.raises(ValueError):
            _anomalies([], now=datetime(2026, 10, 5, 19, 0))


# ---------------------------------------------------------------------------
# GR06  Delivery states
# ---------------------------------------------------------------------------

R, P, U, SENT = "FAILED_RETRYABLE", "FAILED_PERMANENT", "UNCERTAIN", "SENT"


class TestDeliveryStates:

    def _both(self, history, decision=None, **kwargs) -> tuple:
        uncertain, exhausted = _deliveries([decision or _decision(1)], history, **kwargs)
        assert uncertain.finding.code == "delivery_uncertain"
        assert exhausted.finding.code == "delivery_exhausted"
        return _finding(uncertain), _finding(exhausted)

    def test_never_attempted_recent_decision(self):
        assert self._both([]) == ((OK, 0, ()), (OK, 0, ()))

    def test_sent(self):
        assert self._both(_history(1, "log", SENT)) == ((OK, 0, ()), (OK, 0, ()))

    def test_in_flight(self):
        history = _history(1, "log", None, started=_ago(seconds=5))
        assert self._both(history) == ((OK, 0, ()), (OK, 0, ()))

    def test_retryable(self):
        assert self._both(_history(1, "log", R)) == ((OK, 0, ()), (OK, 0, ()))
        assert self._both(_history(1, "log", R, R)) == ((OK, 0, ()), (OK, 0, ()))

    def test_uncertain_explicit(self):
        assert self._both(_history(1, "log", U)) == (
            (VIOLATION, 1, (_pair(1),)), (OK, 0, ()),
        )

    def test_uncertain_from_a_missing_outcome_past_the_limit(self):
        history = _history(1, "log", None, started=_ago(seconds=41))
        assert self._both(history) == ((VIOLATION, 1, (_pair(1),)), (OK, 0, ()))

    def test_missing_outcome_exactly_at_the_limit_is_still_in_flight(self):
        history = _history(1, "log", None, started=_ago(seconds=40))
        assert self._both(history) == ((OK, 0, ()), (OK, 0, ()))

    def test_exhausted(self):
        assert self._both(_history(1, "log", R, R, R)) == (
            (OK, 0, ()), (VIOLATION, 1, (_pair(1),)),
        )

    def test_permanently_failed(self):
        assert self._both(_history(1, "log", P)) == (
            (OK, 0, ()), (VIOLATION, 1, (_pair(1),)),
        )

    def test_expired_never_attempted(self):
        decision = _decision(1, _ago(minutes=61))
        assert self._both([], decision) == ((OK, 0, ()), (VIOLATION, 1, (_pair(1),)))

    def test_expired_retryable(self):
        decision = _decision(1, _ago(hours=2))
        history = _history(1, "log", R, started=_ago(minutes=90))
        assert self._both(history, decision) == (
            (OK, 0, ()), (VIOLATION, 1, (_pair(1),)),
        )

    def test_not_yet_expired_at_exactly_the_delivery_age(self):
        decision = _decision(1, _ago(minutes=60))
        assert self._both([], decision) == ((OK, 0, ()), (OK, 0, ()))

    @pytest.mark.parametrize("earlier", [U, R, P, None])
    def test_superseded_by_sent_is_not_reported(self, earlier):
        history = [
            _attempt(1, "log", 1, earlier, started=_ago(hours=3)),
            _attempt(1, "log", 2, SENT),
        ]
        assert self._both(history) == ((OK, 0, ()), (OK, 0, ()))

    def test_sent_followed_by_a_later_failure_is_still_sent(self):
        assert self._both(_history(1, "log", SENT, P)) == ((OK, 0, ()), (OK, 0, ()))

    def test_uncertain_then_permanent_failure_moves_to_exhausted(self):
        assert self._both(_history(1, "log", U, P)) == (
            (OK, 0, ()), (VIOLATION, 1, (_pair(1),)),
        )

    def test_a_pair_is_never_in_both_findings(self):
        decisions = [_decision(n) for n in range(6)]
        history = (
            _history(0, "log", U) + _history(1, "log", P) + _history(2, "log", R, R, R)
            + _history(3, "log", SENT) + _history(4, "log", R)
        )
        uncertain, exhausted = _deliveries(decisions, history)
        assert set(uncertain.detail_ids) == {_pair(0)}
        assert set(exhausted.detail_ids) == {_pair(1), _pair(2)}
        assert not set(uncertain.detail_ids) & set(exhausted.detail_ids)

    def test_no_decisions(self):
        uncertain, exhausted = _deliveries([], [])
        assert (_finding(uncertain), _finding(exhausted)) == ((OK, 0, ()), (OK, 0, ()))

    def test_several_channels_each_have_their_own_state(self):
        channels = [_channel("log"), _channel("file"), _channel("hook")]
        history = (
            _history(1, "log", SENT) + _history(1, "file", U) + _history(1, "hook", P)
        )
        uncertain, exhausted = _deliveries([_decision(1)], history, channels)
        assert uncertain.detail_ids == (_pair(1, "file"),)
        assert exhausted.detail_ids == (_pair(1, "hook"),)


# ---------------------------------------------------------------------------
# GR07  Delivery lookback
# ---------------------------------------------------------------------------

_START = _T0 - timedelta(hours=24)


class TestLookback:

    def _exhausted(self, decision, history=()) -> tuple:
        _, exhausted = _deliveries([decision], list(history))
        return exhausted.detail_ids

    def test_never_attempted_pair_enters_through_evaluated_at(self):
        assert self._exhausted(_decision(1, _ago(hours=2))) == (_pair(1),)

    def test_decision_exactly_at_the_lookback_start_is_included(self):
        assert self._exhausted(_decision(1, _START)) == (_pair(1),)

    def test_decision_one_microsecond_before_the_start_is_excluded(self):
        assert self._exhausted(_decision(1, _START - _US)) == ()

    def test_old_decision_with_a_recent_attempt_is_included(self):
        history = _history(1, "log", P, started=_ago(hours=1))
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == (_pair(1),)

    def test_old_decision_with_an_old_attempt_is_excluded(self):
        history = _history(1, "log", P, started=_ago(hours=30))
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == ()

    def test_latest_attempt_exactly_at_the_start_is_included(self):
        history = _history(1, "log", P, started=_START)
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == (_pair(1),)

    def test_latest_attempt_one_microsecond_before_the_start_is_excluded(self):
        history = _history(1, "log", P, started=_START - _US)
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == ()

    def test_the_latest_attempt_decides_not_any_attempt(self):
        # Attempt 1 is recent, attempt 2 (the latest by number) is old.
        history = [
            _attempt(1, "log", 1, R, started=_ago(hours=1)),
            _attempt(1, "log", 2, P, started=_ago(hours=30)),
        ]
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == ()
        # The other way round: the latest attempt is the recent one.
        history = [
            _attempt(1, "log", 1, R, started=_ago(hours=30)),
            _attempt(1, "log", 2, P, started=_ago(hours=1)),
        ]
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == (_pair(1),)

    def test_outcome_recorded_at_is_not_used(self):
        row = _attempt(1, "log", 1, P, started=_ago(hours=30))
        row["recorded_at"] = _ago(minutes=1)
        assert self._exhausted(_decision(1, _ago(hours=48)), [row]) == ()

    def test_future_decision_is_included(self):
        decision = _decision(1, _T0 + timedelta(hours=3))
        history = _history(1, "log", P)
        assert self._exhausted(decision, history) == (_pair(1),)

    def test_future_latest_attempt_is_included(self):
        history = _history(1, "log", P, started=_T0 + timedelta(hours=3))
        assert self._exhausted(_decision(1, _ago(hours=48)), history) == (_pair(1),)

    def test_old_never_attempted_decision_is_excluded(self):
        assert self._exhausted(_decision(1, _ago(hours=48))) == ()

    def test_lookback_is_per_pair(self):
        channels = [_channel("log"), _channel("file")]
        history = (
            _history(1, "log", P, started=_ago(hours=1))
            + _history(1, "file", P, started=_ago(hours=30))
        )
        _, exhausted = _deliveries([_decision(1, _ago(hours=48))], history, channels)
        assert exhausted.detail_ids == (_pair(1, "log"),)

    def test_uncertain_uses_the_same_lookback(self):
        recent = _history(1, "log", U, started=_ago(hours=1))
        old = _history(2, "log", U, started=_ago(hours=30))
        decisions = [_decision(1, _ago(hours=48)), _decision(2, _ago(hours=48))]
        uncertain, _ = _deliveries(decisions, recent + old)
        assert uncertain.detail_ids == (_pair(1),)

    def test_lookback_setting_is_used(self):
        decision = _decision(1, _ago(hours=5))
        _, wide = _deliveries([decision], [], lookback_hours=5)
        _, narrow = _deliveries([decision], [], lookback_hours=4)
        assert wide.detail_ids == (_pair(1),) and narrow.detail_ids == ()

    def test_unrepresentable_lookback_covers_everything(self):
        decision = _decision(1, _ago(days=40000))
        _, exhausted = _deliveries([decision], [], lookback_hours=10 ** 15)
        assert exhausted.detail_ids == (_pair(1),)

    def test_other_time_zones_are_normalised(self):
        zone = timezone(timedelta(hours=-7))
        decision = _decision(1, _START.astimezone(zone))
        now = _T0.astimezone(timezone(timedelta(hours=9)))
        _, at_start = _deliveries([decision], [], now=now)
        _, past = _deliveries([decision], [], now=now + _US)
        assert at_start.detail_ids == (_pair(1),) and past.detail_ids == ()


# ---------------------------------------------------------------------------
# GR08  Channel scope and current settings
# ---------------------------------------------------------------------------

class TestChannelScope:

    def test_disabled_channel_is_not_evaluated(self):
        channels = [_channel("log", enabled=False), _channel("file")]
        history = _history(1, "log", P) + _history(1, "file", SENT)
        uncertain, exhausted = _deliveries([_decision(1)], history, channels)
        assert (uncertain.finding.count, exhausted.finding.count) == (0, 0)

    def test_disabled_channel_does_not_expire_alerts(self):
        channels = [_channel("log", enabled=False)]
        _, exhausted = _deliveries([_decision(1, _ago(hours=5))], [], channels)
        assert _finding(exhausted) == (OK, 0, ())

    def test_removed_channel_history_is_ignored(self):
        history = _history(1, "removed-channel", P) + _history(1, "log", SENT)
        uncertain, exhausted = _deliveries([_decision(1)], history)
        assert (uncertain.finding.count, exhausted.finding.count) == (0, 0)

    def test_malformed_history_of_a_channel_out_of_scope_is_not_read(self):
        bad = _attempt(1, "removed-channel", 7, "NOT-AN-OUTCOME")
        uncertain, exhausted = _deliveries([_decision(1)], [bad])
        assert (uncertain.finding.count, exhausted.finding.count) == (0, 0)

    def test_no_enabled_channel(self):
        uncertain, exhausted = _deliveries(
            [_decision(1, _ago(hours=5))], _history(1, "log", U), channels=[],
        )
        assert (_finding(uncertain), _finding(exhausted)) == ((OK, 0, ()), (OK, 0, ()))

    def test_current_max_attempts_decides_retryable_or_exhausted(self):
        history = _history(1, "log", R, R)
        _, with_three = _deliveries([_decision(1)], history, [_channel(max_attempts=3)])
        _, with_two = _deliveries([_decision(1)], history, [_channel(max_attempts=2)])
        assert with_three.detail_ids == ()
        assert with_two.detail_ids == (_pair(1),)

    def test_current_timeout_decides_in_flight_or_uncertain(self):
        history = _history(1, "log", None, started=_ago(seconds=50))
        long, _ = _deliveries([_decision(1)], history, [_channel(timeout_seconds=30)])
        short, _ = _deliveries([_decision(1)], history, [_channel(timeout_seconds=10)])
        assert long.detail_ids == () and short.detail_ids == (_pair(1),)

    def test_current_delivery_age_decides_expiry(self):
        decision = _decision(1, _ago(minutes=30))
        _, lenient = _deliveries([decision], [], max_age=30)
        _, strict = _deliveries([decision], [], max_age=29)
        assert lenient.detail_ids == () and strict.detail_ids == (_pair(1),)

    def test_settings_are_per_channel(self):
        channels = [_channel("strict", max_attempts=1), _channel("lenient", max_attempts=5)]
        history = _history(1, "strict", R) + _history(1, "lenient", R)
        _, exhausted = _deliveries([_decision(1)], history, channels)
        assert exhausted.detail_ids == (_pair(1, "strict"),)

    def test_no_setting_is_invented_for_a_missing_channel(self):
        source = inspect.getsource(alert_guardrails.evaluate_deliveries)
        assert "DEFAULT_" not in source
        assert "max_attempts=channel.max_attempts" in source
        assert "timeout_seconds=channel.timeout_seconds" in source
        assert "max_delivery_age_minutes=delivery.max_delivery_age_minutes" in source


# ---------------------------------------------------------------------------
# GR09  Delivery data that cannot be evaluated
# ---------------------------------------------------------------------------

def _assert_delivery_error(decisions, history, channels=None):
    with pytest.raises(GuardrailEvaluationError) as excinfo:
        _deliveries(decisions, history, channels)
    assert excinfo.value.guardrail_codes == ("delivery_uncertain", "delivery_exhausted")
    assert excinfo.value.reason_code == "invalid_delivery_data"
    assert excinfo.value.__cause__ is None
    return excinfo.value


class TestInvalidDeliveryData:

    @pytest.mark.parametrize("override", [
        {"decision_id": "not-a-digest"},
        {"decision_id": None},
        {"decision_id": "D" * 64},
        {"evaluated_at": datetime(2026, 10, 5, 18, 0)},
        {"evaluated_at": "2026-10-05T18:00:00Z"},
        {"evaluated_at": None},
    ])
    def test_malformed_decision(self, override):
        _assert_delivery_error([{**_decision(1), **override}], [])

    def test_duplicate_decision(self):
        _assert_delivery_error([_decision(1), _decision(1, _ago(hours=1))], [])

    def test_gap_in_attempt_numbers(self):
        _assert_delivery_error([_decision(1)], [_attempt(1, "log", 2, R)])

    def test_repeated_attempt_number(self):
        _assert_delivery_error(
            [_decision(1)], [_attempt(1, "log", 1, R), _attempt(1, "log", 1, P)],
        )

    def test_attempt_with_a_foreign_identity(self):
        row = _attempt(1, "log", 1, R, attempt_id=compute_attempt_id(_dec(1), "log", 9))
        _assert_delivery_error([_decision(1)], [row])

    @pytest.mark.parametrize("field, value", [
        ("channel_type", "pager"),
        ("trigger", "cron"),
        ("attempt_no", 0),
        ("attempt_no", "1"),
        ("summary_included", "no"),
        ("payload_sha256", "short"),
        ("attempt_id", "short"),
        ("started_at", datetime(2026, 10, 5, 18, 0)),
        ("started_at", None),
        ("outcome", "DELIVERED"),
        ("outcome", ""),
        ("recorded_at", None),
        ("recorded_at", datetime(2026, 10, 5, 18, 0)),
        ("channel_type", ["log"]),
    ])
    def test_malformed_history_row(self, field, value):
        row = _attempt(1, "log", 1, R)
        row[field] = value
        _assert_delivery_error([_decision(1)], [row])

    def test_error_carries_no_stored_value(self):
        row = _attempt(1, "log", 1, "PRIVATE-OUTCOME-TEXT")
        error = _assert_delivery_error([_decision(1)], [row])
        assert "PRIVATE" not in str(error) and "PRIVATE" not in repr(error)
        assert str(error) == "delivery_uncertain,delivery_exhausted: invalid_delivery_data"

    def test_malformed_pair_fails_even_outside_the_lookback(self):
        # The decision is read; its history is validated before the lookback
        # test, so an old malformed pair is not silently skipped.
        row = _attempt(1, "log", 3, P, started=_ago(hours=40))
        _assert_delivery_error([_decision(1, _ago(hours=48))], [row])

    def test_one_bad_pair_fails_the_whole_evaluation(self):
        decisions = [_decision(1), _decision(2)]
        history = _history(1, "log", U) + [_attempt(2, "log", 2, R)]
        _assert_delivery_error(decisions, history)

    def test_sent_never_masks_an_invalid_history(self):
        history = [_attempt(1, "log", 1, SENT), _attempt(1, "log", 3, R)]
        _assert_delivery_error([_decision(1)], history)

    def test_invalid_now_is_a_value_error_not_an_evaluation_error(self):
        with pytest.raises(ValueError):
            _deliveries([_decision(1)], [], now=datetime(2026, 10, 5, 19, 0))


# ---------------------------------------------------------------------------
# GR10  Order and cap
# ---------------------------------------------------------------------------

class TestOrderAndCap:

    def test_order_is_evaluated_at_then_decision_then_channel(self):
        channels = [_channel("zeta"), _channel("alpha")]
        times = {1: _ago(hours=3), 2: _ago(hours=9), 3: _ago(hours=3), 4: _ago(hours=1)}
        decisions = [_decision(n, when) for n, when in times.items()]
        history = [
            row for n in times for channel in ("zeta", "alpha")
            for row in _history(n, channel, P)
        ]
        tied = sorted([_dec(1), _dec(3)])
        expected = tuple(
            f"{decision_id}/{channel}"
            for decision_id in (_dec(2), tied[0], tied[1], _dec(4))
            for channel in ("alpha", "zeta")
        )
        for seed in range(5):
            rng = random.Random(seed)
            shuffled_decisions, shuffled_history = list(decisions), list(history)
            rng.shuffle(shuffled_decisions)
            rng.shuffle(shuffled_history)
            _, exhausted = _deliveries(
                shuffled_decisions,
                sorted(shuffled_history, key=lambda r: (r["decision_id"],
                                                        r["channel_name"],
                                                        rng.random())),
                list(reversed(channels)) if seed % 2 else channels,
            )
            assert exhausted.detail_ids == expected
            assert exhausted.finding.count == 8

    def test_more_than_twenty(self):
        decisions = [_decision(n, _ago(minutes=100 + n)) for n in range(27)]
        history = [row for n in range(27) for row in _history(n, "log", U)]
        uncertain, exhausted = _deliveries(decisions, history)
        assert uncertain.finding.count == 27
        assert uncertain.finding.detail == "27 violation(s); showing 20 of 27."
        assert uncertain.detail_ids == tuple(_pair(n) for n in range(26, 6, -1))
        assert _finding(exhausted) == (OK, 0, ())

    def test_exactly_twenty(self):
        decisions = [_decision(n, _ago(minutes=100 + n)) for n in range(20)]
        history = [row for n in range(20) for row in _history(n, "log", P)]
        _, exhausted = _deliveries(decisions, history)
        assert exhausted.finding.count == 20 and len(exhausted.detail_ids) == 20
        assert exhausted.finding.detail == "20 violation(s); showing 20 of 20."

    def test_identifier_shape(self):
        _, exhausted = _deliveries([_decision(1)], _history(1, "log", P))
        (identifier,) = exhausted.detail_ids
        decision_id, channel = identifier.split("/")
        assert (decision_id, channel) == (_dec(1), "log")
        assert identifier.count("/") == 1 and len(decision_id) == 64


# ---------------------------------------------------------------------------
# GR11  Delivery state is the Phase 13.5 function
# ---------------------------------------------------------------------------

class TestStateReuse:

    def test_the_public_phase_13_5_objects_are_used(self):
        assert alert_guardrails.derive_state is alert_delivery_state.derive_state
        assert alert_guardrails.DeliveryState is alert_delivery_state.DeliveryState

    @pytest.mark.parametrize("forced, uncertain_count, exhausted_count", [
        (S.SENT, 0, 0),
        (S.NEVER_ATTEMPTED, 0, 0),
        (S.IN_FLIGHT, 0, 0),
        (S.RETRYABLE, 0, 0),
        (S.UNCERTAIN, 2, 0),
        (S.EXHAUSTED, 0, 2),
        (S.PERMANENTLY_FAILED, 0, 2),
        (S.EXPIRED, 0, 2),
    ])
    def test_findings_follow_whatever_derive_state_returns(
        self, monkeypatch, forced, uncertain_count, exhausted_count,
    ):
        monkeypatch.setattr(alert_guardrails, "derive_state", lambda *a, **k: forced)
        decisions = [_decision(1), _decision(2)]
        history = _history(1, "log", SENT) + _history(2, "log", P)
        uncertain, exhausted = _deliveries(decisions, history)
        assert (uncertain.finding.count, exhausted.finding.count) == (
            uncertain_count, exhausted_count,
        )

    def test_derive_state_receives_the_frozen_arguments(self, monkeypatch):
        calls = []

        def spy(attempts, outcomes, **kwargs):
            calls.append((attempts, outcomes, kwargs))
            return S.SENT

        monkeypatch.setattr(alert_guardrails, "derive_state", spy)
        channel = _channel("log", max_attempts=4, timeout_seconds=17)
        decision = _decision(1, _ago(minutes=7))
        _deliveries([decision], _history(1, "log", R, None), [channel], max_age=45)

        ((attempts, outcomes, kwargs),) = calls
        assert [a.attempt_no for a in attempts] == [1, 2]
        assert [o.outcome.value for o in outcomes] == ["FAILED_RETRYABLE"]
        assert all(o.detail is None for o in outcomes)
        assert kwargs == {
            "evaluated_at": _ago(minutes=7),
            "now": _T0,
            "max_attempts": 4,
            "timeout_seconds": 17,
            "max_delivery_age_minutes": 45,
            "decision_id": _dec(1),
            "channel_name": "log",
        }

    def test_called_once_per_decision_and_enabled_channel(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            alert_guardrails, "derive_state",
            lambda *a, **k: calls.append((k["decision_id"], k["channel_name"])) or S.SENT,
        )
        channels = [_channel("a"), _channel("b", enabled=False), _channel("c")]
        _deliveries([_decision(1), _decision(2)], [], channels)
        assert sorted(calls) == sorted(
            (_dec(n), name) for n in (1, 2) for name in ("a", "c")
        )

    def test_locked_delivery_models_are_used(self):
        import alert_models
        assert alert_guardrails.DeliveryAttempt is alert_models.DeliveryAttempt
        assert alert_guardrails.DeliveryOutcomeRecord is alert_models.DeliveryOutcomeRecord

    def test_no_state_rule_is_written_in_this_module(self):
        tree = ast.parse(inspect.getsource(alert_guardrails))
        outcome_members = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "DeliveryOutcome"
        }
        assert outcome_members == set()
        state_members = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "DeliveryState"
        }
        assert state_members == {
            "UNCERTAIN", "EXHAUSTED", "PERMANENTLY_FAILED", "EXPIRED",
        }
        source = inspect.getsource(alert_guardrails)
        for word in ("IN_FLIGHT_GRACE", "FAILED_RETRYABLE", "FAILED_PERMANENT",
                     "timedelta(seconds", "alert_notifier", "_pair_state", "_records"):
            assert word not in source, word


# ---------------------------------------------------------------------------
# GR12  run_guardrails
# ---------------------------------------------------------------------------

class FakeStore:
    """Recording stand-in for alert_guardrail_store."""

    def __init__(self) -> None:
        self.checkpoints: list[dict] = []
        self.anomalies: list[dict] = []
        self.decisions: list[dict] = []
        self.history: list[dict] = []
        self.calls: list[tuple] = []
        self.errors: dict[str, BaseException] = {}

    def _call(self, name: str, conn, **kwargs) -> None:
        self.calls.append((name, conn, kwargs))
        if name in self.errors:
            raise self.errors[name]

    def fetch_checkpoints(self, conn):
        self._call("fetch_checkpoints", conn)
        return list(self.checkpoints)

    def fetch_uninvestigated_anomalies(self, conn):
        self._call("fetch_uninvestigated_anomalies", conn)
        return list(self.anomalies)

    def fetch_alert_decisions(self, conn, *, lookback_start):
        self._call("fetch_alert_decisions", conn, lookback_start=lookback_start)
        return list(self.decisions)

    def fetch_delivery_history(self, conn, *, decision_ids, channel_names):
        self._call(
            "fetch_delivery_history", conn,
            decision_ids=list(decision_ids), channel_names=list(channel_names),
        )
        return list(self.history)

    def names(self) -> list[str]:
        return [call[0] for call in self.calls]


_STORE_FUNCTIONS = (
    "fetch_checkpoints", "fetch_uninvestigated_anomalies",
    "fetch_alert_decisions", "fetch_delivery_history",
)


@pytest.fixture
def store(monkeypatch) -> FakeStore:
    fake = FakeStore()
    for name in _STORE_FUNCTIONS:
        monkeypatch.setattr(alert_guardrail_store, name, getattr(fake, name))
    return fake


class _Untouchable:
    """A connection the guardrails must hand to the store and never use."""

    def __getattr__(self, name):
        raise AssertionError(f"the connection must not be used: {name}")


def _run(store, policy=None, expected=(_GROUP,), now=_T0, conn=None):
    return run_guardrails(
        conn if conn is not None else _Untouchable(),
        policy=policy if policy is not None else _policy(),
        expected_groups=expected,
        now=now,
    )


class TestRunGuardrails:

    def test_four_results_in_fixed_order_when_all_is_well(self, store):
        store.checkpoints = [_checkpoint(updated_at=_ago(hours=1))]
        results = _run(store)
        assert type(results) is tuple and len(results) == 4
        assert [r.finding.code for r in results] == list(GUARDRAIL_CODES)
        assert all(_finding(r) == (OK, 0, ()) for r in results)

    def test_all_four_can_be_violated_at_once(self, store):
        store.anomalies = [_anomaly_row(1, _ago(hours=3))]
        store.decisions = [_decision(1), _decision(2)]
        store.history = _history(1, "log", U) + _history(2, "log", P)
        results = _run(store)
        assert [(r.finding.code, r.finding.status, r.detail_ids) for r in results] == [
            ("detector_checkpoint_stale", VIOLATION, (_GROUP_ID,)),
            ("uninvestigated_anomalies", VIOLATION, (_anomaly(1),)),
            ("delivery_uncertain", VIOLATION, (_pair(1),)),
            ("delivery_exhausted", VIOLATION, (_pair(2),)),
        ]

    def test_store_reads_and_their_arguments(self, store):
        store.checkpoints = [_checkpoint()]
        store.decisions = [_decision(1), _decision(2)]
        conn = _Untouchable()
        policy = _policy([
            {"name": "off", "type": "log", "enabled": False},
            {"name": "zeta", "type": "log", "enabled": True},
            {"name": "alpha", "type": "log", "enabled": True},
        ])
        _run(store, policy, conn=conn)
        assert store.names() == list(_STORE_FUNCTIONS)
        assert all(call[1] is conn for call in store.calls)
        assert store.calls[2][2] == {"lookback_start": _T0 - timedelta(hours=24)}
        assert store.calls[3][2] == {
            "decision_ids": [_dec(1), _dec(2)],
            "channel_names": ["zeta", "alpha"],
        }

    def test_lookback_start_follows_the_policy_setting(self, store):
        _run(store, _policy(delivery_lookback_hours=6))
        assert store.calls[2][2] == {"lookback_start": _T0 - timedelta(hours=6)}

    def test_lookback_start_is_utc_for_any_now(self, store):
        local = _T0.astimezone(timezone(timedelta(hours=5, minutes=30)))
        _run(store, now=local)
        start = store.calls[2][2]["lookback_start"]
        assert start == _T0 - timedelta(hours=24) and start.tzinfo is timezone.utc

    def test_thresholds_come_from_the_policy(self, store):
        store.checkpoints = [_checkpoint(updated_at=_ago(minutes=100))]
        store.anomalies = [_anomaly_row(1, _ago(minutes=20))]
        defaults = _run(store)
        tight = _run(store, _policy(
            detector_checkpoint_max_age_minutes=99,
            uninvestigated_anomaly_max_age_minutes=19,
        ))
        assert [r.finding.status for r in defaults[:2]] == [OK, OK]
        assert [r.finding.status for r in tight[:2]] == [VIOLATION, VIOLATION]

    @pytest.mark.parametrize("channels", [
        [],
        [{"name": "log", "type": "log", "enabled": False}],
    ])
    def test_zero_enabled_channels_skips_the_delivery_reads(self, store, channels):
        store.decisions = [_decision(1, _ago(hours=5))]
        store.history = _history(1, "log", U)
        store.anomalies = [_anomaly_row(1, _ago(hours=3))]
        results = _run(store, _policy(channels))
        assert store.names() == ["fetch_checkpoints", "fetch_uninvestigated_anomalies"]
        assert [r.finding.status for r in results] == [VIOLATION, VIOLATION, OK, OK]
        assert all(r.detail_ids == () for r in results[2:])
        assert [r.finding.code for r in results] == list(GUARDRAIL_CODES)

    def test_disabled_channel_is_not_requested_from_the_store(self, store):
        policy = _policy([
            {"name": "log", "type": "log", "enabled": True},
            {"name": "hook", "type": "webhook", "enabled": False,
             "url_env": "ALERT_WEBHOOK_URL"},
        ])
        _run(store, policy)
        assert store.calls[3][2]["channel_names"] == ["log"]

    def test_decisions_of_any_policy_version_are_evaluated(self, store):
        # Decision rows carry no policy version at all: none is read.
        store.decisions = [_decision(1), _decision(2)]
        store.history = _history(1, "log", P) + _history(2, "log", P)
        assert _run(store)[3].finding.count == 2
        assert "policy_version" not in inspect.getsource(alert_guardrails)

    def test_same_now_reaches_every_check(self, store, monkeypatch):
        seen = []
        for name in ("evaluate_checkpoints", "evaluate_uninvestigated",
                     "evaluate_deliveries"):
            real = getattr(alert_guardrails, name)

            def spy(*args, _real=real, **kwargs):
                seen.append(kwargs["now"])
                return _real(*args, **kwargs)

            monkeypatch.setattr(alert_guardrails, name, spy)
        _run(store, now=_T0.astimezone(timezone(timedelta(hours=2))))
        assert seen == [_T0, _T0, _T0]
        assert all(value is seen[0] for value in seen)

    def test_connection_is_never_used_directly(self, store):
        _run(store)        # _Untouchable raises on any attribute access

    @pytest.mark.parametrize("now", [datetime(2026, 10, 5, 19, 0), None, "now", 0])
    def test_invalid_now_is_rejected_before_any_read(self, store, now):
        with pytest.raises(ValueError, match="now"):
            _run(store, now=now)
        assert store.calls == []

    def test_wrong_policy_type_is_rejected_before_any_read(self, store):
        with pytest.raises(ValueError, match="AlertPolicy"):
            _run(store, policy=_policy().guardrails)
        assert store.calls == []

    @pytest.mark.parametrize("expected", [(), None, [("a", "b")]])
    def test_unusable_expected_groups_are_rejected_before_any_read(self, store, expected):
        with pytest.raises(ValueError):
            _run(store, expected=expected)
        assert store.calls == []

    @pytest.mark.parametrize("function", _STORE_FUNCTIONS)
    def test_database_error_propagates_unchanged(self, store, function):
        error = psycopg.OperationalError("down")
        store.errors[function] = error
        store.decisions = [_decision(1)]
        with pytest.raises(psycopg.OperationalError) as excinfo:
            _run(store)
        assert excinfo.value is error

    def test_evaluation_error_returns_no_result(self, store):
        store.checkpoints = [_checkpoint(updated_at=_ago(hours=1))]
        store.decisions = [_decision(1)]
        store.history = [_attempt(1, "log", 2, R)]
        with pytest.raises(GuardrailEvaluationError):
            _run(store)

    def test_arguments_are_keyword_only(self, store):
        with pytest.raises(TypeError):
            run_guardrails(_Untouchable(), _policy(), (_GROUP,), _T0)
        parameters = inspect.signature(run_guardrails).parameters
        for name in ("policy", "expected_groups", "now"):
            assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert parameters[name].default is inspect.Parameter.empty

    def test_run_is_deterministic(self, store):
        store.anomalies = [_anomaly_row(n, _ago(hours=3, minutes=n)) for n in range(30)]
        store.decisions = [_decision(n) for n in range(5)]
        store.history = [row for n in range(5) for row in _history(n, "log", P)]
        assert _run(store) == _run(store)


# ---------------------------------------------------------------------------
# GR13  Evaluation errors
# ---------------------------------------------------------------------------

class TestEvaluationError:

    def test_fields(self):
        error = GuardrailEvaluationError(
            ("delivery_uncertain", "delivery_exhausted"), "invalid_delivery_data",
        )
        assert error.guardrail_codes == ("delivery_uncertain", "delivery_exhausted")
        assert error.reason_code == "invalid_delivery_data"
        assert str(error) == "delivery_uncertain,delivery_exhausted: invalid_delivery_data"
        assert error.args == (str(error),)

    @pytest.mark.parametrize("codes, reason", [
        ((), "invalid_delivery_data"),
        (("unknown_guardrail",), "invalid_delivery_data"),
        (("delivery_uncertain",), "something else went wrong"),
        (("delivery_uncertain",), "https://secret.example/?token=abc"),
        (("delivery_uncertain", "PRIVATE"), "invalid_delivery_data"),
    ])
    def test_only_known_codes_and_reasons_can_be_carried(self, codes, reason):
        with pytest.raises(ValueError) as excinfo:
            GuardrailEvaluationError(codes, reason)
        assert "secret" not in str(excinfo.value) and "PRIVATE" not in str(excinfo.value)

    def test_not_a_value_error_and_not_a_database_error(self):
        assert not issubclass(GuardrailEvaluationError, ValueError)
        assert not issubclass(GuardrailEvaluationError, psycopg.Error)

    def test_each_guardrail_maps_to_its_reason(self):
        with pytest.raises(GuardrailEvaluationError) as checkpoint:
            _checkpoints([{**_checkpoint(), "updated_at": None}])
        with pytest.raises(GuardrailEvaluationError) as anomaly:
            _anomalies([{"anomaly_id": "x", "detected_at": _T0}])
        with pytest.raises(GuardrailEvaluationError) as delivery:
            _deliveries([{"decision_id": "x", "evaluated_at": _T0}], [])
        assert (checkpoint.value.guardrail_codes, checkpoint.value.reason_code) == (
            ("detector_checkpoint_stale",), "invalid_checkpoint_data",
        )
        assert (anomaly.value.guardrail_codes, anomaly.value.reason_code) == (
            ("uninvestigated_anomalies",), "invalid_anomaly_data",
        )
        assert (delivery.value.guardrail_codes, delivery.value.reason_code) == (
            ("delivery_uncertain", "delivery_exhausted"), "invalid_delivery_data",
        )

    def test_underlying_errors_are_not_chained(self):
        for call in (
            lambda: _checkpoints([{**_checkpoint(), "updated_at": "PRIVATE"}]),
            lambda: _anomalies([{"anomaly_id": _anomaly(1), "detected_at": "PRIVATE"}]),
            lambda: _deliveries([{"decision_id": _dec(1), "evaluated_at": "PRIVATE"}], []),
            lambda: _deliveries([_decision(1)], [_attempt(1, "log", 1, "PRIVATE")]),
        ):
            with pytest.raises(GuardrailEvaluationError) as excinfo:
                call()
            assert excinfo.value.__cause__ is None
            assert excinfo.value.__suppress_context__ is True
            assert "PRIVATE" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# GR14  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(alert_guardrails))

    def test_imports(self, tree):
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "json", "os", "dataclasses", "datetime", "typing",
            "alert_guardrail_store", "alert_delivery_state", "alert_identity",
            "alert_models", "alert_policy",
        }

    def test_no_driver_statement_or_connection_use(self, tree):
        source = inspect.getsource(alert_guardrails)
        for word in ("psycopg", "SELECT", "INSERT", "UPDATE ", "DELETE ",
                     "ON CONFLICT", "execute(", "cursor("):
            assert word not in source, word
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "conn"
        }
        assert used == set()

    def test_store_functions_used(self, tree):
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "alert_guardrail_store"
        }
        assert used == set(_STORE_FUNCTIONS)

    def test_no_clock_environment_network_or_output(self, tree):
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes.isdisjoint({
            "now", "utcnow", "today", "time", "environ", "getenv", "commit",
            "rollback", "close", "connect", "send", "request",
        })
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert names.isdisjoint({"print", "socket", "sys", "subprocess"})

    def test_the_only_file_access_is_reading_the_detector_config(self, tree):
        opens = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "open"
        ]
        assert len(opens) == 1
        assert ast.literal_eval(opens[0].args[1]) == "rb"
        source = inspect.getsource(alert_guardrails)
        for word in ("os.remove", "os.rename", "os.mkdir", "makedirs", ".write("):
            assert word not in source, word

    def test_no_remediation_notification_or_other_component(self):
        source = inspect.getsource(alert_guardrails)
        for word in ("alert_notifier", "alert_channels", "alert_evaluator",
                     "alert_store.", "alert_delivery_store", "alert_engine",
                     "alert_db", "retry_delivery", "run_notify", "run_evaluation",
                     "embedding", "similar", "incident", "stg_telemetry",
                     "subprocess", "restart"):
            assert word not in source, word

    def test_nothing_sensitive_is_read_from_rows(self, tree):
        keys = {
            node.slice.value for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        }
        assert keys == {
            "signal_path", "service_name", "operation_name", "updated_at",
            "anomaly_id", "detected_at", "decision_id", "evaluated_at",
            "attempt_id", "channel_name", "channel_type", "attempt_no", "trigger",
            "summary_included", "payload_sha256", "started_at", "outcome",
            "recorded_at", "groups",
        }

    def test_public_names(self):
        for name in (
            "CODE_DETECTOR_CHECKPOINT_STALE", "CODE_UNINVESTIGATED_ANOMALIES",
            "CODE_DELIVERY_UNCERTAIN", "CODE_DELIVERY_EXHAUSTED",
            "GUARDRAIL_CODES", "MAX_DETAIL_IDS", "DETAIL_OK", "REASON_CODES",
            "GuardrailResult", "DetectorConfigError", "GuardrailEvaluationError",
            "parse_expected_groups", "load_expected_groups",
            "checkpoint_detail_id", "delivery_detail_id", "evaluate_checkpoints",
            "evaluate_uninvestigated", "evaluate_deliveries", "run_guardrails",
        ):
            assert hasattr(alert_guardrails, name), name


# ---------------------------------------------------------------------------
# GR15  Defective time zones and unreadable rows fail closed
# ---------------------------------------------------------------------------

class _RaisingZone(tzinfo):
    """A time zone that fails when it is asked for its offset."""

    def utcoffset(self, dt):
        raise RuntimeError("PRIVATE zone failure")

    def dst(self, dt):
        raise RuntimeError("PRIVATE zone failure")

    def tzname(self, dt):
        return "PRIVATE"


class _WrongTypeZone(tzinfo):
    """A time zone whose offset is not a duration."""

    def utcoffset(self, dt):
        return "PRIVATE"

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "PRIVATE"


class _HugeOffsetZone(tzinfo):
    """A time zone whose offset is outside what a time zone may have."""

    def utcoffset(self, dt):
        return timedelta(days=3)

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "PRIVATE"


_DEFECTIVE_ZONES = [_RaisingZone(), _WrongTypeZone(), _HugeOffsetZone()]

# A row that cannot be read as a mapping with the expected keys.
_UNREADABLE_ROWS = [None, 5, "PRIVATE", ("PRIVATE",), {}, {"PRIVATE": 1}]


def _in_zone(zone) -> datetime:
    return datetime(2026, 10, 5, 18, 0, 0, tzinfo=zone)


def _assert_error(call, codes, reason):
    with pytest.raises(GuardrailEvaluationError) as excinfo:
        call()
    error = excinfo.value
    assert error.guardrail_codes == codes
    assert error.reason_code == reason
    assert error.__cause__ is None and error.__suppress_context__ is True
    assert "PRIVATE" not in str(error) and "PRIVATE" not in repr(error)


_CHECKPOINT_ERROR = (("detector_checkpoint_stale",), "invalid_checkpoint_data")
_ANOMALY_ERROR = (("uninvestigated_anomalies",), "invalid_anomaly_data")
_DELIVERY_ERROR = (
    ("delivery_uncertain", "delivery_exhausted"), "invalid_delivery_data",
)


class TestDefectiveTimeZones:

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_checkpoint_updated_at(self, zone):
        rows = [_checkpoint(updated_at=_in_zone(zone))]
        _assert_error(lambda: _checkpoints(rows), *_CHECKPOINT_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_checkpoint_of_an_unexpected_group(self, zone):
        rows = [_checkpoint(), _checkpoint(("x", "y", "z"), _in_zone(zone))]
        _assert_error(lambda: _checkpoints(rows), *_CHECKPOINT_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_anomaly_detected_at(self, zone):
        rows = [_anomaly_row(1, _in_zone(zone))]
        _assert_error(lambda: _anomalies(rows), *_ANOMALY_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_decision_evaluated_at(self, zone):
        decisions = [_decision(1, _in_zone(zone))]
        _assert_error(lambda: _deliveries(decisions, []), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_attempt_started_at(self, zone):
        history = [_attempt(1, "log", 1, R, started=_in_zone(zone))]
        _assert_error(lambda: _deliveries([_decision(1)], history), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_outcome_recorded_at(self, zone):
        history = [_attempt(1, "log", 1, R, recorded_at=_in_zone(zone))]
        _assert_error(lambda: _deliveries([_decision(1)], history), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_now_is_a_value_error_without_the_zone_s_message(self, zone):
        for call in (
            lambda: _checkpoints([_checkpoint()], now=_in_zone(zone)),
            lambda: _anomalies([], now=_in_zone(zone)),
            lambda: _deliveries([_decision(1)], [], now=_in_zone(zone)),
        ):
            with pytest.raises(ValueError) as excinfo:
                call()
            assert "PRIVATE" not in str(excinfo.value)
            assert excinfo.value.__cause__ is None
            assert excinfo.value.__suppress_context__ is True

    @pytest.mark.parametrize("zone", _DEFECTIVE_ZONES)
    def test_run_rejects_such_a_now_before_any_read(self, store, zone):
        with pytest.raises(ValueError) as excinfo:
            _run(store, now=_in_zone(zone))
        assert "PRIVATE" not in str(excinfo.value)
        assert store.calls == []

    def test_run_maps_a_stored_defective_zone(self, store):
        store.checkpoints = [_checkpoint(updated_at=_in_zone(_RaisingZone()))]
        _assert_error(lambda: _run(store), *_CHECKPOINT_ERROR)
        assert store.names() == ["fetch_checkpoints"]

    def test_a_working_foreign_zone_is_still_accepted(self):
        plus_five = timezone(timedelta(hours=5))
        rows = [_checkpoint(updated_at=_T0.astimezone(plus_five))]
        assert _checkpoints(rows).finding.status is OK


class TestUnreadableRows:

    @pytest.mark.parametrize("row", _UNREADABLE_ROWS)
    def test_checkpoint_row(self, row):
        _assert_error(lambda: _checkpoints([_checkpoint(), row]), *_CHECKPOINT_ERROR)

    @pytest.mark.parametrize("missing", [
        "signal_path", "service_name", "operation_name", "updated_at",
    ])
    def test_checkpoint_row_without_a_key(self, missing):
        row = _checkpoint()
        del row[missing]
        _assert_error(lambda: _checkpoints([row]), *_CHECKPOINT_ERROR)

    def test_checkpoint_row_with_an_unhashable_value(self):
        row = {**_checkpoint(), "service_name": ["PRIVATE"]}
        _assert_error(lambda: _checkpoints([row]), *_CHECKPOINT_ERROR)

    @pytest.mark.parametrize("row", _UNREADABLE_ROWS)
    def test_anomaly_row(self, row):
        rows = [_anomaly_row(1, _ago(hours=5)), row]
        _assert_error(lambda: _anomalies(rows), *_ANOMALY_ERROR)

    @pytest.mark.parametrize("missing", ["anomaly_id", "detected_at"])
    def test_anomaly_row_without_a_key(self, missing):
        row = _anomaly_row(1, _ago(hours=5))
        del row[missing]
        _assert_error(lambda: _anomalies([row]), *_ANOMALY_ERROR)

    def test_anomaly_row_with_an_unhashable_id(self):
        row = {"anomaly_id": ["PRIVATE"], "detected_at": _T0}
        _assert_error(lambda: _anomalies([row]), *_ANOMALY_ERROR)

    @pytest.mark.parametrize("row", _UNREADABLE_ROWS)
    def test_decision_row(self, row):
        _assert_error(lambda: _deliveries([_decision(1), row], []), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("missing", ["decision_id", "evaluated_at"])
    def test_decision_row_without_a_key(self, missing):
        row = _decision(1)
        del row[missing]
        _assert_error(lambda: _deliveries([row], []), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("row", _UNREADABLE_ROWS)
    def test_history_row(self, row):
        _assert_error(lambda: _deliveries([_decision(1)], [row]), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("missing", [
        "attempt_id", "decision_id", "channel_name", "channel_type", "attempt_no",
        "trigger", "summary_included", "payload_sha256", "started_at", "outcome",
        "recorded_at",
    ])
    def test_history_row_without_a_key(self, missing):
        row = _attempt(1, "log", 1, R)
        del row[missing]
        _assert_error(lambda: _deliveries([_decision(1)], [row]), *_DELIVERY_ERROR)

    def test_history_row_with_an_unhashable_key_column(self):
        row = {**_attempt(1, "log", 1, R), "decision_id": ["PRIVATE"]}
        _assert_error(lambda: _deliveries([_decision(1)], [row]), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("rows", [None, 5])
    def test_rows_that_are_not_a_sequence(self, rows):
        _assert_error(lambda: _checkpoints(rows), *_CHECKPOINT_ERROR)
        _assert_error(lambda: _anomalies(rows), *_ANOMALY_ERROR)
        _assert_error(lambda: _deliveries(rows, []), *_DELIVERY_ERROR)
        _assert_error(lambda: _deliveries([_decision(1)], rows), *_DELIVERY_ERROR)

    @pytest.mark.parametrize("corrupt, error", [
        (lambda store: store.checkpoints.append(None), _CHECKPOINT_ERROR),
        (lambda store: store.anomalies.append({}), _ANOMALY_ERROR),
        (lambda store: store.decisions.append("PRIVATE"), _DELIVERY_ERROR),
        (lambda store: store.history.append({"PRIVATE": 1}), _DELIVERY_ERROR),
    ])
    def test_run_returns_no_result(self, store, corrupt, error):
        store.checkpoints = [_checkpoint()]
        store.decisions = [_decision(1)]
        corrupt(store)
        _assert_error(lambda: _run(store), *error)

    def test_an_unexpected_error_inside_derive_state_fails_closed(self, monkeypatch):
        def broken(*args, **kwargs):
            raise KeyError("PRIVATE")

        monkeypatch.setattr(alert_guardrails, "derive_state", broken)
        _assert_error(lambda: _deliveries([_decision(1)], []), *_DELIVERY_ERROR)

    def test_keyboard_interrupt_is_not_swallowed(self, monkeypatch):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(alert_guardrails, "derive_state", interrupted)
        with pytest.raises(KeyboardInterrupt):
            _deliveries([_decision(1)], [])
