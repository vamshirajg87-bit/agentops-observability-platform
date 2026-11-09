"""
Tests for alerting/alert_policy.py

No database, no network, no environment variables.  The only file read is
the shipped alerting/policy.json; other policies are built in memory or
written to pytest's tmp_path.

Coverage:
    1.  Shipped default policy
    2.  Defaults materialized
    3.  Unknown keys at every object level
    4.  Missing required sections and keys
    5.  Scalar types, including bool-vs-int traps
    6.  Numeric bounds
    7.  Severity and schema version
    8.  Identifiers
    9.  Channels: types, type-specific keys, duplicates
    10. Webhook environment-variable names
    11. include_summary / persist_summary invariant
    12. Policy hash
    13. Loading: files, malformed JSON, duplicate keys
    14. Immutability and module boundary
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import inspect
import json
import os

import pytest

import alert_policy
from alert_models import ChannelType, Severity
from alert_policy import (
    AlertPolicy,
    ChannelConfig,
    DeliveryPolicy,
    EvaluationPolicy,
    GuardrailPolicy,
    PolicyValidationError,
    compute_policy_sha256,
    evaluation_hash_object,
    load_policy,
    parse_policy,
    validate_policy,
)
from alert_version import POLICY_SCHEMA_VERSION

_SHIPPED_POLICY = os.path.join(
    os.path.dirname(__file__), "..", "..", "policy.json",
)

# SHA-256 of the literal text
# {"evaluation":{"cooldown_minutes":30,"enabled":true,
#  "escalation_breaks_cooldown":true,"max_alert_age_minutes":60,
#  "max_alerts_per_hour":10,"min_severity":"WARNING","persist_summary":false},
#  "policy_schema_version":"1.0.0","policy_version":"1.0.0"}
# (one line, no spaces), computed independently of the module.
_DEFAULT_POLICY_SHA256 = (
    "c5458ec284552f01ab8efd9d3934023b43a65f919754b5d3798a721e57dc2fec"
)


def _full() -> dict:
    """A complete, valid policy with every key written out."""
    return {
        "policy_schema_version": "1.0.0",
        "policy_version": "1.0.0",
        "evaluation": {
            "enabled": True,
            "min_severity": "WARNING",
            "max_alert_age_minutes": 60,
            "cooldown_minutes": 30,
            "escalation_breaks_cooldown": True,
            "max_alerts_per_hour": 10,
            "persist_summary": False,
        },
        "delivery": {
            "max_delivery_age_minutes": 60,
            "channels": [
                {
                    "name": "log",
                    "type": "log",
                    "enabled": True,
                    "include_summary": False,
                    "max_attempts": 3,
                    "timeout_seconds": 10,
                },
            ],
        },
        "guardrails": {
            "detector_checkpoint_max_age_minutes": 1440,
            "uninvestigated_anomaly_max_age_minutes": 60,
            "delivery_lookback_hours": 24,
        },
    }


def _minimal() -> dict:
    """The smallest valid policy: every optional key omitted."""
    return {
        "policy_schema_version": "1.0.0",
        "policy_version": "1.0.0",
        "evaluation": {},
        "delivery": {"channels": []},
        "guardrails": {},
    }


def _with(section: str, key: str, value) -> dict:
    data = _full()
    data[section][key] = value
    return data


def _with_channel(**fields) -> dict:
    """A valid policy whose only channel is a log channel plus fields."""
    data = _full()
    data["delivery"]["channels"] = [{**data["delivery"]["channels"][0], **fields}]
    return data


def _webhook(**fields) -> dict:
    channel = {
        "name": "hook",
        "type": "webhook",
        "enabled": False,
        "url_env": "ALERT_WEBHOOK_URL",
    }
    channel.update(fields)
    data = _full()
    data["delivery"]["channels"] = [channel]
    return data


def _file(**fields) -> dict:
    channel = {
        "name": "file",
        "type": "file",
        "enabled": False,
        "path": "alerts.jsonl",
    }
    channel.update(fields)
    data = _full()
    data["delivery"]["channels"] = [channel]
    return data


# ---------------------------------------------------------------------------
# 1. Shipped default policy
# ---------------------------------------------------------------------------

class TestShippedPolicy:
    @pytest.fixture(scope="class")
    def policy(self) -> AlertPolicy:
        return load_policy(_SHIPPED_POLICY)

    def test_loads(self, policy):
        assert isinstance(policy, AlertPolicy)

    def test_versions(self, policy):
        assert policy.policy_schema_version == POLICY_SCHEMA_VERSION == "1.0.0"
        assert policy.policy_version == "1.0.0"

    def test_evaluation_defaults(self, policy):
        assert policy.evaluation == EvaluationPolicy(
            enabled=True,
            min_severity=Severity.WARNING,
            max_alert_age_minutes=60,
            cooldown_minutes=30,
            escalation_breaks_cooldown=True,
            max_alerts_per_hour=10,
            persist_summary=False,
        )

    def test_delivery_defaults(self, policy):
        assert policy.delivery.max_delivery_age_minutes == 60

    def test_guardrail_defaults(self, policy):
        assert policy.guardrails == GuardrailPolicy(
            detector_checkpoint_max_age_minutes=1440,
            uninvestigated_anomaly_max_age_minutes=60,
            delivery_lookback_hours=24,
        )

    def test_log_channel_is_enabled(self, policy):
        enabled = [c for c in policy.delivery.channels if c.enabled]
        assert [(c.name, c.type) for c in enabled] == [("log", ChannelType.LOG)]

    def test_file_channel_is_present_but_disabled(self, policy):
        files = [c for c in policy.delivery.channels if c.type is ChannelType.FILE]
        assert len(files) == 1
        assert files[0].enabled is False

    def test_no_webhook_channel(self, policy):
        assert not any(
            c.type is ChannelType.WEBHOOK for c in policy.delivery.channels
        )

    def test_no_channel_includes_summary(self, policy):
        assert not any(c.include_summary for c in policy.delivery.channels)

    def test_max_attempts_default(self, policy):
        assert all(c.max_attempts == 3 for c in policy.delivery.channels)

    def test_contains_no_url_or_secret(self):
        with open(_SHIPPED_POLICY, encoding="utf-8") as fh:
            text = fh.read().lower()
        for forbidden in ("http://", "https://", "token", "password", "secret", "url"):
            assert forbidden not in text

    def test_equals_the_built_in_defaults(self, policy):
        assert policy.evaluation == EvaluationPolicy()
        assert policy.guardrails == GuardrailPolicy()

    def test_hash(self, policy):
        assert policy.policy_sha256 == _DEFAULT_POLICY_SHA256


# ---------------------------------------------------------------------------
# 2. Defaults materialized
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_minimal_policy_is_valid(self):
        assert isinstance(validate_policy(_minimal()), AlertPolicy)

    def test_minimal_equals_fully_written_defaults(self):
        full = _full()
        full["delivery"]["channels"] = []
        assert validate_policy(_minimal()) == validate_policy(full)

    def test_minimal_hash_equals_default_hash(self):
        assert validate_policy(_minimal()).policy_sha256 == _DEFAULT_POLICY_SHA256

    def test_evaluation_defaults(self):
        evaluation = validate_policy(_minimal()).evaluation
        assert evaluation.enabled is True
        assert evaluation.min_severity is Severity.WARNING
        assert evaluation.max_alert_age_minutes == 60
        assert evaluation.cooldown_minutes == 30
        assert evaluation.escalation_breaks_cooldown is True
        assert evaluation.max_alerts_per_hour == 10
        assert evaluation.persist_summary is False

    def test_delivery_default(self):
        delivery = validate_policy(_minimal()).delivery
        assert delivery.max_delivery_age_minutes == 60
        assert delivery.channels == ()

    def test_guardrail_defaults(self):
        guardrails = validate_policy(_minimal()).guardrails
        assert guardrails.detector_checkpoint_max_age_minutes == 1440
        assert guardrails.uninvestigated_anomaly_max_age_minutes == 60
        assert guardrails.delivery_lookback_hours == 24

    def test_channel_defaults(self):
        data = _minimal()
        data["delivery"]["channels"] = [
            {"name": "log", "type": "log", "enabled": True},
        ]
        channel = validate_policy(data).delivery.channels[0]
        assert channel.include_summary is False
        assert channel.max_attempts == 3
        assert channel.timeout_seconds == 10
        assert channel.path is None
        assert channel.url_env is None
        assert channel.token_env is None
        assert channel.allow_insecure_loopback is False

    def test_webhook_defaults(self):
        channel = validate_policy(_webhook()).delivery.channels[0]
        assert channel.token_env is None
        assert channel.allow_insecure_loopback is False

    def test_partial_evaluation_keeps_other_defaults(self):
        data = _minimal()
        data["evaluation"] = {"cooldown_minutes": 5}
        evaluation = validate_policy(data).evaluation
        assert evaluation.cooldown_minutes == 5
        assert evaluation.max_alert_age_minutes == 60

    def test_input_is_not_mutated(self):
        data = _full()
        before = copy.deepcopy(data)
        validate_policy(data)
        assert data == before


# ---------------------------------------------------------------------------
# 3. Unknown keys
# ---------------------------------------------------------------------------

class TestUnknownKeys:
    def test_root(self):
        data = _full()
        data["extra"] = 1
        with pytest.raises(PolicyValidationError, match="policy root"):
            validate_policy(data)

    @pytest.mark.parametrize("section", ["evaluation", "delivery", "guardrails"])
    def test_section(self, section):
        data = _full()
        data[section]["extra"] = 1
        with pytest.raises(PolicyValidationError, match=f"'{section}'"):
            validate_policy(data)

    def test_channel(self):
        with pytest.raises(PolicyValidationError, match=r"channels\[0\]"):
            validate_policy(_with_channel(extra=1))

    @pytest.mark.parametrize("section, typo", [
        ("evaluation", "cooldown_minute"),
        ("evaluation", "min_severty"),
        ("evaluation", "max_attempts"),
        ("delivery", "channel"),
        ("guardrails", "delivery_lookback_hour"),
    ])
    def test_typos_fail_loudly(self, section, typo):
        data = _full()
        data[section][typo] = 1
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(data)

    def test_evaluation_key_at_root_rejected(self):
        data = _full()
        data["min_severity"] = "INFO"
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(data)

    def test_error_lists_the_unknown_key(self):
        data = _full()
        data["guardrails"]["surprise"] = 1
        with pytest.raises(PolicyValidationError, match="surprise"):
            validate_policy(data)

    @pytest.mark.parametrize("key", [
        "path", "url_env", "token_env", "allow_insecure_loopback",
    ])
    def test_log_channel_rejects_other_types_keys(self, key):
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(_with_channel(**{key: "ALERT_WEBHOOK_URL"}))

    @pytest.mark.parametrize("key", ["url_env", "token_env", "allow_insecure_loopback"])
    def test_file_channel_rejects_webhook_keys(self, key):
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(_file(**{key: "ALERT_WEBHOOK_URL"}))

    def test_webhook_channel_rejects_path(self):
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(_webhook(path="alerts.jsonl"))

    @pytest.mark.parametrize("key", ["url", "webhook_url", "headers", "secret"])
    def test_webhook_cannot_carry_a_literal_url_or_secret(self, key):
        with pytest.raises(PolicyValidationError, match="Unknown key"):
            validate_policy(_webhook(**{key: "https://example.invalid/hook"}))


# ---------------------------------------------------------------------------
# 4. Missing sections and keys
# ---------------------------------------------------------------------------

class TestMissing:
    @pytest.mark.parametrize("key", [
        "policy_schema_version", "policy_version", "evaluation", "delivery",
        "guardrails",
    ])
    def test_required_top_level_key(self, key):
        data = _full()
        del data[key]
        with pytest.raises(PolicyValidationError, match=key):
            validate_policy(data)

    def test_empty_root(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({})

    def test_channels_required(self):
        data = _full()
        del data["delivery"]["channels"]
        with pytest.raises(PolicyValidationError, match="delivery.channels"):
            validate_policy(data)

    @pytest.mark.parametrize("key", ["name", "type", "enabled"])
    def test_channel_required_key(self, key):
        data = _full()
        del data["delivery"]["channels"][0][key]
        with pytest.raises(PolicyValidationError, match=f"requires '{key}'"):
            validate_policy(data)

    def test_file_channel_requires_path(self):
        data = _file()
        del data["delivery"]["channels"][0]["path"]
        with pytest.raises(PolicyValidationError, match="path"):
            validate_policy(data)

    def test_webhook_channel_requires_url_env(self):
        data = _webhook()
        del data["delivery"]["channels"][0]["url_env"]
        with pytest.raises(PolicyValidationError, match="url_env"):
            validate_policy(data)


# ---------------------------------------------------------------------------
# 5. Scalar types
# ---------------------------------------------------------------------------

_BOOL_FIELDS = [
    ("evaluation", "enabled"),
    ("evaluation", "escalation_breaks_cooldown"),
    ("evaluation", "persist_summary"),
]
_INT_FIELDS = [
    ("evaluation", "max_alert_age_minutes"),
    ("evaluation", "cooldown_minutes"),
    ("evaluation", "max_alerts_per_hour"),
    ("delivery", "max_delivery_age_minutes"),
    ("guardrails", "detector_checkpoint_max_age_minutes"),
    ("guardrails", "uninvestigated_anomaly_max_age_minutes"),
    ("guardrails", "delivery_lookback_hours"),
]


class TestScalarTypes:
    @pytest.mark.parametrize("bad", [None, [], "x", 1, 1.5, True])
    def test_root_must_be_object(self, bad):
        with pytest.raises(PolicyValidationError, match="Policy root"):
            validate_policy(bad)

    @pytest.mark.parametrize("section", ["evaluation", "delivery", "guardrails"])
    @pytest.mark.parametrize("bad", [None, [], "x", 1, True])
    def test_section_must_be_object(self, section, bad):
        data = _full()
        data[section] = bad
        with pytest.raises(PolicyValidationError, match=f"'{section}'"):
            validate_policy(data)

    @pytest.mark.parametrize("section, key", _BOOL_FIELDS)
    @pytest.mark.parametrize("bad", [0, 1, "true", "false", None, 1.0, []])
    def test_bool_fields_reject_non_bool(self, section, key, bad):
        with pytest.raises(PolicyValidationError, match=key):
            validate_policy(_with(section, key, bad))

    @pytest.mark.parametrize("section, key", _INT_FIELDS)
    @pytest.mark.parametrize("bad", [True, False])
    def test_int_fields_reject_bool(self, section, key, bad):
        with pytest.raises(PolicyValidationError, match="got bool"):
            validate_policy(_with(section, key, bad))

    @pytest.mark.parametrize("section, key", _INT_FIELDS)
    @pytest.mark.parametrize("bad", ["60", 60.0, 1.5, None, [60], {"v": 60}])
    def test_int_fields_reject_non_int(self, section, key, bad):
        with pytest.raises(PolicyValidationError, match=key):
            validate_policy(_with(section, key, bad))

    @pytest.mark.parametrize("key", ["max_attempts", "timeout_seconds"])
    @pytest.mark.parametrize("bad", [True, "3", 3.0, None])
    def test_channel_int_fields_reject_non_int(self, key, bad):
        with pytest.raises(PolicyValidationError, match=key):
            validate_policy(_with_channel(**{key: bad}))

    @pytest.mark.parametrize("key", ["enabled", "include_summary"])
    @pytest.mark.parametrize("bad", [0, 1, "true", None])
    def test_channel_bool_fields_reject_non_bool(self, key, bad):
        with pytest.raises(PolicyValidationError, match=key):
            validate_policy(_with_channel(**{key: bad}))

    @pytest.mark.parametrize("bad", [0, 1, "true", None])
    def test_allow_insecure_loopback_must_be_bool(self, bad):
        with pytest.raises(PolicyValidationError, match="allow_insecure_loopback"):
            validate_policy(_webhook(allow_insecure_loopback=bad))

    @pytest.mark.parametrize("bad", [None, {}, "log", 1])
    def test_channels_must_be_list(self, bad):
        data = _full()
        data["delivery"]["channels"] = bad
        with pytest.raises(PolicyValidationError, match="delivery.channels"):
            validate_policy(data)

    @pytest.mark.parametrize("bad", [None, "log", 1, ["log"]])
    def test_channel_must_be_object(self, bad):
        data = _full()
        data["delivery"]["channels"] = [bad]
        with pytest.raises(PolicyValidationError, match=r"channels\[0\]"):
            validate_policy(data)

    def test_optional_channel_key_may_not_be_null(self):
        with pytest.raises(PolicyValidationError, match="must not be null"):
            validate_policy(_webhook(token_env=None))

    @pytest.mark.parametrize("bad", ["", "   ", "a\x00b", 5, True, ["p"]])
    def test_file_path_must_be_usable_string(self, bad):
        with pytest.raises(PolicyValidationError, match="path"):
            validate_policy(_file(path=bad))


# ---------------------------------------------------------------------------
# 6. Numeric bounds
# ---------------------------------------------------------------------------

class TestBounds:
    @pytest.mark.parametrize("section, key", [
        field for field in _INT_FIELDS if field[1] != "cooldown_minutes"
    ])
    @pytest.mark.parametrize("bad", [0, -1])
    def test_positive_fields_reject_zero_and_negative(self, section, key, bad):
        with pytest.raises(PolicyValidationError, match="positive integer"):
            validate_policy(_with(section, key, bad))

    @pytest.mark.parametrize("section, key", [
        field for field in _INT_FIELDS if field[1] != "cooldown_minutes"
    ])
    def test_positive_fields_accept_one(self, section, key):
        policy = validate_policy(_with(section, key, 1))
        assert getattr(getattr(policy, section), key) == 1

    def test_cooldown_zero_accepted(self):
        policy = validate_policy(_with("evaluation", "cooldown_minutes", 0))
        assert policy.evaluation.cooldown_minutes == 0

    def test_cooldown_negative_rejected(self):
        with pytest.raises(PolicyValidationError, match="non-negative"):
            validate_policy(_with("evaluation", "cooldown_minutes", -1))

    @pytest.mark.parametrize("bad", [0, -1])
    def test_max_attempts_must_be_at_least_one(self, bad):
        with pytest.raises(PolicyValidationError, match="max_attempts"):
            validate_policy(_with_channel(max_attempts=bad))

    def test_max_attempts_one_accepted(self):
        policy = validate_policy(_with_channel(max_attempts=1))
        assert policy.delivery.channels[0].max_attempts == 1

    @pytest.mark.parametrize("good", [1, 10, 30])
    def test_timeout_inside_range(self, good):
        policy = validate_policy(_with_channel(timeout_seconds=good))
        assert policy.delivery.channels[0].timeout_seconds == good

    @pytest.mark.parametrize("bad", [0, -1, 31, 1000])
    def test_timeout_outside_range(self, bad):
        with pytest.raises(PolicyValidationError, match="timeout_seconds"):
            validate_policy(_with_channel(timeout_seconds=bad))


# ---------------------------------------------------------------------------
# 7. Severity and schema version
# ---------------------------------------------------------------------------

class TestSeverityAndSchema:
    @pytest.mark.parametrize("good", ["INFO", "WARNING", "CRITICAL"])
    def test_supported_severity(self, good):
        policy = validate_policy(_with("evaluation", "min_severity", good))
        assert policy.evaluation.min_severity is Severity(good)

    @pytest.mark.parametrize("bad", [
        "warning", "Warning", "FATAL", "ERROR", "", " WARNING", "WARNING ",
    ])
    def test_unsupported_severity(self, bad):
        with pytest.raises(PolicyValidationError, match="min_severity"):
            validate_policy(_with("evaluation", "min_severity", bad))

    @pytest.mark.parametrize("bad", [1, None, True, ["WARNING"]])
    def test_severity_must_be_string(self, bad):
        with pytest.raises(PolicyValidationError, match="min_severity"):
            validate_policy(_with("evaluation", "min_severity", bad))

    @pytest.mark.parametrize("bad", ["1.0.1", "2.0.0", "1.0", "1", "", "v1.0.0"])
    def test_unsupported_schema_version(self, bad):
        data = _full()
        data["policy_schema_version"] = bad
        with pytest.raises(PolicyValidationError, match="policy_schema_version"):
            validate_policy(data)

    @pytest.mark.parametrize("bad", [1, 1.0, None, True, ["1.0.0"]])
    def test_schema_version_must_be_string(self, bad):
        data = _full()
        data["policy_schema_version"] = bad
        with pytest.raises(PolicyValidationError, match="policy_schema_version"):
            validate_policy(data)


# ---------------------------------------------------------------------------
# 8. Identifiers
# ---------------------------------------------------------------------------

class TestIdentifiers:
    @pytest.mark.parametrize("good", ["1", "1.0.0", "2026-10-05_a", "x" * 64])
    def test_valid_policy_version(self, good):
        data = _full()
        data["policy_version"] = good
        assert validate_policy(data).policy_version == good

    @pytest.mark.parametrize("bad", [
        "", "x" * 65, "1.0 0", "v/1", "v|1", "1.0.0\n", "café", 1, 1.0,
        None, True,
    ])
    def test_invalid_policy_version(self, bad):
        data = _full()
        data["policy_version"] = bad
        with pytest.raises(PolicyValidationError, match="policy_version"):
            validate_policy(data)

    @pytest.mark.parametrize("good", ["log", "local-file", "ops.hook_1", "x" * 64])
    def test_valid_channel_name(self, good):
        policy = validate_policy(_with_channel(name=good))
        assert policy.delivery.channels[0].name == good

    @pytest.mark.parametrize("bad", [
        "", "x" * 65, "my channel", "a/b", "a\n", "café", 1, True, ["log"],
    ])
    def test_invalid_channel_name(self, bad):
        with pytest.raises(PolicyValidationError, match="name"):
            validate_policy(_with_channel(name=bad))


# ---------------------------------------------------------------------------
# 9. Channels
# ---------------------------------------------------------------------------

class TestChannels:
    @pytest.mark.parametrize("bad", [
        "slack", "pagerduty", "email", "sms", "LOG", "Webhook", "",
    ])
    def test_unsupported_type(self, bad):
        with pytest.raises(PolicyValidationError, match="'type'"):
            validate_policy(_with_channel(type=bad))

    @pytest.mark.parametrize("bad", [1, True, ["log"]])
    def test_type_must_be_string(self, bad):
        with pytest.raises(PolicyValidationError, match="'type'"):
            validate_policy(_with_channel(type=bad))

    def test_all_three_types_together(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "log", "type": "log", "enabled": True},
            {"name": "file", "type": "file", "enabled": True, "path": "a.jsonl"},
            {
                "name": "hook", "type": "webhook", "enabled": False,
                "url_env": "ALERT_WEBHOOK_URL",
                "token_env": "ALERT_WEBHOOK_TOKEN",
                "allow_insecure_loopback": True,
            },
        ]
        channels = validate_policy(data).delivery.channels
        assert [c.type for c in channels] == [
            ChannelType.LOG, ChannelType.FILE, ChannelType.WEBHOOK,
        ]
        assert channels[1].path == "a.jsonl"
        assert channels[2].url_env == "ALERT_WEBHOOK_URL"
        assert channels[2].token_env == "ALERT_WEBHOOK_TOKEN"
        assert channels[2].allow_insecure_loopback is True

    def test_order_is_preserved(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": name, "type": "log", "enabled": True}
            for name in ("c", "a", "b")
        ]
        names = [c.name for c in validate_policy(data).delivery.channels]
        assert names == ["c", "a", "b"]

    def test_empty_channel_list_accepted(self):
        data = _full()
        data["delivery"]["channels"] = []
        assert validate_policy(data).delivery.channels == ()

    def test_duplicate_names_rejected(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "dup", "type": "log", "enabled": True},
            {"name": "dup", "type": "log", "enabled": False},
        ]
        with pytest.raises(PolicyValidationError, match="Duplicate channel name"):
            validate_policy(data)

    def test_duplicate_names_across_types_rejected(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "dup", "type": "log", "enabled": True},
            {"name": "dup", "type": "file", "enabled": True, "path": "a.jsonl"},
        ]
        with pytest.raises(PolicyValidationError, match="Duplicate channel name"):
            validate_policy(data)

    def test_names_differing_only_by_case_are_distinct(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "Log", "type": "log", "enabled": True},
            {"name": "log", "type": "log", "enabled": True},
        ]
        assert len(validate_policy(data).delivery.channels) == 2

    def test_error_names_the_channel_index(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "ok", "type": "log", "enabled": True},
            {"name": "bad", "type": "log", "enabled": True, "max_attempts": 0},
        ]
        with pytest.raises(PolicyValidationError, match=r"channels\[1\]"):
            validate_policy(data)

    def test_disabled_channel_is_still_validated(self):
        with pytest.raises(PolicyValidationError, match="timeout_seconds"):
            validate_policy(_with_channel(enabled=False, timeout_seconds=99))


# ---------------------------------------------------------------------------
# 10. Webhook environment-variable names
# ---------------------------------------------------------------------------

_BAD_ENV_NAMES = [
    "", "ALERT_WEBHOOK_", "ALERT_WEBHOOK", "WEBHOOK_URL", "alert_webhook_url",
    "ALERT_WEBHOOK_url", "ALERT_WEBHOOK_URL ", " ALERT_WEBHOOK_URL",
    "ALERT_WEBHOOK_URL\n", "ALERT_WEBHOOK_URL-1", "ALERT_WEBHOOK_URL.1",
    "XALERT_WEBHOOK_URL", "PATH", "https://example.invalid/hook",
    "$ALERT_WEBHOOK_URL", "${ALERT_WEBHOOK_URL}",
]


class TestWebhookEnvNames:
    @pytest.mark.parametrize("good", [
        "ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_1", "ALERT_WEBHOOK__",
        "ALERT_WEBHOOK_OPS_URL_2",
    ])
    def test_valid_url_env(self, good):
        channel = validate_policy(_webhook(url_env=good)).delivery.channels[0]
        assert channel.url_env == good

    @pytest.mark.parametrize("bad", _BAD_ENV_NAMES)
    def test_invalid_url_env(self, bad):
        with pytest.raises(PolicyValidationError, match="url_env"):
            validate_policy(_webhook(url_env=bad))

    @pytest.mark.parametrize("bad", [1, True, ["ALERT_WEBHOOK_URL"]])
    def test_url_env_must_be_string(self, bad):
        with pytest.raises(PolicyValidationError, match="url_env"):
            validate_policy(_webhook(url_env=bad))

    def test_valid_token_env(self):
        channel = validate_policy(
            _webhook(token_env="ALERT_WEBHOOK_TOKEN"),
        ).delivery.channels[0]
        assert channel.token_env == "ALERT_WEBHOOK_TOKEN"

    @pytest.mark.parametrize("bad", _BAD_ENV_NAMES)
    def test_invalid_token_env(self, bad):
        with pytest.raises(PolicyValidationError, match="token_env"):
            validate_policy(_webhook(token_env=bad))

    @pytest.mark.parametrize("bad", [1, True, ["ALERT_WEBHOOK_TOKEN"]])
    def test_token_env_must_be_string(self, bad):
        with pytest.raises(PolicyValidationError, match="token_env"):
            validate_policy(_webhook(token_env=bad))

    def test_token_env_must_differ_from_url_env(self):
        with pytest.raises(PolicyValidationError, match="must differ"):
            validate_policy(_webhook(token_env="ALERT_WEBHOOK_URL"))

    def test_validation_does_not_read_the_environment(self, monkeypatch):
        monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
        channel = validate_policy(_webhook(enabled=True)).delivery.channels[0]
        assert channel.url_env == "ALERT_WEBHOOK_URL"
        assert not hasattr(channel, "url")


# ---------------------------------------------------------------------------
# 11. include_summary / persist_summary
# ---------------------------------------------------------------------------

class TestSummaryInvariant:
    def test_include_summary_without_persist_summary_rejected(self):
        with pytest.raises(PolicyValidationError, match="persist_summary"):
            validate_policy(_with_channel(include_summary=True))

    def test_rejected_when_persist_summary_is_defaulted(self):
        data = _minimal()
        data["delivery"]["channels"] = [
            {"name": "log", "type": "log", "enabled": True, "include_summary": True},
        ]
        with pytest.raises(PolicyValidationError, match="persist_summary"):
            validate_policy(data)

    def test_rejected_even_when_channel_is_disabled(self):
        with pytest.raises(PolicyValidationError, match="persist_summary"):
            validate_policy(_with_channel(include_summary=True, enabled=False))

    @pytest.mark.parametrize("builder", [_with_channel, _file, _webhook])
    def test_rejected_for_every_channel_type(self, builder):
        with pytest.raises(PolicyValidationError, match="persist_summary"):
            validate_policy(builder(include_summary=True))

    def test_error_names_the_channel(self):
        with pytest.raises(PolicyValidationError, match="'hook'"):
            validate_policy(_webhook(include_summary=True))

    @pytest.mark.parametrize("builder", [_with_channel, _file, _webhook])
    def test_allowed_when_persist_summary_is_true(self, builder):
        data = builder(include_summary=True)
        data["evaluation"]["persist_summary"] = True
        assert validate_policy(data).delivery.channels[0].include_summary is True

    def test_persist_summary_without_any_including_channel_is_valid(self):
        policy = validate_policy(_with("evaluation", "persist_summary", True))
        assert policy.evaluation.persist_summary is True

    def test_one_offending_channel_among_several(self):
        data = _full()
        data["delivery"]["channels"] = [
            {"name": "a", "type": "log", "enabled": True},
            {"name": "b", "type": "log", "enabled": True, "include_summary": True},
        ]
        with pytest.raises(PolicyValidationError, match="'b'"):
            validate_policy(data)


# ---------------------------------------------------------------------------
# 12. Policy hash
# ---------------------------------------------------------------------------

_EVALUATION_CHANGES = [
    ("enabled", False),
    ("min_severity", "INFO"),
    ("min_severity", "CRITICAL"),
    ("max_alert_age_minutes", 61),
    ("cooldown_minutes", 0),
    ("cooldown_minutes", 31),
    ("escalation_breaks_cooldown", False),
    ("max_alerts_per_hour", 11),
    ("persist_summary", True),
]


class TestPolicyHash:
    def test_fixed_vector(self):
        assert validate_policy(_full()).policy_sha256 == _DEFAULT_POLICY_SHA256

    def test_is_sha256_of_sorted_compact_ascii_json(self):
        policy = validate_policy(_full())
        obj = evaluation_hash_object(
            policy.policy_schema_version, policy.policy_version, policy.evaluation,
        )
        text = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
        assert policy.policy_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()

    def test_hash_object_scope(self):
        policy = validate_policy(_full())
        obj = evaluation_hash_object(
            policy.policy_schema_version, policy.policy_version, policy.evaluation,
        )
        assert set(obj) == {"policy_schema_version", "policy_version", "evaluation"}
        assert set(obj["evaluation"]) == {
            "enabled", "min_severity", "max_alert_age_minutes", "cooldown_minutes",
            "escalation_breaks_cooldown", "max_alerts_per_hour", "persist_summary",
        }
        assert obj["evaluation"]["min_severity"] == "WARNING"

    def test_hash_object_covers_every_evaluation_field(self):
        policy = validate_policy(_full())
        obj = evaluation_hash_object(
            policy.policy_schema_version, policy.policy_version, policy.evaluation,
        )
        fields = {field.name for field in dataclasses.fields(EvaluationPolicy)}
        assert set(obj["evaluation"]) == fields

    def test_hash_object_holds_only_json_scalars(self):
        policy = validate_policy(_full())
        obj = evaluation_hash_object(
            policy.policy_schema_version, policy.policy_version, policy.evaluation,
        )
        for value in obj["evaluation"].values():
            assert type(value) in (bool, int, str)

    def test_stable_under_whitespace(self):
        compact = json.dumps(_full(), separators=(",", ":"))
        spaced = json.dumps(_full(), indent=8)
        padded = "\n\n  " + json.dumps(_full(), indent=1) + "  \n"
        assert (
            parse_policy(compact).policy_sha256
            == parse_policy(spaced).policy_sha256
            == parse_policy(padded).policy_sha256
            == _DEFAULT_POLICY_SHA256
        )

    def test_stable_under_key_order(self):
        data = _full()
        reordered = {key: data[key] for key in reversed(list(data))}
        reordered["evaluation"] = {
            key: data["evaluation"][key]
            for key in reversed(list(data["evaluation"]))
        }
        assert list(reordered) != list(data)
        text = json.dumps(reordered)
        assert parse_policy(text).policy_sha256 == _DEFAULT_POLICY_SHA256

    def test_stable_when_defaults_are_omitted(self):
        assert validate_policy(_minimal()).policy_sha256 == (
            validate_policy(_full()).policy_sha256
        )

    @pytest.mark.parametrize("key, value", _EVALUATION_CHANGES)
    def test_changes_on_every_evaluation_field(self, key, value):
        changed = validate_policy(_with("evaluation", key, value))
        assert changed.policy_sha256 != _DEFAULT_POLICY_SHA256

    def test_every_evaluation_field_has_a_change_case(self):
        fields = {field.name for field in dataclasses.fields(EvaluationPolicy)}
        assert {key for key, _ in _EVALUATION_CHANGES} == fields

    def test_distinct_changes_give_distinct_hashes(self):
        hashes = {
            validate_policy(_with("evaluation", key, value)).policy_sha256
            for key, value in _EVALUATION_CHANGES
        }
        assert len(hashes) == len(_EVALUATION_CHANGES)

    def test_changes_with_policy_version(self):
        data = _full()
        data["policy_version"] = "1.0.1"
        assert validate_policy(data).policy_sha256 != _DEFAULT_POLICY_SHA256

    def test_changes_with_schema_version(self):
        evaluation = EvaluationPolicy()
        assert compute_policy_sha256("1.0.0", "1.0.0", evaluation) != (
            compute_policy_sha256("1.1.0", "1.0.0", evaluation)
        )

    def test_versions_are_not_interchangeable(self):
        evaluation = EvaluationPolicy()
        assert compute_policy_sha256("1.0.0", "2.0.0", evaluation) != (
            compute_policy_sha256("2.0.0", "1.0.0", evaluation)
        )

    @pytest.mark.parametrize("mutate", [
        lambda d: d["delivery"].update(max_delivery_age_minutes=5),
        lambda d: d["delivery"].update(channels=[]),
        lambda d: d["delivery"]["channels"][0].update(max_attempts=9),
        lambda d: d["delivery"]["channels"][0].update(timeout_seconds=1),
        lambda d: d["delivery"]["channels"][0].update(enabled=False),
        lambda d: d["delivery"]["channels"][0].update(name="renamed"),
        lambda d: d["delivery"]["channels"].append({
            "name": "hook", "type": "webhook", "enabled": True,
            "url_env": "ALERT_WEBHOOK_URL",
        }),
        lambda d: d["delivery"]["channels"].append({
            "name": "file", "type": "file", "enabled": True, "path": "a.jsonl",
        }),
    ])
    def test_unchanged_when_delivery_changes(self, mutate):
        data = _full()
        mutate(data)
        assert validate_policy(data).policy_sha256 == _DEFAULT_POLICY_SHA256

    def test_unchanged_when_include_summary_changes(self):
        base = _with("evaluation", "persist_summary", True)
        changed = copy.deepcopy(base)
        changed["delivery"]["channels"][0]["include_summary"] = True
        assert validate_policy(changed).policy_sha256 == (
            validate_policy(base).policy_sha256
        )

    @pytest.mark.parametrize("key, value", [
        ("detector_checkpoint_max_age_minutes", 1),
        ("uninvestigated_anomaly_max_age_minutes", 999),
        ("delivery_lookback_hours", 1),
    ])
    def test_unchanged_when_guardrails_change(self, key, value):
        changed = validate_policy(_with("guardrails", key, value))
        assert changed.policy_sha256 == _DEFAULT_POLICY_SHA256

    def test_digest_format(self):
        digest = validate_policy(_full()).policy_sha256
        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)

    @pytest.mark.parametrize("bad", ["", None, 1])
    def test_versions_must_be_non_empty_strings(self, bad):
        with pytest.raises(PolicyValidationError):
            compute_policy_sha256(bad, "1.0.0", EvaluationPolicy())
        with pytest.raises(PolicyValidationError):
            compute_policy_sha256("1.0.0", bad, EvaluationPolicy())

    @pytest.mark.parametrize("bad", [None, {}, {"enabled": True}])
    def test_evaluation_must_be_validated_object(self, bad):
        with pytest.raises(PolicyValidationError, match="EvaluationPolicy"):
            compute_policy_sha256("1.0.0", "1.0.0", bad)


# ---------------------------------------------------------------------------
# 13. Loading
# ---------------------------------------------------------------------------

class TestLoading:
    def test_load_from_file(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(_full()), encoding="utf-8")
        assert load_policy(path) == validate_policy(_full())

    def test_load_accepts_str_path(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(_full()), encoding="utf-8")
        assert load_policy(str(path)) == validate_policy(_full())

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_policy(tmp_path / "absent.json")

    @pytest.mark.parametrize("text", ["", "{", "not json", "{'a': 1}", "[1,"])
    def test_malformed_json(self, text):
        with pytest.raises(json.JSONDecodeError):
            parse_policy(text)

    def test_invalid_policy_is_a_value_error(self):
        with pytest.raises(ValueError):
            parse_policy("{}")

    def test_json_root_must_be_object(self):
        with pytest.raises(PolicyValidationError, match="Policy root"):
            parse_policy("[]")

    def test_duplicate_key_at_root_rejected(self):
        text = json.dumps(_full())[:-1] + ', "policy_version": "2.0.0"}'
        with pytest.raises(PolicyValidationError, match="Duplicate key"):
            parse_policy(text)

    def test_duplicate_key_in_section_rejected(self):
        text = (
            '{"policy_schema_version":"1.0.0","policy_version":"1.0.0",'
            '"evaluation":{"min_severity":"CRITICAL","min_severity":"INFO"},'
            '"delivery":{"channels":[]},"guardrails":{}}'
        )
        with pytest.raises(PolicyValidationError, match="Duplicate key"):
            parse_policy(text)

    def test_duplicate_key_in_channel_rejected(self):
        text = (
            '{"policy_schema_version":"1.0.0","policy_version":"1.0.0",'
            '"evaluation":{},"delivery":{"channels":['
            '{"name":"log","type":"log","enabled":false,"enabled":true}]},'
            '"guardrails":{}}'
        )
        with pytest.raises(PolicyValidationError, match="Duplicate key"):
            parse_policy(text)

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_constants_rejected(self, constant):
        text = json.dumps(_full()).replace(
            '"max_alert_age_minutes": 60', f'"max_alert_age_minutes": {constant}',
        )
        assert constant in text
        with pytest.raises(PolicyValidationError, match="must not contain"):
            parse_policy(text)

    def test_float_written_as_integer_value_rejected(self):
        text = json.dumps(_full()).replace(
            '"cooldown_minutes": 30', '"cooldown_minutes": 30.0',
        )
        assert "30.0" in text
        with pytest.raises(PolicyValidationError, match="cooldown_minutes"):
            parse_policy(text)

    @pytest.mark.parametrize("bad", [None, b"{}", 5, {}])
    def test_text_must_be_str(self, bad):
        with pytest.raises(PolicyValidationError, match="must be str"):
            parse_policy(bad)


# ---------------------------------------------------------------------------
# 14. Immutability and module boundary
# ---------------------------------------------------------------------------

class TestImmutability:
    def test_policy_is_frozen(self):
        policy = validate_policy(_full())
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.policy_version = "2.0.0"

    def test_sections_are_frozen(self):
        policy = validate_policy(_full())
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.evaluation.min_severity = Severity.INFO
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.delivery.max_delivery_age_minutes = 1
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.guardrails.delivery_lookback_hours = 1
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.delivery.channels[0].enabled = False

    def test_channels_is_a_tuple(self):
        assert isinstance(validate_policy(_full()).delivery.channels, tuple)

    def test_all_policy_models_are_frozen_dataclasses(self):
        for model in (
            EvaluationPolicy, ChannelConfig, DeliveryPolicy, GuardrailPolicy,
            AlertPolicy,
        ):
            assert model.__dataclass_params__.frozen is True


class TestDirectConstruction:
    """The models enforce the contract even when built without the loader."""

    def test_evaluation_rejects_plain_string_severity(self):
        with pytest.raises(PolicyValidationError, match="min_severity"):
            EvaluationPolicy(min_severity="WARNING")

    def test_evaluation_rejects_bool_as_int(self):
        with pytest.raises(PolicyValidationError, match="got bool"):
            EvaluationPolicy(max_alerts_per_hour=True)

    def test_channel_rejects_plain_string_type(self):
        with pytest.raises(PolicyValidationError, match="'type'"):
            ChannelConfig(name="log", type="log", enabled=True)

    def test_log_channel_rejects_webhook_fields(self):
        with pytest.raises(PolicyValidationError, match="webhook channel only"):
            ChannelConfig(
                name="log", type=ChannelType.LOG, enabled=True,
                url_env="ALERT_WEBHOOK_URL",
            )
        with pytest.raises(PolicyValidationError, match="webhook channel only"):
            ChannelConfig(
                name="log", type=ChannelType.LOG, enabled=True,
                allow_insecure_loopback=True,
            )

    def test_log_channel_rejects_path(self):
        with pytest.raises(PolicyValidationError, match="file channel only"):
            ChannelConfig(name="log", type=ChannelType.LOG, enabled=True, path="x")

    def test_delivery_rejects_list_of_channels(self):
        with pytest.raises(PolicyValidationError, match="tuple"):
            DeliveryPolicy(channels=[])

    def test_delivery_rejects_duplicate_names(self):
        channel = ChannelConfig(name="log", type=ChannelType.LOG, enabled=True)
        with pytest.raises(PolicyValidationError, match="Duplicate channel name"):
            DeliveryPolicy(channels=(channel, channel))

    def test_policy_rejects_unsupported_schema_version(self):
        with pytest.raises(PolicyValidationError, match="policy_schema_version"):
            AlertPolicy(
                policy_schema_version="9.9.9",
                policy_version="1.0.0",
                evaluation=EvaluationPolicy(),
                delivery=DeliveryPolicy(channels=()),
                guardrails=GuardrailPolicy(),
            )

    def test_policy_rejects_raw_dict_sections(self):
        with pytest.raises(PolicyValidationError, match="evaluation"):
            AlertPolicy(
                policy_schema_version="1.0.0",
                policy_version="1.0.0",
                evaluation={},
                delivery=DeliveryPolicy(channels=()),
                guardrails=GuardrailPolicy(),
            )

    def test_policy_enforces_summary_invariant(self):
        channel = ChannelConfig(
            name="log", type=ChannelType.LOG, enabled=True, include_summary=True,
        )
        with pytest.raises(PolicyValidationError, match="persist_summary"):
            AlertPolicy(
                policy_schema_version="1.0.0",
                policy_version="1.0.0",
                evaluation=EvaluationPolicy(persist_summary=False),
                delivery=DeliveryPolicy(channels=(channel,)),
                guardrails=GuardrailPolicy(),
            )


class TestModuleBoundary:
    def test_error_type_is_a_value_error(self):
        assert issubclass(PolicyValidationError, ValueError)

    def test_no_database_network_or_environment_access(self):
        source = inspect.getsource(alert_policy)
        for forbidden in (
            "psycopg", "urllib", "http.client", "socket", "requests",
            "os.environ", "getenv",
        ):
            assert forbidden not in source
