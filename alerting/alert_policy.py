"""
alerting/alert_policy.py

Phase 13.1: Alert policy schema, loader, validator, and policy hash.

Loads and validates the JSON policy that drives alert evaluation, delivery
configuration and guardrail thresholds.  Validation fails closed: nothing is
coerced, and anything unexpected is rejected.

Accepted JSON schema
--------------------
All five top-level keys are required.  Inside a section, a key marked
"default" may be omitted.

    {
      "policy_schema_version": "1.0.0",
      "policy_version": "<identifier>",
      "evaluation": {
        "enabled":                    <bool>          default true
        "min_severity":               "INFO" | "WARNING" | "CRITICAL"
                                                      default "WARNING"
        "max_alert_age_minutes":      <int > 0>       default 60
        "cooldown_minutes":           <int >= 0>      default 30
        "escalation_breaks_cooldown": <bool>          default true
        "max_alerts_per_hour":        <int > 0>       default 10
        "persist_summary":            <bool>          default false
      },
      "delivery": {
        "max_delivery_age_minutes":   <int > 0>       default 60
        "channels": [ <channel>, ... ]                required; may be empty
      },
      "guardrails": {
        "detector_checkpoint_max_age_minutes":    <int > 0>  default 1440
        "uninvestigated_anomaly_max_age_minutes": <int > 0>  default 60
        "delivery_lookback_hours":                <int > 0>  default 24
      }
    }

Channel object
--------------
    "name":             <identifier>              required; unique
    "type":             "log" | "file" | "webhook"  required
    "enabled":          <bool>                    required
    "include_summary":  <bool>                    default false
    "max_attempts":     <int >= 1>                default 3
    "timeout_seconds":  <int 1..30>               default 10

    type "file" only:
    "path":             <non-empty string>        required

    type "webhook" only:
    "url_env":          <ALERT_WEBHOOK_* name>    required
    "token_env":        <ALERT_WEBHOOK_* name>    optional
    "allow_insecure_loopback": <bool>             default false

A webhook URL is never written in the policy: url_env names the environment
variable that holds it.  This module does not read the environment.

Identifiers (policy_version and channel names) match ^[A-Za-z0-9._-]{1,64}$.

Unknown keys at the root, in any section, or in any channel are rejected, as
is a key that does not apply to the channel's type.  A JSON object that
repeats a key is rejected.

include_summary requires evaluation.persist_summary: a channel can only send
a summary that the evaluation persisted.

Policy hash
-----------
policy_sha256 covers policy_schema_version, policy_version, and the
evaluation section with every default written out.  The delivery and
guardrails sections are operational and are not hashed.  It is computed from
the validated object, so whitespace and key order in the file do not matter.

Standard library only.  No database access; the only I/O is reading the
policy file in load_policy().

Public API:
    PolicyValidationError      — raised for any invalid policy (ValueError)
    WEBHOOK_ENV_PATTERN
    EvaluationPolicy, ChannelConfig, DeliveryPolicy, GuardrailPolicy,
    AlertPolicy                — frozen dataclasses
    evaluation_hash_object()   — the object that is hashed
    compute_policy_sha256()
    validate_policy()          — parsed JSON object -> AlertPolicy
    parse_policy()             — JSON text -> AlertPolicy
    load_policy()              — file path -> AlertPolicy
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

from alert_identity import validate_identifier
from alert_models import ChannelType, Severity
from alert_version import POLICY_SCHEMA_VERSION


class PolicyValidationError(ValueError):
    """Raised when a policy is structurally or semantically invalid."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Names of the environment variables a webhook channel may refer to.
WEBHOOK_ENV_PATTERN: str = r"ALERT_WEBHOOK_[A-Z0-9_]+"

# fullmatch is used: "$" would also match before a trailing newline.
_WEBHOOK_ENV_RE = re.compile(WEBHOOK_ENV_PATTERN)

MIN_TIMEOUT_SECONDS: int = 1
MAX_TIMEOUT_SECONDS: int = 30

DEFAULT_MAX_ATTEMPTS: int = 3
DEFAULT_TIMEOUT_SECONDS: int = 10

_ROOT_KEYS: frozenset[str] = frozenset({
    "policy_schema_version",
    "policy_version",
    "evaluation",
    "delivery",
    "guardrails",
})
_EVALUATION_KEYS: frozenset[str] = frozenset({
    "enabled",
    "min_severity",
    "max_alert_age_minutes",
    "cooldown_minutes",
    "escalation_breaks_cooldown",
    "max_alerts_per_hour",
    "persist_summary",
})
_DELIVERY_KEYS: frozenset[str] = frozenset({
    "max_delivery_age_minutes",
    "channels",
})
_GUARDRAIL_KEYS: frozenset[str] = frozenset({
    "detector_checkpoint_max_age_minutes",
    "uninvestigated_anomaly_max_age_minutes",
    "delivery_lookback_hours",
})
_CHANNEL_COMMON_KEYS: frozenset[str] = frozenset({
    "name",
    "type",
    "enabled",
    "include_summary",
    "max_attempts",
    "timeout_seconds",
})
_CHANNEL_TYPE_KEYS: dict[ChannelType, frozenset[str]] = {
    ChannelType.LOG: frozenset(),
    ChannelType.FILE: frozenset({"path"}),
    ChannelType.WEBHOOK: frozenset({
        "url_env",
        "token_env",
        "allow_insecure_loopback",
    }),
}


# ---------------------------------------------------------------------------
# Scalar checks
# ---------------------------------------------------------------------------

def _require_bool(value: Any, field: str) -> None:
    if not isinstance(value, bool):
        raise PolicyValidationError(
            f"'{field}' must be a boolean, got {type(value).__name__}"
        )


def _require_int(value: Any, field: str) -> None:
    # bool is a subclass of int in Python — must be rejected explicitly.
    if isinstance(value, bool):
        raise PolicyValidationError(f"'{field}' must be an integer, got bool")
    if not isinstance(value, int):
        raise PolicyValidationError(
            f"'{field}' must be an integer, got {type(value).__name__}"
        )


def _require_positive_int(value: Any, field: str) -> None:
    _require_int(value, field)
    if value <= 0:
        raise PolicyValidationError(
            f"'{field}' must be a positive integer (> 0), got {value}"
        )


def _require_non_negative_int(value: Any, field: str) -> None:
    _require_int(value, field)
    if value < 0:
        raise PolicyValidationError(
            f"'{field}' must be a non-negative integer (>= 0), got {value}"
        )


def _require_identifier(value: Any, field: str) -> None:
    try:
        validate_identifier(value, f"'{field}'")
    except ValueError as exc:
        raise PolicyValidationError(str(exc)) from None


def _require_webhook_env_name(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise PolicyValidationError(
            f"'{field}' must be a string, got {type(value).__name__}"
        )
    if _WEBHOOK_ENV_RE.fullmatch(value) is None:
        raise PolicyValidationError(
            f"'{field}' must match ^{WEBHOOK_ENV_PATTERN}$, got {value!r}"
        )


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvaluationPolicy:
    """
    The semantic part of the policy: everything that can change a decision.
    Every field takes part in the policy hash.
    """

    enabled: bool = True
    min_severity: Severity = Severity.WARNING
    max_alert_age_minutes: int = 60
    cooldown_minutes: int = 30
    escalation_breaks_cooldown: bool = True
    max_alerts_per_hour: int = 10
    persist_summary: bool = False

    def __post_init__(self) -> None:
        _require_bool(self.enabled, "evaluation.enabled")
        if not isinstance(self.min_severity, Severity):
            raise PolicyValidationError(
                "'evaluation.min_severity' must be Severity, "
                f"got {type(self.min_severity).__name__}"
            )
        _require_positive_int(
            self.max_alert_age_minutes, "evaluation.max_alert_age_minutes"
        )
        _require_non_negative_int(
            self.cooldown_minutes, "evaluation.cooldown_minutes"
        )
        _require_bool(
            self.escalation_breaks_cooldown, "evaluation.escalation_breaks_cooldown"
        )
        _require_positive_int(
            self.max_alerts_per_hour, "evaluation.max_alerts_per_hour"
        )
        _require_bool(self.persist_summary, "evaluation.persist_summary")


@dataclass(frozen=True)
class ChannelConfig:
    """
    Configuration of one notification channel.  Nothing is sent from here.

    path applies to type 'file' only.  url_env, token_env and
    allow_insecure_loopback apply to type 'webhook' only.
    """

    name: str
    type: ChannelType
    enabled: bool
    include_summary: bool = False
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    path: Optional[str] = None
    url_env: Optional[str] = None
    token_env: Optional[str] = None
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        _require_identifier(self.name, "name")
        if not isinstance(self.type, ChannelType):
            raise PolicyValidationError(
                f"'type' must be ChannelType, got {type(self.type).__name__}"
            )
        _require_bool(self.enabled, "enabled")
        _require_bool(self.include_summary, "include_summary")
        _require_positive_int(self.max_attempts, "max_attempts")
        _require_int(self.timeout_seconds, "timeout_seconds")
        if not MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise PolicyValidationError(
                f"'timeout_seconds' must be between {MIN_TIMEOUT_SECONDS} and "
                f"{MAX_TIMEOUT_SECONDS}, got {self.timeout_seconds}"
            )
        _require_bool(self.allow_insecure_loopback, "allow_insecure_loopback")

        if self.type is ChannelType.FILE:
            if not isinstance(self.path, str):
                raise PolicyValidationError(
                    "'path' is required for a file channel and must be a string"
                )
            if self.path.strip() == "" or "\x00" in self.path:
                raise PolicyValidationError(
                    "'path' must be a non-empty string without NUL characters"
                )
        elif self.path is not None:
            raise PolicyValidationError("'path' applies to a file channel only")

        if self.type is ChannelType.WEBHOOK:
            if self.url_env is None:
                raise PolicyValidationError(
                    "'url_env' is required for a webhook channel"
                )
            _require_webhook_env_name(self.url_env, "url_env")
            if self.token_env is not None:
                _require_webhook_env_name(self.token_env, "token_env")
                if self.token_env == self.url_env:
                    raise PolicyValidationError(
                        "'token_env' must differ from 'url_env'"
                    )
        else:
            if self.url_env is not None:
                raise PolicyValidationError(
                    "'url_env' applies to a webhook channel only"
                )
            if self.token_env is not None:
                raise PolicyValidationError(
                    "'token_env' applies to a webhook channel only"
                )
            if self.allow_insecure_loopback:
                raise PolicyValidationError(
                    "'allow_insecure_loopback' applies to a webhook channel only"
                )


@dataclass(frozen=True)
class DeliveryPolicy:
    """Operational delivery configuration.  Not part of the policy hash."""

    channels: tuple[ChannelConfig, ...]
    max_delivery_age_minutes: int = 60

    def __post_init__(self) -> None:
        _require_positive_int(
            self.max_delivery_age_minutes, "delivery.max_delivery_age_minutes"
        )
        if not isinstance(self.channels, tuple) or not all(
            isinstance(channel, ChannelConfig) for channel in self.channels
        ):
            raise PolicyValidationError(
                "'delivery.channels' must be a tuple of ChannelConfig"
            )
        seen: set[str] = set()
        for channel in self.channels:
            if channel.name in seen:
                raise PolicyValidationError(
                    f"Duplicate channel name in 'delivery.channels': {channel.name!r}"
                )
            seen.add(channel.name)


@dataclass(frozen=True)
class GuardrailPolicy:
    """Thresholds of the report-only guardrails.  Not part of the policy hash."""

    detector_checkpoint_max_age_minutes: int = 1440
    uninvestigated_anomaly_max_age_minutes: int = 60
    delivery_lookback_hours: int = 24

    def __post_init__(self) -> None:
        _require_positive_int(
            self.detector_checkpoint_max_age_minutes,
            "guardrails.detector_checkpoint_max_age_minutes",
        )
        _require_positive_int(
            self.uninvestigated_anomaly_max_age_minutes,
            "guardrails.uninvestigated_anomaly_max_age_minutes",
        )
        _require_positive_int(
            self.delivery_lookback_hours, "guardrails.delivery_lookback_hours"
        )


@dataclass(frozen=True)
class AlertPolicy:
    """
    A complete, validated policy.

    policy_sha256 identifies the evaluation semantics of this policy_version;
    it does not change when only delivery or guardrails change.
    """

    policy_schema_version: str
    policy_version: str
    evaluation: EvaluationPolicy
    delivery: DeliveryPolicy
    guardrails: GuardrailPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.policy_schema_version, str):
            raise PolicyValidationError(
                "'policy_schema_version' must be a string, "
                f"got {type(self.policy_schema_version).__name__}"
            )
        if self.policy_schema_version != POLICY_SCHEMA_VERSION:
            raise PolicyValidationError(
                f"Unsupported policy_schema_version "
                f"{self.policy_schema_version!r}; this version accepts "
                f"{POLICY_SCHEMA_VERSION!r}"
            )
        _require_identifier(self.policy_version, "policy_version")
        for field, expected in (
            ("evaluation", EvaluationPolicy),
            ("delivery", DeliveryPolicy),
            ("guardrails", GuardrailPolicy),
        ):
            if not isinstance(getattr(self, field), expected):
                raise PolicyValidationError(
                    f"'{field}' must be {expected.__name__}"
                )

        if not self.evaluation.persist_summary:
            for channel in self.delivery.channels:
                if channel.include_summary:
                    raise PolicyValidationError(
                        f"Channel {channel.name!r} sets include_summary=true "
                        "but 'evaluation.persist_summary' is false"
                    )

    @property
    def policy_sha256(self) -> str:
        return compute_policy_sha256(
            self.policy_schema_version, self.policy_version, self.evaluation,
        )


# ---------------------------------------------------------------------------
# Policy hash
# ---------------------------------------------------------------------------

def evaluation_hash_object(
    policy_schema_version: str,
    policy_version: str,
    evaluation: EvaluationPolicy,
) -> dict[str, Any]:
    """
    The object whose canonical JSON is hashed: the two versions and the
    evaluation section with every field present.

    Raises:
        PolicyValidationError  if a version is not a non-empty str or
                               evaluation is not an EvaluationPolicy.
    """
    for field, value in (
        ("policy_schema_version", policy_schema_version),
        ("policy_version", policy_version),
    ):
        if not isinstance(value, str) or value == "":
            raise PolicyValidationError(f"'{field}' must be a non-empty string")
    if not isinstance(evaluation, EvaluationPolicy):
        raise PolicyValidationError(
            "'evaluation' must be EvaluationPolicy, "
            f"got {type(evaluation).__name__}"
        )
    return {
        "policy_schema_version": policy_schema_version,
        "policy_version": policy_version,
        "evaluation": {
            "enabled": evaluation.enabled,
            "min_severity": evaluation.min_severity.value,
            "max_alert_age_minutes": evaluation.max_alert_age_minutes,
            "cooldown_minutes": evaluation.cooldown_minutes,
            "escalation_breaks_cooldown": evaluation.escalation_breaks_cooldown,
            "max_alerts_per_hour": evaluation.max_alerts_per_hour,
            "persist_summary": evaluation.persist_summary,
        },
    }


def compute_policy_sha256(
    policy_schema_version: str,
    policy_version: str,
    evaluation: EvaluationPolicy,
) -> str:
    """
    64 lowercase hexadecimal characters: SHA-256 of the sorted-key compact
    JSON of evaluation_hash_object().
    """
    text = json.dumps(
        evaluation_hash_object(policy_schema_version, policy_version, evaluation),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Validation of a parsed JSON object
# ---------------------------------------------------------------------------

def _require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyValidationError(
            f"{where} must be a JSON object, got {type(value).__name__}"
        )
    return value


def _reject_unknown_keys(
    data: dict[str, Any], accepted: frozenset[str], where: str,
) -> None:
    unknown = set(data.keys()) - accepted
    if unknown:
        raise PolicyValidationError(
            f"Unknown key(s) in {where}: {sorted(unknown, key=str)}. "
            f"Accepted keys: {sorted(accepted)}"
        )


def _validate_evaluation(raw: Any) -> EvaluationPolicy:
    section = _require_object(raw, "'evaluation'")
    _reject_unknown_keys(section, _EVALUATION_KEYS, "'evaluation'")
    values = dict(section)

    if "min_severity" in values:
        text = values["min_severity"]
        if not isinstance(text, str):
            raise PolicyValidationError(
                "'evaluation.min_severity' must be a string, "
                f"got {type(text).__name__}"
            )
        try:
            values["min_severity"] = Severity(text)
        except ValueError:
            raise PolicyValidationError(
                f"'evaluation.min_severity' must be one of "
                f"{[s.value for s in Severity]}, got {text!r}"
            ) from None

    return EvaluationPolicy(**values)


def _validate_channel(raw: Any, idx: int) -> ChannelConfig:
    where = f"'delivery.channels[{idx}]'"
    channel = _require_object(raw, where)

    for required in ("name", "type", "enabled"):
        if required not in channel:
            raise PolicyValidationError(f"{where} requires '{required}'")

    type_text = channel["type"]
    if not isinstance(type_text, str):
        raise PolicyValidationError(
            f"{where}: 'type' must be a string, got {type(type_text).__name__}"
        )
    try:
        channel_type = ChannelType(type_text)
    except ValueError:
        raise PolicyValidationError(
            f"{where}: 'type' must be one of "
            f"{[t.value for t in ChannelType]}, got {type_text!r}"
        ) from None

    accepted = _CHANNEL_COMMON_KEYS | _CHANNEL_TYPE_KEYS[channel_type]
    _reject_unknown_keys(
        channel, accepted, f"{where} (type {channel_type.value!r})",
    )

    # An optional key is either absent or set; null is not a way to omit it.
    for key, value in channel.items():
        if value is None:
            raise PolicyValidationError(f"{where}: '{key}' must not be null")

    values = dict(channel)
    values["type"] = channel_type
    try:
        return ChannelConfig(**values)
    except PolicyValidationError as exc:
        raise PolicyValidationError(f"{where}: {exc}") from None


def _validate_delivery(raw: Any) -> DeliveryPolicy:
    section = _require_object(raw, "'delivery'")
    _reject_unknown_keys(section, _DELIVERY_KEYS, "'delivery'")

    if "channels" not in section:
        raise PolicyValidationError("'delivery.channels' is required")
    channels_raw = section["channels"]
    if not isinstance(channels_raw, list):
        raise PolicyValidationError(
            "'delivery.channels' must be a JSON list, "
            f"got {type(channels_raw).__name__}"
        )

    values: dict[str, Any] = {
        "channels": tuple(
            _validate_channel(raw_channel, idx)
            for idx, raw_channel in enumerate(channels_raw)
        ),
    }
    if "max_delivery_age_minutes" in section:
        values["max_delivery_age_minutes"] = section["max_delivery_age_minutes"]
    return DeliveryPolicy(**values)


def _validate_guardrails(raw: Any) -> GuardrailPolicy:
    section = _require_object(raw, "'guardrails'")
    _reject_unknown_keys(section, _GUARDRAIL_KEYS, "'guardrails'")
    return GuardrailPolicy(**section)


def validate_policy(data: Any) -> AlertPolicy:
    """
    Validate a parsed JSON policy object and return an AlertPolicy with every
    default filled in.

    Raises:
        PolicyValidationError  for any structural or semantic violation.
    """
    root = _require_object(data, "Policy root")
    _reject_unknown_keys(root, _ROOT_KEYS, "policy root")
    for required in sorted(_ROOT_KEYS):
        if required not in root:
            raise PolicyValidationError(f"Policy must have '{required}'")

    return AlertPolicy(
        policy_schema_version=root["policy_schema_version"],
        policy_version=root["policy_version"],
        evaluation=_validate_evaluation(root["evaluation"]),
        delivery=_validate_delivery(root["delivery"]),
        guardrails=_validate_guardrails(root["guardrails"]),
    )


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------

def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyValidationError(f"Duplicate key in policy JSON: {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise PolicyValidationError(f"Policy JSON must not contain {name}")


def parse_policy(text: str) -> AlertPolicy:
    """
    Parse and validate a policy from JSON text.

    Raises:
        json.JSONDecodeError   text is not valid JSON.
        PolicyValidationError  the policy is invalid, repeats a key, or holds
                               NaN or Infinity.
    """
    if not isinstance(text, str):
        raise PolicyValidationError(
            f"Policy text must be str, got {type(text).__name__}"
        )
    data = json.loads(
        text,
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_constant,
    )
    return validate_policy(data)


def load_policy(path: str | os.PathLike) -> AlertPolicy:
    """
    Load and validate a policy from a JSON file at path.

    Raises:
        FileNotFoundError:     path does not exist.
        json.JSONDecodeError:  file is not valid JSON.
        PolicyValidationError: the policy is invalid (a ValueError).
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return parse_policy(text)
