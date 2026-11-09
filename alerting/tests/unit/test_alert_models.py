"""
Tests for alerting/alert_models.py and alerting/alert_version.py

No database, no network, no environment variables.

Coverage:
    1. Version constants
    2. Enum exact values and membership
    3. Severity ordering
    4. Decision / reason pairing tables
    5. AlertDecision: immutability and record invariants
    6. DeliveryAttempt and DeliveryOutcomeRecord
    7. GuardrailFinding
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import datetime, timezone

import pytest

import alert_models
import alert_version
from alert_models import (
    REASONS_BY_DECISION,
    REASONS_WITH_RELATED_DECISION,
    AlertDecision,
    ChannelType,
    Confidence,
    Decision,
    DeliveryAttempt,
    DeliveryOutcome,
    DeliveryOutcomeRecord,
    DeliveryTrigger,
    GuardrailFinding,
    GuardrailStatus,
    ReasonCode,
    Severity,
    severity_rank,
)

_T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 10, 5, 12, 5, 0, tzinfo=timezone.utc)

_DEC = "d" * 64
_OTHER = "e" * 64


def _decision(**overrides):
    values = dict(
        decision_id=_DEC,
        investigation_id="1" * 64,
        policy_version="1.0.0",
        anomaly_id="2" * 64,
        anomaly_type="latency",
        service_name="agentops-demo-app",
        operation_name="agentops.request",
        event_time=_T0,
        severity=Severity.CRITICAL,
        confidence=Confidence.LOW,
        limitations=("direct_subject_absent",),
        dedup_key="3" * 64,
        decision=Decision.ALERT,
        reason_code=ReasonCode.SEVERITY_MET,
        related_decision_id=None,
        evaluated_at=_T1,
        payload={"payload_version": "1.0.0", "severity": "CRITICAL"},
    )
    values.update(overrides)
    return AlertDecision(**values)


def _suppressed(**overrides):
    values = dict(
        decision=Decision.SUPPRESSED,
        reason_code=ReasonCode.STORM_CAP,
        payload=None,
    )
    values.update(overrides)
    return _decision(**values)


def _attempt(**overrides):
    values = dict(
        attempt_id="4" * 64,
        decision_id=_DEC,
        channel_name="log",
        channel_type=ChannelType.LOG,
        attempt_no=1,
        trigger=DeliveryTrigger.AUTO,
        summary_included=False,
        payload_sha256="5" * 64,
        started_at=_T1,
    )
    values.update(overrides)
    return DeliveryAttempt(**values)


# ---------------------------------------------------------------------------
# 1. Versions
# ---------------------------------------------------------------------------

class TestVersions:
    def test_policy_schema_version(self):
        assert alert_version.POLICY_SCHEMA_VERSION == "1.0.0"

    def test_payload_version(self):
        assert alert_version.PAYLOAD_VERSION == "1.0.0"

    def test_only_the_two_contract_versions_are_defined(self):
        constants = {
            name for name in vars(alert_version)
            if name.isupper()
        }
        assert constants == {"POLICY_SCHEMA_VERSION", "PAYLOAD_VERSION"}


# ---------------------------------------------------------------------------
# 2. Enums
# ---------------------------------------------------------------------------

class TestEnumValues:
    @pytest.mark.parametrize("enum_type, expected", [
        (Severity, {"INFO", "WARNING", "CRITICAL"}),
        (Confidence, {"HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA"}),
        (Decision, {"ALERT", "SUPPRESSED", "NOT_ALERTABLE"}),
        (ReasonCode, {
            "severity_met", "escalation", "kill_switch", "duplicate_anomaly",
            "cooldown", "storm_cap", "below_min_severity", "stale",
        }),
        (ChannelType, {"log", "file", "webhook"}),
        (DeliveryOutcome, {
            "SENT", "FAILED_RETRYABLE", "FAILED_PERMANENT", "UNCERTAIN",
        }),
        (DeliveryTrigger, {"auto", "operator"}),
        (GuardrailStatus, {"OK", "VIOLATION"}),
    ])
    def test_exact_value_set(self, enum_type, expected):
        assert {member.value for member in enum_type} == expected

    def test_lookup_by_value(self):
        assert Severity("WARNING") is Severity.WARNING
        assert ReasonCode("storm_cap") is ReasonCode.STORM_CAP
        assert ChannelType("webhook") is ChannelType.WEBHOOK

    @pytest.mark.parametrize("enum_type, bad", [
        (Severity, "warning"),
        (Severity, "FATAL"),
        (Confidence, "insufficient_data"),
        (Decision, "alert"),
        (ReasonCode, "COOLDOWN"),
        (ChannelType, "slack"),
        (ChannelType, "LOG"),
        (DeliveryOutcome, "STARTED"),
        (DeliveryTrigger, "manual"),
        (GuardrailStatus, "WARN"),
    ])
    def test_unknown_or_miscased_value_rejected(self, enum_type, bad):
        with pytest.raises(ValueError):
            enum_type(bad)

    def test_started_is_not_an_outcome(self):
        assert "STARTED" not in {member.value for member in DeliveryOutcome}


# ---------------------------------------------------------------------------
# 3. Severity ordering
# ---------------------------------------------------------------------------

class TestSeverityRank:
    def test_strict_order(self):
        assert (
            severity_rank(Severity.INFO)
            < severity_rank(Severity.WARNING)
            < severity_rank(Severity.CRITICAL)
        )

    def test_exact_ranks(self):
        assert [severity_rank(s) for s in (
            Severity.INFO, Severity.WARNING, Severity.CRITICAL,
        )] == [0, 1, 2]

    @pytest.mark.parametrize("bad", ["WARNING", 1, None, Confidence.HIGH])
    def test_non_severity_rejected(self, bad):
        with pytest.raises(ValueError, match="Severity"):
            severity_rank(bad)


# ---------------------------------------------------------------------------
# 4. Pairing tables
# ---------------------------------------------------------------------------

class TestPairing:
    def test_alert_reasons(self):
        assert REASONS_BY_DECISION[Decision.ALERT] == {
            ReasonCode.SEVERITY_MET, ReasonCode.ESCALATION,
        }

    def test_suppressed_reasons(self):
        assert REASONS_BY_DECISION[Decision.SUPPRESSED] == {
            ReasonCode.KILL_SWITCH, ReasonCode.DUPLICATE_ANOMALY,
            ReasonCode.COOLDOWN, ReasonCode.STORM_CAP,
        }

    def test_not_alertable_reasons(self):
        assert REASONS_BY_DECISION[Decision.NOT_ALERTABLE] == {
            ReasonCode.BELOW_MIN_SEVERITY, ReasonCode.STALE,
        }

    def test_every_reason_belongs_to_exactly_one_decision(self):
        seen = [
            reason
            for reasons in REASONS_BY_DECISION.values()
            for reason in reasons
        ]
        assert len(seen) == len(set(seen))
        assert set(seen) == set(ReasonCode)

    def test_every_decision_is_covered(self):
        assert set(REASONS_BY_DECISION) == set(Decision)

    def test_table_is_read_only(self):
        with pytest.raises(TypeError):
            REASONS_BY_DECISION[Decision.ALERT] = frozenset()

    def test_reasons_with_related_decision(self):
        assert REASONS_WITH_RELATED_DECISION == {
            ReasonCode.ESCALATION, ReasonCode.DUPLICATE_ANOMALY, ReasonCode.COOLDOWN,
        }


# ---------------------------------------------------------------------------
# 5. AlertDecision
# ---------------------------------------------------------------------------

class TestAlertDecisionImmutability:
    def test_frozen(self):
        decision = _decision()
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.decision = Decision.SUPPRESSED

    def test_cannot_delete_a_field(self):
        decision = _decision()
        with pytest.raises(dataclasses.FrozenInstanceError):
            del decision.severity

    def test_payload_is_read_only(self):
        decision = _decision()
        with pytest.raises(TypeError):
            decision.payload["severity"] = "INFO"

    def test_payload_is_detached_from_the_source_dict(self):
        source = {"payload_version": "1.0.0"}
        decision = _decision(payload=source)
        source["added"] = "later"
        assert "added" not in decision.payload

    def test_equal_records_are_equal(self):
        assert _decision() == _decision()


class TestAlertDecisionPairing:
    @pytest.mark.parametrize("decision, reason", [
        (decision, reason)
        for decision in Decision
        for reason in ReasonCode
        if reason not in REASONS_BY_DECISION[decision]
    ])
    def test_invalid_pairs_rejected(self, decision, reason):
        related = _OTHER if reason in REASONS_WITH_RELATED_DECISION else None
        payload = {"k": "v"} if decision is Decision.ALERT else None
        with pytest.raises(ValueError, match="is not valid for decision"):
            _decision(
                decision=decision, reason_code=reason,
                related_decision_id=related, payload=payload,
            )

    @pytest.mark.parametrize("decision, reason", [
        (decision, reason)
        for decision in Decision
        for reason in REASONS_BY_DECISION[decision]
    ])
    def test_valid_pairs_accepted(self, decision, reason):
        related = _OTHER if reason in REASONS_WITH_RELATED_DECISION else None
        payload = {"k": "v"} if decision is Decision.ALERT else None
        record = _decision(
            decision=decision, reason_code=reason,
            related_decision_id=related, payload=payload,
        )
        assert record.decision is decision
        assert record.reason_code is reason


class TestAlertDecisionConfidenceIsInformational:
    @pytest.mark.parametrize("confidence", list(Confidence))
    def test_every_confidence_can_be_an_alert(self, confidence):
        assert _decision(confidence=confidence).decision is Decision.ALERT

    @pytest.mark.parametrize("confidence", list(Confidence))
    @pytest.mark.parametrize("severity", list(Severity))
    def test_no_confidence_severity_combination_is_rejected(self, confidence, severity):
        record = _decision(confidence=confidence, severity=severity)
        assert record.confidence is confidence
        assert record.severity is severity


class TestAlertDecisionRelatedDecision:
    @pytest.mark.parametrize("reason, decision", [
        (ReasonCode.ESCALATION, Decision.ALERT),
        (ReasonCode.COOLDOWN, Decision.SUPPRESSED),
        (ReasonCode.DUPLICATE_ANOMALY, Decision.SUPPRESSED),
    ])
    def test_required_for_relating_reasons(self, reason, decision):
        payload = {"k": "v"} if decision is Decision.ALERT else None
        with pytest.raises(ValueError, match="related_decision_id"):
            _decision(
                decision=decision, reason_code=reason,
                related_decision_id=None, payload=payload,
            )

    @pytest.mark.parametrize("reason, decision", [
        (ReasonCode.SEVERITY_MET, Decision.ALERT),
        (ReasonCode.KILL_SWITCH, Decision.SUPPRESSED),
        (ReasonCode.STORM_CAP, Decision.SUPPRESSED),
        (ReasonCode.BELOW_MIN_SEVERITY, Decision.NOT_ALERTABLE),
        (ReasonCode.STALE, Decision.NOT_ALERTABLE),
    ])
    def test_forbidden_for_other_reasons(self, reason, decision):
        payload = {"k": "v"} if decision is Decision.ALERT else None
        with pytest.raises(ValueError, match="related_decision_id must be None"):
            _decision(
                decision=decision, reason_code=reason,
                related_decision_id=_OTHER, payload=payload,
            )

    def test_must_not_be_the_decision_itself(self):
        with pytest.raises(ValueError, match="itself"):
            _suppressed(reason_code=ReasonCode.COOLDOWN, related_decision_id=_DEC)

    def test_must_be_a_digest(self):
        with pytest.raises(ValueError, match="related_decision_id"):
            _suppressed(reason_code=ReasonCode.COOLDOWN, related_decision_id="abc")


class TestAlertDecisionPayloadAndSummary:
    def test_alert_requires_payload(self):
        with pytest.raises(ValueError, match="payload must be a mapping"):
            _decision(payload=None)

    @pytest.mark.parametrize("bad", ["text", ["a"], 5])
    def test_alert_payload_must_be_mapping(self, bad):
        with pytest.raises(ValueError, match="payload must be a mapping"):
            _decision(payload=bad)

    @pytest.mark.parametrize("decision, reason", [
        (Decision.SUPPRESSED, ReasonCode.STORM_CAP),
        (Decision.NOT_ALERTABLE, ReasonCode.STALE),
    ])
    def test_non_alert_must_not_carry_payload(self, decision, reason):
        with pytest.raises(ValueError, match="payload must be None"):
            _decision(decision=decision, reason_code=reason, payload={"k": "v"})

    @pytest.mark.parametrize("decision, reason", [
        (Decision.SUPPRESSED, ReasonCode.STORM_CAP),
        (Decision.NOT_ALERTABLE, ReasonCode.STALE),
    ])
    def test_non_alert_must_not_carry_summary(self, decision, reason):
        with pytest.raises(ValueError, match="summary must be None"):
            _decision(
                decision=decision, reason_code=reason, payload=None,
                summary="text",
            )

    def test_summary_defaults_to_absent(self):
        record = _decision()
        assert record.summary is None
        assert record.summary_truncated is False

    def test_alert_may_carry_summary(self):
        record = _decision(summary="Span 'x' showed evidence.", summary_truncated=True)
        assert record.summary == "Span 'x' showed evidence."

    def test_truncated_flag_requires_summary(self):
        with pytest.raises(ValueError, match="summary_truncated requires"):
            _decision(summary=None, summary_truncated=True)

    def test_summary_is_not_part_of_payload(self):
        record = _decision(summary="free text")
        assert "summary" not in record.payload


class TestAlertDecisionFieldValidation:
    @pytest.mark.parametrize("field", [
        "decision_id", "investigation_id", "anomaly_id", "dedup_key",
    ])
    @pytest.mark.parametrize("bad", ["", "abc", "A" * 64, "a" * 63, None, 7])
    def test_digest_fields(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _decision(**{field: bad})

    @pytest.mark.parametrize("bad", ["", "v 1", "x" * 65, None])
    def test_policy_version(self, bad):
        with pytest.raises(ValueError, match="policy_version"):
            _decision(policy_version=bad)

    @pytest.mark.parametrize("bad", ["", None, 3])
    def test_anomaly_type(self, bad):
        with pytest.raises(ValueError, match="anomaly_type"):
            _decision(anomaly_type=bad)

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    def test_nullable_names_accept_none(self, field):
        assert getattr(_decision(**{field: None}), field) is None

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    def test_nullable_names_reject_non_str(self, field):
        with pytest.raises(ValueError, match=field):
            _decision(**{field: 5})

    @pytest.mark.parametrize("field", ["event_time", "evaluated_at"])
    def test_naive_datetime_rejected(self, field):
        with pytest.raises(ValueError, match="timezone-aware"):
            _decision(**{field: datetime(2026, 10, 5, 12, 0, 0)})

    @pytest.mark.parametrize("field", ["event_time", "evaluated_at"])
    @pytest.mark.parametrize("bad", ["2026-10-05T12:00:00Z", 0, None])
    def test_non_datetime_rejected(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _decision(**{field: bad})

    @pytest.mark.parametrize("field, bad", [
        ("severity", "CRITICAL"),
        ("confidence", "LOW"),
        ("decision", "ALERT"),
        ("reason_code", "severity_met"),
    ])
    def test_enum_fields_reject_plain_strings(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _decision(**{field: bad})

    @pytest.mark.parametrize("bad", [["a"], "a", ("a", 1), None])
    def test_limitations_must_be_tuple_of_str(self, bad):
        with pytest.raises(ValueError, match="limitations"):
            _decision(limitations=bad)

    def test_empty_limitations_accepted(self):
        assert _decision(limitations=()).limitations == ()

    @pytest.mark.parametrize("bad", [1, "false", None])
    def test_summary_truncated_must_be_bool(self, bad):
        with pytest.raises(ValueError, match="summary_truncated"):
            _decision(summary="x", summary_truncated=bad)


# ---------------------------------------------------------------------------
# 6. Delivery records
# ---------------------------------------------------------------------------

class TestDeliveryAttempt:
    def test_valid(self):
        attempt = _attempt()
        assert attempt.attempt_no == 1
        assert attempt.trigger is DeliveryTrigger.AUTO

    def test_frozen(self):
        attempt = _attempt()
        with pytest.raises(dataclasses.FrozenInstanceError):
            attempt.attempt_no = 2

    def test_has_no_state_or_outcome_field(self):
        names = {field.name for field in dataclasses.fields(DeliveryAttempt)}
        assert names.isdisjoint({"state", "status", "outcome", "phase"})

    @pytest.mark.parametrize("bad", [0, -1])
    def test_attempt_no_below_one_rejected(self, bad):
        with pytest.raises(ValueError, match=">= 1"):
            _attempt(attempt_no=bad)

    @pytest.mark.parametrize("bad", [True, 1.0, "1", None])
    def test_attempt_no_must_be_int(self, bad):
        with pytest.raises(ValueError, match="attempt_no must be int"):
            _attempt(attempt_no=bad)

    @pytest.mark.parametrize("field", ["attempt_id", "decision_id", "payload_sha256"])
    def test_digest_fields(self, field):
        with pytest.raises(ValueError, match=field):
            _attempt(**{field: "abc"})

    @pytest.mark.parametrize("bad", ["", "my channel", None])
    def test_channel_name(self, bad):
        with pytest.raises(ValueError, match="channel_name"):
            _attempt(channel_name=bad)

    @pytest.mark.parametrize("field, bad", [
        ("channel_type", "log"),
        ("trigger", "auto"),
    ])
    def test_enum_fields_reject_plain_strings(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _attempt(**{field: bad})

    @pytest.mark.parametrize("bad", [0, "false", None])
    def test_summary_included_must_be_bool(self, bad):
        with pytest.raises(ValueError, match="summary_included"):
            _attempt(summary_included=bad)

    def test_naive_started_at_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            _attempt(started_at=datetime(2026, 10, 5))


class TestDeliveryOutcomeRecord:
    @pytest.mark.parametrize("outcome", list(DeliveryOutcome))
    def test_every_outcome_accepted(self, outcome):
        record = DeliveryOutcomeRecord(
            attempt_id="4" * 64, outcome=outcome, detail=None, recorded_at=_T1,
        )
        assert record.outcome is outcome

    def test_detail_kept(self):
        record = DeliveryOutcomeRecord(
            attempt_id="4" * 64, outcome=DeliveryOutcome.FAILED_RETRYABLE,
            detail="http_503", recorded_at=_T1,
        )
        assert record.detail == "http_503"

    def test_frozen(self):
        record = DeliveryOutcomeRecord(
            attempt_id="4" * 64, outcome=DeliveryOutcome.SENT, detail=None,
            recorded_at=_T1,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.outcome = DeliveryOutcome.UNCERTAIN

    def test_invalid_attempt_id(self):
        with pytest.raises(ValueError, match="attempt_id"):
            DeliveryOutcomeRecord(
                attempt_id="abc", outcome=DeliveryOutcome.SENT, detail=None,
                recorded_at=_T1,
            )

    def test_outcome_must_be_enum(self):
        with pytest.raises(ValueError, match="outcome"):
            DeliveryOutcomeRecord(
                attempt_id="4" * 64, outcome="SENT", detail=None, recorded_at=_T1,
            )

    def test_detail_must_be_str_or_none(self):
        with pytest.raises(ValueError, match="detail"):
            DeliveryOutcomeRecord(
                attempt_id="4" * 64, outcome=DeliveryOutcome.SENT, detail=503,
                recorded_at=_T1,
            )

    def test_naive_recorded_at_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            DeliveryOutcomeRecord(
                attempt_id="4" * 64, outcome=DeliveryOutcome.SENT, detail=None,
                recorded_at=datetime(2026, 10, 5),
            )


# ---------------------------------------------------------------------------
# 7. GuardrailFinding
# ---------------------------------------------------------------------------

class TestGuardrailFinding:
    def test_ok(self):
        finding = GuardrailFinding(
            code="delivery_uncertain", status=GuardrailStatus.OK, count=0, detail="",
        )
        assert finding.status is GuardrailStatus.OK

    def test_violation(self):
        finding = GuardrailFinding(
            code="uninvestigated_anomalies", status=GuardrailStatus.VIOLATION,
            count=3, detail="3 anomalies",
        )
        assert finding.count == 3

    def test_violation_with_zero_count_allowed(self):
        finding = GuardrailFinding(
            code="detector_checkpoint_stale", status=GuardrailStatus.VIOLATION,
            count=0, detail="no checkpoint rows",
        )
        assert finding.count == 0

    def test_frozen(self):
        finding = GuardrailFinding(
            code="x", status=GuardrailStatus.OK, count=0, detail="",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            finding.status = GuardrailStatus.VIOLATION

    def test_ok_with_nonzero_count_rejected(self):
        with pytest.raises(ValueError, match="count must be 0"):
            GuardrailFinding(code="x", status=GuardrailStatus.OK, count=1, detail="")

    @pytest.mark.parametrize("bad", [-1, True, 1.0, "1", None])
    def test_invalid_count(self, bad):
        with pytest.raises(ValueError, match="count"):
            GuardrailFinding(
                code="x", status=GuardrailStatus.VIOLATION, count=bad, detail="",
            )

    @pytest.mark.parametrize("bad", ["", None, 1])
    def test_invalid_code(self, bad):
        with pytest.raises(ValueError, match="code"):
            GuardrailFinding(code=bad, status=GuardrailStatus.OK, count=0, detail="")

    def test_status_must_be_enum(self):
        with pytest.raises(ValueError, match="status"):
            GuardrailFinding(code="x", status="OK", count=0, detail="")

    def test_detail_must_be_str(self):
        with pytest.raises(ValueError, match="detail"):
            GuardrailFinding(
                code="x", status=GuardrailStatus.OK, count=0, detail=None,
            )


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------

class TestModuleBoundary:
    def test_all_models_are_frozen_dataclasses(self):
        for model in (
            AlertDecision, DeliveryAttempt, DeliveryOutcomeRecord, GuardrailFinding,
        ):
            assert dataclasses.is_dataclass(model)
            assert model.__dataclass_params__.frozen is True

    def test_no_database_or_network_imports(self):
        source = inspect.getsource(alert_models)
        for forbidden in ("psycopg", "urllib", "http.client", "socket", "requests"):
            assert forbidden not in source
