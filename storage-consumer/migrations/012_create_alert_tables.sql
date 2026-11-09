-- Migration: 012_create_alert_tables
-- Phase 13.2: Alerting persistence tables
--
-- Creates the four tables that hold alert policies, alert decisions, and the
-- delivery audit trail:
--
--   public.alert_policies           — one row per policy_version
--   public.alert_decisions          — one row per (investigation, policy_version)
--   public.alert_delivery_attempts  — one row per delivery attempt
--   public.alert_delivery_outcomes  — at most one row per delivery attempt
--
-- All four tables are append-only.  Rows are inserted with
-- ON CONFLICT DO NOTHING (first-write-wins) and are never changed or removed
-- afterwards, consistent with the anomaly_events and rca_* contracts.
--
-- This migration creates tables and indexes only.  It grants nothing: the
-- roles and their privileges are created in migrations 013 and 014.
--
-- Apply AFTER 007_create_rca_tables.sql (FK requires the table):
--   psql -h localhost -U agentops -d agentops \
--     -f storage-consumer/migrations/012_create_alert_tables.sql
--
-- Intentionally uses CREATE TABLE (not IF NOT EXISTS) so that accidental
-- re-runs or schema drift are caught immediately as an error rather than
-- silently skipped.
--
-- Identities (computed by alerting/alert_identity.py, never by the database):
--   decision_id = SHA-256 of canonical
--                 ["agentops.alert.decision.v1", investigation_id, policy_version]
--   dedup_key   = SHA-256 of canonical
--                 ["agentops.alert.dedup.v1", anomaly_type, service_name,
--                  operation_name]
--   attempt_id  = SHA-256 of canonical
--                 ["agentops.alert.attempt.v1", decision_id, channel_name,
--                  attempt_no]
-- The database checks the digest format only; it does not recompute a digest.

-- ---------------------------------------------------------------------------
-- alert_policies
-- ---------------------------------------------------------------------------
--
-- Registry of policy versions.  The primary key makes it impossible to store
-- the same policy_version with two different hashes, so one policy_version
-- can never mean two different sets of evaluation rules.

CREATE TABLE public.alert_policies (
    -- Policy version identifier from the policy file.
    policy_version          TEXT                NOT NULL,

    -- SHA-256 of the canonical evaluation semantics of this policy version
    -- (policy_schema_version, policy_version, and the evaluation section with
    -- every default written out).  Delivery and guardrail settings are not
    -- part of it.
    policy_sha256           TEXT                NOT NULL,

    -- The canonical evaluation object that policy_sha256 was computed from,
    -- kept for audit.
    policy_json             JSONB               NOT NULL,

    -- Wall-clock time when this policy version was first registered.
    registered_at           TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_alert_policies
        PRIMARY KEY (policy_version),

    CONSTRAINT chk_alert_policies_policy_sha256
        CHECK (policy_sha256 ~ '^[0-9a-f]{64}$')
);


-- ---------------------------------------------------------------------------
-- alert_decisions
-- ---------------------------------------------------------------------------
--
-- One immutable decision per RCA investigation per policy version.  Every
-- evaluated investigation gets a row, whether or not it becomes an alert.

CREATE TABLE public.alert_decisions (
    -- Deterministic identity; exactly 64 lowercase hexadecimal characters.
    decision_id             TEXT                NOT NULL,

    -- Investigation that was evaluated.
    investigation_id        TEXT                NOT NULL,

    -- Policy version the decision was made under.
    policy_version          TEXT                NOT NULL,

    -- Snapshot of the investigation at evaluation time (denormalized;
    -- rca_investigations is the authoritative source).
    anomaly_id              TEXT                NOT NULL,
    anomaly_type            TEXT                NOT NULL,
    service_name            TEXT,
    operation_name          TEXT,
    event_time              TIMESTAMPTZ         NOT NULL,
    severity                TEXT                NOT NULL,

    -- RCA confidence and limitations are recorded for information only.
    -- They never take part in the decision.
    confidence              TEXT                NOT NULL,
    limitations             TEXT[]              NOT NULL DEFAULT '{}',

    -- Deduplication key of the incident stream:
    -- (anomaly_type, service_name, operation_name).
    dedup_key               TEXT                NOT NULL,

    -- Verdict
    decision                TEXT                NOT NULL,
    reason_code             TEXT                NOT NULL,

    -- The earlier decision this one refers to: the alert that suppressed it
    -- (cooldown, duplicate_anomaly) or the alert it escalates over.
    related_decision_id     TEXT,

    -- The evaluation clock value used for this decision.
    evaluated_at            TIMESTAMPTZ         NOT NULL,

    -- Notification payload snapshot; present exactly when decision = 'ALERT'.
    -- The notifier sends this snapshot and never reads RCA tables.
    payload                 JSONB,

    -- RCA summary text, kept apart from payload because it is free text.
    -- NULL unless the policy persists summaries.
    summary                 TEXT,
    summary_truncated       BOOLEAN             NOT NULL DEFAULT FALSE,

    -- Wall-clock time when this decision was written to this table.
    decided_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    -- -----------------------------------------------------------------------
    -- Constraints
    -- -----------------------------------------------------------------------

    CONSTRAINT pk_alert_decisions
        PRIMARY KEY (decision_id),

    -- RESTRICT: an investigation cannot be removed while a decision refers to it.
    CONSTRAINT fk_alert_decisions_investigation
        FOREIGN KEY (investigation_id)
        REFERENCES public.rca_investigations (investigation_id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_alert_decisions_policy
        FOREIGN KEY (policy_version)
        REFERENCES public.alert_policies (policy_version)
        ON DELETE RESTRICT,

    CONSTRAINT fk_alert_decisions_related_decision
        FOREIGN KEY (related_decision_id)
        REFERENCES public.alert_decisions (decision_id)
        ON DELETE RESTRICT,

    -- One decision per investigation per policy version.
    CONSTRAINT uq_alert_decisions_investigation_policy
        UNIQUE (investigation_id, policy_version),

    CONSTRAINT chk_alert_decisions_decision_id
        CHECK (decision_id ~ '^[0-9a-f]{64}$'),

    CONSTRAINT chk_alert_decisions_dedup_key
        CHECK (dedup_key ~ '^[0-9a-f]{64}$'),

    -- Allowed severity values mirror rca_investigations severity.
    CONSTRAINT chk_alert_decisions_severity
        CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),

    -- Allowed confidence values mirror rca_investigations confidence.
    CONSTRAINT chk_alert_decisions_confidence
        CHECK (confidence IN (
            'HIGH',
            'MEDIUM',
            'LOW',
            'INSUFFICIENT_DATA'
        )),

    CONSTRAINT chk_alert_decisions_decision
        CHECK (decision IN ('ALERT', 'SUPPRESSED', 'NOT_ALERTABLE')),

    CONSTRAINT chk_alert_decisions_reason_code
        CHECK (reason_code IN (
            'severity_met',
            'escalation',
            'kill_switch',
            'duplicate_anomaly',
            'cooldown',
            'storm_cap',
            'below_min_severity',
            'stale'
        )),

    -- Each decision may carry only its own reason codes.
    CONSTRAINT chk_alert_decisions_decision_reason
        CHECK (
            (decision = 'ALERT'
                AND reason_code IN ('severity_met', 'escalation'))
            OR (decision = 'SUPPRESSED'
                AND reason_code IN (
                    'kill_switch',
                    'duplicate_anomaly',
                    'cooldown',
                    'storm_cap'
                ))
            OR (decision = 'NOT_ALERTABLE'
                AND reason_code IN ('below_min_severity', 'stale'))
        ),

    -- related_decision_id is present exactly for the reasons that refer to
    -- another decision.
    CONSTRAINT chk_alert_decisions_related_decision_required
        CHECK (
            (reason_code IN ('escalation', 'duplicate_anomaly', 'cooldown'))
            = (related_decision_id IS NOT NULL)
        ),

    CONSTRAINT chk_alert_decisions_related_decision_not_self
        CHECK (related_decision_id IS NULL OR related_decision_id <> decision_id),

    -- A payload exists exactly when the decision is an alert.
    CONSTRAINT chk_alert_decisions_payload_iff_alert
        CHECK ((decision = 'ALERT') = (payload IS NOT NULL)),

    CONSTRAINT chk_alert_decisions_summary_only_for_alert
        CHECK (summary IS NULL OR decision = 'ALERT'),

    CONSTRAINT chk_alert_decisions_summary_truncated
        CHECK (NOT summary_truncated OR summary IS NOT NULL)
);

-- Cooldown lookups: earlier alerts of the same incident stream in a window of
-- event_time.  Partial: only alerts take part in cooldown.
CREATE INDEX idx_alert_decisions_alert_dedup_event_time
    ON public.alert_decisions (dedup_key, event_time)
    WHERE decision = 'ALERT';

-- Storm-cap lookups: all alerts in a window of event_time.
CREATE INDEX idx_alert_decisions_alert_event_time
    ON public.alert_decisions (event_time)
    WHERE decision = 'ALERT';

-- Duplicate lookups: has this anomaly already produced an alert.
CREATE INDEX idx_alert_decisions_alert_anomaly_id
    ON public.alert_decisions (anomaly_id)
    WHERE decision = 'ALERT';


-- ---------------------------------------------------------------------------
-- alert_delivery_attempts
-- ---------------------------------------------------------------------------
--
-- One row per attempt to deliver one decision to one channel.  The row is
-- inserted and committed BEFORE anything is sent, so it is the durable
-- "started" record of the attempt.  There is no separate started event.
--
-- The attempt's identity does not depend on how the attempt ends.  Its result
-- is recorded in alert_delivery_outcomes.  An attempt with no outcome row is
-- one whose result is unknown.

CREATE TABLE public.alert_delivery_attempts (
    -- Deterministic identity; exactly 64 lowercase hexadecimal characters.
    attempt_id              TEXT                NOT NULL,

    -- Decision being delivered.
    decision_id             TEXT                NOT NULL,

    -- Channel name and type from the policy at the time of the attempt.
    channel_name            TEXT                NOT NULL,
    channel_type            TEXT                NOT NULL,

    -- 1 for the first attempt on this channel, then 2, 3, ...
    attempt_no              INTEGER             NOT NULL,

    -- 'auto' for an attempt made by the notifier on its own; 'operator' for
    -- an explicit operator retry.
    trigger                 TEXT                NOT NULL,

    -- Whether the body sent in this attempt included the summary.
    summary_included        BOOLEAN             NOT NULL,

    -- SHA-256 of the exact body bytes of this attempt.
    payload_sha256          TEXT                NOT NULL,

    -- Wall-clock time when the attempt was recorded, before sending.
    started_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_alert_delivery_attempts
        PRIMARY KEY (attempt_id),

    CONSTRAINT fk_alert_delivery_attempts_decision
        FOREIGN KEY (decision_id)
        REFERENCES public.alert_decisions (decision_id)
        ON DELETE RESTRICT,

    -- Two invocations can never both own the same attempt number.
    CONSTRAINT uq_alert_delivery_attempts_decision_channel_no
        UNIQUE (decision_id, channel_name, attempt_no),

    CONSTRAINT chk_alert_delivery_attempts_attempt_id
        CHECK (attempt_id ~ '^[0-9a-f]{64}$'),

    CONSTRAINT chk_alert_delivery_attempts_payload_sha256
        CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT chk_alert_delivery_attempts_channel_type
        CHECK (channel_type IN ('log', 'file', 'webhook')),

    CONSTRAINT chk_alert_delivery_attempts_attempt_no
        CHECK (attempt_no >= 1),

    CONSTRAINT chk_alert_delivery_attempts_trigger
        CHECK (trigger IN ('auto', 'operator'))
);


-- ---------------------------------------------------------------------------
-- alert_delivery_outcomes
-- ---------------------------------------------------------------------------
--
-- The recorded result of a delivery attempt.  attempt_id is the primary key,
-- so an attempt has zero or one outcome.

CREATE TABLE public.alert_delivery_outcomes (
    -- Attempt this outcome belongs to.
    attempt_id              TEXT                NOT NULL,

    outcome                 TEXT                NOT NULL,

    -- Short result code, e.g. 'http_503'.  Never a URL, a header, or a
    -- response body.
    detail                  TEXT,

    -- Wall-clock time when the outcome was recorded.
    recorded_at             TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_alert_delivery_outcomes
        PRIMARY KEY (attempt_id),

    CONSTRAINT fk_alert_delivery_outcomes_attempt
        FOREIGN KEY (attempt_id)
        REFERENCES public.alert_delivery_attempts (attempt_id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_alert_delivery_outcomes_outcome
        CHECK (outcome IN (
            'SENT',
            'FAILED_RETRYABLE',
            'FAILED_PERMANENT',
            'UNCERTAIN'
        ))
);
