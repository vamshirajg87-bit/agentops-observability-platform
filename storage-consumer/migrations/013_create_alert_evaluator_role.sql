-- Migration: 013_create_alert_evaluator_role
-- Phase 13.2: Least-privilege database role for the alert evaluator
--
-- Creates a dedicated role for alert evaluation and for the report-only
-- guardrail checks.
-- This role is separate from alert_notifier to follow least-privilege:
--   - The evaluator reads RCA investigations and writes alert decisions.  It
--     sends nothing and holds no notification secret.
--   - The notifier (migration 014) holds the channel credentials and cannot
--     read RCA or anomaly data.
--
-- Apply AFTER 012_create_alert_tables.sql (grants require the tables):
--   psql -h localhost -U agentops -d agentops \
--     -v alert_evaluator_password='<password>' \
--     -f storage-consumer/migrations/013_create_alert_evaluator_role.sql
--
-- The password supplied here must match ALERT_EVALUATOR_DB_PASSWORD in .env.

CREATE ROLE alert_evaluator WITH LOGIN PASSWORD :'alert_evaluator_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO alert_evaluator;

-- Allow the role to see objects in the public schema (PostgreSQL 15+ does not
-- grant public schema USAGE to PUBLIC by default).
GRANT USAGE ON SCHEMA public TO alert_evaluator;

-- Read access: investigation fields used to evaluate and to build the
-- decision snapshot.
-- Column-level SELECT only; exactly these 10 columns.
GRANT SELECT (
    investigation_id,
    anomaly_id,
    anomaly_type,
    service_name,
    operation_name,
    event_time,
    severity,
    confidence,
    limitations,
    summary
)
ON public.rca_investigations
TO alert_evaluator;

-- Write access: register the policy version and persist decisions; read them
-- back for the policy-hash check, for alert history, and for ON CONFLICT
-- duplicate detection.
-- INSERT and SELECT only — both tables are append-only.
GRANT INSERT, SELECT
ON public.alert_policies
TO alert_evaluator;

GRANT INSERT, SELECT
ON public.alert_decisions
TO alert_evaluator;

-- Guardrail read access: anomalies that have no investigation yet.
-- Column-level SELECT only; exactly these 2 columns.
GRANT SELECT (
    anomaly_id,
    detected_at
)
ON public.anomaly_events
TO alert_evaluator;

-- Guardrail read access: detector checkpoint staleness.
-- Column-level SELECT only; exactly these 4 columns: the three columns that
-- identify a detection group, and updated_at, which is refreshed on every
-- successful checkpoint advance.  checkpoint_at is not needed.
GRANT SELECT (
    signal_path,
    service_name,
    operation_name,
    updated_at
)
ON public.anomaly_detector_runs
TO alert_evaluator;

-- Guardrail read access: delivery attempts and their outcomes.
-- SELECT only — the evaluator never records a delivery.
GRANT SELECT
ON public.alert_delivery_attempts
TO alert_evaluator;

GRANT SELECT
ON public.alert_delivery_outcomes
TO alert_evaluator;

-- NOT granted:
--   row changes or removal on any table — alert records are append-only, and
--                                 this role never modifies RCA or anomaly data.
--   row inserts on public.alert_delivery_attempts or
--   public.alert_delivery_outcomes — only alert_notifier records deliveries.
--   public.rca_evidence           — evidence free text is not needed to decide.
--   public.rca_investigation_embeddings
--                                 — historical similarity never influences
--                                   alerting.
--   public.telemetry_spans, analytics schema
--                                 — raw telemetry is out of scope for alerting.
--   sequence privileges           — every alert key is a deterministic digest.
--   schema object creation        — alert_evaluator does not own schema objects.
--
-- NOT exposed from public.rca_investigations:
--   analyzer_version, investigated_at, trace_id, subject_span_id,
--   trace_span_count, observed_value, baseline_median, anomaly_score
--
-- NOT exposed from public.anomaly_events:
--   every column except anomaly_id and detected_at
--
-- NOT exposed from public.anomaly_detector_runs:
--   checkpoint_at
