-- Migration: 014_create_alert_notifier_role
-- Phase 13.2: Least-privilege database role for the alert notifier
--
-- Creates a dedicated role for notification delivery.
-- This role is separate from alert_evaluator to follow least-privilege:
--   - The notifier holds the outbound channel credentials.  It reads only the
--     persisted decision snapshot and appends delivery audit records.
--   - It cannot read RCA investigations, RCA evidence, anomalies, telemetry,
--     or embeddings, so a compromised notifier cannot send them anywhere.
--
-- Apply AFTER 012_create_alert_tables.sql (grants require the tables):
--   psql -h localhost -U agentops -d agentops \
--     -v alert_notifier_password='<password>' \
--     -f storage-consumer/migrations/014_create_alert_notifier_role.sql
--
-- The password supplied here must match ALERT_NOTIFIER_DB_PASSWORD in .env.

CREATE ROLE alert_notifier WITH LOGIN PASSWORD :'alert_notifier_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO alert_notifier;

-- Allow the role to see objects in the public schema (PostgreSQL 15+ does not
-- grant public schema USAGE to PUBLIC by default).
GRANT USAGE ON SCHEMA public TO alert_notifier;

-- Read access: the persisted decision snapshot to deliver.
-- Column-level SELECT only; exactly these 8 columns.
GRANT SELECT (
    decision_id,
    decision,
    reason_code,
    policy_version,
    evaluated_at,
    payload,
    summary,
    summary_truncated
)
ON public.alert_decisions
TO alert_notifier;

-- Write access: record each delivery attempt before sending and its outcome
-- afterwards; read them back to derive delivery state and for ON CONFLICT
-- duplicate detection.
-- INSERT and SELECT only — the delivery audit trail is append-only.
GRANT INSERT, SELECT
ON public.alert_delivery_attempts
TO alert_notifier;

GRANT INSERT, SELECT
ON public.alert_delivery_outcomes
TO alert_notifier;

-- NOT granted:
--   row changes or removal on any table — delivery records are append-only.
--   row inserts on public.alert_decisions
--                                 — only alert_evaluator may write decisions.
--   public.alert_policies         — the notifier does not evaluate policy.
--   public.rca_investigations, public.rca_evidence
--                                 — the notifier sends the persisted snapshot
--                                   and never rebuilds an alert from RCA data.
--   public.anomaly_events, public.anomaly_detector_runs
--                                 — not needed to deliver a notification.
--   public.rca_investigation_embeddings
--                                 — historical similarity is never sent.
--   public.telemetry_spans, analytics schema
--                                 — raw telemetry is never sent.
--   sequence privileges           — every delivery key is a deterministic digest.
--   schema object creation        — alert_notifier does not own schema objects.
--
-- NOT exposed from public.alert_decisions:
--   investigation_id, anomaly_id, anomaly_type, service_name, operation_name,
--   event_time, severity, confidence, limitations, dedup_key,
--   related_decision_id, decided_at
--   (the values a notification needs are already inside payload)
