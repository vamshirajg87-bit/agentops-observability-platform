-- Migration: 006_create_anomaly_detector_runs
-- Phase 10.5B: Checkpoint table for the anomaly detector runner
--
-- Creates public.anomaly_detector_runs, the durable processing-checkpoint store
-- for the Phase 10.5 anomaly detector runner.  Each row represents one
-- (signal_path, service_name, operation_name) detection group and records the
-- query_end timestamp of the last successfully committed runner invocation for
-- that group.
--
-- Apply AFTER 005_create_anomaly_detector_role.sql (role must exist for GRANT):
--   psql -h localhost -U agentops -d agentops \
--     -f storage-consumer/migrations/006_create_anomaly_detector_runs.sql
--
-- Intentionally uses CREATE TABLE (not IF NOT EXISTS) so that accidental
-- re-runs or schema drift are caught immediately as an error rather than
-- silently skipped.

CREATE TABLE public.anomaly_detector_runs (
    -- Detection group identity: the composite primary key identifies one
    -- (signal_path, service_name, operation_name) combination.
    -- operation_name='' is the canonical representation for signal paths that
    -- do not carry an operation_name (tool_latency, retrieval, tool_failure).
    signal_path     TEXT        NOT NULL,
    service_name    TEXT        NOT NULL,
    operation_name  TEXT        NOT NULL DEFAULT '',

    -- checkpoint_at is the query_end of the last successfully committed runner
    -- invocation.  It is NOT the query_start: the runner computes query_start
    -- dynamically as (checkpoint_at - overlap_minutes) at runtime so that the
    -- overlap window can be tuned without a migration.
    --
    -- The checkpoint is advanced atomically in the same transaction as the
    -- anomaly INSERTs it covers.  If the runner crashes before commit,
    -- checkpoint_at does not advance and the next run reprocesses the same
    -- window — safe because anomaly persistence is idempotent (ON CONFLICT
    -- DO NOTHING on anomaly_events.anomaly_id).
    checkpoint_at   TIMESTAMPTZ NOT NULL,

    -- updated_at is refreshed on every successful advance via the UPSERT's
    -- DO UPDATE SET clause.  Useful for operator monitoring of runner liveness.
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_anomaly_detector_runs
        PRIMARY KEY (signal_path, service_name, operation_name)
);

-- Grant anomaly_detector the privileges required for normal checkpoint operation.
--
-- SELECT  — read the current checkpoint at the start of each run.
-- INSERT  — write the first checkpoint row for a new detection group.
-- UPDATE  — advance checkpoint_at on subsequent runs via ON CONFLICT DO UPDATE.
--
-- UPDATE is required here because the checkpoint row is mutable state: it must
-- be advanced on every successful run.  This contrasts with public.anomaly_events,
-- which is INSERT-only because detected anomaly rows are immutable records; their
-- ON CONFLICT DO NOTHING conflict action never needs to mutate an existing row.
--
-- DELETE and TRUNCATE are intentionally NOT granted.  Checkpoint rewinds needed
-- for testing or operator recovery must be performed by an admin role (agentops)
-- outside the anomaly_detector service boundary.
--
-- No sequence privilege is needed: the table has no SERIAL or GENERATED column.
GRANT SELECT, INSERT, UPDATE
    ON public.anomaly_detector_runs
    TO anomaly_detector;
