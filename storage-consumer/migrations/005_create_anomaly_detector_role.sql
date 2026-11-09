-- Migration: 005_create_anomaly_detector_role
-- Phase 10.4B: Anomaly detector least-privilege database role
--
-- Creates a dedicated role for the anomaly detector service.
-- This role has read access to the telemetry/mart relations required by
-- Phase 10.4 query functions, and insert-only access to public.anomaly_events.
-- No UPDATE, DELETE, CREATE, or schema ownership is granted.
--
-- Apply AFTER 004_create_anomaly_events.sql (INSERT grant requires the table):
--   psql -h localhost -U agentops -d agentops \
--     -v anomaly_detector_password='<password>' \
--     -f storage-consumer/migrations/005_create_anomaly_detector_role.sql
--
-- The password supplied here must match ANOMALY_DETECTOR_DB_PASSWORD in .env.

CREATE ROLE anomaly_detector WITH LOGIN PASSWORD :'anomaly_detector_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO anomaly_detector;

-- Allow the role to see objects in the public schema (required for INSERT on
-- public.anomaly_events in PostgreSQL 15+ where public schema USAGE is not
-- granted to PUBLIC by default).
GRANT USAGE ON SCHEMA public TO anomaly_detector;

-- Allow the role to see objects in the analytics schema.
GRANT USAGE ON SCHEMA analytics TO anomaly_detector;

-- Read access: the telemetry relations queried by Phase 10.4.
--
-- stg_telemetry_spans: required for tool-latency and tool-failure queries
--   (span_name = 'tool.execute' includes error spans excluded from mart_tool_metrics)
--   and for operation-level error-rate queries.
-- mart_trace_metrics:    trace-level latency detection.
-- mart_agent_metrics:    agent-span latency and error-rate detection.
-- mart_retrieval_metrics: retrieval quality detection.
--
-- NOT granted:
--   mart_tool_metrics     — error tool spans are absent (tool_name IS NULL on errors);
--                           stg_telemetry_spans is used instead.
--   mart_error_events     — error-only grain; cannot supply rate denominator.
--   int_trace_spans       — not needed by detector queries.
GRANT SELECT ON
    analytics.stg_telemetry_spans,
    analytics.mart_trace_metrics,
    analytics.mart_agent_metrics,
    analytics.mart_retrieval_metrics
TO anomaly_detector;

-- Write access: persist detected anomalies.
-- INSERT only — no UPDATE, no DELETE.
GRANT INSERT ON public.anomaly_events TO anomaly_detector;

-- Conflict-resolution read: ON CONFLICT (anomaly_id) DO NOTHING requires the
-- executor to read the anomaly_id column to detect duplicate keys.
-- A column-level SELECT on anomaly_id alone satisfies this without granting
-- full-table SELECT on public.anomaly_events.
GRANT SELECT (anomaly_id) ON public.anomaly_events TO anomaly_detector;

-- NOTE — dbt DROP+CREATE lifecycle:
-- dbt materializes mart tables with DROP + CREATE TABLE on each run (under the
-- agentops role), which replaces the table object and silently drops all
-- explicit grants that were made on the old object.  After every dbt run the
-- four SELECT grants above must be re-applied before the anomaly_detector
-- service can query the marts again.
--
-- Preferred remediation (Phase 10.5 or later): add a dbt post-hook to each
-- relevant mart model:
--   {{ config(post_hook="GRANT SELECT ON {{ this }} TO anomaly_detector") }}
--
-- Until that is in place, a DBA must re-run:
--   GRANT SELECT ON
--       analytics.stg_telemetry_spans,
--       analytics.mart_trace_metrics,
--       analytics.mart_agent_metrics,
--       analytics.mart_retrieval_metrics
--   TO anomaly_detector;
-- after each dbt run that rebuilds these relations.
--
-- ALTER DEFAULT PRIVILEGES is intentionally NOT used here.  The grafana_reader
-- migration (002) uses it because Grafana requires read access to every
-- current and future analytics relation.  anomaly_detector is scoped to
-- exactly the four relations above; blanket SELECT on all future analytics
-- tables would violate least-privilege.
