-- Migration: 008_create_rca_analyzer_role
-- Phase 11.2: Least-privilege database role for the RCA analyzer service
--
-- Creates a dedicated role for the RCA analyzer.
-- This role is separate from anomaly_detector to follow least-privilege:
--   - RCA needs full SELECT on public.anomaly_events (not just anomaly_id);
--     granting this to anomaly_detector would let the detector read its own
--     output, which is not required for detection.
--   - RCA writes to different tables (rca_investigations, rca_evidence).
--
-- Apply AFTER 007_create_rca_tables.sql (INSERT grants require the tables):
--   psql -h localhost -U agentops -d agentops \
--     -v rca_analyzer_password='<password>' \
--     -f storage-consumer/migrations/008_create_rca_analyzer_role.sql
--
-- The password supplied here must match RCA_ANALYZER_DB_PASSWORD in .env.

CREATE ROLE rca_analyzer WITH LOGIN PASSWORD :'rca_analyzer_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO rca_analyzer;

-- Allow the role to see objects in the public schema (required for SELECT on
-- public.anomaly_events and INSERT on public.rca_* in PostgreSQL 15+ where
-- public schema USAGE is not granted to PUBLIC by default).
GRANT USAGE ON SCHEMA public TO rca_analyzer;

-- Allow the role to see objects in the analytics schema.
GRANT USAGE ON SCHEMA analytics TO rca_analyzer;

-- Read access: anomalies to investigate.
--
-- Full-table SELECT is required here (unlike anomaly_detector, which only
-- needs anomaly_id for ON CONFLICT resolution).  The RCA analyzer reads the
-- entire anomaly row to populate the investigation snapshot.
GRANT SELECT ON public.anomaly_events TO rca_analyzer;

-- Read access: span evidence for trace reconstruction.
--
-- stg_telemetry_spans is the only analytics relation needed for RCA.
-- It exposes all span columns including parent_span_id (for tree reconstruction),
-- error_type/error_message, tool_name/tool_status, retrieval fields, and the
-- attributes JSONB column.
--
-- NOT granted:
--   mart_trace_metrics     — aggregate only; no per-span data for reconstruction.
--   mart_agent_metrics     — agent spans only; incomplete trace.
--   mart_retrieval_metrics — retrieval spans only; incomplete trace.
--   mart_tool_metrics      — excludes error spans (tool_name IS NULL on errors).
--   mart_error_events      — error-only grain; no success spans for context.
--   int_trace_spans        — aggregate only; no per-span data.
GRANT SELECT ON analytics.stg_telemetry_spans TO rca_analyzer;

-- Write access: persist RCA results.
-- INSERT only — no UPDATE, no DELETE.
GRANT INSERT ON public.rca_investigations TO rca_analyzer;
GRANT INSERT ON public.rca_evidence TO rca_analyzer;

-- Conflict-resolution read: ON CONFLICT (investigation_id) DO NOTHING requires
-- the executor to read investigation_id to detect duplicate keys.
-- A column-level SELECT on investigation_id alone satisfies this without granting
-- full-table SELECT on public.rca_investigations.
-- (Mirrors the pattern used for anomaly_detector on public.anomaly_events.)
GRANT SELECT (investigation_id) ON public.rca_investigations TO rca_analyzer;

-- Sequence privilege: rca_evidence.id is a BIGSERIAL column backed by a
-- sequence.  INSERT requires USAGE on that sequence.
GRANT USAGE ON SEQUENCE rca_evidence_id_seq TO rca_analyzer;

-- NOT granted:
--   UPDATE on any table           — investigation rows are immutable once written.
--   DELETE on any table           — RCA produces append-only audit records.
--   INSERT on public.anomaly_events — rca_analyzer reads anomalies; only
--                                     anomaly_detector may write them.
--   anomaly_detector_runs         — checkpoint table; not used by rca_analyzer.
--   CREATE privileges             — rca_analyzer does not own schema objects.
