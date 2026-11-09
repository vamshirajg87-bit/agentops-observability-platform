-- Migration: 015_grant_trace_viewer_anomaly_rca_read
-- Read-only anomaly and RCA API for the trace viewer
--
-- Extends the existing trace_viewer_reader role (migration 003) so the trace
-- viewer API can read anomalies and RCA investigations.  Read-only: SELECT on
-- exactly three tables, nothing else.
--
-- Prerequisite: 003, 004 and 007 applied.
--
-- Apply once against the agentops database:
--   psql -h localhost -U agentops -d agentops \
--     -f storage-consumer/migrations/015_grant_trace_viewer_anomaly_rca_read.sql

-- The tables live in the public schema.
GRANT USAGE ON SCHEMA public TO trace_viewer_reader;

GRANT SELECT ON public.anomaly_events      TO trace_viewer_reader;
GRANT SELECT ON public.rca_investigations  TO trace_viewer_reader;
GRANT SELECT ON public.rca_evidence        TO trace_viewer_reader;
