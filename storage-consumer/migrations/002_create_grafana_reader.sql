-- Migration: 002_create_grafana_reader
-- Phase 8.1: Grafana read-only datasource role
--
-- Creates a dedicated read-only PostgreSQL role for Grafana datasource access.
-- This role has no write privileges on any table.
--
-- Apply once against the agentops database:
--   psql -h localhost -U agentops -d agentops \
--     -v grafana_reader_password='<password>' \
--     -f storage-consumer/migrations/002_create_grafana_reader.sql
--
-- The password supplied here must match GF_DATASOURCE_AGENTOPS_PASSWORD in .env.

CREATE ROLE grafana_reader WITH LOGIN PASSWORD :'grafana_reader_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO grafana_reader;

-- Allow the role to see objects in the analytics schema.
GRANT USAGE ON SCHEMA analytics TO grafana_reader;

-- Explicit SELECT grants on the five existing mart tables.
-- These cover the objects that already exist at migration apply time.
GRANT SELECT ON
    analytics.mart_trace_metrics,
    analytics.mart_agent_metrics,
    analytics.mart_tool_metrics,
    analytics.mart_retrieval_metrics,
    analytics.mart_error_events
TO grafana_reader;

-- Default privilege grant for future and recreated analytics tables.
-- dbt materializes marts as TABLE and uses DROP + CREATE TABLE on each run,
-- which produces new table objects that explicit grants do not cover.
-- This ensures grafana_reader retains SELECT on any table subsequently
-- created by the agentops role in the analytics schema, including rebuilt marts.
-- Scope is intentionally narrow: agentops role + analytics schema only.
-- public.telemetry_spans and all other schemas are unaffected.
ALTER DEFAULT PRIVILEGES
    FOR ROLE agentops
    IN SCHEMA analytics
    GRANT SELECT ON TABLES TO grafana_reader;
