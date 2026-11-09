-- db-bootstrap/post_dbt_grants.sql
-- Phase 14.2: re-issue the analytics grants that a dbt run removes.
--
-- dbt replaces every relation of the analytics schema on each run, views
-- included.  A replaced relation is a new object, so a grant a migration
-- made on the old one is gone.  Three mechanisms put the grants back; this
-- file is the third and holds only what the other two do not cover:
--
--   1. Default privileges (migration 002): grafana_reader gets SELECT on
--      every relation the owner creates in the schema.
--   2. dbt post-hooks: the three marts read by anomaly_detector grant
--      SELECT to it again when they are rebuilt.
--   3. This file: the grants on the two VIEWS, which have neither.
--
-- Measured on a real database (Phase 14.2C2): after a dbt run exactly these
-- four grants were missing and every other grant of the migrations was
-- still in place.
--
-- Each statement below already exists, word for word in effect, in one of
-- these migrations; no role gains anything it does not have after its own
-- migration:
--
--   003_create_trace_viewer_reader.sql
--   005_create_anomaly_detector_role.sql
--   008_create_rca_analyzer_role.sql
--
-- A unit test derives this list from the migrations, the default
-- privileges and the dbt hooks, and fails on any difference.
--
-- Safe to run any number of times: GRANT is idempotent.  It creates no
-- role and changes no default privilege.  The roles must already exist.
--
-- Run as the owner role, after every `dbt run`:
--   psql -h <host> -U agentops -d agentops -f db-bootstrap/post_dbt_grants.sql

-- trace_viewer_reader (migration 003)
GRANT SELECT ON analytics.stg_telemetry_spans TO trace_viewer_reader;
GRANT SELECT ON analytics.int_trace_spans TO trace_viewer_reader;

-- anomaly_detector (migration 005); its three marts are re-granted by dbt
GRANT SELECT ON analytics.stg_telemetry_spans TO anomaly_detector;

-- rca_analyzer (migration 008)
GRANT SELECT ON analytics.stg_telemetry_spans TO rca_analyzer;
