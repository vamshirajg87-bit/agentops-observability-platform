-- Migration: 001_create_telemetry_spans
-- Phase 6.3: PostgreSQL Schema + Migration
--
-- Creates the telemetry_spans table that persists every CanonicalSpanEvent
-- consumed from agentops.telemetry.spans.
--
-- Apply once against a fresh agentops database:
--   psql -h localhost -U agentops -d agentops -f 001_create_telemetry_spans.sql
--
-- Intentionally uses CREATE TABLE (not IF NOT EXISTS) so that accidental
-- re-runs or schema drift are caught immediately as an error rather than
-- silently skipped.
--
-- Column mapping (CanonicalSpanEvent field → column → type → nullability):
--   schema_version                → schema_version                → TEXT             NOT NULL
--   event_type                    → event_type                    → TEXT             NOT NULL
--   trace_id                      → trace_id                      → CHAR(32)         NOT NULL
--   span_id                       → span_id                       → CHAR(16)         NOT NULL
--   parent_span_id                → parent_span_id                → CHAR(16)         NULL
--   span_name                     → span_name                     → TEXT             NOT NULL
--   span_kind                     → span_kind                     → TEXT             NOT NULL
--   service_name                  → service_name                  → TEXT             NOT NULL
--   start_time                    → start_time                    → TIMESTAMPTZ      NOT NULL
--   end_time                      → end_time                      → TIMESTAMPTZ      NOT NULL
--   duration_ms                   → duration_ms                   → DOUBLE PRECISION NOT NULL
--   status_code                   → status_code                   → TEXT             NOT NULL
--   status_message                → status_message                → TEXT             NULL
--   request_id                    → request_id                    → TEXT             NULL
--   session_id                    → session_id                    → TEXT             NULL
--   gen_ai_operation              → gen_ai_operation              → TEXT             NULL
--   agent_name                    → agent_name                    → TEXT             NULL
--   agent_operation               → agent_operation               → TEXT             NULL
--   tool_name                     → tool_name                     → TEXT             NULL
--   tool_status                   → tool_status                   → TEXT             NULL
--   retrieval_result_count        → retrieval_result_count        → INTEGER          NULL
--   retrieval_top_relevance_score → retrieval_top_relevance_score → DOUBLE PRECISION NULL
--   error_type                    → error_type                    → TEXT             NULL
--   error_message                 → error_message                 → TEXT             NULL
--   attributes                    → attributes                    → JSONB            NOT NULL
--   (ingestion metadata)          → kafka_topic                   → TEXT             NOT NULL
--   (ingestion metadata)          → kafka_partition               → INTEGER          NOT NULL
--   (ingestion metadata)          → kafka_offset                  → BIGINT           NOT NULL
--   (server default)              → ingested_at                   → TIMESTAMPTZ      NOT NULL DEFAULT NOW()

CREATE TABLE telemetry_spans (
    id                            BIGSERIAL        PRIMARY KEY,

    -- CanonicalSpanEvent envelope fields
    schema_version                TEXT             NOT NULL,
    event_type                    TEXT             NOT NULL,

    -- Span identity
    trace_id                      CHAR(32)         NOT NULL,
    span_id                       CHAR(16)         NOT NULL,
    parent_span_id                CHAR(16),

    -- Span description
    span_name                     TEXT             NOT NULL,
    span_kind                     TEXT             NOT NULL,
    service_name                  TEXT             NOT NULL,

    -- Timing
    start_time                    TIMESTAMPTZ      NOT NULL,
    end_time                      TIMESTAMPTZ      NOT NULL,
    duration_ms                   DOUBLE PRECISION NOT NULL,

    -- Status
    status_code                   TEXT             NOT NULL,
    status_message                TEXT,

    -- Tier 2: optional identity fields
    request_id                    TEXT,
    session_id                    TEXT,

    -- Tier 3: promoted business attributes (also present in attributes JSONB)
    gen_ai_operation              TEXT,
    agent_name                    TEXT,
    agent_operation               TEXT,
    tool_name                     TEXT,
    tool_status                   TEXT,
    retrieval_result_count        INTEGER,
    retrieval_top_relevance_score DOUBLE PRECISION,
    error_type                    TEXT,
    error_message                 TEXT,

    -- Raw OTel attribute bag (includes all Tier 3 source keys)
    attributes                    JSONB            NOT NULL,

    -- Kafka ingestion provenance
    kafka_topic                   TEXT             NOT NULL,
    kafka_partition               INTEGER          NOT NULL,
    -- BIGINT: Kafka offsets are 64-bit; INTEGER overflows at ~2.1B messages
    kafka_offset                  BIGINT           NOT NULL,

    -- Server-assigned ingestion timestamp
    ingested_at                   TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    -- Logical deduplication key: trace_id+span_id is the durable span identity.
    -- The B-tree backing this constraint also serves trace_id prefix lookups,
    -- making a standalone trace_id index redundant.
    CONSTRAINT uq_telemetry_spans_trace_span UNIQUE (trace_id, span_id),

    -- Integrity guards for non-negative numeric fields
    CONSTRAINT chk_telemetry_spans_duration_ms_non_negative
        CHECK (duration_ms >= 0),
    CONSTRAINT chk_telemetry_spans_kafka_partition_non_negative
        CHECK (kafka_partition >= 0),
    CONSTRAINT chk_telemetry_spans_kafka_offset_non_negative
        CHECK (kafka_offset >= 0),
    CONSTRAINT chk_telemetry_spans_retrieval_result_count_non_negative
        CHECK (retrieval_result_count IS NULL OR retrieval_result_count >= 0)
);

-- Time-range queries: fetch spans within a wall-clock window
CREATE INDEX idx_telemetry_spans_start_time
    ON telemetry_spans (start_time);

-- Per-service time-range queries: operational dashboards and SLO calculations
CREATE INDEX idx_telemetry_spans_service_name_start_time
    ON telemetry_spans (service_name, start_time);


-- ---------------------------------------------------------------------------
-- Idempotency constraint verification (run manually; do NOT apply in prod)
-- ---------------------------------------------------------------------------
--
-- The following block proves that the unique constraint prevents duplicate
-- spans from being persisted. In Phase 6.4 the storage consumer will use:
--   INSERT ... ON CONFLICT ON CONSTRAINT uq_telemetry_spans_trace_span DO NOTHING
-- This test confirms that constraint fires correctly.
--
-- Execute in psql with \i or copy-paste the block; ROLLBACK leaves no rows.
--
-- BEGIN;
--
-- INSERT INTO telemetry_spans (
--     schema_version, event_type,
--     trace_id, span_id,
--     span_name, span_kind, service_name,
--     start_time, end_time, duration_ms,
--     status_code,
--     attributes,
--     kafka_topic, kafka_partition, kafka_offset
-- ) VALUES (
--     '1.0', 'span',
--     'abcdef1234567890abcdef1234567890',  -- 32 hex chars
--     'fedcba0987654321',                  -- 16 hex chars
--     'test.operation', 'INTERNAL', 'agentops-test',
--     NOW(), NOW() + INTERVAL '100 milliseconds', 100.0,
--     'OK',
--     '{}',
--     'agentops.telemetry.spans', 0, 0
-- );
-- -- Expected: INSERT 0 1
--
-- INSERT INTO telemetry_spans (
--     schema_version, event_type,
--     trace_id, span_id,
--     span_name, span_kind, service_name,
--     start_time, end_time, duration_ms,
--     status_code,
--     attributes,
--     kafka_topic, kafka_partition, kafka_offset
-- ) VALUES (
--     '1.0', 'span',
--     'abcdef1234567890abcdef1234567890',  -- same trace_id
--     'fedcba0987654321',                  -- same span_id → duplicate
--     'test.operation', 'INTERNAL', 'agentops-test',
--     NOW(), NOW() + INTERVAL '100 milliseconds', 100.0,
--     'OK',
--     '{}',
--     'agentops.telemetry.spans', 0, 1   -- different offset, same logical span
-- );
-- -- Expected: ERROR: duplicate key value violates unique constraint
-- --           "uq_telemetry_spans_trace_span"
--
-- ROLLBACK;
-- -- Expected: ROLLBACK (table left clean)
