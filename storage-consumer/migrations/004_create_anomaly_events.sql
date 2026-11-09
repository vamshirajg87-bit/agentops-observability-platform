-- Migration: 004_create_anomaly_events
-- Phase 10.4B: anomaly_events persistence table
--
-- Creates public.anomaly_events, the durable record of every anomaly
-- detected by the Phase 10.3 concrete detectors.  Each row is one
-- AnomalyEvent produced by LatencyDetector, RetrievalQualityDetector,
-- ErrorRateDetector, or ToolFailureDetector.
--
-- Apply once against the agentops database:
--   psql -h localhost -U agentops -d agentops -f 004_create_anomaly_events.sql
--
-- Intentionally uses CREATE TABLE (not IF NOT EXISTS) so that accidental
-- re-runs or schema drift are caught immediately as an error rather than
-- silently skipped.
--
-- Column mapping (AnomalyEvent field → column → type → nullability):
--   (computed deterministically)       → anomaly_id            → TEXT             NOT NULL
--   anomaly_type                       → anomaly_type          → TEXT             NOT NULL
--   signal_name                        → signal_name           → TEXT             NOT NULL
--   detector_name                      → detector_name         → TEXT             NOT NULL
--   detector_version                   → detector_version      → TEXT             NOT NULL
--   trace_id                           → trace_id              → TEXT             NULL
--   span_id                            → span_id               → TEXT             NULL
--   service_name                       → service_name          → TEXT             NULL
--   operation_name                     → operation_name        → TEXT             NULL
--   observed_value                     → observed_value        → DOUBLE PRECISION NOT NULL
--   observed_at                        → event_time            → TIMESTAMPTZ      NOT NULL
--   baseline_median                    → baseline_median       → DOUBLE PRECISION NULL
--   baseline_mad                       → baseline_mad          → DOUBLE PRECISION NULL
--   baseline_n                         → baseline_n            → INTEGER          NULL
--   baseline_window_start              → baseline_window_start → TIMESTAMPTZ      NULL
--   baseline_window_end                → baseline_window_end   → TIMESTAMPTZ      NULL
--   anomaly_score                      → anomaly_score         → DOUBLE PRECISION NULL
--   severity                           → severity              → TEXT             NOT NULL
--   explanation                        → explanation           → TEXT             NOT NULL
--   (server default)                   → detected_at           → TIMESTAMPTZ      NOT NULL DEFAULT NOW()

CREATE TABLE public.anomaly_events (
    -- Deterministic identity: SHA-256 hex digest of canonical identity fields.
    -- 64 lowercase hexadecimal characters; computed by Phase 10.4 Python layer.
    anomaly_id              TEXT             NOT NULL,

    -- Detector identity
    anomaly_type            TEXT             NOT NULL,
    signal_name             TEXT             NOT NULL,
    detector_name           TEXT             NOT NULL,
    detector_version        TEXT             NOT NULL,

    -- Subject identity
    -- trace_id and span_id are TEXT (not CHAR) — stg_telemetry_spans TRIMs the
    -- CHAR(32)/CHAR(16) source columns; values stored here are already trimmed.
    -- span_id is NULL for trace-level LatencyRecord observations.
    trace_id                TEXT,
    span_id                 TEXT,
    service_name            TEXT,
    operation_name          TEXT,

    -- Signal evidence
    observed_value          DOUBLE PRECISION NOT NULL,
    event_time              TIMESTAMPTZ      NOT NULL,

    -- Baseline evidence.
    -- All three scalar fields and both window timestamps are NULL together for
    -- error-rate and tool-failure anomalies, which use rate/novelty/persistence
    -- signals rather than median/MAD baseline statistics.
    baseline_median         DOUBLE PRECISION,
    baseline_mad            DOUBLE PRECISION,
    baseline_n              INTEGER,
    baseline_window_start   TIMESTAMPTZ,
    baseline_window_end     TIMESTAMPTZ,

    -- Score evidence.
    -- NULL when the zero-MAD fallback path was taken (no z-score computable).
    -- Holds rate_ratio for error-rate and tool-failure anomalies.
    anomaly_score           DOUBLE PRECISION,

    -- Verdict
    severity                TEXT             NOT NULL,

    -- Human-readable evidence; no causal claims.
    explanation             TEXT             NOT NULL,

    -- Wall-clock time when the anomaly was written to this table.
    -- Useful for monitoring detection pipeline lag; not a processing checkpoint.
    detected_at             TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    -- Identity constraint: anomaly_id is the primary key.
    -- anomaly_id is a full SHA-256 hex digest: exactly 64 lowercase hex chars.
    CONSTRAINT pk_anomaly_events
        PRIMARY KEY (anomaly_id),

    CONSTRAINT chk_anomaly_events_anomaly_id
        CHECK (anomaly_id ~ '^[0-9a-f]{64}$'),

    -- Allowed anomaly_type values are exactly those emitted by Phase 10.3 detectors.
    CONSTRAINT chk_anomaly_events_anomaly_type
        CHECK (anomaly_type IN (
            'latency',
            'retrieval_quality',
            'error_rate',
            'tool_failure'
        )),

    -- Allowed severity values match the Severity enum in detector/severity.py.
    CONSTRAINT chk_anomaly_events_severity
        CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),

    -- baseline_n is a count; zero is valid (baseline computed over zero records is
    -- represented as INSUFFICIENT_HISTORY, so in practice n >= 10 or NULL, but
    -- the constraint only guards against accidental negatives).
    CONSTRAINT chk_anomaly_events_baseline_n_non_negative
        CHECK (baseline_n IS NULL OR baseline_n >= 0)
);

-- Trace-linkage index for Phase 11 RCA queries.
-- Partial: trace_id IS NOT NULL covers all anomalies with a trace reference
-- while avoiding index entries for potential future detector types without one.
CREATE INDEX idx_anomaly_events_trace_id
    ON public.anomaly_events (trace_id)
    WHERE trace_id IS NOT NULL;
