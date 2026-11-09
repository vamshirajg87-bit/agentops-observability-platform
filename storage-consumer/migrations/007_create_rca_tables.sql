-- Migration: 007_create_rca_tables
-- Phase 11.2: RCA investigation and evidence persistence tables
--
-- Creates two tables that hold the results of Root-Cause Analysis runs:
--
--   public.rca_investigations  — one row per (anomaly_id, analyzer_version)
--   public.rca_evidence        — one row per span examined per investigation
--
-- Each investigation row is the frozen output of one RCA run.  A second run
-- with the same anomaly_id and analyzer_version produces the same
-- investigation_id (SHA-256 of anomaly_id + "|" + analyzer_version) and is
-- silently dropped by ON CONFLICT DO NOTHING — first-write-wins, consistent
-- with the anomaly_events idempotency contract.
--
-- A new analyzer_version produces a distinct investigation_id and therefore
-- a new row, preserving the history of how the RCA result changes across
-- analyzer releases.
--
-- Apply AFTER 004_create_anomaly_events.sql (FK requires the table):
--   psql -h localhost -U agentops -d agentops \
--     -f storage-consumer/migrations/007_create_rca_tables.sql
--
-- Intentionally uses CREATE TABLE (not IF NOT EXISTS) so that accidental
-- re-runs or schema drift are caught immediately as an error rather than
-- silently skipped.
--
-- Column mapping (RCAResult field → column):
--   investigation_id            → investigation_id  TEXT          PK
--   anomaly_id                  → anomaly_id        TEXT          NOT NULL  FK
--   analyzer_version            → analyzer_version  TEXT          NOT NULL
--   investigated_at (server)    → investigated_at   TIMESTAMPTZ   NOT NULL  DEFAULT NOW()
--   trace_id                    → trace_id          TEXT          NULL
--   subject_span_id             → subject_span_id   TEXT          NULL
--   service_name                → service_name      TEXT          NULL
--   operation_name              → operation_name    TEXT          NULL
--   event_time                  → event_time        TIMESTAMPTZ   NOT NULL
--   trace_span_count            → trace_span_count  INTEGER       NOT NULL  DEFAULT 0
--   anomaly_type                → anomaly_type      TEXT          NOT NULL
--   observed_value              → observed_value    DOUBLE PREC.  NOT NULL
--   baseline_median             → baseline_median   DOUBLE PREC.  NULL
--   anomaly_score               → anomaly_score     DOUBLE PREC.  NULL
--   severity                    → severity          TEXT          NOT NULL
--   confidence                  → confidence        TEXT          NOT NULL
--   summary                     → summary           TEXT          NOT NULL
--   limitations                 → limitations       TEXT[]        NOT NULL  DEFAULT '{}'

-- ---------------------------------------------------------------------------
-- rca_investigations
-- ---------------------------------------------------------------------------

CREATE TABLE public.rca_investigations (
    -- Deterministic identity: SHA-256 hex digest of (anomaly_id + "|" + analyzer_version).
    -- Exactly 64 lowercase hexadecimal characters; computed by the rca-analyzer Python layer.
    investigation_id        TEXT                NOT NULL,

    -- Anomaly being investigated.
    -- References public.anomaly_events to ensure an investigation row cannot
    -- exist without a corresponding anomaly record.
    anomaly_id              TEXT                NOT NULL,

    -- Analyzer version string, e.g. "1.0".  A new version produces a new
    -- investigation_id, preserving the history of RCA results across releases.
    analyzer_version        TEXT                NOT NULL,

    -- Wall-clock time when this investigation was persisted.
    -- NOT copied from the anomaly event_time.
    investigated_at         TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    -- Trace context (snapshot from the anomaly event; denormalized for standalone read).
    -- All four fields may be NULL when the anomaly event carried no trace reference
    -- (confidence = 'INSUFFICIENT_DATA').
    trace_id                TEXT,
    subject_span_id         TEXT,           -- anomaly.span_id; NULL for trace-level latency
    service_name            TEXT,
    operation_name          TEXT,

    -- Timestamp of the anomalous event itself (copied from anomaly_events.event_time).
    event_time              TIMESTAMPTZ         NOT NULL,

    -- Number of spans found in the trace reconstruction.
    -- 0 when trace data was unavailable (confidence = 'INSUFFICIENT_DATA').
    trace_span_count        INTEGER             NOT NULL DEFAULT 0,

    -- Anomaly signal snapshot (denormalized; anomaly_events is the authoritative source).
    anomaly_type            TEXT                NOT NULL,
    observed_value          DOUBLE PRECISION    NOT NULL,
    baseline_median         DOUBLE PRECISION,   -- NULL for error-rate / tool-failure signals
    anomaly_score           DOUBLE PRECISION,   -- NULL when zero-MAD fallback was taken

    -- Verdict
    severity                TEXT                NOT NULL,

    -- RCA output
    confidence              TEXT                NOT NULL,
    summary                 TEXT                NOT NULL,
    limitations             TEXT[]              NOT NULL DEFAULT '{}',

    -- ---------------------------------------------------------------------------
    -- Constraints
    -- ---------------------------------------------------------------------------

    CONSTRAINT pk_rca_investigations
        PRIMARY KEY (investigation_id),

    CONSTRAINT fk_rca_investigations_anomaly
        FOREIGN KEY (anomaly_id)
        REFERENCES public.anomaly_events (anomaly_id),

    -- investigation_id is a full SHA-256 hex digest: exactly 64 lowercase hex chars.
    CONSTRAINT chk_rca_investigations_id_format
        CHECK (investigation_id ~ '^[0-9a-f]{64}$'),

    -- Allowed confidence values match the RCA confidence classifier.
    CONSTRAINT chk_rca_investigations_confidence
        CHECK (confidence IN (
            'HIGH',
            'MEDIUM',
            'LOW',
            'INSUFFICIENT_DATA'
        )),

    -- Allowed severity values mirror anomaly_events severity.
    CONSTRAINT chk_rca_investigations_severity
        CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),

    -- trace_span_count is a count; cannot be negative.
    CONSTRAINT chk_rca_investigations_trace_span_count
        CHECK (trace_span_count >= 0)
);

-- Index on anomaly_id for FK-side lookups and "all investigations for this anomaly" queries.
-- PostgreSQL does not automatically index FK child columns.
CREATE INDEX idx_rca_investigations_anomaly_id
    ON public.rca_investigations (anomaly_id);

-- Partial index on trace_id for "all investigations for this trace" lookups.
-- Mirrors the idx_anomaly_events_trace_id pattern from migration 004.
CREATE INDEX idx_rca_investigations_trace_id
    ON public.rca_investigations (trace_id)
    WHERE trace_id IS NOT NULL;


-- ---------------------------------------------------------------------------
-- rca_evidence
-- ---------------------------------------------------------------------------
--
-- Column mapping (SpanEvidence field → column):
--   span_id                        → span_id               TEXT          NOT NULL
--   parent_span_id                 → parent_span_id        TEXT          NULL
--   span_name                      → span_name             TEXT          NOT NULL
--   service_name                   → service_name          TEXT          NOT NULL
--   duration_ms                    → duration_ms           DOUBLE PREC.  NOT NULL
--   status_code                    → status_code           TEXT          NOT NULL
--   error_type                     → error_type            TEXT          NULL
--   error_message                  → error_message         TEXT          NULL
--   tool_name                      → tool_name             TEXT          NULL
--   tool_status                    → tool_status           TEXT          NULL
--   agent_name                     → agent_name            TEXT          NULL
--   agent_operation                → agent_operation       TEXT          NULL
--   retrieval_result_count         → retrieval_result_count INTEGER       NULL
--   retrieval_top_relevance_score  → retrieval_top_relevance_score DOUBLE PREC. NULL
--   is_root_span                   → is_root_span          BOOLEAN       NOT NULL
--   is_error_span                  → is_error_span         BOOLEAN       NOT NULL
--   is_direct_subject              → is_direct_subject     BOOLEAN       NOT NULL
--   depth                          → depth                 INTEGER       NOT NULL
--   trace_duration_fraction        → trace_duration_fraction DOUBLE PREC. NULL
--   evidence_type                  → evidence_type         TEXT          NOT NULL
--   evidence_score                 → evidence_score        DOUBLE PREC.  NOT NULL
--   evidence_score_breakdown       → evidence_score_breakdown TEXT        NOT NULL
--   explanation                    → explanation           TEXT          NOT NULL
--   rank_position                  → rank_position         INTEGER       NOT NULL

CREATE TABLE public.rca_evidence (
    -- Surrogate PK for row-level references and cursor pagination.
    id                      BIGSERIAL           PRIMARY KEY,

    -- Investigation this evidence row belongs to.
    investigation_id        TEXT                NOT NULL,

    -- ---------------------------------------------------------------------------
    -- Section A: raw span facts (directly from stg_telemetry_spans)
    -- ---------------------------------------------------------------------------

    span_id                 TEXT                NOT NULL,
    parent_span_id          TEXT,               -- NULL for root spans
    span_name               TEXT                NOT NULL,
    service_name            TEXT                NOT NULL,
    duration_ms             DOUBLE PRECISION    NOT NULL,
    status_code             TEXT                NOT NULL,

    -- Domain facts (NULL when not applicable to this span type)
    error_type              TEXT,
    error_message           TEXT,
    tool_name               TEXT,               -- NULL on error tool spans (known gap)
    tool_status             TEXT,
    agent_name              TEXT,
    agent_operation         TEXT,
    retrieval_result_count  INTEGER,
    retrieval_top_relevance_score DOUBLE PRECISION,

    -- Structural position within the trace
    is_root_span            BOOLEAN             NOT NULL DEFAULT FALSE,
    is_error_span           BOOLEAN             NOT NULL DEFAULT FALSE,
    is_direct_subject       BOOLEAN             NOT NULL DEFAULT FALSE,
    depth                   INTEGER             NOT NULL DEFAULT 0,
    -- 0 = root, 1 = direct child, etc.
    -- Context only: a deeper error may itself be a downstream consequence.
    -- Depth does not increase evidence_score.

    -- ---------------------------------------------------------------------------
    -- Section B: derived measurements (computed at analysis time)
    -- ---------------------------------------------------------------------------

    trace_duration_fraction DOUBLE PRECISION,
    -- span.duration_ms / trace_duration_ms.
    -- What fraction of the trace's wall-clock window this span occupied.
    -- Conceptually in [0.0, 1.0] for internally consistent telemetry: a single
    -- span cannot exceed the wall-clock envelope it belongs to.
    -- The SUM across concurrent spans may exceed 1.0; this column must not be
    -- interpreted as an additive latency decomposition.
    -- NULL when trace_duration_ms == 0 or the trace could not be reconstructed.

    -- ---------------------------------------------------------------------------
    -- Section C: heuristic evidence output (no causal claims)
    -- ---------------------------------------------------------------------------

    evidence_type           TEXT                NOT NULL,
    -- e.g. "dominant_duration_and_error", "correlated_error", "direct_subject",
    --      "retrieval_quality_signal", "background_span"

    evidence_score          DOUBLE PRECISION    NOT NULL,
    -- Heuristic score in [0.0, 1.0].  Higher means stronger signal.

    evidence_score_breakdown TEXT               NOT NULL,
    -- Human-auditable breakdown, e.g.
    -- "duration_fraction=0.80→0.480 error_status=0.40 → 0.88"

    -- ---------------------------------------------------------------------------
    -- Section D: human-readable explanation (no causal claims)
    -- ---------------------------------------------------------------------------

    explanation             TEXT                NOT NULL,
    -- e.g. "Correlated error span occupied 80% of the trace's wall-clock
    --        duration (1480ms / 1850ms); error_type=ToolExecutionError."

    -- Rank within the investigation (1 = top contributor, ascending).
    rank_position           INTEGER             NOT NULL,

    -- ---------------------------------------------------------------------------
    -- Constraints
    -- ---------------------------------------------------------------------------

    CONSTRAINT fk_rca_evidence_investigation
        FOREIGN KEY (investigation_id)
        REFERENCES public.rca_investigations (investigation_id),

    -- Deterministic uniqueness: each span appears exactly once per investigation.
    -- Also serves as the primary index for "all evidence for an investigation" queries —
    -- the UNIQUE constraint creates an index with investigation_id as the leading column,
    -- so a separate index on investigation_id alone is not needed.
    CONSTRAINT uq_rca_evidence_span
        UNIQUE (investigation_id, span_id),

    -- Integrity constraints
    CONSTRAINT chk_rca_evidence_duration_ms
        CHECK (duration_ms >= 0),

    CONSTRAINT chk_rca_evidence_depth
        CHECK (depth >= 0),

    CONSTRAINT chk_rca_evidence_evidence_score
        CHECK (evidence_score BETWEEN 0.0 AND 1.0),

    -- Only >= 0 is enforced here (not <= 1.0).  Individual fractions are
    -- conceptually in [0.0, 1.0] for consistent telemetry, but values > 1.0
    -- can arise from clock skew, rounding errors, or export bugs in the source
    -- instrumentation.  Rejecting them at the DB layer would cause an entire
    -- investigation to fail to persist because of one span's bad timestamps,
    -- losing all evidence for that anomaly.  The application layer preserves
    -- the raw fraction and guards against > 1.0 when interpreting it.
    CONSTRAINT chk_rca_evidence_trace_duration_fraction
        CHECK (trace_duration_fraction IS NULL OR trace_duration_fraction >= 0.0),

    CONSTRAINT chk_rca_evidence_rank_position
        CHECK (rank_position > 0),

    CONSTRAINT chk_rca_evidence_retrieval_result_count
        CHECK (retrieval_result_count IS NULL OR retrieval_result_count >= 0)
);
