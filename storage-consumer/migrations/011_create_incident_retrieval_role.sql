-- Migration: 011_create_incident_retrieval_role
-- Phase 12.2: Least-privilege database role for the incident retrieval service
--
-- Creates a dedicated role for incident retrieval.
-- This role is separate from rca_analyzer to follow least-privilege:
--   - Retrieval reads a curated subset of RCA output columns to render the
--     retrieval document; it never writes RCA results.
--   - Retrieval writes only to public.rca_investigation_embeddings.
--
-- Apply AFTER 010_create_rca_investigation_embeddings.sql (grants require the
-- table):
--   psql -h localhost -U agentops -d agentops \
--     -v incident_retrieval_password='<password>' \
--     -f storage-consumer/migrations/011_create_incident_retrieval_role.sql
--
-- Retrieval metric contract (queries issued by this role):
--   - exact cosine distance operator: <=>
--   - similarity = 1.0 - (embedding <=> query_vector)
--   - no HNSW index in Phase 12.2; search is exact.
--   - a future HNSW index would use vector_cosine_ops.

CREATE ROLE incident_retrieval
WITH LOGIN PASSWORD :'incident_retrieval_password';

-- Allow the role to connect to the agentops database.
GRANT CONNECT ON DATABASE agentops TO incident_retrieval;

-- Allow the role to see objects in the public schema (PostgreSQL 15+ does not
-- grant public schema USAGE to PUBLIC by default).
GRANT USAGE ON SCHEMA public TO incident_retrieval;

-- Read access: investigation fields used to render the retrieval document.
-- Column-level SELECT only; exactly these 10 columns.
GRANT SELECT (
    investigation_id,
    anomaly_type,
    service_name,
    operation_name,
    confidence,
    severity,
    event_time,
    summary,
    limitations,
    trace_span_count
)
ON public.rca_investigations
TO incident_retrieval;

-- Read access: evidence fields used to render the retrieval document.
-- Column-level SELECT only; exactly these 17 columns.
GRANT SELECT (
    investigation_id,
    rank_position,
    evidence_type,
    evidence_score,
    span_name,
    service_name,
    status_code,
    error_type,
    tool_name,
    tool_status,
    agent_name,
    agent_operation,
    retrieval_result_count,
    retrieval_top_relevance_score,
    is_direct_subject,
    is_root_span,
    trace_duration_fraction
)
ON public.rca_evidence
TO incident_retrieval;

-- Write access: persist embeddings; read them back for similarity search and
-- for ON CONFLICT duplicate detection.
-- INSERT and SELECT only — embeddings are immutable once written.
GRANT INSERT, SELECT
ON public.rca_investigation_embeddings
TO incident_retrieval;

-- NOT granted:
--   UPDATE / DELETE / TRUNCATE on any table — embeddings are append-only.
--   INSERT / UPDATE / DELETE on public.rca_investigations or public.rca_evidence
--                                 — only rca_analyzer may write RCA results.
--   public.anomaly_events         — not needed to render retrieval documents.
--   analytics schema              — raw span data is out of scope for retrieval.
--   sequence privileges           — embedding_id is a deterministic digest, and
--                                   this role never inserts into rca_evidence.
--   CREATE privileges             — incident_retrieval does not own schema objects.
--
-- NOT exposed from public.rca_evidence:
--   error_message, explanation    — free text that may carry sensitive payloads.
--   id, span_id, parent_span_id, is_error_span, duration_ms, depth,
--   evidence_score_breakdown
--
-- NOT exposed from public.rca_investigations:
--   anomaly_id, analyzer_version, investigated_at, trace_id, subject_span_id,
--   observed_value, baseline_median, anomaly_score
