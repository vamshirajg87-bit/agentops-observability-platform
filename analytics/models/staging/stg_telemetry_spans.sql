{{ config(materialized='view') }}

select
    -- Span identity
    -- TRIM normalises CHAR(32) / CHAR(16) trailing-space padding from the source
    -- table so downstream consumers receive canonical unpadded strings.
    trim(trace_id)                          as trace_id,
    trim(span_id)                           as span_id,
    trim(parent_span_id)                    as parent_span_id,

    -- Envelope
    schema_version,
    event_type,

    -- Span description
    span_name,
    span_kind,
    service_name,

    -- Timing
    start_time,
    end_time,
    duration_ms,

    -- Status
    status_code,
    status_message,

    -- Optional session identity (populated on agentops.request root spans)
    request_id,
    session_id,

    -- Promoted business attributes
    gen_ai_operation,
    agent_name,
    agent_operation,
    tool_name,
    tool_status,
    retrieval_result_count,
    retrieval_top_relevance_score,
    error_type,
    error_message,

    -- Raw OTel attribute bag; preserved as-is for downstream access
    attributes,

    -- Kafka ingestion provenance
    kafka_topic,
    kafka_partition,
    kafka_offset,

    -- Ingestion timestamp
    ingested_at,

    -- Derived row-level flags
    parent_span_id is null                  as is_root_span,
    status_code = 'ERROR'                   as is_error_span,
    agent_name is not null                  as is_agent_span,
    tool_name is not null                   as is_tool_span,
    retrieval_result_count is not null      as is_retrieval_span

from {{ source('agentops', 'telemetry_spans') }}
