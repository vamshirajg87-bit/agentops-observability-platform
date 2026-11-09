{{ config(
    materialized='table',
    post_hook="{{ grant_select_if_role_exists(this, 'anomaly_detector') }}"
) }}

select
    trace_id,
    span_id,
    parent_span_id,
    span_name,
    span_kind,
    service_name,
    start_time,
    end_time,
    duration_ms,
    status_code,
    status_message,
    request_id,
    session_id,
    agent_name,
    agent_operation,
    retrieval_result_count,
    retrieval_top_relevance_score,
    is_error_span,
    error_type,
    error_message,
    ingested_at

from {{ ref('stg_telemetry_spans') }}
where is_retrieval_span
