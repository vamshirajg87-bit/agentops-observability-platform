{{ config(
    materialized='table',
    post_hook="{{ grant_select_if_role_exists(this, 'anomaly_detector') }}"
) }}

select
    trace_id,
    trace_start_time,
    trace_end_time,
    trace_duration_ms,
    root_span_id,
    root_span_name,
    root_service_name,
    request_id,
    session_id,
    span_count,
    service_count,
    error_span_count,
    agent_span_count,
    tool_span_count,
    retrieval_span_count,
    has_error

from {{ ref('int_trace_spans') }}
