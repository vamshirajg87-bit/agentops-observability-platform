{{ config(materialized='table') }}

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
    tool_name,
    tool_status,
    is_error_span,
    error_type,
    error_message,
    ingested_at

from {{ ref('stg_telemetry_spans') }}
where is_tool_span
