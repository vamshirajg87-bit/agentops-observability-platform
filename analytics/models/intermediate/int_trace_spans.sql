{{ config(materialized='view') }}

select
    trace_id,

    -- Trace timing: observed wall-clock envelope across all spans in the trace.
    -- MIN(start_time) / MAX(end_time) give the earliest known start and latest
    -- known end of any span in this trace.
    -- trace_duration_ms is derived from this envelope, NOT from SUM(duration_ms):
    -- parent and child spans overlap in wall-clock time so summing span durations
    -- would double-count work that executed concurrently within the same interval.
    min(start_time)                                                    as trace_start_time,
    max(end_time)                                                      as trace_end_time,
    (extract(epoch from (max(end_time) - min(start_time))) * 1000.0)::double precision as trace_duration_ms,

    -- Root span metadata via conditional aggregation.
    -- Groups only by trace_id; root fields are extracted without additional GROUP BY
    -- dimensions. NULL when no root span has been observed for this trace yet —
    -- distributed telemetry may arrive incomplete or out of order; this is expected
    -- and is not a model or test failure.
    max(case when is_root_span then span_id      end)                  as root_span_id,
    max(case when is_root_span then span_name    end)                  as root_span_name,
    max(case when is_root_span then service_name end)                  as root_service_name,
    max(case when is_root_span then request_id   end)                  as request_id,
    max(case when is_root_span then session_id   end)                  as session_id,

    -- Structural counts
    count(*)                                                           as span_count,
    count(distinct service_name)                                       as service_count,

    -- Activity counts by span type
    count(*) filter (where is_error_span)                              as error_span_count,
    count(*) filter (where is_agent_span)                              as agent_span_count,
    count(*) filter (where is_tool_span)                               as tool_span_count,
    count(*) filter (where is_retrieval_span)                          as retrieval_span_count,

    -- Trace-level error flag: true when at least one span has status_code = 'ERROR'
    bool_or(is_error_span)                                             as has_error

from {{ ref('stg_telemetry_spans') }}
group by trace_id
