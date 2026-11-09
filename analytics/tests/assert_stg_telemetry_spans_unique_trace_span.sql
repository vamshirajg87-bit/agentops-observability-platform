-- Singular test: composite uniqueness on (trace_id, span_id).
--
-- dbt's built-in `unique` generic test operates on a single column and cannot
-- express a composite key without adding dbt_utils. This singular test fills
-- that gap with no external dependency.
--
-- The source table enforces uq_telemetry_spans_trace_span UNIQUE (trace_id, span_id),
-- so this test would only fail if staging introduced a fanout (it does not; the
-- model is a straight SELECT with no JOIN or UNION). The test documents the
-- invariant and catches any future regression.
--
-- A non-empty result set means the test fails.

select
    trace_id,
    span_id,
    count(*) as duplicate_count
from {{ ref('stg_telemetry_spans') }}
group by trace_id, span_id
having count(*) > 1
