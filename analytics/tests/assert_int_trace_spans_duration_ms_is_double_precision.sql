-- Singular test: trace_duration_ms must be DOUBLE PRECISION, not NUMERIC.
--
-- EXTRACT(EPOCH FROM interval) returns numeric in PostgreSQL 14+; without an
-- explicit cast the column type propagates as numeric through to psycopg3,
-- which maps it to decimal.Decimal rather than float.  The anomaly detector
-- record mapper (record_mapper.py) passes values through without coercion and
-- relies on psycopg3's native DOUBLE PRECISION → float delivery.  A NUMERIC
-- column would cause TypeError in float arithmetic inside the detectors.
--
-- The ::double precision cast in int_trace_spans guarantees the correct type.
-- This test catches any future regression that removes or weakens that cast.
--
-- A non-empty result means the test fails.

select
    trace_id,
    pg_typeof(trace_duration_ms)::text as actual_type
from {{ ref('int_trace_spans') }}
where pg_typeof(trace_duration_ms)::text <> 'double precision'
limit 1
