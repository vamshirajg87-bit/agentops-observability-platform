-- Phase 11.7: Allow the RCA analyzer to use the rca_evidence
-- unique conflict target while preserving least-privilege access.
--
-- Required by:
--   ON CONFLICT (investigation_id, span_id) DO NOTHING
--
-- The analyzer intentionally does not receive table-level SELECT.

GRANT SELECT (investigation_id, span_id)
ON public.rca_evidence
TO rca_analyzer;