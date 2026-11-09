"""
incident-retrieval/incident_signal.py

Phase 12.5: Derived signal for an investigation.

The incident document builder (incident_document.py) takes the derived signal
as an explicit input.  It is not stored in any column, so it is recomputed
here from the two persisted fields it depends on.

This restates the signal routing rule of the RCA analyzer
(rca-analyzer/rca_confidence.py, _derive_signal).  It is an independent copy
on purpose: this component does not import RCA scoring or confidence code.
If the RCA analyzer's rule changes, this function must be changed to match.

Rule:
    anomaly_type == "latency" and operation_name == "trace"         -> trace_latency
    anomaly_type == "latency" and operation_name == "tool.execute"  -> tool_latency
    anomaly_type == "latency" and any other operation_name          -> agent_latency
    any other anomaly_type                                          -> anomaly_type

The comparison is exact and case-sensitive; no normalization is applied.

Standard library only.  No database access, no I/O.

Public API:
    derive_signal()  — (anomaly_type, operation_name) -> signal name
"""

from __future__ import annotations

from typing import Optional


def derive_signal(anomaly_type: str, operation_name: Optional[str]) -> str:
    """
    Map an investigation's anomaly_type and operation_name to its signal name.

    Returns one of 'trace_latency', 'agent_latency', 'tool_latency' for a
    latency anomaly; otherwise returns anomaly_type unchanged
    ('retrieval_quality', 'error_rate', 'tool_failure').
    """
    if anomaly_type == "latency":
        op = operation_name or ""
        if op == "trace":
            return "trace_latency"
        if op == "tool.execute":
            return "tool_latency"
        return "agent_latency"
    return anomaly_type
