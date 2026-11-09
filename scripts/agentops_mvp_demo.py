"""
scripts/agentops_mvp_demo.py

The deterministic MVP demo dataset and the pure functions around it.

This module only DESCRIBES data and renders it as SQL text and fixed read-only SQL
strings.  It never connects to anything, never runs a process and never opens a file.
agentops_mvp.py decides whether, when and where the text is used.

The dataset (seed label b3j-176)
--------------------------------
  13 traces of 7 spans each + 1 of 5   -> 96 rows in public.telemetry_spans
      12 normal traces                    (7 spans, baseline)
       1 slow-tool trace                  (7 spans, tool.execute 2350 ms)
       1 failed-tool trace                (5 spans, tool.execute ERROR, root ERROR)
   2 anomalies                          -> public.anomaly_events
   2 RCA investigations                 -> public.rca_investigations
  12 RCA evidence rows (7 slow + 5 failed) -> public.rca_evidence

Everything is explicit: UTC timestamps, SHA-256 derived identifiers, no randomness and no
clock.  The anomaly and investigation identifiers use the SAME algorithms as the anomaly
detector and the RCA analyzer, and the anomaly values, the evidence scores, the confidence,
the summary and the limitation codes are produced by re-implementations of their logic
that the tests compare, field by field, with the repository implementations.  Only the
text of the visible markers is invented:

  * every anomaly explanation starts with "[DEMO SEED]"
  * every investigation's limitations end with a "[DEMO SEED] ..." entry

The failed trace has five spans, as in a real run: the tool exception stops the graph after
tool.execute, so research.synthesize and supervisor.finalize never run.

A second, separate function set (spans_only_rows / spans_only_sql, label b3j-419) renders the telemetry
alone, with a caller-chosen start time, for running the real detector and analyzer on it.  It does not
change anything above: seed_sql() is byte for byte what it was.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Sequence

SEED_LABEL = "b3j-176"
KAFKA_TOPIC = "agentops.demo.seed.b3j176"
SERVICE_NAME = "agentops-demo-app"
ANALYZER_VERSION = "1.0.0"
DETECTOR_VERSION = "1.0"
DEMO_MARKER = "[DEMO SEED]"
TOOL_NAME = "technology_info_service"
ERROR_TYPE = "ToolExecutionError"
ERROR_MESSAGE = "External service unavailable: connection refused to metadata.example.internal"

BASE_TIME = datetime(2026, 10, 15, 9, 0, 0, tzinfo=timezone.utc)
NORMAL_TRACES = 12
SPANS_PER_TRACE = 7
FAILED_SPANS_PER_TRACE = 5      # the graph stops after tool.execute

#: public tables the seed may write, in insertion order (parents first)
TABLES = ("telemetry_spans", "anomaly_events", "rca_investigations", "rca_evidence")
EXPECTED_COUNTS = {"telemetry_spans": 96, "anomaly_events": 2, "rca_investigations": 2, "rca_evidence": 12}

#: the bootstrap ledger a seedable database must hold, exactly, in this order
EXPECTED_LEDGER_STEPS = (
    "001_create_telemetry_spans.sql", "dbt_run", "002_create_grafana_reader.sql",
    "003_create_trace_viewer_reader.sql", "004_create_anomaly_events.sql",
    "005_create_anomaly_detector_role.sql", "006_create_anomaly_detector_runs.sql",
    "007_create_rca_tables.sql", "008_create_rca_analyzer_role.sql",
    "009_grant_rca_evidence_conflict_select.sql", "010_create_rca_investigation_embeddings.sql",
    "011_create_incident_retrieval_role.sql", "012_create_alert_tables.sql",
    "013_create_alert_evaluator_role.sql", "014_create_alert_notifier_role.sql",
    "post_dbt_grants.sql", "complete", "015_grant_trace_viewer_anomaly_rca_read.sql",
)

COLUMNS: Mapping[str, tuple[str, ...]] = {
    "telemetry_spans": (
        "schema_version", "event_type", "trace_id", "span_id", "parent_span_id", "span_name", "span_kind",
        "service_name", "start_time", "end_time", "duration_ms", "status_code", "status_message",
        "request_id", "session_id", "gen_ai_operation", "agent_name", "agent_operation", "tool_name",
        "tool_status", "retrieval_result_count", "retrieval_top_relevance_score", "error_type",
        "error_message", "attributes", "kafka_topic", "kafka_partition", "kafka_offset", "ingested_at"),
    "anomaly_events": (
        "anomaly_id", "anomaly_type", "signal_name", "detector_name", "detector_version", "trace_id",
        "span_id", "service_name", "operation_name", "observed_value", "event_time", "baseline_median",
        "baseline_mad", "baseline_n", "baseline_window_start", "baseline_window_end", "anomaly_score",
        "severity", "explanation", "detected_at"),
    "rca_investigations": (
        "investigation_id", "anomaly_id", "analyzer_version", "investigated_at", "trace_id",
        "subject_span_id", "service_name", "operation_name", "event_time", "trace_span_count",
        "anomaly_type", "observed_value", "baseline_median", "anomaly_score", "severity", "confidence",
        "summary", "limitations"),
    "rca_evidence": (
        "investigation_id", "span_id", "parent_span_id", "span_name", "service_name", "duration_ms",
        "status_code", "error_type", "error_message", "tool_name", "tool_status", "agent_name",
        "agent_operation", "retrieval_result_count", "retrieval_top_relevance_score", "is_root_span",
        "is_error_span", "is_direct_subject", "depth", "trace_duration_fraction", "evidence_type",
        "evidence_score", "evidence_score_breakdown", "explanation", "rank_position"),
}
#: the order every table is read back and compared in
ORDER_BY: Mapping[str, str] = {
    "telemetry_spans": "trace_id, span_id",
    "anomaly_events": "anomaly_id",
    "rca_investigations": "investigation_id",
    "rca_evidence": "investigation_id, rank_position",
}
TIMESTAMP_COLUMNS = frozenset({
    "start_time", "end_time", "ingested_at", "event_time", "baseline_window_start", "baseline_window_end",
    "detected_at", "investigated_at"})


# ---------------------------------------------------------------------------
# Identifiers (the same algorithms as the anomaly detector and the RCA analyzer)
# ---------------------------------------------------------------------------

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def trace_id_for(number: int, label: str = SEED_LABEL) -> str:
    return _digest(f"{label}|trace|{number}")[:32]


def span_id_for(trace_id: str, span_name: str) -> str:
    return _digest(f"{trace_id}|{span_name}")[:16]


def compute_anomaly_id(detector_name: str, detector_version: str, anomaly_type: str, signal_name: str,
                       service_name: Optional[str], operation_name: Optional[str], trace_id: Optional[str],
                       span_id: Optional[str], observed_at: datetime) -> str:
    """anomaly-detector/anomaly_repository.compute_anomaly_id, on plain values."""
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    identity = [detector_name, detector_version, anomaly_type, signal_name, service_name, operation_name,
                trace_id, span_id, observed_at.astimezone(timezone.utc).isoformat()]
    canonical = json.dumps(identity, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_investigation_id(anomaly_id: str, analyzer_version: str) -> str:
    """rca-analyzer/rca_persist.compute_investigation_id."""
    return _digest(f"{anomaly_id}|{analyzer_version}")


# ---------------------------------------------------------------------------
# Spans
# ---------------------------------------------------------------------------

#: duration of tool.execute in each normal trace (ms); gives the baseline a real spread
NORMAL_TOOL_MS = (118.0, 121.0, 119.0, 124.0, 117.0, 122.0, 120.0, 126.0, 115.0, 123.0, 119.0, 121.0)
NORMAL_TOP_SCORES = (0.91, 0.88, 0.93, 0.86, 0.9, 0.87, 0.92, 0.89, 0.85, 0.94, 0.9, 0.88)
SLOW_TOOL_MS = 2350.0
FAILED_TOOL_MS = 150.0
SLOW_TRACE_NUMBER = 13
FAILED_TRACE_NUMBER = 14

SPAN_NAMES = ("agentops.request", "supervisor.start", "research.plan", "retrieval.search", "tool.execute",
              "research.synthesize", "supervisor.finalize")
_AGENT = {
    "supervisor.start": ("supervisor", "start"), "research.plan": ("research", "plan"),
    "retrieval.search": ("retrieval", "search"), "tool.execute": ("tool_agent", "execute"),
    "research.synthesize": ("research", "synthesize"), "supervisor.finalize": ("supervisor", "finalize"),
}


def _ms(value: float) -> timedelta:
    return timedelta(milliseconds=value)


def _trace_spans(number: int, start: datetime, tool_ms: float, *, failed: bool, top_score: float,
                 first_offset: int, label: str = SEED_LABEL, topic: str = KAFKA_TOPIC) -> list[dict[str, Any]]:
    trace_id = trace_id_for(number, label)
    root_id = span_id_for(trace_id, SPAN_NAMES[0])
    request_id = "req_" + _digest(f"{label}|request|{number}")[:32]
    session_id = "sess_" + _digest(f"{label}|session|{number}")[:32]

    # explicit offsets (ms after the trace start) keep the arithmetic obvious
    layout = {"supervisor.start": (5.0, 4.0), "research.plan": (12.0, 18.0), "retrieval.search": (34.0, 85.0),
              "tool.execute": (124.0, tool_ms)}
    if failed:
        root_end = 124.0 + tool_ms + 4.0          # the exception ends the request right after tool.execute
    else:
        synth_start = 124.0 + tool_ms + 6.0
        layout["research.synthesize"] = (synth_start, 240.0)
        finalize_start = synth_start + 240.0 + 3.0
        layout["supervisor.finalize"] = (finalize_start, 6.0)
        root_end = finalize_start + 6.0 + 4.0
    layout["agentops.request"] = (0.0, root_end)

    ingested_at = start + _ms(root_end) + timedelta(seconds=2)
    rows: list[dict[str, Any]] = []
    for index, name in enumerate(SPAN_NAMES[:FAILED_SPANS_PER_TRACE] if failed else SPAN_NAMES):
        offset, duration = layout[name]
        is_root = name == SPAN_NAMES[0]
        is_tool = name == "tool.execute"
        agent = _AGENT.get(name)
        attributes: dict[str, Any] = {"demo_seed": label}
        row: dict[str, Any] = {
            "schema_version": "1.0", "event_type": "span", "trace_id": trace_id,
            "span_id": span_id_for(trace_id, name), "parent_span_id": None if is_root else root_id,
            "span_name": name, "span_kind": "INTERNAL", "service_name": SERVICE_NAME,
            "start_time": start + _ms(offset), "end_time": start + _ms(offset + duration),
            "duration_ms": duration, "status_code": "UNSET", "status_message": None,
            "request_id": request_id if is_root else None, "session_id": session_id if is_root else None,
            "gen_ai_operation": None, "agent_name": None, "agent_operation": None, "tool_name": None,
            "tool_status": None, "retrieval_result_count": None, "retrieval_top_relevance_score": None,
            "error_type": None, "error_message": None, "kafka_topic": topic, "kafka_partition": 0,
            "kafka_offset": first_offset + index, "ingested_at": ingested_at,
        }
        if is_root:
            row["gen_ai_operation"] = "invoke_workflow"
            attributes.update({"gen_ai.operation.name": "invoke_workflow", "agentops.request_id": request_id,
                               "agentops.session_id": session_id, "agentops.schema_version": "1.0"})
            if failed:
                row["status_code"] = "ERROR"
                row["status_message"] = f"{ERROR_TYPE}: {ERROR_MESSAGE}"
        if agent:
            row["agent_name"], row["agent_operation"] = agent
            attributes.update({"agent.name": agent[0], "agent.operation": agent[1]})
        if name == "retrieval.search":
            row["gen_ai_operation"] = "retrieval"
            row["retrieval_result_count"] = 3
            row["retrieval_top_relevance_score"] = top_score
            attributes.update({"gen_ai.operation.name": "retrieval", "retrieval.result_count": 3,
                               "retrieval.top_relevance_score": top_score})
        if is_tool:
            row["gen_ai_operation"] = "execute_tool"
            attributes["gen_ai.operation.name"] = "execute_tool"
            if failed:
                row["status_code"] = "ERROR"
                row["status_message"] = ERROR_MESSAGE
                row["error_type"] = ERROR_TYPE
                row["error_message"] = ERROR_MESSAGE
                attributes.update({"error.type": ERROR_TYPE, "error.message": ERROR_MESSAGE})
            else:
                row["tool_name"] = TOOL_NAME
                row["tool_status"] = "success"
                attributes.update({"tool.name": TOOL_NAME, "tool.status": "success"})
        row["attributes"] = attributes
        rows.append(row)
    return rows


def trace_plan() -> list[tuple[int, datetime, float, bool, float]]:
    """(trace number, start, tool.execute duration, failed, top retrieval score), one per trace."""
    plan = []
    for i in range(NORMAL_TRACES):
        plan.append((i + 1, BASE_TIME + timedelta(minutes=5 * i), NORMAL_TOOL_MS[i], False, NORMAL_TOP_SCORES[i]))
    plan.append((SLOW_TRACE_NUMBER, BASE_TIME + timedelta(minutes=60), SLOW_TOOL_MS, False, 0.9))
    plan.append((FAILED_TRACE_NUMBER, BASE_TIME + timedelta(minutes=65), FAILED_TOOL_MS, True, 0.89))
    return plan


# ---------------------------------------------------------------------------
# Anomalies (the latency baseline is the median / MAD of the normal traces)
# ---------------------------------------------------------------------------

MAD_SCALE = 0.6745          # the detector's modified z-score constant


def median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return float(ordered[middle]) if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2.0


def modified_z(observed: float, baseline_median: float, mad: float) -> float:
    return MAD_SCALE * (observed - baseline_median) / mad


def _anomalies(spans_by_trace: Mapping[int, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    tool = {n: next(s for s in rows if s["span_name"] == "tool.execute") for n, rows in spans_by_trace.items()}
    baseline = [tool[n]["duration_ms"] for n in range(1, NORMAL_TRACES + 1)]
    med = median(baseline)
    mad = median([abs(v - med) for v in baseline])
    slow, failed = tool[SLOW_TRACE_NUMBER], tool[FAILED_TRACE_NUMBER]
    score = round(modified_z(slow["duration_ms"], med, mad), 6)

    latency = {
        "anomaly_type": "latency", "signal_name": "duration_ms", "detector_name": "LatencyDetector",
        "detector_version": DETECTOR_VERSION, "trace_id": slow["trace_id"], "span_id": slow["span_id"],
        "service_name": SERVICE_NAME, "operation_name": "tool.execute", "observed_value": slow["duration_ms"],
        "event_time": slow["start_time"], "baseline_median": med, "baseline_mad": mad,
        "baseline_n": len(baseline), "baseline_window_start": slow["start_time"] - timedelta(days=7),
        "baseline_window_end": slow["start_time"], "anomaly_score": score,
        # fewer than 30 baseline observations: the detector caps the severity at INFO
        "severity": "INFO",
        "explanation": (f"{DEMO_MARKER} duration_ms={slow['duration_ms']:.1f}; baseline_median={med:.1f} "
                        f"MAD={mad:.1f} n={len(baseline)}; modified_z={score:.2f} direction=HIGH"),
    }
    n_recent = NORMAL_TRACES + 2        # every tool.execute span in the window, the failing one included
    failure = {
        "anomaly_type": "tool_failure", "signal_name": "tool_error_rate", "detector_name": "ToolFailureDetector",
        "detector_version": DETECTOR_VERSION, "trace_id": failed["trace_id"], "span_id": failed["span_id"],
        "service_name": SERVICE_NAME, "operation_name": f"tool.execute/{ERROR_TYPE}", "observed_value": 1.0,
        "event_time": failed["start_time"], "baseline_median": None, "baseline_mad": None, "baseline_n": None,
        "baseline_window_start": None, "baseline_window_end": None, "anomaly_score": None, "severity": "INFO",
        "explanation": (f"{DEMO_MARKER} span_name=tool.execute error_type={ERROR_TYPE}; is_first_occurrence=True "
                        f"is_novel_type=True; n_recent={n_recent} is_persistent=False"),
    }
    rows = []
    for item in (latency, failure):
        item["anomaly_id"] = compute_anomaly_id(
            item["detector_name"], item["detector_version"], item["anomaly_type"], item["signal_name"],
            item["service_name"], item["operation_name"], item["trace_id"], item["span_id"], item["event_time"])
        item["detected_at"] = item["event_time"] + timedelta(seconds=60)
        rows.append(item)
    return rows


# ---------------------------------------------------------------------------
# RCA (a re-implementation of rca_evidence / rca_ranker / rca_confidence / rca_orchestrator
# for the two flat, single-root traces of this dataset; the tests compare it with the real code)
# ---------------------------------------------------------------------------

def _signal(anomaly: Mapping[str, Any]) -> str:
    if anomaly["anomaly_type"] == "latency":
        op = anomaly["operation_name"] or ""
        return "trace_latency" if op == "trace" else "tool_latency" if op == "tool.execute" else "agent_latency"
    return anomaly["anomaly_type"]


def _components(signal: str, frac: float, is_error: bool, is_subject: bool, error_type: Optional[str],
                anomaly_error_type: Optional[str]) -> tuple[float, float, float, float]:
    if signal == "tool_latency":
        return 0.30 * frac, 0.30 if is_error else 0.0, 0.40 if is_subject else 0.0, 0.0
    if signal == "tool_failure":
        d = 0.20 if (anomaly_error_type is not None and error_type is not None
                     and error_type == anomaly_error_type) else 0.0
        return 0.10 * frac, 0.40 if is_error else 0.0, 0.30 if is_subject else 0.0, d
    raise ValueError("unsupported signal for the demo dataset: " + signal)


def _evidence_type(a: float, b: float, c: float, d: float, signal: str) -> str:
    active = sum(1 for x in (a, b, c, d) if x > 0.0)
    if active == 0:
        return "telemetry"
    if active > 1:
        return "mixed"
    if a > 0.0:
        return "duration"
    if b > 0.0:
        return "error"
    if c > 0.0:
        return "direct_subject"
    return "tool_error_match" if signal == "tool_failure" else "signal_specific"


def _explanation(frac: Optional[float], a: float, b: float, c: float, d: float, signal: str) -> str:
    parts: list[str] = []
    if frac is None:
        parts.append("Trace envelope is zero-width; duration fraction unavailable")
    elif a > 0.0:
        parts.append(f"Span occupied {frac * 100:.1f}% of the trace wall-clock envelope")
    if b > 0.0:
        parts.append("Had ERROR status")
    if c > 0.0:
        parts.append("Is the anomaly's direct subject span")
    if signal == "tool_failure" and d > 0.0:
        parts.append("Error type matched the anomaly's encoded tool-failure error type")
    if not parts:
        parts.append("No positive evidence components for this span")
    return "; ".join(parts)


_GAP_TOLERANCE = 1e-9


def _small_gap(gap: float) -> bool:
    """rca_confidence: gap < 0.10 and not isclose(gap, 0.10) -> MEDIUM."""
    return gap < 0.10 and not math.isclose(gap, 0.10, rel_tol=0.0, abs_tol=_GAP_TOLERANCE)


def _investigation(anomaly: Mapping[str, Any], spans: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    signal = _signal(anomaly)
    prefix = "tool.execute/"
    anomaly_error_type = (anomaly["operation_name"][len(prefix):]
                          if signal == "tool_failure" and anomaly["operation_name"].startswith(prefix) else None)
    start = min(s["start_time"] for s in spans)
    end = max(s["end_time"] for s in spans)
    trace_ms = (end - start).total_seconds() * 1000.0

    scored = []
    for s in spans:
        frac = s["duration_ms"] / trace_ms if trace_ms != 0.0 else None
        is_error = s["status_code"] == "ERROR"
        is_subject = s["span_id"] == anomaly["span_id"]
        a, b, c, d = _components(signal, frac if frac is not None else 0.0, is_error, is_subject,
                                 s["error_type"], anomaly_error_type)
        scored.append({
            "span_id": s["span_id"], "parent_span_id": s["parent_span_id"], "span_name": s["span_name"],
            "service_name": s["service_name"], "duration_ms": s["duration_ms"], "status_code": s["status_code"],
            "error_type": s["error_type"], "error_message": s["error_message"], "tool_name": s["tool_name"],
            "tool_status": s["tool_status"], "agent_name": s["agent_name"],
            "agent_operation": s["agent_operation"], "retrieval_result_count": s["retrieval_result_count"],
            "retrieval_top_relevance_score": s["retrieval_top_relevance_score"],
            "is_root_span": s["parent_span_id"] is None, "is_error_span": is_error,
            "is_direct_subject": is_subject, "depth": 0 if s["parent_span_id"] is None else 1,
            "trace_duration_fraction": frac, "evidence_type": _evidence_type(a, b, c, d, signal),
            "evidence_score": min(1.0, a + b + c + d),
            "evidence_score_breakdown": f"duration={a:.3f},error={b:.3f},direct_subject={c:.3f},signal_specific={d:.3f}",
            "explanation": _explanation(frac, a, b, c, d, signal), "_start": s["start_time"],
        })
    scored.sort(key=lambda e: (-e["evidence_score"], e["_start"], e["span_id"]))

    threshold = {"tool_latency": 0.40, "tool_failure": 0.40}[signal]
    top = scored[0]
    if top["evidence_score"] < threshold or not any(e["is_direct_subject"] for e in scored):
        confidence = "LOW"
    elif _small_gap(top["evidence_score"] - scored[1]["evidence_score"]):
        confidence = "MEDIUM"
    elif any((e["trace_duration_fraction"] or 0.0) > 1.0 for e in scored):
        confidence = "MEDIUM"
    else:
        confidence = "HIGH"
    if confidence == "LOW":
        summary = (f"No span scored above the evidence threshold for this {anomaly['anomaly_type']} anomaly; "
                   "no strong contributing signal was found.")
    else:
        summary = (f"Span '{top['span_name']}' in service '{top['service_name']}' showed the strongest "
                   f"contributing evidence (score {top['evidence_score']:.2f}): {top['explanation']}.")
    limitations = []
    if signal == "tool_failure" and any(e["is_direct_subject"] and e["tool_name"] is None for e in scored):
        limitations.append("tool_name_absent")
    limitations.append(f"{DEMO_MARKER} Synthetic investigation computed offline from seeded spans; "
                       "it was not produced by the RCA analyzer worker.")

    investigation = {
        "investigation_id": compute_investigation_id(anomaly["anomaly_id"], ANALYZER_VERSION),
        "anomaly_id": anomaly["anomaly_id"], "analyzer_version": ANALYZER_VERSION,
        "investigated_at": anomaly["detected_at"] + timedelta(seconds=60), "trace_id": anomaly["trace_id"],
        "subject_span_id": anomaly["span_id"], "service_name": anomaly["service_name"],
        "operation_name": anomaly["operation_name"], "event_time": anomaly["event_time"],
        "trace_span_count": len(spans), "anomaly_type": anomaly["anomaly_type"],
        "observed_value": anomaly["observed_value"], "baseline_median": anomaly["baseline_median"],
        "anomaly_score": anomaly["anomaly_score"], "severity": anomaly["severity"], "confidence": confidence,
        "summary": summary, "limitations": limitations,
    }
    evidence = []
    for rank, item in enumerate(scored, start=1):
        item = dict(item)
        item.pop("_start")
        item["investigation_id"] = investigation["investigation_id"]
        item["rank_position"] = rank
        evidence.append(item)
    return investigation, evidence


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Manifest:
    telemetry_spans: tuple[dict[str, Any], ...]
    anomaly_events: tuple[dict[str, Any], ...]
    rca_investigations: tuple[dict[str, Any], ...]
    rca_evidence: tuple[dict[str, Any], ...]

    def rows(self, table: str) -> tuple[dict[str, Any], ...]:
        if table not in TABLES:
            raise ValueError("not a seed table")
        return getattr(self, table)

    def counts(self) -> dict[str, int]:
        return {table: len(self.rows(table)) for table in TABLES}


_CACHE: list[Manifest] = []


def build_manifest() -> Manifest:
    if _CACHE:
        return _CACHE[0]
    spans: list[dict[str, Any]] = []
    by_trace: dict[int, list[dict[str, Any]]] = {}
    for number, start, tool_ms, failed, top_score in trace_plan():
        rows = _trace_spans(number, start, tool_ms, failed=failed, top_score=top_score, first_offset=len(spans))
        by_trace[number] = rows
        spans.extend(rows)
    anomalies = _anomalies(by_trace)
    investigations: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for anomaly in anomalies:
        number = next(n for n, rows in by_trace.items() if rows[0]["trace_id"] == anomaly["trace_id"])
        investigation, rows = _investigation(anomaly, by_trace[number])
        investigations.append(investigation)
        evidence.extend(rows)
    manifest = Manifest(tuple(spans), tuple(anomalies), tuple(investigations), tuple(evidence))
    if manifest.counts() != EXPECTED_COUNTS:
        raise AssertionError("the manifest does not have the specified row counts")
    _CACHE.append(manifest)
    return manifest


# ---------------------------------------------------------------------------
# SQL text
# ---------------------------------------------------------------------------

def quote_text(value: str) -> str:
    if "\x00" in value:
        raise ValueError("NUL in a seed string")
    return "'" + value.replace("'", "''") + "'"


def sql_literal(column: str, value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("a non-finite number in a seed row")
        return repr(value)
    if isinstance(value, datetime):
        return quote_text(value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00") + "::timestamptz"
    if isinstance(value, dict):
        return quote_text(json.dumps(value, sort_keys=True, separators=(",", ":"))) + "::jsonb"
    if isinstance(value, list):
        return "ARRAY[" + ", ".join(quote_text(str(v)) for v in value) + "]::text[]"
    if isinstance(value, str):
        return quote_text(value)
    raise TypeError(f"unsupported seed value for {column}")


def insert_statement(table: str, rows: Sequence[Mapping[str, Any]]) -> str:
    columns = COLUMNS[table]
    values = ",\n".join("  (" + ", ".join(sql_literal(c, row[c]) for c in columns) + ")" for row in rows)
    return f"INSERT INTO public.{table} ({', '.join(columns)}) VALUES\n{values};"


_NOT_EMPTY = " + ".join(f"(SELECT count(*) FROM public.{t})" for t in TABLES)
_COUNT_CHECK = " AND ".join(f"(SELECT count(*) FROM public.{t}) = {EXPECTED_COUNTS[t]}" for t in TABLES)


def seed_sql(manifest: Optional[Manifest] = None) -> str:
    """The whole seed as ONE script for `psql --single-transaction`.  Tables are locked, found
    empty again inside the transaction, filled, and counted; any problem raises and rolls back."""
    manifest = manifest or build_manifest()
    lock_tables = ", ".join(f"public.{t}" for t in TABLES)
    parts = [
        f"-- {DEMO_MARKER} {SEED_LABEL}: demonstration data only",
        "SET LOCAL lock_timeout = '10s';",
        "SET LOCAL statement_timeout = '120s';",
        f"LOCK TABLE {lock_tables} IN EXCLUSIVE MODE;",
        f"DO $seed$ BEGIN IF {_NOT_EMPTY} <> 0 THEN "
        "RAISE EXCEPTION 'seed refused: the target tables are not empty'; END IF; END $seed$;",
    ]
    parts += [insert_statement(table, manifest.rows(table)) for table in TABLES]
    parts.append(f"DO $verify$ BEGIN IF NOT ({_COUNT_CHECK}) THEN "
                 "RAISE EXCEPTION 'seed verification failed: unexpected row counts'; END IF; END $verify$;")
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Spans only: telemetry for the real detector and analyzer to work on
# ---------------------------------------------------------------------------
#
# seed_sql() inserts finished results (anomalies, investigations, evidence).  This writes none of
# those: only public.telemetry_spans, so that running the anomaly detector and then the RCA analyzer
# produces rows that are genuinely theirs.  The traces have the shape of the seed above and use the
# same span builder; what differs is the label (so no identifier equals one of the seed's), the start
# time (the caller's, so the data can sit inside the detector's lookback window) and the number of
# baseline traces (at least the LatencyDetector's min_baseline_n of 30).
#
# Expected detector signals, in the order the traces occur (normal traces first, then one slow, then one failed):
#   tool_latency  -> LatencyDetector flags the slow tool.execute (2350 ms against a ~120 ms baseline)
#   tool_failure  -> ToolFailureDetector flags the failed tool.execute (first occurrence of its error type)
# The trace-level, agent and retrieval signals read analytics tables that dbt builds from this table;
# they hold nothing until dbt has run, so this data is aimed at tool_latency and tool_failure.

SPANS_ONLY_LABEL = "b3j-419"
SPANS_ONLY_DEFAULT_NORMAL_TRACES = 36
SPANS_ONLY_MIN_NORMAL_TRACES = 30       # the LatencyDetector's min_baseline_n
SPANS_ONLY_MAX_NORMAL_TRACES = 500
TRACE_SPACING_MINUTES = 5
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def _spans_only_arguments(base_time: datetime, normal_traces: int, label: str) -> datetime:
    if not isinstance(base_time, datetime) or base_time.tzinfo is None or base_time.utcoffset() is None:
        raise ValueError("base_time must be a timezone-aware datetime")
    if (isinstance(normal_traces, bool) or not isinstance(normal_traces, int)
            or not SPANS_ONLY_MIN_NORMAL_TRACES <= normal_traces <= SPANS_ONLY_MAX_NORMAL_TRACES):
        raise ValueError(f"normal_traces must be an integer from {SPANS_ONLY_MIN_NORMAL_TRACES} "
                         f"to {SPANS_ONLY_MAX_NORMAL_TRACES}")
    if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
        raise ValueError("label must be 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit")
    if label == SEED_LABEL:
        raise ValueError("label must differ from the seed's, so that no identifier is shared with it")
    return base_time.astimezone(timezone.utc)


def spans_only_expected_count(normal_traces: int = SPANS_ONLY_DEFAULT_NORMAL_TRACES) -> int:
    """Rows spans_only_sql inserts: seven spans per normal trace and per slow trace, five for the failed one."""
    return (normal_traces + 1) * SPANS_PER_TRACE + FAILED_SPANS_PER_TRACE


def spans_only_rows(base_time: datetime, *, normal_traces: int = SPANS_ONLY_DEFAULT_NORMAL_TRACES,
                    label: str = SPANS_ONLY_LABEL) -> tuple[dict[str, Any], ...]:
    """The telemetry_spans rows: `normal_traces` ordinary traces from base_time at five-minute spacing,
    then one trace whose tool.execute takes 2350 ms, then one whose tool.execute fails.  Pure and deterministic:
    the same arguments always give the same rows."""
    start = _spans_only_arguments(base_time, normal_traces, label)
    topic = "agentops.demo.seed." + label.replace("-", "")
    spacing = timedelta(minutes=TRACE_SPACING_MINUTES)
    plan = [(i + 1, start + spacing * i, NORMAL_TOOL_MS[i % len(NORMAL_TOOL_MS)], False,
             NORMAL_TOP_SCORES[i % len(NORMAL_TOP_SCORES)]) for i in range(normal_traces)]
    plan.append((normal_traces + 1, start + spacing * normal_traces, SLOW_TOOL_MS, False, 0.9))
    plan.append((normal_traces + 2, start + spacing * (normal_traces + 1), FAILED_TOOL_MS, True, 0.89))
    rows: list[dict[str, Any]] = []
    for number, trace_start, tool_ms, failed, top_score in plan:
        rows.extend(_trace_spans(number, trace_start, tool_ms, failed=failed, top_score=top_score,
                                 first_offset=len(rows), label=label, topic=topic))
    if len(rows) != spans_only_expected_count(normal_traces):
        raise AssertionError("the spans-only dataset does not have the specified row count")
    return tuple(rows)


def spans_only_extent(base_time: datetime, *, normal_traces: int = SPANS_ONLY_DEFAULT_NORMAL_TRACES,
                      label: str = SPANS_ONLY_LABEL) -> tuple[datetime, datetime]:
    """(earliest start_time, latest end_time) of the rows, so a caller can check them against a lookback window."""
    rows = spans_only_rows(base_time, normal_traces=normal_traces, label=label)
    return min(r["start_time"] for r in rows), max(r["end_time"] for r in rows)


def spans_only_sql(base_time: datetime, *, normal_traces: int = SPANS_ONLY_DEFAULT_NORMAL_TRACES,
                   label: str = SPANS_ONLY_LABEL) -> str:
    """The spans-only dataset as ONE script for `psql --single-transaction`.  It names public.telemetry_spans
    and no other table: the table is locked, found empty again inside the transaction, filled and counted;
    any problem raises and rolls back.  Nothing is executed here."""
    rows = spans_only_rows(base_time, normal_traces=normal_traces, label=label)
    parts = [
        f"-- {DEMO_MARKER} {label}: demonstration spans only (no anomalies, investigations or evidence)",
        "SET LOCAL lock_timeout = '10s';",
        "SET LOCAL statement_timeout = '120s';",
        "LOCK TABLE public.telemetry_spans IN EXCLUSIVE MODE;",
        "DO $seed$ BEGIN IF (SELECT count(*) FROM public.telemetry_spans) <> 0 THEN "
        "RAISE EXCEPTION 'spans-only seed refused: public.telemetry_spans is not empty'; END IF; END $seed$;",
        insert_statement("telemetry_spans", rows),
        f"DO $verify$ BEGIN IF (SELECT count(*) FROM public.telemetry_spans) <> {len(rows)} THEN "
        "RAISE EXCEPTION 'spans-only seed verification failed: unexpected row count'; END IF; END $verify$;",
    ]
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Fixed read-only SQL (each is passed whole to psql -c)
# ---------------------------------------------------------------------------

LEDGER_SQL = "SELECT position || '|' || step FROM agentops_bootstrap.ledger ORDER BY position"
COUNTS_SQL = "SELECT " + " || '|' || ".join(f"(SELECT count(*) FROM public.{t})" for t in TABLES)


def rows_sql(table: str) -> str:
    if table not in TABLES:
        raise ValueError("not a seed table")
    columns = ", ".join(COLUMNS[table])
    return (f"SELECT row_to_json(t) FROM (SELECT {columns} FROM public.{table} "
            f"ORDER BY {ORDER_BY[table]}) t")


_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_counts(text: str) -> Optional[dict[str, int]]:
    parts = text.strip().split("|")
    if len(parts) != len(TABLES) or not all(p.isdigit() for p in parts):
        return None
    return {table: int(part) for table, part in zip(TABLES, parts)}


def parse_ledger(text: str) -> list[tuple[int, str]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        position, _, step = line.partition("|")
        if not position.isdigit() or not step:
            raise ValueError("an unreadable ledger row")
        rows.append((int(position), step))
    return rows


def ledger_matches(rows: Sequence[tuple[int, str]]) -> bool:
    return list(rows) == [(i + 1, step) for i, step in enumerate(EXPECTED_LEDGER_STEPS)]


def _normalise(column: str, value: Any) -> Any:
    if column in TIMESTAMP_COLUMNS and isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    if column in TIMESTAMP_COLUMNS and isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, float) and value == int(value) and abs(value) < 1e15:
        return float(value)
    return value


def compare_rows(table: str, database_lines: str, manifest: Optional[Manifest] = None) -> list[str]:
    """Problems (fixed text) comparing what the database returned for rows_sql(table) with the
    manifest, column by column.  An empty list means the table matches exactly."""
    manifest = manifest or build_manifest()
    expected = manifest.rows(table)
    try:
        actual = [json.loads(line) for line in database_lines.splitlines() if line.strip()]
    except ValueError:
        return [f"{table}: the rows could not be read"]
    if len(actual) != len(expected):
        return [f"{table}: {len(actual)} rows found, {len(expected)} expected"]
    key = ORDER_BY[table].split(", ")
    ordered = sorted(expected, key=lambda r: tuple(str(r[k]) if k != "rank_position" else r[k] for k in key))
    problems = []
    for position, (want, got) in enumerate(zip(ordered, actual), start=1):
        for column in COLUMNS[table]:
            if column not in got:
                problems.append(f"{table}: row {position} has no column {column}")
                continue
            try:
                same = _normalise(column, want[column]) == _normalise(column, got[column])
            except ValueError:
                same = False
            if not same:
                problems.append(f"{table}: row {position} differs in {column}")
                break
    return problems[:10]
