"""
anomaly-detector/run_config.py

Runner configuration for the Phase 10.5 anomaly detector runner.

Loads and validates the JSON configuration that drives which
signal/service/operation groups the runner processes, and the timing
parameters (overlap and initial lookback) that govern evaluation windows.

Accepted JSON schema
--------------------
The configuration must be a JSON object with exactly two top-level keys:

    {
      "run": {
        "overlap_minutes":        <positive integer>,
        "initial_lookback_hours": <positive integer>
      },
      "groups": [
        {
          "signal_path":    "<one of the six valid signal paths>",
          "service_name":   "<non-empty, non-whitespace-only string>",
          "operation_name": "<non-empty string> | null"
        },
        ...
      ]
    }

Unknown keys at the root, in the "run" object, or in any group object are
rejected immediately so that typos such as "overlap_minute" or "service" fail
loudly rather than being silently ignored.

"operation_name" rules
----------------------
  Operation-required signals  (trace_latency, agent_latency, error_rate):
      "operation_name" must be a non-empty, non-whitespace-only string.
      null or missing raises ValueError.

  Operation-forbidden signals (tool_latency, retrieval, tool_failure):
      "operation_name" must be null, missing, or the empty string "".
      Any non-empty value raises ValueError.
      null / missing / "" all normalise to "" — the canonical stored form.

"groups" constraints
--------------------
  - Must contain at least one entry.
  - Duplicate (signal_path, service_name, operation_name) triples are
    rejected after operation_name normalisation.

Public API
----------
  VALID_SIGNAL_PATHS : frozenset[str]
  GroupConfig        : frozen dataclass — one detection group
  RunConfig          : frozen dataclass — full validated configuration
  load_config(path)  -> RunConfig
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Signal path constants
# ---------------------------------------------------------------------------

VALID_SIGNAL_PATHS: frozenset[str] = frozenset({
    "trace_latency",
    "agent_latency",
    "tool_latency",
    "retrieval",
    "error_rate",
    "tool_failure",
})

_OP_REQUIRED: frozenset[str] = frozenset({
    "trace_latency",
    "agent_latency",
    "error_rate",
})

_OP_FORBIDDEN: frozenset[str] = frozenset({
    "tool_latency",
    "retrieval",
    "tool_failure",
})

# Accepted key sets — used for unknown-key rejection.
_ROOT_KEYS: frozenset[str] = frozenset({"run", "groups"})
_RUN_KEYS: frozenset[str] = frozenset({"overlap_minutes", "initial_lookback_hours"})
_GROUP_KEYS: frozenset[str] = frozenset({"signal_path", "service_name", "operation_name"})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GroupConfig:
    """
    Immutable configuration for one (signal_path, service_name, operation_name)
    detection group.

    operation_name is always a str.  For operation-forbidden signal paths it
    is always '' (the canonical normalised form).
    """
    signal_path: str
    service_name: str
    operation_name: str


@dataclass(frozen=True)
class RunConfig:
    """
    Immutable runner configuration loaded from the JSON config file.

    overlap_minutes:        Minutes of overlap behind prior_checkpoint used to
                            catch late-arriving telemetry.  Must be > 0.
    initial_lookback_hours: Width of the candidate window on a first run
                            (when no prior checkpoint exists).  Must be > 0.
    groups:                 Tuple of all detection groups, in declaration order.
    """
    overlap_minutes: int
    initial_lookback_hours: int
    groups: tuple[GroupConfig, ...]


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def load_config(path: str | os.PathLike) -> RunConfig:
    """
    Load and validate a runner configuration from a JSON file at path.

    Raises:
        FileNotFoundError:    path does not exist.
        json.JSONDecodeError: file is not valid JSON.
        ValueError:           configuration is semantically or structurally
                              invalid.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return _validate_config_dict(data)


# ---------------------------------------------------------------------------
# Internal validation
# ---------------------------------------------------------------------------

def _validate_config_dict(data: Any) -> RunConfig:
    """
    Validate a parsed JSON config object and return a RunConfig.

    Intended for unit-testing the validation logic without file I/O.

    Raises ValueError for any structural or semantic violation.
    """
    if not isinstance(data, dict):
        raise ValueError(
            f"Config root must be a JSON object, got {type(data).__name__}"
        )

    unknown_root = set(data.keys()) - _ROOT_KEYS
    if unknown_root:
        raise ValueError(
            f"Unknown key(s) at config root: {sorted(unknown_root)}. "
            f"Accepted keys: {sorted(_ROOT_KEYS)}"
        )

    # ── run section ──────────────────────────────────────────────────────────

    if "run" not in data:
        raise ValueError("Config must have a 'run' section")
    run_section = data["run"]
    if not isinstance(run_section, dict):
        raise ValueError(
            f"'run' must be a JSON object, got {type(run_section).__name__}"
        )

    unknown_run = set(run_section.keys()) - _RUN_KEYS
    if unknown_run:
        raise ValueError(
            f"Unknown key(s) in 'run' section: {sorted(unknown_run)}. "
            f"Accepted keys: {sorted(_RUN_KEYS)}"
        )

    if "overlap_minutes" not in run_section:
        raise ValueError("'run.overlap_minutes' is required")
    _require_positive_int(run_section["overlap_minutes"], "run.overlap_minutes")
    overlap_minutes: int = run_section["overlap_minutes"]

    if "initial_lookback_hours" not in run_section:
        raise ValueError("'run.initial_lookback_hours' is required")
    _require_positive_int(run_section["initial_lookback_hours"], "run.initial_lookback_hours")
    initial_lookback_hours: int = run_section["initial_lookback_hours"]

    # ── groups ────────────────────────────────────────────────────────────────

    if "groups" not in data:
        raise ValueError("Config must have a 'groups' list")
    groups_raw = data["groups"]
    if not isinstance(groups_raw, list):
        raise ValueError(
            f"'groups' must be a JSON list, got {type(groups_raw).__name__}"
        )
    if len(groups_raw) == 0:
        raise ValueError("'groups' must contain at least one group")

    groups: list[GroupConfig] = []
    seen: set[tuple[str, str, str]] = set()

    for idx, raw in enumerate(groups_raw):
        group = _validate_group(raw, idx)
        key = (group.signal_path, group.service_name, group.operation_name)
        if key in seen:
            raise ValueError(
                f"Duplicate group at index {idx}: "
                f"(signal_path={group.signal_path!r}, "
                f"service_name={group.service_name!r}, "
                f"operation_name={group.operation_name!r})"
            )
        seen.add(key)
        groups.append(group)

    return RunConfig(
        overlap_minutes=overlap_minutes,
        initial_lookback_hours=initial_lookback_hours,
        groups=tuple(groups),
    )


def _require_positive_int(value: Any, field: str) -> None:
    # bool is a subclass of int in Python — must be rejected explicitly.
    if isinstance(value, bool):
        raise ValueError(f"'{field}' must be an integer, got bool")
    if not isinstance(value, int):
        raise ValueError(
            f"'{field}' must be an integer, got {type(value).__name__}"
        )
    if value <= 0:
        raise ValueError(
            f"'{field}' must be a positive integer (> 0), got {value}"
        )


def _validate_group(raw: Any, idx: int) -> GroupConfig:
    if not isinstance(raw, dict):
        raise ValueError(
            f"Group at index {idx} must be a JSON object, "
            f"got {type(raw).__name__}"
        )

    unknown = set(raw.keys()) - _GROUP_KEYS
    if unknown:
        raise ValueError(
            f"Unknown key(s) in group at index {idx}: {sorted(unknown)}. "
            f"Accepted keys: {sorted(_GROUP_KEYS)}"
        )

    # signal_path ────────────────────────────────────────────────────────────
    if "signal_path" not in raw:
        raise ValueError(f"Group at index {idx} is missing 'signal_path'")
    signal_path = raw["signal_path"]
    if not isinstance(signal_path, str):
        raise ValueError(
            f"Group at index {idx}: 'signal_path' must be a string, "
            f"got {type(signal_path).__name__}"
        )
    if signal_path not in VALID_SIGNAL_PATHS:
        raise ValueError(
            f"Group at index {idx}: unknown signal_path {signal_path!r}; "
            f"valid paths: {sorted(VALID_SIGNAL_PATHS)}"
        )

    # service_name ───────────────────────────────────────────────────────────
    if "service_name" not in raw:
        raise ValueError(f"Group at index {idx} is missing 'service_name'")
    service_name = raw["service_name"]
    if not isinstance(service_name, str):
        raise ValueError(
            f"Group at index {idx}: 'service_name' must be a string, "
            f"got {type(service_name).__name__}"
        )
    if not service_name:
        raise ValueError(
            f"Group at index {idx}: 'service_name' must not be empty"
        )
    if service_name.strip() == "":
        raise ValueError(
            f"Group at index {idx}: 'service_name' must not be whitespace-only"
        )

    # operation_name ─────────────────────────────────────────────────────────
    # Key may be absent; treat absence the same as JSON null.
    raw_op = raw.get("operation_name", None)

    if signal_path in _OP_REQUIRED:
        if raw_op is None:
            raise ValueError(
                f"Group at index {idx}: signal_path {signal_path!r} requires "
                f"a non-empty 'operation_name'; got null or missing"
            )
        if not isinstance(raw_op, str):
            raise ValueError(
                f"Group at index {idx}: 'operation_name' must be a string, "
                f"got {type(raw_op).__name__}"
            )
        if not raw_op:
            raise ValueError(
                f"Group at index {idx}: 'operation_name' must not be empty "
                f"for signal_path {signal_path!r}"
            )
        if raw_op.strip() == "":
            raise ValueError(
                f"Group at index {idx}: 'operation_name' must not be whitespace-only "
                f"for signal_path {signal_path!r}"
            )
        operation_name = raw_op

    else:  # signal_path in _OP_FORBIDDEN
        # Accepted: null, missing, or explicit "".  Any other value is rejected.
        if raw_op is not None and raw_op != "":
            raise ValueError(
                f"Group at index {idx}: signal_path {signal_path!r} does not "
                f"accept a non-empty 'operation_name'; got {raw_op!r}. "
                f"Use null or omit the key."
            )
        operation_name = ""

    return GroupConfig(
        signal_path=signal_path,
        service_name=service_name,
        operation_name=operation_name,
    )
