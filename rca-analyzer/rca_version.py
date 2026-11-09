"""
rca-analyzer/rca_version.py

Phase 11.5: Single authoritative version string for the RCA analyzer.

This module is the ONE source of truth for analyzer_version used in:
  1. Computing investigation_id: SHA-256(anomaly_id + "|" + analyzer_version)
  2. Persisting rca_investigations.analyzer_version

Must never be derived from Git SHA, wall-clock time, or any runtime state.
A version bump signals a contract change in RCA scoring or confidence logic.
"""

from __future__ import annotations

RCA_ANALYZER_VERSION: str = "1.0.0"
