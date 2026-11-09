"""
incident-retrieval/embedding_backfill_cli.py

Phase 12.8: CLI for the embedding backfill.

Embeds and persists every existing investigation that does not have an
embedding yet, using the locked local model.  Investigations that must not
be embedded are reported, not stored.  Nothing is ever overwritten, updated,
or deleted, so the program is safe to run again: a rerun stores nothing new.

Usage:
    python embedding_backfill_cli.py

The program takes no arguments.

Connection parameters come from the INCIDENT_RETRIEVAL_DB_* environment
variables (see retrieval_db.py).

The embedding model is loaded from local files only, and only when the first
new embedding is needed.  Importing this module does not load it.

Output:
    A plain-text report on stdout: the model identity, one line per
    investigation as it is processed, and a summary.  Errors are written to
    stderr as one line.

Exit codes:
    0  completed: no investigation failed and no stored text mismatched
    2  usage or argument error
    3  configuration error — missing environment variable (RuntimeError)
    4  database error
    6  one or more investigations failed, or one or more stored embeddings
       hold text that no longer matches (text_mismatch)
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional, TextIO

import retrieval_db
from embedding_backfill import (
    STATUS_FAILURE,
    BackfillReport,
    BackfillResult,
    backfill_embeddings,
)
from embedding_provider import EmbeddingProvider
from incident_document import DOC_VERSION
from sentence_transformer_backend import create_default_provider


EXIT_OK: int = 0
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_INCOMPLETE: int = 6
EXIT_INTERRUPTED: int = 130


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Embed and persist every existing investigation that has no "
            "embedding yet. Safe to rerun; nothing is overwritten."
        ),
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------

def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def render_header(provider: EmbeddingProvider) -> str:
    identity = provider.identity
    return "\n".join([
        "Embedding backfill",
        f"  model:       {_one_line(identity.model_name)}",
        f"  revision:    {_one_line(identity.model_revision)}",
        f"  doc version: {DOC_VERSION}",
        "",
        "Investigations",
    ])


def render_result(result: BackfillResult) -> str:
    """One line for one investigation."""
    line = f"  {_one_line(result.investigation_id)}  {result.status}"
    if result.status == STATUS_FAILURE and result.error is not None:
        line += f"  {_one_line(result.error)}"
    elif getattr(result.token_usage, "truncated", False) is True:
        line += "  (document truncated by the model)"
    return line


def render_summary(report: BackfillReport) -> str:
    lines = []
    if report.total == 0:
        lines.append("  (none)")
    lines.extend([
        "",
        "Summary",
        f"  investigations:  {report.total}",
        f"  inserted:        {report.inserted}",
        f"  already_present: {report.already_present}",
        f"  not_eligible:    {report.not_eligible}",
        f"  text_mismatch:   {report.text_mismatch}",
        f"  failures:        {report.failures}",
        "",
    ])
    if report.succeeded:
        lines.append("Result: completed")
    else:
        lines.append(
            "Result: completed with problems "
            f"({report.failures} failed, {report.text_mismatch} text_mismatch). "
            "Nothing was overwritten."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _write(stream: TextIO, text: str) -> None:
    """Write text and a newline; never fail on an unencodable character."""
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="backslashreplace").decode(encoding)
        stream.write(safe + "\n")


def _error(message: str) -> None:
    _write(sys.stderr, f"error: {_one_line(message)}")


def _cleanup(conn: Any) -> None:
    """
    Release the connection this program opened: roll back, then close.

    Every investigation has already been committed or rolled back by the
    pipeline, so the rollback only ends a transaction left open by an
    interrupted run.  close() is attempted even when rollback() fails.  A
    cleanup failure is reported on stderr and does not change the exit code.
    """
    try:
        conn.rollback()
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
        _error(f"rollback failed during cleanup: {exc}")
    try:
        conn.close()
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
        _error(f"close failed during cleanup: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    _parse_args(argv)

    # Constructs objects only; the model is loaded lazily, from local files.
    provider = create_default_provider()

    try:
        conn = retrieval_db.connect()
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION
    except retrieval_db.DatabaseError as exc:
        _error(f"database: {exc}")
        return EXIT_DATABASE

    _write(sys.stdout, render_header(provider))

    try:
        report = backfill_embeddings(
            conn,
            provider,
            on_result=lambda result: _write(sys.stdout, render_result(result)),
        )
    except retrieval_db.DatabaseError as exc:
        _error(f"database: {exc}")
        return EXIT_DATABASE
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _write(sys.stdout, render_summary(report))
    return EXIT_OK if report.succeeded else EXIT_INCOMPLETE


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
