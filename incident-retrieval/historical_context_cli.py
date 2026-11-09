"""
incident-retrieval/historical_context_cli.py

Phase 12.7: CLI for historical incident context.

Shows one investigation, its semantic retrieval status, and the historically
similar investigations with the fields the RCA analyzer recorded for them.

Historical similarity provides context only.  It does not prove that the
current incident has the same root cause as any historical investigation.
This program only presents stored data; it performs no analysis.

Usage:
    python historical_context_cli.py <investigation_id> [--top-k N]

    --top-k N    maximum number of historical matches, 1..50 (default 5)

Connection parameters come from the INCIDENT_RETRIEVAL_DB_* environment
variables (see retrieval_db.py).

The program is read-only.  It opens one connection, never commits, and on
exit rolls the connection back and closes it.  It does not load the
embedding model: retrieval compares embeddings that are already stored.

Output:
    A plain-text report on stdout.  Similarity is printed to four decimal
    places for display; the underlying value is not changed.  Errors are
    written to stderr as one line.

Exit codes:
    0  success, including every retrieval status:
         ok (with or without matches), not_eligible, query_not_embedded,
         text_mismatch
    1  investigation not found (InvestigationNotFoundError)
    2  usage or argument error
    3  configuration error — missing environment variable (RuntimeError)
    4  database error
    6  data integrity or internal validation error
   130 keyboard interrupt (SIGINT)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional, TextIO

import retrieval_db
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity
from historical_context import (
    HistoricalContext,
    InvestigationContext,
    get_historical_context,
)
from sentence_transformer_backend import (
    EMBEDDING_DIMENSION,
    MODEL_NAME,
    MODEL_REVISION,
)
from similarity_search import (
    DEFAULT_TOP_K,
    MAX_TOP_K,
    MIN_TOP_K,
    STATUS_NOT_ELIGIBLE,
    STATUS_OK,
    STATUS_QUERY_NOT_EMBEDDED,
    STATUS_TEXT_MISMATCH,
)


EXIT_OK: int = 0
EXIT_NOT_FOUND: int = 1
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_DATA_INTEGRITY: int = 6
EXIT_INTERRUPTED: int = 130

_NONE: str = "(none)"

_STATUS_EXPLANATIONS: dict[str, str] = {
    STATUS_NOT_ELIGIBLE: (
        "Investigations with confidence INSUFFICIENT_DATA are not compared."
    ),
    STATUS_QUERY_NOT_EMBEDDED: (
        "This investigation has no stored embedding for the current model "
        "and document version, so it cannot be compared. Nothing was "
        "embedded or written."
    ),
    STATUS_TEXT_MISMATCH: (
        "The stored embedding of this investigation no longer matches its "
        "current incident document, so it was not used for comparison."
    ),
}


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def _investigation_id_argument(value: str) -> str:
    if value.strip() == "":
        raise argparse.ArgumentTypeError("investigation_id must not be empty")
    return value


def _top_k_argument(value: str) -> int:
    try:
        top_k = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be an integer between {MIN_TOP_K} and {MAX_TOP_K}"
        ) from None
    if not MIN_TOP_K <= top_k <= MAX_TOP_K:
        raise argparse.ArgumentTypeError(
            f"must be an integer between {MIN_TOP_K} and {MAX_TOP_K}"
        )
    return top_k


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Show historically similar investigations for one investigation. "
            "Historical similarity is context only, not evidence of cause."
        ),
    )
    parser.add_argument(
        "investigation_id",
        type=_investigation_id_argument,
        help="Primary key of the investigation in public.rca_investigations.",
    )
    parser.add_argument(
        "--top-k",
        type=_top_k_argument,
        default=DEFAULT_TOP_K,
        metavar="N",
        help=(
            f"Maximum number of historical matches, {MIN_TOP_K}..{MAX_TOP_K} "
            f"(default {DEFAULT_TOP_K})."
        ),
    )
    return parser.parse_args(argv)


def _locked_identity() -> EmbeddingModelIdentity:
    """The locked model identity.  Built from constants; no model is loaded."""
    return EmbeddingModelIdentity(
        model_name=MODEL_NAME,
        model_revision=MODEL_REVISION,
        dimension=EMBEDDING_DIMENSION,
    )


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------

def _display(value: Optional[str]) -> str:
    """One-line display form of a stored text value."""
    if value is None:
        return _NONE
    collapsed = " ".join(value.split())
    return collapsed or _NONE


def _context_lines(
    context: InvestigationContext,
    indent: str,
    similarity: Optional[float] = None,
) -> list[str]:
    """Field lines for one investigation, without the leading id line."""
    lines: list[str] = []
    if similarity is not None:
        lines.append(f"{indent}similarity:    {similarity:.4f}")
    limitations = ", ".join(_display(item) for item in context.limitations)
    lines.extend([
        f"{indent}anomaly:       {_display(context.anomaly_type)}",
        f"{indent}service:       {_display(context.service_name)}",
        f"{indent}operation:     {_display(context.operation_name)}",
        f"{indent}severity:      {_display(context.severity)}",
        f"{indent}confidence:    {_display(context.confidence)}",
        f"{indent}event time:    {context.event_time.isoformat()}",
        f"{indent}limitations:   {limitations or _NONE}",
        f"{indent}summary:       {_display(context.summary)}",
    ])
    return lines


def render_historical_context(context: HistoricalContext) -> str:
    """
    Render the plain-text report.  Deterministic: the same context always
    yields the same text.  Lines are separated by LF; no trailing newline.

    Raises RuntimeError for a status this program does not know.
    """
    lines: list[str] = [
        "Current investigation",
        f"  investigation: {_display(context.current.investigation_id)}",
    ]
    lines.extend(_context_lines(context.current, "  "))
    lines.append("")
    lines.append(f"Retrieval status: {context.status}")

    count = len(context.matches)
    if context.status == STATUS_OK:
        if count == 0:
            lines.append("  No historical matches were found.")
        else:
            noun = "match" if count == 1 else "matches"
            lines.append(
                f"  {count} historical {noun} (top-k {context.top_k}), "
                "ordered by similarity."
            )
    elif context.status in _STATUS_EXPLANATIONS:
        lines.append(f"  {_STATUS_EXPLANATIONS[context.status]}")
    else:
        raise RuntimeError(f"unknown retrieval status: {context.status!r}")

    if count:
        lines.append("")
        lines.append("Historical matches")
        for rank, match in enumerate(context.matches, start=1):
            prefix = f"{rank}. "
            indent = " " * len(prefix)
            lines.append("")
            lines.append(
                f"{prefix}investigation: "
                f"{_display(match.investigation.investigation_id)}"
            )
            lines.extend(
                _context_lines(match.investigation, indent, match.similarity)
            )

    lines.append("")
    lines.append(f"Note: {context.disclaimer}")
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
    _write(sys.stderr, f"error: {' '.join(str(message).split())}")


def _cleanup(conn: Any) -> None:
    """
    Release the connection this program opened: roll back, then close.

    close() is attempted even when rollback() fails.  A cleanup failure is
    reported on stderr and does not change the exit code; nothing was written.
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
    args = _parse_args(argv)

    try:
        conn = retrieval_db.connect()
    except RuntimeError as exc:
        _error(f"configuration: {exc}")
        return EXIT_CONFIGURATION
    except retrieval_db.DatabaseError as exc:
        _error(f"database: {exc}")
        return EXIT_DATABASE

    try:
        context = get_historical_context(
            conn,
            _locked_identity(),
            args.investigation_id,
            top_k=args.top_k,
        )
        report = render_historical_context(context)
    except InvestigationNotFoundError as exc:
        _error(f"investigation not found: {exc.investigation_id!r}")
        return EXIT_NOT_FOUND
    except retrieval_db.DatabaseError as exc:
        _error(f"database: {exc}")
        return EXIT_DATABASE
    except (ValueError, RuntimeError) as exc:
        _error(f"data integrity: {exc}")
        return EXIT_DATA_INTEGRITY
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    finally:
        _cleanup(conn)

    _write(sys.stdout, report)
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
