"""
agents/tool_agent.py

Tool Agent for the AgentOps demo-app (Milestone 1).

Simulates a deterministic external "technology information service" —
a structured metadata lookup, distinct from the unstructured document
context returned by the Retrieval Agent. This is NOT a real external
API — no network calls, no randomness, no retries, no failure or
timeout simulation. Given the same query, it always produces the same
output.

Exposes:
    run_tool(query)          - pure, independently testable tool logic.
    tool_agent_node(state)   - LangGraph node adapter around run_tool().
"""

from typing import List, Optional

from state import AgentState, ToolResult

TOOL_NAME = "technology_info_service"

# Exact query string (case-insensitive) that triggers the deterministic failure
# scenario.  Pass this as the user request to produce an ERROR-status span for
# testing the error investigation UI without any real service being unavailable.
FAIL_TRIGGER = "fail_demo_unavailable"

# research._derive_retrieval_query() applies _tokenize() which replaces every
# non-alphanumeric character (including underscores) with a space and lower-
# cases. The user types FAIL_TRIGGER but run_tool() receives the normalized
# form below. Both are checked so the failure fires whether the trigger arrives
# directly or via the LangGraph research pipeline.
_FAIL_TRIGGER_NORMALIZED = " ".join(
    "".join(ch.lower() if ch.isalnum() else " " for ch in FAIL_TRIGGER).split()
)


class ToolExecutionError(RuntimeError):
    """Raised by run_tool() when the deterministic failure scenario is triggered.

    Trigger by passing FAIL_TRIGGER as the query.  The resulting exception is
    captured on the 'tool.execute' span with error.type and error.message
    attributes so the full error pipeline (OTel → Kafka → DB → Trace Viewer)
    can be exercised end-to-end.
    """

# Deterministic local table simulating a fake external "technology
# information service". Each entry has a canonical metadata payload
# and a list of aliases used to match against the incoming query.
#
# Table order defines deterministic tie-breaking: if a query somehow
# matches more than one technology, the first technology in this list
# (in iteration order) wins.
_TECH_INFO_TABLE = [
    {
        "aliases": ["langgraph"],
        "metadata": {
            "technology": "LangGraph",
            "category": "agent_orchestration_framework",
            "deployment_model": "library",
            "supports_real_time": True,
        },
    },
    {
        "aliases": ["opentelemetry", "open telemetry"],
        "metadata": {
            "technology": "OpenTelemetry",
            "category": "observability_standard",
            "deployment_model": "instrumentation_library",
            "supports_real_time": True,
        },
    },
    {
        "aliases": ["kafka", "apache kafka"],
        "metadata": {
            "technology": "Apache Kafka",
            "category": "event_streaming",
            "deployment_model": "distributed",
            "supports_real_time": True,
        },
    },
    {
        "aliases": [
            "rag",
            "retrieval augmented generation",
            "retrieval-augmented generation",
        ],
        "metadata": {
            "technology": "Retrieval-Augmented Generation",
            "category": "ml_technique",
            "deployment_model": "n/a",
            "supports_real_time": False,
        },
    },
    {
        "aliases": ["postgresql", "postgres"],
        "metadata": {
            "technology": "PostgreSQL",
            "category": "relational_database",
            "deployment_model": "client_server",
            "supports_real_time": False,
        },
    },
]


def _normalize(text: str) -> str:
    """
    Lowercase text and replace hyphens with spaces, so that
    "retrieval-augmented generation" and "retrieval augmented
    generation" normalize identically.
    """
    return text.lower().replace("-", " ")


def _tokenize(text: str) -> List[str]:
    """
    Split normalized text into whitespace-separated word tokens,
    stripping any remaining punctuation from each token's edges.
    """
    normalized = _normalize(text)
    cleaned = "".join(ch if ch.isalnum() or ch.isspace() else " " for ch in normalized)
    return cleaned.split()


def _match_technology(query: str) -> Optional[dict]:
    """
    Deterministically match a query against _TECH_INFO_TABLE, avoiding
    accidental substring matches (e.g. "rag" inside "storage").

    Matching rule:
      - Single-word aliases must match a whole token in the query
        (query is tokenized on whitespace/punctuation).
      - Multi-word aliases must appear as a normalized phrase
        (contiguous substring) within the normalized query, so word
        order/adjacency is preserved but punctuation/hyphen
        differences don't break the match.

    If multiple technologies match, the first one in table order wins
    (deterministic tie-breaking).
    """
    query_tokens = set(_tokenize(query))
    normalized_query = _normalize(query)

    for entry in _TECH_INFO_TABLE:
        for alias in entry["aliases"]:
            if " " in alias:
                # Multi-word alias: match as a normalized phrase.
                if alias in normalized_query:
                    return entry["metadata"]
            else:
                # Single-word alias: match a whole token only.
                if alias in query_tokens:
                    return entry["metadata"]

    return None


def run_tool(query: str) -> ToolResult:
    """
    Deterministically look up structured technology metadata for the
    given query against a fixed local table simulating an external
    information service.

    If the query is empty/whitespace or matches no known technology,
    returns a structured "not_found" result. This is a defined,
    deterministic outcome, not a failure or error condition.

    If the query matches FAIL_TRIGGER (case-insensitive, stripped), raises
    ToolExecutionError to simulate a service failure for demo/testing purposes.
    """
    q = query.strip().lower()
    if q == FAIL_TRIGGER or q == _FAIL_TRIGGER_NORMALIZED:
        raise ToolExecutionError(
            "External service unavailable: "
            "connection refused to metadata.example.internal"
        )

    if not query or not query.strip():
        return ToolResult(
            tool_name=TOOL_NAME,
            status="not_found",
            result_payload={
                "query": query,
                "matched": False,
                "reason": "empty_query",
            },
        )

    metadata = _match_technology(query)

    if metadata is None:
        return ToolResult(
            tool_name=TOOL_NAME,
            status="not_found",
            result_payload={
                "query": query,
                "matched": False,
                "reason": "no_known_technology_matched",
            },
        )

    return ToolResult(
        tool_name=TOOL_NAME,
        status="success",
        result_payload={
            "query": query,
            "matched": True,
            **metadata,
        },
    )


def tool_agent_node(state: AgentState) -> dict:
    """
    LangGraph node adapter for the Tool Agent.

    Reads state["retrieval_query"], calls run_tool(), and returns only
    the partial state update expected by LangGraph.

    If retrieval_query is None, treats it as an empty string rather
    than erroring.
    """
    query = state.get("retrieval_query") or ""

    result = run_tool(query)
    return {"tool_result": result}