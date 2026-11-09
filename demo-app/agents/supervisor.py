"""
agents/supervisor.py

Supervisor Agent for the AgentOps demo-app (Milestone 1).

Implemented as two explicit LangGraph node functions, matching the two
points the Supervisor appears at in the approved happy path:

    User -> supervisor_start_node -> research_plan_node -> retrieval_node
         -> tool_agent_node -> research_synthesize_node
         -> supervisor_finalize_node -> User

No LLM calls, no network calls, no randomness. request_id/session_id are
established by the invocation layer (main.py), not by the Supervisor -
these nodes only read/pass through existing state.
"""

from state import AgentState

# Deterministic placeholder used when user_request is blank/whitespace
# after stripping, so downstream nodes always receive non-empty input.
_EMPTY_REQUEST_PLACEHOLDER = "No request was provided."

# Deterministic fallback used if synthesized_answer is missing.
_MISSING_SYNTHESIS_FALLBACK = (
    "No research result was available to finalize a response."
)


def supervisor_start_node(state: AgentState) -> dict:
    """
    LangGraph node adapter: Supervisor, start pass.

    Reads state["user_request"], strips surrounding whitespace, and
    substitutes a deterministic placeholder if the result is empty.
    Returns an update only when the normalized value differs from the
    original; otherwise returns {} (no update needed).

    Does not generate or modify request_id/session_id. Does not route.
    Does not call other agent functions directly.
    """
    user_request = state.get("user_request") or ""
    normalized = user_request.strip()

    if not normalized:
        normalized = _EMPTY_REQUEST_PLACEHOLDER

    if normalized != user_request:
        return {"user_request": normalized}

    return {}


def supervisor_finalize_node(state: AgentState) -> dict:
    """
    LangGraph node adapter: Supervisor, finalize pass.

    Reads state["synthesized_answer"] and returns it as
    final_response. Does not re-run research or invent new facts.

    If synthesized_answer is missing (None), returns a deterministic
    fallback message rather than crashing.
    """
    synthesized_answer = state.get("synthesized_answer")

    if not synthesized_answer:
        final_response = _MISSING_SYNTHESIS_FALLBACK
    else:
        final_response = synthesized_answer

    return {"final_response": final_response}