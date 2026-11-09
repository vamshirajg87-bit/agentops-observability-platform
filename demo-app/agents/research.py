"""
agents/research.py

Research Agent for the AgentOps demo-app (Milestone 1).

Implemented as two explicit LangGraph node functions, matching the two
distinct points the Research Agent appears at in the approved happy path:

    Supervisor -> research_plan_node -> Retrieval -> Tool Agent
                -> research_synthesize_node -> Supervisor

No LLM calls, no network calls, no randomness, no embeddings. Query
generation and synthesis are both deterministic, rule-based string
processing.

Research does NOT perform retrieval itself and does NOT call Tool Agent
functions directly - orchestration between nodes is the graph's job.
"""

from typing import List, Optional

from state import AgentState, RetrievedChunk, ToolResult

# Common filler words dropped when deriving a retrieval query from the
# user's request. Deliberately small and explicit for transparency.
_STOPWORDS = {
    "a", "an", "the", "is", "are", "of", "about", "tell", "me", "what",
    "explain", "please", "can", "you", "in", "on", "for", "to",
}


def _tokenize(text: str) -> List[str]:
    """
    Lowercase and split text into word tokens, stripping punctuation.
    Same approach as retrieval.py's _tokenize, for consistency.
    """
    cleaned = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
    return cleaned.split()


def _derive_retrieval_query(user_request: str) -> str:
    """
    Deterministically derive a retrieval query from the user's request:
      1. Tokenize (lowercase, strip punctuation).
      2. Remove stopwords.
      3. Join remaining tokens, preserving original order.
      4. Fallback to the full tokenized request if stopword removal
         leaves nothing.
    """
    tokens = _tokenize(user_request)
    filtered = [tok for tok in tokens if tok not in _STOPWORDS]

    if not filtered:
        filtered = tokens

    return " ".join(filtered)


def research_plan_node(state: AgentState) -> dict:
    """
    LangGraph node adapter: Research Agent, planning pass.

    Reads state["user_request"], deterministically derives a
    retrieval_query, and returns only that partial state update.
    """
    user_request = state.get("user_request") or ""
    retrieval_query = _derive_retrieval_query(user_request)
    return {"retrieval_query": retrieval_query}


def _document_summary(retrieved_context: Optional[List[RetrievedChunk]]) -> Optional[str]:
    """
    Build a natural-language summary of supporting information from
    retrieved document chunks, using their content directly. Does not
    surface document_id or relevance_score - those are debug details,
    not user-facing content. Does not invent information beyond what
    was retrieved.
    """
    if not retrieved_context:
        return None

    # Use the content of the retrieved chunks, most relevant first
    # (retrieved_context is already sorted by relevance_score).
    contents = [chunk.content.strip() for chunk in retrieved_context]

    if len(contents) == 1:
        return f"The retrieved context describes it as follows: {contents[0]}"

    joined = " ".join(contents)
    return f"The retrieved context provides the following relevant information: {joined}"


def _humanize(label: str) -> str:
    """Turn a snake_case field value into a readable phrase."""
    return label.replace("_", " ")


def _tool_summary(tool_result: Optional[ToolResult]) -> Optional[str]:
    """
    Build a natural-language summary of the Tool Agent's structured
    lookup result. Returns None if there is no successful tool result.
    """
    if tool_result is None or tool_result.status != "success":
        return None

    payload = tool_result.result_payload

    technology = payload.get("technology", "This technology")
    category = payload.get("category")
    deployment_model = payload.get("deployment_model")
    supports_real_time = payload.get("supports_real_time")

    sentences = []

    if category:
        sentences.append(
            f"The technology information service classifies "
            f"{technology} as {_humanize(category)} technology."
        )
    else:
        sentences.append(
            f"The technology information service recognizes {technology}."
        )

    if deployment_model and deployment_model != "n/a":
        sentences.append(
            f"Its deployment model is {_humanize(deployment_model)}."
        )

    if supports_real_time is True:
        sentences.append("It supports real-time operation.")
    elif supports_real_time is False:
        sentences.append("It is not designed for real-time operation.")

    return " ".join(sentences)
def research_synthesize_node(state: AgentState) -> dict:
    """
    LangGraph node adapter: Research Agent, synthesis pass.

    Reads state["user_request"], state["retrieved_context"], and
    state["tool_result"], deterministically combines both sources into
    a natural-language synthesized_answer, and returns only that
    partial state update.

    Handles missing/empty retrieved_context and missing/not_found
    tool_result without erroring, and without treating not_found as a
    failure.
    """
    user_request = state.get("user_request") or ""
    retrieved_context = state.get("retrieved_context")
    tool_result = state.get("tool_result")

    doc_summary = _document_summary(retrieved_context)
    tool_summary = _tool_summary(tool_result)

    if doc_summary and tool_summary:
        synthesized_answer = f"{tool_summary} {doc_summary}"

    elif doc_summary and not tool_summary:
        synthesized_answer = doc_summary
        if tool_result is not None and tool_result.status == "not_found":
            synthesized_answer += " No additional structured technology metadata was available for this request."

    elif tool_summary and not doc_summary:
        synthesized_answer = tool_summary

    else:
        synthesized_answer = (
            f"No supporting document or tool information was found for "
            f"the request: \"{user_request}\"."
        )

    return {"synthesized_answer": synthesized_answer}