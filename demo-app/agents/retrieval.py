"""
agents/retrieval.py

Retrieval Agent for the AgentOps demo-app (Milestone 1).

Performs deterministic keyword/token matching against the static local
corpus in data/sample_docs.py. Explicitly NOT embeddings, NOT vector
similarity, and NOT a vector database.

relevance_score formula:
    relevance_score = |query_keywords ∩ document_keywords| / |query_keywords|

This is always in the range [0.0, 1.0] by construction.

Exposes:
    retrieve(query)        - pure, independently testable retrieval logic.
    retrieval_node(state)  - LangGraph node adapter around retrieve().
"""

from typing import List

from data.sample_docs import SAMPLE_DOCUMENTS
from state import AgentState, RetrievedChunk

# Maximum number of matching chunks to return.
TOP_K = 3


def _tokenize(text: str) -> set:
    """
    Lowercase and split text into a set of unique word tokens.

    Simple whitespace/punctuation-insensitive split; deterministic and
    dependency-free.
    """
    cleaned = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
    return set(cleaned.split())


def retrieve(query: str) -> List[RetrievedChunk]:
    """
    Search the static corpus for documents matching `query` using
    deterministic keyword overlap scoring.

    Returns the top TOP_K matches (relevance_score > 0.0), sorted
    descending by relevance_score. Ties preserve original corpus order
    (stable sort).

    Returns an empty list if the query has no usable keywords.
    """
    query_keywords = _tokenize(query)

    if not query_keywords:
        return []

    scored_chunks: List[RetrievedChunk] = []

    for doc in SAMPLE_DOCUMENTS:
        document_keywords = _tokenize(doc["content"])
        matched_keywords = query_keywords & document_keywords

        relevance_score = len(matched_keywords) / len(query_keywords)

        if relevance_score == 0.0:
            continue

        scored_chunks.append(
            RetrievedChunk(
                document_id=doc["document_id"],
                chunk_id=f"{doc['document_id']}_chunk_0",
                content=doc["content"],
                relevance_score=relevance_score,
            )
        )

    # Stable sort: ties keep original SAMPLE_DOCUMENTS order.
    scored_chunks.sort(key=lambda chunk: chunk.relevance_score, reverse=True)

    return scored_chunks[:TOP_K]


def retrieval_node(state: AgentState) -> dict:
    """
    LangGraph node adapter for the Retrieval Agent.

    Reads state["retrieval_query"], calls retrieve(), and returns only
    the partial state update expected by LangGraph.

    If retrieval_query is None or empty, returns an empty result list
    rather than calling retrieve() with unusable input.
    """
    query = state.get("retrieval_query")

    if not query:
        return {"retrieved_context": []}

    results = retrieve(query)
    return {"retrieved_context": results}