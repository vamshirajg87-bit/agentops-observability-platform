"""
state.py

Defines the shared state passed between nodes in the
AgentOps demo application's LangGraph workflow.

Milestone 1 flow:

User
-> Supervisor
-> Research (planning)
-> Retrieval
-> Tool Agent
-> Research (synthesis)
-> Supervisor (final response)
-> User

Milestone 1 intentionally does NOT include:
- OpenTelemetry
- trace_id / span_id
- Kafka
- external LLM APIs
- vector databases
- failure injection
"""

from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field


class RetrievedChunk(BaseModel):
    """
    One document chunk returned by the Retrieval Agent.
    """

    document_id: str
    chunk_id: str
    content: str

    relevance_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Deterministic keyword/token relevance score. "
            "This is not an embedding or vector similarity score."
        ),
    )


class ToolResult(BaseModel):
    """
    Structured result returned by the deterministic Tool Agent.
    """

    tool_name: str
    status: str
    result_payload: Dict[str, Any]


class AgentState(TypedDict):
    """
    Shared LangGraph application state.

    Each graph node reads required values from this mapping and returns
    only the fields that it updates.
    """

    request_id: str
    session_id: str

    user_request: str

    retrieval_query: Optional[str]

    retrieved_context: Optional[List[RetrievedChunk]]

    tool_result: Optional[ToolResult]

    synthesized_answer: Optional[str]

    final_response: Optional[str]