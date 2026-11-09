"""
graph.py

LangGraph wiring for the AgentOps demo-app.

Phase 3 / Milestone 3.2 changes:
the graph now registers observability wrappers instead of the raw
business-logic node functions.

The graph topology and execution order remain unchanged.
"""

from langgraph.graph import StateGraph, START, END

from observability.instrumentation import (
    instrumented_supervisor_start,
    instrumented_research_plan,
    instrumented_retrieval,
    instrumented_tool_agent,
    instrumented_research_synthesize,
    instrumented_supervisor_finalize,
)
from state import AgentState


graph_builder = StateGraph(AgentState)

graph_builder.add_node(
    "supervisor_start",
    instrumented_supervisor_start,
)
graph_builder.add_node(
    "research_plan",
    instrumented_research_plan,
)
graph_builder.add_node(
    "retrieval",
    instrumented_retrieval,
)
graph_builder.add_node(
    "tool_agent",
    instrumented_tool_agent,
)
graph_builder.add_node(
    "research_synthesize",
    instrumented_research_synthesize,
)
graph_builder.add_node(
    "supervisor_finalize",
    instrumented_supervisor_finalize,
)

graph_builder.add_edge(START, "supervisor_start")
graph_builder.add_edge("supervisor_start", "research_plan")
graph_builder.add_edge("research_plan", "retrieval")
graph_builder.add_edge("retrieval", "tool_agent")
graph_builder.add_edge("tool_agent", "research_synthesize")
graph_builder.add_edge(
    "research_synthesize",
    "supervisor_finalize",
)
graph_builder.add_edge(
    "supervisor_finalize",
    END,
)

app = graph_builder.compile()