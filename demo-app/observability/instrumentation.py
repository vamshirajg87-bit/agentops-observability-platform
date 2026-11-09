"""
observability/instrumentation.py

Tracing wrapper layer for the AgentOps demo-app LangGraph nodes
(Phase 3, Milestone 3.2).

Each wrapper creates an OpenTelemetry span around the corresponding
existing node function and returns that function's result unchanged.

No agent business logic is implemented here.
"""

from opentelemetry.trace import StatusCode

from state import AgentState
from agents.supervisor import (
    supervisor_start_node,
    supervisor_finalize_node,
)
from agents.research import (
    research_plan_node,
    research_synthesize_node,
)
from agents.retrieval import retrieval_node
from agents.tool_agent import tool_agent_node
from observability.tracing import get_tracer


# OpenTelemetry may return a ProxyTracer if the SDK provider has not yet
# been configured. Once configure_tracing() installs the real provider,
# spans created through this tracer use that configured provider.
_tracer = get_tracer("agentops.demo")


def instrumented_supervisor_start(state: AgentState) -> dict:
    with _tracer.start_as_current_span("supervisor.start") as span:
        span.set_attribute("agent.name", "supervisor")
        span.set_attribute("agent.operation", "start")

        return supervisor_start_node(state)


def instrumented_research_plan(state: AgentState) -> dict:
    with _tracer.start_as_current_span("research.plan") as span:
        span.set_attribute("agent.name", "research")
        span.set_attribute("agent.operation", "plan")

        return research_plan_node(state)


def instrumented_retrieval(state: AgentState) -> dict:
    with _tracer.start_as_current_span("retrieval.search") as span:
        span.set_attribute("agent.name", "retrieval")
        span.set_attribute("agent.operation", "search")
        span.set_attribute("gen_ai.operation.name", "retrieval")

        result = retrieval_node(state)

        retrieved_context = result.get("retrieved_context") or []

        span.set_attribute(
            "retrieval.result_count",
            len(retrieved_context),
        )

        if retrieved_context:
            top_score = max(
                chunk.relevance_score
                for chunk in retrieved_context
            )

            span.set_attribute(
                "retrieval.top_relevance_score",
                top_score,
            )

        return result


def instrumented_tool_agent(state: AgentState) -> dict:
    with _tracer.start_as_current_span("tool.execute") as span:
        span.set_attribute("agent.name", "tool_agent")
        span.set_attribute("agent.operation", "execute")
        span.set_attribute("gen_ai.operation.name", "execute_tool")

        try:
            result = tool_agent_node(state)
        except Exception as exc:
            # Set error.type and error.message as span ATTRIBUTES (not events)
            # so normalization.py promotes them to the error_type / error_message
            # columns in the DB and the Trace Viewer can surface them without
            # needing to parse span events.
            span.set_attribute("error.type", type(exc).__name__)
            span.set_attribute("error.message", str(exc))
            span.set_status(StatusCode.ERROR, str(exc))
            raise

        tool_result = result.get("tool_result")

        if tool_result is not None:
            span.set_attribute(
                "tool.name",
                tool_result.tool_name,
            )
            span.set_attribute(
                "tool.status",
                tool_result.status,
            )

        return result


def instrumented_research_synthesize(state: AgentState) -> dict:
    with _tracer.start_as_current_span("research.synthesize") as span:
        span.set_attribute("agent.name", "research")
        span.set_attribute("agent.operation", "synthesize")

        return research_synthesize_node(state)


def instrumented_supervisor_finalize(state: AgentState) -> dict:
    with _tracer.start_as_current_span("supervisor.finalize") as span:
        span.set_attribute("agent.name", "supervisor")
        span.set_attribute("agent.operation", "finalize")

        return supervisor_finalize_node(state)