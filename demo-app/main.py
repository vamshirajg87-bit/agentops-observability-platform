"""
main.py

Application / invocation layer for the AgentOps demo-app.

Phase 3 / Milestone 3.2:
- Configure OpenTelemetry tracing.
- Create one root span around the full LangGraph invocation.
- Correlate application request/session IDs with telemetry attributes.
"""

import uuid

from graph import app
from agents.tool_agent import ToolExecutionError
from observability.tracing import configure_tracing, get_tracer


SCHEMA_VERSION = "1.0"


def _generate_request_id() -> str:
    return f"req_{uuid.uuid4().hex}"


def _generate_session_id() -> str:
    return f"sess_{uuid.uuid4().hex}"


def main() -> None:
    configure_tracing()

    tracer = get_tracer("agentops.demo")

    user_request = input("Enter your request: ")

    request_id = _generate_request_id()
    session_id = _generate_session_id()

    initial_state = {
        "request_id": request_id,
        "session_id": session_id,
        "user_request": user_request,
        "retrieval_query": None,
        "retrieved_context": None,
        "tool_result": None,
        "synthesized_answer": None,
        "final_response": None,
    }

    try:
        with tracer.start_as_current_span("agentops.request") as span:
            span.set_attribute(
                "gen_ai.operation.name",
                "invoke_workflow",
            )
            span.set_attribute(
                "agentops.request_id",
                request_id,
            )
            span.set_attribute(
                "agentops.session_id",
                session_id,
            )
            span.set_attribute(
                "agentops.schema_version",
                SCHEMA_VERSION,
            )

            result = app.invoke(initial_state)

        print()
        print(result["final_response"])
    except ToolExecutionError as exc:
        print()
        print(f"[DEMO FAILURE] Agent execution failed: {exc}")
        print(
            "An error trace has been emitted. "
            "Open the Trace Viewer to investigate."
        )


if __name__ == "__main__":
    main()