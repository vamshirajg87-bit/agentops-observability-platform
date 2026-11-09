"""
workload_generator/personas.py

The four traffic profiles of the workload generator.

These are NOT four different agents.  The demo application has one fixed
workflow; a persona describes who is using it: which questions are asked,
how many requests share a session, and how quickly they follow each other.

The query pools are written out in full so that they can be reviewed.  They
are tied to what the demo agent really knows: its tool recognises five
technologies (LangGraph, OpenTelemetry, Apache Kafka, retrieval-augmented
generation, PostgreSQL) and its retrieval step searches six short documents
about the same subjects.  A unit test runs every query through the demo's
own tool and retrieval functions and checks the outcome each persona is
meant to have.

Standard library only.

Public API:
    Persona                the four personas
    PersonaProfile         session shape and mix weight of one persona
    PROFILES               persona -> profile
    MIX                    the personas and weights of the default mix
    session_queries()      the queries of one planned session
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .rng import Draw


class Persona(Enum):
    TECHNOLOGY_LOOKUP = "technology-lookup"
    RESEARCH_SESSION = "research-session"
    OFF_TOPIC_USER = "off-topic-user"
    AUTOMATION_CLIENT = "automation-client"


@dataclass(frozen=True)
class PersonaProfile:
    """
    weight is the share of SESSIONS in the default mix.  session_length is
    the inclusive range of requests per session.  think_gap is the mean gap
    between two requests of one session, relative to a mean gap of 1.0
    between the starts of two sessions.
    """

    persona: Persona
    description: str
    weight: float
    session_length: tuple[int, int]
    think_gap: float


PROFILES: Mapping[Persona, PersonaProfile] = {
    Persona.TECHNOLOGY_LOOKUP: PersonaProfile(
        persona=Persona.TECHNOLOGY_LOOKUP,
        description="one or two questions about a technology the tool knows",
        weight=0.45,
        session_length=(1, 2),
        think_gap=0.60,
    ),
    Persona.RESEARCH_SESSION: PersonaProfile(
        persona=Persona.RESEARCH_SESSION,
        description="three to eight related questions in one session",
        weight=0.25,
        session_length=(3, 8),
        think_gap=0.80,
    ),
    Persona.OFF_TOPIC_USER: PersonaProfile(
        persona=Persona.OFF_TOPIC_USER,
        description="questions the agent has no tool data and no documents for",
        weight=0.15,
        session_length=(1, 3),
        think_gap=0.50,
    ),
    Persona.AUTOMATION_CLIENT: PersonaProfile(
        persona=Persona.AUTOMATION_CLIENT,
        description="a script repeating one short query in a quick burst",
        weight=0.15,
        session_length=(3, 10),
        think_gap=0.03,
    ),
}

MIX: tuple[Persona, ...] = tuple(PROFILES)
MIX_WEIGHTS: tuple[float, ...] = tuple(PROFILES[persona].weight for persona in MIX)

#: Share of an automation client's requests that arrive with no text at all.
#: The demo agent accepts an empty request and answers with a placeholder.
EMPTY_REQUEST_PROBABILITY: float = 0.05


# ---------------------------------------------------------------------------
# Query pools
# ---------------------------------------------------------------------------

#: Every query names exactly one technology the demo tool recognises.
TECHNOLOGY_QUERIES: tuple[str, ...] = (
    "What is LangGraph?",
    "Explain LangGraph conditional routing",
    "How is LangGraph deployed?",
    "Tell me about OpenTelemetry",
    "What is OpenTelemetry used for?",
    "What category of technology is OpenTelemetry?",
    "Explain Apache Kafka",
    "What is Kafka event streaming?",
    "Is Kafka real-time?",
    "What is RAG?",
    "Explain retrieval-augmented generation",
    "What is retrieval augmented generation?",
    "Tell me about PostgreSQL",
    "What is Postgres used for?",
    "Does PostgreSQL support transactions?",
)

#: Four threads of related questions.  Within a thread some questions name a
#: technology (the tool answers) and some do not (the tool finds nothing and
#: only the retrieved documents contribute).
RESEARCH_THREADS: Mapping[str, tuple[str, ...]] = {
    "streaming": (
        "What is Apache Kafka?",
        "How do producers and consumers exchange event data?",
        "Is Kafka suitable for real-time event streaming?",
        "What makes a streaming platform durable?",
        "How does Kafka compare with PostgreSQL as a system of record?",
        "Which platform handles high-throughput publishing?",
        "Where should validated application data be stored?",
        "Summarize Kafka as an event backbone",
    ),
    "observability": (
        "What is OpenTelemetry?",
        "How are traces and spans structured?",
        "Which telemetry do observability platforms rely on?",
        "How does root cause analysis use anomalies?",
        "What supporting evidence does incident analysis need?",
        "Does correlation alone prove causation?",
        "How is telemetry data collected and exported?",
        "Summarize OpenTelemetry for distributed systems",
    ),
    "agents": (
        "What is LangGraph?",
        "How do multi-agent applications share state?",
        "What are graphs of nodes and edges?",
        "Does LangGraph support cycles?",
        "What is retrieval augmented generation?",
        "How does an agent ground its output in retrieved context?",
        "How does RAG differ from parametric knowledge?",
        "Summarize LangGraph conditional routing",
    ),
    "data": (
        "What is PostgreSQL?",
        "Which database supports transactions and indexing?",
        "How are complex queries handled in a relational database?",
        "Is Postgres a system of record?",
        "How does Kafka feed structured application data?",
        "What is a document corpus?",
        "How does retrieval over a corpus work?",
        "Summarize PostgreSQL for structured data",
    ),
}

#: Subjects the demo agent knows nothing about: the tool finds no technology
#: and retrieval finds at most one weakly matching document.
OFF_TOPIC_QUERIES: tuple[str, ...] = (
    "How do I bake sourdough bread?",
    "Best hiking trails near Denver",
    "What time does the pharmacy close?",
    "Recommend a good science fiction novel",
    "How do I fix a flat bicycle tire?",
    "Weather forecast tomorrow morning",
    "Convert 12 miles to kilometers",
    "Who won the football match yesterday?",
    "Cheap flights to Lisbon in March",
    "How long should I boil an egg?",
    "Plan a birthday party menu",
    "What is the capital of Australia?",
)

#: What a script sends: a bare keyword or a short probe.
AUTOMATION_QUERIES: tuple[str, ...] = (
    "kafka",
    "postgres",
    "langgraph",
    "opentelemetry",
    "rag",
    "kafka status",
    "postgres status",
    "status",
    "ping",
    "health check",
)


# ---------------------------------------------------------------------------
# Session planning
# ---------------------------------------------------------------------------

def session_queries(persona: Persona, length: int, draw: Draw) -> tuple[str, ...]:
    """
    The queries of one session of the given persona, in the order asked.

    Raises:
        ValueError  length is below 1 or longer than a research thread.
    """
    if length < 1:
        raise ValueError("a session holds at least one request")

    if persona is Persona.TECHNOLOGY_LOOKUP:
        return tuple(draw.choice(TECHNOLOGY_QUERIES) for _ in range(length))

    if persona is Persona.RESEARCH_SESSION:
        thread = RESEARCH_THREADS[draw.choice(tuple(RESEARCH_THREADS))]
        if length > len(thread):
            raise ValueError("a research session cannot be longer than its thread")
        first = draw.index(len(thread) - length + 1)
        # Consecutive questions: a session reads like one line of inquiry.
        return thread[first:first + length]

    if persona is Persona.OFF_TOPIC_USER:
        return tuple(draw.choice(OFF_TOPIC_QUERIES) for _ in range(length))

    if persona is Persona.AUTOMATION_CLIENT:
        repeated = draw.choice(AUTOMATION_QUERIES)
        return tuple(
            "" if draw.uniform() < EMPTY_REQUEST_PROBABILITY else repeated
            for _ in range(length)
        )

    raise ValueError(f"unknown persona {persona!r}")
