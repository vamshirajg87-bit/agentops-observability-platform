"""
data/sample_docs.py

Static local "corpus" used by the Retrieval Agent in Milestone 1.

This is NOT a vector database and contains no embeddings. It is a
small, fixed, hardcoded set of documents used purely to demonstrate
deterministic keyword/token matching in the Retrieval Agent.

Each document is treated as a single chunk (no sub-document chunking
in Milestone 1) to keep retrieval logic simple and deterministic.
"""

from typing import Dict, List

SAMPLE_DOCUMENTS: List[Dict[str, str]] = [
    {
        "document_id": "doc_1",
        "content": (
            "LangGraph is a framework for building stateful, multi-agent "
            "applications as explicit graphs of nodes and edges. It "
            "supports conditional routing, cycles, and shared state "
            "passed between agent nodes."
        ),
    },
    {
        "document_id": "doc_2",
        "content": (
            "Observability platforms for distributed systems typically "
            "rely on structured telemetry such as traces, spans, and "
            "metrics. OpenTelemetry is a widely adopted standard for "
            "collecting and exporting this telemetry data."
        ),
    },
    {
        "document_id": "doc_3",
        "content": (
            "Root cause analysis in software incidents involves "
            "correlating anomalies with candidate contributing factors "
            "and supporting evidence, rather than assuming causation "
            "directly from correlation alone."
        ),
    },
    {
        "document_id": "doc_4",
        "content": (
            "Apache Kafka is a distributed event streaming platform "
            "commonly used as a durable, high-throughput backbone for "
            "publishing and consuming real-time event data between "
            "producers and consumers."
        ),
    },
    {
        "document_id": "doc_5",
        "content": (
            "Retrieval-augmented generation combines a retrieval step "
            "over a document corpus with a generation step, allowing "
            "an agent to ground its output in retrieved context rather "
            "than relying solely on parametric knowledge."
        ),
    },
    {
        "document_id": "doc_6",
        "content": (
            "PostgreSQL is a relational database commonly used as a "
            "system of record for validated, structured application "
            "data, supporting transactions, indexing, and complex "
            "queries."
        ),
    },
]