"""
workload-generator/tests/unit/test_personas.py

Unit tests for personas.py.

Test inventory:
    WP01  The four personas and their profiles
    WP02  Query pools: explicit, reviewable, well formed
    WP03  Session planning
    WP04  Pools against the demo agent's own tool and retrieval functions

WP04 imports the pure tool and retrieval functions of demo-app and calls
them directly.  It does not run the agent graph, creates no span and sends
nothing.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from workload_generator import personas
from workload_generator.personas import (
    AUTOMATION_QUERIES,
    MIX,
    MIX_WEIGHTS,
    OFF_TOPIC_QUERIES,
    PROFILES,
    RESEARCH_THREADS,
    TECHNOLOGY_QUERIES,
    Persona,
    session_queries,
)
from workload_generator.rng import Draw

_REPO = Path(__file__).resolve().parents[3]

_ALL_POOLS = {
    "technology": TECHNOLOGY_QUERIES,
    "off-topic": OFF_TOPIC_QUERIES,
    "automation": AUTOMATION_QUERIES,
    **{f"thread:{name}": thread for name, thread in RESEARCH_THREADS.items()},
}
_RESEARCH_QUERIES = {query for thread in RESEARCH_THREADS.values() for query in thread}


# ---------------------------------------------------------------------------
# WP01  Personas and profiles
# ---------------------------------------------------------------------------

class TestProfiles:

    def test_exactly_the_four_approved_personas(self):
        assert [persona.name for persona in Persona] == [
            "TECHNOLOGY_LOOKUP", "RESEARCH_SESSION", "OFF_TOPIC_USER", "AUTOMATION_CLIENT",
        ]

    def test_command_line_names(self):
        assert [persona.value for persona in Persona] == [
            "technology-lookup", "research-session", "off-topic-user", "automation-client",
        ]

    def test_every_persona_has_a_profile(self):
        assert set(PROFILES) == set(Persona)
        for persona, profile in PROFILES.items():
            assert profile.persona is persona
            assert profile.description

    def test_mix_weights_are_shares_of_one(self):
        assert MIX == tuple(Persona)
        assert sum(MIX_WEIGHTS) == pytest.approx(1.0)
        assert all(weight > 0 for weight in MIX_WEIGHTS)

    def test_research_sessions_hold_three_to_eight_requests(self):
        assert PROFILES[Persona.RESEARCH_SESSION].session_length == (3, 8)

    def test_session_length_ranges_are_valid(self):
        for profile in PROFILES.values():
            low, high = profile.session_length
            assert 1 <= low <= high

    def test_automation_client_is_the_burst_profile(self):
        gaps = {persona: profile.think_gap for persona, profile in PROFILES.items()}
        assert min(gaps, key=gaps.get) is Persona.AUTOMATION_CLIENT
        assert gaps[Persona.AUTOMATION_CLIENT] * 10 < min(
            gap for persona, gap in gaps.items() if persona is not Persona.AUTOMATION_CLIENT
        )

    def test_personas_are_profiles_not_agents(self):
        # The module describes traffic; it imports nothing of the agent.
        tree = ast.parse(Path(personas.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(("." * node.level) + (node.module or ""))
        assert imported == {"__future__", "dataclasses", "enum", "typing", ".rng"}


# ---------------------------------------------------------------------------
# WP02  Query pools
# ---------------------------------------------------------------------------

class TestPools:

    @pytest.mark.parametrize("name", sorted(_ALL_POOLS))
    def test_pool_is_a_tuple_of_distinct_plain_strings(self, name):
        pool = _ALL_POOLS[name]
        assert isinstance(pool, tuple) and len(pool) >= 8
        assert len(set(pool)) == len(pool)
        for query in pool:
            assert isinstance(query, str)
            assert query == query.strip() and query
            assert query.isascii() and "\n" not in query
            assert len(query) <= 80

    def test_four_research_threads_of_eight_questions(self):
        assert sorted(RESEARCH_THREADS) == ["agents", "data", "observability", "streaming"]
        assert all(len(thread) == 8 for thread in RESEARCH_THREADS.values())

    def test_a_thread_is_long_enough_for_the_longest_session(self):
        longest = PROFILES[Persona.RESEARCH_SESSION].session_length[1]
        assert all(len(thread) >= longest for thread in RESEARCH_THREADS.values())

    def test_off_topic_pool_shares_nothing_with_the_other_pools(self):
        others = set(TECHNOLOGY_QUERIES) | set(AUTOMATION_QUERIES) | _RESEARCH_QUERIES
        assert not set(OFF_TOPIC_QUERIES) & others

    def test_no_pool_is_generated(self):
        # Pools are literals in the module: no comprehension, no call.
        source = Path(personas.__file__).read_text(encoding="utf-8")
        for name in ("TECHNOLOGY_QUERIES", "OFF_TOPIC_QUERIES", "AUTOMATION_QUERIES"):
            start = source.index(f"{name}: tuple[str, ...] = (")
            block = source[start:source.index("\n)\n", start)]
            assert " for " not in block and "range(" not in block

    def test_automation_queries_are_short(self):
        assert all(len(query.split()) <= 2 for query in AUTOMATION_QUERIES)

    def test_empty_request_share_is_occasional(self):
        assert 0.0 < personas.EMPTY_REQUEST_PROBABILITY <= 0.10


# ---------------------------------------------------------------------------
# WP03  Session planning
# ---------------------------------------------------------------------------

def _session(persona: Persona, length: int, index: int = 0, seed: int = 7):
    return session_queries(persona, length, Draw(seed, "test-session", index))


class TestSessionQueries:

    @pytest.mark.parametrize("persona", list(Persona))
    def test_every_persona_can_be_planned(self, persona):
        low, high = PROFILES[persona].session_length
        for length in (low, high):
            queries = _session(persona, length)
            assert isinstance(queries, tuple) and len(queries) == length

    @pytest.mark.parametrize("persona", list(Persona))
    def test_same_draw_gives_the_same_session(self, persona):
        length = PROFILES[persona].session_length[1]
        assert _session(persona, length, index=3) == _session(persona, length, index=3)

    def test_different_draws_give_different_sessions(self):
        sessions = {_session(Persona.TECHNOLOGY_LOOKUP, 2, index=i) for i in range(40)}
        assert len(sessions) > 10

    def test_technology_lookup_uses_only_its_pool(self):
        for index in range(50):
            assert set(_session(Persona.TECHNOLOGY_LOOKUP, 2, index)) <= set(TECHNOLOGY_QUERIES)

    def test_off_topic_user_uses_only_its_pool(self):
        for index in range(50):
            assert set(_session(Persona.OFF_TOPIC_USER, 3, index)) <= set(OFF_TOPIC_QUERIES)

    @pytest.mark.parametrize("length", [3, 4, 5, 6, 7, 8])
    def test_research_session_is_consecutive_questions_of_one_thread(self, length):
        for index in range(30):
            queries = _session(Persona.RESEARCH_SESSION, length, index)
            (thread,) = [t for t in RESEARCH_THREADS.values() if queries[0] in t]
            first = thread.index(queries[0])
            assert queries == thread[first:first + length]
            assert len(set(queries)) == length

    def test_research_sessions_use_every_thread(self):
        firsts = {_session(Persona.RESEARCH_SESSION, 8, index)[0] for index in range(60)}
        assert firsts == {thread[0] for thread in RESEARCH_THREADS.values()}

    def test_research_session_cannot_outgrow_its_thread(self):
        with pytest.raises(ValueError):
            _session(Persona.RESEARCH_SESSION, 9)

    def test_automation_client_repeats_one_query(self):
        for index in range(50):
            queries = _session(Persona.AUTOMATION_CLIENT, 10, index)
            texts = {query for query in queries if query}
            assert len(texts) <= 1
            assert texts <= set(AUTOMATION_QUERIES)

    def test_automation_client_sometimes_sends_an_empty_request(self):
        everything = [
            query for index in range(200)
            for query in _session(Persona.AUTOMATION_CLIENT, 10, index)
        ]
        share = everything.count("") / len(everything)
        assert 0.02 < share < 0.09

    def test_only_the_automation_client_sends_an_empty_request(self):
        for persona in (Persona.TECHNOLOGY_LOOKUP, Persona.RESEARCH_SESSION,
                        Persona.OFF_TOPIC_USER):
            length = PROFILES[persona].session_length[1]
            for index in range(40):
                assert all(_session(persona, length, index))

    @pytest.mark.parametrize("length", [0, -1])
    def test_a_session_needs_at_least_one_request(self, length):
        with pytest.raises(ValueError):
            _session(Persona.TECHNOLOGY_LOOKUP, length)


# ---------------------------------------------------------------------------
# WP04  Pools against the demo agent
# ---------------------------------------------------------------------------
#
# The pools claim outcomes ("the tool knows this", "nothing is retrieved").
# These tests hold them to the demo agent's real, pure functions.

@pytest.fixture(scope="module")
def demo():
    """The demo agent's pure query, tool and retrieval functions."""
    demo_app = str(_REPO / "demo-app")
    sys.path.insert(0, demo_app)
    try:
        from agents import research, retrieval, supervisor, tool_agent
    finally:
        sys.path.remove(demo_app)

    class Demo:
        fail_trigger = tool_agent.FAIL_TRIGGER
        failure_name = tool_agent.ToolExecutionError.__name__

        @staticmethod
        def outcome(query: str):
            """(tool status, documents retrieved, top relevance score)."""
            text = query.strip() or supervisor._EMPTY_REQUEST_PLACEHOLDER
            derived = research._derive_retrieval_query(text)
            status = tool_agent.run_tool(derived).status
            chunks = retrieval.retrieve(derived) if derived else []
            top = max((chunk.relevance_score for chunk in chunks), default=0.0)
            return status, len(chunks), top

    return Demo


class TestPoolsAgainstTheDemoAgent:

    @pytest.mark.parametrize("query", TECHNOLOGY_QUERIES)
    def test_the_tool_knows_every_technology_query(self, demo, query):
        status, _, _ = demo.outcome(query)
        assert status == "success"

    @pytest.mark.parametrize("query", OFF_TOPIC_QUERIES)
    def test_the_agent_knows_nothing_about_an_off_topic_question(self, demo, query):
        status, documents, top = demo.outcome(query)
        assert status == "not_found"
        # Weak retrieval: at most one document, and a poor match at that.
        assert documents <= 1 and top <= 0.34

    @pytest.mark.parametrize("name", sorted(RESEARCH_THREADS))
    def test_a_research_thread_mixes_tool_outcomes(self, demo, name):
        statuses = [demo.outcome(query)[0] for query in RESEARCH_THREADS[name]]
        assert statuses.count("success") >= 2
        assert statuses.count("not_found") >= 2
        assert set(statuses) == {"success", "not_found"}

    @pytest.mark.parametrize("query", sorted(_RESEARCH_QUERIES))
    def test_every_research_question_retrieves_something(self, demo, query):
        _, documents, _ = demo.outcome(query)
        assert documents >= 1

    @pytest.mark.parametrize("query", [*AUTOMATION_QUERIES, ""])
    def test_automation_queries_are_answered_without_an_error(self, demo, query):
        status, _, _ = demo.outcome(query)
        assert status in ("success", "not_found")

    def test_automation_pool_holds_both_outcomes(self, demo):
        statuses = {demo.outcome(query)[0] for query in AUTOMATION_QUERIES}
        assert statuses == {"success", "not_found"}

    def test_the_empty_request_is_one_the_demo_accepts(self, demo):
        assert demo.outcome("") == ("not_found", 0, 0.0)

    def test_no_pool_query_sets_off_the_built_in_failure(self, demo):
        trigger = demo.fail_trigger.lower()
        normalized = trigger.replace("_", " ")
        for pool in _ALL_POOLS.values():
            for query in pool:
                assert trigger not in query.lower()
                assert normalized not in query.lower()

    def test_the_demo_was_only_read(self, demo):
        # Importing it leaves nothing of demo-app on the import path.
        assert str(_REPO / "demo-app") not in sys.path
