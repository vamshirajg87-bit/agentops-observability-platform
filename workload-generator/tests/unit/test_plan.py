"""
workload-generator/tests/unit/test_plan.py

Unit tests for rng.py and plan.py.

Test inventory:
    WL01  Seeded draws
    WL02  Determinism: seed, run id, request-local streams
    WL03  Plan shape and identifiers
    WL04  Arrivals
    WL05  Sessions and personas in a plan
    WL06  Scenarios in a plan
    WL07  MIXED_PRODUCTION in a plan
    WL08  Retries
    WL09  Configuration validation
"""

from __future__ import annotations

import ast
import dataclasses
import math
import re
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from workload_generator import plan as plan_module
from workload_generator.personas import (
    OFF_TOPIC_QUERIES,
    PROFILES,
    RESEARCH_THREADS,
    TECHNOLOGY_QUERIES,
    Persona,
)
from workload_generator.plan import (
    Plan,
    PlanConfig,
    PlannedRequest,
    build_plan,
    validate_run_id,
)
from workload_generator.rng import Draw, derive_hex
from workload_generator.scenarios import (
    ERROR_MESSAGES,
    SPECS,
    RetrievalEffect,
    Scenario,
    Target,
)

_PACKAGE_ROOT = Path(plan_module.__file__).resolve().parents[1]


def _config(**overrides) -> PlanConfig:
    values = dict(
        seed=42, run_id="unit-test-run", scenario=Scenario.NORMAL, traces=300, rate=5.0,
    )
    values.update(overrides)
    return PlanConfig(**values)


def _plan(**overrides) -> Plan:
    return build_plan(_config(**overrides))


def _identifiers(path) -> set[str]:
    """Every name used in the code of a module; docstrings and comments excluded."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(Path(path).read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
    return names


def _traffic(plan: Plan) -> list[tuple]:
    """Everything about a plan except its identifiers."""
    return [
        dataclasses.astuple(dataclasses.replace(
            request, request_id="", session_id="",
            retries=tuple(dataclasses.replace(r, request_id="") for r in request.retries),
        ))
        for request in plan.requests
    ]


# ---------------------------------------------------------------------------
# WL01  Seeded draws
# ---------------------------------------------------------------------------

class TestDraw:

    def test_same_stream_same_values(self):
        first = [Draw(1, "a", 5).uniform() for _ in range(3)]
        assert first[0] == first[1] == first[2]
        a, b = Draw(1, "a", 5), Draw(1, "a", 5)
        assert [a.uniform() for _ in range(20)] == [b.uniform() for _ in range(20)]

    @pytest.mark.parametrize("other", [(2, "a", 5), (1, "b", 5), (1, "a", 6)])
    def test_seed_namespace_and_index_each_change_the_stream(self, other):
        assert Draw(1, "a", 5).uniform() != Draw(*other).uniform()

    def test_known_values_are_stable(self):
        # Pinned: a change here changes every plan ever produced.
        assert derive_hex(42, "request", 0) == (
            hashlib_sha256("agentops-workload-plan/1|42|request|0")
        )
        assert Draw(42, "request", 0).uniform() == 0.9550873126644873

    def test_derivation_does_not_use_the_process_hash(self):
        source = Path(plan_module.__file__).with_name("rng.py").read_text(encoding="utf-8")
        assert "hashlib.sha256" in source
        assert re.search(r"(?<![\w.])hash\(", source) is None

    def test_streams_are_identical_in_another_process_with_another_hash_seed(self):
        code = (
            "from workload_generator.rng import Draw;"
            "print(repr([Draw(42, 'request', i).uniform() for i in range(5)]))"
        )
        outputs = set()
        for hash_seed in ("0", "1", "987654"):
            completed = subprocess.run(
                [sys.executable, "-c", code],
                cwd=_PACKAGE_ROOT,
                env={"PYTHONHASHSEED": hash_seed, "PYTHONDONTWRITEBYTECODE": "1",
                     "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
                capture_output=True, text=True, check=True,
            )
            outputs.add(completed.stdout.strip())
        assert len(outputs) == 1
        assert outputs.pop() == repr([Draw(42, "request", i).uniform() for i in range(5)])

    def test_uniform_range(self):
        draw = Draw(3, "range", 0)
        values = [draw.uniform() for _ in range(2000)]
        assert all(0.0 <= value < 1.0 for value in values)
        assert 0.45 < statistics.fmean(values) < 0.55

    def test_integer_is_inclusive_and_covers_the_range(self):
        draw = Draw(3, "integer", 0)
        assert {draw.integer(3, 8) for _ in range(500)} == {3, 4, 5, 6, 7, 8}
        assert draw.integer(4, 4) == 4

    def test_index_and_choice_stay_inside(self):
        draw = Draw(3, "index", 0)
        assert {draw.index(4) for _ in range(300)} == {0, 1, 2, 3}
        assert {draw.choice("abc") for _ in range(300)} == {"a", "b", "c"}

    def test_weighted_follows_the_weights(self):
        draw = Draw(3, "weighted", 0)
        counts = Counter(draw.weighted("abc", (0.7, 0.2, 0.1)) for _ in range(5000))
        assert 0.66 < counts["a"] / 5000 < 0.74
        assert 0.07 < counts["c"] / 5000 < 0.13
        assert Counter(draw.weighted("ab", (1.0, 0.0)) for _ in range(200)) == {"a": 200}

    def test_exponential_mean(self):
        draw = Draw(3, "exponential", 0)
        values = [draw.exponential(2.0) for _ in range(5000)]
        assert all(value >= 0.0 for value in values)
        assert 1.85 < statistics.fmean(values) < 2.15

    def test_lognormal_median(self):
        draw = Draw(3, "lognormal", 0)
        values = [draw.lognormal(120.0, 0.35) for _ in range(5000)]
        assert all(value > 0.0 for value in values)
        assert 114.0 < statistics.median(values) < 126.0
        # Not a flat range: the top is much further from the median than the bottom.
        assert max(values) - 120.0 > 2 * (120.0 - min(values))

    @pytest.mark.parametrize("call", [
        lambda d: d.index(0), lambda d: d.integer(5, 4), lambda d: d.exponential(0.0),
        lambda d: d.lognormal(0.0, 0.3), lambda d: d.weighted("ab", (0.0, 0.0)),
        lambda d: d.weighted("ab", (1.0,)), lambda d: d.weighted("ab", (1.0, -1.0)),
    ])
    def test_invalid_arguments_are_rejected(self, call):
        with pytest.raises(ValueError):
            call(Draw(1, "invalid", 0))


def hashlib_sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# WL02  Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    @pytest.mark.parametrize("scenario", list(Scenario))
    def test_same_config_gives_the_identical_plan(self, scenario):
        assert _plan(scenario=scenario) == _plan(scenario=scenario)

    @pytest.mark.parametrize("persona", [None, *Persona])
    def test_same_config_gives_the_identical_plan_for_every_persona(self, persona):
        assert _plan(persona=persona) == _plan(persona=persona)

    def test_a_different_seed_gives_materially_different_traffic(self):
        first, second = _plan(seed=1), _plan(seed=2)
        same_query = sum(
            a.query == b.query for a, b in zip(first.requests, second.requests)
        )
        assert same_query < 0.5 * len(first.requests)
        assert [r.arrival_offset_seconds for r in first.requests] != [
            r.arrival_offset_seconds for r in second.requests
        ]
        assert [r.latency for r in first.requests] != [r.latency for r in second.requests]

    def test_a_different_run_id_changes_every_identifier_and_nothing_else(self):
        first = _plan(run_id="run-aaaa", scenario=Scenario.RETRY_STORM)
        second = _plan(run_id="run-bbbb", scenario=Scenario.RETRY_STORM)
        assert _traffic(first) == _traffic(second)
        assert not {r.request_id for r in first.requests} & {r.request_id for r in second.requests}
        assert not {r.session_id for r in first.requests} & {r.session_id for r in second.requests}
        retry_ids = lambda p: {x.request_id for r in p.requests for x in r.retries}
        assert retry_ids(first) and not retry_ids(first) & retry_ids(second)

    def test_same_seed_and_run_id_reproduce_the_identifiers(self):
        first, second = _plan(run_id="run-aaaa"), _plan(run_id="run-aaaa")
        assert [r.request_id for r in first.requests] == [r.request_id for r in second.requests]
        assert [r.session_id for r in first.requests] == [r.session_id for r in second.requests]

    def test_the_seed_also_changes_identifiers(self):
        first, second = _plan(seed=1), _plan(seed=2)
        assert first.requests[0].request_id != second.requests[0].request_id

    def test_mode_is_recorded_and_changes_nothing(self):
        real, synthetic = _plan(mode="real"), _plan(mode="synthetic")
        assert real.requests == synthetic.requests
        assert (real.config.mode, synthetic.config.mode) == ("real", "synthetic")

    def test_concurrency_is_not_an_input_of_the_planner(self):
        names = {field.name for field in dataclasses.fields(PlanConfig)}
        assert names == {"seed", "run_id", "scenario", "traces", "rate", "persona", "mode"}
        # No name in the planner's code refers to it (prose may say so).
        assert not [name for name in _identifiers(plan_module.__file__)
                    if "concurren" in name.lower()]

    def test_a_request_is_planned_from_its_own_stream(self):
        # Latency and scenario draws of request N come from (seed, "request", N)
        # alone, so they are the same in a plan of any other scenario.
        normal = _plan(scenario=Scenario.NORMAL)
        slow = _plan(scenario=Scenario.SLOW_TOOL)
        outside = [
            (a, b) for a, b in zip(normal.requests, slow.requests) if b.episode_id is None
        ]
        assert len(outside) == 210
        for a, b in outside:
            assert a == b

    def test_planner_reads_no_clock_environment_or_file(self):
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        for word in ("import time", "datetime", "os.environ", "open(", "uuid", "secrets"):
            assert word not in source

    def test_building_a_plan_twice_in_one_process_shares_no_state(self):
        first = _plan(seed=5)
        _plan(seed=6)
        _plan(seed=7, scenario=Scenario.MIXED_PRODUCTION)
        assert _plan(seed=5) == first


# ---------------------------------------------------------------------------
# WL03  Shape and identifiers
# ---------------------------------------------------------------------------

class TestShape:

    @pytest.mark.parametrize("traces", [1, 2, 3, 17, 300, 2500])
    def test_exactly_the_requested_number_of_requests(self, traces):
        plan = _plan(traces=traces)
        assert len(plan.requests) == traces
        assert [r.request_index for r in plan.requests] == list(range(traces))

    def test_identifiers_have_the_shape_the_demo_application_uses(self):
        plan = _plan()
        for request in plan.requests:
            assert re.fullmatch(r"req_[0-9a-f]{32}", request.request_id)
            assert re.fullmatch(r"sess_[0-9a-f]{32}", request.session_id)
        main = (_PACKAGE_ROOT.parent / "demo-app" / "main.py").read_text(encoding="utf-8")
        assert 'f"req_{uuid.uuid4().hex}"' in main and 'f"sess_{uuid.uuid4().hex}"' in main

    def test_request_ids_are_unique_including_retries(self):
        plan = _plan(scenario=Scenario.RETRY_STORM, traces=1000)
        ids = [r.request_id for r in plan.requests]
        ids += [x.request_id for r in plan.requests for x in r.retries]
        assert len(set(ids)) == len(ids)

    def test_plan_is_immutable(self):
        plan = _plan(traces=5)
        with pytest.raises(dataclasses.FrozenInstanceError):
            plan.requests[0].query = "changed"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            plan.config.seed = 1  # type: ignore[misc]
        assert isinstance(plan.requests, tuple)

    def test_a_planned_request_holds_no_execution_result(self):
        names = {field.name for field in dataclasses.fields(PlannedRequest)}
        assert names == {
            "request_index", "request_id", "session_id", "persona", "scenario", "query",
            "arrival_offset_seconds", "latency", "fault", "retries", "episode_id",
            "retrieval_effect",
        }

    def test_no_trace_or_span_identifier_is_planned_yet(self):
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        assert "trace_id" not in source and "span_id" not in source

    def test_planned_latencies_are_positive_and_rounded(self):
        for request in _plan().requests:
            for value in dataclasses.astuple(request.latency):
                assert value > 0.0 and round(value, 3) == value

    def test_baseline_latencies_look_like_their_medians(self):
        requests = _plan(traces=3000).requests
        assert 112 < statistics.median(r.latency.tool_ms for r in requests) < 128
        assert 42 < statistics.median(r.latency.retrieval_ms for r in requests) < 48
        assert 56 < statistics.median(r.latency.synthesis_ms for r in requests) < 64

    def test_healthy_traffic_has_a_slow_tail(self):
        tool = sorted(r.latency.tool_ms for r in _plan(traces=3000).requests)
        assert tool[-1] > 3 * statistics.median(tool)


# ---------------------------------------------------------------------------
# WL04  Arrivals
# ---------------------------------------------------------------------------

def _offsets(plan: Plan) -> list[float]:
    return [request.arrival_offset_seconds for request in plan.requests]


class TestArrivals:

    @pytest.mark.parametrize("scenario", [Scenario.NORMAL, Scenario.MIXED_PRODUCTION])
    @pytest.mark.parametrize("persona", [None, *Persona])
    def test_offsets_start_at_zero_and_never_decrease(self, scenario, persona):
        offsets = _offsets(_plan(scenario=scenario, persona=persona))
        assert offsets[0] == 0.0
        assert all(later >= earlier for earlier, later in zip(offsets, offsets[1:]))
        assert all(offset >= 0.0 for offset in offsets)

    @pytest.mark.parametrize("rate", [0.5, 5.0, 50.0])
    def test_the_plan_has_the_requested_average_rate(self, rate):
        plan = _plan(traces=600, rate=rate)
        assert plan.planned_duration_seconds == pytest.approx(599 / rate, rel=1e-6)

    def test_a_higher_rate_compresses_every_offset(self):
        slow, fast = _offsets(_plan(rate=2.0)), _offsets(_plan(rate=20.0))
        for a, b in zip(slow[1:], fast[1:]):
            assert a == pytest.approx(b * 10.0, abs=2e-5)

    def test_the_rate_changes_only_the_offsets(self):
        strip = lambda p: [dataclasses.replace(r, arrival_offset_seconds=0.0) for r in p.requests]
        assert strip(_plan(rate=2.0)) == strip(_plan(rate=20.0))

    def test_arrivals_are_not_evenly_spaced(self):
        offsets = _offsets(_plan(traces=2000, rate=10.0))
        gaps = [later - earlier for earlier, later in zip(offsets, offsets[1:])]
        mean = statistics.fmean(gaps)
        assert mean == pytest.approx(0.1, rel=0.01)
        # Evenly spaced arrivals would have a spread of zero; a plain Poisson
        # process has spread == mean.  Sessions and bursts push it higher.
        assert statistics.pstdev(gaps) > mean

    def test_there_are_bursts_and_quiet_periods(self):
        offsets = _offsets(_plan(traces=2000, rate=10.0))
        gaps = sorted(later - earlier for earlier, later in zip(offsets, offsets[1:]))
        mean = statistics.fmean(gaps)
        assert gaps[len(gaps) // 4] < 0.2 * mean       # many requests close together
        assert gaps[-1] > 6 * mean                     # and some long silences

    def test_offsets_are_rounded_to_microseconds(self):
        for offset in _offsets(_plan()):
            assert round(offset, 6) == offset

    def test_a_single_request_arrives_at_zero(self):
        plan = _plan(traces=1)
        assert _offsets(plan) == [0.0] and plan.planned_duration_seconds == 0.0

    def test_planning_does_not_wait(self):
        import time
        started = time.perf_counter()
        plan = _plan(traces=2000, rate=0.01)            # a plan 55 hours long
        assert time.perf_counter() - started < 10.0
        assert plan.planned_duration_seconds > 150_000


# ---------------------------------------------------------------------------
# WL05  Sessions and personas
# ---------------------------------------------------------------------------

def _by_session(plan: Plan) -> dict[str, list[PlannedRequest]]:
    sessions: dict[str, list[PlannedRequest]] = {}
    for request in plan.requests:
        sessions.setdefault(request.session_id, []).append(request)
    return sessions


class TestSessions:

    def test_the_mix_uses_all_four_personas(self):
        plan = _plan(traces=2000)
        assert {r.persona for r in plan.requests} == set(Persona)

    def test_the_mix_follows_the_session_weights(self):
        plan = _plan(traces=20000, rate=100.0)
        sessions = _by_session(plan)
        counts = Counter(requests[0].persona for requests in sessions.values())
        for persona, profile in PROFILES.items():
            assert counts[persona] / len(sessions) == pytest.approx(profile.weight, abs=0.03)

    @pytest.mark.parametrize("persona", list(Persona))
    def test_a_single_persona_can_be_selected(self, persona):
        plan = _plan(persona=persona)
        assert {r.persona for r in plan.requests} == {persona}

    def test_session_count_matches_the_requests(self):
        plan = _plan(traces=1000)
        assert plan.session_count == len(_by_session(plan))

    def test_a_session_has_one_persona(self):
        for requests in _by_session(_plan(traces=2000)).values():
            assert len({r.persona for r in requests}) == 1

    def test_session_sizes_respect_the_profiles(self):
        for requests in _by_session(_plan(traces=3000)).values():
            low, high = PROFILES[requests[0].persona].session_length
            # The last session of a plan may be cut short.
            assert 1 <= len(requests) <= high

    def test_research_sessions_share_a_session_id_across_three_to_eight_requests(self):
        plan = _plan(traces=3000, persona=Persona.RESEARCH_SESSION)
        sizes = Counter(len(requests) for requests in _by_session(plan).values())
        full = {size: n for size, n in sizes.items() if size >= 3}
        assert set(full) == {3, 4, 5, 6, 7, 8}
        # Only the one session cut off at the end may be shorter.
        assert sum(n for size, n in sizes.items() if size < 3) <= 1

    def test_a_research_session_is_one_line_of_inquiry(self):
        plan = _plan(traces=1500, persona=Persona.RESEARCH_SESSION)
        for requests in _by_session(plan).values():
            queries = tuple(r.query for r in requests)
            (thread,) = [t for t in RESEARCH_THREADS.values() if queries[0] in t]
            first = thread.index(queries[0])
            assert queries == thread[first:first + len(queries)]

    def test_requests_of_a_session_keep_their_order_in_the_plan(self):
        for requests in _by_session(_plan(traces=2000)).values():
            indexes = [r.request_index for r in requests]
            assert indexes == sorted(indexes)

    def test_sessions_overlap_in_time(self):
        plan = _plan(traces=2000)
        interleaved = sum(
            1 for requests in _by_session(plan).values()
            if requests[-1].request_index - requests[0].request_index >= len(requests)
        )
        assert interleaved > 20

    def test_automation_clients_arrive_in_bursts(self):
        plan = _plan(traces=4000, rate=10.0)
        gaps: dict[Persona, list[float]] = {persona: [] for persona in Persona}
        for requests in _by_session(plan).values():
            for earlier, later in zip(requests, requests[1:]):
                gaps[requests[0].persona].append(
                    later.arrival_offset_seconds - earlier.arrival_offset_seconds
                )
        burst = statistics.fmean(gaps[Persona.AUTOMATION_CLIENT])
        assert burst * 8 < statistics.fmean(gaps[Persona.RESEARCH_SESSION])
        assert burst * 8 < statistics.fmean(gaps[Persona.TECHNOLOGY_LOOKUP])

    @pytest.mark.parametrize("scenario", list(Scenario))
    def test_queries_conform_to_the_persona_in_every_scenario(self, scenario):
        # No scenario changes what a user asks.
        research = {q for thread in RESEARCH_THREADS.values() for q in thread}
        plan = _plan(scenario=scenario, traces=1500, rate=20.0)
        for request in plan.requests:
            if request.persona is Persona.TECHNOLOGY_LOOKUP:
                assert request.query in TECHNOLOGY_QUERIES
            elif request.persona is Persona.RESEARCH_SESSION:
                assert request.query in research
            elif request.persona is Persona.OFF_TOPIC_USER:
                assert request.query in OFF_TOPIC_QUERIES

    def test_queries_conform_to_the_persona(self):
        research = {q for thread in RESEARCH_THREADS.values() for q in thread}
        for request in _plan(traces=3000).requests:
            if request.persona is Persona.TECHNOLOGY_LOOKUP:
                assert request.query in TECHNOLOGY_QUERIES
            elif request.persona is Persona.RESEARCH_SESSION:
                assert request.query in research
            elif request.persona is Persona.OFF_TOPIC_USER:
                assert request.query in OFF_TOPIC_QUERIES

    def test_empty_requests_come_from_automation_clients_only(self):
        plan = _plan(traces=6000, rate=100.0)
        empty = [r for r in plan.requests if r.query == ""]
        assert empty and {r.persona for r in empty} == {Persona.AUTOMATION_CLIENT}


# ---------------------------------------------------------------------------
# WL06  Scenarios in a plan
# ---------------------------------------------------------------------------

def _affected(plan: Plan) -> list[PlannedRequest]:
    return [r for r in plan.requests if r.scenario is not Scenario.NORMAL]


class TestScenariosInAPlan:

    def test_normal_plans_no_fault_no_retry_and_no_episode(self):
        plan = _plan(scenario=Scenario.NORMAL, traces=1000)
        assert plan.episodes == ()
        for request in plan.requests:
            assert request.scenario is Scenario.NORMAL
            assert request.fault is None and request.retries == ()
            assert request.episode_id is None

    @pytest.mark.parametrize("scenario", [
        s for s in Scenario if s not in (Scenario.NORMAL, Scenario.MIXED_PRODUCTION)
    ])
    def test_abnormal_requests_lie_inside_episodes_only(self, scenario):
        plan = _plan(scenario=scenario, traces=1000)
        inside = {
            index for episode in plan.episodes
            for index in range(episode.start_index, episode.end_index)
        }
        for request in plan.requests:
            if request.request_index in inside:
                assert request.episode_id is not None
                assert request.scenario in (Scenario.NORMAL, scenario)
            else:
                assert request.episode_id is None
                assert request.scenario is Scenario.NORMAL
                assert request.fault is None and request.retries == ()

    @pytest.mark.parametrize("scenario", [
        s for s in Scenario if s not in (Scenario.NORMAL, Scenario.MIXED_PRODUCTION)
    ])
    def test_the_share_affected_inside_an_episode_follows_the_intensity(self, scenario):
        plan = _plan(scenario=scenario, traces=4000, rate=50.0)
        inside = [r for r in plan.requests if r.episode_id is not None]
        share = len(_affected(plan)) / len(inside)
        assert share == pytest.approx(SPECS[scenario].intensity, abs=0.05)

    @pytest.mark.parametrize("scenario, field", [
        (Scenario.SLOW_TOOL, "tool_ms"),
        (Scenario.SLOW_SYNTHESIS, "synthesis_ms"),
        (Scenario.RETRIEVAL_LATENCY, "retrieval_ms"),
    ])
    def test_latency_scenarios_slow_exactly_one_step(self, scenario, field):
        normal = _plan(scenario=Scenario.NORMAL, traces=1000)
        slow = _plan(scenario=scenario, traces=1000)
        low, high = SPECS[scenario].latency_factor
        changed = 0
        for before, after in zip(normal.requests, slow.requests):
            if after.scenario is Scenario.NORMAL:
                assert before.latency == after.latency
                continue
            changed += 1
            assert after.fault is None and after.retries == ()
            for name in ("tool_ms", "retrieval_ms", "synthesis_ms"):
                ratio = getattr(after.latency, name) / getattr(before.latency, name)
                if name == field:
                    assert low - 0.01 <= ratio <= high + 0.01
                else:
                    assert ratio == 1.0
        assert changed == 300

    @pytest.mark.parametrize("scenario", [
        Scenario.API_500, Scenario.API_429, Scenario.TIMEOUT, Scenario.RETRY_STORM,
        Scenario.REPEATED_FAILURE, Scenario.RECURRING_INCIDENT,
    ])
    def test_failure_scenarios_plan_the_tool_fault_of_their_spec(self, scenario):
        spec = SPECS[scenario]
        affected = _affected(_plan(scenario=scenario, traces=1000))
        assert affected
        for request in affected:
            assert request.fault is not None
            assert request.fault.target is Target.TOOL
            assert request.fault.error_type == spec.error_type
            assert request.fault.error_message == ERROR_MESSAGES[spec.error_type]

    def test_a_fault_is_metadata_not_an_exception(self):
        fault = _affected(_plan(scenario=Scenario.API_500))[0].fault
        assert dataclasses.is_dataclass(fault)
        assert not isinstance(fault, BaseException)
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        # The planner defines no exception type and raises nothing while planning.
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ClassDef):
                assert not [b for b in node.bases
                            if isinstance(b, ast.Name) and b.id.endswith(("Error", "Exception"))]
        assert "raise " not in source.split("def _plan_request")[1].split("def build_plan")[0]

    def test_timeout_plans_the_time_limit_on_the_tool(self):
        for request in _affected(_plan(scenario=Scenario.TIMEOUT, traces=1000)):
            assert request.latency.tool_ms == 5000.0

    def test_rate_limited_calls_fail_fast(self):
        for request in _affected(_plan(scenario=Scenario.API_429, traces=1000)):
            assert 15.0 <= request.latency.tool_ms <= 60.0

    def test_repeated_failure_is_unbroken(self):
        plan = _plan(scenario=Scenario.REPEATED_FAILURE, traces=1000)
        (episode,) = plan.episodes
        run = plan.requests[episode.start_index:episode.end_index]
        assert len(run) == 300
        assert {r.fault.error_type for r in run} == {"ToolExecutionError"}

    def test_recurring_incident_repeats_one_signature_with_health_between(self):
        plan = _plan(scenario=Scenario.RECURRING_INCIDENT, traces=1000)
        first, second = plan.episodes
        signature = lambda episode: {
            (r.fault.target, r.fault.error_type, r.fault.error_message)
            for r in plan.requests[episode.start_index:episode.end_index] if r.fault
        }
        assert signature(first) == signature(second) and len(signature(first)) == 1
        between = plan.requests[first.end_index:second.start_index]
        assert len(between) == 300
        assert all(r.fault is None and r.scenario is Scenario.NORMAL for r in between)

    def test_retrieval_quality_plans_only_a_retrieval_effect(self):
        normal = _plan(scenario=Scenario.NORMAL, traces=1000)
        quality = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        affected = _affected(quality)
        assert len(affected) > 200
        for request in affected:
            before = normal.requests[request.request_index]
            assert request.scenario is Scenario.RETRIEVAL_QUALITY
            assert request.episode_id == "ep01-retrieval-quality"
            assert request.retrieval_effect is RetrievalEffect.DROP_BEST_MATCH
            assert request.fault is None and request.retries == ()
            # The user's own question, unchanged.
            assert request.query == before.query
            # Everything else is the request the user would have sent anyway.
            assert dataclasses.replace(
                request, scenario=Scenario.NORMAL, episode_id=None, retrieval_effect=None,
            ) == before

    def test_retrieval_quality_never_changes_a_query(self):
        normal = _plan(scenario=Scenario.NORMAL, traces=1000)
        quality = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        assert [r.query for r in quality.requests] == [r.query for r in normal.requests]
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        assert "off_topic" not in source and "OFF_TOPIC" not in source

    def test_unaffected_requests_carry_no_retrieval_effect(self):
        quality = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        for request in quality.requests:
            assert (request.retrieval_effect is not None) == (
                request.scenario is Scenario.RETRIEVAL_QUALITY
            )

    @pytest.mark.parametrize("scenario", [
        s for s in Scenario
        if s not in (Scenario.RETRIEVAL_QUALITY, Scenario.MIXED_PRODUCTION)
    ])
    def test_no_other_scenario_plans_a_retrieval_effect(self, scenario):
        plan = _plan(scenario=scenario, traces=600)
        assert {r.retrieval_effect for r in plan.requests} == {None}

    def test_mixed_production_plans_the_effect_only_in_retrieval_quality_episodes(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0)
        degraded = [r for r in plan.requests if r.retrieval_effect is not None]
        assert degraded
        assert {r.scenario for r in degraded} == {Scenario.RETRIEVAL_QUALITY}
        assert all(
            r.retrieval_effect is RetrievalEffect.DROP_BEST_MATCH
            for r in plan.requests if r.scenario is Scenario.RETRIEVAL_QUALITY
        )

    def test_a_retrieval_quality_request_stays_in_its_session(self):
        normal = _plan(scenario=Scenario.NORMAL, traces=1000)
        quality = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        for before, after in zip(normal.requests, quality.requests):
            assert after.session_id == before.session_id
            assert after.persona is before.persona
            assert after.request_id == before.request_id
            assert after.arrival_offset_seconds == before.arrival_offset_seconds

    def test_retrieval_quality_does_not_add_sessions(self):
        normal = _plan(scenario=Scenario.NORMAL, traces=1000)
        quality = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        assert quality.session_count == normal.session_count
        assert len({r.session_id for r in quality.requests}) == normal.session_count
        assert _by_session(quality).keys() == _by_session(normal).keys()

    def test_sessions_around_a_retrieval_quality_request_stay_whole(self):
        normal = _by_session(_plan(scenario=Scenario.NORMAL, traces=1000))
        quality = _by_session(_plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000))
        touched = 0
        for session_id, requests in quality.items():
            # Same members, in the same order, as without the scenario.
            assert [r.request_index for r in requests] == [
                r.request_index for r in normal[session_id]
            ]
            assert len({r.persona for r in requests}) == 1
            degraded = [r for r in requests if r.scenario is Scenario.RETRIEVAL_QUALITY]
            if degraded and len(degraded) < len(requests):
                touched += 1
            # Every request of the session, degraded or not, keeps its question.
            assert [r.query for r in requests] == [r.query for r in normal[session_id]]
        assert touched > 20

    def test_a_degraded_research_session_is_still_one_session(self):
        plan = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1500,
                     persona=Persona.RESEARCH_SESSION)
        mixed = 0
        for requests in _by_session(plan).values():
            assert {r.persona for r in requests} == {Persona.RESEARCH_SESSION}
            kinds = {r.retrieval_effect for r in requests}
            mixed += len(kinds) == 2
            # Still one line of inquiry: consecutive questions of one thread.
            queries = tuple(r.query for r in requests)
            (thread,) = [t for t in RESEARCH_THREADS.values() if queries[0] in t]
            first = thread.index(queries[0])
            assert queries == thread[first:first + len(queries)]
        assert mixed > 10

    def test_retrieval_quality_keeps_the_persona_distribution(self):
        count = lambda plan: Counter(r.persona for r in plan.requests)
        assert count(_plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)) == count(
            _plan(scenario=Scenario.NORMAL, traces=1000)
        )

    def test_retrieval_quality_planning_is_deterministic(self):
        first = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        assert first == _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000)
        other = _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000, run_id="other-run")
        assert _traffic(first) == _traffic(other)
        which = lambda plan: [r.retrieval_effect is not None for r in plan.requests]
        assert which(first) != which(
            _plan(scenario=Scenario.RETRIEVAL_QUALITY, traces=1000, seed=43)
        )

    def test_no_scenario_creates_a_session_of_its_own(self):
        baseline = _plan(scenario=Scenario.NORMAL, traces=600)
        for scenario in Scenario:
            plan = _plan(scenario=scenario, traces=600)
            assert plan.session_count == baseline.session_count
            assert [r.session_id for r in plan.requests] == [
                r.session_id for r in baseline.requests
            ]
            assert [r.persona for r in plan.requests] == [
                r.persona for r in baseline.requests
            ]

    def test_only_one_session_identifier_derivation_exists(self):
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        assert source.count('_identifier("sess_"') == 1
        assert "off-topic-session" not in source

    def test_only_retry_storm_plans_retries(self):
        for scenario in Scenario:
            plan = _plan(scenario=scenario, traces=400, seed=9)
            if scenario is Scenario.RETRY_STORM:
                assert plan.planned_retries > 0
            elif scenario is not Scenario.MIXED_PRODUCTION:
                assert plan.planned_retries == 0


# ---------------------------------------------------------------------------
# WL07  MIXED_PRODUCTION
# ---------------------------------------------------------------------------

class TestMixedProduction:

    @pytest.mark.parametrize("seed", [0, 1, 42, 2026])
    def test_about_ninety_five_percent_of_a_large_plan_is_normal(self, seed):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0, seed=seed)
        normal = sum(r.scenario is Scenario.NORMAL for r in plan.requests)
        assert normal / 5000 == pytest.approx(0.95, abs=0.01)

    def test_abnormal_requests_form_clusters(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0)
        abnormal = [r.request_index for r in _affected(plan)]
        runs = 1 + sum(1 for a, b in zip(abnormal, abnormal[1:]) if b != a + 1)
        # 250 abnormal requests scattered independently would form about 240
        # separate runs; planned as episodes they form about 30.
        assert len(abnormal) == 250
        assert runs <= len(plan.episodes) <= 40
        assert len(abnormal) / runs >= 6

    def test_every_abnormal_request_belongs_to_an_episode(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0)
        ids = {episode.episode_id for episode in plan.episodes}
        for request in _affected(plan):
            assert request.episode_id in ids
        for request in plan.requests:
            if request.episode_id is None:
                assert request.scenario is Scenario.NORMAL

    def test_one_episode_is_one_kind_of_trouble(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0)
        for episode in plan.episodes:
            kinds = {
                r.scenario for r in plan.requests[episode.start_index:episode.end_index]
            }
            assert kinds == {episode.scenario}

    def test_no_request_is_labelled_mixed_production_itself(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=5000, rate=50.0)
        kinds = {r.scenario for r in plan.requests}
        assert Scenario.MIXED_PRODUCTION not in kinds
        assert Scenario.RECURRING_INCIDENT not in kinds
        assert len(kinds) >= 6

    def test_a_small_mixed_plan_is_still_mostly_normal(self):
        plan = _plan(scenario=Scenario.MIXED_PRODUCTION, traces=100)
        normal = sum(r.scenario is Scenario.NORMAL for r in plan.requests)
        assert 90 <= normal <= 98


# ---------------------------------------------------------------------------
# WL08  Retries
# ---------------------------------------------------------------------------

class TestRetries:

    @pytest.fixture(scope="class")
    def storm(self) -> Plan:
        return _plan(scenario=Scenario.RETRY_STORM, traces=2000, rate=20.0)

    def test_every_failed_request_of_the_storm_has_planned_retries(self, storm):
        affected = _affected(storm)
        assert len(affected) > 300
        for request in affected:
            assert request.fault is not None
            assert 1 <= len(request.retries) <= 3

    def test_retry_counts_cover_one_to_three(self, storm):
        assert {len(r.retries) for r in _affected(storm)} == {1, 2, 3}

    def test_attempts_are_numbered_from_one(self, storm):
        for request in _affected(storm):
            assert [retry.attempt for retry in request.retries] == list(
                range(1, len(request.retries) + 1)
            )

    def test_backoff_doubles_with_jitter(self, storm):
        for request in _affected(storm):
            for retry in request.retries:
                base = 0.5 * 2 ** (retry.attempt - 1)
                assert 0.8 * base - 0.001 <= retry.backoff_seconds <= 1.2 * base + 0.001
        backoffs = {x.backoff_seconds for r in _affected(storm) for x in r.retries}
        assert len(backoffs) > 50                       # jittered, not three fixed values

    def test_a_retry_is_a_new_request_of_the_same_session(self, storm):
        # The retry carries its own request id and no session id or query of
        # its own: both are those of the request it resubmits.
        retry_fields = {f.name for f in dataclasses.fields(plan_module.PlannedRetry)}
        assert retry_fields == {"attempt", "request_id", "backoff_seconds", "fault"}
        for request in _affected(storm):
            for retry in request.retries:
                assert re.fullmatch(r"req_[0-9a-f]{32}", retry.request_id)
                assert retry.request_id != request.request_id

    def test_only_the_last_retry_may_succeed(self, storm):
        recovered = 0
        for request in _affected(storm):
            *earlier, last = request.retries
            assert all(retry.fault == request.fault for retry in earlier)
            assert last.fault in (None, request.fault)
            recovered += last.fault is None
        share = recovered / len(_affected(storm))
        assert 0.4 < share < 0.6

    def test_healthy_requests_of_the_storm_have_no_retry(self, storm):
        for request in storm.requests:
            if request.fault is None:
                assert request.retries == ()

    def test_planned_retries_is_the_sum(self, storm):
        assert storm.planned_retries == sum(len(r.retries) for r in storm.requests)
        assert storm.planned_retries > len(_affected(storm))

    def test_retries_do_not_change_the_arrival_plan(self, storm):
        normal = _plan(scenario=Scenario.NORMAL, traces=2000, rate=20.0)
        assert _offsets(storm) == _offsets(normal)
        assert len(storm.requests) == 2000

    def test_no_retry_is_executed_by_the_planner(self):
        source = Path(plan_module.__file__).read_text(encoding="utf-8")
        body = source.split("def _plan_retries")[1].split("\ndef ")[0]
        for word in ("sleep", "while ", "try:", "except"):
            assert word not in body

    def test_the_agent_is_not_claimed_to_retry(self):
        text = Path(plan_module.__file__).read_text(encoding="utf-8")
        assert "CLIENT resubmission" in text
        assert "no retry of its own" in " ".join(text.split())


# ---------------------------------------------------------------------------
# WL09  Configuration validation
# ---------------------------------------------------------------------------

class TestConfigValidation:

    @pytest.mark.parametrize("run_id", [
        "abcd", "run-2026-10-06", "a1b2c3d4e5f6", "0000", "x" * 40,
    ])
    def test_valid_run_ids(self, run_id):
        assert validate_run_id(run_id) == run_id

    @pytest.mark.parametrize("run_id", [
        "", "abc", "x" * 41, "Run-1234", "run_1234", "-run1", "run1-", "run 1234",
        "run/1234", "run.1234", "run|1234", "rün-1234", "run-1234\n", None, 1234,
    ])
    def test_invalid_run_ids(self, run_id):
        with pytest.raises(ValueError):
            validate_run_id(run_id)

    @pytest.mark.parametrize("overrides", [
        {"seed": -1}, {"seed": 1.5}, {"seed": "1"}, {"seed": True},
        {"run_id": "BAD"},
        {"scenario": "normal"},
        {"persona": "mix"},
        {"traces": 0}, {"traces": -3}, {"traces": 2.0}, {"traces": True},
        {"rate": 0}, {"rate": -1.0}, {"rate": math.inf}, {"rate": math.nan},
        {"rate": "5"}, {"rate": True},
        {"mode": "live"},
    ])
    def test_invalid_configurations_are_rejected(self, overrides):
        with pytest.raises(ValueError):
            _config(**overrides)

    def test_an_integer_rate_is_accepted(self):
        assert len(_plan(rate=5, traces=10).requests) == 10
