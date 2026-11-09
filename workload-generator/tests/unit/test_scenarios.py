"""
workload-generator/tests/unit/test_scenarios.py

Unit tests for scenarios.py.

Test inventory:
    WS01  Vocabulary: exactly the approved scenarios
    WS02  Scenario metadata
    WS03  Episodes of single-incident scenarios
    WS04  Episodes of MIXED_PRODUCTION
"""

from __future__ import annotations

from pathlib import Path

import pytest

from workload_generator import scenarios
from workload_generator.scenarios import (
    ERROR_MESSAGES,
    ERROR_RATE_LIMIT,
    ERROR_SERVER,
    ERROR_TIMEOUT,
    ERROR_UNAVAILABLE,
    MIXED_ABNORMAL_SCENARIOS,
    SPECS,
    Episode,
    RetrievalEffect,
    Scenario,
    ScenarioSpec,
    Target,
    plan_episodes,
)

_PACKAGE = Path(scenarios.__file__).parent

_APPROVED = [
    "NORMAL", "SLOW_TOOL", "SLOW_SYNTHESIS", "API_500", "API_429", "TIMEOUT",
    "RETRY_STORM", "RETRIEVAL_LATENCY", "REPEATED_FAILURE", "RECURRING_INCIDENT",
    "RETRIEVAL_QUALITY", "MIXED_PRODUCTION",
]

_SINGLE_INCIDENT = [
    Scenario.SLOW_TOOL, Scenario.SLOW_SYNTHESIS, Scenario.API_500, Scenario.API_429,
    Scenario.TIMEOUT, Scenario.RETRY_STORM, Scenario.RETRIEVAL_LATENCY,
    Scenario.REPEATED_FAILURE, Scenario.RETRIEVAL_QUALITY,
]


# ---------------------------------------------------------------------------
# WS01  Vocabulary
# ---------------------------------------------------------------------------

class TestVocabulary:

    def test_exactly_the_approved_scenarios_in_order(self):
        assert [scenario.name for scenario in Scenario] == _APPROVED

    def test_command_line_names_are_the_names_in_kebab_case(self):
        for scenario in Scenario:
            assert scenario.value == scenario.name.lower().replace("_", "-")

    @pytest.mark.parametrize("name", ["TOKEN_SPIKE", "SLOW_LLM", "DB_LATENCY"])
    def test_rejected_scenarios_do_not_exist(self, name):
        assert name not in Scenario.__members__
        assert name.lower().replace("_", "-") not in [s.value for s in Scenario]

    @pytest.mark.parametrize("word", [
        "TOKEN_SPIKE", "token-spike", "SLOW_LLM", "slow-llm", "DB_LATENCY", "db-latency",
    ])
    def test_rejected_scenarios_are_named_nowhere_in_the_package(self, word):
        for path in _PACKAGE.glob("*.py"):
            assert word not in path.read_text(encoding="utf-8"), path.name

    @pytest.mark.parametrize("word", [
        "gen_ai.usage", "input_tokens", "output_tokens", "prompt_tokens",
        "model_name", "provider", "cost_usd",
    ])
    def test_no_model_or_cost_telemetry_is_invented(self, word):
        for path in _PACKAGE.glob("*.py"):
            if word == "provider" and path.name == "real_driver.py":
                # There the word is OpenTelemetry's tracer provider, not a
                # model provider; every other word still applies to the file.
                continue
            text = path.read_text(encoding="utf-8")
            # The one place the word may appear is prose saying it is absent.
            code = "\n".join(
                line for line in text.splitlines()
                if not line.lstrip().startswith(("#", '"', "'"))
            )
            assert f'"{word}' not in code and f"'{word}" not in code, path.name
            assert f"{word} =" not in code and f"{word}:" not in code, path.name

    def test_every_scenario_has_a_spec(self):
        assert set(SPECS) == set(Scenario)
        for scenario, spec in SPECS.items():
            assert spec.scenario is scenario
            assert spec.description


# ---------------------------------------------------------------------------
# WS02  Metadata
# ---------------------------------------------------------------------------

class TestMetadata:

    def test_targets_are_span_names_the_demo_agent_emits(self):
        assert {target.value for target in Target} == {
            "tool.execute", "retrieval.search", "research.synthesize",
        }
        instrumentation = (
            _PACKAGE.parents[1] / "demo-app" / "observability" / "instrumentation.py"
        ).read_text(encoding="utf-8")
        for target in Target:
            assert f'start_as_current_span("{target.value}")' in instrumentation

    def test_normal_changes_nothing(self):
        spec = SPECS[Scenario.NORMAL]
        assert spec.target is None and spec.error_type is None
        assert spec.latency_factor is None and spec.windows == ()
        assert not spec.client_retries and spec.retrieval_effect is None

    @pytest.mark.parametrize("scenario, target", [
        (Scenario.SLOW_TOOL, Target.TOOL),
        (Scenario.SLOW_SYNTHESIS, Target.SYNTHESIS),
        (Scenario.RETRIEVAL_LATENCY, Target.RETRIEVAL),
    ])
    def test_latency_scenarios_slow_one_step_and_fail_nothing(self, scenario, target):
        spec = SPECS[scenario]
        assert spec.target is target
        low, high = spec.latency_factor
        assert 2.0 <= low < high
        assert spec.error_type is None and not spec.client_retries

    @pytest.mark.parametrize("scenario, error_type", [
        (Scenario.API_500, ERROR_SERVER),
        (Scenario.API_429, ERROR_RATE_LIMIT),
        (Scenario.TIMEOUT, ERROR_TIMEOUT),
        (Scenario.RETRY_STORM, ERROR_SERVER),
        (Scenario.REPEATED_FAILURE, ERROR_UNAVAILABLE),
        (Scenario.RECURRING_INCIDENT, ERROR_SERVER),
    ])
    def test_failure_scenarios_fail_the_tool_with_their_error_type(self, scenario, error_type):
        spec = SPECS[scenario]
        assert spec.target is Target.TOOL
        assert spec.error_type == error_type

    def test_failures_are_planned_on_the_tool_only(self):
        # The only step whose error type the instrumentation records.
        for spec in SPECS.values():
            if spec.error_type is not None:
                assert spec.target is Target.TOOL

    def test_every_error_type_has_a_message(self):
        used = {spec.error_type for spec in SPECS.values() if spec.error_type}
        assert used == set(ERROR_MESSAGES) == {
            "ToolExecutionError", "UpstreamServerError", "RateLimitError",
            "ToolTimeoutError",
        }
        for name, message in ERROR_MESSAGES.items():
            assert name.endswith("Error") and name.isidentifier()
            assert message and "\n" not in message

    def test_repeated_failure_is_the_failure_the_demo_agent_already_has(self):
        tool_agent = (
            _PACKAGE.parents[1] / "demo-app" / "agents" / "tool_agent.py"
        ).read_text(encoding="utf-8")
        assert f"class {ERROR_UNAVAILABLE}(" in tool_agent
        first, second = ERROR_MESSAGES[ERROR_UNAVAILABLE].split(": ", 1)
        assert f'"{first}: "' in tool_agent and f'"{second}"' in tool_agent

    def test_timeout_takes_the_time_limit(self):
        spec = SPECS[Scenario.TIMEOUT]
        assert spec.fixed_latency_ms == scenarios.TIMEOUT_MS == 5000.0
        assert "5000 ms" in ERROR_MESSAGES[ERROR_TIMEOUT]

    def test_rate_limiting_fails_quickly(self):
        low, high = SPECS[Scenario.API_429].fault_latency_ms
        assert 0 < low < high < 120.0

    def test_only_retry_storm_plans_client_retries(self):
        assert [s for s, spec in SPECS.items() if spec.client_retries] == [
            Scenario.RETRY_STORM
        ]

    def test_retry_storm_says_who_retries(self):
        description = SPECS[Scenario.RETRY_STORM].description
        assert "CLIENT" in description and "same session" in description
        assert "agent itself never retries" in description

    def test_exactly_one_retrieval_effect_exists(self):
        assert [(effect.name, effect.value) for effect in RetrievalEffect] == [
            ("DROP_BEST_MATCH", "drop-best-match"),
        ]

    def test_only_retrieval_quality_plans_a_retrieval_effect(self):
        assert [s for s, spec in SPECS.items() if spec.retrieval_effect is not None] == [
            Scenario.RETRIEVAL_QUALITY
        ]
        spec = SPECS[Scenario.RETRIEVAL_QUALITY]
        assert spec.retrieval_effect is RetrievalEffect.DROP_BEST_MATCH
        assert spec.target is Target.RETRIEVAL
        # A degraded result, nothing else: no failure, no added time, no retry.
        assert spec.error_type is None and spec.latency_factor is None
        assert spec.fixed_latency_ms is None and spec.fault_latency_ms is None
        assert not spec.client_retries

    def test_no_spec_can_replace_a_question(self):
        names = {field for field in ScenarioSpec.__dataclass_fields__}
        assert "off_topic" not in names and "query" not in names
        source = (_PACKAGE / "scenarios.py").read_text(encoding="utf-8")
        assert "off_topic" not in source

    def test_retrieval_quality_does_not_promise_detection(self):
        description = SPECS[Scenario.RETRIEVAL_QUALITY].description
        assert "Visible in telemetry" in description
        assert "not necessarily raised as an anomaly" in description

    def test_intensities_are_shares(self):
        for spec in SPECS.values():
            assert 0.0 < spec.intensity <= 1.0

    def test_recurring_incident_has_two_separate_windows(self):
        (first, second) = SPECS[Scenario.RECURRING_INCIDENT].windows
        assert first[1] < second[0]
        assert (second[0] - first[1]) >= 0.2

    def test_mixed_production_draws_on_every_abnormal_kind_but_itself(self):
        assert set(MIXED_ABNORMAL_SCENARIOS) == set(Scenario) - {
            Scenario.NORMAL, Scenario.MIXED_PRODUCTION, Scenario.RECURRING_INCIDENT,
        }

    def test_specs_are_immutable(self):
        with pytest.raises(Exception):
            SPECS[Scenario.NORMAL].intensity = 0.5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# WS03  Single-incident episodes
# ---------------------------------------------------------------------------

class TestWindowEpisodes:

    @pytest.mark.parametrize("total", [1, 2, 10, 100, 12345])
    def test_normal_has_no_episode(self, total):
        assert plan_episodes(Scenario.NORMAL, total, seed=1) == ()

    @pytest.mark.parametrize("scenario", _SINGLE_INCIDENT)
    def test_one_episode_after_a_healthy_first_half(self, scenario):
        (episode,) = plan_episodes(scenario, 1000, seed=1)
        assert (episode.start_index, episode.end_index) == (500, 800)
        assert episode.scenario is scenario
        assert episode.intensity == SPECS[scenario].intensity
        assert episode.episode_id == f"ep01-{scenario.value}"
        assert episode.length == 300

    def test_recovery_follows_the_episode(self):
        (episode,) = plan_episodes(Scenario.API_500, 1000, seed=1)
        assert episode.end_index < 1000

    def test_recurring_incident_has_two_episodes_of_the_same_scenario(self):
        first, second = plan_episodes(Scenario.RECURRING_INCIDENT, 1000, seed=1)
        assert (first.start_index, first.end_index) == (250, 400)
        assert (second.start_index, second.end_index) == (700, 850)
        assert first.scenario is second.scenario is Scenario.RECURRING_INCIDENT
        assert first.episode_id != second.episode_id

    @pytest.mark.parametrize("scenario", _SINGLE_INCIDENT + [Scenario.RECURRING_INCIDENT])
    def test_window_episodes_do_not_depend_on_the_seed(self, scenario):
        assert plan_episodes(scenario, 400, seed=1) == plan_episodes(scenario, 400, seed=999)

    @pytest.mark.parametrize("scenario", _SINGLE_INCIDENT + [Scenario.RECURRING_INCIDENT])
    @pytest.mark.parametrize("total", [1, 2, 3, 5, 7, 20])
    def test_tiny_plans_stay_inside_bounds(self, scenario, total):
        episodes = plan_episodes(scenario, total, seed=1)
        previous_end = 0
        for episode in episodes:
            assert previous_end <= episode.start_index < episode.end_index <= total
            previous_end = episode.end_index

    @pytest.mark.parametrize("total", [0, -5])
    def test_a_plan_needs_a_request(self, total):
        with pytest.raises(ValueError):
            plan_episodes(Scenario.API_500, total, seed=1)

    def test_membership(self):
        episode = Episode("ep01-x", Scenario.API_500, 10, 20, 1.0)
        assert 10 in episode and 19 in episode
        assert 9 not in episode and 20 not in episode
        assert "10" not in episode


# ---------------------------------------------------------------------------
# WS04  MIXED_PRODUCTION episodes
# ---------------------------------------------------------------------------

class TestMixedEpisodes:

    @pytest.mark.parametrize("total", [200, 1000, 5000, 20000])
    @pytest.mark.parametrize("seed", [0, 1, 42])
    def test_abnormal_share_is_about_five_percent(self, total, seed):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, total, seed)
        abnormal = sum(episode.length for episode in episodes)
        assert abnormal / total == pytest.approx(0.05, abs=0.005)

    @pytest.mark.parametrize("seed", [0, 1, 42])
    def test_episodes_are_ordered_separate_and_inside_the_plan(self, seed):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 5000, seed)
        assert len(episodes) >= 20
        previous_end = 0
        for episode in episodes:
            assert previous_end <= episode.start_index < episode.end_index <= 5000
            previous_end = episode.end_index

    def test_abnormal_traffic_comes_in_runs_not_single_requests(self):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 5000, seed=3)
        assert all(4 <= episode.length <= 12 for episode in episodes)

    def test_the_plan_starts_healthy(self):
        for seed in range(20):
            episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 2000, seed)
            assert episodes[0].start_index >= 200

    def test_episodes_are_of_different_abnormal_kinds(self):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 20000, seed=5)
        kinds = {episode.scenario for episode in episodes}
        assert kinds <= set(MIXED_ABNORMAL_SCENARIOS)
        assert len(kinds) >= 7

    def test_every_request_of_a_mixed_episode_is_abnormal(self):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 5000, seed=3)
        assert {episode.intensity for episode in episodes} == {1.0}

    def test_episode_ids_are_unique(self):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, 20000, seed=5)
        ids = [episode.episode_id for episode in episodes]
        assert len(set(ids)) == len(ids)
        assert all(i.startswith("ep") for i in ids)

    def test_same_seed_gives_the_same_episodes(self):
        assert (
            plan_episodes(Scenario.MIXED_PRODUCTION, 3000, seed=11)
            == plan_episodes(Scenario.MIXED_PRODUCTION, 3000, seed=11)
        )

    def test_different_seeds_place_episodes_differently(self):
        first = plan_episodes(Scenario.MIXED_PRODUCTION, 3000, seed=11)
        second = plan_episodes(Scenario.MIXED_PRODUCTION, 3000, seed=12)
        assert [e.start_index for e in first] != [e.start_index for e in second]

    @pytest.mark.parametrize("total", [1, 2, 5, 9])
    def test_a_tiny_plan_may_have_no_episode(self, total):
        assert plan_episodes(Scenario.MIXED_PRODUCTION, total, seed=1) == ()

    @pytest.mark.parametrize("total", [20, 30, 50, 100])
    def test_a_small_plan_has_one_short_episode(self, total):
        episodes = plan_episodes(Scenario.MIXED_PRODUCTION, total, seed=1)
        assert len(episodes) == 1
        assert 1 <= episodes[0].length <= 5
        assert episodes[0].end_index <= total
