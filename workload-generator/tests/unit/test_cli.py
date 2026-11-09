"""
workload-generator/tests/unit/test_cli.py

Unit tests for cli.py, and the architectural guards of the whole package.

Test inventory:
    WC01  Safe defaults
    WC02  Arguments reach the plan
    WC03  Safety limits and refusals
    WC04  Run id
    WC05  --send is refused
    WC06  --report
    WC07  Running as a module, and repeatability across processes
    WC08  Architectural guards: nothing is contacted, nothing else is needed
"""

from __future__ import annotations

import ast
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import workload_generator
from workload_generator import cli

_PACKAGE = Path(workload_generator.__file__).resolve().parent
_COMPONENT = _PACKAGE.parent
_REPO = _COMPONENT.parent
_RUNTIME_MODULES = sorted(_PACKAGE.glob("*.py"))


def _run(*argv: str) -> str:
    """Run the command in this process; return what it printed."""
    out = io.StringIO()
    assert cli.main(list(argv), stdout=out) == 0
    return out.getvalue()


def _refused(capsys, *argv: str) -> str:
    """The command must stop with exit code 2; return its error text."""
    out = io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        cli.main(list(argv), stdout=out)
    assert excinfo.value.code == 2
    assert out.getvalue() == ""                      # nothing was planned or printed
    return capsys.readouterr().err


def _value(text: str, label: str) -> str:
    (line,) = [
        l for l in text.splitlines() if l.startswith(label + " ") and not l.endswith(":")
    ]
    return line[len(label):].strip()


# ---------------------------------------------------------------------------
# WC01  Safe defaults
# ---------------------------------------------------------------------------

class TestDefaults:

    def test_default_values(self):
        assert (
            cli.DEFAULT_MODE, cli.DEFAULT_SCENARIO, cli.DEFAULT_PERSONA,
            cli.DEFAULT_TRACES, cli.DEFAULT_RATE, cli.DEFAULT_CONCURRENCY,
            cli.DEFAULT_SEED, cli.DEFAULT_MAX_DURATION,
        ) == ("real", "normal", "mix", 100, 5.0, 4, 0, "15m")

    def test_no_argument_plans_the_defaults_and_sends_nothing(self):
        text = _run()
        assert text.splitlines()[0] == (
            "PLAN ONLY - nothing was executed and nothing was sent."
        )
        assert _value(text, "mode").startswith("real")
        assert _value(text, "scenario") == "normal"
        assert _value(text, "persona") == "mix"
        assert _value(text, "requested traces") == "100"
        assert _value(text, "planned requests") == "100"
        assert _value(text, "rate") == "5 requests/second"
        assert _value(text, "concurrency") == "4"
        assert _value(text, "seed") == "0"
        assert "(limit 900)" in _value(text, "planned duration")
        assert _value(text, "planned retries").startswith("0 ")

    def test_default_output_is_short(self):
        assert len(_run().splitlines()) < 40

    def test_a_plan_of_ten_thousand_still_prints_a_summary_only(self):
        text = _run("--traces", "10000", "--rate", "100")
        assert len(text.splitlines()) < 45
        assert text.count("  #") == 5

    def test_default_run_id_is_random_and_printed(self):
        first, second = _value(_run(), "run id"), _value(_run(), "run id")
        assert first != second
        assert re.fullmatch(r"[0-9a-f]{12}", first)

    def test_help_says_plan_only(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--help"])
        assert excinfo.value.code == 0
        text = " ".join(capsys.readouterr().out.split())
        assert "nothing is executed and nothing is sent" in text
        for option in ("--mode", "--scenario", "--persona", "--traces", "--rate",
                       "--concurrency", "--seed", "--run-id", "--max-duration",
                       "--allow-large", "--send", "--report"):
            assert option in text


# ---------------------------------------------------------------------------
# WC02  Arguments reach the plan
# ---------------------------------------------------------------------------

class TestArguments:

    def test_the_target_invocation(self):
        text = _run("--mode", "real", "--scenario", "mixed-production", "--traces", "100",
                    "--rate", "5", "--seed", "42", "--run-id", "target-run")
        assert _value(text, "scenario") == "mixed-production"
        assert _value(text, "seed") == "42"
        assert _value(text, "run id") == "target-run"
        assert "normal " in text and "episodes: 1" in text

    @pytest.mark.parametrize("scenario", [
        "normal", "slow-tool", "slow-synthesis", "api-500", "api-429", "timeout",
        "retry-storm", "retrieval-latency", "repeated-failure", "recurring-incident",
        "retrieval-quality", "mixed-production",
    ])
    def test_every_approved_scenario_is_accepted(self, scenario):
        assert _value(_run("--scenario", scenario), "scenario") == scenario

    @pytest.mark.parametrize("scenario", [
        "token-spike", "slow-llm", "db-latency", "NORMAL", "mixed_production", "chaos", "",
    ])
    def test_any_other_scenario_is_refused(self, capsys, scenario):
        assert "--scenario" in _refused(capsys, "--scenario", scenario)

    @pytest.mark.parametrize("persona", [
        "mix", "technology-lookup", "research-session", "off-topic-user",
        "automation-client",
    ])
    def test_every_persona_is_selectable(self, persona):
        text = _run("--persona", persona)
        assert _value(text, "persona") == persona
        if persona != "mix":
            (line,) = [l for l in text.splitlines() if l.startswith(f"  {persona} ")]
            assert line.split()[1:] == ["100", "100.0%"]

    def test_an_unknown_persona_is_refused(self, capsys):
        assert "--persona" in _refused(capsys, "--persona", "customer-support")

    @pytest.mark.parametrize("mode", ["real", "synthetic"])
    def test_both_modes_are_plan_only_and_plan_the_same(self, mode):
        text = _run("--mode", mode, "--run-id", "mode-test")
        assert text.splitlines()[0].startswith("PLAN ONLY")
        assert "nothing is executed without --send" in _value(text, "mode")
        assert _value(text, "plan digest") == _value(
            _run("--mode", "real", "--run-id", "mode-test"), "plan digest",
        )

    def test_an_unknown_mode_is_refused(self, capsys):
        assert "--mode" in _refused(capsys, "--mode", "live")

    def test_concurrency_is_reported_and_does_not_change_the_plan(self):
        one = _run("--concurrency", "1", "--run-id", "conc-test", "--seed", "3")
        many = _run("--concurrency", "64", "--run-id", "conc-test", "--seed", "3")
        assert (_value(one, "concurrency"), _value(many, "concurrency")) == ("1", "64")
        assert _value(one, "plan digest") == _value(many, "plan digest")

    def test_retry_storm_reports_planned_retries(self):
        text = _run("--scenario", "retry-storm", "--traces", "200", "--seed", "1")
        retries = int(_value(text, "planned retries").split()[0])
        assert retries > 0
        assert _value(text, "planned submissions") == str(200 + retries)
        assert "client resubmissions" in text

    def test_unknown_argument_is_refused(self, capsys):
        _refused(capsys, "--endpoint", "http://localhost:4317")
        _refused(capsys, "--provider", "anything")
        _refused(capsys, "positional")


# ---------------------------------------------------------------------------
# WC03  Safety limits
# ---------------------------------------------------------------------------

class TestSafetyLimits:

    def test_limits(self):
        assert (cli.LARGE_TRACES, cli.ABSOLUTE_MAX_TRACES) == (10_000, 1_000_000)
        assert (cli.MAX_CONCURRENCY, cli.MAX_RATE) == (64, 10_000.0)

    @pytest.mark.parametrize("traces", ["0", "-1", "-100"])
    def test_traces_must_be_positive(self, capsys, traces):
        assert "--traces must be at least 1" in _refused(capsys, "--traces", traces)

    @pytest.mark.parametrize("traces", ["ten", "1.5", "", "1e3"])
    def test_traces_must_be_an_integer(self, capsys, traces):
        assert "--traces" in _refused(capsys, "--traces", traces)

    def test_ten_thousand_is_allowed_without_the_flag(self):
        assert _value(_run("--traces", "10000", "--rate", "100"), "planned requests") == "10000"

    def test_more_than_ten_thousand_requires_allow_large(self, capsys):
        error = _refused(capsys, "--traces", "10001", "--rate", "100")
        assert "--traces above 10,000 requires --allow-large" in error

    def test_allow_large_permits_planning_and_still_sends_nothing(self):
        text = _run("--traces", "10001", "--rate", "100", "--allow-large")
        assert text.splitlines()[0].startswith("PLAN ONLY")
        assert _value(text, "planned requests") == "10001"

    def test_allow_large_is_not_needed_and_harmless_below_the_limit(self):
        assert _value(_run("--traces", "50", "--allow-large"), "planned requests") == "50"

    def test_the_absolute_cap_holds_even_with_allow_large(self, capsys):
        error = _refused(
            capsys, "--traces", "1000001", "--rate", "10000", "--allow-large",
            "--max-duration", "1h",
        )
        assert "must not exceed 1,000,000" in error and "memory" in error

    @pytest.mark.parametrize("rate", ["0", "-5", "nan", "inf", "10001", "-inf"])
    def test_rate_must_be_positive_and_bounded(self, capsys, rate):
        assert "--rate must be more than 0" in _refused(capsys, f"--rate={rate}")

    def test_a_dash_value_is_refused_whichever_way_it_is_written(self, capsys):
        # Written as a separate word, the argument parser itself rejects it.
        assert "--rate" in _refused(capsys, "--rate", "-inf")

    def test_rate_must_be_a_number(self, capsys):
        assert "--rate" in _refused(capsys, "--rate", "fast")

    def test_a_fractional_rate_is_fine(self):
        text = _run("--traces", "20", "--rate", "0.5")
        assert _value(text, "rate") == "0.5 requests/second"
        assert _value(text, "planned duration").startswith("38.000 seconds")

    @pytest.mark.parametrize("concurrency", ["0", "-1", "65", "1000"])
    def test_concurrency_must_be_one_to_sixty_four(self, capsys, concurrency):
        error = _refused(capsys, "--concurrency", concurrency)
        assert "--concurrency must be between 1 and 64" in error

    @pytest.mark.parametrize("concurrency", ["1", "64"])
    def test_concurrency_bounds_are_inclusive(self, concurrency):
        assert _value(_run("--concurrency", concurrency), "concurrency") == concurrency

    @pytest.mark.parametrize("seed", ["-1", str(2 ** 63)])
    def test_seed_must_be_in_range(self, capsys, seed):
        assert "--seed must be a non-negative integer" in _refused(capsys, "--seed", seed)

    def test_seed_must_be_an_integer(self, capsys):
        assert "--seed" in _refused(capsys, "--seed", "abc")

    @pytest.mark.parametrize("text, seconds", [
        ("90", 90.0), ("90s", 90.0), ("15m", 900.0), ("2h", 7200.0), ("1.5m", 90.0),
        (" 30S ", 30.0),
    ])
    def test_durations(self, text, seconds):
        assert cli._parse_duration(text) == seconds

    @pytest.mark.parametrize("value", ["", "soon", "15 minutes", "-5m", "5d", "1h30m"])
    def test_max_duration_must_be_a_duration(self, capsys, value):
        assert "--max-duration" in _refused(capsys, f"--max-duration={value}")

    @pytest.mark.parametrize("value", ["0", "0s", "0m"])
    def test_max_duration_must_be_positive(self, capsys, value):
        assert "--max-duration must be positive" in _refused(capsys, "--max-duration", value)

    def test_a_plan_longer_than_the_limit_is_refused(self, capsys):
        # 100 requests at 5 per second take 19.8 seconds.
        error = " ".join(_refused(capsys, "--max-duration", "10s").split())
        assert "more than --max-duration" in error
        assert "lower --traces, raise --rate or raise --max-duration" in error

    def test_a_plan_that_just_fits_is_accepted(self):
        text = _run("--max-duration", "19.8s")
        assert "19.800 seconds (limit 19.8)" in _value(text, "planned duration")

    def test_a_large_slow_plan_is_refused_even_with_allow_large(self, capsys):
        error = _refused(capsys, "--traces", "100000", "--allow-large")
        assert "more than --max-duration" in error

    def test_nothing_is_planned_when_an_argument_is_refused(self, capsys, monkeypatch):
        def fail(*args, **kwargs):
            raise AssertionError("a plan was built for a refused request")

        monkeypatch.setattr(cli, "build_plan", fail)
        for argv in (
            ["--traces", "0"], ["--rate", "0"], ["--concurrency", "99"],
            ["--traces", "20000"], ["--send"], ["--run-id", "BAD ID"],
            ["--max-duration", "1s"],
        ):
            _refused(capsys, *argv)


# ---------------------------------------------------------------------------
# WC04  Run id
# ---------------------------------------------------------------------------

class TestRunId:

    def test_an_explicit_run_id_is_used_and_shown(self):
        assert _value(_run("--run-id", "bench-2026-10-06"), "run id") == "bench-2026-10-06"

    def test_same_seed_and_run_id_give_the_identical_output(self):
        argv = ("--scenario", "mixed-production", "--traces", "500", "--seed", "42",
                "--run-id", "repeat-0001")
        assert _run(*argv) == _run(*argv)

    def test_same_seed_other_run_id_gives_other_identifiers_and_the_same_traffic(self):
        argv = ("--scenario", "retry-storm", "--traces", "300", "--seed", "42")
        first, second = _run(*argv, "--run-id", "run-aaaa"), _run(*argv, "--run-id", "run-bbbb")
        # The digest covers the identifiers, so it differs ...
        assert _value(first, "plan digest") != _value(second, "plan digest")
        # ... while everything else that is printed is the same.
        strip = lambda text: [
            line for line in text.splitlines()
            if not line.startswith(("run id", "plan digest"))
        ]
        assert strip(first) == strip(second)

    def test_same_run_id_other_seed_gives_other_traffic(self):
        first = _run("--seed", "1", "--run-id", "seed-test")
        second = _run("--seed", "2", "--run-id", "seed-test")
        assert first.split("first 5 planned requests:")[1] != (
            second.split("first 5 planned requests:")[1]
        )

    def test_without_a_run_id_the_same_seed_never_repeats_identifiers(self):
        digests = {_value(_run("--seed", "42"), "plan digest") for _ in range(5)}
        assert len(digests) == 5

    @pytest.mark.parametrize("run_id", [
        "abc", "UPPER-case", "has space", "under_score", "-leading", "trailing-",
        "a" * 41, "semi;colon", "slash/x", "dot.dot",
    ])
    def test_an_invalid_run_id_is_refused(self, capsys, run_id):
        error = _refused(capsys, f"--run-id={run_id}")
        assert "--run-id: run id must be 4 to 40 lower-case" in error

    def test_the_default_run_id_is_valid_and_not_from_the_seeded_stream(self):
        source = (_PACKAGE / "cli.py").read_text(encoding="utf-8")
        assert "secrets.token_hex(6)" in source
        from workload_generator.plan import validate_run_id
        validate_run_id(_value(_run(), "run id"))


# ---------------------------------------------------------------------------
# WC05  --send
# ---------------------------------------------------------------------------

_ENDPOINT = "http://localhost:14317"


def _execution(**overrides):
    """An execution report as a driver would return it for a clean run."""
    from workload_generator.report import OUTCOMES, ExecutionReport
    values = dict(
        endpoint=_ENDPOINT, started="2026-10-06T12:00:00+00:00",
        finished="2026-10-06T12:00:20+00:00", elapsed_seconds=20.0,
        planned_requests=100, planned_retries=0, planned_submissions=100,
        started_requests=100, not_started_requests=0,
        attempts={**{name: 0 for name in OUTCOMES}, "expected_success": 100},
        executed_attempts=100, executed_retries=0, late_starts=0,
        max_start_lag_seconds=0.0, mean_start_lag_seconds=0.0,
        achieved_submission_rate=5.0, spans_ended=700, spans_exported_successfully=700,
        export_failures=0, flush_ok=True, run_status="completed",
    )
    values.update(overrides)
    return ExecutionReport(**values)


class FakeRunner:
    """Stands in for the production execution path; contacts nothing."""

    def __init__(self, execution=None, error=None) -> None:
        self.calls: list[dict] = []
        self.execution = execution if execution is not None else _execution()
        self.error = error

    def __call__(self, plan, **kwargs):
        self.calls.append({"plan": plan, **kwargs})
        if self.error is not None:
            raise self.error
        return self.execution


def _send(*argv: str, runner=None) -> tuple[int, str, FakeRunner]:
    runner = runner if runner is not None else FakeRunner()
    out = io.StringIO()
    code = cli.main(["--send", "--endpoint", _ENDPOINT, *argv], stdout=out, runner=runner)
    return code, out.getvalue(), runner


class TestSendIsRefused:

    def test_send_without_an_endpoint_is_refused(self, capsys):
        error = " ".join(_refused(capsys, "--send").split())
        assert "--send is not available without --endpoint" in error
        assert "there is no default endpoint" in error

    def test_synthetic_send_is_refused_and_never_falls_back(self, capsys):
        runner = FakeRunner()
        out = io.StringIO()
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--send", "--mode", "synthetic", "--endpoint", _ENDPOINT],
                     stdout=out, runner=runner)
        assert excinfo.value.code == 2
        error = " ".join(capsys.readouterr().err.split())
        assert "--send is not available for --mode synthetic" in error
        assert "synthetic execution is not implemented" in error
        assert "does not fall back" in error
        assert runner.calls == [] and out.getvalue() == ""

    @pytest.mark.parametrize("names", [
        ["OTEL_SDK_DISABLED"],
        ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME"],
        ["OTEL_RESOURCE_ATTRIBUTES"],
        ["OTEL_ANYTHING_AT_ALL"],
    ])
    def test_send_is_refused_while_any_otel_variable_is_set(self, capsys, monkeypatch, names):
        for name in names:
            monkeypatch.setenv(name, "SECRET-VALUE-do-not-print")
        runner = FakeRunner()
        out = io.StringIO()
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--send", "--endpoint", _ENDPOINT], stdout=out, runner=runner)
        assert excinfo.value.code == 2
        error = capsys.readouterr().err
        assert "--send is not available while OpenTelemetry environment variables" in error
        for name in names:
            assert name in error                         # names are shown ...
        assert "SECRET-VALUE-do-not-print" not in error  # ... values never
        assert runner.calls == [] and out.getvalue() == ""

    def test_otel_variables_do_not_affect_plan_only_mode(self, monkeypatch):
        monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://example.invalid:4317")
        text = _run("--run-id", "otel-plan-only", "--seed", "3")
        assert text.splitlines()[0].startswith("PLAN ONLY")
        monkeypatch.delenv("OTEL_SDK_DISABLED")
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        assert _run("--run-id", "otel-plan-only", "--seed", "3") == text

    @pytest.mark.parametrize("endpoint, reason", [
        ("http://localhost:4317", "port 4317 is refused"),
        ("http://127.0.0.1:4318", "port 4318 is refused"),
        ("http://[::1]:4317", "port 4317 is refused"),
        ("http://collector.example.com:14317", "needs --allow-remote-endpoint"),
        ("http://10.0.0.5:14317", "needs --allow-remote-endpoint"),
        ("https://localhost:14317", "must start with http://"),
        ("localhost:14317", "must start with http://"),
        ("grpc://localhost:14317", "must start with http://"),
        ("http://localhost", "must name its port explicitly"),
        ("http://localhost:14317/v1/traces", "and nothing more"),
        ("http://localhost:14317?x=1", "and nothing more"),
        ("http://user:pw@localhost:14317", "must not contain credentials"),
        ("http://localhost:notaport", "not a valid http://host:port"),
        ("http://localhost:99999", "not a valid http://host:port"),
        ("http://:14317", "has no host"),
        ("", "is empty"),
        ("http://local host:14317", "must not contain whitespace"),
    ])
    def test_a_refused_endpoint(self, capsys, endpoint, reason):
        runner = FakeRunner()
        out = io.StringIO()
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--send", f"--endpoint={endpoint}"], stdout=out, runner=runner)
        assert excinfo.value.code == 2
        error = " ".join(capsys.readouterr().err.split())
        assert "--endpoint:" in error and reason in error
        assert "pw@" not in error                        # credentials are not echoed
        assert runner.calls == [] and out.getvalue() == ""

    @pytest.mark.parametrize("port", ["4317", "4318"])
    def test_the_platform_ports_are_refused_even_for_a_remote_endpoint(self, capsys, port):
        with pytest.raises(SystemExit):
            cli.main(["--send", "--endpoint", f"http://collector.example.com:{port}",
                      "--allow-remote-endpoint"], stdout=io.StringIO(), runner=FakeRunner())
        assert f"port {port} is refused" in capsys.readouterr().err

    @pytest.mark.parametrize("argv", [
        ["--endpoint", _ENDPOINT], ["--allow-remote-endpoint"],
        ["--endpoint", _ENDPOINT, "--allow-remote-endpoint"],
    ])
    def test_endpoint_arguments_without_send_are_refused(self, capsys, argv):
        error = _refused(capsys, *argv)
        assert "only used with --send" in error and "nothing is sent anywhere" in error

    def test_there_is_no_default_endpoint(self):
        parser = cli._build_parser()
        assert parser.get_default("endpoint") is None
        assert parser.get_default("send") is False
        assert parser.get_default("allow_remote_endpoint") is False

    @pytest.mark.parametrize("argv", [
        ["--send", "--traces", "1"],
        ["--mode", "synthetic", "--send"],
        ["--scenario", "api-500", "--send", "--run-id", "send-test"],
        ["--send", "--allow-large", "--traces", "20000", "--rate", "100"],
    ])
    def test_send_is_refused_in_every_combination(self, capsys, argv):
        assert "--send is not available" in _refused(capsys, *argv)

    def test_send_is_refused_before_other_checks(self, capsys):
        error = _refused(capsys, "--send", "--traces", "0")
        assert "--send is not available" in error and "--traces" not in error.split("error:")[1]

    def test_send_writes_no_report(self, capsys, tmp_path):
        target = tmp_path / "plan.json"
        _refused(capsys, "--send", "--report", str(target))
        assert not target.exists()


class TestSendExecutes:

    def test_a_valid_send_executes_the_plan_once(self):
        code, text, runner = _send("--run-id", "send-ok", "--seed", "4", "--concurrency", "3",
                                   "--max-duration", "2m")
        assert code == 0
        (call,) = runner.calls
        assert len(call["plan"].requests) == 100
        assert call["plan"].config.run_id == "send-ok" and call["plan"].config.seed == 4
        assert call["concurrency"] == 3 and call["max_duration_seconds"] == 120.0
        endpoint = call["endpoint"]
        assert (endpoint.url, endpoint.host, endpoint.port, endpoint.is_loopback) == (
            _ENDPOINT, "localhost", 14317, True,
        )
        assert set(call) == {"plan", "endpoint", "concurrency", "max_duration_seconds"}

    def test_the_plan_executed_is_the_plan_that_plan_only_prints(self):
        plain = _run("--run-id", "same-plan", "--seed", "9", "--scenario", "api-500")
        _, text, runner = _send("--run-id", "same-plan", "--seed", "9", "--scenario", "api-500")
        assert _value(text, "plan digest") == _value(plain, "plan digest")
        from workload_generator.report import plan_digest
        assert plan_digest(runner.calls[0]["plan"]) == _value(plain, "plan digest")

    def test_output_says_plan_then_execution_and_never_plan_only(self):
        _, text, _ = _send()
        lines = text.splitlines()
        assert lines[0] == "PLAN - about to be executed; the execution report follows."
        assert "PLAN ONLY" not in text
        assert _value(text, "mode") == "real (executing)"
        assert "EXECUTION - what this driver did." in text
        assert text.index("plan digest") < text.index("EXECUTION -")
        assert _value(text, "run status") == "completed"
        assert _value(text, "endpoint") == _ENDPOINT

    @pytest.mark.parametrize("endpoint, url", [
        ("http://localhost:14317", "http://localhost:14317"),
        ("http://127.0.0.1:14317/", "http://127.0.0.1:14317"),
        ("http://[::1]:5317", "http://[::1]:5317"),
    ])
    def test_loopback_endpoints_are_accepted(self, endpoint, url):
        runner = FakeRunner()
        assert cli.main(["--send", "--endpoint", endpoint], stdout=io.StringIO(),
                        runner=runner) == 0
        assert runner.calls[0]["endpoint"].url == url
        assert runner.calls[0]["endpoint"].is_loopback

    def test_a_remote_endpoint_needs_the_explicit_flag(self):
        runner = FakeRunner()
        code = cli.main(["--send", "--endpoint", "http://collector.example.com:14317",
                         "--allow-remote-endpoint"], stdout=io.StringIO(), runner=runner)
        assert code == 0
        endpoint = runner.calls[0]["endpoint"]
        assert endpoint.host == "collector.example.com" and not endpoint.is_loopback

    @pytest.mark.parametrize("status, code", [
        ("completed", 0), ("stopped_integrity", 3), ("export_failed", 4),
        ("deadline_reached", 5),
    ])
    def test_exit_code_follows_the_run_status(self, status, code):
        actual, text, _ = _send(runner=FakeRunner(_execution(run_status=status)))
        assert actual == code
        assert _value(text, "run status") == status

    def test_a_driver_refusal_exits_two_and_says_why(self, capsys):
        from workload_generator.real_driver import DriverError
        runner = FakeRunner(error=DriverError("nothing is reachable at localhost:14317"))
        code, text, _ = _send(runner=runner)
        assert code == 2
        assert "error: nothing is reachable at localhost:14317" in capsys.readouterr().err
        assert "EXECUTION" not in text

    def test_an_unexpected_error_is_not_swallowed(self):
        with pytest.raises(ZeroDivisionError):
            _send(runner=FakeRunner(error=ZeroDivisionError()))

    def test_safety_limits_still_apply_with_send(self, capsys):
        for argv, message in (
            (["--traces", "10001", "--rate", "100"], "requires --allow-large"),
            (["--concurrency", "65"], "--concurrency must be between 1 and 64"),
            (["--max-duration", "5s"], "more than --max-duration"),
            (["--rate", "0"], "--rate must be more than 0"),
        ):
            runner = FakeRunner()
            with pytest.raises(SystemExit) as excinfo:
                cli.main(["--send", "--endpoint", _ENDPOINT, *argv], stdout=io.StringIO(),
                         runner=runner)
            assert excinfo.value.code == 2 and runner.calls == []
            assert message in capsys.readouterr().err

    def test_report_with_send_holds_plan_and_execution(self, tmp_path):
        target = tmp_path / "run.json"
        code, text, _ = _send("--run-id", "send-report", "--report", str(target))
        assert code == 0 and text.splitlines()[-1] == f"report written to {target}"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["executed"] is True and data["run_id"] == "send-report"
        assert data["plan_digest"] == _value(text, "plan digest")
        execution = data["execution"]
        assert execution["run_status"] == "completed" and execution["endpoint"] == _ENDPOINT
        assert execution["spans_ended"] == execution["spans_exported_successfully"] == 700

    def test_report_is_written_for_a_stopped_run_too(self, tmp_path):
        target = tmp_path / "run.json"
        stopped = _execution(run_status="stopped_integrity", problems=("request 3: x",))
        code, _, _ = _send("--report", str(target), runner=FakeRunner(stopped))
        assert code == 3
        assert json.loads(target.read_text(encoding="utf-8"))["execution"]["problems"] == [
            "request 3: x"
        ]

    def test_without_a_runner_the_production_path_is_the_drivers(self):
        source = (_PACKAGE / "cli.py").read_text(encoding="utf-8")
        assert "runner if runner is not None else driver.run_real" in source

    def test_send_through_the_module_refuses_without_contacting_anything(self):
        # A real process, the real production path: refused before any
        # connection is attempted.
        for argv, message in (
            (["--send"], "without --endpoint"),
            (["--send", "--endpoint", "http://localhost:4317"], "port 4317 is refused"),
            (["--send", "--mode", "synthetic", "--endpoint", _ENDPOINT], "synthetic"),
        ):
            completed = _module(*argv)
            assert completed.returncode == 2 and completed.stdout == ""
            assert message in completed.stderr


# ---------------------------------------------------------------------------
# WC06  --report
# ---------------------------------------------------------------------------

class TestReportFile:

    def test_report_is_written_as_json(self, tmp_path):
        target = tmp_path / "plan.json"
        text = _run("--scenario", "retry-storm", "--traces", "200", "--seed", "5",
                    "--run-id", "report-test", "--report", str(target))
        assert text.splitlines()[-1] == f"plan report written to {target}"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["report"] == "workload-plan" and data["executed"] is False
        assert (data["run_id"], data["seed"], data["mode"]) == ("report-test", 5, "real")
        assert data["requested_traces"] == data["planned_requests"] == 200
        assert data["planned_retries"] == int(_value(text, "planned retries").split()[0])
        assert data["plan_digest"] == _value(text, "plan digest")
        assert data["concurrency"] == 4 and data["requested_rate"] == 5.0
        assert data["max_duration_seconds"] == 900.0

    def test_no_report_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _run("--traces", "10")
        assert list(tmp_path.iterdir()) == []

    def test_an_existing_file_is_never_overwritten(self, capsys, tmp_path):
        target = tmp_path / "plan.json"
        target.write_text("keep me", encoding="utf-8")
        error = _refused(capsys, "--report", str(target))
        assert "already exists; nothing is overwritten" in error
        assert target.read_text(encoding="utf-8") == "keep me"

    def test_a_missing_directory_is_not_created(self, capsys, tmp_path):
        error = _refused(capsys, "--report", str(tmp_path / "missing" / "plan.json"))
        assert "directory does not exist" in error
        assert not (tmp_path / "missing").exists()

    def test_the_same_run_writes_the_same_report(self, tmp_path):
        argv = ("--scenario", "mixed-production", "--traces", "400", "--seed", "42",
                "--run-id", "repeat-0001")
        _run(*argv, "--report", str(tmp_path / "a.json"))
        _run(*argv, "--report", str(tmp_path / "b.json"))
        assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()


# ---------------------------------------------------------------------------
# WC07  Running as a module
# ---------------------------------------------------------------------------

def _module(*argv: str, hash_seed: str = "0") -> subprocess.CompletedProcess:
    env = {"PYTHONHASHSEED": hash_seed, "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("SYSTEMROOT", "PATH"):
        if name in os.environ:
            env[name] = os.environ[name]
    return subprocess.run(
        [sys.executable, "-m", "workload_generator", *argv],
        cwd=_COMPONENT, env=env, capture_output=True, text=True,
    )


class TestModuleInvocation:

    def test_python_dash_m_runs_the_command(self):
        completed = _module("--traces", "20", "--run-id", "module-test")
        assert completed.returncode == 0 and completed.stderr == ""
        assert completed.stdout.splitlines()[0].startswith("PLAN ONLY")
        assert _value(completed.stdout, "planned requests") == "20"

    def test_two_processes_give_the_identical_output(self):
        argv = ("--scenario", "mixed-production", "--traces", "1000", "--rate", "20",
                "--seed", "42", "--run-id", "repeat-0001")
        first = _module(*argv, hash_seed="1")
        second = _module(*argv, hash_seed="424242")
        assert first.returncode == second.returncode == 0
        assert first.stdout == second.stdout
        assert first.stdout == _run(*argv)

    def test_a_refusal_exits_two_and_prints_nothing_to_stdout(self):
        for argv in (["--send"], ["--traces", "10001"], ["--concurrency", "0"]):
            completed = _module(*argv)
            assert completed.returncode == 2
            assert completed.stdout == ""
            assert "error:" in completed.stderr

    def test_needs_nothing_from_the_environment(self):
        # Run with an environment that holds no credential and no setting.
        completed = _module("--traces", "5", "--run-id", "bare-env")
        assert completed.returncode == 0


# ---------------------------------------------------------------------------
# WC08  Architectural guards
# ---------------------------------------------------------------------------

_ALLOWED_IMPORTS = {
    "__future__", "argparse", "contextlib", "contextvars", "dataclasses", "enum",
    "hashlib", "json", "math", "pathlib", "random", "re", "secrets", "sys", "typing",
}

_FORBIDDEN_IMPORTS = {
    # databases
    "psycopg", "psycopg2", "sqlite3", "sqlalchemy", "asyncpg",
    # Kafka
    "confluent_kafka", "kafka", "aiokafka",
    # telemetry export
    "opentelemetry", "grpc",
    # network
    "socket", "http", "urllib", "requests", "httpx", "ssl", "ftplib", "smtplib",
    # processes, Docker, waiting
    "subprocess", "docker", "os", "shutil", "multiprocessing", "threading", "asyncio",
    "time", "datetime", "signal",
    # the agent itself
    "langgraph", "graph", "agents", "observability", "schemas", "state",
}


def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def _called_names(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                found.add(function.id)
            elif isinstance(function, ast.Attribute):
                found.add(function.attr)
    return found


_DRIVER = _PACKAGE / "real_driver.py"
# Every module but the execution driver keeps the strict rules.
_STRICT_MODULES = [path for path in _RUNTIME_MODULES if path != _DRIVER]


class TestArchitecturalGuards:

    def test_the_runtime_package_is_these_modules(self):
        assert [path.name for path in _RUNTIME_MODULES] == [
            "__init__.py", "__main__.py", "cli.py", "faults.py", "personas.py",
            "plan.py", "real_driver.py", "report.py", "rng.py", "scenarios.py",
        ]
        assert [path.name for path in _STRICT_MODULES] == [
            "__init__.py", "__main__.py", "cli.py", "faults.py", "personas.py",
            "plan.py", "report.py", "rng.py", "scenarios.py",
        ]

    @pytest.mark.parametrize("path", _STRICT_MODULES, ids=lambda p: p.name)
    def test_standard_library_only(self, path):
        assert _imports(path) <= _ALLOWED_IMPORTS

    @pytest.mark.parametrize("path", _STRICT_MODULES, ids=lambda p: p.name)
    def test_no_database_kafka_telemetry_network_or_process_import(self, path):
        assert not _imports(path) & _FORBIDDEN_IMPORTS

    def test_importing_the_package_loads_none_of_them(self):
        code = (
            "import sys, workload_generator.cli;"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in %r);"
            "print(bad)"
        ) % sorted(_FORBIDDEN_IMPORTS - {"os", "time", "signal", "threading", "datetime",
                                         "shutil", "http", "urllib", "subprocess",
                                         "socket", "ssl", "asyncio", "multiprocessing"})
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=_COMPONENT, capture_output=True, text=True,
            env={**{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH")},
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "[]"

    @pytest.mark.parametrize("path", _STRICT_MODULES, ids=lambda p: p.name)
    def test_nothing_waits_starts_a_process_or_opens_a_connection(self, path):
        calls = _called_names(path)
        for name in ("sleep", "run", "Popen", "system", "connect", "create_connection",
                     "urlopen", "Producer", "Consumer", "start_as_current_span",
                     "invoke", "getenv", "load_dotenv"):
            assert name not in calls, name

    @pytest.mark.parametrize("path", _STRICT_MODULES, ids=lambda p: p.name)
    def test_the_environment_is_never_read(self, path):
        text = path.read_text(encoding="utf-8")
        assert "os.environ" not in text and "environ[" not in text
        assert ".env" not in text.replace(".environ", "")

    def test_the_only_file_ever_opened_is_the_report(self):
        opened = [
            path.name for path in _RUNTIME_MODULES
            if "open" in _called_names(path) or "write_text" in _called_names(path)
        ]
        assert opened == ["report.py"]
        text = (_PACKAGE / "report.py").read_text(encoding="utf-8")
        assert text.count("open(") == 1 and 'open(path, "x"' in text

    def test_only_the_driver_uses_the_fault_layer(self):
        for path in _STRICT_MODULES:
            if path.name != "faults.py":
                text = path.read_text(encoding="utf-8")
                assert ".faults" not in text and "import faults" not in text, path.name
        assert "from .faults import" in _DRIVER.read_text(encoding="utf-8")

    def test_no_synthetic_driver_or_detector_file_exists_yet(self):
        for name in ("synthetic_driver.py", "driver.py"):
            assert not (_PACKAGE / name).exists()
        assert not list(_COMPONENT.rglob("runner_config*.json"))
        # The one JSON file selects which existing detector groups the small
        # end-to-end test runs; it holds no threshold.
        assert [path.relative_to(_COMPONENT).as_posix() for path in _COMPONENT.rglob("*.json")] == [
            "detector_config.json",
        ]
        # The one Compose file is the smoke harness's override, used only by
        # run_smoke.py for a separate, disposable stack.
        assert [path.relative_to(_COMPONENT).as_posix() for path in _COMPONENT.rglob("*.yml")] == [
            "compose.smoke.override.yml",
        ]
        assert not list(_COMPONENT.rglob("*.yaml"))

    def test_runtime_requirements_are_the_demo_applications(self):
        lines = [
            line.strip()
            for line in (_COMPONENT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert lines == ["-r ../demo-app/requirements.txt"]
        assert (_REPO / "demo-app" / "requirements.txt").is_file()
        # Test tooling is not a runtime requirement.
        assert not (_COMPONENT / "requirements-dev.txt").exists()

    # -- the execution driver: the one module with wider, still bounded, rules --

    @staticmethod
    def _driver_top_level_imports() -> set[str]:
        """What is imported when the driver module is loaded (not inside functions)."""
        top = set()
        for node in ast.parse(_DRIVER.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.Import):
                top.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                top.add(node.module.split(".")[0])
        return top

    def test_the_driver_loads_with_the_standard_library_only(self):
        assert self._driver_top_level_imports() == {
            "__future__", "os", "socket", "threading", "time", "concurrent", "contextlib",
            "dataclasses", "datetime", "enum", "typing", "urllib",
        }

    def test_the_driver_imports_telemetry_and_the_demo_only_inside_functions(self):
        inside_functions = _imports(_DRIVER) - self._driver_top_level_imports()
        assert inside_functions == {
            "grpc", "opentelemetry", "graph", "agents", "observability",
        }

    @pytest.mark.parametrize("module", [
        "psycopg", "psycopg2", "sqlalchemy", "sqlite3", "confluent_kafka", "kafka",
        "subprocess", "docker", "requests", "httpx", "ssl", "asyncio", "multiprocessing",
        "random", "secrets", "shutil",
    ])
    def test_the_driver_never_imports(self, module):
        assert module not in _imports(_DRIVER)

    def test_loading_the_driver_imports_no_telemetry_and_no_demo_module(self):
        code = (
            "import sys, workload_generator.real_driver;"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in "
            "('opentelemetry','grpc','langgraph','langchain_core','pydantic',"
            "'confluent_kafka','graph','agents','observability','psycopg'));"
            "print(bad)"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=_COMPONENT, capture_output=True, text=True,
            env={**{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH")},
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "[]"

    def test_the_driver_reads_the_environment_for_variable_names_only(self):
        text = _DRIVER.read_text(encoding="utf-8")
        assert text.count("os.environ") == 1
        assert "source = os.environ if environ is None else environ" in text
        for word in ("getenv", "environ[", "environ.get", ".env\"", "load_dotenv"):
            assert word not in text

    def test_the_driver_opens_exactly_one_kind_of_connection_of_its_own(self):
        text = _DRIVER.read_text(encoding="utf-8")
        assert text.count("socket.") == 1 and "socket.create_connection(" in text
        calls = _called_names(_DRIVER)
        for name in ("Popen", "system", "urlopen", "Producer", "Consumer", "open",
                     "connect", "execute_sql", "cursor"):
            assert name not in calls, name

    def test_the_driver_has_no_default_endpoint(self):
        text = _DRIVER.read_text(encoding="utf-8")
        for word in ("DEFAULT_ENDPOINT", "http://localhost", "http://127.0.0.1",
                     "localhost:4317", "localhost:4318"):
            assert word not in text, word
        from workload_generator import real_driver
        assert real_driver.REFUSED_PORTS == frozenset({4317, 4318})
        assert real_driver.LOOPBACK_HOSTS == frozenset({"localhost", "127.0.0.1", "::1"})

    def test_the_driver_does_not_change_the_import_path_or_register_a_provider(self):
        text = _DRIVER.read_text(encoding="utf-8")
        for word in ("sys.path", "set_tracer_provider", "configure_tracing",
                     "ConsoleSpanExporter", "CanonicalSpanExporter", "KafkaTelemetryPublisher",
                     "AGENTOPS_DIRECT_EXPORT"):
            assert word not in text, word

    def test_the_driver_plans_nothing(self):
        names = set()
        for node in ast.walk(ast.parse(_DRIVER.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        for word in ("Draw", "build_plan", "plan_episodes", "SPECS", "uniform", "choice",
                     "seed", "randint"):
            assert word not in names, word

    def test_plan_only_never_loads_the_driver(self):
        code = (
            "import io, sys; from workload_generator import cli;"
            "cli.main(['--traces', '20', '--run-id', 'plan-only'], stdout=io.StringIO());"
            "print(sorted(m for m in sys.modules if m.split('.')[0] in "
            "('opentelemetry','grpc','langgraph','confluent_kafka','graph','agents',"
            "'observability','socket') or m == 'workload_generator.real_driver'))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=_COMPONENT, capture_output=True, text=True,
            env={**{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH")},
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "[]"

    def test_the_component_holds_only_code_and_tests(self):
        files = sorted(
            path.relative_to(_COMPONENT).as_posix()
            for path in _COMPONENT.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
            and ".pytest_cache" not in path.parts
        )
        assert files == [
            "PHASE-14.5-FAILURE-RECOVERY.md",
            "compose.smoke.override.yml",
            "detector_config.json",
            "requirements.txt",
            "run_commit_batching_it.py",
            "run_e2e.py",
            "run_pipeline_it.py",
            "run_shutdown_it.py",
            "run_smoke.py",
            "run_viewer_sql_it.py",
            "tests/__init__.py",
            "tests/conftest.py",
            "tests/integration/__init__.py",
            "tests/integration/test_real_driver.py",
            "tests/unit/__init__.py",
            "tests/unit/test_cli.py",
            "tests/unit/test_commit_batching_it.py",
            "tests/unit/test_consumer_timing_env.py",
            "tests/unit/test_e2e_preflight_remediation.py",
            "tests/unit/test_faults.py",
            "tests/unit/test_personas.py",
            "tests/unit/test_pipeline_it_network.py",
            "tests/unit/test_plan.py",
            "tests/unit/test_report.py",
            "tests/unit/test_scenarios.py",
            "tests/unit/test_shutdown_it.py",
            "tests/unit/test_smoke_cleanup_containment.py",
            "tests/unit/test_viewer_sql_it.py",
            "workload_generator/__init__.py",
            "workload_generator/__main__.py",
            "workload_generator/cli.py",
            "workload_generator/faults.py",
            "workload_generator/personas.py",
            "workload_generator/plan.py",
            "workload_generator/real_driver.py",
            "workload_generator/report.py",
            "workload_generator/rng.py",
            "workload_generator/scenarios.py",
        ]

    def test_no_endpoint_or_topic_is_configured_outside_the_command_and_driver(self):
        # The command names endpoints only in its help and refusals; the
        # driver only validates the one it is given.
        for path in _STRICT_MODULES:
            if path.name == "cli.py":
                continue
            text = path.read_text(encoding="utf-8")
            for word in ("4317", "4318", "9092", "5432", "localhost", "agentops.telemetry",
                         "bootstrap.servers", "http://", "https://"):
                assert word not in text, (path.name, word)

    def test_no_kafka_or_database_target_anywhere(self):
        for path in _RUNTIME_MODULES:
            text = path.read_text(encoding="utf-8")
            for word in ("9092", "5432", "agentops.telemetry", "bootstrap.servers",
                         "postgresql://", "PG_PASSWORD", "KAFKA_BOOTSTRAP"):
                assert word not in text, (path.name, word)

    def test_the_demo_application_is_not_imported_by_the_strict_modules(self):
        for path in _STRICT_MODULES:
            text = path.read_text(encoding="utf-8")
            assert "sys.path" not in text
            assert "demo-app" not in text and "demo_app" not in text
