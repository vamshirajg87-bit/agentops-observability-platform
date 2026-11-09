"""
workload-generator/tests/unit/test_consumer_timing_env.py

The storage consumer's timing switch in the D3 smoke harness (run_smoke.py).
No process, Docker or network: start_host_process and the waits are replaced.

Proves:
  - timing is off by default and nothing is inherited from the ambient environment
  - it is passed to the storage consumer only when the harness setting is above 0
  - no other host process, and no other setting of the consumer, changes
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_WG = Path(__file__).resolve().parents[2]
if str(_WG) not in sys.path:
    sys.path.insert(0, str(_WG))

import run_smoke as smoke  # noqa: E402

VARIABLE = "CONSUMER_TIMING_INTERVAL_SECONDS"


@pytest.fixture
def started(monkeypatch):
    """Runs start_host_services with the process start and the waits replaced; returns
    {process name: environment it would have been given}."""
    environments = {}
    monkeypatch.setattr(smoke, "start_host_process",
                        lambda name, directory, env: environments.__setitem__(name, dict(env)))
    monkeypatch.setattr(smoke, "wait_started", lambda *a, **k: None)
    monkeypatch.setattr(smoke, "wait_for", lambda *a, **k: None)
    monkeypatch.setattr(smoke, "check_host_processes", lambda: None)
    monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "not-a-real-password"})
    monkeypatch.delenv(VARIABLE, raising=False)
    return environments


def test_the_harness_setting_is_off_by_default():
    assert smoke.CONSUMER_TIMING_INTERVAL == 0.0


def test_the_ambient_environment_is_never_inherited(monkeypatch, started):
    monkeypatch.setenv(VARIABLE, "5")
    assert VARIABLE not in smoke.host_environment()
    smoke.start_host_services()
    assert set(started) == {"stream-processor", "storage-consumer"}
    assert all(VARIABLE not in env for env in started.values())


def test_disabled_leaves_the_consumer_environment_exactly_as_before(monkeypatch, started):
    monkeypatch.setattr(smoke, "CONSUMER_TIMING_INTERVAL", 0.0)
    smoke.start_host_services()
    consumer = started["storage-consumer"]
    assert VARIABLE not in consumer
    assert consumer["PG_PASSWORD"] == "not-a-real-password"
    assert consumer["CONSUMER_GROUP_ID"] == smoke.GROUP_STORAGE
    assert consumer["KAFKA_BOOTSTRAP_SERVERS"] == f"127.0.0.1:{smoke.KAFKA_PORT}"


@pytest.mark.parametrize("interval,text", [(5.0, "5"), (2.5, "2.5"), (10, "10")])
def test_enabled_passes_the_interval_to_the_storage_consumer_only(monkeypatch, started,
                                                                  interval, text):
    monkeypatch.setattr(smoke, "CONSUMER_TIMING_INTERVAL", interval)
    smoke.start_host_services()
    assert started["storage-consumer"][VARIABLE] == text
    assert VARIABLE not in started["stream-processor"]


def test_enabling_changes_exactly_one_variable(monkeypatch, started):
    smoke.start_host_services()
    plain = {name: dict(env) for name, env in started.items()}
    started.clear()
    monkeypatch.setattr(smoke, "CONSUMER_TIMING_INTERVAL", 5.0)
    smoke.start_host_services()
    assert started["stream-processor"] == plain["stream-processor"]
    consumer = dict(started["storage-consumer"])
    assert consumer.pop(VARIABLE) == "5"
    assert consumer == plain["storage-consumer"]


def test_a_non_positive_setting_is_off(monkeypatch, started):
    for value in (0, 0.0, -1.0):
        started.clear()
        monkeypatch.setattr(smoke, "CONSUMER_TIMING_INTERVAL", value)
        smoke.start_host_services()
        assert VARIABLE not in started["storage-consumer"]


# ---------------------------------------------------------------------------
# B3J-257: opt-in commit batching of the storage consumer
# ---------------------------------------------------------------------------

BATCH = "CONSUMER_COMMIT_BATCH_MESSAGES"
INTERVAL = "CONSUMER_COMMIT_INTERVAL_SECONDS"


@pytest.fixture
def waits(monkeypatch, started):
    """Also records what the harness waits for in each host process's startup banner."""
    seen = {}
    monkeypatch.setattr(smoke, "wait_started",
                        lambda name, expected, forbidden=(): seen.__setitem__(name, (tuple(expected), tuple(forbidden))))
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_BATCH_MESSAGES", 1)
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_INTERVAL_SECONDS", 1.0)
    for name in (BATCH, INTERVAL):
        monkeypatch.delenv(name, raising=False)
    return seen


def test_batching_is_off_by_default():
    assert smoke.CONSUMER_COMMIT_BATCH_MESSAGES == 1 and smoke.CONSUMER_COMMIT_INTERVAL_SECONDS == 1.0
    assert smoke.COMMIT_BATCH_LIMITS == (1, 1000) and smoke.COMMIT_INTERVAL_LIMITS == (0.05, 30.0)


def test_n_equals_one_leaves_the_consumer_environment_byte_identical(waits, started):
    smoke.start_host_services()
    consumer = started["storage-consumer"]
    assert BATCH not in consumer and INTERVAL not in consumer
    assert set(consumer) == set(smoke.host_environment()) | {
        "KAFKA_BOOTSTRAP_SERVERS", "CONSUMER_GROUP_ID", "CONSUMER_AUTO_OFFSET_RESET", "TOPIC_SPANS",
        "PG_HOST", "PG_PORT", "PG_DATABASE", "PG_USER", "PG_PASSWORD"}
    assert not any(name.startswith("CONSUMER_COMMIT") for name in consumer)


def test_n_equals_one_adds_nothing_even_with_a_changed_interval(waits, started, monkeypatch):
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_INTERVAL_SECONDS", 7.0)
    smoke.start_host_services()
    assert BATCH not in started["storage-consumer"] and INTERVAL not in started["storage-consumer"]


def test_the_ambient_environment_cannot_enable_batching(waits, started, monkeypatch):
    monkeypatch.setenv(BATCH, "100")
    monkeypatch.setenv(INTERVAL, "1")
    assert BATCH not in smoke.host_environment() and BATCH not in smoke.tool_environment()
    smoke.start_host_services()
    assert all(BATCH not in env and INTERVAL not in env for env in started.values())


@pytest.mark.parametrize("batch,interval,text", [(100, 1.0, "1"), (2, 0.05, "0.05"), (1000, 30.0, "30"), (100, 2.5, "2.5")])
def test_n_greater_than_one_adds_exactly_the_two_variables_to_the_storage_consumer(
        waits, started, monkeypatch, batch, interval, text):
    smoke.start_host_services()
    plain = {name: dict(env) for name, env in started.items()}
    started.clear()
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_BATCH_MESSAGES", batch)
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_INTERVAL_SECONDS", interval)
    smoke.start_host_services()
    assert started["stream-processor"] == plain["stream-processor"]
    consumer = dict(started["storage-consumer"])
    assert consumer.pop(BATCH) == str(batch) and consumer.pop(INTERVAL) == text
    assert consumer == plain["storage-consumer"]


def test_the_startup_banner_is_expected_for_n_greater_than_one_and_forbidden_for_n_equals_one(waits, started, monkeypatch):
    smoke.start_host_services()
    expected, forbidden = waits["storage-consumer"]
    assert not any(line.startswith("commit") for line in expected) and forbidden == ("commit     :",)
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_BATCH_MESSAGES", 100)
    smoke.start_host_services()
    expected, forbidden = waits["storage-consumer"]
    assert "commit     : batches of up to 100 messages, about every 1 s" in expected and forbidden == ()


def test_the_banner_text_is_what_the_consumer_prints():
    source = (_WG.parent / "storage-consumer" / "main.py").read_text(encoding="utf-8")
    assert 'print(f"  commit     : batches of up to {config.COMMIT_BATCH_MESSAGES} messages, "' in source
    assert 'f"about every {config.COMMIT_INTERVAL_SECONDS:g} s")' in source


def test_an_unrequested_commit_line_in_the_banner_fails_the_start(monkeypatch):
    monkeypatch.setattr(smoke, "check_host_processes", lambda: None)
    monkeypatch.setattr(smoke, "read_log", lambda name: "group      : x\n  commit     : batches of up to 100 messages, about every 1 s\n")
    with pytest.raises(smoke.SmokeFailure, match="not requested"):
        smoke.wait_started("storage-consumer", ("group      : x",), forbidden=("commit     :",))


@pytest.mark.parametrize("batch", [0, -1, 1001, 1.5, "100", None, True, False, [100]])
def test_an_unsupported_batch_fails_closed_before_any_service_starts(waits, started, monkeypatch, batch):
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_BATCH_MESSAGES", batch)
    with pytest.raises(smoke.SmokeFailure):
        smoke.start_host_services()
    assert started == {} and waits == {}


@pytest.mark.parametrize("interval", [0, 0.04, 30.1, -1.0, float("nan"), "1.0", None, True])
def test_an_unsupported_interval_fails_closed_when_batching_is_on(waits, started, monkeypatch, interval):
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_BATCH_MESSAGES", 100)
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_INTERVAL_SECONDS", interval)
    with pytest.raises(smoke.SmokeFailure):
        smoke.start_host_services()
    assert started == {}


def test_the_interval_is_not_validated_when_batching_is_off(waits, started, monkeypatch):
    monkeypatch.setattr(smoke, "CONSUMER_COMMIT_INTERVAL_SECONDS", None)
    smoke.start_host_services()
    assert INTERVAL not in started["storage-consumer"]


def test_the_limits_equal_the_consumers_own():
    source = (_WG.parent / "storage-consumer" / "config.py").read_text(encoding="utf-8")
    assert "between 1 and 1000" in source and "between 0.05 and 30" in source
