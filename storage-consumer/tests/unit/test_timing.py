"""
storage-consumer/tests/unit/test_timing.py

Unit tests for the opt-in timing instrumentation (timing.py and its use in
consumer.py).  No live Kafka or PostgreSQL: mocks and a fake clock.

Proves:
  - timing is off by default and a disabled consumer behaves as before
  - turning it on changes no call the consumer makes (poll, insert, commit, close)
  - stage accounting with a fake clock, a bounded histogram, periodic and final
    summaries, one line per interval (never per message)
  - summaries hold only numbers: no message content, ids or credentials
  - a failed insert still prevents the offset commit, a failed Kafka commit is
    still a failure, and the timing code never replaces a processing error
"""

from __future__ import annotations

import importlib
import inspect
import json
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

import config
import consumer as consumer_mod
import timing as timing_mod
from consumer import process_message, run_consumer_loop
from timing import BUCKET_BOUNDS_MS, LINE_PREFIX, STAGES, TimingRecorder

SECRET_TEXT = "super-secret-payload-text"
TID = "a" * 32
SID = "b" * 16


def make_span_bytes(**overrides) -> bytes:
    now = datetime.now(tz=timezone.utc).isoformat()
    data = {"trace_id": TID, "span_id": SID, "span_name": "test.op", "span_kind": "INTERNAL",
            "service_name": "test-svc", "start_time": now, "end_time": now,
            "duration_ms": 0.0, "status_code": "OK"}
    data.update(overrides)
    return json.dumps(data).encode("utf-8")


def make_msg(value, topic="agentops.telemetry.spans", partition=3, offset=77, error=None):
    msg = MagicMock()
    msg.value.return_value = value
    msg.topic.return_value = topic
    msg.partition.return_value = partition
    msg.offset.return_value = offset
    msg.error.return_value = error
    return msg


def make_repository(insert_result=True):
    repo = MagicMock()
    repo.insert_span.return_value = insert_result
    return repo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeClock:
    """A clock that returns scripted values in order, then repeats the last."""

    def __init__(self, values):
        self._values = list(values)
        self._last = self._values[-1]

    def __call__(self):
        if self._values:
            self._last = self._values.pop(0)
        return self._last


class Tick:
    """A clock that advances by `step` on every reading."""

    def __init__(self, step=0.001, start=0.0):
        self.now, self.step = start, step

    def __call__(self):
        self.now += self.step
        return self.now


def consumer_yielding(messages, shutdown_event):
    """A mock consumer whose poll() delivers each message once, then stops the loop."""
    mock_consumer = MagicMock()
    remaining = list(messages)

    def poll(timeout):
        message = remaining.pop(0)
        if not remaining:
            shutdown_event.set()
        return message

    mock_consumer.poll.side_effect = poll
    return mock_consumer


def lines_of(emitted):
    parsed = []
    for line in emitted:
        assert line.startswith(LINE_PREFIX)
        parsed.append(json.loads(line[len(LINE_PREFIX):]))
    return parsed


def recorder(interval=60.0, clock=None, emitted=None):
    emitted = [] if emitted is None else emitted
    return TimingRecorder(interval, clock=clock or Tick(), emit=emitted.append), emitted


def run(messages, repo=None, timing=None, consumer=None):
    shutdown_event = threading.Event()
    mock_consumer = consumer or consumer_yielding(messages, shutdown_event)
    if consumer is not None:
        mock_consumer.poll.side_effect = None
    run_consumer_loop(mock_consumer, repo or make_repository(), shutdown_event, timing=timing)
    return mock_consumer


# ---------------------------------------------------------------------------
# Disabled by default
# ---------------------------------------------------------------------------

class TestDisabledByDefault:

    def test_config_default_is_zero_and_means_disabled(self, monkeypatch):
        monkeypatch.delenv("CONSUMER_TIMING_INTERVAL_SECONDS", raising=False)
        try:
            importlib.reload(config)
            assert config.TIMING_INTERVAL_SECONDS == 0.0
        finally:
            monkeypatch.undo()
            importlib.reload(config)

    @pytest.mark.parametrize("raw,expected", [("0", 0.0), ("10", 10.0), ("0.5", 0.5)])
    def test_config_accepts_numbers(self, monkeypatch, raw, expected):
        assert config._timing_interval(raw) == expected

    @pytest.mark.parametrize("raw", ["abc", "-1", "nan", "inf", ""])
    def test_config_refuses_anything_else(self, raw):
        with pytest.raises(ValueError, match="CONSUMER_TIMING_INTERVAL_SECONDS"):
            config._timing_interval(raw)

    def test_a_zero_interval_gives_no_recorder(self):
        assert TimingRecorder.from_interval(0) is None
        assert isinstance(TimingRecorder.from_interval(5), TimingRecorder)
        with pytest.raises(ValueError):
            TimingRecorder(0)

    def test_main_builds_a_recorder_only_when_enabled(self):
        import main as main_mod
        source = inspect.getsource(main_mod.main)
        assert "timing = None" in source
        assert "if config.TIMING_INTERVAL_SECONDS > 0" in source
        # imported lazily: a deployment that never enables timing does not need timing.py
        assert "from timing import" not in inspect.getsource(main_mod).split("def main")[0]

    def test_without_a_recorder_the_loop_does_no_timing_work(self):
        msg = make_msg(make_span_bytes())
        assert inspect.signature(run_consumer_loop).parameters["timing"].default is None
        assert inspect.signature(process_message).parameters["timing"].default is None
        mock_consumer = run([msg])                       # runs with timing=None, no recorder
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)
        assert not hasattr(consumer_mod, "TimingRecorder")   # consumer.py imports it for typing only


# ---------------------------------------------------------------------------
# Behavior is unchanged
# ---------------------------------------------------------------------------

class TestNoBehavioralChange:

    @staticmethod
    def _calls(msgs, timing):
        repo = make_repository()
        mock_consumer = run(msgs, repo=repo, timing=timing)
        return (mock_consumer.mock_calls, repo.insert_span.mock_calls)

    def test_the_same_calls_are_made_with_and_without_timing(self):
        msgs = [make_msg(make_span_bytes(span_id=f"{i:016x}"), offset=i) for i in range(3)]
        recorder_, _ = recorder()
        without = self._calls(list(msgs), None)
        with_timing = self._calls(list(msgs), recorder_)
        assert without == with_timing
        assert len(without[0]) == 7 and len(without[1]) == 3     # 3 polls + 3 commits + close

    def test_commit_is_still_synchronous_and_per_message_after_the_insert(self):
        msgs = [make_msg(make_span_bytes(span_id=f"{i:016x}"), offset=i) for i in range(2)]
        order = []
        repo = make_repository()
        repo.insert_span.side_effect = lambda *a, **k: order.append("insert") or True
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding(msgs, shutdown_event)
        mock_consumer.commit.side_effect = lambda **k: order.append(("commit", k["asynchronous"]))
        recorder_, _ = recorder()
        run_consumer_loop(mock_consumer, repo, shutdown_event, timing=recorder_)
        assert order == ["insert", ("commit", False), "insert", ("commit", False)]
        assert mock_consumer.commit.call_args_list == [
            call(message=msgs[0], asynchronous=False), call(message=msgs[1], asynchronous=False)]
        mock_consumer.poll.assert_called_with(timeout=1.0)
        mock_consumer.close.assert_called_once()

    def test_process_message_still_returns_none_and_never_commits(self):
        repo = make_repository(insert_result=False)
        recorder_, _ = recorder()
        assert process_message(make_msg(make_span_bytes()), repo, recorder_) is None
        assert process_message(make_msg(make_span_bytes()), repo) is None
        assert ".commit(" not in inspect.getsource(process_message)


# ---------------------------------------------------------------------------
# Stage accounting with a fake clock
# ---------------------------------------------------------------------------

class TestStageAccounting:

    def test_each_stage_gets_its_own_duration(self):
        # readings: recorder start, cycle start, poll end, decode start, validated,
        # insert end, commit start, commit end, maybe_emit, final
        clock = FakeClock([0.0, 10.000, 10.004, 10.004, 10.006, 10.011, 10.011, 10.014,
                           10.014, 11.0])
        timing, emitted = recorder(interval=1000.0, clock=clock)
        run([make_msg(make_span_bytes())], timing=timing)
        (final,) = lines_of(emitted)
        stages = final["stages"]
        assert final["kind"] == "final" and final["counters"]["messages"] == 1
        expected = {"poll": 4.0, "decode_validate": 2.0, "insert_txn": 5.0,
                    "kafka_commit": 3.0, "cycle": 14.0}
        for name, milliseconds in expected.items():
            assert stages[name]["count"] == 1
            assert stages[name]["total_ms"] == pytest.approx(milliseconds, abs=0.01)
            assert stages[name]["max_ms"] == pytest.approx(milliseconds, abs=0.01)
            assert stages[name]["mean_ms"] == pytest.approx(milliseconds, abs=0.01)
        assert final["elapsed_s"] == pytest.approx(11.0)
        assert set(stages) == set(STAGES)

    def test_totals_and_maxima_over_several_messages(self):
        timing, emitted = recorder()
        for seconds in (0.001, 0.003, 0.002):
            timing.record("insert_txn", seconds)
        timing.final()
        insert = lines_of(emitted)[0]["stages"]["insert_txn"]
        assert insert["count"] == 3
        assert insert["total_ms"] == pytest.approx(6.0)
        assert insert["max_ms"] == pytest.approx(3.0)
        assert insert["mean_ms"] == pytest.approx(2.0)

    def test_new_and_conflicting_inserts_are_counted(self):
        for result, key in ((True, "inserted"), (False, "conflicts")):
            timing, emitted = recorder()
            run([make_msg(make_span_bytes())], repo=make_repository(result), timing=timing)
            counters = lines_of(emitted)[-1]["counters"]
            assert counters[key] == 1 and counters["conflicts" if key == "inserted" else "inserted"] == 0

    def test_idle_polls_are_counted_not_timed(self):
        timing, emitted = recorder()
        shutdown_event = threading.Event()
        mock_consumer = MagicMock()

        def poll(timeout):
            shutdown_event.set()
            return None

        mock_consumer.poll.side_effect = poll
        run_consumer_loop(mock_consumer, make_repository(), shutdown_event, timing=timing)
        final = lines_of(emitted)[-1]
        assert final["counters"]["idle_polls"] == 1 and final["counters"]["messages"] == 0
        assert all(stage["count"] == 0 for stage in final["stages"].values())

    def test_a_negative_duration_is_recorded_as_zero(self):
        timing, emitted = recorder()
        timing.record("poll", -5.0)
        timing.final()
        assert lines_of(emitted)[0]["stages"]["poll"]["total_ms"] == 0.0


# ---------------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------------

class TestHistogram:

    def test_values_fall_into_the_documented_buckets(self):
        timing, emitted = recorder()
        probes = {0.0004: 0, 0.0005: 0, 0.00051: 1, 0.001: 1, 0.0031: 3, 1.0: 11,
                  1.5: 12, 2.0: 12, 2.0001: 13, 3600.0: 13}
        for seconds in probes:
            timing.record("cycle", seconds)
        timing.final()
        line = lines_of(emitted)[0]
        histogram = line["stages"]["cycle"]["hist"]
        assert line["bounds_ms"] == list(BUCKET_BOUNDS_MS)
        assert len(histogram) == len(BUCKET_BOUNDS_MS) + 1
        expected = [0] * len(histogram)
        for index in probes.values():
            expected[index] += 1
        assert histogram == expected and sum(histogram) == len(probes)

    def test_memory_is_bounded_whatever_the_number_of_messages(self):
        timing, emitted = recorder()
        timing.final()
        small = len(emitted[0])
        timing2, emitted2 = recorder()
        for i in range(20000):
            timing2.record(STAGES[i % len(STAGES)], (i % 4000) / 1000.0)
        timing2.final()
        stages = lines_of(emitted2)[0]["stages"]
        assert all(len(s["hist"]) == len(BUCKET_BOUNDS_MS) + 1 for s in stages.values())
        assert sum(s["count"] for s in stages.values()) == 20000
        assert len(emitted2[0]) < small * 6            # a fixed shape, not a list of samples


# ---------------------------------------------------------------------------
# Periodic and final summaries
# ---------------------------------------------------------------------------

class TestSummaries:

    def test_no_window_line_before_the_interval_has_elapsed(self):
        clock = FakeClock([0.0, 1.0, 2.0, 3.0, 4.0])
        timing, emitted = recorder(interval=10.0, clock=clock)
        timing.count("messages")
        for _ in range(3):
            timing.maybe_emit()
        assert emitted == []

    def test_a_window_line_covers_only_its_own_interval(self):
        clock = FakeClock([0.0, 10.0, 25.0, 40.0])
        timing, emitted = recorder(interval=10.0, clock=clock)
        timing.count("messages")
        timing.record("cycle", 0.002)
        timing.maybe_emit()                           # t=10: first window
        timing.count("messages")
        timing.count("messages")
        timing.record("cycle", 0.004)
        timing.record("cycle", 0.006)
        timing.maybe_emit()                           # t=25: second window
        timing.final()                                # t=40
        first, second, final = lines_of(emitted)
        assert [first["kind"], second["kind"], final["kind"]] == ["window", "window", "final"]
        assert first["counters"]["messages"] == 1 and first["stages"]["cycle"]["count"] == 1
        assert second["counters"]["messages"] == 2 and second["stages"]["cycle"]["count"] == 2
        assert first["elapsed_s"] == pytest.approx(10.0) and second["elapsed_s"] == pytest.approx(15.0)
        assert final["counters"]["messages"] == 3 and final["stages"]["cycle"]["count"] == 3
        assert final["stages"]["cycle"]["max_ms"] == pytest.approx(6.0)
        assert final["elapsed_s"] == pytest.approx(40.0)

    def test_a_quiet_window_writes_nothing(self):
        clock = FakeClock([0.0, 11.0, 22.0])
        timing, emitted = recorder(interval=10.0, clock=clock)
        timing.maybe_emit()
        timing.maybe_emit()
        assert emitted == []

    def test_one_line_per_interval_never_one_per_message(self):
        timing, emitted = recorder(interval=10_000.0)
        msgs = [make_msg(make_span_bytes(span_id=f"{i:016x}"), offset=i) for i in range(50)]
        run(msgs, timing=timing)
        assert len(emitted) == 1 and lines_of(emitted)[0]["counters"]["messages"] == 50

    def test_the_final_summary_is_written_once_on_normal_shutdown(self):
        timing, emitted = recorder()
        mock_consumer = run([make_msg(make_span_bytes())], timing=timing)
        timing.final()                                 # a second call adds nothing
        assert [l["kind"] for l in lines_of(emitted)] == ["final"]
        mock_consumer.close.assert_called_once()

    def test_the_final_summary_is_written_before_the_consumer_is_closed(self):
        order = []
        timing = TimingRecorder(60.0, clock=Tick(), emit=lambda line: order.append("summary"))
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding([make_msg(make_span_bytes())], shutdown_event)
        mock_consumer.close.side_effect = lambda: order.append("close")
        run_consumer_loop(mock_consumer, make_repository(), shutdown_event, timing=timing)
        assert order == ["summary", "close"]


# ---------------------------------------------------------------------------
# Nothing sensitive in the output
# ---------------------------------------------------------------------------

class TestNoSensitiveOutput:

    def test_summaries_hold_only_numbers_and_stage_names(self):
        emitted = []
        timing = TimingRecorder(0.000001, clock=Tick(0.01), emit=emitted.append)
        body = make_span_bytes(
            status_message=SECRET_TEXT, service_name="svc-confidential",
            attributes={"password": "hunter2", "dsn": "postgresql://u:pw@host/db"})
        msgs = [make_msg(body, offset=i) for i in range(4)]
        run(msgs, timing=timing)
        text = "\n".join(emitted)
        assert emitted and "\n" not in emitted[0]
        for forbidden in (TID, SID, SECRET_TEXT, "svc-confidential", "hunter2", "postgresql",
                          "password", "agentops.telemetry.spans"):
            assert forbidden not in text
        for line in lines_of(emitted):
            assert set(line) == {"kind", "elapsed_s", "start_epoch_s", "end_epoch_s",
                                 "bounds_ms", "counters", "stages"}
            assert set(line["counters"]) == {"messages", "idle_polls", "inserted", "conflicts"}
            assert set(line["stages"]) == set(STAGES)

    def test_the_module_never_reads_a_message(self):
        source = inspect.getsource(timing_mod)
        for word in (".value(", ".key(", "trace_id", "span_id", "password", "connection"):
            assert word not in source.split('"""', 2)[2]


# ---------------------------------------------------------------------------
# Failures stay failures
# ---------------------------------------------------------------------------

class TestFailuresAreUnchanged:

    def test_a_failed_insert_prevents_the_offset_commit(self):
        timing, emitted = recorder()
        repo = make_repository()
        repo.insert_span.side_effect = RuntimeError("db down")
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding([make_msg(make_span_bytes())], shutdown_event)
        with pytest.raises(RuntimeError, match="db down"):
            run_consumer_loop(mock_consumer, repo, shutdown_event, timing=timing)
        mock_consumer.commit.assert_not_called()
        mock_consumer.close.assert_called_once()
        final = lines_of(emitted)[-1]
        assert final["stages"]["decode_validate"]["count"] == 1     # it finished
        assert final["stages"]["poll"]["count"] == 1                # the poll had completed
        for stage in ("insert_txn", "kafka_commit", "cycle"):
            assert final["stages"][stage]["count"] == 0, stage      # the failed message is not timed
        assert final["counters"]["messages"] == 0 and final["counters"]["inserted"] == 0

    def test_a_failed_kafka_commit_is_still_a_failure(self):
        timing, emitted = recorder()
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding([make_msg(make_span_bytes())], shutdown_event)
        mock_consumer.commit.side_effect = RuntimeError("commit failed")
        with pytest.raises(RuntimeError, match="commit failed"):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event, timing=timing)
        mock_consumer.close.assert_called_once()
        final = lines_of(emitted)[-1]
        assert final["stages"]["kafka_commit"]["count"] == 0
        assert final["stages"]["cycle"]["count"] == 0 and final["counters"]["messages"] == 0
        assert final["stages"]["insert_txn"]["count"] == 1          # the insert had completed

    @pytest.mark.parametrize("value", [b"{not json", b"\xff\xfe", None])
    def test_bad_messages_still_halt_without_insert_or_commit(self, value):
        timing, emitted = recorder()
        repo = make_repository()
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding([make_msg(value)], shutdown_event)
        with pytest.raises(Exception):
            run_consumer_loop(mock_consumer, repo, shutdown_event, timing=timing)
        repo.insert_span.assert_not_called()
        mock_consumer.commit.assert_not_called()
        mock_consumer.close.assert_called_once()
        assert lines_of(emitted)[-1]["kind"] == "final"

    def test_a_kafka_message_error_still_raises_and_does_not_commit(self):
        timing, emitted = recorder()
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding(
            [make_msg(make_span_bytes(), error=MagicMock())], shutdown_event)
        with pytest.raises(RuntimeError, match="consumer error"):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event, timing=timing)
        mock_consumer.commit.assert_not_called()

    def test_a_failing_summary_writer_never_disturbs_processing(self):
        def broken(line):
            raise OSError("stdout closed")

        timing = TimingRecorder(0.000001, clock=Tick(0.01), emit=broken)
        msgs = [make_msg(make_span_bytes(span_id=f"{i:016x}"), offset=i) for i in range(3)]
        repo = make_repository()
        mock_consumer = run(msgs, repo=repo, timing=timing)
        assert repo.insert_span.call_count == 3 and mock_consumer.commit.call_count == 3
        mock_consumer.close.assert_called_once()

    def test_a_failing_summary_writer_never_replaces_the_processing_error(self):
        def broken(line):
            raise OSError("stdout closed")

        timing = TimingRecorder(60.0, clock=Tick(), emit=broken)
        repo = make_repository()
        repo.insert_span.side_effect = RuntimeError("db down")
        shutdown_event = threading.Event()
        mock_consumer = consumer_yielding([make_msg(make_span_bytes())], shutdown_event)
        with pytest.raises(RuntimeError, match="db down"):
            run_consumer_loop(mock_consumer, repo, shutdown_event, timing=timing)
        mock_consumer.commit.assert_not_called()
        mock_consumer.close.assert_called_once()

    def test_the_default_writer_prints_one_flushed_line(self, capsys):
        timing = TimingRecorder(60.0, clock=Tick())
        timing.record("cycle", 0.001)
        timing.final()
        out = capsys.readouterr().out
        assert out.count("\n") == 1 and out.startswith(LINE_PREFIX)


# ---------------------------------------------------------------------------
# Wall-clock epoch of each summary (alignment with benchmark stages)
# ---------------------------------------------------------------------------

class TestEpochTimestamps:

    def test_windows_carry_their_wall_clock_start_and_end(self):
        wall = FakeClock([1000.0, 1010.5, 1030.25, 1040.0])
        clock = FakeClock([0.0, 10.0, 25.0, 40.0])
        emitted = []
        timing = TimingRecorder(10.0, clock=clock, emit=emitted.append, wall=wall)
        timing.count("messages")
        timing.maybe_emit()                           # wall 1010.5
        timing.count("messages")
        timing.maybe_emit()                           # wall 1030.25
        timing.final()                                # wall 1040.0
        first, second, final = lines_of(emitted)
        assert (first["start_epoch_s"], first["end_epoch_s"]) == (1000.0, 1010.5)
        assert (second["start_epoch_s"], second["end_epoch_s"]) == (1010.5, 1030.25)
        assert (final["start_epoch_s"], final["end_epoch_s"]) == (1000.0, 1040.0)

    def test_durations_still_come_from_the_monotonic_clock(self):
        # the wall clock jumps backwards (a clock correction); durations are unaffected
        wall = FakeClock([5000.0, 4000.0, 4000.0])
        clock = FakeClock([0.0, 10.0, 10.0])
        emitted = []
        timing = TimingRecorder(10.0, clock=clock, emit=emitted.append, wall=wall)
        timing.count("messages")
        timing.record("cycle", 0.002)
        timing.maybe_emit()
        (window,) = lines_of(emitted)
        assert window["elapsed_s"] == 10.0
        assert window["stages"]["cycle"]["total_ms"] == pytest.approx(2.0)
        assert window["end_epoch_s"] < window["start_epoch_s"]      # reported as it was

    def test_the_default_wall_clock_is_real_time(self):
        import time as real_time
        emitted = []
        before = real_time.time()
        timing = TimingRecorder(60.0, clock=Tick(), emit=emitted.append)
        timing.final()
        after = real_time.time()
        (final,) = lines_of(emitted)
        assert before - 1 <= final["start_epoch_s"] <= final["end_epoch_s"] <= after + 1

    def test_the_epoch_fields_hold_only_numbers(self):
        emitted = []
        timing = TimingRecorder(60.0, clock=Tick(), emit=emitted.append, wall=lambda: 1.5)
        timing.final()
        (final,) = lines_of(emitted)
        assert isinstance(final["start_epoch_s"], float) and isinstance(final["end_epoch_s"], float)
