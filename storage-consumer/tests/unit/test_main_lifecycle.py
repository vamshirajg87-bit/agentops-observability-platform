"""
storage-consumer/tests/unit/test_main_lifecycle.py

Offline tests for the storage-consumer entrypoint's graceful shutdown (main.py).

What is real: main.install_shutdown_handlers and main.main() (with the Kafka and PostgreSQL clients and,
where noted, the loop replaced), and, in the last class, the real consumer.run_consumer_loop /
process_message / OffsetBatcher with the real CanonicalSpanEvent validation.
What is fake: the signal module (nothing is registered with the operating system and no signal is ever
sent: a "signal" is a direct call of the handler the code registered), the Kafka consumer, the repository
(it records the order of database work and Kafka commits), and the stderr writer.

What this proves, and what it does not
  - It proves the registration, restoration and escalation logic, the exit codes, that the existing loop
    finishes the message in hand (database insert first, then its offset commit or its batcher record),
    and that a graceful or interrupted exit commits only the offsets of persisted messages.
  - It does NOT prove behavior under real signals, under Docker (PID 1 handling, stop grace period), with a
    real PostgreSQL transaction or with real Kafka commit semantics; those need the separately gated live
    validation.
"""

from __future__ import annotations

import inspect
import json
import signal
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import confluent_kafka
import pytest

import consumer as consumer_mod
import main as main_mod
from consumer import OffsetBatcher
from main import install_shutdown_handlers

TOPIC = "agentops.telemetry.spans"


class FakeSignalModule:
    """Stands in for the signal module: records registrations, never touches the operating system."""

    SIGTERM, SIGINT, SIG_DFL = signal.SIGTERM, signal.SIGINT, signal.SIG_DFL

    def __init__(self, previous=None, fail=None):
        self.handlers = {self.SIGTERM: "previous-term", self.SIGINT: "previous-int"}
        self.handlers.update(previous or {})
        self.fail = fail or {}
        self.calls = []                      # (signum, handler) for every successful registration

    def getsignal(self, signum):
        return self.handlers.get(signum)

    def signal(self, signum, handler):
        if signum in self.fail:
            raise self.fail[signum]
        self.calls.append((signum, handler))
        self.handlers[signum] = handler


def deliver(fake, signum):
    """A 'signal' arrives: call the handler the code registered."""
    fake.handlers[signum](signum, None)


ORIGINAL = {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}


# ---------------------------------------------------------------------------
# install_shutdown_handlers
# ---------------------------------------------------------------------------

class TestInstallShutdownHandlers:
    def test_sigterm_and_sigint_are_registered(self):
        fake, event = FakeSignalModule(), threading.Event()
        install_shutdown_handlers(event, signal_module=fake, report=lambda line: None)
        assert {s for s, _ in fake.calls} == {signal.SIGTERM, signal.SIGINT}
        assert all(callable(h) for _, h in fake.calls) and not event.is_set()

    @pytest.mark.parametrize("signum, name", [(signal.SIGTERM, "SIGTERM"), (signal.SIGINT, "SIGINT")])
    def test_the_first_signal_sets_the_event_and_writes_one_diagnostic(self, signum, name):
        fake, event, lines = FakeSignalModule(), threading.Event(), []
        install_shutdown_handlers(event, signal_module=fake, report=lines.append)
        deliver(fake, signum)
        assert event.is_set()
        assert len(lines) == 1 and lines[0].startswith("storage consumer: ") and name in lines[0]
        assert lines[0].endswith("\n") and "immediately" in lines[0]

    @pytest.mark.parametrize("first, second", [(signal.SIGTERM, signal.SIGTERM), (signal.SIGTERM, signal.SIGINT),
                                               (signal.SIGINT, signal.SIGINT), (signal.SIGINT, signal.SIGTERM)])
    def test_a_repeated_signal_raises_keyboard_interrupt_without_another_diagnostic(self, first, second):
        fake, event, lines = FakeSignalModule(), threading.Event(), []
        install_shutdown_handlers(event, signal_module=fake, report=lines.append)
        deliver(fake, first)
        with pytest.raises(KeyboardInterrupt):
            deliver(fake, second)
        assert event.is_set() and len(lines) == 1

    def test_restore_puts_back_the_previous_handlers(self):
        fake = FakeSignalModule()
        restore = install_shutdown_handlers(threading.Event(), signal_module=fake, report=lambda line: None)
        assert fake.handlers[signal.SIGTERM] != "previous-term"
        restore()
        assert fake.handlers == ORIGINAL

    def test_a_handler_that_was_not_set_from_python_is_restored_to_the_default(self):
        fake = FakeSignalModule(previous={signal.SIGTERM: None})
        restore = install_shutdown_handlers(threading.Event(), signal_module=fake, report=lambda line: None)
        restore()
        assert fake.handlers[signal.SIGTERM] == signal.SIG_DFL and fake.handlers[signal.SIGINT] == "previous-int"

    def test_restore_is_idempotent(self):
        fake = FakeSignalModule()
        restore = install_shutdown_handlers(threading.Event(), signal_module=fake, report=lambda line: None)
        restore()
        registrations = len(fake.calls)
        restore()
        assert len(fake.calls) == registrations

    def test_an_unsupported_context_is_skipped_with_a_diagnostic_and_changes_nothing(self):
        error = ValueError("signal only works in main thread of the main interpreter")
        fake = FakeSignalModule(fail={signal.SIGTERM: error, signal.SIGINT: error})
        event, lines = threading.Event(), []
        restore = install_shutdown_handlers(event, signal_module=fake, report=lines.append)
        assert fake.calls == [] and not event.is_set()
        assert len(lines) == 2 and all("cannot handle" in line and "previous behavior" in line for line in lines)
        restore()
        assert fake.calls == [] and fake.handlers == ORIGINAL

    def test_a_partial_failure_installs_and_restores_only_what_it_installed(self):
        fake = FakeSignalModule(fail={signal.SIGINT: OSError("not supported")})
        lines = []
        restore = install_shutdown_handlers(threading.Event(), signal_module=fake, report=lines.append)
        assert [s for s, _ in fake.calls] == [signal.SIGTERM] and len(lines) == 1 and "SIGINT" in lines[0]
        restore()
        assert fake.handlers == ORIGINAL

    def test_the_default_diagnostic_is_written_to_file_descriptor_2(self, capfd):
        main_mod._report_to_stderr("storage consumer: hello\n")
        assert capfd.readouterr().err == "storage consumer: hello\n"

    def test_the_default_signal_module_is_the_real_one(self):
        # main() installs real handlers; every other test here passes a fake, so nothing is registered
        assert inspect.signature(install_shutdown_handlers).parameters["signal_module"].default is signal


# ---------------------------------------------------------------------------
# main(): shutdown event wiring and exit behavior
# ---------------------------------------------------------------------------

@pytest.fixture
def entrypoint(monkeypatch):
    """main() with the Kafka and PostgreSQL clients mocked, the signal module faked, the loop replaced."""
    state = SimpleNamespace(fake=FakeSignalModule(), reports=[], loop_kwargs=None, handlers_at_loop=None,
                            kafka=MagicMock(), pg=MagicMock())

    def run(loop, fake=None, batch=1):
        state.fake = fake or state.fake
        monkeypatch.setattr(main_mod, "confluent_kafka", state.kafka)
        monkeypatch.setattr(main_mod, "psycopg", state.pg)
        monkeypatch.setattr(main_mod.config, "COMMIT_BATCH_MESSAGES", batch)
        monkeypatch.setattr(main_mod, "install_shutdown_handlers",
                            lambda event: install_shutdown_handlers(
                                event, signal_module=state.fake, report=state.reports.append))

        def wrapped_loop(**kwargs):
            state.loop_kwargs = kwargs
            state.handlers_at_loop = dict(state.fake.handlers)
            return loop(state.fake, kwargs["shutdown_event"])
        monkeypatch.setattr(main_mod, "run_consumer_loop", wrapped_loop)
        return main_mod.main()
    state.run = run
    return state


class TestMainShutdownBehavior:
    def test_a_signal_during_the_loop_ends_in_a_normal_return_which_is_exit_code_zero(self, entrypoint, capsys):
        def loop(fake, event):
            deliver(fake, signal.SIGTERM)             # the signal arrives while the loop runs
            assert event.is_set()                     # and the loop sees the very event the handler set
        assert entrypoint.run(loop) is None           # returned: the process exits 0
        assert "stopped (shutdown requested)" in capsys.readouterr().out
        assert len(entrypoint.reports) == 1 and "SIGTERM" in entrypoint.reports[0]
        entrypoint.pg.connect.return_value.close.assert_called_once()

    def test_the_event_passed_to_the_loop_is_the_one_the_handler_sets(self, entrypoint):
        seen = {}

        def loop(fake, event):
            seen["before"] = event.is_set()
            deliver(fake, signal.SIGINT)
            seen["after"] = event.is_set()
        entrypoint.run(loop)
        assert seen == {"before": False, "after": True}
        assert set(entrypoint.loop_kwargs) == {"consumer", "repository", "shutdown_event", "timing"}

    def test_the_batcher_is_still_passed_when_batching_is_enabled(self, entrypoint):
        entrypoint.run(lambda fake, event: None, batch=3)
        assert set(entrypoint.loop_kwargs) == {"consumer", "repository", "shutdown_event", "timing", "batcher"}
        assert isinstance(entrypoint.loop_kwargs["batcher"], OffsetBatcher)

    def test_handlers_are_installed_before_the_loop_and_restored_after_it(self, entrypoint):
        entrypoint.run(lambda fake, event: None)
        assert entrypoint.handlers_at_loop[signal.SIGTERM] != "previous-term"          # installed during the loop
        assert entrypoint.fake.handlers == ORIGINAL

    def test_a_processing_failure_still_exits_nonzero_restores_handlers_and_closes_the_connection(
            self, entrypoint, capsys):
        def loop(fake, event):
            raise RuntimeError("boom")
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 1 and "halted: boom" in capsys.readouterr().err
        assert entrypoint.fake.handlers == ORIGINAL
        entrypoint.pg.connect.return_value.close.assert_called_once()

    def test_a_second_signal_keeps_the_existing_interruption_behavior(self, entrypoint, capsys):
        def loop(fake, event):
            deliver(fake, signal.SIGTERM)
            deliver(fake, signal.SIGTERM)             # raises KeyboardInterrupt out of the loop
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 0 and "stopped." in capsys.readouterr().out
        assert len(entrypoint.reports) == 1           # one diagnostic only
        assert entrypoint.fake.handlers == ORIGINAL
        entrypoint.pg.connect.return_value.close.assert_called_once()

    def test_a_system_exit_from_the_loop_is_not_changed(self, entrypoint):
        def loop(fake, event):
            raise SystemExit(7)
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 7
        assert entrypoint.fake.handlers == ORIGINAL

    def test_an_unsupported_signal_context_does_not_stop_the_service_from_running(self, entrypoint):
        error = ValueError("signal only works in main thread of the main interpreter")
        fake = FakeSignalModule(fail={signal.SIGTERM: error, signal.SIGINT: error})
        ran = []
        assert entrypoint.run(lambda fake_, event: ran.append(event.is_set()), fake=fake) is None
        assert ran == [False] and len(entrypoint.reports) == 2


# ---------------------------------------------------------------------------
# The real loop: the message in hand is finished, and only persisted work is committed
# ---------------------------------------------------------------------------

def span_bytes(index):
    now = datetime.now(tz=timezone.utc).isoformat()
    return json.dumps({"trace_id": "a" * 32, "span_id": f"{index:016x}", "span_name": "t.op",
                       "span_kind": "INTERNAL", "service_name": "svc", "start_time": now,
                       "end_time": now, "duration_ms": 0.0, "status_code": "OK"}).encode()


def message(offset):
    msg = MagicMock()
    msg.value.return_value = span_bytes(offset)
    msg.topic.return_value, msg.partition.return_value, msg.offset.return_value = TOPIC, 0, offset
    msg.error.return_value = None
    return msg


class TestTheRealLoopUnderShutdown:
    @pytest.fixture
    def stack(self):
        order, polls = [], []
        fake, event = FakeSignalModule(), threading.Event()
        install_shutdown_handlers(event, signal_module=fake, report=lambda line: order.append("diagnostic"))
        consumer = MagicMock()
        consumer.close.side_effect = lambda: order.append("consumer.close")

        def commit(message=None, offsets=None, asynchronous=True):
            assert asynchronous is False
            if message is not None:
                order.append(f"commit message {message.offset()}")
                return None
            order.append("commit offsets " + ",".join(f"{o.partition}:{o.offset}" for o in offsets))
            return [confluent_kafka.TopicPartition(o.topic, o.partition, o.offset) for o in offsets]
        consumer.commit.side_effect = commit

        repo = MagicMock()
        hooks = {}

        def insert_span(event_, topic, partition, offset):
            order.append(f"insert {offset}")
            if offset in hooks:
                hooks[offset]()
            order.append(f"inserted {offset}")
            return True
        repo.insert_span.side_effect = insert_span

        def feed(count, *, idle_after=None):
            queue = [message(i) for i in range(count)]

            def poll(timeout=None):
                polls.append(1)
                assert len(polls) <= count + 3, "the loop did not stop after the shutdown event was set"
                return queue.pop(0) if queue else None
            consumer.poll.side_effect = poll
        return SimpleNamespace(order=order, polls=polls, fake=fake, event=event, consumer=consumer, repo=repo,
                               hooks=hooks, feed=feed)

    def run(self, s, *, batch=None):
        batcher = None
        if batch is not None:
            batcher = OffsetBatcher(s.consumer, batch, 30.0, clock=lambda: 0.0, log=lambda m: None)
            batcher.on_assign(s.consumer, [confluent_kafka.TopicPartition(TOPIC, 0)])
        consumer_mod.run_consumer_loop(s.consumer, s.repo, s.event, poll_timeout_seconds=0.0, batcher=batcher)

    # -- the default loop ------------------------------------------------------------------------
    def test_a_signal_during_the_database_insert_lets_it_finish_and_commit_before_the_loop_exits(self, stack):
        s = stack
        s.feed(3)
        s.hooks[0] = lambda: deliver(s.fake, signal.SIGTERM)             # arrives while message 0 is being inserted
        self.run(s)
        assert s.order == ["insert 0", "diagnostic", "inserted 0", "commit message 0", "consumer.close"]
        assert len(s.polls) == 1                                          # no further polling once shutdown is seen
        assert s.order.index("inserted 0") < s.order.index("commit message 0")      # database work first

    def test_a_second_signal_during_the_insert_commits_nothing_and_still_closes(self, stack):
        s = stack
        s.feed(3)

        def twice():
            deliver(s.fake, signal.SIGTERM)
            deliver(s.fake, signal.SIGTERM)
        s.hooks[0] = twice
        with pytest.raises(KeyboardInterrupt):
            self.run(s)
        assert s.order == ["insert 0", "diagnostic", "consumer.close"]    # never "inserted", never committed
        s.consumer.commit.assert_not_called()
        assert len(s.polls) == 1

    def test_a_database_failure_after_a_signal_commits_nothing(self, stack):
        s = stack
        s.feed(3)

        def fail():
            deliver(s.fake, signal.SIGTERM)
            raise RuntimeError("database down")
        s.hooks[0] = fail
        with pytest.raises(RuntimeError, match="database down"):
            self.run(s)
        assert s.order == ["insert 0", "diagnostic", "consumer.close"]
        s.consumer.commit.assert_not_called()

    def test_a_signal_while_idle_exits_without_any_commit_or_insert(self, stack):
        s = stack
        polls = []

        def poll(timeout=None):
            polls.append(1)
            assert len(polls) <= 3, "the loop did not stop after the shutdown event was set"
            deliver(s.fake, signal.SIGINT)
            return None
        s.consumer.poll.side_effect = poll
        self.run(s)
        assert s.order == ["diagnostic", "consumer.close"] and len(polls) == 1
        s.repo.insert_span.assert_not_called()

    # -- the opt-in batched loop -----------------------------------------------------------------
    def test_with_batching_a_graceful_exit_flushes_exactly_the_persisted_offsets(self, stack):
        s = stack
        s.feed(5)
        s.hooks[2] = lambda: deliver(s.fake, signal.SIGTERM)             # arrives while message 2 is being inserted
        self.run(s, batch=10)
        assert s.order == ["insert 0", "inserted 0", "insert 1", "inserted 1", "insert 2", "diagnostic",
                           "inserted 2", "commit offsets 0:3", "consumer.close"]
        assert len(s.polls) == 3                                          # messages 3 and 4 are never polled
        assert s.order.index("inserted 2") < s.order.index("commit offsets 0:3")

    def test_with_batching_a_second_signal_flushes_only_what_was_persisted_before_it(self, stack):
        s = stack
        s.feed(5)

        def twice():
            deliver(s.fake, signal.SIGTERM)
            deliver(s.fake, signal.SIGTERM)
        s.hooks[2] = twice                                                # message 2 is never recorded
        with pytest.raises(KeyboardInterrupt):
            self.run(s, batch=10)
        assert s.order == ["insert 0", "inserted 0", "insert 1", "inserted 1", "insert 2", "diagnostic",
                           "commit offsets 0:2", "consumer.close"]
        assert "commit offsets 0:3" not in s.order                       # offset 3 would cover unpersisted work

    def test_with_batching_a_database_failure_after_a_signal_flushes_only_earlier_persisted_offsets(self, stack):
        s = stack
        s.feed(5)

        def fail():
            deliver(s.fake, signal.SIGTERM)
            raise RuntimeError("database down")
        s.hooks[2] = fail
        with pytest.raises(RuntimeError, match="database down"):
            self.run(s, batch=10)
        assert s.order[-2:] == ["commit offsets 0:2", "consumer.close"]
        assert "commit offsets 0:3" not in s.order

    def test_with_batching_a_signal_while_idle_flushes_the_pending_offsets_and_exits(self, stack):
        s = stack
        s.feed(2)
        polls = []
        real_poll = s.consumer.poll.side_effect

        def poll(timeout=None):
            message_ = real_poll(timeout)
            polls.append(message_)
            if message_ is None:
                deliver(s.fake, signal.SIGTERM)                          # the signal arrives on the idle poll
            return message_
        s.consumer.poll.side_effect = poll
        self.run(s, batch=10)
        assert s.order == ["insert 0", "inserted 0", "insert 1", "inserted 1", "diagnostic",
                           "commit offsets 0:2", "consumer.close"]
        assert sum(1 for m in polls if m is None) == 1
