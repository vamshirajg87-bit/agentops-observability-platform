"""
tests/unit/test_main_lifecycle.py

Offline tests for the stream-processor entrypoint's graceful shutdown (main.py).

What is real: main.install_shutdown_handlers and main.main() (with the Kafka clients and the loop replaced
where noted), and, in the last class, the real processor.run_consumer_loop / process_message with the real
SpanDeduplicator.
What is fake: the signal module (nothing is registered with the operating system and no signal is ever
sent: a "signal" is a direct call of the handler the code registered), the Kafka consumer, the publisher,
and the stderr writer.

What this proves, and what it does not
  - It proves the registration, restoration and escalation logic, the exit codes, and that the existing
    loop finishes the message in hand and commits only completed work after the shutdown event is set.
  - It does NOT prove behavior under real signals, under Docker (PID 1 handling, stop grace period), or on
    Windows; those need the separately gated live validation.
"""

from __future__ import annotations

import inspect
import signal
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import main as main_mod
import processor as proc
from deduplicator import SpanDeduplicator
from main import install_shutdown_handlers

TOPIC = "agentops.telemetry.otlp.traces"
TID = "aa" * 16
SID_A, SID_B = "11" * 8, "22" * 8


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
        assert len(lines) == 1 and lines[0].startswith("stream processor: ") and name in lines[0]
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
        assert fake.handlers[signal.SIGTERM] not in ("previous-term",)
        restore()
        assert fake.handlers == {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}

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
        assert fake.calls == [] and fake.handlers == {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}

    def test_a_partial_failure_installs_and_restores_only_what_it_installed(self):
        fake = FakeSignalModule(fail={signal.SIGINT: OSError("not supported")})
        lines = []
        restore = install_shutdown_handlers(threading.Event(), signal_module=fake, report=lines.append)
        assert [s for s, _ in fake.calls] == [signal.SIGTERM] and len(lines) == 1 and "SIGINT" in lines[0]
        restore()
        assert fake.handlers[signal.SIGTERM] == "previous-term" and fake.handlers[signal.SIGINT] == "previous-int"

    def test_the_default_diagnostic_is_written_to_file_descriptor_2(self, capfd):
        main_mod._report_to_stderr("stream processor: hello\n")
        assert capfd.readouterr().err == "stream processor: hello\n"

    def test_the_default_signal_module_is_the_real_one(self):
        # main() installs real handlers; every other test here passes a fake, so nothing is registered
        assert inspect.signature(install_shutdown_handlers).parameters["signal_module"].default is signal


# ---------------------------------------------------------------------------
# main(): shutdown event wiring and exit behavior
# ---------------------------------------------------------------------------

@pytest.fixture
def entrypoint(monkeypatch):
    """main() with the Kafka clients mocked, the signal module faked and the loop replaced by `loop`."""
    state = SimpleNamespace(fake=FakeSignalModule(), reports=[], loop_kwargs=None, handlers_at_loop=None)

    def run(loop, fake=None):
        state.fake = fake or state.fake
        monkeypatch.setattr(main_mod, "confluent_kafka", MagicMock())
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

    def test_the_event_passed_to_the_loop_is_the_one_the_handler_sets(self, entrypoint):
        seen = {}

        def loop(fake, event):
            seen["before"] = event.is_set()
            deliver(fake, signal.SIGINT)
            seen["after"] = event.is_set()
        entrypoint.run(loop)
        assert seen == {"before": False, "after": True}
        assert set(entrypoint.loop_kwargs) == {"consumer", "publisher", "deduplicator", "shutdown_event"}

    def test_handlers_are_installed_before_the_loop_and_restored_after_it(self, entrypoint):
        def loop(fake, event):
            return None
        entrypoint.run(loop)
        assert entrypoint.handlers_at_loop[signal.SIGTERM] != "previous-term"          # installed during the loop
        assert entrypoint.fake.handlers == {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}

    def test_a_processing_failure_still_exits_nonzero_and_restores_the_handlers(self, entrypoint, capsys):
        def loop(fake, event):
            raise RuntimeError("boom")
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 1 and "halted: boom" in capsys.readouterr().err
        assert entrypoint.fake.handlers == {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}

    def test_a_second_signal_keeps_the_existing_interruption_behavior(self, entrypoint, capsys):
        def loop(fake, event):
            deliver(fake, signal.SIGTERM)
            deliver(fake, signal.SIGTERM)             # raises KeyboardInterrupt out of the loop
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 0 and "stopped." in capsys.readouterr().out
        assert len(entrypoint.reports) == 1           # one diagnostic only
        assert entrypoint.fake.handlers == {signal.SIGTERM: "previous-term", signal.SIGINT: "previous-int"}

    def test_a_system_exit_from_the_loop_is_not_changed(self, entrypoint):
        def loop(fake, event):
            raise SystemExit(7)
        with pytest.raises(SystemExit) as caught:
            entrypoint.run(loop)
        assert caught.value.code == 7

    def test_an_unsupported_signal_context_does_not_stop_the_service_from_running(self, entrypoint, capsys):
        error = ValueError("signal only works in main thread of the main interpreter")
        fake = FakeSignalModule(fail={signal.SIGTERM: error, signal.SIGINT: error})
        ran = []

        def loop(fake_, event):
            ran.append(event.is_set())
        assert entrypoint.run(loop, fake=fake) is None
        assert ran == [False] and len(entrypoint.reports) == 2


# ---------------------------------------------------------------------------
# The real loop: the message in hand is finished, and only completed work is committed
# ---------------------------------------------------------------------------

def _message(offset):
    msg = MagicMock()
    msg.value.return_value = b"payload"
    msg.topic.return_value, msg.partition.return_value, msg.offset.return_value = TOPIC, 0, offset
    msg.error.return_value = None
    return msg


class TestTheLoopFinishesTheMessageInHand:
    @pytest.fixture
    def stack(self, monkeypatch):
        order = []
        events = {SID_A: SimpleNamespace(trace_id=TID, span_id=SID_A),
                  SID_B: SimpleNamespace(trace_id=TID, span_id=SID_B)}
        monkeypatch.setattr(proc, "decode", lambda _: [{"span_id": SID_A}, {"span_id": SID_B}])
        monkeypatch.setattr(proc, "canonicalize", lambda d: events[d["span_id"]])
        consumer, publisher = MagicMock(), MagicMock()
        consumer.commit.side_effect = lambda **kw: order.append(f"commit {kw['message'].offset()}")
        consumer.close.side_effect = lambda: order.append("consumer.close")
        publisher.close.side_effect = lambda: order.append("publisher.close")
        fake, event = FakeSignalModule(), threading.Event()
        install_shutdown_handlers(event, signal_module=fake, report=lambda line: order.append("diagnostic"))
        return SimpleNamespace(order=order, consumer=consumer, publisher=publisher, fake=fake, event=event,
                               dedup=SpanDeduplicator(max_size=10))

    def run(self, s):
        proc.run_consumer_loop(s.consumer, s.publisher, s.dedup, s.event, poll_timeout_seconds=0.0)

    def test_a_signal_during_publication_lets_the_message_complete_and_commit_before_the_loop_exits(self, stack):
        s = stack
        s.consumer.poll.side_effect = [_message(0), _message(1)]          # the second must never be polled

        def publish(event):
            s.order.append(f"publish {event.span_id[:2]}")
            if len(s.order) == 1:
                deliver(s.fake, signal.SIGTERM)                          # arrives during the first publication
        s.publisher.publish_span.side_effect = publish

        self.run(s)

        assert s.order == ["publish 11", "diagnostic", "publish 22", "commit 0",
                           "publisher.close", "consumer.close"]
        assert s.consumer.poll.call_count == 1                            # the loop stopped between messages
        s.consumer.commit.assert_called_once()
        assert s.consumer.commit.call_args.kwargs["asynchronous"] is False
        assert s.dedup.contains(TID, SID_A) and s.dedup.contains(TID, SID_B)

    def test_a_signal_while_idle_exits_without_any_commit(self, stack):
        s = stack

        polls = []

        def poll(timeout=None):
            polls.append(1)
            assert len(polls) <= 3, "the loop did not stop after the shutdown event was set"
            deliver(s.fake, signal.SIGINT)
            return None
        s.consumer.poll.side_effect = poll
        self.run(s)
        assert s.order == ["diagnostic", "publisher.close", "consumer.close"]
        assert len(polls) == 1
        s.consumer.commit.assert_not_called()
        s.publisher.publish_span.assert_not_called()

    def test_a_second_signal_during_publication_commits_nothing_and_still_cleans_up(self, stack):
        s = stack
        s.consumer.poll.side_effect = [_message(0), _message(1)]

        def publish(event):
            s.order.append(f"publish {event.span_id[:2]}")
            deliver(s.fake, signal.SIGTERM)                               # first, then second on the next span
        s.publisher.publish_span.side_effect = publish

        with pytest.raises(KeyboardInterrupt):
            self.run(s)

        assert s.order == ["publish 11", "diagnostic", "publish 22", "publisher.close", "consumer.close"]
        s.consumer.commit.assert_not_called()                             # unfinished work is never committed
        assert s.consumer.poll.call_count == 1
