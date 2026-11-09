"""
storage-consumer/tests/unit/test_consumer.py

Unit tests for consumer.py — process_message() and run_consumer_loop().

Proves:
  - At-least-once Kafka delivery with DB-before-Kafka ordering
  - Idempotent PostgreSQL persistence (duplicate replay committed to Kafka)
  - Kafka offset committed ONLY after repository.insert_span() returns normally
  - Tombstone / decode / validation failures halt without DB or Kafka writes
  - consumer.close() is guaranteed regardless of failure mode

No live Kafka or PostgreSQL required.
"""

from __future__ import annotations

import inspect
import json
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

import consumer as consumer_mod
from consumer import process_message, run_consumer_loop


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOPIC = "agentops.telemetry.spans"
PARTITION = 3
OFFSET = 77
TID = "a" * 32   # 32 hex chars — valid trace_id
SID = "b" * 16   # 16 hex chars — valid span_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def make_span_bytes(**overrides) -> bytes:
    """Return a minimal valid CanonicalSpanEvent as UTF-8 JSON bytes."""
    now = _now_iso()
    data = {
        "trace_id": TID,
        "span_id": SID,
        "span_name": "test.op",
        "span_kind": "INTERNAL",
        "service_name": "test-svc",
        "start_time": now,
        "end_time": now,
        "duration_ms": 0.0,
        "status_code": "OK",
    }
    data.update(overrides)
    return json.dumps(data).encode("utf-8")


def make_msg(
    value: bytes | None,
    topic: str = TOPIC,
    partition: int = PARTITION,
    offset: int = OFFSET,
    error=None,
) -> MagicMock:
    """Build a mock confluent_kafka.Message."""
    msg = MagicMock()
    msg.value.return_value = value
    msg.topic.return_value = topic
    msg.partition.return_value = partition
    msg.offset.return_value = offset
    msg.error.return_value = error
    return msg


def make_repository(insert_result: bool = True) -> MagicMock:
    """Build a mock SpanRepository."""
    repo = MagicMock()
    repo.insert_span.return_value = insert_result
    return repo


def make_consumer_that_yields(msg, shutdown_event: threading.Event) -> MagicMock:
    """
    Return a mock consumer whose poll() delivers msg exactly once, sets
    shutdown_event so the loop exits cleanly after that one cycle.
    """
    mock_consumer = MagicMock()

    def poll_side_effect(timeout):
        shutdown_event.set()
        return msg

    mock_consumer.poll.side_effect = poll_side_effect
    return mock_consumer


# ===========================================================================
# TestProcessMessage
# ===========================================================================

class TestProcessMessage:

    # -----------------------------------------------------------------------
    # 1. Valid canonical JSON — insert_span called once with correct provenance
    # -----------------------------------------------------------------------

    def test_valid_canonical_json_calls_insert_once(self):
        msg = make_msg(make_span_bytes())
        repo = make_repository()
        process_message(msg, repo)
        repo.insert_span.assert_called_once()

    def test_provenance_topic_forwarded(self):
        msg = make_msg(make_span_bytes(), topic="custom.topic", partition=0, offset=0)
        repo = make_repository()
        process_message(msg, repo)
        _, kwargs = repo.insert_span.call_args
        assert kwargs["topic"] == "custom.topic"

    def test_provenance_partition_forwarded(self):
        msg = make_msg(make_span_bytes(), partition=7)
        repo = make_repository()
        process_message(msg, repo)
        _, kwargs = repo.insert_span.call_args
        assert kwargs["partition"] == 7

    def test_provenance_offset_forwarded(self):
        msg = make_msg(make_span_bytes(), offset=99999)
        repo = make_repository()
        process_message(msg, repo)
        _, kwargs = repo.insert_span.call_args
        assert kwargs["offset"] == 99999

    # -----------------------------------------------------------------------
    # 2. New span — insert_span returns True → process_message returns normally
    # -----------------------------------------------------------------------

    def test_new_span_returns_normally(self):
        msg = make_msg(make_span_bytes())
        repo = make_repository(insert_result=True)
        result = process_message(msg, repo)
        assert result is None

    # -----------------------------------------------------------------------
    # 3. Duplicate replay — insert_span returns False → still returns normally
    # -----------------------------------------------------------------------

    def test_duplicate_replay_returns_normally(self):
        """False (ON CONFLICT DO NOTHING) is not an error; message is commit-eligible."""
        msg = make_msg(make_span_bytes())
        repo = make_repository(insert_result=False)
        result = process_message(msg, repo)
        assert result is None

    def test_duplicate_replay_still_calls_insert(self):
        msg = make_msg(make_span_bytes())
        repo = make_repository(insert_result=False)
        process_message(msg, repo)
        repo.insert_span.assert_called_once()

    # -----------------------------------------------------------------------
    # 4. Tombstone (None payload) — raises, repository NOT called
    # -----------------------------------------------------------------------

    def test_tombstone_raises(self):
        msg = make_msg(None)
        repo = make_repository()
        with pytest.raises(RuntimeError):
            process_message(msg, repo)

    def test_tombstone_does_not_call_repository(self):
        msg = make_msg(None)
        repo = make_repository()
        with pytest.raises(RuntimeError):
            process_message(msg, repo)
        repo.insert_span.assert_not_called()

    # -----------------------------------------------------------------------
    # 5. Invalid UTF-8 — UnicodeDecodeError propagates, repository NOT called
    # -----------------------------------------------------------------------

    def test_invalid_utf8_propagates(self):
        msg = make_msg(b"\xff\xfe\x80 not utf-8")
        repo = make_repository()
        with pytest.raises(UnicodeDecodeError):
            process_message(msg, repo)

    def test_invalid_utf8_does_not_call_repository(self):
        msg = make_msg(b"\xff\xfe\x80 not utf-8")
        repo = make_repository()
        with pytest.raises(UnicodeDecodeError):
            process_message(msg, repo)
        repo.insert_span.assert_not_called()

    # -----------------------------------------------------------------------
    # 6. Malformed JSON — JSONDecodeError propagates, repository NOT called
    # -----------------------------------------------------------------------

    def test_malformed_json_propagates(self):
        msg = make_msg(b"this is not json {{ bad")
        repo = make_repository()
        with pytest.raises(json.JSONDecodeError):
            process_message(msg, repo)

    def test_malformed_json_does_not_call_repository(self):
        msg = make_msg(b"this is not json {{ bad")
        repo = make_repository()
        with pytest.raises(json.JSONDecodeError):
            process_message(msg, repo)
        repo.insert_span.assert_not_called()

    # -----------------------------------------------------------------------
    # 7. Invalid CanonicalSpanEvent — ValidationError propagates, repository NOT called
    # -----------------------------------------------------------------------

    def test_invalid_span_event_propagates(self):
        """trace_id that is not 32 hex chars fails Pydantic validation."""
        msg = make_msg(make_span_bytes(trace_id="tooshort"))
        repo = make_repository()
        with pytest.raises(ValidationError):
            process_message(msg, repo)

    def test_invalid_span_event_does_not_call_repository(self):
        msg = make_msg(make_span_bytes(trace_id="tooshort"))
        repo = make_repository()
        with pytest.raises(ValidationError):
            process_message(msg, repo)
        repo.insert_span.assert_not_called()

    # -----------------------------------------------------------------------
    # 8. Repository/SQL failure — exception propagates
    # -----------------------------------------------------------------------

    def test_repository_exception_propagates(self):
        msg = make_msg(make_span_bytes())
        repo = make_repository()
        repo.insert_span.side_effect = Exception("psycopg connection lost")
        with pytest.raises(Exception, match="psycopg connection lost"):
            process_message(msg, repo)

    # -----------------------------------------------------------------------
    # 9. process_message itself causes NO Kafka offset commit
    # -----------------------------------------------------------------------

    def test_no_kafka_commit_in_process_message_source(self):
        """process_message source must not contain any consumer.commit call."""
        src = inspect.getsource(consumer_mod.process_message)
        assert "consumer.commit" not in src
        assert ".commit(" not in src


# ===========================================================================
# TestRunConsumerLoop
# ===========================================================================

class TestRunConsumerLoop:

    # -----------------------------------------------------------------------
    # 10. poll() returns None → continue (no process_message, no commit)
    # -----------------------------------------------------------------------

    def test_none_poll_does_not_process_or_commit(self):
        shutdown_event = threading.Event()
        mock_consumer = MagicMock()

        def poll_side_effect(timeout):
            shutdown_event.set()
            return None

        mock_consumer.poll.side_effect = poll_side_effect
        repo = make_repository()

        run_consumer_loop(mock_consumer, repo, shutdown_event)

        repo.insert_span.assert_not_called()
        mock_consumer.commit.assert_not_called()

    # -----------------------------------------------------------------------
    # 11. shutdown_event pre-set → exits immediately, no poll
    # -----------------------------------------------------------------------

    def test_shutdown_event_pre_set_exits_immediately(self):
        shutdown_event = threading.Event()
        shutdown_event.set()
        mock_consumer = MagicMock()
        repo = make_repository()

        run_consumer_loop(mock_consumer, repo, shutdown_event)

        mock_consumer.poll.assert_not_called()
        repo.insert_span.assert_not_called()
        mock_consumer.commit.assert_not_called()

    # -----------------------------------------------------------------------
    # 12. Kafka message error → raises RuntimeError, no commit
    # -----------------------------------------------------------------------

    def test_kafka_message_error_raises(self):
        shutdown_event = threading.Event()
        fake_error = MagicMock()
        msg = make_msg(make_span_bytes(), error=fake_error)
        mock_consumer = MagicMock()
        mock_consumer.poll.side_effect = lambda timeout: msg

        with pytest.raises(RuntimeError, match="consumer error"):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

    def test_kafka_message_error_no_commit(self):
        shutdown_event = threading.Event()
        fake_error = MagicMock()
        msg = make_msg(make_span_bytes(), error=fake_error)
        mock_consumer = MagicMock()
        mock_consumer.poll.side_effect = lambda timeout: msg

        try:
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)
        except RuntimeError:
            pass

        mock_consumer.commit.assert_not_called()

    # -----------------------------------------------------------------------
    # 13. Successful NEW span → commit(message=msg, asynchronous=False) exactly once
    # -----------------------------------------------------------------------

    def test_successful_new_span_commits_offset(self):
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        repo = make_repository(insert_result=True)

        run_consumer_loop(mock_consumer, repo, shutdown_event)

        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    # -----------------------------------------------------------------------
    # 14. Duplicate replay (False from insert_span) → Kafka offset STILL committed
    # -----------------------------------------------------------------------

    def test_duplicate_replay_commits_kafka_offset(self):
        """
        ON CONFLICT DO NOTHING → insert_span returns False.
        The span already exists in the DB; Kafka offset must still be committed.
        """
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        repo = make_repository(insert_result=False)

        run_consumer_loop(mock_consumer, repo, shutdown_event)

        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    # -----------------------------------------------------------------------
    # 15. process_message failure → NO Kafka commit
    # -----------------------------------------------------------------------

    def test_process_failure_malformed_json_no_kafka_commit(self):
        shutdown_event = threading.Event()
        msg = make_msg(b"{ invalid json }")
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)

        with pytest.raises(json.JSONDecodeError):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        mock_consumer.commit.assert_not_called()

    def test_process_failure_tombstone_no_kafka_commit(self):
        shutdown_event = threading.Event()
        msg = make_msg(None)
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)

        with pytest.raises(RuntimeError):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        mock_consumer.commit.assert_not_called()

    # -----------------------------------------------------------------------
    # 16. PostgreSQL transaction/commit failure → NO Kafka commit
    # -----------------------------------------------------------------------

    def test_db_execution_failure_no_kafka_commit(self):
        """repository.insert_span raises → Kafka commit must not be reached."""
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        repo = make_repository()
        repo.insert_span.side_effect = Exception("psycopg OperationalError")

        with pytest.raises(Exception, match="psycopg OperationalError"):
            run_consumer_loop(mock_consumer, repo, shutdown_event)

        mock_consumer.commit.assert_not_called()

    def test_db_transaction_commit_failure_no_kafka_commit(self):
        """Simulate exception raised during transaction exit (commit phase)."""
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        repo = make_repository()
        repo.insert_span.side_effect = Exception("commit failed at transaction exit")

        with pytest.raises(Exception, match="commit failed"):
            run_consumer_loop(mock_consumer, repo, shutdown_event)

        mock_consumer.commit.assert_not_called()

    # -----------------------------------------------------------------------
    # 17. Kafka offset commit fails AFTER DB commit — models safe replay scenario
    # -----------------------------------------------------------------------

    def test_kafka_commit_failure_after_db_propagates(self):
        """
        DB transaction committed → consumer.commit raises.
        Exception propagates; no second commit; no DB rollback.

        On process restart, Kafka redelivers; ON CONFLICT DO NOTHING handles
        the duplicate → offset eventually committed safely.
        """
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        repo = make_repository(insert_result=True)
        mock_consumer.commit.side_effect = Exception("Kafka broker disconnect")

        with pytest.raises(Exception, match="Kafka broker disconnect"):
            run_consumer_loop(mock_consumer, repo, shutdown_event)

        # DB write happened before commit was attempted
        repo.insert_span.assert_called_once()
        # No retry of commit
        assert mock_consumer.commit.call_count == 1

    # -----------------------------------------------------------------------
    # 18. DB-before-Kafka ordering proof via runtime call log
    # -----------------------------------------------------------------------

    def test_db_commit_before_kafka_commit_ordering(self):
        """
        Behavioral ordering proof: insert_span is invoked and returns before
        consumer.commit is invoked. Uses a shared call log populated via
        side effects — not source inspection.
        """
        call_log: list[str] = []

        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())

        mock_consumer = MagicMock()

        def poll_side_effect(timeout):
            shutdown_event.set()
            return msg

        def commit_side_effect(**kwargs):
            call_log.append("kafka.commit")

        mock_consumer.poll.side_effect = poll_side_effect
        mock_consumer.commit.side_effect = commit_side_effect

        repo = MagicMock()

        def insert_side_effect(event, topic, partition, offset):
            call_log.append("db.insert_span")
            return True

        repo.insert_span.side_effect = insert_side_effect

        run_consumer_loop(mock_consumer, repo, shutdown_event)

        assert call_log == ["db.insert_span", "kafka.commit"], (
            f"Expected db.insert_span before kafka.commit; actual order: {call_log}"
        )

    # -----------------------------------------------------------------------
    # 19. consumer.close() on normal shutdown
    # -----------------------------------------------------------------------

    def test_consumer_close_on_normal_shutdown(self):
        shutdown_event = threading.Event()
        shutdown_event.set()
        mock_consumer = MagicMock()

        run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        mock_consumer.close.assert_called_once()

    # -----------------------------------------------------------------------
    # 20. consumer.close() when processing raises
    # -----------------------------------------------------------------------

    def test_consumer_close_on_processing_failure(self):
        shutdown_event = threading.Event()
        msg = make_msg(b"not valid json")
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)

        with pytest.raises(json.JSONDecodeError):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        mock_consumer.close.assert_called_once()

    # -----------------------------------------------------------------------
    # 21. consumer.close() when Kafka commit raises
    # -----------------------------------------------------------------------

    def test_consumer_close_on_kafka_commit_failure(self):
        shutdown_event = threading.Event()
        msg = make_msg(make_span_bytes())
        mock_consumer = make_consumer_that_yields(msg, shutdown_event)
        mock_consumer.commit.side_effect = Exception("commit failed")

        with pytest.raises(Exception, match="commit failed"):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        mock_consumer.close.assert_called_once()

    # -----------------------------------------------------------------------
    # 22. Processing failure halts without extra poll or commit
    # -----------------------------------------------------------------------

    def test_processing_failure_halts_without_extra_poll(self):
        """After process_message raises, the loop must not poll again."""
        shutdown_event = threading.Event()
        msg = make_msg(b"{ bad json }")

        poll_count = [0]
        mock_consumer = MagicMock()

        def poll_side_effect(timeout):
            poll_count[0] += 1
            if poll_count[0] == 1:
                return msg
            shutdown_event.set()
            return None

        mock_consumer.poll.side_effect = poll_side_effect

        with pytest.raises(json.JSONDecodeError):
            run_consumer_loop(mock_consumer, make_repository(), shutdown_event)

        assert poll_count[0] == 1, (
            f"Loop polled {poll_count[0]} times after failure; expected exactly 1"
        )
        mock_consumer.commit.assert_not_called()


# ===========================================================================
# TestMainWiring
# ===========================================================================

class TestMainWiring:
    """
    Tests 23–25: verify main.py wiring contracts.

    Source inspection is appropriate here: these are specific config-dict
    key/value literals and keyword arguments that would require deep mocking
    of confluent_kafka and psycopg constructors to test behaviourally,
    making source checks the less-brittle choice.
    """

    def _main_src(self) -> str:
        import main
        return inspect.getsource(main)

    def test_enable_auto_commit_is_python_false(self):
        """Consumer config must set enable.auto.commit to the Python boolean False."""
        src = self._main_src()
        assert "enable.auto.commit" in src
        assert '"enable.auto.commit": False' in src

    def test_psycopg_connect_uses_autocommit_true(self):
        """psycopg.connect must receive autocommit=True so per-insert transactions work."""
        src = self._main_src()
        assert "autocommit=True" in src

    def test_subscribes_to_configured_topic(self):
        """Consumer must subscribe using config.TOPIC_SPANS (the trusted spans topic)."""
        src = self._main_src()
        assert "config.TOPIC_SPANS" in src
        assert "subscribe" in src
