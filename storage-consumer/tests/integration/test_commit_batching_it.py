"""
storage-consumer/tests/integration/test_commit_batching_it.py

Integration validation of the opt-in batched Kafka offset commits (consumer.OffsetBatcher and the
batched loop) against a REAL Kafka broker and a REAL PostgreSQL.

THESE TESTS NEVER RUN BY ACCIDENT.  Every test is skipped unless AGENTOPS_BATCHING_IT=1, and the
environment is validated before anything connects: only 127.0.0.1 on the disposable project's two
published ports (19092 for Kafka, 15432 for PostgreSQL) is accepted; 9092, 5432, 4317, 4318, 8000
and 3000 are refused.  They are started only by workload-generator/run_commit_batching_it.py,
which creates the disposable Compose project, passes the temporary credential and cleans up.
This module does not touch the older test_persistence_e2e.py, which targets the normal stack.

Each test records a result (results.json in AGENTOPS_IT_EVIDENCE_DIR):
    deterministic cases   PASS / FAIL / BLOCKED (a skip)
    timing-sensitive      OBSERVED / NOT_OBSERVED / INCONCLUSIVE, and FAIL on a safety violation
A timing-sensitive case that does not happen is NOT a failure; a deterministic case that was
skipped or did not run can never make the whole run pass.

Real-client behavior that the design could only assume (what commit() returns, whether it raises,
which callbacks close() fires) is RECORDED in each case's detail, so a difference from the
design shows up as evidence and as a failed assertion, not as a silent adaptation.

What drives the consumer in each case is recorded too (DRIVERS, and "driver" in each case's
detail).  The real OffsetBatcher, process_message, SpanRepository, Kafka client and PostgreSQL
are used everywhere; but only some cases run the real run_consumer_loop.  The others use
Member.step, a re-implementation of the batched loop body written for this module (so that
two members can be stepped by hand), and are therefore evidence about the batcher and the
client, not about the loop itself.

How an exception is classified (see classify_exception):
    safety violation   AssertionError, CommitFailed, the batcher's "offset batching state is
                       unsafe" error, a process that could not be verified stopped  -> FAIL
    infrastructure     a narrow allowlist: timeouts, refused or lost connections, a broker that
                       is not available, InfrastructureError / EnvironmentNotReady
                       -> INCONCLUSIVE in a timing case (never a PASS anywhere)
    anything else      FAIL
A safety exception in the chain of an infrastructure one still counts as a safety violation.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import pytest

DETERMINISTIC_CASES = (
    "C01_commit_response_shape", "C02_partial_failure", "C03_eager_rebalance",
    "C06_close_callbacks", "C07a_crash_replay", "C08_postgres_idempotency",
    "C09_n1_versus_n100", "C10_idle_and_time_flush", "C11_subscription_callbacks",
)
TIMING_CASES = (
    "C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart",
    "C12_sustained_main_n100",
)
TIMING_STATUSES = ("OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE")
PROHIBITED_PORTS = (9092, 5432, 4317, 4318, 8000, 3000)
ALLOWED_PORTS = (19092, 15432)
PROJECT_PREFIX = "agentops-batching-it-"

#: What drives the consumer under test in each case (recorded in the case's detail).
LOOP = "run_consumer_loop (real loop)"
STEP = "Member.step (re-implemented loop body)"
DRIVERS = {
    "C01_commit_response_shape": "raw Kafka consumer (no batcher, no loop)",
    "C02_partial_failure": "real OffsetBatcher fed by hand, real Kafka client (no loop)",
    "C03_eager_rebalance": STEP,
    "C04_cooperative_rebalance": STEP,
    "C05_lost_ownership": STEP,
    "C06_close_callbacks": LOOP,
    "C07a_crash_replay": f"phase 1: {STEP}; phase 2: {LOOP}",
    "C07b_forced_kill_restart": "storage-consumer/main.py as a real subprocess (real loop)",
    "C12_sustained_main_n100": "storage-consumer/main.py as a real subprocess (real loop), N=100, T=1.0 s, default assignor",
    "C08_postgres_idempotency": "real SpanRepository only (no loop)",
    "C09_n1_versus_n100": LOOP,
    "C10_idle_and_time_flush": LOOP,
    "C11_subscription_callbacks": STEP,
}

PROCESS_REPORT = "process-report.json"
_PROCESS_PROBLEMS: list[str] = []

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENTOPS_BATCHING_IT") != "1",
    reason="integration validation: only started by workload-generator/run_commit_batching_it.py "
           "(AGENTOPS_BATCHING_IT=1)")


# ---------------------------------------------------------------------------
# Endpoint rules (pure)
# ---------------------------------------------------------------------------

def validate_endpoint(host: Any, port: Any, allowed=ALLOWED_PORTS) -> tuple[str, int]:
    """127.0.0.1 on one of the disposable project's ports; anything else is refused."""
    if not isinstance(host, str) or host.strip() != "127.0.0.1":
        raise ValueError(f"endpoint host {host!r} is not 127.0.0.1")
    if isinstance(port, bool):
        raise ValueError(f"endpoint port {port!r} is not a number")
    try:
        number = int(str(port).strip())
    except ValueError:
        raise ValueError(f"endpoint port {port!r} is not a number") from None
    if number in PROHIBITED_PORTS:
        raise ValueError(f"endpoint port {number} is prohibited")
    if number not in allowed:
        raise ValueError(f"endpoint port {number} is not one of {list(allowed)}")
    return "127.0.0.1", number


def split_endpoint(value: str) -> tuple[str, str]:
    host, _, port = (value or "").rpartition(":")
    return host, port


# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

_RECORDS: list[dict[str, Any]] = []
_CURRENT: dict[str, Any] = {}


def note(key: str, value: Any) -> None:
    """Add an observation to the current case's detail."""
    _CURRENT.setdefault("detail", {})[key] = value


class InfrastructureError(Exception):
    """The environment (broker, database, network) did not do what a helper needed."""


class EnvironmentNotReady(Exception):
    """A timing precondition was not reached in time (a slow join, an assignment that never
    came).  Deliberately NOT an AssertionError: nothing unsafe was observed."""


class ProcessNotStopped(Exception):
    """A process this test started could not be verified stopped.  Always a failure."""


def require(condition: Any, message: str) -> None:
    """A precondition that depends on timing or on the environment, not on safety."""
    if not condition:
        raise EnvironmentNotReady(message)


_INFRASTRUCTURE_KAFKA_CODES = frozenset({
    "_TRANSPORT", "_ALL_BROKERS_DOWN", "_TIMED_OUT", "_TIMED_OUT_QUEUE", "_RESOLVE",
    "BROKER_NOT_AVAILABLE", "REQUEST_TIMED_OUT", "NETWORK_EXCEPTION", "COORDINATOR_NOT_AVAILABLE",
    "NOT_COORDINATOR", "COORDINATOR_LOAD_IN_PROGRESS"})


def _chain(exc: BaseException):
    seen, pending = set(), [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending.extend((current.__cause__, current.__context__))


def is_safety_violation(exc: BaseException) -> bool:
    """CommitFailed, the batcher's fatal-state error, an assertion (which includes the
    batcher's invariant check) or an unstopped process, anywhere in the exception chain."""
    for item in _chain(exc):
        if isinstance(item, (AssertionError, ProcessNotStopped)):
            return True
        if any(base.__name__ == "CommitFailed" for base in type(item).__mro__):
            return True
        if isinstance(item, RuntimeError) and "offset batching state is unsafe" in str(item):
            return True
    return False


def is_infrastructure_error(exc: BaseException) -> bool:
    """The narrow allowlist of environmental failures.  Only the exception itself is examined."""
    if isinstance(exc, (InfrastructureError, EnvironmentNotReady, TimeoutError, ConnectionError,
                        subprocess.TimeoutExpired)):
        return True
    module = type(exc).__module__ or ""
    if module.startswith("psycopg") and type(exc).__name__ in ("OperationalError", "InterfaceError"):
        return True
    if type(exc).__name__ == "KafkaException" and exc.args:
        name = getattr(exc.args[0], "name", None)
        try:
            return callable(name) and name() in _INFRASTRUCTURE_KAFKA_CODES
        except Exception:  # noqa: BLE001
            return False
    return False


def classify_exception(exc: BaseException) -> tuple[str, str]:
    """(status for a timing case, category).  Safety first; then the allowlist; the rest fails."""
    if is_safety_violation(exc):
        return "FAIL", "safety"
    if is_infrastructure_error(exc):
        return "INCONCLUSIVE", "infrastructure"
    return "FAIL", "unexpected"


def record_process_problems(problems: list[str]) -> None:
    """A process that could not be verified stopped: noted in the case, kept in a report file
    the orchestrator reads (it writes the blocking cleanup marker)."""
    if not problems:
        return
    _PROCESS_PROBLEMS.extend(problems)
    _CURRENT["process_problems"] = list(_CURRENT.get("process_problems", [])) + list(problems)
    note("process_problems", _CURRENT["process_problems"])
    directory = os.environ.get("AGENTOPS_IT_EVIDENCE_DIR")
    if directory and Path(directory).is_dir():
        try:
            Path(directory, PROCESS_REPORT).write_text(json.dumps(_PROCESS_PROBLEMS) + "\n", encoding="utf-8")
        except OSError:
            pass


def case(case_id: str):
    """Records PASS / FAIL / BLOCKED for a deterministic case, and OBSERVED / NOT_OBSERVED /
    INCONCLUSIVE (the function's return value) or FAIL for a timing case.  An exception in a
    timing case is INCONCLUSIVE only when classify_exception puts it on the infrastructure
    allowlist; a safety violation or anything unexpected is FAIL."""
    deterministic = case_id in DETERMINISTIC_CASES
    assert deterministic or case_id in TIMING_CASES, case_id

    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _CURRENT.clear()
            _CURRENT["detail"] = {}
            note("driver", DRIVERS[case_id])
            started = time.time()
            status = "FAIL"
            try:
                outcome = fn(*args, **kwargs)
                status = "PASS" if deterministic else (outcome if outcome in TIMING_STATUSES else "INCONCLUSIVE")
            except pytest.skip.Exception as skipped:
                status = "BLOCKED" if deterministic else "INCONCLUSIVE"
                note("skip", str(skipped))
                raise
            except AssertionError as failure:
                status = "FAIL"
                note("assertion", str(failure)[:600])
                note("error_category", "safety")
                raise
            except Exception as exc:  # noqa: BLE001
                note("error", f"{type(exc).__name__}: {exc}"[:600])
                timing_status, category = classify_exception(exc)
                note("error_category", category)
                if deterministic or timing_status == "FAIL":
                    status = "FAIL"
                    raise
                status = "INCONCLUSIVE"        # a timing precondition or the environment, not a violation
            finally:
                if _CURRENT.get("process_problems"):
                    status = "FAIL"              # an unverified process is never hidden by the case's own result
                _RECORDS.append({"case": case_id, "status": status, "seconds": round(time.time() - started, 2),
                                 "detail": dict(_CURRENT.get("detail", {}))})
                write_results()
        return wrapper
    return decorate


@pytest.fixture(scope="session", autouse=True)
def _write_results():
    yield
    write_results()


def write_results() -> None:
    """results.json in the evidence directory, with the temporary credential masked."""
    directory = os.environ.get("AGENTOPS_IT_EVIDENCE_DIR")
    if not directory or not Path(directory).is_dir():
        return
    secret = os.environ.get("AGENTOPS_IT_PG_PASSWORD", "")
    text = json.dumps(_RECORDS, indent=2, sort_keys=True, default=str)
    if secret:
        text = text.replace(secret, "<redacted>")
    Path(directory, "results.json").write_text(text + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Terminating the one subprocess this test started (and its descendants), verified
# ---------------------------------------------------------------------------

_MIN_TARGET_PID = 5


def _children_of(pid: int, run=subprocess.run) -> set[int]:
    """Descendants of `pid` by parent-process id; never by command line."""
    if os.name == "nt":
        result = run(["powershell", "-NoProfile", "-Command",
                      "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId)\" }"],
                     capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    else:
        result = run(["ps", "-eo", "pid=,ppid="], capture_output=True, text=True, timeout=60,
                     stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise OSError(f"the process table could not be read (exit {result.returncode})")
    parent_of: dict[int, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(f.isdigit() for f in fields):
            parent_of[int(fields[0])] = int(fields[1])
    found: set[int] = set()
    frontier = {pid}
    while frontier:
        frontier = {c for c, p in parent_of.items() if p in frontier and c not in found and c != pid}
        found |= frontier
    return found


def _pid_alive(pid: int, run=subprocess.run) -> bool:
    if os.name == "nt":
        result = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                     timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            raise OSError(f"tasklist failed (exit {result.returncode})")
        return f'"{pid}"' in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _posix_kill(pid: int) -> None:
    import signal
    os.kill(pid, signal.SIGKILL)


def terminate_tree(process, *, run=subprocess.run, children=_children_of, alive=_pid_alive, kill_pid=None,
                   windows=None, grace: float = 15.0, sleep=time.sleep) -> list[str]:
    """Stops the exact process this test started plus its descendants, and verifies it.

    On Windows the interpreter of a virtual environment is a launcher whose child is the real
    interpreter, so Popen.kill() would leave the real consumer running: `taskkill /PID <pid> /T /F`
    on that one PID is used instead.  Returns the problems; an empty list means every PID
    (the process and the descendants found before the kill) is verified gone."""
    pid = getattr(process, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < _MIN_TARGET_PID or pid == os.getpid():
        raise ProcessNotStopped(f"refusing to terminate process id {pid!r}")
    windows = (os.name == "nt") if windows is None else windows
    problems: list[str] = []
    try:
        targets = set(children(pid))
    except Exception as exc:  # noqa: BLE001
        targets = set()
        problems.append(f"descendants of pid {pid} could not be listed: {type(exc).__name__}")
    targets.discard(os.getpid())
    # A process this test already reaped may have had its PID reused: the root PID is then never
    # signalled; only the descendants found through it are.
    running = process.poll() is None
    if windows:
        for root in ([pid] if running else sorted(targets)):
            try:
                run(["taskkill", "/PID", str(root), "/T", "/F"], capture_output=True, timeout=30,
                    stdin=subprocess.DEVNULL)
            except Exception as exc:  # noqa: BLE001
                problems.append(f"taskkill for pid {root} failed: {type(exc).__name__}")
    else:
        for target in sorted(targets):
            try:
                (kill_pid or _posix_kill)(target)
            except OSError:
                pass
        if running:
            try:
                process.kill()
            except OSError:
                pass
    if running:
        try:
            process.wait(timeout=grace)
        except Exception:  # noqa: BLE001
            try:
                process.kill()
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
    for target in sorted(targets | ({pid} if running else set())):
        gone = False
        for _ in range(10):
            try:
                if not alive(target):
                    gone = True
                    break
            except Exception as exc:  # noqa: BLE001
                problems.append(f"pid {target} could not be checked: {type(exc).__name__}")
                gone = None
                break
            sleep(0.5)
        if gone is False:
            problems.append(f"pid {target} is still running")
    if running and process.poll() is None and not any(f"pid {pid} " in p for p in problems):
        problems.append(f"pid {pid} is still running")
    return problems


def sanitize_file(path: Path, secret: str) -> None:
    """Masks the temporary credential in a raw log written by a subprocess."""
    if not secret or not Path(path).is_file():
        return
    data = Path(path).read_bytes()
    cleaned = data.replace(secret.encode("utf-8"), b"<redacted>")
    if cleaned != data:
        Path(path).write_bytes(cleaned)


# ---------------------------------------------------------------------------
# Environment and helpers (real services are imported lazily, never at module import)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def env():
    if os.environ.get("AGENTOPS_BATCHING_IT") != "1":
        pytest.skip("AGENTOPS_BATCHING_IT is not 1")
    project = os.environ.get("AGENTOPS_IT_PROJECT", "")
    if not project.startswith(PROJECT_PREFIX):
        pytest.fail(f"AGENTOPS_IT_PROJECT {project!r} is not a disposable batching project", pytrace=False)
    try:
        khost, kport = validate_endpoint(*split_endpoint(os.environ.get("AGENTOPS_IT_KAFKA", "")))
        phost, pport = validate_endpoint(os.environ.get("AGENTOPS_IT_PG_HOST", ""),
                                         os.environ.get("AGENTOPS_IT_PG_PORT", ""))
    except ValueError as refused:
        pytest.fail(f"endpoint refused: {refused}", pytrace=False)
    if (khost, kport) == (phost, pport) or kport != 19092 or pport != 15432:
        pytest.fail("the Kafka and PostgreSQL endpoints must be 127.0.0.1:19092 and 127.0.0.1:15432", pytrace=False)
    password = os.environ.get("AGENTOPS_IT_PG_PASSWORD", "")
    if not password:
        pytest.fail("no temporary PostgreSQL credential was given", pytrace=False)
    evidence = os.environ.get("AGENTOPS_IT_EVIDENCE_DIR", "")
    if not evidence or not Path(evidence).is_dir():
        pytest.fail("AGENTOPS_IT_EVIDENCE_DIR is missing", pytrace=False)
    repo = Path(os.environ.get("AGENTOPS_IT_REPO", ""))
    if not (repo / "storage-consumer" / "main.py").is_file():
        pytest.fail("AGENTOPS_IT_REPO does not name the repository", pytrace=False)
    return SimpleNamespace(
        project=project, run_id=os.environ.get("AGENTOPS_IT_RUN_ID", ""), kafka=f"{khost}:{kport}",
        pg_host=phost, pg_port=pport, pg_database=os.environ.get("AGENTOPS_IT_PG_DATABASE", "agentops"),
        pg_user=os.environ.get("AGENTOPS_IT_PG_USER", "agentops"), pg_password=password,
        evidence=Path(evidence), repo=repo, python=os.environ.get("AGENTOPS_IT_PYTHON", sys.executable))


def kafka():
    import confluent_kafka
    return confluent_kafka


def mods():
    """The code under test, imported lazily (it needs PYTHONPATH to hold storage-consumer and demo-app)."""
    import consumer as consumer_module
    import repository as repository_module
    return SimpleNamespace(
        process_message=consumer_module.process_message, run_consumer_loop=consumer_module.run_consumer_loop,
        OffsetBatcher=consumer_module.OffsetBatcher, CommitFailed=consumer_module.CommitFailed,
        SpanRepository=repository_module.SpanRepository)


def base_conf(env, group, **extra):
    conf = {"bootstrap.servers": env.kafka, "group.id": group, "auto.offset.reset": "earliest",
            "enable.auto.commit": False, "broker.address.family": "v4"}
    conf.update(extra)
    return conf


def connect_pg(env):
    import psycopg
    return psycopg.connect(host=env.pg_host, port=env.pg_port, dbname=env.pg_database,
                           user=env.pg_user, password=env.pg_password, autocommit=True, connect_timeout=10)


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def make_topic(env, partitions: int) -> str:
    from confluent_kafka.admin import AdminClient, NewTopic
    name = unique("it-batching")
    admin = AdminClient({"bootstrap.servers": env.kafka, "broker.address.family": "v4"})
    for future in admin.create_topics([NewTopic(name, num_partitions=partitions, replication_factor=1)]).values():
        future.result(timeout=30)
    deadline = time.time() + 30
    while time.time() < deadline:
        metadata = admin.list_topics(name, timeout=10)
        if name in metadata.topics and len(metadata.topics[name].partitions) == partitions:
            return name
        time.sleep(0.5)
    raise InfrastructureError(f"topic {name} did not appear")


def span_bytes(tag: str, index: int) -> bytes:
    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc).isoformat()
    return json.dumps({"trace_id": tag, "span_id": f"{index:016x}", "span_name": "it.op",
                       "span_kind": "INTERNAL", "service_name": "batching-it", "start_time": now,
                       "end_time": now, "duration_ms": 0.0, "status_code": "OK"}).encode("utf-8")


def produce(env, topic: str, counts: dict[int, int], tag: str, start: int = 0) -> dict[int, list[int]]:
    """Produce counts[p] messages to each partition p; returns the delivered offsets per partition."""
    delivered: dict[int, list[int]] = {p: [] for p in counts}
    errors: list[str] = []

    def on_delivery(err, msg):
        if err is not None:
            errors.append(str(err))
        else:
            delivered[msg.partition()].append(msg.offset())

    producer = kafka().Producer({"bootstrap.servers": env.kafka, "broker.address.family": "v4",
                                 "message.timeout.ms": 20000})
    index = start
    for partition, count in counts.items():
        for _ in range(count):
            producer.produce(topic, value=span_bytes(tag, index), partition=partition, on_delivery=on_delivery)
            index += 1
    if producer.flush(30) != 0 or errors:
        raise InfrastructureError(f"produce failed: {errors[:3]}")
    return {p: sorted(v) for p, v in delivered.items()}


def tag_for(topic: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, topic).hex            # 32 hex characters, unique per topic


#: C12: what the production entry point is run with, and the load it is given.
SUSTAINED_BATCH = "100"
SUSTAINED_INTERVAL = "1.0"
SUSTAINED_RATE = 70
SUSTAINED_SECONDS = 30
SUSTAINED_MARKER_PER_PARTITION = 10


def paced_produce(producer, topic: str, tag: str, *, rate: float, seconds: float, partitions: int = 3,
                  start_index: int = 0, stop=None, clock=time.monotonic, sleep=time.sleep) -> dict[str, Any]:
    """Produces about rate x seconds messages at a steady pace, round-robin over the partitions, with
    ONE producer, and reports what really happened: the count sent, the elapsed time, the observed
    rate (never assumed to equal the target), delivery errors and the delivered offsets."""
    total = int(rate * seconds)
    delivered: dict[int, list[int]] = {p: [] for p in range(partitions)}
    errors: list[str] = []

    def on_delivery(err, msg):
        if err is not None:
            errors.append(str(err))
        else:
            delivered[msg.partition()].append(msg.offset())

    began, sent = clock(), 0
    for index in range(total):
        if stop is not None and stop.is_set():
            break
        wait = began + index / rate - clock()
        if wait > 0:
            sleep(wait)
        producer.produce(topic, value=span_bytes(tag, start_index + index), partition=index % partitions,
                         on_delivery=on_delivery)
        producer.poll(0)
        sent += 1
    elapsed = clock() - began
    remaining = producer.flush(30)
    return {"target_rate": rate, "target_seconds": seconds, "sent": sent, "elapsed_s": round(elapsed, 3),
            "observed_rate": round(sent / elapsed, 2) if elapsed > 0 else 0.0,
            "delivered": sum(len(v) for v in delivered.values()), "errors": errors[:5],
            "flush_remaining": remaining, "offsets": {p: sorted(v) for p, v in delivered.items()}}


def expected_end_from_offsets(offsets: dict[int, list[int]]) -> dict[int, int]:
    """The end offset implied by the offsets this test itself produced (the topic is new, so these
    are the only records): per partition, the highest delivered offset + 1."""
    return {p: max(v) + 1 for p, v in offsets.items() if v}


def reconciliation_problems(held: dict, expected_end: dict[int, int], process_alive: bool) -> list[str]:
    """Offsets must equal the end of the records produced for this case, and the consumer must still
    have been running when that was checked (reconciliation before termination)."""
    problems = []
    if not process_alive:
        problems.append("the consumer was not running when the offsets were reconciled")
    for partition in sorted(expected_end):
        if held.get(partition) != expected_end[partition]:
            problems.append(f"partition {partition}: committed {held.get(partition)}, expected {expected_end[partition]}")
    return problems


def persistence_problems(pairs, rows: int, distinct: int, expected_end: dict[int, int], expected_total: int) -> list[str]:
    """Missing, duplicate or non-contiguous persisted records."""
    problems = list(contiguity_problems(pairs, expected_end))
    if rows != expected_total:
        problems.append(f"{rows} rows persisted, {expected_total} expected")
    if distinct != rows:
        problems.append(f"{rows - distinct} duplicate logical span(s)")
    if len(pairs) != rows:
        problems.append(f"{len(pairs)} partition/offset pairs for {rows} rows")
    return problems


def main_consumer_environment(env, topic: str, group: str, *, batch, interval, timing, source=None) -> dict[str, str]:
    """The explicit environment of the production entry point (main.py): a few system variables, the
    disposable endpoints and the batching settings.  No partition assignment strategy is set; the
    client default applies, exactly as in production."""
    source = os.environ if source is None else source
    values = {key: source[key] for key in ("SYSTEMROOT", "PATH", "TEMP", "TMP") if key in source}
    values.update({
        "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join([str(env.repo / "storage-consumer"), str(env.repo / "demo-app")]),
        "KAFKA_BOOTSTRAP_SERVERS": env.kafka, "TOPIC_SPANS": topic, "CONSUMER_GROUP_ID": group,
        "CONSUMER_AUTO_OFFSET_RESET": "earliest", "PG_HOST": env.pg_host, "PG_PORT": str(env.pg_port),
        "PG_DATABASE": env.pg_database, "PG_USER": env.pg_user, "PG_PASSWORD": env.pg_password,
        "CONSUMER_COMMIT_BATCH_MESSAGES": str(batch), "CONSUMER_COMMIT_INTERVAL_SECONDS": str(interval),
        "CONSUMER_TIMING_INTERVAL_SECONDS": str(timing)})
    return values


def start_main_consumer(env, topic: str, group: str, log_name: str, *, batch, interval, timing):
    """Starts storage-consumer/main.py (the production entry point) as a subprocess; returns it with
    its open log.  The caller terminates it with terminate_tree and masks the log."""
    process_env = main_consumer_environment(env, topic, group, batch=batch, interval=interval, timing=timing)
    log = open(env.evidence / log_name, "w", encoding="utf-8")
    process = subprocess.Popen([env.python, "-B", str(env.repo / "storage-consumer" / "main.py")],
                               cwd=str(env.repo / "storage-consumer"), env=process_env,
                               stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    return process, log


def committed(env, group: str, topic: str, partitions) -> dict[int, Optional[int]]:
    """Offsets the broker holds for the group (None = nothing committed)."""
    K = kafka()
    reader = K.Consumer(base_conf(env, group))
    try:
        result = reader.committed([K.TopicPartition(topic, p) for p in partitions], timeout=20)
        return {tp.partition: (tp.offset if tp.offset >= 0 else None) for tp in result}
    finally:
        reader.close()


def end_offsets(env, topic: str, partitions) -> dict[int, int]:
    K = kafka()
    reader = K.Consumer(base_conf(env, unique("it-reader")))
    try:
        return {p: reader.get_watermark_offsets(K.TopicPartition(topic, p), timeout=20)[1] for p in partitions}
    finally:
        reader.close()


def count_rows(conn, tag: str) -> tuple[int, int]:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), count(DISTINCT (trace_id, span_id)) FROM telemetry_spans WHERE trace_id = %s", (tag,))
        row = cur.fetchone()
    return int(row[0]), int(row[1])


def delete_rows(conn, tag: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM telemetry_spans WHERE trace_id = %s", (tag,))


def persisted_pairs(conn, tag: str) -> list[tuple[int, int]]:
    """(kafka_partition, kafka_offset) of every row stored for this test's trace id."""
    with conn.cursor() as cur:
        cur.execute("SELECT kafka_partition, kafka_offset FROM telemetry_spans WHERE trace_id = %s "
                    "ORDER BY 1, 2", (tag,))
        return [(int(p), int(o)) for p, o in cur.fetchall()]


def expected_replays(pairs, committed_offsets) -> dict[int, int]:
    """How many persisted rows a restarted consumer will be given again: per partition, the rows
    whose offset is at or beyond the committed offset (the next offset to read; none = 0)."""
    partitions = {p for p, _ in pairs} | set(committed_offsets)
    return {p: sum(1 for q, o in pairs if q == p and o >= (committed_offsets.get(p) or 0))
            for p in sorted(partitions)}


def contiguity_problems(pairs, end=None) -> list[str]:
    """Persisted offsets must be exactly 0..n-1 per partition (n = end offset when given): a gap
    is a lost message, a repeat is a duplicate."""
    by_partition: dict[int, list[int]] = {}
    for partition, offset in pairs:
        by_partition.setdefault(partition, []).append(offset)
    problems = []
    for partition in sorted(set(by_partition) | set(end or {})):
        offsets = sorted(by_partition.get(partition, []))
        wanted = set(range(len(offsets) if end is None else end[partition]))
        missing, extra = sorted(wanted - set(offsets)), sorted(set(offsets) - wanted)
        duplicates = len(offsets) - len(set(offsets))
        if missing or extra or duplicates:
            problems.append(f"partition {partition}: missing {missing[:5]}, unexpected {extra[:5]}, "
                            f"{duplicates} duplicate(s)")
    return problems


def parse_timing_counters(text: str) -> dict[str, int]:
    """Sums the counters of the consumer's periodic timing windows.  Call it only on the log of a
    process that has been stopped, so that no window is still waiting to be printed."""
    totals = {"windows": 0, "messages": 0, "inserted": 0, "conflicts": 0}
    for line in text.splitlines():
        if not line.startswith("storage-consumer timing "):
            continue
        try:
            record = json.loads(line[len("storage-consumer timing "):])
        except ValueError:
            continue
        if record.get("kind") != "window":
            continue
        totals["windows"] += 1
        for name in ("messages", "inserted", "conflicts"):
            totals[name] += int(record.get("counters", {}).get(name, 0))
    return totals


def verify_replay(expected_conflicts: int, expected_messages: int, totals) -> tuple[str, list[str]]:
    """OK / INCOMPLETE (the log does not hold every message, so nothing can be concluded) /
    MISMATCH (a safety problem: the replay was not absorbed as conflicts)."""
    if totals["messages"] != expected_messages:
        return "INCOMPLETE", [f"the log counts {totals['messages']} messages, {expected_messages} were redelivered"]
    problems = []
    if totals["conflicts"] != expected_conflicts:
        problems.append(f"{totals['conflicts']} conflicts counted, {expected_conflicts} persisted-but-uncommitted "
                        f"rows were expected to be redelivered")
    if totals["inserted"] + totals["conflicts"] != totals["messages"]:
        problems.append("inserted + conflicts differs from messages")
    return ("OK" if not problems else "MISMATCH"), problems


class RecordingRepo:
    """A stand-in repository with the REAL insert_span signature (event, topic, partition, offset):
    the consumer calls it by keyword.  It writes through to a real SpanRepository and records every
    result; on_insert(count, result) may stop the loop after a number of messages."""

    def __init__(self, real, on_insert=None):
        self.real, self.on_insert, self.results = real, on_insert, []

    def insert_span(self, event, topic, partition, offset):
        fresh = self.real.insert_span(event, topic=topic, partition=partition, offset=offset)
        self.results.append(fresh)
        if self.on_insert is not None:
            self.on_insert(len(self.results), fresh)
        return fresh


class FakePersistedMessage:
    """A stand-in for a message that was persisted, used only to feed the batcher's bookkeeping."""

    def __init__(self, topic, partition, offset):
        self._t, self._p, self._o = topic, partition, offset

    def topic(self):
        return self._t

    def partition(self):
        return self._p

    def offset(self):
        return self._o


class SpyConsumer:
    """Stands in for the Kafka consumer that BOTH the OffsetBatcher and the loop use, forwards
    everything to the real one and records, in order: every commit (argument form, offsets sent,
    whether the batcher was closing, whether shutdown had been requested, whether the previous poll
    returned nothing, and the error if it raised) and the close() call.

    Build it first, then give it to the batcher and to the loop; set `.batcher` afterwards:
        spy = SpyConsumer(consumer, shutdown); batcher = OffsetBatcher(spy, ...); spy.batcher = batcher
    A batcher built on the raw consumer would be invisible to it."""

    def __init__(self, real, shutdown=None):
        self._real, self.shutdown, self.batcher = real, shutdown, None
        self.events: list[dict] = []
        self._last_poll_empty = False

    @property
    def commits(self) -> list[dict]:
        return [e for e in self.events if e["kind"] == "commit"]

    def poll(self, *args, **kwargs):
        message = self._real.poll(*args, **kwargs)
        self._last_poll_empty = message is None
        return message

    def commit(self, *args, **kwargs):
        if "offsets" in kwargs:
            sent = [(tp.partition, tp.offset) for tp in kwargs["offsets"]]
        elif "message" in kwargs:
            sent = [(kwargs["message"].partition(), kwargs["message"].offset() + 1)]
        else:
            sent = []
        event = {"kind": "commit", "seq": len(self.events), "t": round(time.time(), 3),
                 "keywords": sorted(kwargs), "offsets": sent,
                 "closing": bool(self.batcher is not None and self.batcher.closing),
                 "shutdown": bool(self.shutdown is not None and self.shutdown.is_set()),
                 "after_empty_poll": self._last_poll_empty}
        self.events.append(event)
        try:
            return self._real.commit(*args, **kwargs)
        except BaseException as exc:
            event["error"] = f"{type(exc).__name__}: {exc}"[:240]
            raise

    def close(self, *args, **kwargs):
        self.events.append({"kind": "close", "seq": len(self.events), "t": round(time.time(), 3)})
        return self._real.close(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


def classify_flushes(events) -> dict[str, list[int]]:
    """Sorts the observed commits (by sequence number) into
        during_close  made after closing began, or after close() was called
        shutdown      made after shutdown was requested (the final flush)
        idle          made while active, right after a poll that returned nothing
        interval      made while active, after a message (by age or by batch size)
    so that an interval flush can never be mistaken for the final flush at shutdown."""
    closes = [e["seq"] for e in events if e.get("kind") == "close"]
    first_close = min(closes) if closes else None
    out: dict[str, list[int]] = {"during_close": [], "shutdown": [], "idle": [], "interval": []}
    for e in events:
        if e.get("kind") != "commit":
            continue
        if e.get("closing") or (first_close is not None and e["seq"] > first_close):
            out["during_close"].append(e["seq"])
        elif e.get("shutdown"):
            out["shutdown"].append(e["seq"])
        elif e.get("after_empty_poll"):
            out["idle"].append(e["seq"])
        else:
            out["interval"].append(e["seq"])
    return out


def verify_close_ordering(events, keywords=("asynchronous", "offsets")) -> list[str]:
    """C06: problems, empty only if commits were really observed, all use the expected form, the
    last one precedes close(), and none was made once closing began.  Zero commits is a problem."""
    commits = [e for e in events if e.get("kind") == "commit"]
    closes = [e for e in events if e.get("kind") == "close"]
    problems = []
    if not commits:
        problems.append("no commit was observed: the check would be vacuous")
    if len(closes) != 1:
        problems.append(f"expected exactly one close(), saw {len(closes)}")
    if classify_flushes(events)["during_close"]:
        problems.append(f"commit(s) made after closing began: {classify_flushes(events)['during_close']}")
    if commits and closes and commits[-1]["seq"] > closes[0]["seq"]:
        problems.append("the final commit does not precede close()")
    for e in commits:
        if e["keywords"] != sorted(keywords):
            problems.append(f"commit #{e['seq']} used {e['keywords']}, expected {sorted(keywords)}")
    return problems


def verify_interval_run(events, minimum: int = 2) -> list[str]:
    """C10 (steady traffic): at least `minimum` flushes made while the consumer was active and
    not idle, and none after closing began.  Shutdown flushes do not count."""
    flush = classify_flushes(events)
    problems = []
    if len(flush["interval"]) < minimum:
        problems.append(f"{len(flush['interval'])} interval flush(es) before shutdown, {minimum} required "
                        f"(idle {len(flush['idle'])}, shutdown {len(flush['shutdown'])})")
    if flush["during_close"]:
        problems.append(f"commit(s) made after closing began: {flush['during_close']}")
    return problems


class Member:
    """One consumer of a group with its own batcher and repository, driven one step at a time.

    step() is a RE-IMPLEMENTATION of the body of consumer._run_batched_loop (poll, check_fatal,
    idle flush, process_message, record, flush_if_due), kept in this module so that two members
    can be stepped by hand.  It uses the real OffsetBatcher, process_message, SpanRepository and
    the real Kafka client, but NOT run_consumer_loop: cases driven by it (see DRIVERS) are
    evidence about the batcher and the client, and must not be read as evidence about the loop."""

    def __init__(self, env, topic, group, *, n=1000, t=30.0, strategy=None, extra=None, batching=True):
        K, m = kafka(), mods()
        conf = base_conf(env, group, **(extra or {}))
        if strategy:
            conf["partition.assignment.strategy"] = strategy
        self.events: list[tuple] = []
        self.topic, self.persisted, self.conflicts = topic, 0, 0
        self.consumer = K.Consumer(conf)
        self.conn = connect_pg(env)
        self.repo = m.SpanRepository(self.conn)
        self.m = m
        self.timeline: list[dict] = []
        self.spy = SpyConsumer(self.consumer) if batching else None
        self.batcher = m.OffsetBatcher(self.spy, n, t, log=lambda text: self.events.append(("log", text))) if batching else None
        if self.batcher is None:
            self.consumer.subscribe([topic])
            return
        self.spy.batcher = self.batcher

        def on_assign(consumer, partitions):
            self.events.append(("assign", sorted(p.partition for p in partitions)))
            self.mark("assign", partitions=sorted(p.partition for p in partitions))
            self.batcher.on_assign(consumer, partitions)

        def on_revoke(consumer, partitions):
            self.events.append(("revoke", sorted(p.partition for p in partitions), self.batcher.pending_offsets()))
            self.mark("revoke", partitions=sorted(p.partition for p in partitions),
                      pending={f"{k[1]}": v for k, v in self.batcher.pending_offsets().items()})
            self.batcher.on_revoke(consumer, partitions)

        def on_lost(consumer, partitions):
            self.events.append(("lost", sorted(p.partition for p in partitions), self.batcher.pending_offsets()))
            self.mark("lost", partitions=sorted(p.partition for p in partitions),
                      pending={f"{k[1]}": v for k, v in self.batcher.pending_offsets().items()})
            self.batcher.on_lost(consumer, partitions)

        self.consumer.subscribe([topic], on_assign=on_assign, on_revoke=on_revoke, on_lost=on_lost)

    def mark(self, kind, **info):
        """A timestamped diagnostic event (callbacks, resume points); survives a failing case."""
        self.timeline.append({"t": round(time.time(), 3), "event": kind, **info})

    def step(self, timeout=0.5, idle_flush=True):
        msg = (self.spy or self.consumer).poll(timeout)
        self.batcher.check_fatal()
        if msg is None:
            if idle_flush:
                self.batcher.flush_pending()
            return None
        if msg.error() is not None:
            self.events.append(("error", str(msg.error())))
            return None
        self.m.process_message(msg, self.repo)
        self.batcher.record(msg)
        self.batcher.flush_if_due()
        self.persisted += 1
        return msg

    def assignment(self):
        return sorted(tp.partition for tp in self.consumer.assignment())

    def owned(self):
        return sorted(p for (_, p) in self.batcher.owned)

    def close(self, *, flush=True):
        try:
            if self.batcher is not None:
                if flush:
                    self.batcher.finish()
                self.batcher.closing = True
            self.consumer.close()
        finally:
            self.conn.close()


def snapshot_member(member) -> dict:
    """What a Member did, for the case's detail: callbacks, every commit attempt with its outcome,
    the batcher's state.  Never raises."""
    info: dict[str, Any] = {"timeline": list(member.timeline)}
    try:
        info["commit_attempts"] = [
            {k: e[k] for k in ("t", "offsets", "keywords", "closing", "after_empty_poll", "error") if k in e}
            for e in (member.spy.commits if member.spy is not None else [])]
        batcher = member.batcher
        if batcher is not None:
            info["batcher"] = {"owned": sorted(p for (_, p) in batcher.owned), "commit_failed": bool(batcher.commit_failed),
                               "fatal": repr(batcher.fatal) if batcher.fatal is not None else None,
                               "pending": {str(k[1]): v for k, v in batcher.pending_offsets().items()}}
    except Exception as exc:  # noqa: BLE001
        info["snapshot_error"] = f"{type(exc).__name__}: {exc}"[:200]
    try:
        info["assignment"] = member.assignment()
    except Exception as exc:  # noqa: BLE001
        info["assignment_error"] = f"{type(exc).__name__}"
    return info


def run_until(predicate, members, timeout, step=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for member in members:
            member.step(step)
        if predicate():
            return True
    return False


# ---------------------------------------------------------------------------
# C01  commit response semantics
# ---------------------------------------------------------------------------

@case("C01_commit_response_shape")
def test_c01_synchronous_commit_response(env):
    K = kafka()
    topic = make_topic(env, 3)
    produce(env, topic, {0: 5, 1: 5, 2: 5}, tag_for(topic))
    group = unique("it-c01")
    consumer = K.Consumer(base_conf(env, group))
    try:
        consumer.subscribe([topic])
        highest: dict[int, int] = {}
        deadline = time.time() + 40
        seen = 0
        while seen < 15 and time.time() < deadline:
            msg = consumer.poll(0.5)
            if msg is not None and msg.error() is None:
                seen += 1
                highest[msg.partition()] = max(highest.get(msg.partition(), -1), msg.offset())
        assert seen == 15, f"only {seen} of 15 messages arrived"
        sent = {p: highest[p] + 1 for p in highest}
        result = consumer.commit(offsets=[K.TopicPartition(topic, p, o) for p, o in sent.items()], asynchronous=False)
    finally:
        consumer.close()
    note("result_type", type(result).__name__)
    note("items", [{"partition": tp.partition, "offset": tp.offset, "error": str(getattr(tp, "error", "n/a")),
                    "has_err_attribute": hasattr(tp, "err")} for tp in (result or [])])
    assert isinstance(result, (list, tuple)) and len(result) == 3
    for tp in result:
        assert tp.topic == topic and getattr(tp, "error", "missing") is None
        assert tp.offset == sent[tp.partition], "the returned offset differs from the offset sent"
    assert committed(env, group, topic, [0, 1, 2]) == sent


# ---------------------------------------------------------------------------
# C02  partial failure and exceptions, produced for real
# ---------------------------------------------------------------------------

@case("C02_partial_failure")
def test_c02_commit_for_unknown_partitions(env):
    K, m = kafka(), mods()
    topic = make_topic(env, 1)
    produce(env, topic, {0: 3}, tag_for(topic))
    bogus_topic = unique("it-no-such-topic")
    group = unique("it-c02")
    consumer = K.Consumer(base_conf(env, group))
    try:
        consumer.subscribe([topic])
        seen = 0
        deadline = time.time() + 40
        while seen < 3 and time.time() < deadline:
            msg = consumer.poll(0.5)
            if msg is not None and msg.error() is None:
                seen += 1
        assert seen == 3
        batcher = m.OffsetBatcher(consumer, 100, 60.0, log=lambda text: None)
        batcher.on_assign(consumer, [K.TopicPartition(topic, 0), K.TopicPartition(topic, 99),
                                     K.TopicPartition(bogus_topic, 0)])
        batcher.record(FakePersistedMessage(topic, 0, 2))
        batcher.record(FakePersistedMessage(topic, 99, 4))
        batcher.record(FakePersistedMessage(bogus_topic, 0, 4))
        raised = None
        try:
            batcher.flush()
        except m.CommitFailed as failure:
            raised = repr(failure)
        note("flush_raised", raised)
        pending = batcher.pending_offsets()
        note("pending_after", {f"{t}:{p}": o for (t, p), o in pending.items()})
        assert raised is not None, "committing partitions that do not exist must not look like success"
        assert batcher.commit_failed is True
        batcher.check_invariants()
        broker = committed(env, group, topic, [0])
        note("broker_committed_partition_0", broker[0])
        # the batcher may drop a partition from `pending` only if the broker really holds its offset
        if (topic, 0) not in pending:
            assert broker[0] == 3, "the batcher acknowledged partition 0 but the broker does not hold it"
        for key in ((topic, 99), (bogus_topic, 0)):
            assert key in pending, f"{key} was acknowledged although it does not exist"
        batcher.closing = True
    finally:
        consumer.close()


# ---------------------------------------------------------------------------
# C03 / C04  rebalance (eager and cooperative)
# ---------------------------------------------------------------------------

def rebalance_scenario(env, strategy):
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    produce(env, topic, {0: 6, 1: 6, 2: 6}, tag)
    group = unique("it-reb")
    first = Member(env, topic, group, n=1000, t=60.0, strategy=strategy)
    second = None
    facts: dict[str, Any] = {}
    try:
        require(run_until(lambda: len(first.assignment()) == 3, [first], 40), "the first member never got 3 partitions")
        require(run_until(lambda: first.persisted >= 12, [first], 40), "the first member did not persist 12 messages")
        pending_before = first.batcher.pending_offsets()
        facts["pending_before_join"] = {f"{t}:{p}": o for (t, p), o in pending_before.items()}
        require(pending_before, "no pending offsets before the second member joined")
        second = Member(env, topic, group, n=1000, t=60.0, strategy=strategy)
        # Let the second member's join request reach the broker while the first member is not
        # polling, so that the first member's pending offsets are still pending when its revoke
        # callback runs (an idle poll would otherwise flush them first).
        for _ in range(12):
            second.consumer.poll(0.5)
        settled = run_until(lambda: first.assignment() and second.assignment()
                            and len(set(first.assignment()) | set(second.assignment())) == 3
                            and not set(first.assignment()) & set(second.assignment())
                            and first.owned() == first.assignment() and second.owned() == second.assignment(),
                            [first, second], 60)
        facts["first_events"] = [list(e[:2]) + ([{f"{t}:{p}": o for (t, p), o in e[2].items()}] if len(e) > 2 else [])
                                 for e in first.events if e[0] in ("assign", "revoke", "lost")]
        facts["second_events"] = [list(e[:2]) for e in second.events if e[0] in ("assign", "revoke", "lost")]
        facts["first_assignment"], facts["second_assignment"] = first.assignment(), second.assignment()
        facts["settled"] = settled
        # safety, whatever the assignor did
        assert first.batcher.fatal is None and second.batcher.fatal is None
        first.batcher.check_invariants()
        second.batcher.check_invariants()
        assert first.owned() == first.assignment() and second.owned() == second.assignment()
        assert not set(first.owned()) & set(second.owned())
        revokes = [e for e in first.events if e[0] == "revoke"]
        facts["revoke_count"] = len(revokes)
        if revokes:
            end = end_offsets(env, topic, [0, 1, 2])
            held = committed(env, group, topic, [0, 1, 2])
            for _, parts, snapshot in revokes:
                for (_, partition), offset in snapshot.items():
                    if partition in parts:
                        assert held[partition] is not None and held[partition] >= offset, (
                            f"partition {partition}: pending offset {offset} was not committed on revoke "
                            f"(broker holds {held[partition]})")
                        assert held[partition] <= end[partition]
        return settled, facts, first, second
    finally:
        # recorded even when the case raises (CommitFailed, an assertion, ...): the wrapper keeps the detail
        note("diagnostics_first", snapshot_member(first))
        if second is not None:
            note("diagnostics_second", snapshot_member(second))
        for member in (second, first):
            if member is not None:
                try:
                    member.close()
                except Exception:  # noqa: BLE001
                    pass


@case("C03_eager_rebalance")
def test_c03_eager_rebalance(env):
    settled, facts, _, _ = rebalance_scenario(env, None)
    for key, value in facts.items():
        note(key, value)
    assert settled, "the group did not settle on a disjoint assignment of all 3 partitions"
    assert facts["revoke_count"] >= 1, "no revoke callback fired for the first member"


@case("C04_cooperative_rebalance")
def test_c04_cooperative_rebalance(env):
    settled, facts, first, _ = rebalance_scenario(env, "cooperative-sticky")
    for key, value in facts.items():
        note(key, value)
    revoked = {p for e in first.events if e[0] == "revoke" for p in e[1]}
    retained = set(facts["first_assignment"])
    note("retained_without_revoke", sorted(retained - revoked))
    if not settled:
        return "INCONCLUSIVE"
    return "OBSERVED" if (retained - revoked) and revoked else "NOT_OBSERVED"


# ---------------------------------------------------------------------------
# C05  lost ownership (timing-sensitive)
# ---------------------------------------------------------------------------

@case("C05_lost_ownership")
def test_c05_lost_ownership(env):
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    produce(env, topic, {0: 4, 1: 4, 2: 4}, tag)
    group = unique("it-lost")
    stalled = Member(env, topic, group, n=1000, t=60.0,
                     extra={"session.timeout.ms": 6000, "max.poll.interval.ms": 6000})
    other = None
    try:
        require(run_until(lambda: len(stalled.assignment()) == 3, [stalled], 40), "the stalled member never got 3 partitions")
        require(run_until(lambda: stalled.persisted >= 8, [stalled], 40), "the stalled member did not persist 8 messages")
        owned_before = stalled.owned()
        pending_before = stalled.batcher.pending_offsets()
        held_before = committed(env, group, topic, [0, 1, 2])
        note("owned_before", owned_before)
        other = Member(env, topic, group, n=1000, t=60.0, batching=False)
        deadline = time.time() + 14                  # the stalled member does not poll: its poll interval expires
        while time.time() < deadline:
            other.consumer.poll(0.5)
        stalled.events.append(("resume",))
        run_until(lambda: any(e[0] in ("lost", "revoke") for e in stalled.events), [stalled], 30)
        for _ in range(10):
            stalled.step(0.5)
        held_after = committed(env, group, topic, [0, 1, 2])
        events = [e[0] for e in stalled.events]
        note("events", events)
        note("assignment_after", stalled.assignment())
        note("owned_after", stalled.owned())
        # safety: nothing may be committed for partitions this member no longer owns
        assert stalled.batcher.fatal is None
        stalled.batcher.check_invariants()
        assert stalled.owned() == stalled.assignment()
        for partition in set(owned_before) - set(stalled.owned()):
            assert held_after[partition] == held_before[partition], (
                f"partition {partition} was lost but its committed offset moved "
                f"{held_before[partition]} -> {held_after[partition]}")
            assert not any(k[1] == partition for k in stalled.batcher.pending_offsets())
        note("pending_before", {f"{t}:{p}": o for (t, p), o in pending_before.items()})
        return "OBSERVED" if any(e in ("lost", "revoke") for e in events) else "NOT_OBSERVED"
    finally:
        note("diagnostics_stalled", snapshot_member(stalled))
        for member in (other, stalled):
            if member is not None:
                try:
                    member.close(flush=False)
                except Exception:  # noqa: BLE001
                    pass


# ---------------------------------------------------------------------------
# C06  close() callbacks and the final flush
# ---------------------------------------------------------------------------

@case("C06_close_callbacks")
def test_c06_close_callbacks(env):
    K, m = kafka(), mods()
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    produce(env, topic, {0: 4, 1: 4, 2: 4}, tag)
    group = unique("it-c06")
    conn = connect_pg(env)
    consumer = K.Consumer(base_conf(env, group))
    shutdown = threading.Event()
    spy = SpyConsumer(consumer, shutdown)                     # the consumer the batcher AND the loop use
    batcher = m.OffsetBatcher(spy, 5, 60.0, log=lambda text: None)
    spy.batcher = batcher
    events: list[tuple] = []
    consumer.subscribe([topic],
                       on_assign=lambda c, p: (events.append(("assign", sorted(x.partition for x in p), batcher.closing)), batcher.on_assign(c, p)),
                       on_revoke=lambda c, p: (events.append(("revoke", sorted(x.partition for x in p), batcher.closing)), batcher.on_revoke(c, p)),
                       on_lost=lambda c, p: (events.append(("lost", sorted(x.partition for x in p), batcher.closing)), batcher.on_lost(c, p)))
    repo = RecordingRepo(m.SpanRepository(conn), on_insert=lambda count, fresh: shutdown.set() if count >= 12 else None)
    try:
        m.run_consumer_loop(spy, repo, shutdown, batcher=batcher)
        high = end_offsets(env, topic, [0, 1, 2])
        held = committed(env, group, topic, [0, 1, 2])
        note("events", events)
        note("commit_events", spy.events)
        note("callbacks_during_close", [e for e in events if e[2]])
        problems = verify_close_ordering(spy.events)
        note("ordering_problems", problems)
        assert len(repo.results) == 12 and count_rows(conn, tag) == (12, 12)
        assert held == high, f"the final flush did not commit everything: {held} vs {high}"
        assert not problems, "; ".join(problems)
        assert batcher.closing and batcher.pending_messages() == 0
        assert batcher.fatal is None and not batcher.commit_failed
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# C07a  crash and replay, deterministic simulation; C07b forced kill of the real process
# ---------------------------------------------------------------------------

@case("C07a_crash_replay")
def test_c07a_crash_and_replay(env):
    m = mods()
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    produce(env, topic, {0: 44, 1: 43, 2: 43}, tag)
    group = unique("it-c07a")
    first = Member(env, topic, group, n=50, t=600.0)
    try:
        assert run_until(lambda: len(first.assignment()) == 3, [first], 40)
        deadline = time.time() + 90
        while first.persisted < 130 and time.time() < deadline:
            first.step(0.5, idle_flush=False)          # flush by count only, so the numbers below are exact
        assert first.persisted == 130, f"only {first.persisted} of 130 messages were persisted"
        end = end_offsets(env, topic, [0, 1, 2])
        # the "crash": no final flush; commits are blocked so that close() cannot commit either
        first.batcher.closing = True
        pending_lost = first.batcher.pending_messages()
    finally:
        first.close(flush=False)
    held = committed(env, group, topic, [0, 1, 2])
    note("committed_after_crash", held)
    note("persisted_not_committed", pending_lost)
    assert pending_lost == 30, f"expected 30 persisted but uncommitted messages, saw {pending_lost}"
    assert sum(v or 0 for v in held.values()) == 100
    conn = connect_pg(env)
    try:
        assert count_rows(conn, tag) == (130, 130)
        # restart: Kafka redelivers from the committed offsets; the unique constraint absorbs the replay
        shutdown = threading.Event()
        repo = RecordingRepo(m.SpanRepository(conn), on_insert=lambda count, fresh: shutdown.set() if count >= 30 else None)
        results = repo.results
        pairs_at_crash = persisted_pairs(conn, tag)
        expected = expected_replays(pairs_at_crash, held)
        note("expected_replays_by_partition", expected)
        assert sum(expected.values()) == 30 == pending_lost, f"expected replays {expected} do not match the 30 pending"
        assert not contiguity_problems(pairs_at_crash), contiguity_problems(pairs_at_crash)
        K = kafka()
        consumer = K.Consumer(base_conf(env, group))
        batcher = m.OffsetBatcher(consumer, 50, 600.0, log=lambda text: None)
        consumer.subscribe([topic], on_assign=batcher.on_assign, on_revoke=batcher.on_revoke, on_lost=batcher.on_lost)
        m.run_consumer_loop(consumer, repo, shutdown, batcher=batcher)
        note("replayed", len(results))
        note("conflicts", results.count(False))
        assert len(results) == 30 and results.count(False) == 30, "the replayed messages were not all conflicts"
        assert count_rows(conn, tag) == (130, 130), "the replay changed the rows"
        assert persisted_pairs(conn, tag) == pairs_at_crash, "the replay changed the stored provenance"
        assert committed(env, group, topic, [0, 1, 2]) == end
    finally:
        conn.close()


@case("C07b_forced_kill_restart")
def test_c07b_forced_kill_of_the_real_consumer(env):
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    group = unique("it-c07b")
    total = {"n": 0}
    stop_producing = threading.Event()

    def produce_steadily():
        index = 0
        while not stop_producing.is_set() and index < 400:
            produce(env, topic, {index % 3: 1}, tag, start=index)
            index += 1
            time.sleep(0.02)
        total["n"] = index

    def start_consumer(log_name):
        return start_main_consumer(env, topic, group, log_name, batch="50", interval="30", timing="2")

    producer_thread = threading.Thread(target=produce_steadily, daemon=True)
    conn = connect_pg(env)
    first = second = None
    logs: list[tuple[Any, str]] = []                            # (open file, name) of every consumer log
    try:
        first, first_log = start_consumer("c07b-first.log")
        logs.append((first_log, "c07b-first.log"))
        time.sleep(8)                                            # let it join and consume
        producer_thread.start()
        time.sleep(4)                                            # kill it while messages are still arriving
        # The crash: the process tree of this one subprocess (the venv launcher AND the real
        # interpreter below it) is terminated and verified, never just the launcher.
        stopped = terminate_tree(first)
        note("first_kill_verified", not stopped)
        if stopped:
            record_process_problems([f"first consumer: {p}" for p in stopped])
            raise ProcessNotStopped("the first consumer could not be verified stopped: " + "; ".join(stopped))
        first_log.close()
        producer_thread.join(timeout=60)
        stop_producing.set()
        produced = total["n"]
        # the first consumer's whole process tree is verified gone, so these numbers cannot change any more
        held_at_kill = committed(env, group, topic, [0, 1, 2])
        pairs_at_kill = persisted_pairs(conn, tag)
        rows_at_kill = len(pairs_at_kill)
        expected_by_partition = expected_replays(pairs_at_kill, held_at_kill)
        expected_conflicts = sum(expected_by_partition.values())
        note("produced", produced)
        note("committed_after_kill", held_at_kill)
        note("rows_at_kill", rows_at_kill)
        note("persisted_not_committed_by_partition", expected_by_partition)
        assert not contiguity_problems(pairs_at_kill), contiguity_problems(pairs_at_kill)
        second, second_log = start_consumer("c07b-second.log")
        logs.append((second_log, "c07b-second.log"))
        end = end_offsets(env, topic, [0, 1, 2])
        deadline = time.time() + 90
        while time.time() < deadline:
            if committed(env, group, topic, [0, 1, 2]) == end and count_rows(conn, tag)[0] == produced:
                break
            time.sleep(1.0)
        rows, distinct = count_rows(conn, tag)
        final_held = committed(env, group, topic, [0, 1, 2])
        note("final_rows", [rows, distinct])
        note("final_committed", final_held)
        caught_up = final_held == end
        note("caught_up", caught_up)
        # persistence is a safety property: never a duplicate or an extra row, and no loss once
        # every offset was committed.  Merely not being finished within the time allowed is not.
        assert produced > 0, "the producer thread produced nothing"
        assert rows == distinct and rows <= produced, f"rows {rows}/{distinct}, produced {produced}"
        assert all((final_held[p] or 0) <= end[p] for p in end), f"committed {final_held} beyond the end {end}"
        assert not caught_up or rows == produced, f"all offsets committed but rows {rows} != produced {produced}"
        require(caught_up, "the restarted consumer had not caught up within the time allowed")
        assert rows == produced
        # Let the consumer print the timing window that holds the replayed burst, then stop its
        # process tree (verified) and only then read its log: a log read while it runs is incomplete.
        time.sleep(6)
        left = terminate_tree(second)
        if left:
            record_process_problems([f"second consumer: {p}" for p in left])
            raise ProcessNotStopped("the restarted consumer could not be verified stopped: " + "; ".join(left))
        second_log.close()
        sanitize_file(env.evidence / "c07b-second.log", env.pg_password)
        totals = parse_timing_counters((env.evidence / "c07b-second.log").read_text(encoding="utf-8", errors="replace"))
        expected_messages = sum(end.values()) - sum(v or 0 for v in held_at_kill.values())
        verdict, replay_problems = verify_replay(expected_conflicts, expected_messages, totals)
        final_pairs = persisted_pairs(conn, tag)
        note("timing_totals_of_the_restarted_consumer", totals)
        note("expected_conflicts", expected_conflicts)
        note("expected_messages_after_restart", expected_messages)
        note("replay_check", {"verdict": verdict, "problems": replay_problems})
        assert not contiguity_problems(final_pairs, end), contiguity_problems(final_pairs, end)
        require(verdict != "INCOMPLETE", "; ".join(replay_problems))
        assert verdict == "OK", "; ".join(replay_problems)
        return "OBSERVED" if expected_conflicts > 0 else "NOT_OBSERVED"
    finally:
        stop_producing.set()
        for label, process in (("first", first), ("second", second)):
            if process is None:
                continue
            try:
                left = terminate_tree(process)              # tree kill + verification, also for a launcher that already exited
            except Exception as exc:  # noqa: BLE001
                left = [f"{type(exc).__name__}: {exc}"]
            if left:
                record_process_problems([f"{label} consumer: {p}" for p in left])
        for handle, name in logs:
            try:
                handle.close()
            except OSError:
                pass
            sanitize_file(env.evidence / name, env.pg_password)
        conn.close()


# ---------------------------------------------------------------------------
# C12  sustained load through the production entry point, N=100, T=1.0 s
# ---------------------------------------------------------------------------

@case("C12_sustained_main_n100")
def test_c12_sustained_production_entry_point(env):
    topic = make_topic(env, 3)
    tag = tag_for(topic)
    group = unique("it-c12")
    conn = connect_pg(env)
    first = second = None
    logs: list[tuple[Any, str]] = []
    box: dict[str, Any] = {"stats": None, "error": None}
    stop_traffic = threading.Event()
    settings = {"batch": SUSTAINED_BATCH, "interval": SUSTAINED_INTERVAL, "timing": 2}

    def traffic():
        try:
            producer = kafka().Producer({"bootstrap.servers": env.kafka, "broker.address.family": "v4",
                                         "message.timeout.ms": 20000})
            box["stats"] = paced_produce(producer, topic, tag, rate=SUSTAINED_RATE, seconds=SUSTAINED_SECONDS,
                                         stop=stop_traffic)
        except BaseException as exc:  # noqa: BLE001 - reported below, never lost
            box["error"] = exc
    thread = threading.Thread(target=traffic, daemon=True)
    try:
        first, first_log = start_main_consumer(env, topic, group, "c12-first.log", **settings)
        logs.append((first_log, "c12-first.log"))
        time.sleep(8)                                            # let it join before the traffic starts
        began = time.time()
        thread.start()
        samples: list[dict] = []
        while thread.is_alive():
            assert first.poll() is None, f"the consumer exited during the traffic (code {first.poll()})"
            held_now = committed(env, group, topic, [0, 1, 2])
            samples.append({"t": round(time.time() - began, 1), "rows": count_rows(conn, tag)[0],
                            "committed": sum(v or 0 for v in held_now.values())})
            time.sleep(1.0)
        thread.join(timeout=30)
        if box["error"] is not None:
            raise InfrastructureError(f"the producer failed: {box['error']!r}") from box["error"]
        stats = box["stats"]
        if stats is None or stats["errors"] or stats["flush_remaining"]:
            raise InfrastructureError(f"the traffic was not delivered cleanly: {stats and {k: stats[k] for k in ('errors', 'flush_remaining')}}")
        expected_end = expected_end_from_offsets(stats["offsets"])
        total = stats["delivered"]
        note("traffic", {k: v for k, v in stats.items() if k != "offsets"})
        note("expected_end_of_the_records_of_this_case", expected_end)
        note("samples_during_traffic", samples)
        midstream = any(0 < sample["committed"] < total for sample in samples)
        note("offsets_advanced_while_traffic_flowed", midstream)

        # steady state: everything persisted, then reconciled, with the process still running
        deadline = time.time() + 90
        while time.time() < deadline and count_rows(conn, tag)[0] < total:
            assert first.poll() is None, f"the consumer exited while catching up (code {first.poll()})"
            time.sleep(0.5)
        t_rows = time.time()
        rows_now = count_rows(conn, tag)[0]
        # offsets committed past rows that do not exist would be a lost record: a safety failure,
        # whereas a consumer that is merely behind has committed nothing it has not persisted
        assert not (rows_now < total and committed(env, group, topic, [0, 1, 2]) == expected_end), (
            f"every offset is committed but only {rows_now} of {total} rows exist")
        require(rows_now >= total, "the consumer had not persisted every record within 90 s")
        held = committed(env, group, topic, [0, 1, 2])
        while held != expected_end and time.time() < t_rows + 20:
            assert first.poll() is None, f"the consumer exited before the flush (code {first.poll()})"
            time.sleep(0.5)
            held = committed(env, group, topic, [0, 1, 2])
        t_committed = time.time()
        alive = first.poll() is None
        problems = reconciliation_problems(held, expected_end, alive)
        pairs = persisted_pairs(conn, tag)
        rows, distinct = count_rows(conn, tag)
        persisted = persistence_problems(pairs, rows, distinct, expected_end, total)
        note("seconds_from_last_row_to_reconciled_offsets", round(t_committed - t_rows, 2))
        note("reconciled_before_termination", not problems)
        note("committed_before_termination", held)
        note("reconciliation_problems", problems)
        note("persistence_problems", persisted)
        assert not problems, "; ".join(problems)
        assert not persisted, "; ".join(persisted)

        # the crash: this one process tree, verified dead before anything is read
        stopped = terminate_tree(first)
        note("first_kill_verified", not stopped)
        if stopped:
            record_process_problems([f"first consumer: {p}" for p in stopped])
            raise ProcessNotStopped("the first consumer could not be verified stopped: " + "; ".join(stopped))
        first_log.close()
        held_at_kill = committed(env, group, topic, [0, 1, 2])
        pairs_at_kill = persisted_pairs(conn, tag)
        expected_by_partition = expected_replays(pairs_at_kill, held_at_kill)
        expected_conflicts = sum(expected_by_partition.values())          # zero is a valid expectation here
        note("committed_after_kill", held_at_kill)
        note("expected_replay_by_partition", expected_by_partition)

        # restart with the same group and settings; a small marker batch proves the new process is
        # assigned and consuming, so that "no replay" cannot be confused with "not running"
        second, second_log = start_main_consumer(env, topic, group, "c12-second.log", **settings)
        logs.append((second_log, "c12-second.log"))
        marker = produce(env, topic, {p: SUSTAINED_MARKER_PER_PARTITION for p in (0, 1, 2)}, tag, start=total)
        end2 = {p: expected_end[p] + len(marker[p]) for p in expected_end}
        total2 = total + sum(len(v) for v in marker.values())
        expected_messages = sum(end2.values()) - sum(v or 0 for v in held_at_kill.values())
        deadline = time.time() + 150
        while time.time() < deadline:
            assert second.poll() is None, f"the restarted consumer exited (code {second.poll()})"
            if count_rows(conn, tag)[0] >= total2 and committed(env, group, topic, [0, 1, 2]) == end2:
                break
            time.sleep(1.0)
        time.sleep(6)                                            # let the timing window with the last messages print
        left = terminate_tree(second)
        if left:
            record_process_problems([f"second consumer: {p}" for p in left])
            raise ProcessNotStopped("the restarted consumer could not be verified stopped: " + "; ".join(left))
        second_log.close()
        sanitize_file(env.evidence / "c12-second.log", env.pg_password)
        totals = parse_timing_counters((env.evidence / "c12-second.log").read_text(encoding="utf-8", errors="replace"))
        final_held = committed(env, group, topic, [0, 1, 2])
        final_pairs = persisted_pairs(conn, tag)
        rows2, distinct2 = count_rows(conn, tag)
        verdict, replay_problems = verify_replay(expected_conflicts, expected_messages, totals)
        final_problems = persistence_problems(final_pairs, rows2, distinct2, end2, total2)
        note("restart_totals", totals)
        note("expected_messages_after_restart", expected_messages)
        note("expected_conflicts", expected_conflicts)
        note("replay_check", {"verdict": verdict, "problems": replay_problems})
        note("final_persistence_problems", final_problems)
        note("final_committed", final_held)
        assert not final_problems, "; ".join(final_problems)
        assert final_held == end2, f"final committed offsets {final_held} differ from the end {end2}"
        require(verdict != "INCOMPLETE", "; ".join(replay_problems))
        assert verdict == "OK", "; ".join(replay_problems)
        rate_ok = stats["observed_rate"] >= 0.8 * SUSTAINED_RATE
        note("observed_rate_meets_80_percent_of_target", rate_ok)
        return "OBSERVED" if (rate_ok and midstream) else "NOT_OBSERVED"
    finally:
        stop_traffic.set()
        for label, process in (("first", first), ("second", second)):
            if process is None:
                continue
            try:
                left = terminate_tree(process)
            except Exception as exc:  # noqa: BLE001
                left = [f"{type(exc).__name__}: {exc}"]
            if left:
                record_process_problems([f"{label} consumer: {p}" for p in left])
        for handle, name in logs:
            try:
                handle.close()
            except OSError:
                pass
            sanitize_file(env.evidence / name, env.pg_password)
        conn.close()


# ---------------------------------------------------------------------------
# C08  PostgreSQL idempotency through the real unique constraint
# ---------------------------------------------------------------------------

@case("C08_postgres_idempotency")
def test_c08_unique_constraint_idempotency(env):
    m = mods()
    from schemas.telemetry import CanonicalSpanEvent
    tag = uuid.uuid4().hex
    conn = connect_pg(env)
    try:
        repo = m.SpanRepository(conn)
        event = CanonicalSpanEvent.model_validate(json.loads(span_bytes(tag, 7)))
        first = repo.insert_span(event, topic="it", partition=0, offset=1)
        second = repo.insert_span(event, topic="it", partition=0, offset=1)
        third = repo.insert_span(event, topic="it", partition=1, offset=99)       # same span, other provenance
        note("results", [first, second, third])
        assert (first, second, third) == (True, False, False)
        assert count_rows(conn, tag) == (1, 1)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_constraint WHERE conname = 'uq_telemetry_spans_trace_span'")
            assert cur.fetchone()[0] == 1
    finally:
        delete_rows(conn, tag)
        conn.close()


# ---------------------------------------------------------------------------
# C09  N=1 versus N=100
# ---------------------------------------------------------------------------

def drain_with_loop(env, topic, group, n, expected):
    """Run the real loop (batcher only for n > 1) until `expected` messages were persisted; returns the spy.
    The spy is the consumer of both the loop and the batcher, so every commit is observed."""
    m, K = mods(), kafka()
    conn = connect_pg(env)
    consumer = K.Consumer(base_conf(env, group))
    shutdown = threading.Event()
    spy = SpyConsumer(consumer, shutdown)
    batcher = m.OffsetBatcher(spy, n, 30.0, log=lambda text: None) if n > 1 else None
    spy.batcher = batcher
    if batcher is not None:
        consumer.subscribe([topic], on_assign=batcher.on_assign, on_revoke=batcher.on_revoke, on_lost=batcher.on_lost)
    else:
        consumer.subscribe([topic])
    repo = RecordingRepo(m.SpanRepository(conn), on_insert=lambda count, fresh: shutdown.set() if count >= expected else None)
    try:
        m.run_consumer_loop(spy, repo, shutdown, batcher=batcher)
    finally:
        conn.close()
    return spy


@case("C09_n1_versus_n100")
def test_c09_default_and_batched_loops_agree(env):
    outcomes = {}
    for n in (1, 100):
        topic = make_topic(env, 3)
        tag = tag_for(topic)
        produce(env, topic, {0: 100, 1: 100, 2: 100}, tag)
        group = unique(f"it-c09-n{n}")
        spy = drain_with_loop(env, topic, group, n, 300)
        conn = connect_pg(env)
        try:
            rows = count_rows(conn, tag)
        finally:
            delete_rows(conn, tag)
            conn.close()
        held = committed(env, group, topic, [0, 1, 2])
        end = end_offsets(env, topic, [0, 1, 2])
        assert not verify_close_ordering(spy.events, ("asynchronous", "message") if n == 1 else ("asynchronous", "offsets")), \
            verify_close_ordering(spy.events, ("asynchronous", "message") if n == 1 else ("asynchronous", "offsets"))
        outcomes[n] = {"rows": rows, "committed": held, "end": end, "commit_calls": len(spy.commits),
                       "keywords": sorted({tuple(call["keywords"]) for call in spy.commits})}
    note("outcomes", {str(k): v for k, v in outcomes.items()})
    for n, outcome in outcomes.items():
        assert outcome["rows"] == (300, 300), f"N={n}: rows {outcome['rows']}"
        assert outcome["committed"] == outcome["end"], f"N={n}: committed offsets differ from the end offsets"
    assert outcomes[1]["commit_calls"] == 300 and outcomes[1]["keywords"] == [("asynchronous", "message")]
    assert 1 <= outcomes[100]["commit_calls"] <= 10 and outcomes[100]["keywords"] == [("asynchronous", "offsets")]


# ---------------------------------------------------------------------------
# C10  idle and time flush with the real one-second poll
# ---------------------------------------------------------------------------

def start_loop(env, topic, group, n, seconds):
    """The real loop in a thread, on a spy shared with its batcher; stop_loop() ends it."""
    m, K = mods(), kafka()
    conn = connect_pg(env)
    consumer = K.Consumer(base_conf(env, group))
    shutdown = threading.Event()
    spy = SpyConsumer(consumer, shutdown)
    batcher = m.OffsetBatcher(spy, n, seconds, log=lambda text: None)
    spy.batcher = batcher
    consumer.subscribe([topic], on_assign=batcher.on_assign, on_revoke=batcher.on_revoke, on_lost=batcher.on_lost)
    errors: list[BaseException] = []

    def work():
        try:
            m.run_consumer_loop(spy, RecordingRepo(m.SpanRepository(conn)), shutdown, batcher=batcher)
        except BaseException as exc:  # noqa: BLE001 - surfaced by stop_loop, never swallowed
            errors.append(exc)
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    return SimpleNamespace(spy=spy, batcher=batcher, shutdown=shutdown, worker=worker, conn=conn, errors=errors)


def stop_loop(loop) -> None:
    loop.shutdown.set()
    loop.worker.join(timeout=30)
    try:
        loop.conn.close()
    finally:
        if loop.worker.is_alive():
            raise InfrastructureError("the consumer loop did not stop within 30 s")
    if loop.errors:
        raise loop.errors[0]


@case("C10_idle_and_time_flush")
def test_c10_flushes_without_waiting_for_shutdown(env):
    # A: five messages, then silence.  The offsets must be committed by an idle flush while the
    # consumer is still active (nothing has asked it to stop).
    topic = make_topic(env, 1)
    produce(env, topic, {0: 5}, tag_for(topic))
    group = unique("it-c10a")
    loop = start_loop(env, topic, group, 1000, 1.0)
    try:
        started, reached = time.time(), None
        while time.time() - started < 40 and not loop.errors:
            if committed(env, group, topic, [0]).get(0) == 5:
                reached = time.time() - started
                break
            time.sleep(0.5)
        active_commits = [e for e in loop.spy.commits if not e["shutdown"]]
        note("idle_seconds_until_committed", reached)
        note("idle_commits_while_active", active_commits)
        note("idle_shutdown_requested", loop.shutdown.is_set())
    finally:
        stop_loop(loop)
    assert reached is not None, "the offsets were not committed by an idle flush"
    assert active_commits and not any(e["closing"] for e in active_commits)
    flush = classify_flushes(loop.spy.events)
    note("idle_flushes", flush)
    assert (flush["idle"] or flush["interval"]) and not flush["during_close"]

    # B: steady low-rate traffic (one message every 0.4 s, never idle for a whole poll), N=1000 so
    # the batch size can never trigger, T=1.0 s.  Offsets must advance in steps WHILE traffic
    # flows, by flushes made when the oldest pending offset reached its age, not at shutdown.
    topic = make_topic(env, 1)
    tag = tag_for(topic)
    group = unique("it-c10b")
    total, producing = 24, threading.Event()
    producing.set()

    trickle_errors: list[BaseException] = []

    def trickle():
        try:
            for index in range(total):
                produce(env, topic, {0: 1}, tag, start=index)
                time.sleep(0.4)
        except BaseException as exc:  # noqa: BLE001 - reported below, never lost
            trickle_errors.append(exc)
        finally:
            producing.clear()
    loop = start_loop(env, topic, group, 1000, 1.0)
    thread = threading.Thread(target=trickle, daemon=True)
    samples: list[tuple[float, Optional[int]]] = []
    try:
        thread.start()
        began = time.time()
        while producing.is_set() and time.time() - began < 60 and not loop.errors:
            samples.append((round(time.time() - began, 1), committed(env, group, topic, [0]).get(0)))
            time.sleep(1.0)
        thread.join(timeout=30)
        deadline = time.time() + 30
        while time.time() < deadline and committed(env, group, topic, [0]).get(0) != total and not loop.errors:
            time.sleep(0.5)
        reached_end = committed(env, group, topic, [0]).get(0)
        before_shutdown = classify_flushes(loop.spy.events)
        problems_before = verify_interval_run(loop.spy.events)
        note("traffic_committed_samples", samples)
        note("flushes_before_shutdown", before_shutdown)
        note("shutdown_requested_before_checks", loop.shutdown.is_set())
    finally:
        stop_loop(loop)
    after = classify_flushes(loop.spy.events)
    note("flushes_total", after)
    midway = [value for _, value in samples if value is not None and 0 < value < total]
    note("progress_while_traffic_flowed", midway)
    assert not problems_before, "; ".join(problems_before)
    assert midway, "no committed offset was seen between 0 and the end while messages were still arriving"
    assert reached_end == total, f"the broker holds {reached_end}, expected {total}"
    assert not trickle_errors, f"the producer failed: {trickle_errors[0]!r}"
    assert not after["during_close"] and not loop.errors


# ---------------------------------------------------------------------------
# C11  subscription callback registration
# ---------------------------------------------------------------------------

@case("C11_subscription_callbacks")
def test_c11_subscription_callbacks(env):
    topic = make_topic(env, 3)
    plain = Member(env, topic, unique("it-c11-plain"), batching=False)
    try:
        assert run_until_plain(plain.consumer, 3, 40), "the plain (N=1) subscription never got 3 partitions"
    finally:
        plain.close()
    batched = Member(env, topic, unique("it-c11-batched"), n=100, t=30.0)
    try:
        assert run_until(lambda: len(batched.assignment()) == 3, [batched], 40)
        note("events", [list(e[:2]) for e in batched.events if e[0] in ("assign", "revoke", "lost")])
        assert batched.owned() == batched.assignment() == [0, 1, 2]
        assert any(e[0] == "assign" for e in batched.events)
        assert batched.batcher.fatal is None
    finally:
        batched.close()


def run_until_plain(consumer, partitions, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        consumer.poll(0.3)
        if len(consumer.assignment()) == partitions:
            return True
    return False
