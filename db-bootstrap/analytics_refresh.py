"""
db-bootstrap/analytics_refresh.py

Phase 14.2: The one sanctioned way to rebuild the analytics models.

dbt replaces every relation of the analytics schema when it runs, and a
replaced relation loses the grants a migration made on it.  This program
does the whole operation, in this order, and fails if any part of it fails:

    dbt run -> post_dbt_grants.sql -> verify every analytics grant

It works only on a database the bootstrap has finished.  Any other database
is refused before anything is run: an empty one, one whose bootstrap stopped
half way, and one the bootstrap did not build.

It creates no role, applies no migration, and neither writes nor creates the
bootstrap's record of applied steps.  That record is read before and after,
and the refresh fails if the two readings differ.

Credentials
-----------
Only the owner role's password is needed, and it comes from the environment
exactly as it does for the bootstrap.  The application roles' passwords are
not read.

Everything is reused from bootstrap.py: configuration, the plan, the state
classifier, the child processes, and the verification.

Exit codes are the bootstrap's:
    0  refreshed and verified
    3  configuration
    4  the database could not be reached or read
    5  the database is not one this program may refresh; nothing was run
    6  dbt, the grants or the verification failed
    1  unexpected error

Public API:
    run_refresh()   — the whole procedure
    main()          — command-line entry point
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Mapping, Optional, Sequence

import bootstrap
from bootstrap import (
    BootstrapError,
    BootstrapState,
    IncompatibleError,
    PsqlExecutor,
    Runner,
    Step,
    StepError,
)


_NOT_INITIALIZED = (
    "the database is not initialized; the database bootstrap has to finish first"
)
_NOT_FINISHED = (
    "the database bootstrap has not finished; it has to finish first"
)
_DBT_FAILED_HINT = (
    "the analytics grants were not re-applied; correct the cause and run the "
    "refresh again"
)


def _grants_step(plan: Sequence[Step]) -> Step:
    for step in plan:
        if step.name == bootstrap.STEP_GRANTS and step.path is not None:
            return step
    raise ValueError("the plan holds no post-dbt grants step")


def _require_complete(found: bootstrap.Classification) -> None:
    """
    Raises:
        IncompatibleError  unless the database is COMPLETE.
    """
    if found.state is BootstrapState.COMPLETE:
        return
    if found.state is BootstrapState.EMPTY:
        raise IncompatibleError(_NOT_INITIALIZED)
    if found.state is BootstrapState.PARTIAL_VALID:
        raise IncompatibleError(f"{_NOT_FINISHED} ({found.reason})")
    raise IncompatibleError(found.reason)


def run_refresh(
    executor,
    plan: Sequence[Step],
    intended_grants: frozenset[tuple[str, str, str]],
    *,
    report: Callable[[str], None] = print,
) -> None:
    """
    Rebuild the analytics models of a complete database and restore and
    verify their grants.

    Raises:
        DatabaseError      the database could not be inspected.
        IncompatibleError  the database is not COMPLETE; nothing was run.
        StepError          dbt, the grants or the verification failed, or
                           the bootstrap's record changed meanwhile.
    """
    grants = _grants_step(plan)

    bootstrap.check_facts(executor.read_facts())
    before = executor.read_state(plan)
    found = bootstrap.classify(before, plan)
    report(f"database state: {found.state.value} ({found.reason})")
    _require_complete(found)

    report("step 1/3: dbt run")
    try:
        executor.run_dbt()
    except StepError as exc:
        raise StepError(f"{exc}\n{_DBT_FAILED_HINT}") from None

    report(f"step 2/3: {grants.name}")
    executor.apply_unrecorded(grants.path, grants.name)

    report("step 3/3: verify analytics privileges")
    bootstrap.verify(executor, plan, intended_grants)

    after = executor.read_state(plan)
    unchanged = (
        after.ledger_schema_exists == before.ledger_schema_exists
        and after.ledger_table_exists == before.ledger_table_exists
        and after.ledger_rows == before.ledger_rows
    )
    if not unchanged:
        raise StepError("the bootstrap record changed during the refresh")

    report("analytics refresh complete")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild the AgentOps analytics models with dbt, re-apply the "
            "grants a dbt run removes, and verify every analytics grant. "
            "Configuration comes from the environment. Only a database the "
            "bootstrap has finished is accepted."
        ),
    )
    return parser.parse_args(argv)


def _error(message: str) -> None:
    sys.stderr.write(f"error: {message}\n")


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    runner: Runner = bootstrap.run_process,
) -> int:
    _parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        config = bootstrap.load_config(environment, require_role_passwords=False)
        plan = bootstrap.build_plan(config.migrations_dir, config.grants_file)
        executor = PsqlExecutor(config, runner=runner, environ=environment)
        run_refresh(executor, plan, bootstrap.intended_analytics_grants(plan))
    except BootstrapError as exc:
        _error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - last line of containment
        # Only the type: a message could quote a value.
        _error(f"internal: {type(exc).__name__}")
        return bootstrap.EXIT_INTERNAL
    return bootstrap.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
