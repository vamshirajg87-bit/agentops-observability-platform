"""
Static tests for the Phase 13.2 alerting migrations:

    storage-consumer/migrations/012_create_alert_tables.sql
    storage-consumer/migrations/013_create_alert_evaluator_role.sql
    storage-consumer/migrations/014_create_alert_notifier_role.sql

The migration files are read as text and inspected.  Nothing is executed:
no database, no network, no environment variables.

SQL comments are removed before inspection, so a privilege that is only
named in a "NOT granted" comment is never mistaken for a grant.

Coverage:
    1.  Migration inventory: 012-014 exist; alerting objects appear nowhere
        else
    2.  Exactly four tables, exact column definitions
    3.  Primary keys, foreign keys, unique constraints
    4.  CHECK constraints and their vocabulary, tied to alert_models
    5.  Decision / reason pairing and related_decision_id rules
    6.  Indexes
    7.  Migration 012 grants nothing
    8.  alert_evaluator: exact grant matrix
    9.  alert_notifier: exact grant matrix
    10. No broad or dangerous privilege
    11. No password or credential literal
    12. No SQL or database driver in the alerting component, except in its
        five database boundary modules (alert_db.py, alert_store.py,
        alert_notifier_db.py, alert_delivery_store.py,
        alert_guardrail_store.py)
"""

from __future__ import annotations

import os
import re

import pytest

from alert_models import (
    REASONS_BY_DECISION,
    REASONS_WITH_RELATED_DECISION,
    ChannelType,
    Confidence,
    Decision,
    DeliveryOutcome,
    DeliveryTrigger,
    ReasonCode,
    Severity,
)

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".."),
)
_MIGRATIONS = os.path.join(_REPO_ROOT, "storage-consumer", "migrations")
_ALERTING = os.path.join(_REPO_ROOT, "alerting")

_M012 = "012_create_alert_tables.sql"
_M013 = "013_create_alert_evaluator_role.sql"
_M014 = "014_create_alert_notifier_role.sql"

_TABLES = (
    "alert_policies",
    "alert_decisions",
    "alert_delivery_attempts",
    "alert_delivery_outcomes",
)

_DIGEST_CHECK = "~ '^[0-9a-f]{64}$'"


# ---------------------------------------------------------------------------
# Reading and parsing (text only)
# ---------------------------------------------------------------------------

def _raw(name: str) -> str:
    with open(os.path.join(_MIGRATIONS, name), encoding="utf-8") as fh:
        return fh.read()


def _sql(name: str) -> str:
    """Migration text without comments, whitespace collapsed to single spaces."""
    lines = [line.split("--", 1)[0] for line in _raw(name).splitlines()]
    return " ".join(" ".join(lines).split())


def _statements(name: str) -> list[str]:
    return [part.strip() for part in _sql(name).split(";") if part.strip()]


def _split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on commas that are not inside parentheses."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _table_items(table: str) -> list[str]:
    prefix = f"CREATE TABLE public.{table} ("
    matches = [s for s in _statements(_M012) if s.startswith(prefix)]
    assert len(matches) == 1, f"expected one CREATE TABLE for {table}"
    statement = matches[0]
    assert statement.endswith(")")
    return _split_top_level(statement[len(prefix):-1])


def _columns(table: str) -> dict[str, str]:
    """column name -> its definition after the name."""
    columns: dict[str, str] = {}
    for item in _table_items(table):
        if item.startswith("CONSTRAINT "):
            continue
        name, definition = item.split(" ", 1)
        assert name not in columns
        columns[name] = " ".join(definition.split())
    return columns


def _constraints(table: str) -> dict[str, str]:
    """constraint name -> its definition after the name."""
    constraints: dict[str, str] = {}
    for item in _table_items(table):
        if not item.startswith("CONSTRAINT "):
            continue
        _, name, definition = item.split(" ", 2)
        assert name not in constraints
        constraints[name] = " ".join(definition.split())
    return constraints


def _in_list(text: str) -> set[str]:
    """The quoted values of a single IN (...) list."""
    found = re.findall(r"IN \(([^()]*)\)", text)
    assert len(found) == 1, f"expected exactly one IN list in: {text}"
    return set(re.findall(r"'([^']*)'", found[0]))


_GRANT_RE = re.compile(
    r"^GRANT (?P<privileges>.+?) ON (?:(?P<kind>DATABASE|SCHEMA|TABLE) )?"
    r"(?P<object>\S+) TO (?P<grantee>\S+)$"
)
_PRIVILEGE_RE = re.compile(r"([A-Z]+)(?: \(([^()]*)\))?")


def _grants(name: str) -> set[tuple]:
    """
    Every grant in a migration as
    (kind, object, privilege, columns-or-None, grantee).
    """
    grants: set[tuple] = set()
    for statement in _statements(name):
        if not statement.startswith("GRANT "):
            continue
        match = _GRANT_RE.match(statement)
        assert match is not None, f"unparsed GRANT: {statement}"
        kind = match.group("kind") or "TABLE"
        privileges = match.group("privileges")
        parsed = _PRIVILEGE_RE.findall(privileges)
        rebuilt = ", ".join(
            f"{priv} ({cols})" if cols else priv for priv, cols in parsed
        )
        assert rebuilt == privileges, f"unparsed privilege list: {privileges}"
        for privilege, column_text in parsed:
            columns = (
                frozenset(c.strip() for c in column_text.split(","))
                if column_text else None
            )
            entry = (
                kind, match.group("object"), privilege, columns,
                match.group("grantee"),
            )
            assert entry not in grants, f"duplicate grant: {entry}"
            grants.add(entry)
    return grants


def _table(obj: str, privilege: str, grantee: str, columns=None) -> tuple:
    return (
        "TABLE", obj, privilege,
        frozenset(columns) if columns is not None else None,
        grantee,
    )


# ---------------------------------------------------------------------------
# 1. Migration inventory
# ---------------------------------------------------------------------------

class TestInventory:
    def test_alert_migrations_exist(self):
        present = set(os.listdir(_MIGRATIONS))
        assert {_M012, _M013, _M014} <= present

    def test_migration_numbers_are_contiguous_and_unique(self):
        numbers = sorted(
            int(name[:3]) for name in os.listdir(_MIGRATIONS)
            if name.endswith(".sql")
        )
        assert numbers == list(range(1, len(numbers) + 1))
        assert numbers[:14] == list(range(1, 15))

    def test_exactly_three_alert_migrations(self):
        named = sorted(
            name for name in os.listdir(_MIGRATIONS) if "alert" in name
        )
        assert named == [_M012, _M013, _M014]

    def test_earlier_migrations_do_not_mention_alerting(self):
        for name in sorted(os.listdir(_MIGRATIONS)):
            if not name.endswith(".sql") or int(name[:3]) >= 12:
                continue
            text = _raw(name).lower()
            assert "alert_" not in text, name
            assert "alert_evaluator" not in text, name
            assert "alert_notifier" not in text, name

    def test_only_expected_statement_kinds(self):
        kinds_012 = {s.split(" ", 2)[0] + " " + s.split(" ", 2)[1]
                     for s in _statements(_M012)}
        assert kinds_012 == {"CREATE TABLE", "CREATE INDEX"}
        for name in (_M013, _M014):
            kinds = {s.split(" ", 1)[0] for s in _statements(name)}
            assert kinds == {"CREATE", "GRANT"}, name

    def test_statement_counts(self):
        assert len(_statements(_M012)) == 7       # 4 tables + 3 indexes
        assert len(_statements(_M013)) == 10      # 1 role + 9 grants
        assert len(_statements(_M014)) == 6       # 1 role + 5 grants


# ---------------------------------------------------------------------------
# 2. Tables and columns
# ---------------------------------------------------------------------------

class TestTables:
    def test_exactly_four_tables(self):
        created = re.findall(r"CREATE TABLE (\S+) \(", _sql(_M012))
        assert created == [f"public.{table}" for table in _TABLES]

    def test_no_if_not_exists(self):
        assert "IF NOT EXISTS" not in _sql(_M012)

    def test_no_table_created_by_role_migrations(self):
        for name in (_M013, _M014):
            assert "CREATE TABLE" not in _sql(name)
            assert "CREATE INDEX" not in _sql(name)

    def test_alert_policies_columns(self):
        assert _columns("alert_policies") == {
            "policy_version": "TEXT NOT NULL",
            "policy_sha256": "TEXT NOT NULL",
            "policy_json": "JSONB NOT NULL",
            "registered_at": "TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        }

    def test_alert_decisions_columns(self):
        assert _columns("alert_decisions") == {
            "decision_id": "TEXT NOT NULL",
            "investigation_id": "TEXT NOT NULL",
            "policy_version": "TEXT NOT NULL",
            "anomaly_id": "TEXT NOT NULL",
            "anomaly_type": "TEXT NOT NULL",
            "service_name": "TEXT",
            "operation_name": "TEXT",
            "event_time": "TIMESTAMPTZ NOT NULL",
            "severity": "TEXT NOT NULL",
            "confidence": "TEXT NOT NULL",
            "limitations": "TEXT[] NOT NULL DEFAULT '{}'",
            "dedup_key": "TEXT NOT NULL",
            "decision": "TEXT NOT NULL",
            "reason_code": "TEXT NOT NULL",
            "related_decision_id": "TEXT",
            "evaluated_at": "TIMESTAMPTZ NOT NULL",
            "payload": "JSONB",
            "summary": "TEXT",
            "summary_truncated": "BOOLEAN NOT NULL DEFAULT FALSE",
            "decided_at": "TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        }

    def test_alert_delivery_attempts_columns(self):
        assert _columns("alert_delivery_attempts") == {
            "attempt_id": "TEXT NOT NULL",
            "decision_id": "TEXT NOT NULL",
            "channel_name": "TEXT NOT NULL",
            "channel_type": "TEXT NOT NULL",
            "attempt_no": "INTEGER NOT NULL",
            "trigger": "TEXT NOT NULL",
            "summary_included": "BOOLEAN NOT NULL",
            "payload_sha256": "TEXT NOT NULL",
            "started_at": "TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        }

    def test_alert_delivery_outcomes_columns(self):
        assert _columns("alert_delivery_outcomes") == {
            "attempt_id": "TEXT NOT NULL",
            "outcome": "TEXT NOT NULL",
            "detail": "TEXT",
            "recorded_at": "TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        }

    def test_no_serial_or_identity_column(self):
        sql = _sql(_M012).upper()
        for forbidden in ("SERIAL", "GENERATED", "SEQUENCE", "NEXTVAL"):
            assert forbidden not in sql

    def test_attempts_have_no_state_column(self):
        columns = set(_columns("alert_delivery_attempts"))
        assert columns.isdisjoint({"state", "status", "outcome", "phase", "event_type"})

    def test_no_started_event_exists(self):
        assert "STARTED" not in _sql(_M012)

    def test_defaults_never_supply_an_identity_or_a_verdict(self):
        # Only write timestamps, the empty limitations array and the
        # summary_truncated flag have a default.
        for table in _TABLES:
            for column, definition in _columns(table).items():
                if "DEFAULT" in definition:
                    assert column in {
                        "registered_at", "decided_at", "started_at",
                        "recorded_at", "limitations", "summary_truncated",
                    }, (table, column)


# ---------------------------------------------------------------------------
# 3. Keys
# ---------------------------------------------------------------------------

class TestKeys:
    @pytest.mark.parametrize("table, constraint, definition", [
        ("alert_policies", "pk_alert_policies",
         "PRIMARY KEY (policy_version)"),
        ("alert_decisions", "pk_alert_decisions",
         "PRIMARY KEY (decision_id)"),
        ("alert_delivery_attempts", "pk_alert_delivery_attempts",
         "PRIMARY KEY (attempt_id)"),
        ("alert_delivery_outcomes", "pk_alert_delivery_outcomes",
         "PRIMARY KEY (attempt_id)"),
    ])
    def test_primary_keys(self, table, constraint, definition):
        assert _constraints(table)[constraint] == definition

    @pytest.mark.parametrize("table", _TABLES)
    def test_exactly_one_primary_key_per_table(self, table):
        keys = [d for d in _constraints(table).values() if d.startswith("PRIMARY KEY")]
        assert len(keys) == 1

    @pytest.mark.parametrize("table, constraint, definition", [
        ("alert_decisions", "fk_alert_decisions_investigation",
         "FOREIGN KEY (investigation_id) REFERENCES "
         "public.rca_investigations (investigation_id) ON DELETE RESTRICT"),
        ("alert_decisions", "fk_alert_decisions_policy",
         "FOREIGN KEY (policy_version) REFERENCES "
         "public.alert_policies (policy_version) ON DELETE RESTRICT"),
        ("alert_decisions", "fk_alert_decisions_related_decision",
         "FOREIGN KEY (related_decision_id) REFERENCES "
         "public.alert_decisions (decision_id) ON DELETE RESTRICT"),
        ("alert_delivery_attempts", "fk_alert_delivery_attempts_decision",
         "FOREIGN KEY (decision_id) REFERENCES "
         "public.alert_decisions (decision_id) ON DELETE RESTRICT"),
        ("alert_delivery_outcomes", "fk_alert_delivery_outcomes_attempt",
         "FOREIGN KEY (attempt_id) REFERENCES "
         "public.alert_delivery_attempts (attempt_id) ON DELETE RESTRICT"),
    ])
    def test_foreign_keys(self, table, constraint, definition):
        assert _constraints(table)[constraint] == definition

    def test_exact_foreign_key_count(self):
        count = sum(
            1 for table in _TABLES
            for definition in _constraints(table).values()
            if definition.startswith("FOREIGN KEY")
        )
        assert count == 5

    def test_every_foreign_key_restricts_deletion(self):
        for table in _TABLES:
            for definition in _constraints(table).values():
                if definition.startswith("FOREIGN KEY"):
                    assert definition.endswith("ON DELETE RESTRICT")
        assert "CASCADE" not in _sql(_M012)
        assert "SET NULL" not in _sql(_M012)

    def test_alert_policies_has_no_foreign_key(self):
        assert not any(
            d.startswith("FOREIGN KEY")
            for d in _constraints("alert_policies").values()
        )

    def test_decisions_do_not_reference_anomaly_events_directly(self):
        assert "anomaly_events" not in _sql(_M012)

    @pytest.mark.parametrize("table, constraint, definition", [
        ("alert_decisions", "uq_alert_decisions_investigation_policy",
         "UNIQUE (investigation_id, policy_version)"),
        ("alert_delivery_attempts",
         "uq_alert_delivery_attempts_decision_channel_no",
         "UNIQUE (decision_id, channel_name, attempt_no)"),
    ])
    def test_unique_constraints(self, table, constraint, definition):
        assert _constraints(table)[constraint] == definition

    def test_exact_unique_constraint_count(self):
        count = sum(
            1 for table in _TABLES
            for definition in _constraints(table).values()
            if definition.startswith("UNIQUE")
        )
        assert count == 2

    def test_outcome_primary_key_allows_at_most_one_outcome_per_attempt(self):
        constraints = _constraints("alert_delivery_outcomes")
        assert constraints["pk_alert_delivery_outcomes"] == "PRIMARY KEY (attempt_id)"
        assert "REFERENCES public.alert_delivery_attempts (attempt_id)" in (
            constraints["fk_alert_delivery_outcomes_attempt"]
        )


# ---------------------------------------------------------------------------
# 4. CHECK constraints and vocabulary
# ---------------------------------------------------------------------------

class TestChecks:
    @pytest.mark.parametrize("table, constraint, column", [
        ("alert_policies", "chk_alert_policies_policy_sha256", "policy_sha256"),
        ("alert_decisions", "chk_alert_decisions_decision_id", "decision_id"),
        ("alert_decisions", "chk_alert_decisions_dedup_key", "dedup_key"),
        ("alert_delivery_attempts", "chk_alert_delivery_attempts_attempt_id",
         "attempt_id"),
        ("alert_delivery_attempts", "chk_alert_delivery_attempts_payload_sha256",
         "payload_sha256"),
    ])
    def test_digest_format_checks(self, table, constraint, column):
        assert _constraints(table)[constraint] == f"CHECK ({column} {_DIGEST_CHECK})"

    def test_digest_pattern_accepts_only_lowercase_sha256_hex(self):
        pattern = re.compile(r"^[0-9a-f]{64}$")
        assert pattern.match("a" * 64)
        assert not pattern.match("A" * 64)
        assert not pattern.match("a" * 63)
        assert not pattern.match("a" * 65)
        assert not pattern.match("g" * 64)

    @pytest.mark.parametrize("table, constraint, column, enum_type", [
        ("alert_decisions", "chk_alert_decisions_severity", "severity", Severity),
        ("alert_decisions", "chk_alert_decisions_confidence", "confidence",
         Confidence),
        ("alert_decisions", "chk_alert_decisions_decision", "decision", Decision),
        ("alert_decisions", "chk_alert_decisions_reason_code", "reason_code",
         ReasonCode),
        ("alert_delivery_attempts", "chk_alert_delivery_attempts_channel_type",
         "channel_type", ChannelType),
        ("alert_delivery_attempts", "chk_alert_delivery_attempts_trigger",
         "trigger", DeliveryTrigger),
        ("alert_delivery_outcomes", "chk_alert_delivery_outcomes_outcome",
         "outcome", DeliveryOutcome),
    ])
    def test_vocabulary_matches_the_contract_enums(
        self, table, constraint, column, enum_type,
    ):
        definition = _constraints(table)[constraint]
        assert definition.startswith(f"CHECK ({column} IN (")
        assert _in_list(definition) == {member.value for member in enum_type}

    def test_exact_reason_codes(self):
        definition = _constraints("alert_decisions")["chk_alert_decisions_reason_code"]
        assert _in_list(definition) == {
            "severity_met", "escalation", "kill_switch", "duplicate_anomaly",
            "cooldown", "storm_cap", "below_min_severity", "stale",
        }

    def test_exact_decisions(self):
        definition = _constraints("alert_decisions")["chk_alert_decisions_decision"]
        assert _in_list(definition) == {"ALERT", "SUPPRESSED", "NOT_ALERTABLE"}

    def test_exact_outcomes(self):
        definition = _constraints("alert_delivery_outcomes")[
            "chk_alert_delivery_outcomes_outcome"
        ]
        assert _in_list(definition) == {
            "SENT", "FAILED_RETRYABLE", "FAILED_PERMANENT", "UNCERTAIN",
        }

    def test_attempt_no_at_least_one(self):
        assert _constraints("alert_delivery_attempts")[
            "chk_alert_delivery_attempts_attempt_no"
        ] == "CHECK (attempt_no >= 1)"

    def test_payload_iff_alert(self):
        assert _constraints("alert_decisions")[
            "chk_alert_decisions_payload_iff_alert"
        ] == "CHECK ((decision = 'ALERT') = (payload IS NOT NULL))"

    def test_summary_only_for_alert(self):
        assert _constraints("alert_decisions")[
            "chk_alert_decisions_summary_only_for_alert"
        ] == "CHECK (summary IS NULL OR decision = 'ALERT')"

    def test_summary_truncated_requires_summary(self):
        assert _constraints("alert_decisions")[
            "chk_alert_decisions_summary_truncated"
        ] == "CHECK (NOT summary_truncated OR summary IS NOT NULL)"

    def test_exact_constraint_names(self):
        assert set(_constraints("alert_policies")) == {
            "pk_alert_policies",
            "chk_alert_policies_policy_sha256",
        }
        assert set(_constraints("alert_decisions")) == {
            "pk_alert_decisions",
            "fk_alert_decisions_investigation",
            "fk_alert_decisions_policy",
            "fk_alert_decisions_related_decision",
            "uq_alert_decisions_investigation_policy",
            "chk_alert_decisions_decision_id",
            "chk_alert_decisions_dedup_key",
            "chk_alert_decisions_severity",
            "chk_alert_decisions_confidence",
            "chk_alert_decisions_decision",
            "chk_alert_decisions_reason_code",
            "chk_alert_decisions_decision_reason",
            "chk_alert_decisions_related_decision_required",
            "chk_alert_decisions_related_decision_not_self",
            "chk_alert_decisions_payload_iff_alert",
            "chk_alert_decisions_summary_only_for_alert",
            "chk_alert_decisions_summary_truncated",
        }
        assert set(_constraints("alert_delivery_attempts")) == {
            "pk_alert_delivery_attempts",
            "fk_alert_delivery_attempts_decision",
            "uq_alert_delivery_attempts_decision_channel_no",
            "chk_alert_delivery_attempts_attempt_id",
            "chk_alert_delivery_attempts_payload_sha256",
            "chk_alert_delivery_attempts_channel_type",
            "chk_alert_delivery_attempts_attempt_no",
            "chk_alert_delivery_attempts_trigger",
        }
        assert set(_constraints("alert_delivery_outcomes")) == {
            "pk_alert_delivery_outcomes",
            "fk_alert_delivery_outcomes_attempt",
            "chk_alert_delivery_outcomes_outcome",
        }

    def test_constraint_names_are_unique_across_tables(self):
        names = [name for table in _TABLES for name in _constraints(table)]
        assert len(names) == len(set(names))

    def test_no_check_mentions_confidence_except_its_vocabulary(self):
        for name, definition in _constraints("alert_decisions").items():
            if name != "chk_alert_decisions_confidence":
                assert "confidence" not in definition, name


# ---------------------------------------------------------------------------
# 5. Decision / reason pairing and related_decision_id
# ---------------------------------------------------------------------------

class TestPairing:
    @staticmethod
    def _pairing() -> dict[str, set[str]]:
        definition = _constraints("alert_decisions")[
            "chk_alert_decisions_decision_reason"
        ]
        branches = re.findall(
            r"\(decision = '([A-Z_]+)' AND reason_code IN \(([^()]*)\)\)",
            definition,
        )
        return {
            decision: set(re.findall(r"'([^']*)'", reasons))
            for decision, reasons in branches
        }

    def test_pairing_is_exact(self):
        assert self._pairing() == {
            "ALERT": {"severity_met", "escalation"},
            "SUPPRESSED": {
                "kill_switch", "duplicate_anomaly", "cooldown", "storm_cap",
            },
            "NOT_ALERTABLE": {"below_min_severity", "stale"},
        }

    def test_pairing_matches_the_contract_table(self):
        assert self._pairing() == {
            decision.value: {reason.value for reason in reasons}
            for decision, reasons in REASONS_BY_DECISION.items()
        }

    def test_pairing_branches_are_joined_by_or_only(self):
        definition = _constraints("alert_decisions")[
            "chk_alert_decisions_decision_reason"
        ]
        assert definition.count(" OR ") == 2
        assert definition.count("decision = ") == 3

    def test_every_reason_is_paired_exactly_once(self):
        paired = [r for reasons in self._pairing().values() for r in reasons]
        assert sorted(paired) == sorted(member.value for member in ReasonCode)

    def test_related_decision_required_for_exactly_three_reasons(self):
        definition = _constraints("alert_decisions")[
            "chk_alert_decisions_related_decision_required"
        ]
        assert definition == (
            "CHECK ( (reason_code IN ('escalation', 'duplicate_anomaly', "
            "'cooldown')) = (related_decision_id IS NOT NULL) )"
        )
        assert _in_list(definition) == {
            reason.value for reason in REASONS_WITH_RELATED_DECISION
        }

    def test_related_decision_cannot_be_itself(self):
        assert _constraints("alert_decisions")[
            "chk_alert_decisions_related_decision_not_self"
        ] == "CHECK (related_decision_id IS NULL OR related_decision_id <> decision_id)"


# ---------------------------------------------------------------------------
# 6. Indexes
# ---------------------------------------------------------------------------

class TestIndexes:
    @staticmethod
    def _indexes() -> list[str]:
        return [s for s in _statements(_M012) if s.startswith("CREATE INDEX")]

    def test_exactly_three_indexes(self):
        assert len(self._indexes()) == 3

    def test_index_definitions(self):
        assert self._indexes() == [
            "CREATE INDEX idx_alert_decisions_alert_dedup_event_time "
            "ON public.alert_decisions (dedup_key, event_time) "
            "WHERE decision = 'ALERT'",
            "CREATE INDEX idx_alert_decisions_alert_event_time "
            "ON public.alert_decisions (event_time) "
            "WHERE decision = 'ALERT'",
            "CREATE INDEX idx_alert_decisions_alert_anomaly_id "
            "ON public.alert_decisions (anomaly_id) "
            "WHERE decision = 'ALERT'",
        ]

    def test_all_indexes_are_partial_on_alert(self):
        for statement in self._indexes():
            assert statement.endswith("WHERE decision = 'ALERT'")

    def test_no_unique_index(self):
        assert "CREATE UNIQUE INDEX" not in _sql(_M012)


# ---------------------------------------------------------------------------
# 7. Migration 012 grants nothing
# ---------------------------------------------------------------------------

class TestTableMigrationHasNoPrivileges:
    @pytest.mark.parametrize("forbidden", [
        "GRANT", "REVOKE", "CREATE ROLE", "ALTER", "DROP", "OWNER",
        "CREATE EXTENSION", "CREATE SCHEMA", "CREATE FUNCTION",
        "CREATE TRIGGER", "CREATE RULE", "CREATE VIEW", "INSERT", "COPY",
    ])
    def test_forbidden_statement(self, forbidden):
        assert forbidden not in _sql(_M012)

    def test_delete_appears_only_as_on_delete_restrict(self):
        sql = _sql(_M012)
        assert sql.count("DELETE") == sql.count("ON DELETE RESTRICT") == 5

    @pytest.mark.parametrize("word", ["UPDATE", "TRUNCATE"])
    def test_no_row_change_keyword(self, word):
        assert re.search(rf"\b{word}\b", _sql(_M012)) is None


# ---------------------------------------------------------------------------
# 8. alert_evaluator grants
# ---------------------------------------------------------------------------

_EVALUATOR = "alert_evaluator"

_EVALUATOR_GRANTS = {
    ("DATABASE", "agentops", "CONNECT", None, _EVALUATOR),
    ("SCHEMA", "public", "USAGE", None, _EVALUATOR),
    _table("public.rca_investigations", "SELECT", _EVALUATOR, {
        "investigation_id", "anomaly_id", "anomaly_type", "service_name",
        "operation_name", "event_time", "severity", "confidence",
        "limitations", "summary",
    }),
    _table("public.alert_policies", "INSERT", _EVALUATOR),
    _table("public.alert_policies", "SELECT", _EVALUATOR),
    _table("public.alert_decisions", "INSERT", _EVALUATOR),
    _table("public.alert_decisions", "SELECT", _EVALUATOR),
    _table("public.anomaly_events", "SELECT", _EVALUATOR, {
        "anomaly_id", "detected_at",
    }),
    _table("public.anomaly_detector_runs", "SELECT", _EVALUATOR, {
        "signal_path", "service_name", "operation_name", "updated_at",
    }),
    _table("public.alert_delivery_attempts", "SELECT", _EVALUATOR),
    _table("public.alert_delivery_outcomes", "SELECT", _EVALUATOR),
}


class TestEvaluatorRole:
    def test_role_creation(self):
        assert _statements(_M013)[0] == (
            "CREATE ROLE alert_evaluator WITH LOGIN PASSWORD "
            ":'alert_evaluator_password'"
        )

    def test_exactly_one_role_created(self):
        assert _sql(_M013).count("CREATE ROLE") == 1

    def test_exact_grant_matrix(self):
        assert _grants(_M013) == _EVALUATOR_GRANTS

    def test_every_grant_is_to_the_evaluator(self):
        assert {grant[4] for grant in _grants(_M013)} == {_EVALUATOR}

    def test_only_select_and_insert_on_tables(self):
        privileges = {g[2] for g in _grants(_M013) if g[0] == "TABLE"}
        assert privileges == {"SELECT", "INSERT"}

    def test_insert_only_on_policies_and_decisions(self):
        inserts = {g[1] for g in _grants(_M013) if g[2] == "INSERT"}
        assert inserts == {"public.alert_policies", "public.alert_decisions"}

    def test_cannot_write_delivery_tables(self):
        for grant in _grants(_M013):
            if grant[1] in (
                "public.alert_delivery_attempts",
                "public.alert_delivery_outcomes",
            ):
                assert grant[2] == "SELECT"

    @pytest.mark.parametrize("table", [
        "public.rca_investigations", "public.anomaly_events",
        "public.anomaly_detector_runs",
    ])
    def test_existing_tables_are_read_by_column_only(self, table):
        grants = [g for g in _grants(_M013) if g[1] == table]
        assert len(grants) == 1
        assert grants[0][2] == "SELECT"
        assert grants[0][3] is not None

    def test_checkpoint_at_is_not_exposed(self):
        (grant,) = [
            g for g in _grants(_M013) if g[1] == "public.anomaly_detector_runs"
        ]
        assert "checkpoint_at" not in grant[3]

    @pytest.mark.parametrize("forbidden", [
        "rca_evidence", "rca_investigation_embeddings", "telemetry_spans",
        "analytics", "stg_telemetry_spans", "mart_",
    ])
    def test_no_access_to_forbidden_objects(self, forbidden):
        assert forbidden not in _sql(_M013)

    def test_guardrail_columns_exist_in_the_locked_schema(self):
        runs = _raw("006_create_anomaly_detector_runs.sql")
        for column in ("signal_path", "service_name", "operation_name", "updated_at"):
            assert re.search(rf"^\s+{column}\s+(TEXT|TIMESTAMPTZ)", runs, re.M), column
        events = _raw("004_create_anomaly_events.sql")
        for column in ("anomaly_id", "detected_at"):
            assert re.search(rf"^\s+{column}\s+(TEXT|TIMESTAMPTZ)", events, re.M), column

    def test_investigation_columns_exist_in_the_locked_schema(self):
        rca = _raw("007_create_rca_tables.sql")
        (grant,) = [
            g for g in _grants(_M013) if g[1] == "public.rca_investigations"
        ]
        for column in grant[3]:
            assert re.search(rf"^\s+{column}\s+(TEXT|TIMESTAMPTZ)", rca, re.M), column


# ---------------------------------------------------------------------------
# 9. alert_notifier grants
# ---------------------------------------------------------------------------

_NOTIFIER = "alert_notifier"

_NOTIFIER_DECISION_COLUMNS = {
    "decision_id", "decision", "reason_code", "policy_version",
    "evaluated_at", "payload", "summary", "summary_truncated",
}

_NOTIFIER_GRANTS = {
    ("DATABASE", "agentops", "CONNECT", None, _NOTIFIER),
    ("SCHEMA", "public", "USAGE", None, _NOTIFIER),
    _table("public.alert_decisions", "SELECT", _NOTIFIER,
           _NOTIFIER_DECISION_COLUMNS),
    _table("public.alert_delivery_attempts", "INSERT", _NOTIFIER),
    _table("public.alert_delivery_attempts", "SELECT", _NOTIFIER),
    _table("public.alert_delivery_outcomes", "INSERT", _NOTIFIER),
    _table("public.alert_delivery_outcomes", "SELECT", _NOTIFIER),
}


class TestNotifierRole:
    def test_role_creation(self):
        assert _statements(_M014)[0] == (
            "CREATE ROLE alert_notifier WITH LOGIN PASSWORD "
            ":'alert_notifier_password'"
        )

    def test_exactly_one_role_created(self):
        assert _sql(_M014).count("CREATE ROLE") == 1

    def test_exact_grant_matrix(self):
        assert _grants(_M014) == _NOTIFIER_GRANTS

    def test_every_grant_is_to_the_notifier(self):
        assert {grant[4] for grant in _grants(_M014)} == {_NOTIFIER}

    def test_only_select_and_insert_on_tables(self):
        privileges = {g[2] for g in _grants(_M014) if g[0] == "TABLE"}
        assert privileges == {"SELECT", "INSERT"}

    def test_insert_only_on_delivery_tables(self):
        inserts = {g[1] for g in _grants(_M014) if g[2] == "INSERT"}
        assert inserts == {
            "public.alert_delivery_attempts", "public.alert_delivery_outcomes",
        }

    def test_decisions_are_read_by_column_only(self):
        grants = [g for g in _grants(_M014) if g[1] == "public.alert_decisions"]
        assert len(grants) == 1
        assert grants[0][2] == "SELECT"
        assert grants[0][3] == frozenset(_NOTIFIER_DECISION_COLUMNS)

    def test_decision_columns_exist_in_migration_012(self):
        assert _NOTIFIER_DECISION_COLUMNS <= set(_columns("alert_decisions"))

    def test_hidden_decision_columns(self):
        hidden = set(_columns("alert_decisions")) - _NOTIFIER_DECISION_COLUMNS
        assert hidden == {
            "investigation_id", "anomaly_id", "anomaly_type", "service_name",
            "operation_name", "event_time", "severity", "confidence",
            "limitations", "dedup_key", "related_decision_id", "decided_at",
        }

    @pytest.mark.parametrize("forbidden", [
        "rca_investigations", "rca_evidence", "rca_investigation_embeddings",
        "anomaly_events", "anomaly_detector_runs", "telemetry_spans",
        "analytics", "alert_policies",
    ])
    def test_no_access_to_forbidden_objects(self, forbidden):
        assert forbidden not in _sql(_M014)


class TestRoleSeparation:
    def test_roles_are_distinct_and_do_not_grant_to_each_other(self):
        assert _NOTIFIER not in _sql(_M013)
        assert _EVALUATOR not in _sql(_M014)

    def test_no_table_is_writable_by_both_roles(self):
        evaluator = {g[1] for g in _grants(_M013) if g[2] == "INSERT"}
        notifier = {g[1] for g in _grants(_M014) if g[2] == "INSERT"}
        assert evaluator.isdisjoint(notifier)

    def test_every_alert_table_has_exactly_one_writer(self):
        writers: dict[str, set[str]] = {}
        for name in (_M013, _M014):
            for grant in _grants(name):
                if grant[2] == "INSERT":
                    writers.setdefault(grant[1], set()).add(grant[4])
        assert writers == {
            "public.alert_policies": {_EVALUATOR},
            "public.alert_decisions": {_EVALUATOR},
            "public.alert_delivery_attempts": {_NOTIFIER},
            "public.alert_delivery_outcomes": {_NOTIFIER},
        }

    def test_only_the_evaluator_reads_phase_10_and_11_tables(self):
        notifier_objects = {g[1] for g in _grants(_M014)}
        assert notifier_objects == {
            "agentops", "public", "public.alert_decisions",
            "public.alert_delivery_attempts", "public.alert_delivery_outcomes",
        }


# ---------------------------------------------------------------------------
# 10. No broad or dangerous privilege
# ---------------------------------------------------------------------------

_ROLE_MIGRATIONS = (_M013, _M014)


class TestNoBroadPrivileges:
    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    @pytest.mark.parametrize("word", [
        "UPDATE", "DELETE", "TRUNCATE", "ALL", "REFERENCES", "TRIGGER",
        "TEMPORARY", "TEMP", "EXECUTE", "MAINTAIN",
    ])
    def test_privilege_word_absent(self, name, word):
        assert re.search(rf"\b{word}\b", _sql(name)) is None

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    @pytest.mark.parametrize("phrase", [
        "ALL TABLES", "ALL PRIVILEGES", "ALL SEQUENCES", "IN SCHEMA",
        "DEFAULT PRIVILEGES", "TO PUBLIC", "WITH GRANT OPTION",
        "WITH ADMIN OPTION", "SEQUENCE", "CREATE ON", "REVOKE",
        "ALTER", "DROP", "OWNER", "SET ROLE", "IN ROLE", "INHERIT",
    ])
    def test_phrase_absent(self, name, phrase):
        assert phrase not in _sql(name)

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    @pytest.mark.parametrize("attribute", [
        "SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS",
    ])
    def test_role_attribute_absent(self, name, attribute):
        assert attribute not in _sql(name)

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_schema_privilege_is_usage_only(self, name):
        schema = [g for g in _grants(name) if g[0] == "SCHEMA"]
        assert [(g[1], g[2]) for g in schema] == [("public", "USAGE")]

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_database_privilege_is_connect_only(self, name):
        database = [g for g in _grants(name) if g[0] == "DATABASE"]
        assert [(g[1], g[2]) for g in database] == [("agentops", "CONNECT")]

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_every_table_grant_names_a_public_table_explicitly(self, name):
        for grant in _grants(name):
            if grant[0] == "TABLE":
                assert re.fullmatch(r"public\.[a-z_]+", grant[1]), grant

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_no_grant_touches_an_existing_role(self, name):
        sql = _sql(name)
        for existing in (
            "anomaly_detector ", "rca_analyzer", "incident_retrieval",
            "grafana_reader", "trace_viewer_reader",
        ):
            assert existing not in sql


# ---------------------------------------------------------------------------
# 11. No password or credential literal
# ---------------------------------------------------------------------------

class TestNoCredentials:
    @pytest.mark.parametrize("name, variable", [
        (_M013, "alert_evaluator_password"),
        (_M014, "alert_notifier_password"),
    ])
    def test_password_is_a_psql_variable(self, name, variable):
        sql = _sql(name)
        assert sql.count("PASSWORD") == 1
        assert f"PASSWORD :'{variable}'" in sql

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_no_quoted_string_literal_in_role_migrations(self, name):
        # The only quoted text is the psql variable reference :'name'.
        without_variable = re.sub(r":'[a-z_]+'", "", _sql(name))
        assert "'" not in without_variable
        assert '"' not in without_variable

    def test_table_migration_has_no_password(self):
        assert "PASSWORD" not in _sql(_M012).upper()

    @pytest.mark.parametrize("name", [_M012, _M013, _M014])
    def test_no_url_or_secret_anywhere_including_comments(self, name):
        text = _raw(name).lower()
        for forbidden in ("http://", "https://", "postgres://", "postgresql://",
                          "agentops_dev", "api_key", "apikey", "bearer "):
            assert forbidden not in text

    @pytest.mark.parametrize("name", _ROLE_MIGRATIONS)
    def test_comment_shows_a_placeholder_not_a_password(self, name):
        raw = _raw(name)
        assert "_password='<password>'" in raw
        assert len(re.findall(r"_password='", raw)) == 1


# ---------------------------------------------------------------------------
# 12. No SQL in the alerting component outside its database boundary
# ---------------------------------------------------------------------------

#: The only alerting modules that may hold SQL or import the database driver:
#: the evaluator's pair (Phase 13.4), the notifier's pair (Phase 13.5) and
#: the guardrails' read-only store (Phase 13.6).
#: Every other module is still checked.
_DB_BOUNDARY_MODULES = frozenset({
    "alert_db.py",
    "alert_store.py",
    "alert_notifier_db.py",
    "alert_delivery_store.py",
    "alert_guardrail_store.py",
})


class TestNoSqlOutsideMigrations:
    def test_db_boundary_is_exactly_five_top_level_modules(self):
        assert _DB_BOUNDARY_MODULES == {
            "alert_db.py",
            "alert_store.py",
            "alert_notifier_db.py",
            "alert_delivery_store.py",
            "alert_guardrail_store.py",
        }

    def test_no_python_module_below_the_top_level(self):
        # The check below reads top-level modules only, so no module may sit
        # in a subdirectory, where it would not be checked.
        found = []
        for entry in os.listdir(_ALERTING):
            path = os.path.join(_ALERTING, entry)
            if not os.path.isdir(path) or entry in ("tests", "__pycache__"):
                continue
            for root, _, names in os.walk(path):
                found.extend(
                    os.path.join(root, name)
                    for name in names if name.endswith(".py")
                )
        assert found == []

    def test_no_sql_file_in_alerting(self):
        found = [
            os.path.join(root, name)
            for root, _, names in os.walk(_ALERTING)
            for name in names
            if name.endswith(".sql")
        ]
        assert found == []

    def test_alerting_modules_contain_no_sql_or_driver(self):
        modules = [
            name for name in os.listdir(_ALERTING)
            if name.endswith(".py")
        ]
        assert modules
        statement = re.compile(
            r"\b(SELECT\s.+\sFROM|INSERT\s+INTO|CREATE\s+(TABLE|ROLE|INDEX)|"
            r"GRANT\s.+\sTO|ON\s+CONFLICT)\b",
            re.S,
        )
        assert _DB_BOUNDARY_MODULES < set(modules)
        for name in modules:
            if name in _DB_BOUNDARY_MODULES:
                continue
            with open(os.path.join(_ALERTING, name), encoding="utf-8") as fh:
                source = fh.read()
            assert statement.search(source) is None, name
            assert "psycopg" not in source, name
