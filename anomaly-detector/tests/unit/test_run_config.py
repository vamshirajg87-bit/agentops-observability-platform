"""
Tests for anomaly-detector/run_config.py

No live PostgreSQL required.  No filesystem access required for most tests —
_validate_config_dict() is exercised directly; load_config() file-I/O tests
use pytest's tmp_path fixture.

Correct invocation from repo root:
    PYTHONPATH=anomaly-detector python -m pytest anomaly-detector/tests/unit/test_run_config.py -q

Coverage:
    TestConstants
        VALID_SIGNAL_PATHS has exactly six entries and the right values
        _OP_REQUIRED and _OP_FORBIDDEN are disjoint
        their union equals VALID_SIGNAL_PATHS

    TestPositiveIntValidation
        overlap_minutes: bool True rejected
        overlap_minutes: bool False rejected
        overlap_minutes: float rejected
        overlap_minutes: numeric string rejected
        overlap_minutes: zero rejected
        overlap_minutes: negative rejected
        initial_lookback_hours: bool True rejected
        initial_lookback_hours: float rejected
        initial_lookback_hours: zero rejected
        initial_lookback_hours: negative rejected

    TestRootStructure
        root list rejected
        root string rejected
        root None rejected
        unknown root key rejected
        misspelled root key rejected
        missing 'run' section rejected
        missing 'groups' key rejected

    TestRunSection
        run not dict rejected
        run list rejected
        unknown run key rejected
        misspelled overlap key rejected
        missing overlap_minutes rejected
        missing initial_lookback_hours rejected

    TestGroupsSection
        groups not dict rejected
        groups string rejected
        empty groups list rejected

    TestGroupStructure
        group not dict rejected
        group list rejected
        unknown group key rejected
        misspelled service key rejected
        missing signal_path rejected
        missing service_name rejected

    TestSignalPath
        each of the six valid signal paths accepted (parametrized)
        unknown signal_path rejected
        empty signal_path rejected
        signal_path not a string rejected

    TestServiceName
        valid service_name accepted and preserved exactly
        service_name with internal whitespace accepted
        empty service_name rejected
        whitespace-only service_name rejected

    TestOperationNameOpRequired
        valid operation_name accepted and preserved (parametrized x 3 signals)
        null rejected (parametrized x 3)
        missing rejected (parametrized x 3)
        empty string rejected (parametrized x 3)
        whitespace-only rejected (parametrized x 3)

    TestOperationNameOpForbidden
        null normalises to '' (parametrized x 3)
        missing key normalises to '' (parametrized x 3)
        empty string normalises to '' (parametrized x 3)
        non-empty string rejected (parametrized x 3)
        whitespace-only string rejected (parametrized x 3)

    TestDuplicateGroups
        identical op-required groups rejected
        identical op-forbidden groups rejected
        null and missing are duplicates (normalisation before dedup)
        null and "" are duplicates (normalisation before dedup)
        different service names are not duplicates
        different operation names are not duplicates
        same service different signal paths are not duplicates

    TestDataclassImmutability
        GroupConfig frozen — mutation raises
        RunConfig frozen — mutation raises
        groups field is a tuple
        tuple has no append

    TestValidConfig
        minimal config loads without error
        multiple groups accepted
        groups preserved in declaration order
        overlap_minutes value preserved
        initial_lookback_hours value preserved

    TestLoadConfig
        valid JSON file loads correctly
        accepts pathlib.Path
        accepts str path
        file not found raises FileNotFoundError
        invalid JSON raises json.JSONDecodeError
        groups field is tuple after file load
"""

from __future__ import annotations

import json
import pathlib

import pytest

from run_config import (
    VALID_SIGNAL_PATHS,
    GroupConfig,
    RunConfig,
    _OP_FORBIDDEN,
    _OP_REQUIRED,
    _validate_config_dict,
    load_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_config(
    *,
    overlap_minutes: object = 5,
    initial_lookback_hours: object = 24,
    groups: list | None = None,
) -> dict:
    if groups is None:
        groups = [_valid_group_trace()]
    return {
        "run": {
            "overlap_minutes": overlap_minutes,
            "initial_lookback_hours": initial_lookback_hours,
        },
        "groups": groups,
    }


def _valid_group_trace(
    service_name: str = "demo-service",
    operation_name: str = "chat",
) -> dict:
    return {
        "signal_path": "trace_latency",
        "service_name": service_name,
        "operation_name": operation_name,
    }


def _valid_group_op_forbidden(
    signal_path: str = "tool_latency",
    service_name: str = "demo-service",
) -> dict:
    return {
        "signal_path": signal_path,
        "service_name": service_name,
    }


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------

class TestConstants:

    def test_valid_signal_paths_has_exactly_six_entries(self):
        assert len(VALID_SIGNAL_PATHS) == 6

    def test_valid_signal_paths_contains_all_expected(self):
        expected = {
            "trace_latency", "agent_latency", "tool_latency",
            "retrieval", "error_rate", "tool_failure",
        }
        assert VALID_SIGNAL_PATHS == expected

    def test_op_required_and_op_forbidden_are_disjoint(self):
        assert _OP_REQUIRED.isdisjoint(_OP_FORBIDDEN)

    def test_op_required_union_op_forbidden_equals_valid_paths(self):
        assert _OP_REQUIRED | _OP_FORBIDDEN == VALID_SIGNAL_PATHS

    def test_op_required_contains_expected_paths(self):
        assert _OP_REQUIRED == {"trace_latency", "agent_latency", "error_rate"}

    def test_op_forbidden_contains_expected_paths(self):
        assert _OP_FORBIDDEN == {"tool_latency", "retrieval", "tool_failure"}


# ---------------------------------------------------------------------------
# TestPositiveIntValidation
# ---------------------------------------------------------------------------

class TestPositiveIntValidation:

    def test_overlap_minutes_bool_true_rejected(self):
        with pytest.raises(ValueError, match="bool"):
            _validate_config_dict(_valid_config(overlap_minutes=True))

    def test_overlap_minutes_bool_false_rejected(self):
        with pytest.raises(ValueError, match="bool"):
            _validate_config_dict(_valid_config(overlap_minutes=False))

    def test_overlap_minutes_float_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(overlap_minutes=5.0))

    def test_overlap_minutes_numeric_string_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(overlap_minutes="5"))

    def test_overlap_minutes_zero_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_config_dict(_valid_config(overlap_minutes=0))

    def test_overlap_minutes_negative_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_config_dict(_valid_config(overlap_minutes=-1))

    def test_initial_lookback_hours_bool_true_rejected(self):
        with pytest.raises(ValueError, match="bool"):
            _validate_config_dict(_valid_config(initial_lookback_hours=True))

    def test_initial_lookback_hours_float_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(initial_lookback_hours=24.0))

    def test_initial_lookback_hours_zero_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_config_dict(_valid_config(initial_lookback_hours=0))

    def test_initial_lookback_hours_negative_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_config_dict(_valid_config(initial_lookback_hours=-24))


# ---------------------------------------------------------------------------
# TestRootStructure
# ---------------------------------------------------------------------------

class TestRootStructure:

    def test_root_list_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict([])

    def test_root_string_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict("not a dict")

    def test_root_none_rejected(self):
        with pytest.raises(ValueError):
            _validate_config_dict(None)

    def test_unknown_root_key_rejected(self):
        cfg = _valid_config()
        cfg["logging"] = {"level": "DEBUG"}
        with pytest.raises(ValueError, match="logging"):
            _validate_config_dict(cfg)

    def test_misspelled_run_key_rejected(self):
        cfg = {
            "Run": {"overlap_minutes": 5, "initial_lookback_hours": 24},
            "groups": [_valid_group_trace()],
        }
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_missing_run_section_raises(self):
        cfg = _valid_config()
        del cfg["run"]
        with pytest.raises(ValueError, match="run"):
            _validate_config_dict(cfg)

    def test_missing_groups_key_raises(self):
        cfg = _valid_config()
        del cfg["groups"]
        with pytest.raises(ValueError, match="groups"):
            _validate_config_dict(cfg)


# ---------------------------------------------------------------------------
# TestRunSection
# ---------------------------------------------------------------------------

class TestRunSection:

    def test_run_not_dict_raises(self):
        cfg = _valid_config()
        cfg["run"] = "invalid"
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_run_list_raises(self):
        cfg = _valid_config()
        cfg["run"] = [5, 24]
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_unknown_run_key_rejected(self):
        cfg = _valid_config()
        cfg["run"]["timeout_seconds"] = 60
        with pytest.raises(ValueError, match="timeout_seconds"):
            _validate_config_dict(cfg)

    def test_misspelled_overlap_key_rejected(self):
        cfg = _valid_config()
        cfg["run"]["overlap_minute"] = cfg["run"].pop("overlap_minutes")
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_missing_overlap_minutes_raises(self):
        cfg = _valid_config()
        del cfg["run"]["overlap_minutes"]
        with pytest.raises(ValueError, match="overlap_minutes"):
            _validate_config_dict(cfg)

    def test_missing_initial_lookback_hours_raises(self):
        cfg = _valid_config()
        del cfg["run"]["initial_lookback_hours"]
        with pytest.raises(ValueError, match="initial_lookback_hours"):
            _validate_config_dict(cfg)


# ---------------------------------------------------------------------------
# TestGroupsSection
# ---------------------------------------------------------------------------

class TestGroupsSection:

    def test_groups_not_list_raises(self):
        cfg = _valid_config()
        cfg["groups"] = {}
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_groups_string_raises(self):
        cfg = _valid_config()
        cfg["groups"] = "not a list"
        with pytest.raises(ValueError):
            _validate_config_dict(cfg)

    def test_empty_groups_list_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            _validate_config_dict(_valid_config(groups=[]))


# ---------------------------------------------------------------------------
# TestGroupStructure
# ---------------------------------------------------------------------------

class TestGroupStructure:

    def test_group_not_dict_raises(self):
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=["not a dict"]))

    def test_group_list_raises(self):
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=[["trace_latency", "svc", "op"]]))

    def test_unknown_group_key_rejected(self):
        group = _valid_group_trace()
        group["enabled"] = True
        with pytest.raises(ValueError, match="enabled"):
            _validate_config_dict(_valid_config(groups=[group]))

    def test_misspelled_service_key_rejected(self):
        group = {
            "signal_path": "trace_latency",
            "service": "demo-service",
            "operation_name": "chat",
        }
        with pytest.raises(ValueError, match="service"):
            _validate_config_dict(_valid_config(groups=[group]))

    def test_missing_signal_path_raises(self):
        group = {"service_name": "demo-service", "operation_name": "chat"}
        with pytest.raises(ValueError, match="signal_path"):
            _validate_config_dict(_valid_config(groups=[group]))

    def test_missing_service_name_raises(self):
        group = {"signal_path": "trace_latency", "operation_name": "chat"}
        with pytest.raises(ValueError, match="service_name"):
            _validate_config_dict(_valid_config(groups=[group]))


# ---------------------------------------------------------------------------
# TestSignalPath
# ---------------------------------------------------------------------------

class TestSignalPath:

    @pytest.mark.parametrize("signal_path", sorted(VALID_SIGNAL_PATHS))
    def test_each_valid_signal_path_accepted(self, signal_path: str):
        if signal_path in _OP_REQUIRED:
            group = {
                "signal_path": signal_path,
                "service_name": "demo-service",
                "operation_name": "some-op",
            }
        else:
            group = {
                "signal_path": signal_path,
                "service_name": "demo-service",
            }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].signal_path == signal_path

    def test_unknown_signal_path_raises(self):
        group = _valid_group_trace()
        group["signal_path"] = "span_latency"
        with pytest.raises(ValueError, match="span_latency"):
            _validate_config_dict(_valid_config(groups=[group]))

    def test_empty_signal_path_raises(self):
        group = _valid_group_trace()
        group["signal_path"] = ""
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=[group]))

    def test_signal_path_not_string_raises(self):
        group = _valid_group_trace()
        group["signal_path"] = 42
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=[group]))


# ---------------------------------------------------------------------------
# TestServiceName
# ---------------------------------------------------------------------------

class TestServiceName:

    def test_valid_service_name_accepted(self):
        result = _validate_config_dict(_valid_config(groups=[_valid_group_trace(service_name="my-service")]))
        assert result.groups[0].service_name == "my-service"

    def test_service_name_preserved_exactly(self):
        name = "agentops-demo-app"
        result = _validate_config_dict(_valid_config(groups=[_valid_group_trace(service_name=name)]))
        assert result.groups[0].service_name == name

    def test_service_name_with_internal_whitespace_accepted(self):
        name = "my service app"
        result = _validate_config_dict(_valid_config(groups=[_valid_group_trace(service_name=name)]))
        assert result.groups[0].service_name == name

    def test_empty_service_name_raises(self):
        with pytest.raises(ValueError, match="service_name"):
            _validate_config_dict(_valid_config(groups=[_valid_group_trace(service_name="")]))

    def test_whitespace_only_service_name_raises(self):
        with pytest.raises(ValueError, match="service_name"):
            _validate_config_dict(_valid_config(groups=[_valid_group_trace(service_name="   ")]))


# ---------------------------------------------------------------------------
# TestOperationNameOpRequired
# ---------------------------------------------------------------------------

class TestOperationNameOpRequired:

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_valid_operation_name_accepted(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "some.operation",
        }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].operation_name == "some.operation"

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_operation_name_preserved_exactly(self, signal_path: str):
        op = "agent.run/v2"
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": op,
        }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].operation_name == op

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_null_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": None,
        }
        with pytest.raises(ValueError, match="operation_name"):
            _validate_config_dict(_valid_config(groups=[group]))

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_missing_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
        }
        with pytest.raises(ValueError, match="operation_name"):
            _validate_config_dict(_valid_config(groups=[group]))

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_empty_string_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "",
        }
        with pytest.raises(ValueError, match="operation_name"):
            _validate_config_dict(_valid_config(groups=[group]))

    @pytest.mark.parametrize("signal_path", sorted(_OP_REQUIRED))
    def test_whitespace_only_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "  ",
        }
        with pytest.raises(ValueError, match="whitespace"):
            _validate_config_dict(_valid_config(groups=[group]))


# ---------------------------------------------------------------------------
# TestOperationNameOpForbidden
# ---------------------------------------------------------------------------

class TestOperationNameOpForbidden:

    @pytest.mark.parametrize("signal_path", sorted(_OP_FORBIDDEN))
    def test_null_normalises_to_empty_string(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": None,
        }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].operation_name == ""

    @pytest.mark.parametrize("signal_path", sorted(_OP_FORBIDDEN))
    def test_missing_key_normalises_to_empty_string(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
        }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].operation_name == ""

    @pytest.mark.parametrize("signal_path", sorted(_OP_FORBIDDEN))
    def test_empty_string_normalises_to_empty_string(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "",
        }
        result = _validate_config_dict(_valid_config(groups=[group]))
        assert result.groups[0].operation_name == ""

    @pytest.mark.parametrize("signal_path", sorted(_OP_FORBIDDEN))
    def test_non_empty_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "some.op",
        }
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=[group]))

    @pytest.mark.parametrize("signal_path", sorted(_OP_FORBIDDEN))
    def test_whitespace_only_operation_name_raises(self, signal_path: str):
        group = {
            "signal_path": signal_path,
            "service_name": "demo-service",
            "operation_name": "  ",
        }
        with pytest.raises(ValueError):
            _validate_config_dict(_valid_config(groups=[group]))


# ---------------------------------------------------------------------------
# TestDuplicateGroups
# ---------------------------------------------------------------------------

class TestDuplicateGroups:

    def test_identical_op_required_groups_rejected(self):
        group = _valid_group_trace()
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            _validate_config_dict(_valid_config(groups=[group, group.copy()]))

    def test_identical_op_forbidden_groups_rejected(self):
        group = _valid_group_op_forbidden()
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            _validate_config_dict(_valid_config(groups=[group, group.copy()]))

    def test_null_and_missing_operation_name_are_duplicates(self):
        g1 = {"signal_path": "tool_latency", "service_name": "svc", "operation_name": None}
        g2 = {"signal_path": "tool_latency", "service_name": "svc"}
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            _validate_config_dict(_valid_config(groups=[g1, g2]))

    def test_null_and_empty_string_are_duplicates(self):
        g1 = {"signal_path": "retrieval", "service_name": "svc", "operation_name": None}
        g2 = {"signal_path": "retrieval", "service_name": "svc", "operation_name": ""}
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            _validate_config_dict(_valid_config(groups=[g1, g2]))

    def test_different_service_names_are_not_duplicates(self):
        g1 = _valid_group_trace(service_name="svc-a")
        g2 = _valid_group_trace(service_name="svc-b")
        result = _validate_config_dict(_valid_config(groups=[g1, g2]))
        assert len(result.groups) == 2

    def test_different_operation_names_are_not_duplicates(self):
        g1 = _valid_group_trace(operation_name="chat")
        g2 = _valid_group_trace(operation_name="search")
        result = _validate_config_dict(_valid_config(groups=[g1, g2]))
        assert len(result.groups) == 2

    def test_same_service_different_signal_paths_are_not_duplicates(self):
        g1 = {"signal_path": "trace_latency", "service_name": "svc", "operation_name": "op"}
        g2 = {"signal_path": "agent_latency", "service_name": "svc", "operation_name": "op"}
        result = _validate_config_dict(_valid_config(groups=[g1, g2]))
        assert len(result.groups) == 2


# ---------------------------------------------------------------------------
# TestDataclassImmutability
# ---------------------------------------------------------------------------

class TestDataclassImmutability:

    def test_group_config_is_frozen(self):
        gc = GroupConfig(
            signal_path="trace_latency",
            service_name="demo-service",
            operation_name="chat",
        )
        with pytest.raises((AttributeError, TypeError)):
            gc.signal_path = "agent_latency"  # type: ignore[misc]

    def test_run_config_is_frozen(self):
        rc = RunConfig(
            overlap_minutes=5,
            initial_lookback_hours=24,
            groups=(GroupConfig("trace_latency", "svc", "op"),),
        )
        with pytest.raises((AttributeError, TypeError)):
            rc.overlap_minutes = 10  # type: ignore[misc]

    def test_groups_field_is_tuple(self):
        result = _validate_config_dict(_valid_config())
        assert isinstance(result.groups, tuple)

    def test_groups_tuple_has_no_append(self):
        result = _validate_config_dict(_valid_config())
        with pytest.raises((TypeError, AttributeError)):
            result.groups.append(None)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# TestValidConfig
# ---------------------------------------------------------------------------

class TestValidConfig:

    def test_minimal_config_loads(self):
        result = _validate_config_dict(_valid_config())
        assert isinstance(result, RunConfig)
        assert result.overlap_minutes == 5
        assert result.initial_lookback_hours == 24
        assert len(result.groups) == 1

    def test_multiple_groups_accepted(self):
        groups = [
            _valid_group_trace(operation_name="chat"),
            _valid_group_trace(operation_name="search"),
            _valid_group_op_forbidden("tool_latency"),
        ]
        result = _validate_config_dict(_valid_config(groups=groups))
        assert len(result.groups) == 3

    def test_groups_preserved_in_declaration_order(self):
        groups = [
            _valid_group_trace(operation_name="chat"),
            _valid_group_trace(operation_name="search"),
        ]
        result = _validate_config_dict(_valid_config(groups=groups))
        assert result.groups[0].operation_name == "chat"
        assert result.groups[1].operation_name == "search"

    def test_overlap_minutes_preserved(self):
        result = _validate_config_dict(_valid_config(overlap_minutes=15))
        assert result.overlap_minutes == 15

    def test_initial_lookback_hours_preserved(self):
        result = _validate_config_dict(_valid_config(initial_lookback_hours=48))
        assert result.initial_lookback_hours == 48


# ---------------------------------------------------------------------------
# TestLoadConfig
# ---------------------------------------------------------------------------

class TestLoadConfig:

    def test_valid_json_file_loads(self, tmp_path: pathlib.Path):
        config_file = tmp_path / "runner_config.json"
        config_file.write_text(json.dumps(_valid_config()), encoding="utf-8")
        result = load_config(config_file)
        assert isinstance(result, RunConfig)
        assert result.overlap_minutes == 5

    def test_accepts_pathlib_path(self, tmp_path: pathlib.Path):
        config_file = tmp_path / "runner_config.json"
        config_file.write_text(json.dumps(_valid_config()), encoding="utf-8")
        result = load_config(pathlib.Path(config_file))
        assert isinstance(result, RunConfig)

    def test_accepts_str_path(self, tmp_path: pathlib.Path):
        config_file = tmp_path / "runner_config.json"
        config_file.write_text(json.dumps(_valid_config()), encoding="utf-8")
        result = load_config(str(config_file))
        assert isinstance(result, RunConfig)

    def test_file_not_found_raises(self, tmp_path: pathlib.Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.json")

    def test_invalid_json_raises_json_decode_error(self, tmp_path: pathlib.Path):
        config_file = tmp_path / "bad.json"
        config_file.write_text("{ not valid json }", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            load_config(config_file)

    def test_groups_field_is_tuple_after_file_load(self, tmp_path: pathlib.Path):
        config_file = tmp_path / "runner_config.json"
        config_file.write_text(json.dumps(_valid_config()), encoding="utf-8")
        result = load_config(config_file)
        assert isinstance(result.groups, tuple)
