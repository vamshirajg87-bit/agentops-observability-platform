"""
incident-retrieval/tests/unit/test_incident_signal.py

Unit tests for incident_signal.py.

All tests are pure Python — no database, no network, no I/O beyond reading
module sources for the boundary and parity checks.

Test inventory:
    S01  The four branches of the rule
    S02  Latency edge cases: None, empty, unknown and near-miss operations
    S03  Non-latency anomaly types pass through
    S04  Parity with the RCA analyzer rule (source comparison, no import)
    S05  Purity / import boundary
"""

from __future__ import annotations

import ast
import os

import pytest

import incident_signal
from incident_signal import derive_signal


_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "incident_signal.py")
_RCA_CONFIDENCE_PATH = os.path.join(
    _COMPONENT_DIR, "..", "rca-analyzer", "rca_confidence.py",
)


# ---------------------------------------------------------------------------
# S01  The four branches
# ---------------------------------------------------------------------------

class TestRuleBranches:

    def test_latency_trace_is_trace_latency(self):
        assert derive_signal("latency", "trace") == "trace_latency"

    def test_latency_tool_execute_is_tool_latency(self):
        assert derive_signal("latency", "tool.execute") == "tool_latency"

    def test_latency_other_operation_is_agent_latency(self):
        assert derive_signal("latency", "research/plan") == "agent_latency"

    def test_non_latency_returns_anomaly_type(self):
        assert derive_signal("tool_failure", "tool.execute/ToolExecutionError") == "tool_failure"

    def test_returns_str(self):
        assert type(derive_signal("latency", "trace")) is str


# ---------------------------------------------------------------------------
# S02  Latency edge cases
# ---------------------------------------------------------------------------

class TestLatencyEdgeCases:

    def test_none_operation_is_agent_latency(self):
        assert derive_signal("latency", None) == "agent_latency"

    def test_empty_operation_is_agent_latency(self):
        assert derive_signal("latency", "") == "agent_latency"

    @pytest.mark.parametrize(
        "operation",
        [
            "research/plan", "supervisor/start", "retrieval/search", "unknown",
            "tool.execute/ToolExecutionError", "tool.execute/", "tool.executeX",
            "traces", "trace/root", "trace ", " trace", "Trace", "TRACE",
            "Tool.Execute", "TOOL.EXECUTE", " tool.execute", "tool.execute ",
            "tool_execute", "tool", "execute",
        ],
    )
    def test_any_other_operation_is_agent_latency(self, operation):
        assert derive_signal("latency", operation) == "agent_latency"

    def test_match_is_exact_and_case_sensitive(self):
        assert derive_signal("latency", "trace") == "trace_latency"
        assert derive_signal("latency", "Trace") == "agent_latency"
        assert derive_signal("latency", "tool.execute") == "tool_latency"
        assert derive_signal("latency", "tool.execute ") == "agent_latency"

    @pytest.mark.parametrize("anomaly_type", ["Latency", "LATENCY", " latency", "latency ", "latencies"])
    def test_anomaly_type_match_is_exact(self, anomaly_type):
        """Only the exact string 'latency' takes the latency branches."""
        assert derive_signal(anomaly_type, "trace") == anomaly_type


# ---------------------------------------------------------------------------
# S03  Non-latency anomaly types
# ---------------------------------------------------------------------------

class TestNonLatency:

    @pytest.mark.parametrize("anomaly_type", ["retrieval_quality", "error_rate", "tool_failure"])
    @pytest.mark.parametrize(
        "operation",
        [None, "", "trace", "tool.execute", "tool.execute/ToolExecutionError", "research/plan"],
    )
    def test_anomaly_type_returned_unchanged(self, anomaly_type, operation):
        assert derive_signal(anomaly_type, operation) == anomaly_type

    def test_unknown_anomaly_type_passes_through(self):
        assert derive_signal("something_new", "trace") == "something_new"

    def test_operation_is_ignored_for_non_latency(self):
        assert derive_signal("error_rate", "trace") == derive_signal("error_rate", "tool.execute")

    def test_deterministic(self):
        assert {derive_signal("latency", "x") for _ in range(10)} == {"agent_latency"}

    def test_signal_vocabulary(self):
        """The six signal names produced for the four valid anomaly types."""
        produced = {
            derive_signal("latency", "trace"),
            derive_signal("latency", "tool.execute"),
            derive_signal("latency", "other"),
            derive_signal("retrieval_quality", None),
            derive_signal("error_rate", None),
            derive_signal("tool_failure", None),
        }
        assert produced == {
            "trace_latency", "tool_latency", "agent_latency",
            "retrieval_quality", "error_rate", "tool_failure",
        }


# ---------------------------------------------------------------------------
# S04  Parity with the RCA analyzer rule
# ---------------------------------------------------------------------------

class _AnomalyFieldsToNames(ast.NodeTransformer):
    """Rewrite `anomaly.<field>` to the plain name `<field>`."""

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        if isinstance(node.value, ast.Name) and node.value.id == "anomaly":
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return self.generic_visit(node)


def _function_body_dump(path: str, name: str, rename_anomaly: bool = False) -> str:
    """AST dump of a function body with the docstring removed."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    body = function.body
    if (
        body and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if rename_anomaly:
        body = [_AnomalyFieldsToNames().visit(node) for node in body]
    return "\n".join(ast.dump(node) for node in body)


class TestParityWithRcaAnalyzer:

    def test_rule_matches_rca_confidence_source(self):
        """
        The RCA analyzer rule is compared as source, without importing it.
        Its body uses `anomaly.anomaly_type` / `anomaly.operation_name`; ours
        uses the two plain arguments.  After that renaming the logic must be
        identical.
        """
        ours = _function_body_dump(_MODULE_PATH, "derive_signal")
        theirs = _function_body_dump(
            _RCA_CONFIDENCE_PATH, "_derive_signal", rename_anomaly=True,
        )
        assert ours == theirs
        assert "trace_latency" in ours and "tool_latency" in ours


# ---------------------------------------------------------------------------
# S05  Purity / import boundary
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestPurityBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(incident_signal.__file__) == _MODULE_PATH

    def test_imports_are_standard_library_only(self, module_tree):
        assert _imported_modules(module_tree) <= {"__future__", "typing"}

    @pytest.mark.parametrize(
        "forbidden",
        ["rca_confidence", "rca_ranker", "rca_source", "rca_models", "psycopg",
         "incident_document", "embedding_provider", "os", "sys"],
    )
    def test_forbidden_module_not_imported(self, module_tree, forbidden):
        assert forbidden not in _imported_modules(module_tree)

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(incident_signal).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "incident_signal"
        }
        assert defined_here == {"derive_signal"}
