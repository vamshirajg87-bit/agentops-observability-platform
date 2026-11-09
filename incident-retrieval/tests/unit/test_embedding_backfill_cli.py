"""
incident-retrieval/tests/unit/test_embedding_backfill_cli.py

Unit tests for embedding_backfill_cli.py.

No database, no model, no network.  retrieval_db.connect, the provider
factory, and backfill_embeddings are replaced; stdout / stderr are captured.

Test inventory:
    BC01  Arguments: the program takes none
    BC02  Wiring: provider, connection, backfill call
    BC03  Report: golden output
    BC04  Exit codes
    BC05  Connection ownership: rollback + close, never commit
    BC06  Model is not loaded by import or by a no-op run
    BC07  Boundaries: no SQL, no driver import, argparse only
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

import embedding_backfill_cli as cli
import retrieval_db
from embedding_backfill import BackfillReport, BackfillResult
from embedding_backfill_cli import main
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "embedding_backfill_cli.py")

_A, _B, _C, _D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)

_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_REV = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

_HEADER = "\n".join([
    "Embedding backfill",
    f"  model:       {_MODEL}",
    f"  revision:    {_REV}",
    "  doc version: 1.0.0",
    "",
    "Investigations",
])


def _result(investigation_id, status, error=None, token_usage=None) -> BackfillResult:
    embedding_id = None if status in ("not_eligible", "failure") else "e" * 64
    return BackfillResult(investigation_id, status, embedding_id, token_usage, error)


def _summary(total, inserted, already, not_eligible, mismatch, failures, result_line) -> str:
    return "\n".join([
        "",
        "Summary",
        f"  investigations:  {total}",
        f"  inserted:        {inserted}",
        f"  already_present: {already}",
        f"  not_eligible:    {not_eligible}",
        f"  text_mismatch:   {mismatch}",
        f"  failures:        {failures}",
        "",
        result_line,
    ])


class ExplodingBackend:
    """A backend that fails the test if the model is ever used or loaded."""

    is_loaded = False

    def __call__(self, text):
        raise AssertionError("the model must not be used by this test")

    def load(self):
        raise AssertionError("the model must not be loaded by this test")


class Harness:
    def __init__(self, monkeypatch) -> None:
        self.conn = MagicMock(name="connection")
        self.provider = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, _REV, 384), ExplodingBackend(),
        )
        self.provider_calls = 0
        self.connect_calls = 0
        self.connect_error: BaseException | None = None
        self.backfill_calls: list[tuple] = []
        self.results: list[BackfillResult] = []
        self.backfill_error: BaseException | None = None
        self.error_after: int | None = None
        monkeypatch.setattr(cli, "create_default_provider", self._provider)
        monkeypatch.setattr(cli.retrieval_db, "connect", self._connect)
        monkeypatch.setattr(cli, "backfill_embeddings", self._backfill)

    def _provider(self):
        self.provider_calls += 1
        return self.provider

    def _connect(self):
        self.connect_calls += 1
        if self.connect_error is not None:
            raise self.connect_error
        return self.conn

    def _backfill(self, conn, provider, *, on_result=None):
        self.backfill_calls.append((conn, provider, on_result))
        emitted = []
        for index, result in enumerate(self.results):
            if self.backfill_error is not None and index == self.error_after:
                raise self.backfill_error
            emitted.append(result)
            if on_result is not None:
                on_result(result)
        if self.backfill_error is not None and self.error_after in (None, len(self.results)):
            raise self.backfill_error
        return BackfillReport(tuple(emitted))


@pytest.fixture
def harness(monkeypatch) -> Harness:
    return Harness(monkeypatch)


# ---------------------------------------------------------------------------
# BC01  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    def test_runs_with_no_arguments(self, harness):
        assert main([]) == 0
        assert len(harness.backfill_calls) == 1

    @pytest.mark.parametrize(
        "argv", [["extra"], [_A], ["--top-k", "5"], ["--dry-run"], ["--force"], ["-x"]],
        ids=["positional", "investigation-id", "top-k", "dry-run", "force", "short"],
    )
    def test_any_argument_is_a_usage_error(self, harness, argv):
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 2
        assert harness.connect_calls == 0
        assert harness.backfill_calls == []
        assert harness.provider_calls == 0

    def test_help_exits_zero_without_connecting(self, harness, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = " ".join(capsys.readouterr().out.split())     # argparse wraps lines
        assert "Safe to rerun" in out and "nothing is overwritten" in out
        assert harness.connect_calls == 0

    def test_no_arguments_are_defined(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ]
        assert calls == []


# ---------------------------------------------------------------------------
# BC02  Wiring
# ---------------------------------------------------------------------------

class TestWiring:

    def test_default_provider_is_created_once(self, harness):
        main([])
        assert harness.provider_calls == 1

    def test_one_connection_from_retrieval_db(self, harness):
        main([])
        assert harness.connect_calls == 1

    def test_backfill_called_once_with_connection_and_provider(self, harness):
        main([])
        assert len(harness.backfill_calls) == 1
        conn, provider, on_result = harness.backfill_calls[0]
        assert conn is harness.conn
        assert provider is harness.provider
        assert callable(on_result)

    def test_real_factory_is_the_locked_default(self):
        import sentence_transformer_backend
        assert cli.create_default_provider is sentence_transformer_backend.create_default_provider

    def test_header_shows_the_locked_identity(self):
        import sentence_transformer_backend
        provider = sentence_transformer_backend.create_default_provider()
        assert cli.render_header(provider) == _HEADER
        assert provider.backend.is_loaded is False


# ---------------------------------------------------------------------------
# BC03  Golden output
# ---------------------------------------------------------------------------

class TestGoldenOutput:

    def test_first_run_inserted_and_not_eligible(self, harness, capsys):
        harness.results = [_result(_A, "inserted"), _result(_B, "not_eligible")]
        assert main([]) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == "\n".join([
            _HEADER,
            f"  {_A}  inserted",
            f"  {_B}  not_eligible",
            _summary(2, 1, 0, 1, 0, 0, "Result: completed"),
        ]) + "\n"

    def test_rerun_already_present(self, harness, capsys):
        harness.results = [_result(_A, "already_present"), _result(_B, "not_eligible")]
        assert main([]) == 0
        assert capsys.readouterr().out == "\n".join([
            _HEADER,
            f"  {_A}  already_present",
            f"  {_B}  not_eligible",
            _summary(2, 0, 1, 1, 0, 0, "Result: completed"),
        ]) + "\n"

    def test_no_investigations(self, harness, capsys):
        assert main([]) == 0
        assert capsys.readouterr().out == "\n".join([
            _HEADER,
            "  (none)",
            _summary(0, 0, 0, 0, 0, 0, "Result: completed"),
        ]) + "\n"

    def test_failure_and_text_mismatch(self, harness, capsys):
        harness.results = [
            _result(_A, "inserted"),
            _result(_B, "text_mismatch"),
            _result(_C, "failure", error="ValueError: duplicate rank_position 2"),
            _result(_D, "already_present"),
        ]
        assert main([]) == 6
        captured = capsys.readouterr()
        assert captured.out == "\n".join([
            _HEADER,
            f"  {_A}  inserted",
            f"  {_B}  text_mismatch",
            f"  {_C}  failure  ValueError: duplicate rank_position 2",
            f"  {_D}  already_present",
            _summary(
                4, 1, 1, 0, 1, 1,
                "Result: completed with problems (1 failed, 1 text_mismatch). "
                "Nothing was overwritten.",
            ),
        ]) + "\n"

    def test_truncated_document_is_flagged(self, harness, capsys):
        class Usage:
            truncated = True

        class NotTruncated:
            truncated = False

        harness.results = [
            _result(_A, "inserted", token_usage=Usage()),
            _result(_B, "inserted", token_usage=NotTruncated()),
            _result(_C, "inserted", token_usage=None),
        ]
        main([])
        out = capsys.readouterr().out
        assert f"  {_A}  inserted  (document truncated by the model)\n" in out
        assert f"  {_B}  inserted\n" in out
        assert f"  {_C}  inserted\n" in out

    def test_failure_message_is_one_line(self, harness, capsys):
        harness.results = [_result(_A, "failure", error="RuntimeError: line one\nline two")]
        main([])
        assert f"  {_A}  failure  RuntimeError: line one line two\n" in capsys.readouterr().out

    def test_lines_follow_processing_order(self, harness, capsys):
        harness.results = [_result(_C, "inserted"), _result(_A, "inserted"), _result(_B, "inserted")]
        main([])
        out = capsys.readouterr().out
        assert out.index(_C) < out.index(_A) < out.index(_B)

    def test_output_is_deterministic(self, harness, capsys):
        harness.results = [_result(_A, "inserted"), _result(_B, "not_eligible")]
        main([])
        first = capsys.readouterr().out
        main([])
        assert capsys.readouterr().out == first

    def test_no_trailing_whitespace_and_lf_only(self, harness, capsys):
        harness.results = [_result(_A, "inserted"), _result(_B, "failure", error="ValueError: x")]
        main([])
        out = capsys.readouterr().out
        assert "\r" not in out
        assert all(line == line.rstrip() for line in out.split("\n"))

    def test_no_secret_or_vector_content_is_printed(self, harness, capsys, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "s3cret-value")
        harness.results = [_result(_A, "inserted")]
        main([])
        captured = capsys.readouterr()
        assert "s3cret-value" not in captured.out + captured.err
        assert "e" * 64 not in captured.out


# ---------------------------------------------------------------------------
# BC04  Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_exit_code_constants(self):
        assert (cli.EXIT_OK, cli.EXIT_USAGE, cli.EXIT_CONFIGURATION, cli.EXIT_DATABASE,
                cli.EXIT_INCOMPLETE, cli.EXIT_INTERRUPTED) == (0, 2, 3, 4, 6, 130)

    def test_only_the_locked_exit_codes_exist(self):
        codes = sorted(v for n, v in vars(cli).items() if n.startswith("EXIT_"))
        assert codes == [0, 2, 3, 4, 6, 130]

    @pytest.mark.parametrize(
        "statuses",
        [[], ["inserted"], ["already_present"], ["not_eligible"],
         ["inserted", "already_present", "not_eligible"]],
        ids=["empty", "inserted", "already_present", "not_eligible", "mixed-good"],
    )
    def test_clean_run_exits_zero(self, harness, statuses):
        harness.results = [_result(str(i) * 4, s) for i, s in enumerate(statuses)]
        assert main([]) == 0

    def test_text_mismatch_exits_six(self, harness, capsys):
        harness.results = [_result(_A, "inserted"), _result(_B, "text_mismatch")]
        assert main([]) == 6
        assert "completed with problems (0 failed, 1 text_mismatch)" in capsys.readouterr().out

    def test_text_mismatch_alone_exits_six(self, harness):
        harness.results = [_result(_A, "text_mismatch")]
        assert main([]) == 6

    def test_failure_exits_six(self, harness, capsys):
        harness.results = [_result(_A, "failure", error="ValueError: x"), _result(_B, "inserted")]
        assert main([]) == 6
        assert "completed with problems (1 failed, 0 text_mismatch)" in capsys.readouterr().out

    def test_failure_and_text_mismatch_exit_six(self, harness):
        harness.results = [_result(_A, "failure", error="x"), _result(_B, "text_mismatch")]
        assert main([]) == 6

    def test_usage_error_exits_two(self, harness):
        with pytest.raises(SystemExit) as excinfo:
            main(["unexpected"])
        assert excinfo.value.code == 2

    def test_missing_password_exits_three(self, harness, capsys):
        harness.connect_error = RuntimeError(
            "INCIDENT_RETRIEVAL_DB_PASSWORD environment variable is not set"
        )
        assert main([]) == 3
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "error: configuration: INCIDENT_RETRIEVAL_DB_PASSWORD environment variable is not set\n"
        )
        assert harness.backfill_calls == []

    def test_connection_failure_exits_four(self, harness, capsys):
        harness.connect_error = retrieval_db.DatabaseError("connection refused")
        assert main([]) == 4
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "error: database: connection refused\n"

    def test_database_error_during_backfill_exits_four(self, harness, capsys):
        import psycopg
        harness.results = [_result(_A, "inserted"), _result(_B, "inserted")]
        harness.backfill_error = psycopg.OperationalError("server closed the connection")
        harness.error_after = 1
        assert main([]) == 4
        captured = capsys.readouterr()
        assert captured.err == "error: database: server closed the connection\n"
        assert f"  {_A}  inserted\n" in captured.out
        assert _B not in captured.out
        assert "Summary" not in captured.out

    def test_database_error_during_discovery_exits_four(self, harness, capsys):
        harness.backfill_error = retrieval_db.DatabaseError("permission denied")
        assert main([]) == 4
        captured = capsys.readouterr()
        assert captured.out == _HEADER + "\n"
        assert captured.err == "error: database: permission denied\n"

    def test_keyboard_interrupt_exits_130(self, harness, capsys):
        harness.results = [_result(_A, "inserted"), _result(_B, "inserted")]
        harness.backfill_error = KeyboardInterrupt()
        harness.error_after = 1
        assert main([]) == 130
        assert "Summary" not in capsys.readouterr().out

    def test_unexpected_error_is_not_swallowed(self, harness):
        harness.backfill_error = KeyError("unexpected")
        with pytest.raises(KeyError):
            main([])

    def test_database_error_takes_precedence_over_partial_results(self, harness):
        harness.results = [_result(_A, "failure", error="x"), _result(_B, "inserted")]
        harness.backfill_error = retrieval_db.DatabaseError("boom")
        harness.error_after = 1
        assert main([]) == 4


# ---------------------------------------------------------------------------
# BC05  Connection ownership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    @pytest.mark.parametrize(
        "statuses", [[], ["inserted"], ["text_mismatch"], ["failure"]],
        ids=["empty", "inserted", "text_mismatch", "failure"],
    )
    def test_rollback_then_close_after_every_run(self, harness, statuses):
        harness.results = [_result(_A, s) for s in statuses]
        main([])
        assert [c[0] for c in harness.conn.mock_calls] == ["rollback", "close"]

    @pytest.mark.parametrize(
        "error", [retrieval_db.DatabaseError("x"), KeyboardInterrupt(), KeyError("k")],
        ids=["database", "interrupt", "unexpected"],
    )
    def test_rollback_then_close_on_error(self, harness, error):
        harness.backfill_error = error
        try:
            main([])
        except KeyError:
            pass
        assert [c[0] for c in harness.conn.mock_calls] == ["rollback", "close"]

    def test_cli_itself_never_commits(self, harness):
        harness.results = [_result(_A, "inserted")]
        main([])
        harness.conn.commit.assert_not_called()

    def test_close_is_attempted_when_rollback_fails(self, harness, capsys):
        harness.conn.rollback.side_effect = retrieval_db.DatabaseError("rollback broke")
        harness.results = [_result(_A, "inserted")]
        assert main([]) == 0
        harness.conn.close.assert_called_once_with()
        assert "error: rollback failed during cleanup: rollback broke\n" in capsys.readouterr().err

    def test_close_failure_does_not_change_the_exit_code(self, harness, capsys):
        harness.conn.close.side_effect = RuntimeError("close broke")
        harness.results = [_result(_A, "text_mismatch")]
        assert main([]) == 6
        assert "error: close failed during cleanup: close broke\n" in capsys.readouterr().err

    def test_no_connection_cleanup_when_connect_fails(self, harness):
        harness.connect_error = RuntimeError("no password")
        assert main([]) == 3
        assert harness.conn.mock_calls == []

    def test_summary_is_printed_after_cleanup(self, harness, capsys):
        events = []
        harness.conn.close.side_effect = lambda: events.append("close")
        original = cli._write

        def recording(stream, text):
            if stream is sys.stdout and "Summary" in text:
                events.append("summary")
            original(stream, text)

        cli._write = recording
        try:
            main([])
        finally:
            cli._write = original
        assert events == ["close", "summary"]


# ---------------------------------------------------------------------------
# BC06  Model is not loaded
# ---------------------------------------------------------------------------

class TestModelNotLoaded:

    def test_no_op_run_never_uses_the_model(self, harness):
        """ExplodingBackend fails the test if the model is called or loaded."""
        harness.results = [_result(_A, "already_present"), _result(_B, "not_eligible")]
        assert main([]) == 0
        assert harness.provider.backend.is_loaded is False

    def test_cli_does_not_load_or_embed_directly(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"load", "embed", "backend"})

    def test_run_does_not_import_a_model_library(self, harness):
        watched = ("sentence_transformers", "torch", "transformers")
        before = {m for m in watched if m in sys.modules}
        main([])
        assert {m for m in watched if m in sys.modules} == before

    def test_importing_the_cli_loads_no_model_library(self):
        code = (
            "import sys\n"
            "import embedding_backfill_cli as c\n"
            "p = c.create_default_provider()\n"
            "assert p.backend.is_loaded is False\n"
            "c.render_header(p)\n"
            "print(sorted(m for m in ('sentence_transformers','torch','transformers',"
            "'tokenizers','huggingface_hub','numpy') if m in sys.modules))\n"
        )
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=_COMPONENT_DIR, env=env,
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "[]"


# ---------------------------------------------------------------------------
# BC07  Boundaries
# ---------------------------------------------------------------------------

def _module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules() -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestBoundaries:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(cli.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "argparse", "sys", "typing",
            "retrieval_db", "embedding_backfill", "embedding_provider",
            "incident_document", "sentence_transformer_backend",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "psycopg2", "embedding_store", "embedding_pipeline",
         "sentence_transformers", "torch", "transformers", "numpy",
         "click", "typer", "rich", "json", "logging", "socket", "subprocess", "os",
         "similarity_search", "historical_context"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    def test_database_errors_are_caught_through_retrieval_db(self):
        caught = [
            ast.unparse(h.type) for h in ast.walk(_module_tree())
            if isinstance(h, ast.ExceptHandler) and h.type is not None
        ]
        assert caught.count("retrieval_db.DatabaseError") == 2
        assert not any("psycopg" in name for name in caught)

    def test_cli_contains_no_sql(self):
        tree = _module_tree()
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"execute", "executemany", "cursor"})
        strings = [
            n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" not in n.value
        ]
        for text in strings:
            words = set(text.upper().replace(",", " ").split())
            assert words.isdisjoint({"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE"}), text

    def test_cli_never_commits(self):
        attributes = {n.attr for n in ast.walk(_module_tree()) if isinstance(n, ast.Attribute)}
        assert "commit" not in attributes
        assert {"rollback", "close"} <= attributes

    def test_only_argparse_is_used_for_arguments(self):
        parsers = [
            ast.unparse(node.func) for node in ast.walk(_module_tree())
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("ArgumentParser")
        ]
        assert parsers == ["argparse.ArgumentParser"]

    def test_script_entry_point_exists(self):
        source = open(_MODULE_PATH, encoding="utf-8").read()
        assert 'if __name__ == "__main__":' in source
        assert "sys.exit(main())" in source

    def test_no_destructive_or_retrieval_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("delete", "update", "overwrite", "truncate", "reset", "search",
                     "similar", "threshold", "root_cause"):
            assert not any(word in name for name in names)
