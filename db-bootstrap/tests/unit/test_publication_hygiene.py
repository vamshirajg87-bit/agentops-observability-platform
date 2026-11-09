"""
db-bootstrap/tests/unit/test_publication_hygiene.py

Publication hygiene checks (B3J-202).  They read .gitignore and the benchmark sources as text and
ask Git (read-only) which tracked files the ignore rules would match.  No Docker, no database,
no network.

    PH01  .gitignore keeps its existing rules and names the credential, key, log and dump patterns
    PH02  No tracked file is matched by an ignore rule
    PH03  No tracked benchmark file contains a real Windows user-profile path
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_GITIGNORE = _REPO / ".gitignore"

_EXISTING_RULES = ["venv/", ".venv/", "__pycache__/", "*.pyc", ".env", "docker-compose.override.yml"]
_NEW_RULES = [".env.*", "!.env.example", "credentials.env", "*.pem", "*.key", "*.p12", "*.pfx", "*.log",
              "*.dump", "*.sql.gz"]


def _rules() -> list[str]:
    return [line.strip() for line in _GITIGNORE.read_text(encoding="utf-8").splitlines()]


def _git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(_REPO), *args], capture_output=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError("git failed")
    return result.stdout.decode("utf-8", "replace")


def _git_available() -> bool:
    if shutil.which("git") is None:
        return False
    try:
        _git("rev-parse", "--is-inside-work-tree")
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return False
    return True


class TestIgnoreRules:

    def test_the_existing_rules_are_kept(self):
        rules = _rules()
        for rule in _EXISTING_RULES:
            assert rule in rules, rule

    def test_credential_key_log_and_dump_patterns_are_listed(self):
        rules = _rules()
        for rule in _NEW_RULES:
            assert rule in rules, rule

    def test_the_example_environment_file_is_excepted_after_the_wildcard(self):
        rules = _rules()
        assert rules.index("!.env.example") > rules.index(".env.*")

    def test_the_rules_are_narrow(self):
        # nothing that would hide source, documentation, examples or tests
        rules = [r for r in _rules() if r and not r.startswith("#")]
        for broad in ("*", "*.py", "*.md", "*.yml", "*.yaml", "*.json", "*.sql", "*.txt", "tests/", "docs/"):
            assert broad not in rules, broad


@pytest.mark.skipif(not _git_available(), reason="git is not available")
class TestTrackedFiles:

    def test_no_tracked_file_is_matched_by_an_ignore_rule(self):
        assert _git("ls-files", "-ci", "--exclude-standard").strip() == ""

    def test_the_example_environment_file_is_tracked_and_not_ignored(self):
        assert ".env.example" in _git("ls-files").splitlines()
        assert not _check_ignore(".env.example")

    @pytest.mark.parametrize("name", [".env", ".env.local", "credentials.env", "server.pem", "id.key", "db.dump",
                                      "x.sql.gz", "run.log"])
    def test_real_secrets_and_dumps_would_be_ignored(self, name):
        assert _check_ignore(name), name


def _check_ignore(path: str) -> bool:
    """True when Git would ignore this (possibly non-existent) path."""
    result = subprocess.run(["git", "-C", str(_REPO), "check-ignore", "-q", "--no-index", path],
                            capture_output=True, timeout=60)
    return result.returncode == 0


_PROFILE_PATH = re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+([^\\/\s'\"]+)")
_ALLOWED_PROFILES = {"public", "default", "runner", "user"}


def _benchmark_files() -> list[Path]:
    root = _REPO / "benchmarks"
    return sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts
                  and p.suffix in {".py", ".json", ".md", ".ps1", ".txt", ".yml"})


class TestNoMachineSpecificPaths:

    def test_benchmark_files_exist_for_the_scan(self):
        assert len(_benchmark_files()) > 5

    def test_no_real_user_profile_path_in_the_benchmark_files(self):
        found = []
        for path in _benchmark_files():
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for match in _PROFILE_PATH.finditer(line):
                    name = match.group(1).lower()
                    if len(name) >= 3 and name not in _ALLOWED_PROFILES:
                        found.append(f"{path.relative_to(_REPO).as_posix()}:{number}")
        assert found == []

    def test_the_scan_pattern_flags_a_real_looking_profile_and_accepts_placeholders(self):
        assert _PROFILE_PATH.search(r"C:\Users\Jane Doe\AppData")
        assert _PROFILE_PATH.search(r"C:\Users\JANEDO~1\AppData").group(1) == "JANEDO~1"
        assert _PROFILE_PATH.search(r"C:\Users\u\AppData").group(1) == "u"         # allowed: one letter
        assert _PROFILE_PATH.search("C:/Users/Public/x").group(1) == "Public"       # allowed: system name
