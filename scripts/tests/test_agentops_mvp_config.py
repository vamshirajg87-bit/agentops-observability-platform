"""
scripts/tests/test_agentops_mvp_config.py

Offline tests for scripts/agentops_mvp.py (init-credentials, check-credentials).

Everything runs in temporary directories with a replaced command runner.  No container
engine is invoked, no database is touched, and no real MVP credential file is created:
every path used here is below pytest's temporary directory, and the one test that uses
the real Windows permission tool works on a dummy directory and file that hold no
secret.

Test inventory:
    T01  Generation: eight unique secure values
    T02  Credential set matches docker/mvp/compose.yml
    T03  File rendering, parsing, complete and incomplete files, malformed content
    T04  Default paths on Windows and POSIX
    T05  Repository, OneDrive, relative path, file name and link refusal
    T06  init-credentials: exclusive creation, existing file preserved, rollback
    T07  POSIX permissions (real files, skipped on Windows)
    T08  Windows ACLs with a mocked tool, and with the real tool on a dummy file
    T09  check-credentials: validation never modifies the file
    T10  Redaction of credential values
    T11  No container engine, no destructive operation
    T12  Command-line behaviour
    T13  check-config: engine locality, command construction, resolved configuration
"""

from __future__ import annotations

import ast
import io
import ntpath
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentops_mvp as mvp  # noqa: E402
from agentops_mvp import CommandResult, CredentialError  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO / "docker" / "mvp" / "compose.yml"
_SOURCE = Path(mvp.__file__).read_text(encoding="utf-8")

_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
_OTHER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"

windows_only = pytest.mark.skipif(os.name != "nt", reason="needs the real Windows permission tool")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _values(prefix: str = "V") -> dict[str, str]:
    """Distinct, valid, recognizable values (never real credentials)."""
    return {name: f"{prefix}{index}".ljust(40, "z") for index, name in enumerate(mvp.CREDENTIAL_VARIABLES)}


def _content(values: dict[str, str] | None = None) -> bytes:
    return mvp.render_file(values or _values())


class FakeWindows:
    """A stand-in for whoami.exe and icacls.exe that models the ACL of each path.

    States: "inherited" (a new object), "granted" (explicit entry added, inheritance
    still on), "private" (explicit entry only, protected), "broad" (private plus an
    entry for Everyone).  It records every call and can be told to misbehave.
    """

    def __init__(self, *, sid: str = _SID, fail: str | None = None, broaden: bool = False,
                 garbage: bool = False, whoami_text: str | None = None) -> None:
        self.sid = sid
        self.fail = fail
        self.broaden = broaden
        self.garbage = garbage
        self.whoami_text = whoami_text
        self.calls: list[list[str]] = []
        self.state: dict[str, str] = {}
        self.file_sizes_at_grant: dict[str, int] = {}

    def make_private(self, *paths: Path) -> None:
        for path in paths:
            self.state[str(path)] = "private"

    def _sddl(self, path: str) -> str:
        state = self.state.get(path, "inherited")
        inherited = f"(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{self.sid})"
        explicit = f"(A;;FA;;;{self.sid})"
        if state == "inherited":
            return "D:" + inherited
        if state == "granted":
            return "D:" + explicit + inherited
        if state == "broad":
            return "D:P" + explicit + "(A;;FR;;;WD)"
        return "D:PAI" + explicit

    def __call__(self, argv):
        self.calls.append(list(argv))
        tool = ntpath.basename(argv[0]).lower()
        if tool == "whoami.exe":
            text = self.whoami_text if self.whoami_text is not None else f'"HOST\\user","{self.sid}"\r\n'
            return CommandResult(0 if self.fail != "whoami" else 1, text.encode())
        assert tool == "icacls.exe", argv
        path = argv[1]
        if "/save" in argv:
            if self.fail == "save":
                return CommandResult(1, b"")
            target = argv[argv.index("/save") + 1]
            body = "garbage" if self.garbage else self._sddl(path)
            with open(target, "wb") as handle:
                handle.write((os.path.basename(path) + "\r\n" + body + "\r\n").encode("utf-16-le"))
            return CommandResult(0, b"")
        if self.fail == "grant" and "/grant:r" in argv:
            return CommandResult(5, b"")
        if "/grant:r" in argv:
            if os.path.isfile(path):
                self.file_sizes_at_grant[path] = os.path.getsize(path)
            self.state[path] = "granted"
        elif "/inheritance:r" in argv:
            self.state[path] = "broad" if self.broaden else "private"
        return CommandResult(0, b"")


def _nt_environ(tmp_path: Path) -> dict[str, str]:
    return {"SystemRoot": r"C:\Windows", "LOCALAPPDATA": str(tmp_path / "local")}


def _host_environ(tmp_path: Path) -> dict[str, str]:
    """An injected environment whose default credential location is tmp_path/local/agentops-mvp,
    in the host's own conventions.  A simulated Windows environment is only meaningful on a
    Windows host (ntpath does not treat a POSIX path as absolute), so tests that rely on the
    default location use the real platform instead of a simulated one."""
    if os.name == "nt":
        return _nt_environ(tmp_path)
    return {"XDG_CONFIG_HOME": str(tmp_path / "local")}


def _host_runner():
    """The Windows tool mock on Windows hosts; on POSIX no tool may run at all."""
    if os.name == "nt":
        return FakeWindows()

    def forbidden(argv):
        raise AssertionError("no external tool may run on POSIX: " + " ".join(argv))

    return forbidden


def _target(tmp_path: Path, name: str = "case") -> Path:
    return tmp_path / name / mvp.DIRECTORY_NAME / mvp.FILE_NAME


def _run(args, tmp_path, *, platform_name="nt", runner=None, environ=None, repo_root=None, home=None):
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(
        args,
        environ=environ if environ is not None else _nt_environ(tmp_path),
        platform_name=platform_name,
        runner=runner or FakeWindows(),
        repo_root=repo_root if repo_root is not None else tmp_path / "repo-elsewhere",
        home=home or str(tmp_path / "home"),
        out=out, err=err,
    )
    return code, out.getvalue(), err.getvalue()


def _init(tmp_path, name="case", **kwargs):
    target = _target(tmp_path, name)
    code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, **kwargs)
    return target, code, out, err


def _write_valid(tmp_path, name="case", values=None, fake=None):
    """A valid credential file with private permissions in the mocked-Windows model."""
    target = _target(tmp_path, name)
    target.parent.mkdir(parents=True)
    target.write_bytes(_content(values))
    fake = fake or FakeWindows()
    fake.make_private(target.parent, target)
    return target, fake


# ---------------------------------------------------------------------------
# T01  Generation
# ---------------------------------------------------------------------------

class TestGeneration:

    def test_eight_distinct_values_of_secure_length(self):
        values = mvp.generate_credentials()
        assert list(values) == list(mvp.CREDENTIAL_VARIABLES) and len(values) == 8
        assert len(set(values.values())) == 8
        for value in values.values():
            assert 32 <= len(value) <= 128
            assert re.fullmatch(r"[A-Za-z0-9_-]+", value)
            assert mvp.value_problem(value) is None

    def test_values_come_from_secrets_token_urlsafe_32_independently(self, monkeypatch):
        calls = []

        def fake(nbytes=None):
            calls.append(nbytes)
            return f"unique-{len(calls):02d}-" + "x" * 32

        monkeypatch.setattr(mvp.secrets, "token_urlsafe", fake)
        values = mvp.generate_credentials()
        assert calls == [32] * 8
        assert len(set(values.values())) == 8

    def test_runs_differ(self):
        assert mvp.generate_credentials() != mvp.generate_credentials()

    def test_identical_values_are_rejected(self, monkeypatch):
        monkeypatch.setattr(mvp.secrets, "token_urlsafe", lambda nbytes=None: "a" * 43)
        with pytest.raises(CredentialError, match="identical"):
            mvp.generate_credentials()

    @pytest.mark.parametrize("bad", ["", "   ", "changeme", "<password>", "short", "a" * 31, "a" * 129,
                                     "has space" + "a" * 30, "dollar$" + "a" * 30, "hash#" + "a" * 30,
                                     "quote\"" + "a" * 30, "ünï" + "a" * 30, "line\nbreak" + "a" * 30])
    def test_unacceptable_values_are_rejected(self, bad):
        assert mvp.value_problem(bad) is not None

    @pytest.mark.parametrize("word", sorted(mvp._PLACEHOLDER_WORDS))
    def test_placeholder_words_are_rejected(self, word):
        assert mvp.value_problem(word) is not None
        assert mvp.value_problem(word.upper()) is not None


# ---------------------------------------------------------------------------
# T02  The credential set matches the compose file
# ---------------------------------------------------------------------------

def test_variables_are_exactly_the_ones_the_compose_file_requires():
    text = _COMPOSE.read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z_]+):\?", text))
    assert required == set(mvp.CREDENTIAL_VARIABLES)
    assert len(mvp.CREDENTIAL_VARIABLES) == len(set(mvp.CREDENTIAL_VARIABLES)) == 8


# ---------------------------------------------------------------------------
# T03  Rendering and parsing
# ---------------------------------------------------------------------------

class TestFileFormat:

    def test_round_trip(self):
        values = _values()
        assert mvp.parse_file(mvp.render_file(values)) == values

    def test_layout(self):
        lines = _content().decode("ascii").split("\n")
        assert lines[0] == mvp.HEADER and lines[-2] == mvp.FOOTER and lines[-1] == ""
        assert [line.split("=")[0] for line in lines[1:-2]] == list(mvp.CREDENTIAL_VARIABLES)

    def _mutate(self, fn):
        lines = _content().decode("ascii").split("\n")
        return "\n".join(fn(lines)).encode("ascii")

    @pytest.mark.parametrize("label,mutation,expected", [
        ("no footer", lambda l: l[:-2] + [""], "end marker"),
        ("no header", lambda l: l[1:], "header"),
        ("truncated mid-file", lambda l: l[:5] + [""], "end marker"),
        ("missing variable", lambda l: l[:3] + l[4:], "missing"),
        ("duplicate variable", lambda l: l[:3] + [l[2]] + l[3:], "repeats"),
        ("extra variable", lambda l: l[:-2] + ["EXTRA_PASSWORD=" + "e" * 40] + l[-2:], "not expected"),
        ("lowercase key", lambda l: l[:1] + [l[1].lower()] + l[2:], "NAME=value"),
        ("no equals sign", lambda l: l[:1] + ["POSTGRES_PASSWORD"] + l[2:], "NAME=value"),
        ("empty value", lambda l: l[:1] + ["POSTGRES_PASSWORD="] + l[2:], "POSTGRES_PASSWORD"),
        ("short value", lambda l: l[:1] + ["POSTGRES_PASSWORD=" + "s" * 31] + l[2:], "POSTGRES_PASSWORD"),
        ("value with a dollar sign", lambda l: l[:1] + ["POSTGRES_PASSWORD=" + "d$" * 20] + l[2:], "POSTGRES_PASSWORD"),
        ("quoted value", lambda l: l[:1] + ['POSTGRES_PASSWORD="' + "q" * 40 + '"'] + l[2:], "POSTGRES_PASSWORD"),
        ("placeholder value", lambda l: l[:1] + ["POSTGRES_PASSWORD=changeme"] + l[2:], "POSTGRES_PASSWORD"),
        ("blank line inside", lambda l: l[:3] + [""] + l[3:], "NAME=value"),
        ("stray comment inside", lambda l: l[:3] + ["# note"] + l[3:], "NAME=value"),
    ])
    def test_malformed_content_is_rejected(self, label, mutation, expected):
        with pytest.raises(CredentialError, match=expected):
            mvp.parse_file(self._mutate(mutation))

    def test_equal_values_under_different_names_are_rejected(self):
        lines = _content().decode("ascii").split("\n")
        lines[2] = "GF_DATASOURCE_AGENTOPS_PASSWORD=" + lines[1].split("=", 1)[1]
        with pytest.raises(CredentialError, match="identical"):
            mvp.parse_file("\n".join(lines).encode("ascii"))

    @pytest.mark.parametrize("label,data,expected", [
        ("byte-order mark", b"\xef\xbb\xbf" + _content(), "byte-order mark"),
        ("CRLF", _content().replace(b"\n", b"\r\n"), "LF"),
        ("non-ASCII", _content().replace(b"V0", "Vé".encode("utf-8"), 1), "non-ASCII"),
        ("no final newline", _content()[:-1], "final newline"),
        ("too large", _content() + b"#" * 5000, "larger"),
        ("empty", b"", "header|final newline"),
    ])
    def test_encoding_and_framing_problems(self, label, data, expected):
        with pytest.raises(CredentialError, match=expected):
            mvp.parse_file(data)

    def test_render_refuses_an_incomplete_or_invalid_set(self):
        values = _values()
        del values["POSTGRES_PASSWORD"]
        with pytest.raises(CredentialError):
            mvp.render_file(values)
        bad = _values()
        bad["POSTGRES_PASSWORD"] = "short"
        with pytest.raises(CredentialError):
            mvp.render_file(bad)


# ---------------------------------------------------------------------------
# T04  Default paths
# ---------------------------------------------------------------------------

class TestDefaultPaths:

    def test_windows_uses_localappdata(self):
        path = mvp.default_credentials_path({"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}, "nt", "")
        assert path == r"C:\Users\u\AppData\Local\agentops-mvp\credentials.env"

    @pytest.mark.parametrize("environ", [{}, {"LOCALAPPDATA": ""}, {"LOCALAPPDATA": "relative\\dir"}])
    def test_windows_without_a_usable_localappdata_fails_closed(self, environ):
        with pytest.raises(CredentialError):
            mvp.default_credentials_path(environ, "nt", r"C:\Users\u")

    def test_posix_prefers_an_absolute_xdg_config_home(self):
        assert mvp.default_credentials_path({"XDG_CONFIG_HOME": "/x/cfg"}, "posix", "/home/u") == \
            "/x/cfg/agentops-mvp/credentials.env"

    @pytest.mark.parametrize("environ", [{}, {"XDG_CONFIG_HOME": ""}, {"XDG_CONFIG_HOME": "relative/cfg"}])
    def test_posix_falls_back_to_dot_config(self, environ):
        assert mvp.default_credentials_path(environ, "posix", "/home/u") == \
            "/home/u/.config/agentops-mvp/credentials.env"

    def test_posix_without_an_absolute_home_fails_closed(self):
        with pytest.raises(CredentialError):
            mvp.default_credentials_path({}, "posix", "")

    def test_macos_follows_the_posix_rule(self):
        assert mvp.default_credentials_path({}, "posix", "/Users/u").startswith("/Users/u/.config/")

    def test_default_path_is_used_when_no_option_is_given(self, tmp_path):
        environ = _host_environ(tmp_path)
        code, out, err = _run(["init-credentials"], tmp_path, platform_name=os.name,
                              runner=_host_runner(), environ=environ, home=str(tmp_path / "home"))
        expected = tmp_path / "local" / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        assert code == mvp.EXIT_OK, err
        assert expected.is_file()

    def test_repository_root_comes_from_the_module_not_the_working_directory(self, tmp_path, monkeypatch):
        before = mvp.repository_root()
        monkeypatch.chdir(tmp_path)
        assert mvp.repository_root() == before == _REPO


# ---------------------------------------------------------------------------
# T05  Location refusals
# ---------------------------------------------------------------------------

class TestLocationPolicy:

    def _check(self, path, tmp_path, environ=None, repo=None):
        return mvp.check_location(str(path), repo or (tmp_path / "repo"), environ or {})

    def test_a_normal_location_is_accepted(self, tmp_path):
        path = _target(tmp_path)
        assert self._check(path, tmp_path) == os.path.abspath(path)

    def test_inside_the_repository_is_refused_even_for_ignored_paths(self, tmp_path):
        repo = tmp_path / "repo"
        for inside in (repo / mvp.DIRECTORY_NAME / mvp.FILE_NAME, repo / "docker" / mvp.DIRECTORY_NAME / mvp.FILE_NAME):
            with pytest.raises(CredentialError, match="outside the repository"):
                self._check(inside, tmp_path, repo=repo)

    def test_the_repository_root_itself_and_its_sibling_prefix(self, tmp_path):
        repo = tmp_path / "repo"
        sibling = tmp_path / "repo-other" / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        assert self._check(sibling, tmp_path, repo=repo)   # a name that merely starts alike is fine

    @pytest.mark.parametrize("parts", [
        ("OneDrive", "Documents"), ("onedrive - Contoso", "x"), ("OneDriveBackup",), ("home", "OneDrive", "cfg"),
    ])
    def test_onedrive_folders_are_refused(self, tmp_path, parts):
        path = tmp_path.joinpath(*parts) / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        with pytest.raises(CredentialError, match="OneDrive"):
            self._check(path, tmp_path)

    @pytest.mark.parametrize("variable", ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"])
    def test_a_path_under_a_onedrive_environment_root_is_refused(self, tmp_path, variable):
        root = tmp_path / "synced"
        path = root / "sub" / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        with pytest.raises(CredentialError, match="OneDrive"):
            self._check(path, tmp_path, environ={variable: str(root)})

    @pytest.mark.parametrize("path", ["", "relative/agentops-mvp/credentials.env", "agentops-mvp/credentials.env"])
    def test_relative_paths_are_refused(self, path, tmp_path):
        with pytest.raises(CredentialError, match="absolute"):
            mvp.check_location(path, tmp_path / "repo", {})

    @pytest.mark.parametrize("name", ["credentials.txt", "creds.env", ".env", "credentials.env.bak"])
    def test_other_file_names_are_refused(self, tmp_path, name):
        path = tmp_path / mvp.DIRECTORY_NAME / name
        with pytest.raises(CredentialError, match="must be named"):
            self._check(path, tmp_path)

    def test_a_different_directory_name_is_refused(self, tmp_path):
        with pytest.raises(CredentialError, match="must be named"):
            self._check(tmp_path / "other" / mvp.FILE_NAME, tmp_path)

    def test_a_link_to_a_location_inside_the_repository_is_refused(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / mvp.DIRECTORY_NAME).mkdir(parents=True)
        link = tmp_path / "linked" / mvp.DIRECTORY_NAME
        link.parent.mkdir()
        try:
            os.symlink(repo / mvp.DIRECTORY_NAME, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        with pytest.raises(CredentialError):
            self._check(link / mvp.FILE_NAME, tmp_path, repo=repo)

    def test_a_symbolic_link_directory_or_file_is_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "x" / mvp.DIRECTORY_NAME
        link.parent.mkdir()
        try:
            os.symlink(real, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        with pytest.raises(CredentialError, match="links"):
            self._check(link / mvp.FILE_NAME, tmp_path)

    def test_a_symbolic_link_file_is_refused(self, tmp_path):
        directory = tmp_path / "y" / mvp.DIRECTORY_NAME
        directory.mkdir(parents=True)
        (tmp_path / "elsewhere.env").write_bytes(b"x")
        try:
            os.symlink(tmp_path / "elsewhere.env", directory / mvp.FILE_NAME)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        with pytest.raises(CredentialError, match="links"):
            self._check(directory / mvp.FILE_NAME, tmp_path)

    @windows_only
    def test_a_real_junction_is_refused(self, tmp_path):
        """Junctions need no privilege on Windows (unlike symbolic links), so this runs where
        the symbolic-link tests are skipped.  A test-only mklink call, never the tool itself."""
        real = tmp_path / "real-target"
        real.mkdir()
        parent = tmp_path / "j"
        parent.mkdir()
        link = parent / mvp.DIRECTORY_NAME
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], capture_output=True)
        if made.returncode != 0:
            pytest.skip("a junction could not be created here")
        try:
            assert mvp._is_redirect(str(link)) is True
            with pytest.raises(CredentialError, match="links"):
                self._check(link / mvp.FILE_NAME, tmp_path)
            # and a junction pointing INTO the repository is refused whatever its name
            repo = tmp_path / "repo"
            (repo / mvp.DIRECTORY_NAME).mkdir(parents=True)
            inside = parent / "to-repo"
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(inside), str(repo)], capture_output=True)
            if made.returncode == 0:
                with pytest.raises(CredentialError, match="outside the repository"):
                    mvp.check_location(str(inside / mvp.DIRECTORY_NAME / mvp.FILE_NAME), repo, {})
                os.rmdir(inside)
        finally:
            os.rmdir(link)       # removes the junction only, never its target

    def test_a_reparse_point_is_detected_by_its_attribute(self, tmp_path, monkeypatch):
        directory = tmp_path / "z" / mvp.DIRECTORY_NAME
        directory.mkdir(parents=True)

        class Info:
            st_file_attributes = 0x400
            st_mode = stat.S_IFDIR

        real_lstat = os.lstat
        monkeypatch.setattr(mvp.os, "lstat", lambda p: Info() if os.path.abspath(p) == str(directory) else real_lstat(p))
        assert mvp._is_redirect(str(directory)) is True

    def test_main_reports_a_refused_location_without_creating_anything(self, tmp_path):
        repo = tmp_path / "repo"
        target = repo / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, repo_root=repo)
        assert code == mvp.EXIT_REFUSED and "outside the repository" in err
        assert not repo.exists()


# ---------------------------------------------------------------------------
# T06  init-credentials
# ---------------------------------------------------------------------------

class TestInit:

    def test_creates_the_file_with_eight_unique_values_and_reports_no_value(self, tmp_path):
        fake = FakeWindows()
        target = _target(tmp_path)
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_OK and err == ""
        values = mvp.parse_file(target.read_bytes())
        assert len(values) == 8 and len(set(values.values())) == 8
        for value in values.values():
            assert value not in out and value not in err
        for name in mvp.CREDENTIAL_VARIABLES:
            assert name in out
        assert str(target) in out

    def test_exclusive_creation_uses_o_excl(self, tmp_path, monkeypatch):
        flags = []
        real_open = os.open

        def recording(path, flag, mode=0o777, **kw):
            flags.append((os.path.basename(str(path)), flag, mode))
            return real_open(path, flag, mode, **kw)

        monkeypatch.setattr(mvp.os, "open", recording)
        _init(tmp_path)
        created = [item for item in flags if item[0] == mvp.FILE_NAME and item[1] & os.O_CREAT]
        assert len(created) == 1
        assert created[0][1] & os.O_EXCL and created[0][1] & os.O_WRONLY and created[0][2] == 0o600

    def test_an_existing_file_is_preserved_byte_for_byte(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        original = b"ORIGINAL-CONTENT-NOT-A-CREDENTIAL\n"
        target.write_bytes(original)
        before = target.stat().st_mtime_ns
        fake = FakeWindows()
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_EXISTS and "already exists" in err
        assert target.read_bytes() == original and target.stat().st_mtime_ns == before
        assert fake.calls == []     # nothing was even inspected or changed

    def test_an_existing_valid_credential_file_is_never_regenerated(self, tmp_path):
        target, fake = _write_valid(tmp_path)
        original = target.read_bytes()
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_EXISTS and target.read_bytes() == original
        assert "regenerated" in err

    def test_a_dangling_link_at_the_path_counts_as_existing(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        try:
            os.symlink(tmp_path / "missing-target", target)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path)
        assert code in (mvp.EXIT_EXISTS, mvp.EXIT_REFUSED)
        assert os.path.islink(target)

    def test_second_run_after_success_refuses(self, tmp_path):
        fake = FakeWindows()
        target = _target(tmp_path)
        args = ["init-credentials", "--credentials-file", str(target)]
        assert _run(args, tmp_path, runner=fake)[0] == mvp.EXIT_OK
        first = target.read_bytes()
        assert _run(args, tmp_path, runner=fake)[0] == mvp.EXIT_EXISTS
        assert target.read_bytes() == first

    def test_missing_directories_are_created_and_a_failure_removes_only_those(self, tmp_path):
        fake = FakeWindows(broaden=True)         # verification will fail
        target = tmp_path / "fresh" / "deeper" / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        sibling = tmp_path / "fresh" / "keep.txt"
        sibling.parent.mkdir()
        sibling.write_text("pre-existing", encoding="utf-8")
        code, out, err = _run(["init-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_FAILED
        assert not target.exists() and not target.parent.exists() and not (tmp_path / "fresh" / "deeper").exists()
        assert sibling.read_text(encoding="utf-8") == "pre-existing"      # pre-existing files untouched

    def test_a_failure_leaves_a_pre_existing_directory_and_its_files(self, tmp_path):
        fake = FakeWindows()
        directory = tmp_path / "case" / mvp.DIRECTORY_NAME
        directory.mkdir(parents=True)
        other = directory / "notes.txt"
        other.write_text("keep me", encoding="utf-8")
        fake.make_private(directory)
        fake.broaden = True          # the new file's permissions will verify badly
        code, out, err = _run(["init-credentials", "--credentials-file", str(directory / mvp.FILE_NAME)], tmp_path, runner=fake)
        assert code == mvp.EXIT_FAILED
        assert not (directory / mvp.FILE_NAME).exists()
        assert other.read_text(encoding="utf-8") == "keep me" and directory.is_dir()

    def test_a_pre_existing_directory_with_weak_permissions_is_refused_and_untouched(self, tmp_path):
        fake = FakeWindows()
        directory = tmp_path / "case" / mvp.DIRECTORY_NAME
        directory.mkdir(parents=True)        # state "inherited": not private
        code, out, err = _run(["init-credentials", "--credentials-file", str(directory / mvp.FILE_NAME)], tmp_path, runner=fake)
        assert code == mvp.EXIT_REFUSED and "directory" in err
        assert list(directory.iterdir()) == []
        assert not any("/grant:r" in call for call in fake.calls)         # never modified

    def test_no_secret_is_written_before_the_file_is_hardened(self, tmp_path):
        fake = FakeWindows()
        target, code, out, err = _init(tmp_path, runner=fake)
        assert code == mvp.EXIT_OK
        assert fake.file_sizes_at_grant[str(target)] == 0

    def test_an_unexpected_os_error_reports_only_its_code(self, tmp_path, monkeypatch):
        def boom(*a, **k):
            raise PermissionError(13, "secret detail: C:\\private\\thing")

        monkeypatch.setattr(mvp.os, "open", boom)
        target, code, out, err = _init(tmp_path)
        assert code == mvp.EXIT_FAILED and "EACCES" in err
        assert "secret detail" not in err and "private" not in err
        assert not target.exists()


# ---------------------------------------------------------------------------
# T07  POSIX permissions (real files)
# ---------------------------------------------------------------------------

@posix_only
def test_this_host_enforces_posix_modes_so_the_posix_tests_are_meaningful(tmp_path):
    """Canary: on Linux the POSIX permission tests below must run (they are skipped only
    on Windows) and must run on a file system that really keeps mode bits.  A file system
    that ignores chmod (some mounted Windows drives) would make them misleading, so this
    fails loudly instead."""
    assert hasattr(os, "geteuid") and hasattr(os, "fchmod")
    probe = tmp_path / "mode-probe"
    probe.write_bytes(b"x")
    os.chmod(probe, 0o600)
    assert stat.S_IMODE(probe.stat().st_mode) == 0o600
    os.chmod(probe, 0o644)
    assert stat.S_IMODE(probe.stat().st_mode) == 0o644


@posix_only
class TestPosix:

    def _run_posix(self, tmp_path, *args):
        return _run(list(args), tmp_path, platform_name="posix", runner=lambda argv: pytest.fail("no tool runs on POSIX"))

    def test_created_directory_and_file_are_private(self, tmp_path):
        target = _target(tmp_path)
        code, out, err = self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        assert code == mvp.EXIT_OK, err
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
        assert target.stat().st_uid == os.geteuid()

    def test_the_umask_cannot_loosen_the_file(self, tmp_path):
        old = os.umask(0)
        try:
            target = _target(tmp_path)
            code, out, err = self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        finally:
            os.umask(old)
        assert code == mvp.EXIT_OK
        assert stat.S_IMODE(target.stat().st_mode) == 0o600 and stat.S_IMODE(target.parent.stat().st_mode) == 0o700

    def test_check_accepts_a_private_file(self, tmp_path):
        target = _target(tmp_path)
        assert self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))[0] == mvp.EXIT_OK
        code, out, err = self._run_posix(tmp_path, "check-credentials", "--credentials-file", str(target))
        assert code == mvp.EXIT_OK and "OK" in out

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o700])
    def test_check_refuses_a_file_others_or_group_can_access(self, tmp_path, mode):
        target = _target(tmp_path)
        self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        os.chmod(target, mode)
        code, out, err = self._run_posix(tmp_path, "check-credentials", "--credentials-file", str(target))
        if mode & 0o077:
            assert code == mvp.EXIT_REFUSED and "group or others" in err
        else:
            assert code == mvp.EXIT_OK

    @pytest.mark.parametrize("mode", [0o755, 0o750, 0o705])
    def test_check_refuses_an_open_directory(self, tmp_path, mode):
        target = _target(tmp_path)
        self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        os.chmod(target.parent, mode)
        code, out, err = self._run_posix(tmp_path, "check-credentials", "--credentials-file", str(target))
        assert code == mvp.EXIT_REFUSED and "directory" in err

    def test_a_pre_existing_open_directory_is_refused_not_changed(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        os.chmod(target.parent, 0o755)
        code, out, err = self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        assert code == mvp.EXIT_REFUSED
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o755 and not target.exists()

    def test_no_hardlinked_or_linked_file_is_followed_on_creation(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        os.chmod(target.parent, 0o700)
        victim = tmp_path / "victim.txt"
        victim.write_text("do not touch", encoding="utf-8")
        os.symlink(victim, target)
        code, out, err = self._run_posix(tmp_path, "init-credentials", "--credentials-file", str(target))
        assert code in (mvp.EXIT_EXISTS, mvp.EXIT_REFUSED)
        assert victim.read_text(encoding="utf-8") == "do not touch"


class _FakeStat:
    def __init__(self, mode, uid):
        self.st_mode, self.st_uid = mode, uid


class TestPosixLogicWithSimulatedStat:
    """The POSIX permission rules, checked on any host with a simulated lstat."""

    def _problems(self, monkeypatch, mode, uid=1000, euid=1000, is_dir=False):
        monkeypatch.setattr(mvp.os, "lstat", lambda p: _FakeStat(mode, uid))
        monkeypatch.setattr(mvp.os, "geteuid", lambda: euid, raising=False)
        return mvp.posix_problems("/x/agentops-mvp/credentials.env", is_dir=is_dir)

    def test_private_file_and_directory_have_no_problems(self, monkeypatch):
        assert self._problems(monkeypatch, stat.S_IFREG | 0o600) == []
        assert self._problems(monkeypatch, stat.S_IFDIR | 0o700, is_dir=True) == []

    @pytest.mark.parametrize("bits", [0o640, 0o604, 0o644, 0o660, 0o666, 0o777])
    def test_group_or_other_access_is_reported(self, monkeypatch, bits):
        assert any("group or others" in p for p in self._problems(monkeypatch, stat.S_IFREG | bits))

    @pytest.mark.parametrize("bits", [0o750, 0o705, 0o755, 0o777])
    def test_open_directories_are_reported(self, monkeypatch, bits):
        assert any("group or others" in p for p in self._problems(monkeypatch, stat.S_IFDIR | bits, is_dir=True))

    def test_another_owner_is_reported(self, monkeypatch):
        assert any("owned" in p for p in self._problems(monkeypatch, stat.S_IFREG | 0o600, uid=1001))

    def test_a_symbolic_link_and_the_wrong_object_kind_are_reported(self, monkeypatch):
        assert self._problems(monkeypatch, stat.S_IFLNK | 0o777) == ["is a symbolic link"]
        assert any("not a regular file" in p for p in self._problems(monkeypatch, stat.S_IFDIR | 0o700))
        assert any("not a directory" in p for p in self._problems(monkeypatch, stat.S_IFREG | 0o600, is_dir=True))

    def test_an_uninspectable_path_is_not_treated_as_private(self, monkeypatch):
        def fail(path):
            raise PermissionError(13, "denied")

        monkeypatch.setattr(mvp.os, "lstat", fail)
        assert mvp.posix_problems("/x", is_dir=False) == ["cannot be inspected"]


# ---------------------------------------------------------------------------
# T08  Windows ACLs
# ---------------------------------------------------------------------------

class TestWindowsAcl:

    def test_dacl_parsing(self):
        flags, aces = mvp.parse_dacl(f"D:PAI(A;;FA;;;{_SID})(A;;FA;;;SY)(A;;FA;;;BA)")
        assert "P" in flags
        assert aces == [("A", "", _SID), ("A", "", "S-1-5-18"), ("A", "", "S-1-5-32-544")]
        assert mvp.parse_dacl("D:(A;ID;FA;;;WD)")[1] == [("A", "ID", "WD")]

    @pytest.mark.parametrize("sddl", ["", "garbage", "O:BAD:", "D:(A;;FA)"])
    def test_unparsable_permissions_fail_closed(self, sddl):
        with pytest.raises(CredentialError):
            mvp.parse_dacl(sddl)

    def _problems(self, sddl):
        class Runner:
            def __call__(self_inner, argv):
                if "/save" in argv:
                    with open(argv[argv.index("/save") + 1], "wb") as handle:
                        handle.write(("x\r\n" + sddl + "\r\n").encode("utf-16-le"))
                return CommandResult(0, b"")

        return mvp.windows_problems("C:\\x", _SID, runner=Runner(), environ={"SystemRoot": r"C:\Windows"})

    def test_private_acl_has_no_problems(self):
        assert self._problems(f"D:P(A;;FA;;;{_SID})") == []
        assert self._problems(f"D:PAI(A;;FA;;;{_SID})(A;;FA;;;SY)(A;;FA;;;BA)") == []
        # what Python 3.13 creates for a directory made with mode 0o700, plus the user entry
        assert self._problems(f"D:PAI(A;OICI;FA;;;{_SID})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)") == []

    @pytest.mark.parametrize("sddl,expected", [
        (f"D:(A;;FA;;;{_SID})", "inherits"),                                   # not protected
        (f"D:P(A;ID;FA;;;{_SID})", "inherited entry"),
        (f"D:P(A;;FA;;;{_SID})(A;;FR;;;WD)", "another account"),               # Everyone
        (f"D:P(A;;FA;;;{_SID})(A;;FR;;;BU)", "another account"),               # Users
        (f"D:P(A;;FA;;;{_SID})(A;;FR;;;AU)", "another account"),               # Authenticated Users
        (f"D:P(A;;FA;;;{_SID})(A;;FA;;;{_OTHER_SID})", "another account"),
        (f"D:P(A;;FA;;;{_SID})(D;;FW;;;{_OTHER_SID})", "not a plain allow"),
        (f"D:P(A;;FA;;;SY)(A;;FA;;;BA)", "current user"),
        ("D:P", "no access entry"),
    ])
    def test_unsafe_acls_are_reported(self, sddl, expected):
        assert any(expected in problem for problem in self._problems(sddl)), self._problems(sddl)

    def test_init_hardens_by_sid_then_verifies_before_reporting_success(self, tmp_path):
        fake = FakeWindows()
        target, code, out, err = _init(tmp_path, runner=fake)
        assert code == mvp.EXIT_OK, err
        icacls = [call for call in fake.calls if ntpath.basename(call[0]).lower() == "icacls.exe"]
        grants = [c for c in icacls if "/grant:r" in c]
        assert [c[1] for c in grants] == [str(target.parent), str(target)]
        assert grants[0][3] == f"*{_SID}:(OI)(CI)(F)" and grants[1][3] == f"*{_SID}:(F)"
        assert all("/inheritance:r" in c or "/grant:r" in c or "/save" in c for c in icacls)
        saves = [c for c in icacls if "/save" in c]
        assert len(saves) >= 3                                   # directory, empty file, final file
        assert fake.state[str(target)] == "private" and fake.state[str(target.parent)] == "private"

    def test_tools_are_called_by_absolute_system_path(self, tmp_path):
        fake = FakeWindows()
        _init(tmp_path, runner=fake)
        for call in fake.calls:
            assert call[0] in (r"C:\Windows\System32\whoami.exe", r"C:\Windows\System32\icacls.exe")

    def test_no_secret_value_appears_in_any_command(self, tmp_path, monkeypatch):
        sentinels = {name: f"SENTINEL-{index}-".ljust(43, "q") for index, name in enumerate(mvp.CREDENTIAL_VARIABLES)}
        monkeypatch.setattr(mvp, "generate_credentials", lambda: dict(sentinels))
        fake = FakeWindows()
        target, code, out, err = _init(tmp_path, runner=fake)
        assert code == mvp.EXIT_OK
        flat = " ".join(" ".join(call) for call in fake.calls)
        assert not any(value in flat or value in out or value in err for value in sentinels.values())
        assert all(value in target.read_text(encoding="ascii") for value in sentinels.values())

    @pytest.mark.parametrize("failure,fragment", [
        ("whoami", "current user"), ("grant", "could not be set"), ("save", "could not be read"),
    ])
    def test_tool_failures_fail_closed_and_remove_what_the_run_created(self, tmp_path, failure, fragment):
        fake = FakeWindows(fail=failure)
        target, code, out, err = _init(tmp_path, runner=fake)
        assert code != mvp.EXIT_OK and fragment in err
        assert not target.exists() and not target.parent.exists()

    def test_a_missing_tool_fails_closed(self, tmp_path):
        def missing(argv):
            raise CredentialError("a required Windows tool could not be run", mvp.EXIT_FAILED)

        target, code, out, err = _init(tmp_path, runner=missing)
        assert code == mvp.EXIT_FAILED and not target.exists()

    def test_the_default_runner_turns_missing_tools_into_a_refusal(self, monkeypatch):
        def no_such(*a, **k):
            raise FileNotFoundError(2, "no such file")

        monkeypatch.setattr(mvp.subprocess, "run", no_such)
        with pytest.raises(CredentialError, match="could not be run"):
            mvp.default_runner(["whatever.exe"])

    def test_unparsable_permissions_never_report_success(self, tmp_path):
        target, code, out, err = _init(tmp_path, runner=FakeWindows(garbage=True))
        assert code != mvp.EXIT_OK and not target.exists()
        assert "created" not in out

    def test_a_broad_result_never_reports_success(self, tmp_path):
        target, code, out, err = _init(tmp_path, runner=FakeWindows(broaden=True))
        assert code == mvp.EXIT_FAILED and "another account" in err and not target.exists()
        assert "created" not in out

    @pytest.mark.parametrize("text", ["", "no sid here", '"HOST\\user"'])
    def test_an_unreadable_user_sid_fails_closed(self, tmp_path, text):
        target, code, out, err = _init(tmp_path, runner=FakeWindows(whoami_text=text))
        assert code == mvp.EXIT_FAILED and not target.exists()

    def test_sddl_scratch_file_is_removed(self, tmp_path):
        fake = FakeWindows()
        _init(tmp_path, runner=fake)
        for call in fake.calls:
            if "/save" in call:
                assert not os.path.exists(call[call.index("/save") + 1])

    @windows_only
    def test_real_icacls_hardens_and_the_verification_catches_inherited_permissions(self, tmp_path):
        """Dummy directory and file only; nothing secret is written."""
        environ = dict(os.environ)
        sid = mvp.current_user_sid(mvp.default_runner, environ)
        assert re.fullmatch(r"S-1-5-21(-\d+)+", sid) or sid.startswith("S-1-")
        directory = tmp_path / "real-acl"
        directory.mkdir()
        dummy = directory / "dummy.txt"
        dummy.write_text("not a credential", encoding="utf-8")
        for path in (directory, dummy):
            problems = mvp.windows_problems(str(path), sid, runner=mvp.default_runner, environ=environ)
            assert any("inherit" in p for p in problems), (path, problems)      # a new object inherits
        mvp.windows_harden(str(directory), sid, is_dir=True, runner=mvp.default_runner, environ=environ)
        mvp.windows_harden(str(dummy), sid, is_dir=False, runner=mvp.default_runner, environ=environ)
        for path in (directory, dummy):
            assert mvp.windows_problems(str(path), sid, runner=mvp.default_runner, environ=environ) == []
        assert dummy.read_text(encoding="utf-8") == "not a credential"      # still accessible to its owner


@windows_only
def test_real_windows_tools_end_to_end_in_a_temporary_directory(tmp_path):
    """The whole flow with the REAL whoami/icacls, below pytest's temporary directory.

    This is not the MVP credential location and the generated values are discarded with
    the directory.  It is the evidence that the Windows permission handling works with
    the real operating-system tools, not only with the mock.
    """
    environ = dict(os.environ)
    environ["LOCALAPPDATA"] = str(tmp_path)          # never the real per-user location
    target = tmp_path / mvp.DIRECTORY_NAME / mvp.FILE_NAME
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(["init-credentials", "--credentials-file", str(target)], environ=environ,
                    platform_name="nt", repo_root=tmp_path / "repo-elsewhere", out=out, err=err)
    assert code == mvp.EXIT_OK, err.getvalue()
    values = mvp.parse_file(target.read_bytes())
    assert len(values) == 8 and not any(v in out.getvalue() + err.getvalue() for v in values.values())
    sid = mvp.current_user_sid(mvp.default_runner, environ)
    for path in (target.parent, target):
        assert mvp.windows_problems(str(path), sid, runner=mvp.default_runner, environ=environ) == []
    out2, err2 = io.StringIO(), io.StringIO()
    assert mvp.main(["check-credentials", "--credentials-file", str(target)], environ=environ,
                    platform_name="nt", repo_root=tmp_path / "repo-elsewhere", out=out2, err=err2) == mvp.EXIT_OK
    # a second init must refuse and leave the file untouched
    before = target.read_bytes()
    out3, err3 = io.StringIO(), io.StringIO()
    assert mvp.main(["init-credentials", "--credentials-file", str(target)], environ=environ,
                    platform_name="nt", repo_root=tmp_path / "repo-elsewhere", out=out3, err=err3) == mvp.EXIT_EXISTS
    assert target.read_bytes() == before
    # the owner can still read and, if needed, remove it
    assert target.read_bytes()


# ---------------------------------------------------------------------------
# T09  check-credentials
# ---------------------------------------------------------------------------

class TestCheck:

    def test_a_valid_private_file_passes_and_values_are_not_shown(self, tmp_path):
        target, fake = _write_valid(tmp_path)
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_OK and "8 variables" in out
        assert not any(value in out + err for value in _values().values())

    def test_a_missing_file_points_to_init(self, tmp_path):
        code, out, err = _run(["check-credentials", "--credentials-file", str(_target(tmp_path))], tmp_path)
        assert code == mvp.EXIT_REFUSED and "init-credentials" in err

    def test_a_missing_directory_is_reported(self, tmp_path):
        target = _target(tmp_path)
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path)
        assert code == mvp.EXIT_REFUSED

    @pytest.mark.parametrize("label,data", [
        ("empty", b""),
        ("truncated", _content()[:200]),
        ("no footer", _content().replace(mvp.FOOTER.encode(), b"")),
        ("extra key", _content().replace(mvp.FOOTER.encode(), b"EXTRA=" + b"e" * 40 + b"\n" + mvp.FOOTER.encode())),
        ("short value", _content().replace(b"V0", b"V0", 1)[:0] + mvp.HEADER.encode() + b"\nPOSTGRES_PASSWORD=short\n" + mvp.FOOTER.encode() + b"\n"),
        ("CRLF", _content().replace(b"\n", b"\r\n")),
    ])
    def test_an_invalid_file_is_refused_and_left_unchanged(self, tmp_path, label, data):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        fake = FakeWindows()
        fake.make_private(target.parent, target)
        before, mtime = target.read_bytes(), target.stat().st_mtime_ns
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_REFUSED and err.startswith("error:")
        assert target.read_bytes() == before and target.stat().st_mtime_ns == mtime
        assert not any("/grant:r" in call or "/inheritance:r" in call for call in fake.calls)

    def test_weak_windows_permissions_are_refused_and_not_repaired(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        target.write_bytes(_content())
        fake = FakeWindows()        # both objects are "inherited": not private
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_REFUSED and "inherits" in err
        assert not any("/grant:r" in call for call in fake.calls)

    def test_check_never_creates_or_regenerates(self, tmp_path):
        target = _target(tmp_path)
        _run(["check-credentials", "--credentials-file", str(target)], tmp_path)
        assert not target.exists() and not target.parent.exists()

    def test_the_file_is_read_without_following_links_on_posix(self):
        assert "O_NOFOLLOW" in _SOURCE


# ---------------------------------------------------------------------------
# T10  Redaction
# ---------------------------------------------------------------------------

class TestRedaction:

    _SECRET = "LEAK-CANARY-9f8e7d6c5b4a-" + "k" * 20

    def _file_with_secret_problem(self, tmp_path):
        """A file whose rejected line carries a recognizable canary value."""
        lines = _content().decode("ascii").split("\n")
        lines[1] = "POSTGRES_PASSWORD=" + self._SECRET + "!bad"      # invalid character
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        target.write_bytes("\n".join(lines).encode("ascii"))
        fake = FakeWindows()
        fake.make_private(target.parent, target)
        return target, fake

    def test_a_rejected_value_is_never_echoed(self, tmp_path):
        target, fake = self._file_with_secret_problem(tmp_path)
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_REFUSED
        assert "LEAK-CANARY" not in out + err and "POSTGRES_PASSWORD" in err

    def test_a_duplicate_or_extra_entry_names_the_variable_not_the_value(self, tmp_path):
        lines = _content().decode("ascii").split("\n")
        lines.insert(2, "POSTGRES_PASSWORD=" + self._SECRET)
        with pytest.raises(CredentialError) as info:
            mvp.parse_file("\n".join(lines).encode("ascii"))
        assert "LEAK-CANARY" not in str(info.value) and "POSTGRES_PASSWORD" in str(info.value)

    def test_unexpected_exceptions_report_only_their_type(self, tmp_path, monkeypatch):
        def explode(data):
            raise ValueError("internal detail " + self._SECRET)

        monkeypatch.setattr(mvp, "parse_file", explode)
        target, fake = _write_valid(tmp_path)
        code, out, err = _run(["check-credentials", "--credentials-file", str(target)], tmp_path, runner=fake)
        assert code == mvp.EXIT_INTERNAL and "ValueError" in err
        assert "LEAK-CANARY" not in out + err and "internal detail" not in err

    def test_errors_raised_from_a_cause_do_not_carry_it(self, tmp_path, monkeypatch):
        class Boom(OSError):
            pass

        def read_fails(path):
            raise Boom(5, "payload " + self._SECRET)

        monkeypatch.setattr(mvp, "_read_bytes", read_fails)
        target, fake = _write_valid(tmp_path)
        with pytest.raises(CredentialError) as info:
            mvp.check_credentials(os.path.abspath(target), mvp._Context(_nt_environ(tmp_path), "nt", fake))
        assert info.value.__cause__ is None and "LEAK-CANARY" not in str(info.value)

    def test_success_output_never_contains_a_generated_value(self, tmp_path, monkeypatch):
        canary = {name: f"CANARY{index}-".ljust(43, "c") for index, name in enumerate(mvp.CREDENTIAL_VARIABLES)}
        monkeypatch.setattr(mvp, "generate_credentials", lambda: dict(canary))
        target, code, out, err = _init(tmp_path)
        assert code == mvp.EXIT_OK
        assert "CANARY" not in out + err

    def test_the_command_line_has_no_option_that_accepts_a_value_for_a_variable(self):
        parser = mvp._build_parser()
        help_text = parser.format_help() + "".join(
            action.format_usage() for action in parser._subparsers._group_actions[0].choices.values())
        assert "PASSWORD" not in help_text.upper().replace("CREDENTIAL", "")


# ---------------------------------------------------------------------------
# T11  No container engine, no destructive operation
# ---------------------------------------------------------------------------

class TestScope:

    def _tree(self):
        return ast.parse(_SOURCE)

    def test_no_container_tool_verb_other_than_the_two_read_only_ones_exists(self):
        """The module names the container tool only to inspect: "compose config" and
        "context inspect".  In the functions that build or issue those commands, every
        single-token string constant is on an explicit allow-list, so no verb that starts,
        stops, builds, creates or removes anything can be added unnoticed."""
        tree = self._tree()
        functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        allowed = {"docker", "compose", "context", "inspect", "config", "-p", "--project-directory", "-f",
                   "--format", "{{.Endpoints.docker.Host}}", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
                   "DOCKER_HOST", "DOCKER_CONTEXT",
                   "utf-8", "replace", ".env", "COMPOSE_"}      # codec names, the stray-file check, the prefix
        for name in ("compose_argv", "require_local_engine", "check_config", "build_child_environment"):
            for node in ast.walk(functions[name]):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    text = node.value
                    if " " in text or "\n" in text or len(text) > 40:
                        continue                                  # message text
                    assert text in allowed, (name, text)
        for verb in ("up", "down", "run", "start", "stop", "kill", "rm", "build", "create", "exec", "pull",
                     "push", "cp", "logs", "prune", "--volumes", "--remove-orphans", "--force",
                     "--build", "--force-recreate", "-d", "--detach"):
            for name in ("compose_argv", "require_local_engine", "check_config"):
                assert not any(isinstance(n, ast.Constant) and n.value == verb for n in ast.walk(functions[name])), (name, verb)
        assert mvp._ALLOWED_COMPOSE_SUBCOMMANDS == frozenset({"config"})
        assert mvp._INSPECTION_OPTIONS == ("--format", "json", "--no-interpolate")

    def test_no_module_other_than_the_standard_library_is_imported(self):
        imported = set()
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add((node.module or "").split(".")[0])
        # the sibling modules (lifecycle foundation, demo dataset) are imported lazily, one helper each
        siblings = {"agentops_mvp_lifecycle", "agentops_mvp_demo"}
        assert imported <= set(sys.stdlib_module_names) | {"__future__"} | siblings
        assert imported & siblings == siblings
        for name, helper_name, next_name in (("agentops_mvp_lifecycle", "def _lifecycle_module", "def _default_probes"),
                                             ("agentops_mvp_demo", "def _demo_module", "# -- demo seeding")):
            helper = _SOURCE[_SOURCE.index(helper_name):_SOURCE.index(next_name)]
            assert f"import {name}" in helper
            assert _SOURCE.count(f"import {name}") == 1

    def test_only_the_expected_commands_exist(self):
        parser = mvp._build_parser()
        choices = set(parser._subparsers._group_actions[0].choices)
        assert choices == {"init-credentials", "check-credentials", "check-config", "status", "build", "up", "seed-demo"}
        for forbidden in ("down", "reset", "smoke", "start", "stop"):
            assert forbidden not in choices

    def test_status_takes_no_credential_file_option(self):
        status = mvp._build_parser()._subparsers._group_actions[0].choices["status"]
        assert "--credentials-file" not in status.format_help()

    def test_removal_calls_exist_only_where_the_run_removes_what_it_created(self):
        tree = self._tree()
        found: dict[str, set[str]] = {}
        for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    # file-system calls only (str.replace and the like are not removals)
                    owner = node.func.value
                    if isinstance(owner, ast.Name) and owner.id in {"os", "shutil"} and node.func.attr in {
                            "unlink", "remove", "rmdir", "rmtree", "removedirs", "rename", "replace", "truncate"}:
                        found.setdefault(function.name, set()).add(node.func.attr)
                    if node.func.attr in {"unlink", "rmdir", "rmtree", "removedirs", "truncate"} and not (
                            isinstance(owner, ast.Name) and owner.id == "os"):
                        found.setdefault(function.name + ":other", set()).add(node.func.attr)
        assert found == {"_rollback": {"unlink", "rmdir"}, "_read_sddl": {"unlink"}}

    def test_subprocess_is_used_in_exactly_three_runners_without_a_shell(self):
        tree = self._tree()
        owners = {}
        for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(function):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                        and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}):
                    owners.setdefault(function.name, []).append(node)
        assert set(owners) == {"default_runner", "default_compose_runner", "_run_bounded"}
        for calls in owners.values():
            assert len(calls) == 1 and calls[0].func.attr == "run"
            assert any(k.arg == "shell" and getattr(k.value, "value", None) is False for k in calls[0].keywords)
        assert not any(isinstance(n, ast.Name) and n.id in {"shell", "os_system"} for n in ast.walk(tree))
        assert "os.system" not in _SOURCE and "shell=True" not in _SOURCE

    def test_nothing_is_ever_run_during_a_posix_style_run(self, tmp_path):
        ran = []

        def tracker(argv):
            ran.append(list(argv))
            return CommandResult(0, b"")

        if os.name == "nt":
            pytest.skip("POSIX run needs POSIX permission calls")
        _run(["init-credentials", "--credentials-file", str(_target(tmp_path))], tmp_path,
             platform_name="posix", runner=tracker)
        assert ran == []

    def test_only_windows_tools_are_ever_invoked(self, tmp_path):
        fake = FakeWindows()
        _init(tmp_path, runner=fake)
        for call in fake.calls:
            assert ntpath.basename(call[0]).lower() in {"whoami.exe", "icacls.exe"}

    def test_a_real_subprocess_is_never_started_by_the_mocked_runs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("subprocess.run was called"))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("Popen was called"))
        _init(tmp_path)
        _run(["check-credentials", "--credentials-file", str(_target(tmp_path))], tmp_path)

    def test_the_real_default_location_is_never_used_when_the_environment_is_injected(self, tmp_path, monkeypatch):
        real = tmp_path / "real-default-must-stay-empty"
        for variable in ("LOCALAPPDATA", "XDG_CONFIG_HOME", "HOME", "USERPROFILE"):
            monkeypatch.setenv(variable, str(real))
        injected = dict(platform_name=os.name, runner=_host_runner(), environ=_host_environ(tmp_path),
                        home=str(tmp_path / "home"))
        assert _run(["init-credentials"], tmp_path, **injected)[0] == mvp.EXIT_OK
        assert _run(["check-credentials"], tmp_path, **injected)[0] == mvp.EXIT_OK
        assert not real.exists()
        assert (tmp_path / "local" / mvp.DIRECTORY_NAME / mvp.FILE_NAME).is_file()


# ---------------------------------------------------------------------------
# T13  check-config
# ---------------------------------------------------------------------------

_DOCKER = "/usr/bin/docker"
_LOCAL_ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
_HOST_SECRET = "HOST-SECRET-must-never-appear-anywhere-0123456789"


def _ref(name: str) -> str:
    return "${" + name + ":?" + name + " must be set}"


def _resolved(repo: Path = _REPO, *, short: bool = False) -> dict:
    """What `compose config` is expected to print for docker/mvp/compose.yml, in the long
    (normalized) syntax, or in the short syntax when short=True."""
    root = str(repo)

    def build(dockerfile):
        return {"context": root, "dockerfile": dockerfile}

    bootstrap_env = {
        "BOOTSTRAP_DB_HOST": "postgres", "BOOTSTRAP_DB_PORT": "5432", "BOOTSTRAP_DB_NAME": "agentops",
        "BOOTSTRAP_DB_ADMIN_USER": "agentops", "BOOTSTRAP_DB_ADMIN_PASSWORD": _ref("POSTGRES_PASSWORD"),
    }
    for name in mvp.CREDENTIAL_VARIABLES[1:]:
        bootstrap_env[name] = _ref(name)
    depends_viewer = {"postgres": {"condition": "service_healthy", "required": True},
                      "db-bootstrap": {"condition": "service_completed_successfully", "required": True}}
    config = {
        "name": "agentops-mvp",
        "services": {
            "postgres": {
                "build": build("docker/postgres/Dockerfile"), "restart": "no",
                "environment": {"POSTGRES_DB": "agentops", "POSTGRES_USER": "agentops",
                                "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256",
                                "POSTGRES_PASSWORD": _ref("POSTGRES_PASSWORD")},
                "volumes": [{"type": "volume", "source": "postgres-data",
                             "target": "/var/lib/postgresql/data", "volume": {}}],
                "healthcheck": {"test": ["CMD-SHELL", "pg_isready -h 127.0.0.1 -p 5432 -U agentops -d agentops"],
                                "interval": "3s", "timeout": "3s", "retries": 20, "start_period": "10s"},
                "networks": {"mvp-net": None},
            },
            "db-bootstrap": {
                "build": build("docker/bootstrap/Dockerfile"), "restart": "no",
                "depends_on": {"postgres": {"condition": "service_healthy", "required": True}},
                "environment": bootstrap_env, "networks": {"mvp-net": None},
            },
            "viewer": {
                "build": build("docker/trace-viewer/Dockerfile"), "restart": "no",
                "depends_on": depends_viewer,
                "environment": {"TRACE_VIEWER_DB_HOST": "postgres", "TRACE_VIEWER_DB_PORT": "5432",
                               "TRACE_VIEWER_DB_NAME": "agentops", "TRACE_VIEWER_DB_USER": "trace_viewer_reader",
                               "TRACE_VIEWER_DB_PASSWORD": _ref("TRACE_VIEWER_DB_PASSWORD")},
                "ports": [{"mode": "ingress", "host_ip": "127.0.0.1", "target": 8000,
                           "published": "8000", "protocol": "tcp"}],
                "healthcheck": {"test": ["CMD", "python", "-c",
                                         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"],
                                "interval": "10s", "timeout": "5s", "retries": 5, "start_period": "10s"},
                "read_only": True, "tmpfs": ["/tmp"], "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"], "networks": {"mvp-net": None},
            },
        },
        "networks": {"mvp-net": {"name": "agentops-mvp_mvp-net", "driver": "bridge"}},
        "volumes": {"postgres-data": {"name": "agentops-mvp-postgres-data", "labels": {"agentops.mvp": "true"}}},
    }
    if short:
        services = config["services"]
        services["postgres"]["volumes"] = ["postgres-data:/var/lib/postgresql/data"]
        services["viewer"]["ports"] = ["127.0.0.1:8000:8000"]
        for service in services.values():
            service["networks"] = ["mvp-net"]
            service["environment"] = [f"{k}={v}" for k, v in service["environment"].items()]
        services["viewer"]["depends_on"] = {k: {"condition": v["condition"]} for k, v in depends_viewer.items()}
        services["db-bootstrap"]["depends_on"] = {"postgres": {"condition": "service_healthy"}}
        config["networks"] = {"mvp-net": {"driver": "bridge"}}
    return config


class FakeEngine:
    """Stands in for the container tool: answers `context inspect` and `compose ... config`,
    and records every call.  Nothing real is ever run."""

    def __init__(self, config=None, *, endpoint=_LOCAL_ENDPOINT, context_rc=0, config_rc=0,
                 stdout=None):
        self.config = _resolved() if config is None else config
        self.endpoint = endpoint
        self.context_rc = context_rc
        self.config_rc = config_rc
        self.stdout = stdout
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, argv, env):
        self.calls.append((list(argv), dict(env)))
        if list(argv[1:3]) == ["context", "inspect"]:
            return CommandResult(self.context_rc, (self.endpoint + "\n").encode())
        assert list(argv[1:2]) == ["compose"], argv
        if self.stdout is not None:
            return CommandResult(self.config_rc, self.stdout)
        import json as _json
        return CommandResult(self.config_rc, _json.dumps(self.config).encode())

    @property
    def compose_calls(self):
        return [c for c in self.calls if c[0][1:2] == ["compose"]]

    @property
    def context_calls(self):
        return [c for c in self.calls if c[0][1:3] == ["context", "inspect"]]


def _check_config(tmp_path, engine, *, values=None, host=None, docker=_DOCKER, repo_root=None,
                  prepared=None, which=None):
    target, fake = prepared if prepared else _write_valid(tmp_path, values=values)
    environ = {"SystemRoot": r"C:\Windows", "PATH": "/usr/bin", "DOCKER_CONFIG": "/home/x/.docker"}
    environ.update(host or {})
    out, err = io.StringIO(), io.StringIO()
    kwargs = {} if which is None else {"which": which}
    code = mvp.main(
        ["check-config", "--credentials-file", str(target)],
        environ=environ, platform_name="nt", runner=fake, compose_runner=engine,
        docker=docker, repo_root=repo_root if repo_root is not None else _REPO,
        out=out, err=err, **kwargs,
    )
    return code, out.getvalue(), err.getvalue(), target, fake


class TestCheckConfig:

    def test_a_valid_configuration_passes_in_long_and_short_syntax(self, tmp_path):
        for index, short in enumerate((False, True)):
            engine = FakeEngine(_resolved(short=short))
            code, out, err, target, fake = _check_config(tmp_path / str(index), engine)
            assert code == mvp.EXIT_OK, err
            assert "configuration OK: project agentops-mvp" in out and "nothing was started" in out
            assert not any(v in out + err for v in _values().values())

    def test_the_real_compose_file_satisfies_the_validator(self):
        if os.environ.get("CI", "").lower() in ("true", "1"):
            import yaml
        else:
            yaml = pytest.importorskip("yaml")
        document = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
        for service in document["services"].values():
            service["build"] = {"context": str(_REPO), "dockerfile": service["build"]["dockerfile"]}
        assert mvp.validate_resolved_config(document, _REPO) == []

    # -- exact command construction -------------------------------------------------

    def test_the_inspection_command_is_an_exact_argument_list(self, tmp_path):
        engine = FakeEngine()
        assert _check_config(tmp_path, engine)[0] == mvp.EXIT_OK
        compose_file = _REPO / "docker" / "mvp" / "compose.yml"
        assert [c[0] for c in engine.compose_calls] == [[
            _DOCKER, "compose", "-p", "agentops-mvp", "--project-directory", str(compose_file.parent),
            "-f", str(compose_file), "config", "--format", "json", "--no-interpolate"]]
        assert [c[0] for c in engine.context_calls] == [[
            _DOCKER, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"]]
        for argv, env in engine.calls:
            assert isinstance(argv, list) and all(isinstance(part, str) for part in argv)
            assert "--env-file" not in argv and argv.count("-f") <= 1

    def test_compose_argv_names_one_file_the_project_and_only_the_config_subcommand(self):
        argv = mvp.compose_argv("docker", _REPO, ["config"])
        assert argv[:2] == ["docker", "compose"] and argv.count("-f") == 1 and argv.count("-p") == 1
        assert argv[argv.index("-p") + 1] == "agentops-mvp"
        assert Path(argv[argv.index("-f") + 1]) == _REPO / "docker" / "mvp" / "compose.yml"
        assert Path(argv[argv.index("--project-directory") + 1]) == _REPO / "docker" / "mvp"
        for forbidden in ("up", "down", "run", "start", "stop", "restart", "rm", "kill", "build", "exec",
                          "create", "pull", "push", "cp", "logs", "volume", "reset", "-v", "--volumes"):
            with pytest.raises(CredentialError):
                mvp.compose_argv("docker", _REPO, [forbidden])
        with pytest.raises(CredentialError):
            mvp.compose_argv("docker", _REPO, [])

    def test_the_compose_file_comes_from_the_repository_root_not_the_working_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        engine = FakeEngine()
        assert _check_config(tmp_path / "w", engine)[0] == mvp.EXIT_OK
        assert str(_REPO / "docker" / "mvp" / "compose.yml") in engine.compose_calls[0][0]
        assert str(tmp_path) not in " ".join(engine.compose_calls[0][0])

    # -- environment isolation ---------------------------------------------------------

    def test_the_child_environment_has_no_compose_variables_and_no_credentials(self, tmp_path):
        host = {"COMPOSE_FILE": "other.yml", "COMPOSE_PROJECT_NAME": "legacy", "compose_profiles": "x",
                "Compose_Env_Files": "bad.env", "COMPOSE_PATH_SEPARATOR": ";", "KEEP_ME": "yes",
                "POSTGRES_PASSWORD": _HOST_SECRET, "trace_viewer_db_password": _HOST_SECRET + "2"}
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, host=host)
        assert code == mvp.EXIT_OK, err
        for _argv, env in engine.calls:
            upper = {key.upper() for key in env}
            assert not any(key.startswith("COMPOSE_") for key in upper)
            assert not upper & {name.upper() for name in mvp.CREDENTIAL_VARIABLES}
            assert env["KEEP_ME"] == "yes" and env["DOCKER_CONFIG"] == "/home/x/.docker" and env["PATH"] == "/usr/bin"
        assert _HOST_SECRET not in out + err

    def test_no_credential_value_from_the_file_reaches_the_inspection_environment(self, tmp_path):
        engine = FakeEngine()
        _check_config(tmp_path, engine)
        flat = " ".join(" ".join(argv) + " " + " ".join(env.values()) for argv, env in engine.calls)
        assert not any(value in flat for value in _values().values())

    def test_file_values_take_precedence_over_inherited_variables(self):
        values = _values("F")
        host = {"POSTGRES_PASSWORD": "host-value", "trace_viewer_db_password": "host-value-2",
                "COMPOSE_FILE": "x", "KEEP": "1"}
        child = mvp.build_child_environment(host, values)
        for name in mvp.CREDENTIAL_VARIABLES:
            assert child[name] == values[name]
        assert "trace_viewer_db_password" not in child and "COMPOSE_FILE" not in child and child["KEEP"] == "1"
        assert "host-value" not in " ".join(child.values())
        assert host["POSTGRES_PASSWORD"] == "host-value"            # the caller's mapping is untouched

    def test_invalid_values_are_refused_before_they_can_be_exported(self):
        values = _values("F")
        values["POSTGRES_PASSWORD"] = "short"
        with pytest.raises(CredentialError):
            mvp.build_child_environment({}, values)

    def test_a_credential_value_in_the_compose_output_is_discarded_unread(self, tmp_path):
        for secret in (_values()["POSTGRES_PASSWORD"], _HOST_SECRET):
            config = _resolved()
            config["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = secret
            engine = FakeEngine(config)
            code, out, err, *_ = _check_config(tmp_path / secret[:6], engine, host={"POSTGRES_PASSWORD": _HOST_SECRET})
            assert code == mvp.EXIT_REFUSED and "contained a credential value" in err
            assert secret not in out + err

    # -- local engine --------------------------------------------------------------------

    @pytest.mark.parametrize("host", ["unix:///var/run/docker.sock", "unix:///Users/x/.docker/run/docker.sock",
                                      "npipe:////./pipe/docker_engine", "npipe:///./pipe/dockerDesktopLinuxEngine"])
    def test_local_endpoints_are_accepted(self, tmp_path, host):
        engine = FakeEngine()
        assert _check_config(tmp_path, engine, host={"DOCKER_HOST": host})[0] == mvp.EXIT_OK

    @pytest.mark.parametrize("host", ["tcp://127.0.0.1:2375", "tcp://localhost:2376", "tcp://10.0.0.5:2375",
                                      "ssh://user@server", "http://x", "fd://", "npipe://server/pipe/docker_engine",
                                      "unix://", "foo", ""])
    def test_remote_or_unknown_endpoints_are_refused_without_running_anything(self, tmp_path, host):
        engine = FakeEngine()
        env = {"DOCKER_HOST": host} if host else {}
        if host == "":
            engine = FakeEngine(endpoint="tcp://203.0.113.9:2375")      # empty variable: the context decides
        code, out, err, *_ = _check_config(tmp_path, engine, host=env)
        assert code == mvp.EXIT_REFUSED and "local" in err
        assert engine.compose_calls == []

    @pytest.mark.parametrize("variable", ["DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"])
    def test_tls_settings_mean_a_remote_engine_and_are_refused(self, tmp_path, variable):
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, host={variable: "1"})
        assert code == mvp.EXIT_REFUSED and variable in err and engine.calls == []

    @pytest.mark.parametrize("name", ["--help", "a b", "-x", "a;b", "$(x)", "a/b", ""])
    def test_unexpected_context_names_are_refused(self, tmp_path, name):
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, host={"DOCKER_CONTEXT": name} if name else {})
        if name:
            assert code == mvp.EXIT_REFUSED and engine.calls == []
        else:
            assert code == mvp.EXIT_OK

    def test_a_named_context_is_inspected_and_must_be_local(self, tmp_path):
        engine = FakeEngine()
        assert _check_config(tmp_path / "a", engine, host={"DOCKER_CONTEXT": "desktop-linux"})[0] == mvp.EXIT_OK
        assert engine.context_calls[0][0] == [_DOCKER, "context", "inspect", "desktop-linux",
                                              "--format", "{{.Endpoints.docker.Host}}"]
        remote = FakeEngine(endpoint="ssh://user@build-server")
        code, out, err, *_ = _check_config(tmp_path / "b", remote, host={"DOCKER_CONTEXT": "remote"})
        assert code == mvp.EXIT_REFUSED and remote.compose_calls == []

    def test_a_remote_current_context_is_refused(self, tmp_path):
        engine = FakeEngine(endpoint="tcp://192.0.2.7:2376")
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code == mvp.EXIT_REFUSED and engine.compose_calls == []

    def test_an_uninspectable_context_fails_closed(self, tmp_path):
        engine = FakeEngine(context_rc=1)
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code == mvp.EXIT_FAILED and "could not be established" in err and engine.compose_calls == []

    @pytest.mark.parametrize("endpoint,expected", [
        ("unix:///var/run/docker.sock", True), ("npipe:////./pipe/x", True), ("npipe:///./pipe/x", True),
        ("npipe://srv/pipe/x", False), ("tcp://127.0.0.1:1", False), ("ssh://h", False), ("", False),
        ("unix://", False), ("fd://", False), ("  unix:///x  ", True),
    ])
    def test_endpoint_classification(self, endpoint, expected):
        assert mvp.endpoint_is_local(endpoint) is expected

    # -- the Compose inspection itself ----------------------------------------------------

    def test_unsupported_inspection_options_fail_closed_with_a_fixed_message(self, tmp_path):
        engine = FakeEngine(config_rc=1, stdout=b"unknown flag: --no-interpolate " + _HOST_SECRET.encode())
        code, out, err, *_ = _check_config(tmp_path, engine, host={"POSTGRES_PASSWORD": _HOST_SECRET})
        assert code == mvp.EXIT_FAILED and "--no-interpolate" in err and "may not support" in err
        assert _HOST_SECRET not in out + err and "unknown flag" not in err

    @pytest.mark.parametrize("stdout", [b"", b"not json", b"[]", b"null", b'"text"', b"{", b"{}"])
    def test_malformed_output_is_refused(self, tmp_path, stdout):
        engine = FakeEngine(stdout=stdout)
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code in (mvp.EXIT_REFUSED, mvp.EXIT_FAILED) and err.startswith("error:")
        assert engine.compose_calls

    def test_oversized_output_is_refused(self, tmp_path):
        engine = FakeEngine(stdout=b" " * (mvp._MAX_COMPOSE_OUTPUT + 5))
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code == mvp.EXIT_REFUSED and "larger" in err

    def test_unredacted_child_output_is_never_printed(self, tmp_path):
        canary = b"LEAK-CANARY-" + b"c" * 30
        engine = FakeEngine(stdout=canary)
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code != mvp.EXIT_OK and "LEAK-CANARY" not in out + err

    def test_the_default_runner_returns_stdout_only_and_never_uses_a_shell(self, monkeypatch):
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"], seen["kwargs"] = argv, kwargs
            return subprocess.CompletedProcess(argv, 0, stdout=b"{}", stderr=b"stderr LEAK-CANARY")

        monkeypatch.setattr(mvp.subprocess, "run", fake_run)
        result = mvp.default_compose_runner(["docker", "compose", "config"], {"A": "1"})
        assert result == CommandResult(0, b"{}") and not hasattr(result, "stderr")
        assert seen["kwargs"]["shell"] is False and seen["kwargs"]["env"] == {"A": "1"}
        assert seen["kwargs"]["capture_output"] is True and isinstance(seen["argv"], list)

    def test_a_missing_container_tool_fails_closed_without_running_anything(self, tmp_path):
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, docker=None, which=lambda name: None)
        assert code == mvp.EXIT_FAILED and "not found" in err and engine.calls == []

    def test_the_container_tool_is_looked_up_as_docker(self, tmp_path):
        asked = []

        def which(name):
            asked.append(name)
            return _DOCKER

        engine = FakeEngine()
        assert _check_config(tmp_path, engine, docker=None, which=which)[0] == mvp.EXIT_OK
        assert asked == ["docker"] and engine.calls[0][0][0] == _DOCKER

    # -- the resolved configuration ---------------------------------------------------------

    @staticmethod
    def _mutations():
        def edit(fn):
            def apply(config):
                fn(config)
                return config
            return apply

        S = lambda c, n: c["services"][n]  # noqa: E731
        return {
            "container_name added": edit(lambda c: S(c, "viewer").update(container_name="agentops-viewer")),
            "legacy container name": edit(lambda c: S(c, "postgres").update(container_name="agentops-postgres")),
            "postgres publishes 5432": edit(lambda c: S(c, "postgres").update(ports=[{"target": 5432, "published": "5432", "host_ip": "", "protocol": "tcp"}])),
            "postgres publishes (short form)": edit(lambda c: S(c, "postgres").update(ports=["5432:5432"])),
            "bootstrap publishes a port": edit(lambda c: S(c, "db-bootstrap").update(ports=["9000:9000"])),
            "viewer on all interfaces": edit(lambda c: S(c, "viewer").update(ports=[{"target": 8000, "published": "8000", "host_ip": "0.0.0.0", "protocol": "tcp"}])),
            "viewer without host ip": edit(lambda c: S(c, "viewer").update(ports=["8000:8000"])),
            "viewer on another port": edit(lambda c: S(c, "viewer").update(ports=["127.0.0.1:8080:8000"])),
            "viewer publishes two ports": edit(lambda c: S(c, "viewer").update(ports=["127.0.0.1:8000:8000", "127.0.0.1:9000:9000"])),
            "viewer without ports": edit(lambda c: S(c, "viewer").pop("ports")),
            "extra service": edit(lambda c: c["services"].update(extra={"build": {}})),
            "missing service": edit(lambda c: c["services"].pop("db-bootstrap")),
            "project renamed": edit(lambda c: c.update(name="agentops")),
            "project missing": edit(lambda c: c.pop("name")),
            "volume renamed": edit(lambda c: c["volumes"]["postgres-data"].update(name="agentops-mvp-other")),
            "legacy volume": edit(lambda c: c["volumes"]["postgres-data"].update(name="agentops_postgres-data")),
            "external volume": edit(lambda c: c["volumes"]["postgres-data"].update(external=True)),
            "unlabelled volume": edit(lambda c: c["volumes"]["postgres-data"].pop("labels")),
            "extra volume": edit(lambda c: c["volumes"].update(scratch={})),
            "extra network": edit(lambda c: c["networks"].update(other={"driver": "bridge"})),
            "external network": edit(lambda c: c["networks"]["mvp-net"].update(external=True)),
            "internal network": edit(lambda c: c["networks"]["mvp-net"].update(internal=True)),
            "host network on a service": edit(lambda c: S(c, "viewer").update(network_mode="host")),
            "service on a second network": edit(lambda c: S(c, "viewer").update(networks={"mvp-net": None, "x": None})),
            "extra top-level section": edit(lambda c: c.update(secrets={"s": {"file": "x"}})),
            "literal password": edit(lambda c: S(c, "postgres")["environment"].update(POSTGRES_PASSWORD="hunter2-literal-value")),
            "reference to the wrong variable": edit(lambda c: S(c, "viewer")["environment"].update(TRACE_VIEWER_DB_PASSWORD=_ref("POSTGRES_PASSWORD"))),
            "password with a default": edit(lambda c: S(c, "viewer")["environment"].update(TRACE_VIEWER_DB_PASSWORD="${TRACE_VIEWER_DB_PASSWORD:-viewer}")),
            "extra environment variable": edit(lambda c: S(c, "viewer")["environment"].update(EXTRA="1")),
            "missing environment variable": edit(lambda c: S(c, "db-bootstrap")["environment"].pop("ALERT_NOTIFIER_DB_PASSWORD")),
            "trust authentication": edit(lambda c: S(c, "postgres")["environment"].update(POSTGRES_HOST_AUTH_METHOD="trust")),
            "initdb option changed": edit(lambda c: S(c, "postgres")["environment"].update(POSTGRES_INITDB_ARGS="--auth-host=trust")),
            "viewer database role changed": edit(lambda c: S(c, "viewer")["environment"].update(TRACE_VIEWER_DB_USER="agentops")),
            "viewer not read-only": edit(lambda c: S(c, "viewer").update(read_only=False)),
            "viewer read_only missing": edit(lambda c: S(c, "viewer").pop("read_only")),
            "capabilities kept": edit(lambda c: S(c, "viewer").pop("cap_drop")),
            "capability added": edit(lambda c: S(c, "viewer").update(cap_add=["NET_ADMIN"])),
            "no-new-privileges missing": edit(lambda c: S(c, "viewer").update(security_opt=[])),
            "privileged": edit(lambda c: S(c, "viewer").update(privileged=True)),
            "extra tmpfs": edit(lambda c: S(c, "viewer").update(tmpfs=["/tmp", "/var"])),
            "user override": edit(lambda c: S(c, "viewer").update(user="root")),
            "command override": edit(lambda c: S(c, "postgres").update(command=["sleep", "1"])),
            "entrypoint override": edit(lambda c: S(c, "db-bootstrap").update(entrypoint=["sh"])),
            "env_file": edit(lambda c: S(c, "viewer").update(env_file=[".env"])),
            "host pid": edit(lambda c: S(c, "viewer").update(pid="host")),
            "docker socket mount": edit(lambda c: S(c, "viewer").update(volumes=["/var/run/docker.sock:/var/run/docker.sock"])),
            "viewer mounts a volume": edit(lambda c: S(c, "viewer").update(volumes=["postgres-data:/data"])),
            "postgres bind mount": edit(lambda c: S(c, "postgres").update(volumes=["./data:/var/lib/postgresql/data"])),
            "postgres extra mount": edit(lambda c: S(c, "postgres").update(volumes=[{"type": "volume", "source": "postgres-data", "target": "/var/lib/postgresql/data"}, {"type": "volume", "source": "x", "target": "/x"}])),
            "restart always": edit(lambda c: S(c, "viewer").update(restart="always")),
            "restart missing": edit(lambda c: S(c, "postgres").pop("restart")),
            "viewer does not wait for the bootstrap": edit(lambda c: S(c, "viewer").update(depends_on={"postgres": {"condition": "service_healthy"}})),
            "viewer waits only for start": edit(lambda c: S(c, "viewer").update(depends_on={"postgres": {"condition": "service_started"}, "db-bootstrap": {"condition": "service_started"}})),
            "bootstrap does not wait for health": edit(lambda c: S(c, "db-bootstrap").update(depends_on={"postgres": {"condition": "service_started"}})),
            "postgres health check changed": edit(lambda c: S(c, "postgres").update(healthcheck={"test": ["CMD", "true"]})),
            "viewer health check changed": edit(lambda c: S(c, "viewer").update(healthcheck={"test": ["CMD", "true"]})),
            "health check missing": edit(lambda c: S(c, "viewer").pop("healthcheck")),
            "wrong Dockerfile": edit(lambda c: S(c, "viewer")["build"].update(dockerfile="docker/other/Dockerfile")),
            "context outside the repository": edit(lambda c: S(c, "viewer")["build"].update(context=os.path.abspath(os.sep))),
            "image of another stack": edit(lambda c: S(c, "postgres").update(image="agentops-postgres:latest")),
            "image tag not project scoped": edit(lambda c: S(c, "viewer").update(image="viewer:latest")),
            "refers to the legacy volume name anywhere": edit(lambda c: S(c, "viewer")["environment"].update(NOTE="agentops_postgres-data")),
        }

    @pytest.mark.parametrize("label", sorted(_mutations.__func__().keys()))
    def test_every_mutated_configuration_is_refused_and_leaks_nothing(self, tmp_path, label):
        config = self._mutations()[label](_resolved())
        engine = FakeEngine(config)
        code, out, err, *_ = _check_config(tmp_path, engine)
        assert code == mvp.EXIT_REFUSED, label
        assert "not acceptable" in err and out == ""
        assert not any(v in out + err for v in _values().values())
        assert "hunter2" not in err

    def test_the_validator_reports_names_not_values(self):
        config = _resolved()
        config["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = "hunter2-literal-value"
        problems = mvp.validate_resolved_config(config, _REPO)
        assert problems and not any("hunter2" in problem for problem in problems)
        assert any("POSTGRES_PASSWORD" in problem for problem in problems)

    def test_nothing_unrecognized_passes(self):
        for document in (None, [], "text", 5, {}, {"name": "agentops-mvp"}, {"services": {}}):
            assert mvp.validate_resolved_config(document, _REPO) != []

    # -- credentials ---------------------------------------------------------------------------

    def test_a_missing_credential_file_is_refused_before_anything_else_happens(self, tmp_path):
        engine = FakeEngine()
        out, err = io.StringIO(), io.StringIO()
        target = _target(tmp_path)
        code = mvp.main(["check-config", "--credentials-file", str(target)],
                        environ={"SystemRoot": r"C:\Windows"}, platform_name="nt", runner=FakeWindows(),
                        compose_runner=engine, docker=_DOCKER, repo_root=_REPO, out=out, err=err)
        assert code == mvp.EXIT_REFUSED and "init-credentials" in err.getvalue()
        assert engine.calls == [] and not target.exists() and not target.parent.exists()

    @pytest.mark.parametrize("label,data", [
        ("truncated", _content()[:150]), ("no footer", _content().replace(mvp.FOOTER.encode(), b"")),
        ("short value", mvp.HEADER.encode() + b"\nPOSTGRES_PASSWORD=short\n" + mvp.FOOTER.encode() + b"\n"),
        ("extra key", _content().replace(mvp.FOOTER.encode(), b"EXTRA=" + b"e" * 40 + b"\n" + mvp.FOOTER.encode())),
        ("empty", b""),
    ])
    def test_a_malformed_credential_file_is_refused_unchanged_and_nothing_runs(self, tmp_path, label, data):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        fake = FakeWindows()
        fake.make_private(target.parent, target)
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, prepared=(target, fake))
        assert code == mvp.EXIT_REFUSED and engine.calls == []
        assert target.read_bytes() == data
        assert not any("/grant:r" in call or "/inheritance:r" in call for call in fake.calls)

    def test_weak_credential_permissions_are_refused_before_the_engine_is_touched(self, tmp_path):
        target = _target(tmp_path)
        target.parent.mkdir(parents=True)
        target.write_bytes(_content())
        engine = FakeEngine()
        code, out, err, *_ = _check_config(tmp_path, engine, prepared=(target, FakeWindows()))
        assert code == mvp.EXIT_REFUSED and "inherits" in err and engine.calls == []

    def test_check_config_never_creates_or_changes_credentials(self, tmp_path):
        target, fake = _write_valid(tmp_path)
        before, mtime = target.read_bytes(), target.stat().st_mtime_ns
        engine = FakeEngine()
        assert _check_config(tmp_path, engine, prepared=(target, fake))[0] == mvp.EXIT_OK
        assert target.read_bytes() == before and target.stat().st_mtime_ns == mtime
        assert not any("/grant:r" in c or "/inheritance:r" in c for c in fake.calls)

    def test_redaction_across_every_failure(self, tmp_path):
        values = _values("S")
        for index, engine in enumerate((FakeEngine(context_rc=1), FakeEngine(config_rc=2),
                                        FakeEngine(stdout=b"junk"), FakeEngine({"name": "x"}))):
            code, out, err, *_ = _check_config(tmp_path / str(index), engine, values=values,
                                               host={"POSTGRES_PASSWORD": _HOST_SECRET})
            assert code != mvp.EXIT_OK
            assert not any(v in out + err for v in values.values()) and _HOST_SECRET not in out + err

    # -- the repository and the project directory ---------------------------------------------

    def _fake_repo(self, tmp_path, *, compose=True, dotenv=False):
        repo = tmp_path / "fake-repo"
        directory = repo / "docker" / "mvp"
        directory.mkdir(parents=True)
        if compose:
            (directory / "compose.yml").write_text("name: agentops-mvp\n", encoding="utf-8")
        if dotenv:
            (directory / ".env").write_text("COMPOSE_FILE=other.yml\n", encoding="utf-8")
        return repo

    def test_a_missing_compose_file_is_refused(self, tmp_path):
        engine = FakeEngine()
        repo = self._fake_repo(tmp_path, compose=False)
        code, out, err, *_ = _check_config(tmp_path / "c", engine, repo_root=repo)
        assert code == mvp.EXIT_REFUSED and "not found" in err and engine.calls == []

    def test_an_env_file_next_to_the_compose_file_is_refused(self, tmp_path):
        engine = FakeEngine()
        repo = self._fake_repo(tmp_path, dotenv=True)
        code, out, err, *_ = _check_config(tmp_path / "c", engine, repo_root=repo)
        assert code == mvp.EXIT_REFUSED and ".env" in err and engine.calls == []

    def test_a_credential_path_inside_the_repository_is_still_refused(self, tmp_path):
        repo = self._fake_repo(tmp_path)
        target = repo / mvp.DIRECTORY_NAME / mvp.FILE_NAME
        out, err = io.StringIO(), io.StringIO()
        engine = FakeEngine()
        code = mvp.main(["check-config", "--credentials-file", str(target)],
                        environ={"SystemRoot": r"C:\Windows"}, platform_name="nt", runner=FakeWindows(),
                        compose_runner=engine, docker=_DOCKER, repo_root=repo, out=out, err=err)
        assert code == mvp.EXIT_REFUSED and "outside the repository" in err.getvalue() and engine.calls == []

    # -- nothing is started, nothing is destroyed -------------------------------------------------

    def test_only_two_read_only_container_commands_are_ever_issued(self, tmp_path):
        engine = FakeEngine()
        _check_config(tmp_path, engine)
        issued = []
        for argv, _env in engine.calls:
            tail = argv[1:]
            issued.append("context inspect" if tail[:2] == ["context", "inspect"]
                          else "compose config" if tail[0] == "compose" and "config" in tail else "OTHER")
        assert issued == ["context inspect", "compose config"]
        flat = " ".join(" ".join(argv) for argv, _ in engine.calls).split()
        for forbidden in ("up", "down", "run", "start", "stop", "kill", "rm", "build", "create", "exec",
                          "volume", "network", "prune", "reset", "pull", "push", "-v", "--volumes", "-d"):
            assert forbidden not in flat, forbidden

    def test_main_without_an_injected_runner_uses_the_default_compose_runner(self, tmp_path, monkeypatch):
        used = []

        def fake_default(argv, env):
            used.append(list(argv))
            return CommandResult(1, b"")

        monkeypatch.setattr(mvp, "default_compose_runner", fake_default)
        target, fake = _write_valid(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main(["check-config", "--credentials-file", str(target)],
                        environ={"SystemRoot": r"C:\Windows"}, platform_name="nt", runner=fake,
                        docker=_DOCKER, repo_root=_REPO, out=out, err=err)
        assert code == mvp.EXIT_FAILED and used and used[0][1:3] == ["context", "inspect"]


# ---------------------------------------------------------------------------
# T12  Command line
# ---------------------------------------------------------------------------

class TestCommandLine:

    def test_a_command_is_required(self, tmp_path):
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main([], environ={}, platform_name="nt", runner=FakeWindows(), out=out, err=err)
        assert code == mvp.EXIT_USAGE

    def test_an_unknown_command_is_a_usage_error(self, tmp_path):
        for unknown in ("down", "reset", "start", "stop", "smoke"):
            assert _run([unknown], tmp_path)[0] == mvp.EXIT_USAGE

    def test_an_unknown_option_is_a_usage_error(self, tmp_path):
        assert _run(["init-credentials", "--force"], tmp_path)[0] == mvp.EXIT_USAGE
        assert _run(["init-credentials", "--password", "x"], tmp_path)[0] == mvp.EXIT_USAGE

    def test_a_relative_credentials_file_is_refused(self, tmp_path):
        code, out, err = _run(["check-credentials", "--credentials-file", "agentops-mvp/credentials.env"], tmp_path)
        assert code == mvp.EXIT_REFUSED and "absolute" in err

    def test_exit_codes_are_distinct(self):
        codes = [mvp.EXIT_OK, mvp.EXIT_INTERNAL, mvp.EXIT_USAGE, mvp.EXIT_REFUSED, mvp.EXIT_EXISTS, mvp.EXIT_FAILED]
        assert codes == [0, 1, 2, 3, 4, 5] and len(set(codes)) == 6
