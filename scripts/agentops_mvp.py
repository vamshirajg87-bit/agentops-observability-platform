#!/usr/bin/env python3
"""
scripts/agentops_mvp.py

Credential tooling for the dedicated AgentOps MVP stack (docker/mvp/compose.yml).

Three commands, nothing else:

    init-credentials   create the credential file once, with restrictive permissions
    check-credentials  validate the file, its location and its permissions
    check-config       validate the credential file, the local engine and the resolved
                       Compose configuration, without starting anything

This module starts, stops, resets and builds nothing and never touches a database.
The only container-tool commands it can build are "compose config" (a read-only
inspection that prints the configuration) and "context inspect" (a read of the local
client configuration); the stack commands (up, down, reset, status, smoke) arrive in
later stages.  Standard library only.

The file holds one independent random password for each of the eight variables the
compose file requires.  By default it lives OUTSIDE the repository and outside any
cloud-synchronized folder:

    Windows      %LOCALAPPDATA%\\agentops-mvp\\credentials.env
    Linux/macOS  $XDG_CONFIG_HOME/agentops-mvp/credentials.env
                 (or ~/.config/agentops-mvp/credentials.env)

Rules this tool never breaks:
  - it never overwrites, regenerates or edits an existing credential file;
  - it never deletes anything it did not create in the same run;
  - it never prints a credential value, passes one on a command line, or puts one in
    an error message (messages come from a fixed vocabulary: file names, variable
    names and line numbers only);
  - it refuses paths inside the repository or a OneDrive location, and a credential
    file or directory that is a symbolic link or a reparse point;
  - it reports success only after the permissions were VERIFIED, not merely set.

Platform security behaviour
  POSIX    directory 0700 and file 0600, owned by the current user, created with
           O_EXCL (and O_NOFOLLOW where available); the mode is verified with lstat.
  Windows  the directory and the empty file are given a single access entry for the
           current user (inheritance removed) with icacls, addressed by SID, before
           any secret is written.  The result is read back as an SDDL string with
           "icacls /save" and verified: protected (no inherited entries), only
           allow entries, and only the current user, SYSTEM and Administrators.
           If that verification cannot be completed the run fails, the file this run
           created is removed, and no success is reported.

Limits that remain: the file is plain text readable by the owning account and by
anything running as it (and by SYSTEM and Administrators on Windows); it is not a
secrets manager.  Ancestor directories that are redirected are followed, but the
repository and OneDrive checks use the resolved path.  Windows system tools are
called by absolute path under %SystemRoot%\\System32.
"""

from __future__ import annotations

import argparse
import errno
import ntpath
import os
import posixpath
import re
import json
import secrets
import shutil
import stat
import subprocess
import time
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, TextIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The variables docker/mvp/compose.yml requires, in file order.
CREDENTIAL_VARIABLES: tuple[str, ...] = (
    "POSTGRES_PASSWORD",
    "GF_DATASOURCE_AGENTOPS_PASSWORD",
    "TRACE_VIEWER_DB_PASSWORD",
    "ANOMALY_DETECTOR_DB_PASSWORD",
    "RCA_ANALYZER_DB_PASSWORD",
    "INCIDENT_RETRIEVAL_DB_PASSWORD",
    "ALERT_EVALUATOR_DB_PASSWORD",
    "ALERT_NOTIFIER_DB_PASSWORD",
)

TOKEN_BYTES = 32            # secrets.token_urlsafe(32) -> 43 characters
MIN_LENGTH = 32
MAX_LENGTH = 128
HEADER = "# agentops-mvp credentials v1"
FOOTER = "# agentops-mvp credentials end"
DIRECTORY_NAME = "agentops-mvp"
FILE_NAME = "credentials.env"
MAX_FILE_BYTES = 4096

_VALUE_RE = re.compile(r"[A-Za-z0-9_-]+")
_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_PLACEHOLDER_WORDS = frozenset({
    "changeme", "change-me", "change_me", "password", "placeholder", "example",
    "secret", "todo", "xxx", "none", "null",
})

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3       # path policy, permissions, or an invalid file
EXIT_EXISTS = 4        # the credential file already exists; it was not touched
EXIT_FAILED = 5        # creation or verification failed; this run's files were removed
EXIT_AMBIGUOUS = 6     # status only: unexpected or contradictory MVP resources
EXIT_UNKNOWN = 7       # status only: the stack could not be classified

#: Principals allowed on a Windows credential file or directory: the current user,
#: SYSTEM, Administrators and Owner Rights.  Aliases that SDDL may use for them are mapped here.
#: OW is "Owner Rights": it applies to whoever owns the object, which is the current user
#: or Administrators.  Python 3.13 adds it to directories it creates with mode 0o700.
_SID_ALIASES = {"SY": "S-1-5-18", "BA": "S-1-5-32-544", "OW": "S-1-3-4"}
_ALWAYS_ALLOWED_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-4"})

_CLOUD_ENV_VARIABLES = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
_REPARSE_POINT = 0x400


class CredentialError(Exception):
    """A refusal or failure.  The message is from a fixed vocabulary and never holds a
    credential value."""

    def __init__(self, message: str, exit_code: int = EXIT_REFUSED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes


Runner = Callable[[Sequence[str]], CommandResult]


def _env(environ: Mapping[str, str], name: str) -> str:
    """An environment value; the name is matched exactly, then case-insensitively
    (Windows environment names are not case sensitive, and a copied mapping loses that)."""
    value = environ.get(name)
    if value is None:
        wanted = name.upper()
        for key in environ:
            if key.upper() == wanted:
                value = environ[key]
                break
    return value or ""


def repository_root() -> Path:
    """The repository root, derived from this file's location, never from the CWD."""
    return Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Generation and validation of credential values
# ---------------------------------------------------------------------------

def _is_placeholder(value: str) -> bool:
    text = value.strip()
    if text == "":
        return True
    if text.startswith("<") and text.endswith(">"):
        return True
    return text.lower() in _PLACEHOLDER_WORDS


def value_problem(value: str) -> Optional[str]:
    """None when the value is acceptable, otherwise a fixed-vocabulary reason."""
    if _is_placeholder(value):
        return "is empty or a placeholder"
    if len(value) < MIN_LENGTH or len(value) > MAX_LENGTH or not _VALUE_RE.fullmatch(value):
        return f"must be {MIN_LENGTH} to {MAX_LENGTH} characters from A-Z a-z 0-9 - _"
    return None


def generate_credentials() -> dict[str, str]:
    """Eight independent random values, one per required variable.

    Raises:
        CredentialError  a generated value was rejected or two values were equal
                         (practically impossible; it fails closed rather than retry).
    """
    values = {name: secrets.token_urlsafe(TOKEN_BYTES) for name in CREDENTIAL_VARIABLES}
    check_values(values)
    return values


def check_values(values: Mapping[str, str]) -> None:
    if set(values) != set(CREDENTIAL_VARIABLES):
        raise CredentialError("the credential set is not exactly the eight required variables")
    for name in CREDENTIAL_VARIABLES:
        problem = value_problem(values[name])
        if problem:
            raise CredentialError(f"the value of {name} {problem}")
    if len(set(values.values())) != len(CREDENTIAL_VARIABLES):
        raise CredentialError("two credential values are identical")


def render_file(values: Mapping[str, str]) -> bytes:
    check_values(values)
    lines = [HEADER] + [f"{name}={values[name]}" for name in CREDENTIAL_VARIABLES] + [FOOTER]
    return ("\n".join(lines) + "\n").encode("ascii")


def parse_file(data: bytes) -> dict[str, str]:
    """Parse and validate the content of a credential file.

    Raises:
        CredentialError  naming a line number or a variable, never a value.
    """
    if len(data) > MAX_FILE_BYTES:
        raise CredentialError("the credential file is larger than expected")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CredentialError("the credential file starts with a byte-order mark")
    if b"\r" in data:
        raise CredentialError("the credential file must use LF line endings")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise CredentialError("the credential file holds a non-ASCII character") from None
    if not text.endswith("\n"):
        raise CredentialError("the credential file is incomplete (no final newline)")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != HEADER:
        raise CredentialError("the credential file does not start with the expected header")
    if lines[-1] != FOOTER:
        raise CredentialError("the credential file is incomplete (end marker missing)")
    body = lines[1:-1]
    values: dict[str, str] = {}
    for offset, line in enumerate(body, start=2):
        key, separator, value = line.partition("=")
        if separator == "" or not _KEY_RE.fullmatch(key):
            raise CredentialError(f"line {offset} is not a NAME=value entry")
        if key not in CREDENTIAL_VARIABLES:
            raise CredentialError(f"line {offset} names a variable that is not expected: {key}")
        if key in values:
            raise CredentialError(f"line {offset} repeats the variable {key}")
        problem = value_problem(value)
        if problem:
            raise CredentialError(f"the value of {key} {problem}")
        values[key] = value
    missing = [name for name in CREDENTIAL_VARIABLES if name not in values]
    if missing:
        raise CredentialError("the credential file is missing: " + ", ".join(missing))
    if len(set(values.values())) != len(values):
        raise CredentialError("two credential values are identical")
    return values


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

def default_credentials_path(environ: Mapping[str, str], platform_name: str, home: str) -> str:
    """The default credential file path as a string, using the target platform's rules.

    platform_name is "nt" or "posix".  Pure function: it reads nothing but its inputs.
    """
    if platform_name == "nt":
        base = _env(environ, "LOCALAPPDATA")
        if not base or not ntpath.isabs(base):
            raise CredentialError("LOCALAPPDATA is not set to an absolute path")
        return ntpath.join(base, DIRECTORY_NAME, FILE_NAME)
    xdg = _env(environ, "XDG_CONFIG_HOME")
    if xdg and posixpath.isabs(xdg):
        base = xdg
    else:
        if not home or not posixpath.isabs(home):
            raise CredentialError("the home directory is not an absolute path")
        base = posixpath.join(home, ".config")
    return posixpath.join(base, DIRECTORY_NAME, FILE_NAME)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _is_within(path: str, parent: str) -> bool:
    child, base = _norm(path), _norm(parent)
    return child == base or child.startswith(base.rstrip("\\/") + os.sep)


def _cloud_synchronized(path: str, environ: Mapping[str, str]) -> bool:
    parts = [p.lower() for p in re.split(r"[\\/]+", path) if p]
    if any(part.startswith("onedrive") for part in parts):
        return True
    for variable in _CLOUD_ENV_VARIABLES:
        root = _env(environ, variable)
        if root and _is_within(path, root):
            return True
    return False


def _is_redirect(path: str) -> bool:
    """True when the path itself is a symbolic link, junction or other reparse point."""
    try:
        if os.path.islink(path):
            return True
        junction = getattr(os.path, "isjunction", None)
        if junction is not None and junction(path):
            return True
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        return bool(attributes & _REPARSE_POINT)
    except FileNotFoundError:
        return False
    except OSError:
        return True   # cannot tell: treat as unsafe


def check_location(
    path: str,
    repo_root: Path,
    environ: Mapping[str, str],
) -> str:
    """Refuse an unsafe credential path; return the absolute path as a string.

    Refused: a relative path; any path (as written or after resolving links) inside
    the repository or a OneDrive location; a file name other than the expected one;
    and a credential directory or file that is a link or reparse point.
    """
    if not path or not os.path.isabs(path):
        raise CredentialError("the credential file path must be absolute")
    absolute = os.path.abspath(path)
    if os.path.basename(absolute) != FILE_NAME or os.path.basename(os.path.dirname(absolute)) != DIRECTORY_NAME:
        raise CredentialError(f"the credential file must be named {DIRECTORY_NAME}/{FILE_NAME}")
    resolved = os.path.realpath(absolute)
    root = str(repo_root)
    for candidate in (absolute, resolved):
        if _is_within(candidate, root) or _is_within(candidate, os.path.realpath(root)):
            raise CredentialError("the credential file must be outside the repository")
        if _cloud_synchronized(candidate, environ):
            raise CredentialError("the credential file must not be in a OneDrive location")
    directory = os.path.dirname(absolute)
    if _is_redirect(directory) or _is_redirect(absolute):
        raise CredentialError("the credential directory and file must not be links or reparse points")
    return absolute


# ---------------------------------------------------------------------------
# POSIX permissions
# ---------------------------------------------------------------------------

def posix_problems(path: str, *, is_dir: bool) -> list[str]:
    """Permission problems of an existing path, from lstat (empty list: private)."""
    problems = []
    try:
        info = os.lstat(path)
    except OSError:
        return ["cannot be inspected"]
    if stat.S_ISLNK(info.st_mode):
        return ["is a symbolic link"]
    if is_dir and not stat.S_ISDIR(info.st_mode):
        problems.append("is not a directory")
    if not is_dir and not stat.S_ISREG(info.st_mode):
        problems.append("is not a regular file")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        problems.append("is not owned by the current user")
    if info.st_mode & 0o077:
        problems.append("is accessible to group or others")
    return problems


# ---------------------------------------------------------------------------
# Windows ACLs (icacls, addressed by SID, verified from SDDL)
# ---------------------------------------------------------------------------

def _system_tool(name: str, environ: Mapping[str, str]) -> str:
    root = _env(environ, "SystemRoot") or _env(environ, "windir")
    if not root or not ntpath.isabs(root):
        raise CredentialError("SystemRoot is not set; the Windows tools cannot be located")
    return ntpath.join(root, "System32", name)


def default_runner(argv: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, timeout=60, shell=False, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise CredentialError("a required Windows tool could not be run", EXIT_FAILED) from None
    return CommandResult(completed.returncode, completed.stdout or b"")


def current_user_sid(runner: Runner, environ: Mapping[str, str]) -> str:
    result = runner([_system_tool("whoami.exe", environ), "/user", "/fo", "csv", "/nh"])
    if result.returncode != 0:
        raise CredentialError("the current user could not be identified", EXIT_FAILED)
    match = re.search(r"S-1-\d+(?:-\d+)+", result.stdout.decode("utf-8", "replace"))
    if not match:
        raise CredentialError("the current user's SID could not be read", EXIT_FAILED)
    return match.group(0)


def windows_harden(path: str, sid: str, *, is_dir: bool, runner: Runner,
                   environ: Mapping[str, str]) -> None:
    """Give the current user the only access entry and remove inherited entries."""
    icacls = _system_tool("icacls.exe", environ)
    spec = f"*{sid}:(OI)(CI)(F)" if is_dir else f"*{sid}:(F)"
    for arguments in (["/grant:r", spec], ["/inheritance:r"]):
        result = runner([icacls, path, *arguments])
        if result.returncode != 0:
            raise CredentialError("the Windows permissions could not be set", EXIT_FAILED)


def _read_sddl(path: str, runner: Runner, environ: Mapping[str, str]) -> str:
    icacls = _system_tool("icacls.exe", environ)
    scratch = os.path.join(tempfile.gettempdir(), f"agentops-mvp-{secrets.token_hex(8)}.sddl")
    try:
        result = runner([icacls, path, "/save", scratch])
        if result.returncode != 0:
            raise CredentialError("the Windows permissions could not be read", EXIT_FAILED)
        try:
            with open(scratch, "rb") as handle:
                raw = handle.read(65536)
        except OSError:
            raise CredentialError("the Windows permissions could not be read", EXIT_FAILED) from None
    finally:
        try:
            os.unlink(scratch)      # this tool's own scratch file; it holds no secret
        except OSError:
            pass
    if raw.startswith(b"\xff\xfe"):
        raw = raw[2:]
    text = raw.decode("utf-16-le", "replace")
    for line in text.splitlines():
        if line.startswith("D:"):
            return line.strip()
    raise CredentialError("the Windows permissions could not be understood", EXIT_FAILED)


def parse_dacl(sddl: str) -> tuple[str, list[tuple[str, str, str]]]:
    """(DACL flags, [(ACE type, ACE flags, trustee)]) from an SDDL string."""
    if not sddl.startswith("D:"):
        raise CredentialError("the Windows permissions could not be understood", EXIT_FAILED)
    body = sddl[2:]
    flags = body.split("(", 1)[0]
    # the owner/group/SACL parts are not part of this output; stop at a SACL if present
    body = body.split("S:", 1)[0]
    aces = []
    for entry in re.findall(r"\(([^()]*)\)", body):
        fields = entry.split(";")
        if len(fields) < 6:
            raise CredentialError("the Windows permissions could not be understood", EXIT_FAILED)
        trustee = _SID_ALIASES.get(fields[5], fields[5])
        aces.append((fields[0], fields[1], trustee))
    return flags, aces


def windows_problems(path: str, user_sid: str, *, runner: Runner,
                     environ: Mapping[str, str]) -> list[str]:
    """Permission problems of an existing path (empty list: private)."""
    flags, aces = parse_dacl(_read_sddl(path, runner, environ))
    problems = []
    if "P" not in flags:
        problems.append("inherits permissions from its parent")
    allowed = _ALWAYS_ALLOWED_SIDS | {user_sid}
    if not aces:
        problems.append("has no access entry for the current user")
    for ace_type, ace_flags, trustee in aces:
        if ace_type != "A":
            problems.append("has an entry that is not a plain allow entry")
        if "ID" in ace_flags:
            problems.append("has an inherited entry")
        if trustee not in allowed:
            problems.append("grants access to another account or group")
    if aces and user_sid not in {trustee for _, _, trustee in aces}:
        problems.append("has no access entry for the current user")
    return sorted(set(problems))


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

def _describe(problems: Sequence[str]) -> str:
    return "; ".join(problems)


class _Context:
    """Settings of one run, so the platform and tools can be replaced in tests."""

    def __init__(self, environ: Mapping[str, str], platform_name: str, runner: Runner) -> None:
        self.environ = environ
        self.windows = platform_name == "nt"
        self.runner = runner
        self.user_sid: Optional[str] = None

    def sid(self) -> str:
        if self.user_sid is None:
            self.user_sid = current_user_sid(self.runner, self.environ)
        return self.user_sid

    def problems(self, path: str, *, is_dir: bool) -> list[str]:
        if self.windows:
            return windows_problems(path, self.sid(), runner=self.runner, environ=self.environ)
        return posix_problems(path, is_dir=is_dir)

    def require_private(self, path: str, *, is_dir: bool, what: str,
                        code: int = EXIT_REFUSED) -> None:
        problems = self.problems(path, is_dir=is_dir)
        if problems:
            raise CredentialError(f"the credential {what} {_describe(problems)}", code)


def _missing_ancestors(directory: str) -> list[str]:
    """Directories that do not exist yet, outermost first."""
    missing = []
    current = directory
    while current and not os.path.lexists(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return list(reversed(missing))


def _rollback(file_created: Optional[str], directories: Sequence[str]) -> list[str]:
    """Remove only what this run created (the file, then empty directories it made).

    Returns the paths that could not be removed.
    """
    left = []
    if file_created is not None:
        try:
            if not os.path.islink(file_created):
                os.unlink(file_created)
        except FileNotFoundError:
            pass
        except OSError:
            left.append(file_created)
    for directory in reversed(list(directories)):
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            pass
        except OSError:
            left.append(directory)
    return left


def init_credentials(path: str, ctx: _Context) -> str:
    """Create the credential file.  Returns a message without any value.

    Raises:
        CredentialError  the path was refused, the file exists, or creation or
                         verification failed.  Nothing pre-existing is modified;
                         what this run created is removed.
    """
    directory = os.path.dirname(path)
    if os.path.lexists(path):
        raise CredentialError(
            "the credential file already exists and was not modified; "
            "credentials are never regenerated for an existing database", EXIT_EXISTS)

    created_dirs: list[str] = []
    created_file: Optional[str] = None
    try:
        existing_directory = os.path.isdir(directory) and not os.path.islink(directory)
        if os.path.lexists(directory) and not existing_directory:
            raise CredentialError("the credential directory is not a plain directory")
        if existing_directory:
            # not ours: verify, never modify
            ctx.require_private(directory, is_dir=True, what="directory")
        else:
            for missing in _missing_ancestors(directory):
                if ctx.windows:
                    os.mkdir(missing)       # the mode is ignored here; permissions are set below
                else:
                    os.mkdir(missing, 0o700)
                    os.chmod(missing, 0o700)
                created_dirs.append(missing)
            if ctx.windows:
                windows_harden(directory, ctx.sid(), is_dir=True, runner=ctx.runner, environ=ctx.environ)
            ctx.require_private(directory, is_dir=True, what="directory", code=EXIT_FAILED)

        values = generate_credentials()
        content = render_file(values)

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        created_file = path
        try:
            if ctx.windows:
                # harden and verify the still EMPTY file before any secret is written
                windows_harden(path, ctx.sid(), is_dir=False, runner=ctx.runner, environ=ctx.environ)
            else:
                os.fchmod(descriptor, 0o600)
            ctx.require_private(path, is_dir=False, what="file", code=EXIT_FAILED)
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        ctx.require_private(path, is_dir=False, what="file", code=EXIT_FAILED)
        try:
            parse_file(_read_bytes(path))     # round trip: complete and well formed
        except CredentialError as error:
            raise CredentialError(str(error), EXIT_FAILED) from None
    except CredentialError as error:
        left = _rollback(created_file, created_dirs)
        message = str(error)
        if left:
            message += "; could not remove what this run created, delete it by hand: " + ", ".join(left)
        raise CredentialError(message, error.exit_code) from None
    except FileExistsError:
        left = _rollback(created_file, created_dirs)
        raise CredentialError(
            "the credential file already exists and was not modified", EXIT_EXISTS) from None
    except OSError as error:
        left = _rollback(created_file, created_dirs)
        name = errno.errorcode.get(error.errno or 0, "OSError")
        suffix = ("; could not remove what this run created, delete it by hand: " + ", ".join(left)) if left else ""
        raise CredentialError(f"the credential file could not be created ({name}){suffix}", EXIT_FAILED) from None
    finally:
        content = b""
        values = {}      # type: ignore[assignment]
    return (f"credential file created: {path}\n"
            f"  variables: {', '.join(CREDENTIAL_VARIABLES)}\n"
            "  values are not shown; permissions were verified; the file is never overwritten")


def _read_bytes(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, MAX_FILE_BYTES + 1)
    finally:
        os.close(descriptor)


def check_credentials(path: str, ctx: _Context) -> str:
    """Validate an existing credential file.  Read only; the file is never modified.

    Raises:
        CredentialError  the file is missing, unsafe, incomplete or malformed.
    """
    if not os.path.lexists(path):
        raise CredentialError("the credential file does not exist; run init-credentials first")
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        raise CredentialError("the credential directory does not exist")
    ctx.require_private(directory, is_dir=True, what="directory")
    ctx.require_private(path, is_dir=False, what="file")
    try:
        data = _read_bytes(path)
    except OSError as error:
        raise CredentialError(
            f"the credential file could not be read ({errno.errorcode.get(error.errno or 0, 'OSError')})"
        ) from None
    parse_file(data)
    return (f"credential file OK: {path}\n"
            f"  {len(CREDENTIAL_VARIABLES)} variables present, distinct and well formed; "
            "permissions verified; values are not shown")


# ---------------------------------------------------------------------------
# Configuration validation (check-config)
# ---------------------------------------------------------------------------
#
# check-config reads the Compose configuration WITHOUT starting anything.  The one
# inspection command is
#
#     docker compose -p agentops-mvp --project-directory <repo>/docker/mvp \
#         -f <repo>/docker/mvp/compose.yml config --format json --no-interpolate
#
# built as an argument list (never a shell string).  Why this form, and what is NOT
# assumed:
#   - "config" only parses and prints; it creates no container, network or volume.
#   - "--no-interpolate" asks Compose to leave ${VARIABLE} references as written, so
#     the output carries no credential.  It is not assumed to be supported or
#     effective: if Compose rejects it the run fails closed, and the inspection child
#     is given NO credential at all (its environment has the eight variable names
#     removed), so even a Compose that ignored the flag could not print a value: a
#     required variable would simply be missing.  Any output that still contains a
#     credential value (from the credential file or the host) is discarded unread.
#   - "--env-file" is deliberately not passed, because the credential file is not
#     needed for the inspection; a stray .env in the project directory (which Compose
#     would read) makes the check refuse instead.
#   - The output is parsed in memory.  It is never printed, and neither is the
#     child's stderr: messages come from a fixed vocabulary.

PROJECT_NAME = "agentops-mvp"
VOLUME_NAME = "agentops-mvp-postgres-data"
COMPOSE_RELATIVE = ("docker", "mvp", "compose.yml")
SERVICES = ("postgres", "db-bootstrap", "viewer")
#: Names of resources that belong to something else.  Used only to REFUSE; the tool
#: never looks at, mounts or touches them.
_FOREIGN_NAMES = ("agentops_postgres-data", "agentops-postgres")
_ALLOWED_COMPOSE_SUBCOMMANDS = frozenset({"config"})
_INSPECTION_OPTIONS = ("--format", "json", "--no-interpolate")
_MAX_COMPOSE_OUTPUT = 2_000_000
_CONTEXT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_PUBLISH_RE = re.compile(r"(?:(?P<ip>[0-9.]+):)?(?P<pub>[0-9]+):(?P<tgt>[0-9]+)(?:/(?P<proto>[a-z]+))?")
_REFERENCE_RE = re.compile(r"\$\{(?P<name>[A-Z][A-Z0-9_]*):\?[^}]*\}")

ComposeRunner = Callable[[Sequence[str], Mapping[str, str]], CommandResult]


def compose_file_path(repo_root: Path) -> Path:
    """The only Compose file this tool ever names, derived from the repository root."""
    return Path(repo_root).joinpath(*COMPOSE_RELATIVE)


def compose_argv(docker: str, repo_root: Path, subcommand: Sequence[str]) -> list[str]:
    """The Compose command as an argument list: one file, the fixed project name, and
    only a subcommand this stage allows (config)."""
    if not subcommand or subcommand[0] not in _ALLOWED_COMPOSE_SUBCOMMANDS:
        raise CredentialError("that Compose subcommand is not available in this stage", EXIT_USAGE)
    return [*_compose_prefix(docker, repo_root), *subcommand]


def _compose_prefix(docker: str, repo_root: Path) -> list[str]:
    compose_file = compose_file_path(repo_root)
    return [
        docker, "compose",
        "-p", PROJECT_NAME,
        "--project-directory", str(compose_file.parent),
        "-f", str(compose_file),
    ]


def build_argv(docker: str, repo_root: Path, service: str) -> list[str]:
    """Build ONE named MVP service.  Nothing else is ever appended: no pull, no cache
    option, no push, no build argument, no up."""
    if service not in SERVICES:
        raise CredentialError("that service is not part of the MVP stack", EXIT_USAGE)
    return [*_compose_prefix(docker, repo_root), "build", service]


def up_argv(docker: str, repo_root: Path) -> list[str]:
    """Create and start the MVP stack in the background.  Exactly this and nothing else:
    never a build, never a pull, never a recreate, never an orphan or volume removal."""
    return [*_compose_prefix(docker, repo_root), "up", "-d", "--no-build", "--pull", "never", "--no-recreate"]


def up_capability_argv(docker: str, repo_root: Path) -> list[str]:
    """Help text only: proves the installed Compose has every option the start command uses."""
    return [*_compose_prefix(docker, repo_root), "up", "--help"]


def build_capability_argv(docker: str, repo_root: Path) -> list[str]:
    """Help text only: proves the installed Compose has a build command that takes service names."""
    return [*_compose_prefix(docker, repo_root), "build", "--help"]


def build_child_environment(
    host: Mapping[str, str],
    values: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """The environment for a Docker child process.

    Removed from the host copy: every COMPOSE_* variable (they can add files, change
    the project or enable profiles) and the eight credential variable names (a host
    value must never reach the stack).  Names are matched case-insensitively.  When
    values is given, the validated credential-file values are then set, so they always
    take precedence over anything inherited.  check-config passes no values.
    """
    secret_names = {name.upper() for name in CREDENTIAL_VARIABLES}
    child = {
        key: value for key, value in host.items()
        if not key.upper().startswith("COMPOSE_") and key.upper() not in secret_names
    }
    if values is not None:
        check_values(values)
        child.update(values)
    return child


def default_compose_runner(argv: Sequence[str], env: Mapping[str, str]) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, timeout=120, shell=False, check=False, env=dict(env),
        )
    except (OSError, subprocess.SubprocessError):
        raise CredentialError("the container tool could not be run", EXIT_FAILED) from None
    return CommandResult(completed.returncode, (completed.stdout or b"")[:_MAX_COMPOSE_OUTPUT + 1])


BUILD_TIMEOUT_SECONDS = 1800        # per service
UP_TIMEOUT_SECONDS = 1500           # the whole start, including the one-shot bootstrap
_BUILD_OUTPUT_TAIL = 4000
#: Compose requires the eight variables to be set, but building an image needs none of
#: their values (no build argument or build-time variable uses them).  The build is
#: therefore given this fixed non-secret word, never a real credential.
_BUILD_PLACEHOLDER = "build-only-value-not-a-credential"


def _run_bounded(argv: Sequence[str], env: Mapping[str, str], timeout: int,
                 input_bytes: Optional[bytes] = None) -> CommandResult:
    """Run one long command with a bounded time.  Output (stderr merged in) is cut to its tail.
    input_bytes, when given, is written to the command's standard input and nowhere else."""
    extra = {} if input_bytes is None else {"input": input_bytes}
    try:
        completed = subprocess.run(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
            shell=False, check=False, env=dict(env), **extra,
        )
    except subprocess.TimeoutExpired:
        raise CredentialError("the container command timed out and was stopped", EXIT_FAILED) from None
    except (OSError, subprocess.SubprocessError):
        raise CredentialError("the container tool could not be run", EXIT_FAILED) from None
    return CommandResult(completed.returncode, (completed.stdout or b"")[-_BUILD_OUTPUT_TAIL:])


def default_build_runner(argv: Sequence[str], env: Mapping[str, str]) -> CommandResult:
    return _run_bounded(argv, env, BUILD_TIMEOUT_SECONDS)


def default_up_runner(argv: Sequence[str], env: Mapping[str, str]) -> CommandResult:
    return _run_bounded(argv, env, UP_TIMEOUT_SECONDS)


# -- local engine --------------------------------------------------------------

def endpoint_is_local(host: str) -> bool:
    """True only for an endpoint on this machine: a unix socket or a local named pipe.
    tcp, ssh, http, fd and remote named pipes are refused (a tcp address on the loopback
    may be a tunnel to another machine)."""
    text = host.strip()
    if text.startswith("unix://") and len(text) > len("unix://"):
        return True
    if text.startswith("npipe://"):
        rest = text[len("npipe://"):]
        return rest.startswith("//./pipe/") or rest.startswith("/./pipe/")
    return False


def require_local_engine(
    host_env: Mapping[str, str],
    child_env: Mapping[str, str],
    docker: str,
    run: ComposeRunner,
) -> None:
    """Refuse unless the container engine this tool would talk to is established as local.

    Checked: DOCKER_TLS_VERIFY and DOCKER_CERT_PATH must be unset (they only make sense for
    a remote engine); DOCKER_HOST, when set, must be local; and the endpoint of the active
    context (DOCKER_CONTEXT, or the current context) is read with "context inspect" and
    must be local.  If that cannot be read, the run fails closed.
    """
    for name in ("DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if _env(host_env, name):
            raise CredentialError(f"{name} is set; only a local container engine is allowed")
    docker_host = _env(host_env, "DOCKER_HOST")
    if docker_host and not endpoint_is_local(docker_host):
        raise CredentialError("DOCKER_HOST is not a local endpoint; only a local container engine is allowed")
    context = _env(host_env, "DOCKER_CONTEXT")
    if context and not _CONTEXT_NAME_RE.fullmatch(context):
        raise CredentialError("DOCKER_CONTEXT is not an acceptable context name")
    argv = [docker, "context", "inspect"]
    if context:
        argv.append(context)
    argv += ["--format", "{{.Endpoints.docker.Host}}"]
    result = run(argv, child_env)
    if result.returncode != 0:
        raise CredentialError("the container context could not be inspected; "
                              "a local container engine could not be established", EXIT_FAILED)
    endpoint = result.stdout.decode("utf-8", "replace").strip()
    if not endpoint_is_local(endpoint):
        raise CredentialError("the active container context is not a local endpoint")


# -- resolved configuration ----------------------------------------------------

def _reference(name: str) -> tuple[str, str]:
    return ("ref", name)


def _expected_environment(service: str) -> dict[str, tuple[str, str]]:
    literal = lambda value: ("literal", value)  # noqa: E731
    if service == "postgres":
        return {
            "POSTGRES_DB": literal("agentops"),
            "POSTGRES_USER": literal("agentops"),
            "POSTGRES_INITDB_ARGS": literal("--auth-host=scram-sha-256"),
            "POSTGRES_PASSWORD": _reference("POSTGRES_PASSWORD"),
        }
    if service == "db-bootstrap":
        expected = {
            "BOOTSTRAP_DB_HOST": literal("postgres"),
            "BOOTSTRAP_DB_PORT": literal("5432"),
            "BOOTSTRAP_DB_NAME": literal("agentops"),
            "BOOTSTRAP_DB_ADMIN_USER": literal("agentops"),
            "BOOTSTRAP_DB_ADMIN_PASSWORD": _reference("POSTGRES_PASSWORD"),
        }
        for name in CREDENTIAL_VARIABLES[1:]:
            expected[name] = _reference(name)
        return expected
    return {
        "TRACE_VIEWER_DB_HOST": literal("postgres"),
        "TRACE_VIEWER_DB_PORT": literal("5432"),
        "TRACE_VIEWER_DB_NAME": literal("agentops"),
        "TRACE_VIEWER_DB_USER": literal("trace_viewer_reader"),
        "TRACE_VIEWER_DB_PASSWORD": _reference("TRACE_VIEWER_DB_PASSWORD"),
    }


_SERVICE_KEYS = {
    "postgres": {"build", "restart", "environment", "volumes", "healthcheck", "networks"},
    "db-bootstrap": {"build", "restart", "depends_on", "environment", "networks"},
    "viewer": {"build", "restart", "depends_on", "environment", "ports", "healthcheck",
               "read_only", "tmpfs", "cap_drop", "security_opt", "networks"},
}
_DOCKERFILES = {
    "postgres": "docker/postgres/Dockerfile",
    "db-bootstrap": "docker/bootstrap/Dockerfile",
    "viewer": "docker/trace-viewer/Dockerfile",
}
_DEPENDENCIES = {
    "postgres": {},
    "db-bootstrap": {"postgres": "service_healthy"},
    "viewer": {"postgres": "service_healthy", "db-bootstrap": "service_completed_successfully"},
}


def _as_environment(raw: object) -> Optional[dict[str, Optional[str]]]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(key): (None if value is None else str(value)) for key, value in raw.items()}
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        pairs = {}
        for item in raw:
            key, separator, value = item.partition("=")
            pairs[key] = value if separator else None
        return pairs
    return None


def _as_string_list(raw: object) -> Optional[list[str]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return list(raw)
    return None


def _as_names(raw: object) -> Optional[set[str]]:
    if raw is None:
        return set()
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return set(raw)
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    return None


def _as_dependencies(raw: object) -> Optional[dict[str, str]]:
    if raw is None:
        return {}
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return {item: "service_started" for item in raw}
    if isinstance(raw, dict):
        result = {}
        for name, detail in raw.items():
            if not isinstance(detail, dict):
                return None
            result[str(name)] = str(detail.get("condition", "service_started"))
        return result
    return None


def _as_published(raw: object) -> Optional[list[tuple[str, str, str, str]]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return None
    published = []
    for item in raw:
        if isinstance(item, str):
            match = _PUBLISH_RE.fullmatch(item)
            if not match:
                return None
            published.append((match.group("ip") or "", match.group("pub"), match.group("tgt"),
                              match.group("proto") or "tcp"))
        elif isinstance(item, dict):
            published.append((str(item.get("host_ip") or ""), str(item.get("published") or ""),
                              str(item.get("target") or ""), str(item.get("protocol") or "tcp")))
        else:
            return None
    return published


def _as_mounts(raw: object) -> Optional[list[tuple[str, str]]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return None
    mounts = []
    for item in raw:
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) < 2:
                return None
            mounts.append((parts[0], parts[1]))
        elif isinstance(item, dict):
            if item.get("type", "volume") != "volume":
                return None
            mounts.append((str(item.get("source", "")), str(item.get("target", ""))))
        else:
            return None
    return mounts


def _check_service(name: str, service: object, repo_root: Path) -> list[str]:
    problems: list[str] = []
    if not isinstance(service, dict):
        return [f"service {name} is not a mapping"]
    unexpected = sorted(set(service) - _SERVICE_KEYS[name] - {"image"})
    if unexpected:
        problems.append(f"service {name} has unexpected settings: " + ", ".join(unexpected))
    if "image" in service and service["image"] != f"{PROJECT_NAME}-{name}":
        problems.append(f"service {name} names an image that is not project scoped")
    if service.get("restart") != "no":
        problems.append(f"service {name} does not have restart policy no")

    build = service.get("build")
    if not isinstance(build, dict) or "context" not in build:
        problems.append(f"service {name} has no build context")
    else:
        context = os.path.normcase(os.path.realpath(str(build["context"])))
        if context != os.path.normcase(os.path.realpath(str(repo_root))):
            problems.append(f"service {name} builds from a context outside the repository root")
        if str(build.get("dockerfile", "")).replace("\\", "/") != _DOCKERFILES[name]:
            problems.append(f"service {name} uses an unexpected Dockerfile")
        if set(build) - {"context", "dockerfile"}:
            problems.append(f"service {name} has unexpected build settings")

    environment = _as_environment(service.get("environment"))
    expected = _expected_environment(name)
    if environment is None:
        problems.append(f"service {name} environment is not understood")
    else:
        for key in sorted(set(environment) ^ set(expected)):
            problems.append(f"service {name} environment variable set differs: {key}")
        for key, (kind, wanted) in expected.items():
            if key not in environment:
                continue
            value = environment[key]
            if kind == "literal":
                if value != wanted:
                    problems.append(f"service {name} variable {key} has an unexpected value")
            else:
                match = _REFERENCE_RE.fullmatch(value or "")
                if not match or match.group("name") != wanted:
                    problems.append(f"service {name} variable {key} is not a required-variable reference")

    networks = _as_names(service.get("networks"))
    if networks != {"mvp-net"}:
        problems.append(f"service {name} is not on exactly the project network")

    dependencies = _as_dependencies(service.get("depends_on"))
    if dependencies != _DEPENDENCIES[name]:
        problems.append(f"service {name} start-up dependencies are not the expected ones")

    published = _as_published(service.get("ports"))
    if name == "viewer":
        if published != [("127.0.0.1", "8000", "8000", "tcp")]:
            problems.append("the viewer does not publish exactly 127.0.0.1:8000")
    elif "ports" in service or published:
        problems.append(f"service {name} publishes a port")

    health = service.get("healthcheck")
    if name in ("postgres", "viewer"):
        test = _as_string_list(health.get("test")) if isinstance(health, dict) else None
        if not isinstance(health, dict) or not test:
            problems.append(f"service {name} has no health check")
        elif name == "postgres" and test != ["CMD-SHELL",
                                             "pg_isready -h 127.0.0.1 -p 5432 -U agentops -d agentops"]:
            problems.append("the postgres health check is not the expected one")
        elif name == "viewer" and not (test[:3] == ["CMD", "python", "-c"] and len(test) == 4
                                      and "http://127.0.0.1:8000/api/health" in test[3]):
            problems.append("the viewer health check is not the expected one")
    elif "healthcheck" in service:
        problems.append(f"service {name} has an unexpected health check")

    if name == "postgres":
        if _as_mounts(service.get("volumes")) != [("postgres-data", "/var/lib/postgresql/data")]:
            problems.append("postgres does not mount exactly the project data volume")
    if name == "viewer":
        if service.get("read_only") is not True:
            problems.append("the viewer root file system is not read-only")
        if _as_string_list(service.get("tmpfs")) != ["/tmp"]:
            problems.append("the viewer tmpfs is not exactly /tmp")
        if _as_string_list(service.get("cap_drop")) != ["ALL"]:
            problems.append("the viewer does not drop all capabilities")
        if _as_string_list(service.get("security_opt")) != ["no-new-privileges:true"]:
            problems.append("the viewer does not set no-new-privileges")
    return problems


def validate_resolved_config(config: object, repo_root: Path) -> list[str]:
    """Problems found in a parsed `compose config` document (empty list: acceptable).

    Fail closed: anything unrecognized is a problem.  The messages hold names of
    services, keys and variables, never values.
    """
    if not isinstance(config, dict):
        return ["the Compose configuration is not a mapping"]
    problems: list[str] = []
    extra = sorted(set(config) - {"name", "services", "networks", "volumes"})
    if extra:
        problems.append("the configuration has unexpected top-level sections: " + ", ".join(map(str, extra)))
    if config.get("name") != PROJECT_NAME:
        problems.append(f"the project name is not {PROJECT_NAME}")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        problems.append("the services are not exactly: " + ", ".join(SERVICES))
        services = {}
    for name in SERVICES:
        if name in services:
            problems += _check_service(name, services[name], repo_root)

    networks = config.get("networks")
    if not isinstance(networks, dict) or set(networks) != {"mvp-net"}:
        problems.append("the networks are not exactly mvp-net")
    else:
        detail = networks["mvp-net"] or {}
        if not isinstance(detail, dict) or detail.get("driver", "bridge") != "bridge" \
                or detail.get("external") or detail.get("internal") \
                or detail.get("name", f"{PROJECT_NAME}_mvp-net") != f"{PROJECT_NAME}_mvp-net" \
                or set(detail) - {"name", "driver"}:
            problems.append("the project network is not a plain bridge network owned by the project")

    volumes = config.get("volumes")
    if not isinstance(volumes, dict) or set(volumes) != {"postgres-data"}:
        problems.append("the volumes are not exactly postgres-data")
    else:
        detail = volumes["postgres-data"]
        if not isinstance(detail, dict) or detail.get("name") != VOLUME_NAME:
            problems.append(f"the data volume is not named {VOLUME_NAME}")
        elif detail.get("external") or set(detail) - {"name", "labels"} \
                or (detail.get("labels") or {}).get("agentops.mvp") != "true":
            problems.append("the data volume is external, unlabelled or has unexpected settings")

    text = repr(config)
    for foreign in _FOREIGN_NAMES:
        if foreign in text:
            problems.append("the configuration refers to a resource that belongs to something else")
            break
    return problems


# -- the command ----------------------------------------------------------------

def check_config(
    credentials_path: str,
    ctx: _Context,
    *,
    repo_root: Path,
    host_env: Mapping[str, str],
    docker: Optional[str],
    run: ComposeRunner,
) -> str:
    """Validate the credential file, the local engine and the resolved Compose
    configuration.  Starts nothing, creates nothing, reads no database."""
    check_credentials(credentials_path, ctx)          # location, permissions, content
    values = parse_file(_read_bytes(credentials_path))

    compose_file = compose_file_path(repo_root)
    if not compose_file.is_file():
        raise CredentialError("the MVP Compose file was not found in the repository")
    if (compose_file.parent / ".env").exists():
        raise CredentialError("a .env file exists next to the MVP Compose file; "
                              "Compose would read it, so the check refuses")
    if not docker:
        raise CredentialError("the container command-line tool was not found", EXIT_FAILED)

    child = build_child_environment(host_env)          # no credential reaches the inspection
    require_local_engine(host_env, child, docker, run)

    secrets_seen = set(values.values())
    for name in CREDENTIAL_VARIABLES:
        host_value = _env(host_env, name)
        if host_value:
            secrets_seen.add(host_value)

    argv = compose_argv(docker, repo_root, ["config", *_INSPECTION_OPTIONS])
    result = run(argv, child)
    if result.returncode != 0:
        raise CredentialError(
            "the Compose configuration could not be inspected; the installed Compose may not "
            "support the required options (config --format json --no-interpolate)", EXIT_FAILED)
    output = result.stdout
    if len(output) > _MAX_COMPOSE_OUTPUT:
        raise CredentialError("the Compose output is larger than expected")
    text = output.decode("utf-8", "replace")
    if any(secret in text for secret in secrets_seen):
        raise CredentialError("the Compose output contained a credential value and was discarded")
    try:
        config = json.loads(text)
    except ValueError:
        raise CredentialError("the Compose output is not valid JSON", EXIT_FAILED) from None
    problems = validate_resolved_config(config, repo_root)
    if problems:
        raise CredentialError("the Compose configuration is not acceptable: " + "; ".join(problems))
    return ("configuration OK: project " + PROJECT_NAME + "\n"
            "  services: " + ", ".join(SERVICES) + "; data volume " + VOLUME_NAME + "\n"
            "  only 127.0.0.1:8000 is published; PostgreSQL publishes nothing\n"
            "  credential file valid (values not shown); nothing was started")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentops_mvp.py",
        description="Credential, status and image-build tooling for the AgentOps MVP stack.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "status", help="read-only status of the MVP stack's Docker resources",
        description="Inspect the MVP project's containers, network, volume and images (read only). "
                    "No credential file is needed, nothing is created, and no lock is taken.")
    for name, text in (("init-credentials", "create the credential file once"),
                       ("check-credentials", "validate the credential file"),
                       ("check-config", "validate credentials, the local engine and the Compose configuration"),
                       ("build", "build the three MVP images (nothing is started, created or pulled)"),
                       ("up", "create and start the MVP stack once, from the built images (nothing is built or pulled)"),
                       ("seed-demo", "write the deterministic demo dataset into the empty MVP database (once)")):
        command = sub.add_parser(name, help=text, description=text)
        command.add_argument(
            "--credentials-file", metavar="PATH", default=None,
            help="absolute path ending in agentops-mvp/credentials.env "
                 "(default: outside the repository, in the per-user configuration directory)")
    return parser


def _lifecycle_module():
    import agentops_mvp_lifecycle as lifecycle
    return lifecycle


def _default_probes(lifecycle, platform_name, run, child, directory):
    return lifecycle.Probes(
        memory_mib=lambda: lifecycle.read_available_memory_mib(platform_name, runner=run, env=child),
        disk_free_gib=lambda: lifecycle.disk_free_gib(directory),
        port_in_use=lambda port: lifecycle.port_in_use(port, platform_name=platform_name),
    )


def _joined(built: Sequence[str]) -> str:
    return ", ".join(built) or "nothing"


def _build_command(
    path: str,
    ctx: _Context,
    *,
    repo_root: Path,
    environ: Mapping[str, str],
    platform_name: str,
    run: ComposeRunner,
    build_run: ComposeRunner,
    docker: Optional[str],
    probes: Optional[object],
) -> str:
    """build: create the three MVP images, one at a time.  Starts nothing, creates no
    container, network or volume, pulls nothing, and removes nothing (not even after a failure)."""
    lifecycle = _lifecycle_module()

    # 1. credentials, local engine and the resolved configuration: the existing checks
    check_config(path, ctx, repo_root=repo_root, host_env=environ, docker=docker, run=run)
    if not docker:
        raise CredentialError("the container command-line tool was not found", EXIT_FAILED)
    values = parse_file(_read_bytes(path))
    secrets = list(values.values()) + [_BUILD_PLACEHOLDER]
    secrets += [v for v in (_env(environ, name) for name in CREDENTIAL_VARIABLES) if v]

    inspect_env = build_child_environment(environ)      # no COMPOSE_*, no credential names
    build_env = dict(inspect_env)
    build_env.update({name: _BUILD_PLACEHOLDER for name in CREDENTIAL_VARIABLES})

    credentials_directory = os.path.dirname(path)
    if probes is None:
        probes = _default_probes(lifecycle, platform_name, run, inspect_env, credentials_directory)

    # 2. the installed Compose must have a build command that takes service names
    _require_help(run, build_capability_argv(docker, repo_root), inspect_env, ("docker compose build", "SERVICE"),
                  "the installed Compose does not support building named services")

    # 3. one lifecycle command at a time
    lock = lifecycle.ExclusiveLock(os.path.join(credentials_directory, "lifecycle.lock"), platform_name=platform_name)
    try:
        lock.acquire()
    except lifecycle.LifecycleError as error:
        raise CredentialError(lifecycle.safe_message(error)) from None
    try:
        return _build_locked(lifecycle, repo_root, docker, run, build_run, inspect_env, build_env, probes, secrets)
    finally:
        lock.release()


def _build_locked(lifecycle, repo_root, docker, run, build_run, inspect_env, build_env, probes, secrets) -> str:
    def memory_low() -> Optional[str]:
        try:
            return lifecycle.memory_problem(probes.memory_mib(), lifecycle.BUILD_MIN_MIB)
        except lifecycle.LifecycleError:
            return "available memory could not be read"

    # 4. the resources must be in a state that allows building
    problem = lifecycle.build_preflight_problem(lifecycle.inspect_stack(docker, run, inspect_env))
    if problem:
        raise CredentialError("not building: " + problem)

    # 5. host memory and disk, then the engine's own memory
    problem = memory_low()
    if problem:
        raise CredentialError("not building: " + problem)
    try:
        problem = lifecycle.disk_problem(probes.disk_free_gib())
    except lifecycle.LifecycleError:
        problem = "free disk space could not be read"
    if problem:
        raise CredentialError("not building: " + problem)
    try:
        engine_mib = lifecycle.read_engine_memory_mib(docker, run, inspect_env)
    except lifecycle.LifecycleError as error:
        raise CredentialError("not building: " + lifecycle.safe_message(error)) from None
    problem = lifecycle.memory_problem(engine_mib, lifecycle.DOCKER_VM_MIN_MIB)
    if problem:
        raise CredentialError("not building: the container engine has too little memory (" + problem + ")")

    # 6. base images must already exist locally: the build is never allowed to fetch one
    missing: list[str] = []
    try:
        for service in lifecycle.BUILD_ORDER:
            dockerfile = Path(repo_root).joinpath(*_DOCKERFILES[service].split("/"))
            for reference in lifecycle.parse_base_images(dockerfile.read_text(encoding="utf-8")):
                if reference not in missing and not lifecycle.base_image_present(docker, run, inspect_env, reference):
                    missing.append(reference)
    except (OSError, UnicodeError):
        raise CredentialError("not building: a Dockerfile could not be read") from None
    except lifecycle.LifecycleError as error:
        raise CredentialError("not building: " + lifecycle.safe_message(error)) from None
    if missing:
        raise CredentialError("not building: base images are not present locally (nothing is pulled): "
                              + ", ".join(missing))

    # 7. build sequentially, re-checking host memory before each service
    built: list[str] = []
    for service in lifecycle.BUILD_ORDER:
        problem = memory_low()
        if problem:
            raise CredentialError(f"stopped before building {service}: {problem}; built so far: {_joined(built)}; "
                                  "nothing was removed", EXIT_FAILED)
        try:
            result = build_run(build_argv(docker, repo_root, service), build_env)
        except subprocess.TimeoutExpired:
            raise CredentialError(f"the {service} image build timed out; built so far: {_joined(built)}; "
                                  "nothing was removed", EXIT_FAILED) from None
        except CredentialError as error:
            raise CredentialError(f"the {service} image build did not run ({error}); built so far: "
                                  f"{_joined(built)}; nothing was removed", EXIT_FAILED) from None
        except Exception:  # noqa: BLE001
            raise CredentialError(f"the {service} image build could not be run; built so far: {_joined(built)}; "
                                  "nothing was removed", EXIT_FAILED) from None
        if result.returncode != 0:
            tail = lifecycle.redact(result.stdout.decode("utf-8", "replace"), secrets)
            tail = "".join(ch if ch.isprintable() or ch == "\n" else " " for ch in tail).strip()[-1500:]
            raise CredentialError(
                f"the {service} image build failed (exit code {result.returncode}); built so far: {_joined(built)}; "
                "nothing was removed" + (f"\n--- last build output (redacted) ---\n{tail}" if tail else ""),
                EXIT_FAILED)
        built.append(service)

    # 8. the result: three images, and nothing else was created
    problems = lifecycle.build_result_problems(lifecycle.inspect_stack(docker, run, inspect_env))
    if problems:
        raise CredentialError("the build finished but: " + "; ".join(problems) + "; nothing was removed", EXIT_FAILED)
    return ("images built: " + ", ".join(built) + "\n"
            "  no container, network or volume was created; nothing was started, pulled or removed\n"
            "  credential file valid (values not shown)")


def _require_help(run: ComposeRunner, argv: list[str], env: Mapping[str, str], needles: Sequence[str],
                  refusal: str) -> None:
    """Fail closed unless the installed Compose's help text shows every needed word."""
    try:
        result = run(argv, env)
    except CredentialError:
        raise
    except Exception:  # noqa: BLE001
        raise CredentialError("the Compose command could not be checked", EXIT_FAILED) from None
    text = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0 or any(word not in text for word in needles):
        raise CredentialError(refusal, EXIT_FAILED)


#: Every option the start command uses must be present in the installed Compose's help.
_UP_HELP_WORDS = ("docker compose up", "--detach", "--no-build", "--pull", "never", "--no-recreate")


def _up_command(
    path: str,
    ctx: _Context,
    *,
    repo_root: Path,
    environ: Mapping[str, str],
    platform_name: str,
    run: ComposeRunner,
    up_run: ComposeRunner,
    docker: Optional[str],
    probes: Optional[object],
    sleep: Callable[[float], None],
) -> str:
    """up: create and start the isolated MVP stack once, from images that already exist.
    Never builds, pulls, recreates or removes anything, and never touches another project."""
    lifecycle = _lifecycle_module()

    # 1. credentials, local engine and the resolved configuration: the existing checks
    check_config(path, ctx, repo_root=repo_root, host_env=environ, docker=docker, run=run)
    if not docker:
        raise CredentialError("the container command-line tool was not found", EXIT_FAILED)
    values = parse_file(_read_bytes(path))
    secrets = list(values.values())
    secrets += [v for v in (_env(environ, name) for name in CREDENTIAL_VARIABLES) if v]

    inspect_env = build_child_environment(environ)      # no COMPOSE_*, no credential names
    up_env = build_child_environment(environ, values)   # the validated file values, in the environment only

    credentials_directory = os.path.dirname(path)
    if probes is None:
        probes = _default_probes(lifecycle, platform_name, run, inspect_env, credentials_directory)

    # 2. the installed Compose must support every option the start command uses
    _require_help(run, up_capability_argv(docker, repo_root), inspect_env, _UP_HELP_WORDS,
                  "the installed Compose does not support the options the start command needs")

    # 3. one lifecycle command at a time
    lock = lifecycle.ExclusiveLock(os.path.join(credentials_directory, "lifecycle.lock"), platform_name=platform_name)
    try:
        lock.acquire()
    except lifecycle.LifecycleError as error:
        raise CredentialError(lifecycle.safe_message(error)) from None
    try:
        return _up_locked(lifecycle, repo_root, docker, run, up_run, inspect_env, up_env, probes, secrets, sleep)
    finally:
        lock.release()


def _up_evidence(lifecycle, docker, run, inspect_env) -> str:
    """The current classification, for a failure report.  Never raises."""
    try:
        report = lifecycle.classify(lifecycle.inspect_stack(docker, run, inspect_env))
        return lifecycle.format_evidence(report)
    except Exception:  # noqa: BLE001
        return "the stack state could not be inspected"


def _up_locked(lifecycle, repo_root, docker, run, up_run, inspect_env, up_env, probes, secrets, sleep) -> str:
    kept = "nothing was removed; every container, the network and the data volume were kept for inspection"

    # 4. the stack must not exist yet, and its images must
    problem = lifecycle.start_preflight_problem(lifecycle.inspect_stack(docker, run, inspect_env))
    if problem:
        raise CredentialError("not starting: " + problem)

    # 5. host memory (twice: now, and again right before the start), disk, engine memory, the port
    def memory_low() -> Optional[str]:
        try:
            return lifecycle.memory_problem(probes.memory_mib(), lifecycle.UP_MIN_MIB)
        except lifecycle.LifecycleError:
            return "available memory could not be read"

    problem = memory_low()
    if problem:
        raise CredentialError("not starting: " + problem)
    try:
        problem = lifecycle.disk_problem(probes.disk_free_gib())
    except lifecycle.LifecycleError:
        problem = "free disk space could not be read"
    if problem:
        raise CredentialError("not starting: " + problem)
    try:
        engine_mib = lifecycle.read_engine_memory_mib(docker, run, inspect_env)
    except lifecycle.LifecycleError as error:
        raise CredentialError("not starting: " + lifecycle.safe_message(error)) from None
    problem = lifecycle.memory_problem(engine_mib, lifecycle.DOCKER_VM_MIN_MIB)
    if problem:
        raise CredentialError("not starting: the container engine has too little memory (" + problem + ")")
    try:
        busy = probes.port_in_use(lifecycle.PUBLISHED_PORT)
    except lifecycle.LifecycleError:
        raise CredentialError(f"not starting: port {lifecycle.PUBLISHED_PORT} could not be checked") from None
    if busy:
        raise CredentialError(f"not starting: port {lifecycle.PUBLISHED_PORT} is already in use")

    problem = memory_low()
    if problem:
        raise CredentialError("not starting: " + problem)

    # 6. start; whatever happens next, nothing is cleaned up
    try:
        result = up_run(up_argv(docker, repo_root), up_env)
    except KeyboardInterrupt:
        raise CredentialError("the start was interrupted; the stack may be partly created; " + kept
                              + "\n" + _up_evidence(lifecycle, docker, run, inspect_env), EXIT_FAILED) from None
    except subprocess.TimeoutExpired:
        raise CredentialError("the start timed out; the stack may be partly created; " + kept
                              + "\n" + _up_evidence(lifecycle, docker, run, inspect_env), EXIT_FAILED) from None
    except CredentialError as error:
        raise CredentialError(f"the start did not complete ({error}); the stack may be partly created; " + kept
                              + "\n" + _up_evidence(lifecycle, docker, run, inspect_env), EXIT_FAILED) from None
    except Exception:  # noqa: BLE001
        raise CredentialError("the start command could not be run; " + kept
                              + "\n" + _up_evidence(lifecycle, docker, run, inspect_env), EXIT_FAILED) from None
    if result.returncode != 0:
        tail = lifecycle.redact(result.stdout.decode("utf-8", "replace"), secrets)
        tail = "".join(ch if ch.isprintable() or ch == "\n" else " " for ch in tail).strip()[-1500:]
        raise CredentialError(
            f"the start failed (exit code {result.returncode}); " + kept
            + "\n" + _up_evidence(lifecycle, docker, run, inspect_env)
            + (f"\n--- last start output (redacted) ---\n{tail}" if tail else ""), EXIT_FAILED)

    # 7. read-only polling until the stack is complete, has failed, or the time is up
    report = None
    try:
        for attempt in range(lifecycle.START_POLLS):
            report = lifecycle.classify(lifecycle.inspect_stack(docker, run, inspect_env))
            verdict = lifecycle.start_verdict(report)
            if verdict != lifecycle.VERDICT_PENDING:
                break
            if attempt + 1 < lifecycle.START_POLLS:
                sleep(lifecycle.START_POLL_SECONDS)
    except KeyboardInterrupt:
        raise CredentialError("waiting was interrupted; the stack was started; " + kept
                              + "\n" + _up_evidence(lifecycle, docker, run, inspect_env), EXIT_FAILED) from None
    if report is None or verdict == lifecycle.VERDICT_FAILED:
        raise CredentialError("the stack did not reach a complete state; " + kept + "\n"
                              + (lifecycle.format_evidence(report) if report else ""), EXIT_FAILED)
    if verdict == lifecycle.VERDICT_PENDING:
        raise CredentialError("timed out waiting for the stack to become healthy; " + kept + "\n"
                              + lifecycle.format_evidence(report), EXIT_FAILED)
    return ("stack started: COMPLETE (container evidence: the bootstrap container exited 0 and the viewer is healthy)\n"
            f"  viewer: http://127.0.0.1:{lifecycle.PUBLISHED_PORT}/  (published on 127.0.0.1 only)\n"
            "  PostgreSQL publishes no port; nothing was built, pulled, recreated or removed\n"
            "  the migration ledger was not read; credential file valid (values not shown)")


def _demo_module():
    import agentops_mvp_demo as demo
    return demo


# -- demo seeding ------------------------------------------------------------------------
#
# seed-demo writes the deterministic demo dataset (agentops_mvp_demo) into the MVP
# PostgreSQL and nowhere else:
#   - the target is the fixed container agentops-mvp-postgres-1 (never named by anything
#     the user types), checked for its project label, its dedicated data volume and the
#     absence of any published port
#   - the database is reached through the container's own local socket (docker exec ... psql),
#     so no password is needed anywhere; nothing is ever put in an argument or a log
#   - the work is one psql --single-transaction script: the four tables are locked, found
#     empty again, filled and counted, or nothing happens at all
#   - the script writes INSERT statements into four public tables; the bootstrap ledger
#     and the analytics schema are only ever read
#   - nothing is cleaned up after a failure

POSTGRES_CONTAINER = "agentops-mvp-postgres-1"
POSTGRES_DATA_DESTINATION = "/var/lib/postgresql/data"
SEED_TIMEOUT_SECONDS = 120
_EXPECTED_CONTAINER_FACTS = (f"{PROJECT_NAME}|postgres|true|volume:{VOLUME_NAME}:{POSTGRES_DATA_DESTINATION};")
_CONTAINER_FACTS_FORMAT = (
    '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|'
    '{{.State.Running}}|{{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}};{{end}}|{{json .HostConfig.PortBindings}}')


def container_facts_argv(docker: str) -> list[str]:
    """Identity, volume and port facts of the one container the seed may write to.
    Labels, mounts and port bindings only: never its environment or configuration."""
    return [docker, "inspect", "--type", "container", "--format", _CONTAINER_FACTS_FORMAT, POSTGRES_CONTAINER]


def psql_read_argv(docker: str, sql: str) -> list[str]:
    """One fixed SELECT, in a session that is read-only."""
    demo = _demo_module()
    allowed = {demo.LEDGER_SQL, demo.COUNTS_SQL, *(demo.rows_sql(t) for t in demo.TABLES)}
    if sql not in allowed:
        raise CredentialError("that query is not one of the fixed seed queries", EXIT_USAGE)
    return [docker, "exec", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on", POSTGRES_CONTAINER,
            "psql", "-U", "agentops", "-d", "agentops", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql]


def psql_write_argv(docker: str) -> list[str]:
    """The seed script arrives on standard input; one transaction; stop at the first error."""
    return [docker, "exec", "-i", POSTGRES_CONTAINER,
            "psql", "-U", "agentops", "-d", "agentops", "-X", "-q", "--single-transaction",
            "-v", "ON_ERROR_STOP=1", "-f", "-"]


SeedRunner = Callable[[Sequence[str], Mapping[str, str], bytes], CommandResult]


def default_seed_runner(argv: Sequence[str], env: Mapping[str, str], input_bytes: bytes) -> CommandResult:
    return _run_bounded(argv, env, SEED_TIMEOUT_SECONDS, input_bytes)


def _seed_command(
    path: str,
    ctx: _Context,
    *,
    repo_root: Path,
    environ: Mapping[str, str],
    platform_name: str,
    run: ComposeRunner,
    seed_run: SeedRunner,
    docker: Optional[str],
) -> str:
    """seed-demo: write the demo dataset once, into an empty, bootstrapped MVP database."""
    lifecycle = _lifecycle_module()

    # 1. credentials, local engine and the resolved configuration: the existing checks
    check_config(path, ctx, repo_root=repo_root, host_env=environ, docker=docker, run=run)
    if not docker:
        raise CredentialError("the container command-line tool was not found", EXIT_FAILED)
    secrets = [v for v in (_env(environ, name) for name in CREDENTIAL_VARIABLES) if v]
    inspect_env = build_child_environment(environ)      # no COMPOSE_*, no credential names

    # 2. one lifecycle command at a time
    lock = lifecycle.ExclusiveLock(os.path.join(os.path.dirname(path), "lifecycle.lock"), platform_name=platform_name)
    try:
        lock.acquire()
    except lifecycle.LifecycleError as error:
        raise CredentialError(lifecycle.safe_message(error)) from None
    try:
        return _seed_locked(lifecycle, _demo_module(), docker, run, seed_run, inspect_env, secrets)
    finally:
        lock.release()


def _query(run: ComposeRunner, argv: list[str], env: Mapping[str, str], what: str) -> str:
    try:
        result = run(argv, env)
    except CredentialError:
        raise
    except Exception:  # noqa: BLE001
        raise CredentialError(f"not seeding: {what} could not be read", EXIT_FAILED) from None
    if result.returncode != 0:
        raise CredentialError(f"not seeding: {what} could not be read", EXIT_FAILED)
    return result.stdout.decode("utf-8", "replace")


def _seed_locked(lifecycle, demo, docker, run, seed_run, env, secrets) -> str:
    # 3. the stack must be complete and the target must be the dedicated MVP database
    report = lifecycle.classify(lifecycle.inspect_stack(docker, run, env))
    if report.state != lifecycle.STATE_COMPLETE:
        raise CredentialError(f"not seeding: the MVP stack status is {report.state}, not COMPLETE; "
                              "run status for details")
    facts = _query(run, container_facts_argv(docker), env, "the database container's identity").strip()
    head, _, ports = facts.rpartition("|")
    if head != _EXPECTED_CONTAINER_FACTS or ports.strip() not in ("{}", "null"):
        raise CredentialError("not seeding: the database container is not the isolated MVP database "
                              "(project label, dedicated data volume or published ports differ)")

    # 4. the bootstrap ledger must be exactly the 18 expected steps
    try:
        ledger = demo.parse_ledger(_query(run, psql_read_argv(docker, demo.LEDGER_SQL), env, "the bootstrap ledger"))
    except ValueError:
        raise CredentialError("not seeding: the bootstrap ledger could not be read", EXIT_FAILED) from None
    if not demo.ledger_matches(ledger):
        raise CredentialError(f"not seeding: the bootstrap ledger is not the expected {len(demo.EXPECTED_LEDGER_STEPS)} "
                              f"steps ({len(ledger)} rows found)")

    # 5. empty: seed.  Identical to the manifest: nothing to do.  Anything else: refuse.
    counts = demo.parse_counts(_query(run, psql_read_argv(docker, demo.COUNTS_SQL), env, "the table row counts"))
    if counts is None:
        raise CredentialError("not seeding: the table row counts could not be read", EXIT_FAILED)
    if any(counts.values()):
        if counts != demo.EXPECTED_COUNTS:
            raise CredentialError("not seeding: the target tables already hold data that is not the demo dataset "
                                  "(" + _describe_counts(demo, counts) + "); nothing was changed")
        problems = _compare_all(run, docker, env, demo)
        if problems:
            raise CredentialError("not seeding: the target tables hold data that differs from the demo dataset ("
                                  + "; ".join(problems[:3]) + "); nothing was changed")
        return ("demo data already present: all " + _describe_counts(demo, counts) + " match the manifest exactly\n"
                "  nothing was written")

    # 6. one transaction; whatever happens, nothing is cleaned up
    script = demo.seed_sql().encode("utf-8")
    try:
        result = seed_run(psql_write_argv(docker), env, script)
    except KeyboardInterrupt:
        raise CredentialError("the seed was interrupted; the transaction commits completely or not at all and "
                              "may still be finishing; nothing was removed; " + _seed_evidence(run, docker, env, demo),
                              EXIT_FAILED) from None
    except subprocess.TimeoutExpired:
        raise CredentialError("the seed timed out; nothing was removed; " + _seed_evidence(run, docker, env, demo),
                              EXIT_FAILED) from None
    except CredentialError as error:
        raise CredentialError(f"the seed did not complete ({error}); nothing was removed; "
                              + _seed_evidence(run, docker, env, demo), EXIT_FAILED) from None
    except Exception:  # noqa: BLE001
        raise CredentialError("the seed command could not be run; nothing was removed; "
                              + _seed_evidence(run, docker, env, demo), EXIT_FAILED) from None
    if result.returncode != 0:
        tail = lifecycle.redact(result.stdout.decode("utf-8", "replace"), secrets)
        tail = "".join(ch if ch.isprintable() or ch == "\n" else " " for ch in tail).strip()[-1500:]
        raise CredentialError(f"the seed failed (exit code {result.returncode}) and was rolled back; nothing was removed; "
                              + _seed_evidence(run, docker, env, demo)
                              + (f"\n--- last database output (redacted) ---\n{tail}" if tail else ""), EXIT_FAILED)

    # 7. the committed result must equal the manifest, row by row
    after = demo.parse_counts(_query(run, psql_read_argv(docker, demo.COUNTS_SQL), env, "the table row counts"))
    problems = _compare_all(run, docker, env, demo) if after == demo.EXPECTED_COUNTS else ["row counts differ"]
    if problems:
        raise CredentialError("the seed was committed but verification failed (" + "; ".join(problems[:3])
                              + "); nothing was removed", EXIT_FAILED)
    return ("demo data seeded: " + _describe_counts(demo, demo.EXPECTED_COUNTS) + "\n"
            "  rows written only to public.telemetry_spans, anomaly_events, rca_investigations and rca_evidence\n"
            "  the bootstrap ledger and the analytics schema were not changed; verified row by row")


def _describe_counts(demo, counts: Mapping[str, int]) -> str:
    return ", ".join(f"{counts[t]} {t}" for t in demo.TABLES)


def _compare_all(run, docker, env, demo) -> list[str]:
    problems: list[str] = []
    for table in demo.TABLES:
        text = _query(run, psql_read_argv(docker, demo.rows_sql(table)), env, f"the {table} rows")
        problems += demo.compare_rows(table, text)
    return problems


def _seed_evidence(run, docker, env, demo) -> str:
    """What the tables hold now, for a failure report.  Never raises."""
    try:
        counts = demo.parse_counts(_query(run, psql_read_argv(docker, demo.COUNTS_SQL), env, "the row counts"))
    except Exception:  # noqa: BLE001
        counts = None
    return ("the tables now hold " + _describe_counts(demo, counts)) if counts else "the table state could not be read"


def _status_command(
    environ: Mapping[str, str],
    platform_name: str,
    home: str,
    run: ComposeRunner,
    docker: Optional[str],
    probes: Optional[object],
    out: TextIO,
) -> int:
    """status: read-only.  Needs no credential file, takes no lock, writes nothing."""
    lifecycle = _lifecycle_module()

    child = build_child_environment(environ)           # no COMPOSE_*, no credential names
    if probes is None:
        try:
            credentials_directory = os.path.dirname(default_credentials_path(environ, platform_name, home))
        except CredentialError:
            credentials_directory = home
        probes = _default_probes(lifecycle, platform_name, run, child, credentials_directory)
    unavailable = False
    if not docker:
        unavailable = True
    else:
        try:
            require_local_engine(environ, child, docker, run)
        except CredentialError as error:
            if error.exit_code != EXIT_FAILED:
                raise                                   # not a local engine: refused
            unavailable = True
    if unavailable:
        snapshot = lifecycle.Snapshot(errors=["ENGINE_UNAVAILABLE"])
    else:
        snapshot = lifecycle.inspect_stack(docker, run, child)
    report = lifecycle.classify(snapshot)
    print(lifecycle.format_status(report, probes), file=out)
    return {lifecycle.STATE_AMBIGUOUS: EXIT_AMBIGUOUS, lifecycle.STATE_UNKNOWN: EXIT_UNKNOWN}.get(report.state, EXIT_OK)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    platform_name: Optional[str] = None,
    runner: Optional[Runner] = None,
    compose_runner: Optional[ComposeRunner] = None,
    docker: Optional[str] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    repo_root: Optional[Path] = None,
    home: Optional[str] = None,
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
    probes: Optional[object] = None,
    sleep: Callable[[float], None] = time.sleep,
    seed_runner: Optional[SeedRunner] = None,
) -> int:
    environ = os.environ if environ is None else environ
    platform_name = os.name if platform_name is None else platform_name
    runner = default_runner if runner is None else runner
    repo_root = repository_root() if repo_root is None else repo_root
    home = os.path.expanduser("~") if home is None else home
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        args = _build_parser().parse_args(list(argv) if argv is not None else None)
    except SystemExit as exit_request:
        return EXIT_USAGE if exit_request.code not in (0, None) else EXIT_OK
    try:
        if args.command == "status":
            return _status_command(
                environ, platform_name, home, compose_runner or default_compose_runner,
                docker if docker is not None else which("docker"), probes, out,
            )
        raw = args.credentials_file or default_credentials_path(environ, platform_name, home)
        path = check_location(raw, repo_root, environ)
        ctx = _Context(environ, platform_name, runner)
        if args.command == "init-credentials":
            message = init_credentials(path, ctx)
        elif args.command == "check-credentials":
            message = check_credentials(path, ctx)
        elif args.command == "build":
            message = _build_command(
                path, ctx, repo_root=repo_root, environ=environ, platform_name=platform_name,
                run=compose_runner or default_compose_runner, build_run=compose_runner or default_build_runner,
                docker=docker if docker is not None else which("docker"), probes=probes,
            )
        elif args.command == "up":
            message = _up_command(
                path, ctx, repo_root=repo_root, environ=environ, platform_name=platform_name,
                run=compose_runner or default_compose_runner, up_run=compose_runner or default_up_runner,
                docker=docker if docker is not None else which("docker"), probes=probes, sleep=sleep,
            )
        elif args.command == "seed-demo":
            message = _seed_command(
                path, ctx, repo_root=repo_root, environ=environ, platform_name=platform_name,
                run=compose_runner or default_compose_runner, seed_run=seed_runner or default_seed_runner,
                docker=docker if docker is not None else which("docker"),
            )
        else:
            message = check_config(
                path, ctx, repo_root=repo_root, host_env=environ,
                docker=docker if docker is not None else which("docker"),
                run=compose_runner or default_compose_runner,
            )
        print(message, file=out)
        return EXIT_OK
    except CredentialError as error:
        print(f"error: {error}", file=err)
        return error.exit_code
    except Exception as error:  # noqa: BLE001 - last line of containment; type only
        print(f"error: internal ({type(error).__name__})", file=err)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
