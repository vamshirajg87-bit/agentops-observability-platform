"""
trace-viewer/tests/unit/test_legacy_demo_script.py

Static guard tests for docker/trace-viewer/legacy-demo.ps1.

The script is only READ here, as text.  It is never executed, no Docker or database is
touched, and the PowerShell syntax check (skipped where PowerShell is not installed)
parses the file without running it.

Coverage
    1  Script is ASCII, Windows PowerShell 5.1 compatible, and takes only start|status|stop
       and -Open (no bypass, keep-on-failure or force switch)
    2  Fixed resource identities and label
    3  Port publication: one literal 127.0.0.1:8000:8000, never 5432, never -P
    4  Allowed and prohibited Docker operations
    5  Start preflights (original stopped, volume users, backup, image, ports, refuse existing)
    6  Isolation flags of the two docker run commands
    7  Password handling
    8  Ownership checks before any removal, stop order, failure cleanup scope
    9  status is read-only
   10  The original container and the volume are never mutated
   11  README documents the script and the read-write volume caveat
   12  PowerShell 5.1 parser accepts the file (skipped without PowerShell)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

_DOCKER_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docker", "trace-viewer")
_SCRIPT = os.path.join(_DOCKER_DIR, "legacy-demo.ps1")
_README = os.path.join(_DOCKER_DIR, "README.md")


def _read(path: str) -> str:
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


SRC = _read(_SCRIPT)


def _code() -> str:
    """Script without comment-based help and without # comment lines."""
    text = re.sub(r"<#.*?#>", "", SRC, flags=re.S)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


CODE = _code()
CODE_BODY = re.sub(r"^param\(.*?^\)\n", "", CODE, count=1, flags=re.S | re.M)  # without the param block
assert CODE_BODY != CODE
# Docker argument literals only: no entry-point switch, no double-quoted message text.
CODE_ARGS = CODE_BODY[:CODE_BODY.index("try {\n  if ($Open")]


def _blank(text: str) -> str:
    """Text with double-quoted message strings emptied."""
    return re.sub(r'"(?:[^"`]|`.)*"', '""', text)


CODE_ARGS = _blank(CODE_ARGS)


def _func(name: str) -> str:
    match = re.search(r"^function " + re.escape(name) + r"\b.*?(?=^function |\Z)", CODE, re.S | re.M)
    assert match, f"function {name} not found"
    return match.group(0)


def _docker_calls() -> list[str]:
    """Text of every Invoke-Docker / Docker-Ok argument list."""
    return re.findall(r"(?:Invoke-Docker|Docker-Ok)\s*\(?\s*(@\(.*?\)\s*(?:\+\s*\$\w+\s*\+\s*@\(.*?\))?)", CODE, re.S)


# ---------------------------------------------------------------------------
# 1  Script form
# ---------------------------------------------------------------------------


def test_script_is_ascii_only():
    SRC.encode("ascii")  # PowerShell 5.1 reads BOM-less files in the ANSI code page


def test_powershell_5_1_compatible_constructs_only():
    assert "&&" not in CODE and "||" not in CODE
    assert "??" not in CODE and "?." not in CODE
    assert not re.search(r"\$\w+\s*\?\s*[^\s]", CODE)  # no ternary
    assert "-AsHashtable" not in CODE and "-AsByteStream" not in CODE
    assert "#requires -Version 7" not in SRC.lower()


def test_parameters_are_action_and_open_only():
    block = re.search(r"param\((.*?)\n\)", SRC, re.S).group(1)
    assert "ValidateSet('start', 'status', 'stop')" in block
    assert set(re.findall(r"\[(?:string|switch)\]\$(\w+)", block)) == {"Action", "Open"}
    assert "[switch]$Open" in block
    # No bypass of the backup check and no keep-on-failure option.  The only allowed
    # mention of "Bypass" is the documented one-process execution-policy hint for users.
    without_hint = SRC.replace("-ExecutionPolicy Bypass", "")
    for forbidden in ("SkipBackup", "KeepOnFailure", "Force", "Bypass", "NoBackup"):
        assert forbidden not in without_hint, forbidden
        assert forbidden not in block, forbidden


def test_open_is_only_valid_with_start():
    assert "-Open is only valid with the start action" in SRC
    assert re.search(r"if \(\$Open\) \{ Start-Process \$Url \}", CODE)
    assert CODE.count("Start-Process") == 1


# ---------------------------------------------------------------------------
# 2  Identities
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("declaration", [
    "$PgName          = 'agentops-legacy-demo-pg'",
    "$ViewerName      = 'agentops-legacy-demo-viewer'",
    "$NetworkName     = 'agentops-legacy-demo-net'",
    "$LabelKey        = 'agentops.demo'",
    "$LabelValue      = 'legacy-viewer'",
    "$LabelFilter     = 'label=agentops.demo=legacy-viewer'",
    "$OriginalName    = 'agentops-postgres'",
    "$VolumeName      = 'agentops_postgres-data'",
    "$ViewerImage     = 'agentops-trace-viewer:local'",
])
def test_fixed_identities(declaration):
    assert declaration in SRC


def test_both_containers_and_the_network_are_labelled():
    assert CODE.count("'--label', ($LabelKey + '=' + $LabelValue)") == 3  # network + 2 containers


# ---------------------------------------------------------------------------
# 3  Port publication
# ---------------------------------------------------------------------------


def test_only_one_published_mapping_and_it_is_loopback_8000():
    assert "$PublishMapping  = '127.0.0.1:8000:8000'" in SRC
    assert CODE.count("'-p'") == 1
    assert "'-p', $PublishMapping" in CODE
    for forbidden in ("'-P'", "--publish", "-p 5432", "5432:5432", "0.0.0.0:", "'-p',  '"):
        assert forbidden not in CODE


_ALLOWED_5432 = re.compile(
    r"TRACE_VIEWER_DB_PORT=5432|Host-Listening 5432|listener|listening|port 5432|ports? .*5432"
)
_PUBLISH_5432 = re.compile(
    r"'-p'|'-P'|--publish|(?:\d{1,3}\.){3}\d{1,3}:\d+:5432|\b\d+:5432\b|\b5432:\d+\b|0\.0\.0\.0:5432|:5432'"
)


def _violations_5432(code: str) -> list[str]:
    """Lines that mention 5432 without being an allowed use, or that publish it.

    Allowed uses are the viewer's in-namespace DB port variable, the host-listener
    checks, and message text.  A line that publishes or maps 5432 is always a violation,
    even if it also happens to contain allowed wording.
    """
    bad = []
    for line in code.splitlines():
        if "5432" not in line:
            continue
        if not _ALLOWED_5432.search(line) or _PUBLISH_5432.search(line):
            bad.append(line.strip())
    return bad


def test_port_5432_is_never_published_or_mapped():
    assert _violations_5432(CODE) == []
    assert any("5432" in line for line in CODE.splitlines())  # the check has something to inspect


@pytest.mark.parametrize("bad_line", [
    "$PublishMapping  = '127.0.0.1:5432:5432'",
    "'-p', '5432:5432',",
    "'-p', '127.0.0.1:8000:8000', '-p', '5432',",
    "docker run --publish 5432",
    "'-p', '0.0.0.0:5432:5432',",
    "$mapping = '15432:5432'",
    "'-e', 'TRACE_VIEWER_DB_PORT=5432', '-p', '5432:5432',",   # allowed wording does not excuse a publish
    "$PgPort = 5432",                                          # unexplained use of the number
])
def test_5432_check_detects_violations(bad_line):
    """The invariant check itself must fail when the invariant is violated."""
    assert _violations_5432("harmless line\n" + bad_line + "\nanother harmless line") != []


@pytest.mark.parametrize("good_line", [
    "'-e', 'TRACE_VIEWER_DB_PORT=5432',",
    "if (Host-Listening 5432) { Fail 'a host listener exists on port 5432' }",
    "Say 'port guard OK: only 127.0.0.1:8000 is published; nothing listens on host port 5432'",
])
def test_5432_check_accepts_the_real_uses(good_line):
    assert _violations_5432(good_line) == []


def test_port_guard_fails_closed_and_runs_before_health_checks():
    guard = _func("Assert-PortsFailClosed")
    assert "'8000/tcp -> 127.0.0.1:8000'" in guard
    assert "$ports.Count -ne 1" in guard
    assert "HostIp -ne '127.0.0.1'" in guard
    assert "the viewer container must not publish any port" in guard
    assert "Host-Listening 5432" in guard
    start = _func("Start-Demo")
    assert start.index("Assert-PortsFailClosed") < start.index("Wait-Viewer") < start.index("Verify-Api")


def test_preflight_refuses_occupied_ports():
    pre = _func("Preflight")
    assert "Host-Listening $HostPort" in pre and "Host-Listening 5432" in pre


# ---------------------------------------------------------------------------
# 4  Docker operations
# ---------------------------------------------------------------------------

_ALLOWED_VERBS = {"version", "ps", "network", "volume", "image", "inspect", "run", "logs",
                  "port", "exec", "stop", "rm"}


def test_only_allowed_docker_verbs_are_used():
    calls = _docker_calls()
    assert calls, "no docker calls found"
    verbs = {re.match(r"@\(\s*'([a-z]+)'", c).group(1) for c in calls}
    assert verbs <= _ALLOWED_VERBS, verbs - _ALLOWED_VERBS


@pytest.mark.parametrize("token", [
    "'build'", "'pull'", "'push'", "'compose'", "'prune'", "'rmi'", "'kill'", "'restart'",
    "'start'", "'cp'", "'commit'", "'save'", "'load'", "'tag'", "'system'", "'update'",
    "'--force'", "'-f'", "'--volumes'", "'-v'" + ", '--", "--privileged", "--network host",
    "'host'", "--pid", "--cap-add", "--device", "--volumes-from", "--env-file",
])
def test_prohibited_docker_operations_and_flags_absent(token):
    assert token not in CODE_ARGS


def test_volume_and_network_subcommands_are_restricted():
    subs = re.findall(r"'volume',\s*'([a-z]+)'", CODE)
    assert subs and set(subs) == {"inspect"}
    nets = set(re.findall(r"'network',\s*'([a-z]+)'", CODE))
    assert nets <= {"ls", "create", "inspect", "rm"}
    assert re.findall(r"'image',\s*'([a-z]+)'", CODE) and set(re.findall(r"'image',\s*'([a-z]+)'", CODE)) == {"inspect"}


def test_no_sql_or_database_client_is_run():
    for word in ("psql", "pg_dump", "pg_restore", "ALTER", "GRANT", "INSERT", "UPDATE ", "DELETE", "migration"):
        assert word not in CODE.replace("pg_isready", ""), word
    execs = re.findall(r"'exec',\s*\$(\w+),\s*'([a-z_]+)'", CODE)
    assert execs == [("PgName", "pg_isready")]


def test_remove_commands_only_inside_the_owned_removers():
    owned = _blank(_func("Remove-OwnedContainer") + _func("Remove-OwnedNetwork"))
    outside = CODE_ARGS.replace(_blank(_func("Remove-OwnedContainer")), "").replace(_blank(_func("Remove-OwnedNetwork")), "")
    assert outside != CODE_ARGS
    assert "'rm'" in owned and "'rm'" not in outside
    assert "'stop'" in owned and "'stop'" not in outside


# ---------------------------------------------------------------------------
# 5  Start preflight
# ---------------------------------------------------------------------------


def test_start_runs_preflight_before_creating_anything():
    start = _func("Start-Demo")
    assert start.index("Preflight") < start.index("'create'") < start.index("'run'")


def test_preflight_checks():
    pre = _func("Preflight")
    required = [
        "'version', '--format', '{{.Server.Version}}'",        # Docker available
        "Demo-Resources",                                      # refuse existing demo resources
        "demo resources already exist",
        "if ($state -ne 'exited')",                            # original stopped
        "'volume', 'inspect', $VolumeName",                    # volume exists
        "'ps', '--filter', ('volume=' + $VolumeName)",         # running volume users
        "running container(s) use the database volume",
        "Container-Field $OriginalName '{{.Image}}'",           # exact original image id
        "'^sha256:[0-9a-f]{64}$'",
        "'image', 'inspect', $ViewerImage",                    # viewer image exists
        "this script never builds",
        "-Filter '*.dump'",                                    # backup
        "$_.Length -gt 0",
        "Fail \"no non-empty database backup",
        "Host-Listening $HostPort",
    ]
    for needle in required:
        assert needle in pre, needle


def test_backup_root_is_under_localappdata_and_cannot_be_bypassed():
    assert "$BackupRoot      = Join-Path $env:LOCALAPPDATA 'agentops-backups'" in SRC
    pre = _func("Preflight")
    assert pre.index("backup") < pre.index("Host-Listening $HostPort")


def test_start_never_uses_the_original_container_for_anything_but_reads():
    for line in CODE.splitlines():
        if "$OriginalName" in line:
            assert not re.search(r"'(run|stop|rm|exec|start|restart)'", line), line


def test_pg_container_must_report_an_existing_data_directory():
    start = _func("Start-Demo")
    assert "Skipping initialization" in start
    assert start.index("Wait-Pg") < start.index("Skipping initialization") < start.index(", $ViewerName")


# ---------------------------------------------------------------------------
# 6  Isolation flags
# ---------------------------------------------------------------------------


def _run_blocks() -> list[str]:
    """The two docker run argument lists: PostgreSQL first, then the viewer."""
    start = _func("Start-Demo")
    marker = "Invoke-Docker @('run'"
    first = start.index(marker)
    second = start.index(marker, first + 1)
    assert start.count(marker) == 2
    pg = start[first:second]
    viewer = start[second:start.index("$ViewerImage)", second) + len("$ViewerImage)")]
    return [pg, viewer]


def test_exactly_two_docker_run_commands():
    assert len(_run_blocks()) == 2


def test_postgres_run_command():
    pg = [b for b in _run_blocks() if "$PgName" in b.split("'--restart'")[0]][0]
    for needle in ("'--name', $PgName", "'--network', $NetworkName", "'--restart', 'no'",
                   "'-p', $PublishMapping", "($VolumeName + ':' + $DataDir)", "$script:ImageId"):
        assert needle in pg, needle
    assert "--read-only" not in pg  # PostgreSQL must write its data directory


def test_viewer_run_command_is_hardened_and_shares_the_pg_namespace():
    viewer = [b for b in _run_blocks() if "$ViewerName" in b.split("'--restart'")[0]][0]
    for needle in ("'--name', $ViewerName", "('container:' + $PgName)", "'--restart', 'no'",
                   "'--read-only'", "'--tmpfs', '/tmp'", "'--cap-drop', 'ALL'",
                   "'--security-opt', 'no-new-privileges:true'",
                   "TRACE_VIEWER_DB_HOST=127.0.0.1", "TRACE_VIEWER_DB_PORT=5432",
                   "TRACE_VIEWER_DB_NAME=agentops", "TRACE_VIEWER_DB_USER=trace_viewer_reader",
                   "$ViewerImage"):
        assert needle in viewer, needle
    assert "'-p'" not in viewer and "-v'" not in viewer
    assert "'--user'" not in viewer  # runs as the image's non-root USER


def test_viewer_image_user_is_non_root():
    dockerfile = _read(os.path.join(_DOCKER_DIR, "Dockerfile"))
    assert re.search(r"^USER viewer$", dockerfile, re.M)


def test_no_restart_policy_other_than_no_and_no_privileged_flags():
    assert re.findall(r"'--restart', '([a-z-]+)'", CODE) == ["no", "no"]
    for forbidden in ("--privileged", "unless-stopped", "'always'", "on-failure"):
        assert forbidden not in CODE


# ---------------------------------------------------------------------------
# 7  Password handling
# ---------------------------------------------------------------------------


def test_password_is_generated_passed_by_name_and_never_printed():
    start = _func("Start-Demo")
    assert "$env:TRACE_VIEWER_DB_PASSWORD = [guid]::NewGuid().ToString('N')" in start
    assert "'-e', 'TRACE_VIEWER_DB_PASSWORD'," in start             # name only, no value
    assert "TRACE_VIEWER_DB_PASSWORD=" not in CODE                  # never a literal assignment in args
    assert "Remove-Item Env:\\TRACE_VIEWER_DB_PASSWORD" in start    # removed in finally
    assert "finally" in start
    for line in CODE.splitlines():
        if re.search(r"\b(Say|Write-Host)\b", line):
            assert "PASSWORD" not in line and "$env:" not in line.replace("$env:LOCALAPPDATA", ""), line


def test_no_password_or_secret_literals_anywhere():
    assert not re.search(r"(?i)(password|secret|token)\s*=\s*['\"][^'\"]+['\"]", CODE)
    assert "demo-unused" not in SRC
    assert ".env" not in CODE.replace("$env:", "")


# ---------------------------------------------------------------------------
# 8  Ownership, stop order, failure cleanup
# ---------------------------------------------------------------------------


def test_removers_require_exact_name_and_label_before_removal():
    rc = _func("Remove-OwnedContainer")
    assert rc.index("Container-Owned") < rc.index("'stop'") < rc.index("'rm'")
    assert "refusing to remove" in rc
    rn = _func("Remove-OwnedNetwork")
    assert rn.index("Network-Owned") < rn.index("'rm'")
    assert "refusing to remove network" in rn


def test_ownership_helpers_compare_the_exact_label():
    for name in ("Container-Owned", "Network-Owned"):
        body = _func(name)
        assert "$prop.Value -eq $LabelValue" in body and "$LabelKey" in body


def test_stop_order_viewer_then_postgres_then_network_with_bounded_stops():
    stop = _func("Stop-Demo")
    assert stop.index("Remove-OwnedContainer $ViewerName") < stop.index("Remove-OwnedContainer $PgName") < stop.index("Remove-OwnedNetwork $NetworkName")
    assert "$PgStopSeconds   = 30" in SRC and "$ViewerStopSeconds = 10" in SRC
    assert "'-t', \"$StopSeconds\"" in _func("Remove-OwnedContainer")


def test_stop_refuses_ambiguous_ownership_and_unrelated_dependents():
    stop = _func("Stop-Demo")
    for needle in ("ownership is ambiguous", "unexpected labelled container(s)", "unexpected labelled network(s)",
                   "an unrelated container depends on the demo", "unrelated container attached to the demo network",
                   "exists without the label"):
        assert needle in stop, needle
    deps = _func("Unrelated-Dependents")
    assert "'container:' + $pgId" in deps and "$mode -eq $NetworkName" in deps


def test_stop_verifies_original_container_volume_and_free_port():
    stop = _func("Stop-Demo")
    for needle in ("demo resources remain", "Host-Listening $HostPort", "if ($state -ne 'exited')",
                   "'volume', 'inspect', $VolumeName", "images, backups and evidence files untouched"):
        assert needle in stop, needle


def test_stop_never_removes_volumes_images_backups_or_evidence():
    for forbidden in ("Remove-Item", "'volume', 'rm'", "'rmi'", "Remove-Item -Recurse"):
        assert forbidden not in _func("Stop-Demo")
    assert CODE.count("Remove-Item") == 1  # only the environment variable in Start-Demo
    assert "Remove-Item Env:" in CODE


def _finally_block(body: str) -> str:
    return body[body.index("} finally {"):]


def _catch_block(body: str) -> str:
    return body[body.index("} catch {"):body.index("} finally {")]


def test_cleanup_runs_in_finally_so_that_interruption_is_covered():
    start = _func("Start-Demo")
    assert "$succeeded = $false" in start and "$succeeded = $true" in start
    # the flag is set only after every step, including the API verification, has passed
    assert start.index("Verify-Api") < start.index("$succeeded = $true")
    assert start.index("$succeeded = $false") < start.index("try {")
    tail = _finally_block(start)
    assert "if (-not $succeeded)" in tail and "Cleanup-Created" in tail
    # one cleanup call site only, and not in the catch (a Ctrl+C never reaches a catch)
    assert start.count("Cleanup-Created") == 1
    assert "Cleanup-Created" not in _catch_block(start)
    # the catch reports and rethrows; it does not swallow, retry or restart
    catch = _catch_block(start)
    assert re.search(r"^\s*throw\s*$", catch, re.M)
    assert "Start-Demo" not in catch and "'run'" not in catch and "Preflight" not in catch
    # the throwaway password is removed whether or not the start succeeded
    assert "Remove-Item Env:\\TRACE_VIEWER_DB_PASSWORD" in tail
    assert tail.index("Remove-Item Env:") < tail.index("Cleanup-Created")
    assert start.index("$env:TRACE_VIEWER_DB_PASSWORD = ") > start.index("try {")


def test_interrupted_start_cleanup_keeps_exact_name_and_label_verification():
    cleanup = _func("Cleanup-Created")
    # only entries registered by this invocation, never a discovery by name or label
    assert "$script:Created" in cleanup and "Demo-Resources" not in cleanup
    assert "Container-Exists" not in cleanup and "'ps'" not in cleanup
    # removal goes through the owned removers, which require the exact label first
    assert "Remove-OwnedContainer" in cleanup and "Remove-OwnedNetwork" in cleanup
    assert "'rm'" not in cleanup and "'stop'" not in cleanup
    removers = _func("Remove-OwnedContainer")
    assert removers.index("Container-Owned") < removers.index("'rm'")
    assert "refusing to remove" in removers
    # a cleanup problem is reported and cannot abort the remaining cleanup
    assert re.search(r"try \{.*?\} catch \{\s*Say", cleanup, re.S)
    # no retry loop around the start
    assert "Start-Demo" not in _func("Cleanup-Created")
    assert re.findall(r"\bStart-Demo\b", CODE) == ["Start-Demo", "Start-Demo"]  # definition + one call


def test_script_documents_what_cleanup_cannot_guarantee():
    comment = SRC[SRC.index("# Failure / interruption cleanup"):SRC.index("function Cleanup-Created")]
    for needle in ("best effort", "CANNOT be guaranteed", "killed", "power loss", "Docker Desktop",
                   "second interrupt", "status", "stop"):
        assert needle in comment, needle


def test_failure_cleanup_only_removes_what_this_run_created():
    start = _func("Start-Demo")
    assert "start did not complete; removing only the resources this invocation created" in start
    assert "Cleanup-Created" in start
    cleanup = _func("Cleanup-Created")
    assert "$script:Created" in cleanup and "Remove-OwnedContainer" in cleanup and "Remove-OwnedNetwork" in cleanup
    # resources are registered only after Docker created them
    assert start.index("Created.Add(@('network'") > start.index("'network', 'create'")
    assert start.count("$script:Created.Add") == 3
    # preflight (which also refuses pre-existing resources) runs before anything is registered
    assert start.index("Preflight") < start.index("$script:Created.Add")
    assert "Demo-Resources" not in cleanup  # cleanup never discovers other resources


def test_waits_are_bounded():
    assert "$PgReadyTries    = 30" in SRC and "$ViewerReadyTries = 20" in SRC
    assert re.search(r"for \(\$i = 1; \$i -le \$PgReadyTries; \$i\+\+\)", _func("Wait-Pg"))
    assert re.search(r"for \(\$i = 1; \$i -le \$ViewerReadyTries; \$i\+\+\)", _func("Wait-Viewer"))
    assert "while" not in CODE.lower().replace("-while", "") or "while ($true)" not in CODE
    assert "-TimeoutSec 10" in CODE


def test_api_verification_covers_the_four_urls():
    api = _func("Verify-Api")
    for needle in ("'/api/health'", "'/api/traces?limit=1'", "'/api/anomalies?limit=1'", "Get-Url '/'"):
        assert needle in api, needle


# ---------------------------------------------------------------------------
# 9  status is read-only
# ---------------------------------------------------------------------------


def test_status_is_read_only():
    status = _func("Show-Status")
    for verb in ("'stop'", "'rm'", "'run'", "'create'", "'exec'", "Remove-", "Start-Process", "Stop-"):
        assert verb not in status, verb
    for needle in ("Demo-Resources", "viewer health", "original container", "database volume"):
        assert needle in status, needle


# ---------------------------------------------------------------------------
# 10  Nothing outside the demo is touched
# ---------------------------------------------------------------------------


def test_container_names_given_to_mutating_commands_are_only_demo_resources():
    # every 'stop' / 'rm' target is the parameter of the owned removers, every 'run'
    # creates a demo-named resource, and 'exec' targets the demo PostgreSQL container
    for func in ("Remove-OwnedContainer",):
        body = _func(func)
        assert "@('stop', '-t', \"$StopSeconds\", $Name)" in body and "@('rm', $Name)" in body
    callers = re.findall(r"Remove-OwnedContainer\s+(\$\w+)", CODE)
    assert set(callers) <= {"$PgName", "$ViewerName", "$name"}
    for caller in re.findall(r"Remove-OwnedNetwork\s+(\$\w+)", CODE):
        assert caller in {"$NetworkName", "$name"}


def test_script_writes_nothing_to_disk():
    for forbidden in ("Set-Content", "Out-File", "Add-Content", "New-Item", "Copy-Item", "Move-Item", "> $", ">>"):
        assert forbidden not in CODE


# ---------------------------------------------------------------------------
# 11  README
# ---------------------------------------------------------------------------


def test_readme_documents_the_script_and_the_read_write_volume():
    readme = _read(_README)
    assert "legacy-demo.ps1" in readme
    for action in ("start", "status", "stop"):
        assert f"legacy-demo.ps1 {action}" in readme
    lowered = " ".join(readme.lower().split())
    assert "read-write" in lowered
    assert "byte-for-byte" in lowered
    assert "not a security model" in lowered or "not a production" in lowered


def _readme_flat() -> str:
    return " ".join(_read(_README).split())


def test_readme_documents_both_live_tests_and_ties_the_current_script_to_b3j_152():
    flat = _readme_flat()
    lowered = flat.lower()
    # both live tests, each tied to its own script version
    assert "b3j-149b" in lowered and "b3j-152" in lowered
    assert re.search(r"\*{0,2}B3J-149B\*{0,2} ran the original script version \(hash prefix `8016cc23`\)", flat)
    assert re.search(r"\*{0,2}B3J-152\*{0,2} ran the \*\*current\*\* script version \(hash prefix `db6eb55a`\)", flat)
    # the current script on disk is the version the README ties to B3J-152
    import hashlib
    current = hashlib.sha256(SRC.encode("utf-8")).hexdigest()  # line endings already normalised to LF
    assert current.startswith("db6eb55a"), (
        "legacy-demo.ps1 changed: update the README's hash prefix and live-verification status")
    assert "8016cc23" in lowered and "db6eb55a" in lowered
    # two cycles, one machine, same normal lifecycle, no -Open
    assert "two successful live cycles on one machine" in lowered
    assert "each a single `start`, then `status`" in lowered
    assert "without `-open`" in lowered
    assert "same machine" in lowered and "normal, uninterrupted lifecycle" in lowered
    # execution policy: 149B used the one-process option, 152 used the plain command
    assert "ran the original script version" in lowered and "-executionpolicy bypass` option" in lowered
    assert "the live test in b3j-149b used the one-process option" in lowered
    assert "b3j-152 used the plain command without it and succeeded" in lowered
    assert "does not show the plain command works under a stricter policy" in lowered
    # what is NOT live-verified, stated explicitly and never represented as verified
    assert "not live-verified" in lowered
    for item in ("failure cleanup", "interruption (ctrl+c) cleanup", "the refusal paths", "the `-open` switch",
                 "repeated runs"):
        assert item in lowered, item
    assert "have only been checked statically, not live" in lowered
    assert "only been exercised on the success path, where it removes nothing" in lowered
    assert "each live run still needs its own authorization" in lowered
    assert "failure cleanup, ctrl+c interruption, the refusal paths and repeated runs have **not** been live-verified" in lowered
    # no stale or over-claiming wording
    for stale in ("has not been run", "not yet been run", "checked statically only", "first live run needs",
                  "one successful live cycle", "that is one run on one machine", "the unchanged script ran"):
        assert stale not in lowered, stale
    for overclaim in ("interruption cleanup was live", "ctrl+c cleanup was live", "failure cleanup was live",
                      "cleanup was tested live", "live-verified cleanup on failure"):
        assert overclaim not in lowered, overclaim


def test_readme_verified_demo_table_lists_both_live_tests():
    readme = _read(_README)
    rows = [line for line in readme.splitlines() if line.startswith("| B3J-")]
    by_id = {line.split("|")[1].strip(): line for line in rows}
    assert {"B3J-149B", "B3J-151", "B3J-152"} <= set(by_id)
    assert "8016cc23" in by_id["B3J-149B"] and "original" in by_id["B3J-149B"].lower()
    assert "-ExecutionPolicy Bypass" in by_id["B3J-149B"]
    assert "db6eb55a" in by_id["B3J-152"] and "current" in by_id["B3J-152"].lower()
    assert "plain `powershell -NoProfile -File` command" in by_id["B3J-152"]
    assert "-ExecutionPolicy" not in by_id["B3J-152"].replace("no execution-policy option", "")
    # B3J-151 is described as a code and documentation change, not as a live test
    assert "live" not in by_id["B3J-151"].lower().replace("live-verified", "")


def test_readme_documents_a_one_process_execution_policy_option_only():
    readme = _read(_README)
    lowered = " ".join(readme.lower().split())
    assert "powershell -noprofile -executionpolicy bypass -file docker/trace-viewer/legacy-demo.ps1 start" in lowered
    assert "that one process only" in lowered and "does not change any stored policy" in lowered
    assert "do not change the machine-wide or the per-user execution policy" in lowered
    assert "group policy" in lowered
    # nothing in the README or the script changes the user's PowerShell configuration
    for forbidden in ("set-executionpolicy", "-scope localmachine", "-scope currentuser", "unblock-file"):
        assert forbidden not in lowered, forbidden
        assert forbidden not in SRC.lower(), forbidden
    # every documented invocation uses -NoProfile, and the script's own hint matches
    for action in ("start", "status", "stop"):
        assert f"powershell -NoProfile -File docker/trace-viewer/legacy-demo.ps1 {action}" in readme
    assert "-ExecutionPolicy Bypass: it applies to that one process only" in SRC


def test_readme_documents_interruption_limits_and_recovery():
    readme = _read(_README)
    lowered = " ".join(readme.lower().split())
    assert "if a start is interrupted" in lowered
    assert "best effort and cannot be guaranteed" in lowered
    for scenario in ("process is killed", "loses power or crashes", "docker desktop stops or restarts",
                     "second time while the cleanup itself is running",
                     "before the script has recorded it as its own"):
        assert scenario in lowered, scenario
    assert "run `status` and then `stop`" in lowered
    assert "never retried automatically" in lowered
    assert "only the resources that this invocation itself created" in lowered


# ---------------------------------------------------------------------------
# 12  PowerShell 5.1 syntax (parse only, never executed)
# ---------------------------------------------------------------------------


def _powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_powershell_parser_accepts_the_script():
    # The path travels in the environment, so it is never interpreted as code.
    command = (
        "$e = $null; $t = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile($env:LEGACY_DEMO_PARSE_TARGET, [ref]$t, [ref]$e); "
        "if (@($e).Count -gt 0) { $e | ForEach-Object { $_.Message }; exit 1 } else { exit 0 }"
    )
    env = dict(os.environ, LEGACY_DEMO_PARSE_TARGET=os.path.abspath(_SCRIPT))
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
