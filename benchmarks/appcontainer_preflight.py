"""
benchmarks/appcontainer_preflight.py

Read-only planning tool for the future AppContainer staging environment of
the isolation probe (see calibrate_generator.py).  It never changes the
host: it has no profile, ACL, firewall, registry-write, copy, directory,
process or network operation at all.

Two parts:
    inventory  structured, injectable collectors for future read-only host
               checks.  The real collectors are gated by
               HOST_INVENTORY_ENABLED (False here) and refuse before
               touching anything; tests inject fake host data.
    planner    pure functions that turn an inventory (real or fake) into a
               dry-run staging plan: layout, required runtime and source
               files, native extensions, .pth handling, ACL intentions, a
               manifest format bound to the Git HEAD, findings, and a
               recommendation that is NO-GO unless every prerequisite has
               been independently verified.
    identity   pure helpers for a future staged execution: Git object
               format and blob ids (SHA-1/SHA-256), canonical JSON and
               manifest digests, relative-path validation, runtime
               manifests, the authorization-context schema with binding
               checks against independently obtained values, and the
               prelaunch failure model.  A digest identifies bytes; it
               never authenticates them, and no helper grants
               authorization.

The planner reports, and does not fix, one incompatibility of the committed
harness: a staged copy has no .git directory, and calibrate_generator reads
the HEAD from <script>/../.git (authorize / authorize_probe ->
_read_git_head).  Fabricating Git metadata is not an option, so a staged
probe cannot start until the harness learns another way to verify the
authoritative HEAD.

Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

HERE: Path = Path(__file__).resolve().parent
REPO: Path = HERE.parent

#: Real host inspection is not reachable until separately authorized.
HOST_INVENTORY_ENABLED: bool = False

PROFILE_NAME: str = "agentops.calibration.condition-a"
SCHEMA_PLAN: str = "agentops-appcontainer-staging-plan/1"
SCHEMA_MANIFEST: str = "agentops-appcontainer-staging-manifest/1"
STAGING_DIR_NAME: str = "agentops-probe"
SUPPORTED_ARCHITECTURES: frozenset[str] = frozenset({"AMD64"})

COLLECTORS: tuple[str, ...] = (
    "windows", "python", "venv", "onedrive", "repository", "staging_parent", "services",
    "firewall_profiles", "appcontainer_profiles", "loopback_exemptions", "privileges",
    "agentops_baseline",
)

#: Files of the Python installation the staged interpreter needs (relative
#: to the installation directory; {xy} is the version without the dot).
PYTHON_RUNTIME_FILES: tuple[str, ...] = (
    "python.exe", "python{xy}.dll", "python3.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    "Lib/os.py", "Lib/site.py", "DLLs/_socket.pyd", "DLLs/_ctypes.pyd", "DLLs/select.pyd",
    "DLLs/libffi-8.dll",
)
#: Top-level packages the probe imports (directly) from site-packages, and
#: the native extension each must carry (None: pure Python).
REQUIRED_PACKAGES: Mapping[str, Optional[str]] = {
    "pydantic": None, "pydantic_core": "pydantic_core/_pydantic_core", "langgraph": None,
    "opentelemetry": None,
}
#: Repository files the staged harness imports or reads.
REPOSITORY_ANCHORS: tuple[str, ...] = (
    "benchmarks/calibrate_generator.py", "benchmarks/metrics.py",
    "benchmarks/run_benchmark.py", "benchmarks/ladder.json",
    "workload-generator/workload_generator/__init__.py",
    "workload-generator/workload_generator/plan.py",
    "workload-generator/workload_generator/scenarios.py",
    "demo-app/graph.py", "demo-app/state.py",
)
REPOSITORY_PATTERNS: tuple[str, ...] = (
    r"benchmarks/(calibrate_generator|metrics|run_benchmark)\.py",
    r"benchmarks/ladder\.json",
    r"workload-generator/workload_generator/[^/]+\.py",
    r"demo-app/(?!main\.py)(?:[^/]+/)*[^/]+\.py",
)
#: Windows file attributes of cloud placeholders that are not local.
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
PLACEHOLDER_ATTRIBUTES = (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN
                          | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)

#: Prerequisites that must be independently verified before GO.
PREREQUISITES: tuple[str, ...] = (
    "host_prep_tool_reviewed", "inventory_independently_verified",
    "harness_staging_compatibility_resolved", "git_content_verified_against_head",
    "rollback_procedure_reviewed",
)

VERIFICATION_CHECKS: tuple[str, ...] = (
    "profile exists: CreateAppContainerProfile result AND NetworkIsolationEnumAppContainers "
    "entry (same SID, name, display name, description); registry mapping as corroboration",
    "profile SID equals the derived SID and the enumerated SID",
    "zero capabilities: enumeration entry empty AND the probe child's TokenCapabilities empty",
    "no loopback exemption: SID absent from NetworkIsolationGetAppContainerConfig before and "
    "after the probe",
    "MpsSvc and BFE Running/Automatic immediately before and after the probe",
    "staged files: manifest sizes, SHA-256 and Git blob ids equal the committed files at HEAD",
    "ACL grants exist only for the profile SID and only on the staging sub-roots",
    "AgentOps baseline (containers, health, listening ports) identical before and after",
)
HOST_SIDE_EFFECTS: tuple[str, ...] = (
    "a per-user AppContainer profile (registry mapping and Packages folder)",
    "a new staging directory tree (copies only) with ACEs for the profile SID",
    "one loopback test listener and one control connection during the probe",
    "file-system reads of the Python installation, site-packages and repository files",
)
ROLLBACK_PREREQUISITES: tuple[str, ...] = (
    "ACL snapshot of the staging tree taken before any grant, with its SHA-256",
    "profile creation record (SID, display name, description, UTC) to recognise our profile",
    "loopback exemption listing and AgentOps baseline captured before any change",
    "reviewed revoke/delete procedure; never delete a profile that is not ours",
    "evidence archive location outside the staging tree",
)
UNRESOLVED_ASSUMPTIONS: tuple[str, ...] = (
    "CreateAppContainerProfile/DeleteAppContainerProfile work without elevation",
    "NetworkIsolationEnumAppContainers lists API-created profiles with their capabilities",
    "AppContainer loopback denial is enforced while MpsSvc runs and surfaces as WSAEACCES",
    "a copied CPython installation is relocatable and starts inside an AppContainer",
    "the AppContainer can traverse to the staging directory under %LOCALAPPDATA%",
    "DLL dependencies of native extensions (not analysed here) are inside the copy",
    "working-tree files equal the committed blobs (core.autocrlf may differ)",
)

_HEAD_RE = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class PreflightError(Exception):
    """The plan cannot be produced.  The message is the evidence."""


class InventoryDisabled(PreflightError):
    """Real host inspection was requested while it is disabled."""


@dataclass(frozen=True)
class Finding:
    severity: str           # "blocker" | "risk" | "info"
    area: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "area": self.area, "message": self.message}


def _blocker(area: str, message: str) -> Finding:
    return Finding("blocker", area, message)


def _risk(area: str, message: str) -> Finding:
    return Finding("risk", area, message)


def _info(area: str, message: str) -> Finding:
    return Finding("info", area, message)


# ---------------------------------------------------------------------------
# Inventory collection (gated real source; injectable)
# ---------------------------------------------------------------------------

def _require_inventory() -> None:
    if not HOST_INVENTORY_ENABLED:
        raise InventoryDisabled("real host inventory is not enabled (HOST_INVENTORY_ENABLED is "
                                "False); nothing was inspected")


NOT_IMPLEMENTED = {"collected": False,
                   "reason": "real collection needs a separately reviewed read-only "
                             "implementation (Win32 service/firewall APIs or external tools)"}


class RealHostSource:
    """
    Future read-only collectors.  Every call checks HOST_INVENTORY_ENABLED
    first.  Only file-system and registry *reads* are implemented; the
    collectors that would need Win32 service/firewall APIs, an external
    tool or Docker report themselves as not collected.  There is no write,
    create, delete, ACL, firewall, process or network operation here.
    """

    def __init__(self, *, repo: Path = REPO, environ: Optional[Mapping[str, str]] = None) -> None:
        self.repo = Path(repo)
        self.environ = dict(os.environ if environ is None else environ)

    def collect(self, name: str) -> Mapping[str, Any]:
        _require_inventory()
        if name not in COLLECTORS:
            raise PreflightError(f"unknown collector {name!r}")
        return getattr(self, f"_collect_{name}")()

    @staticmethod
    def _registry_value(root: str, key: str, name: str) -> Any:
        import winreg
        hive = getattr(winreg, root)
        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ) as handle:
            return winreg.QueryValueEx(handle, name)[0]

    def _collect_windows(self) -> Mapping[str, Any]:
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        values = {n: self._registry_value("HKEY_LOCAL_MACHINE", key, n)
                  for n in ("EditionID", "CurrentBuild", "UBR")}
        return {"collected": True, "edition": values["EditionID"],
                "build": f"{values['CurrentBuild']}.{values['UBR']}",
                "architecture": self.environ.get("PROCESSOR_ARCHITECTURE"),
                "pointer_bits": struct.calcsize("P") * 8}

    def _collect_python(self) -> Mapping[str, Any]:
        base = Path(getattr(sys, "_base_executable", None) or sys.executable)
        root = base.parent
        files = []
        for relative in _python_runtime_files(sys.version_info[:2]):
            if (root / relative).is_file():
                files.append(relative)
        return {"collected": True, "executable": str(base), "home": str(root),
                "version": list(sys.version_info[:3]), "files": files,
                "sha256": {name: _sha256_file(root / name)
                           for name in ("python.exe", f"python{_xy(sys.version_info[:2])}.dll")
                           if (root / name).is_file()}}

    def _collect_venv(self) -> Mapping[str, Any]:
        import sysconfig
        site = Path(sysconfig.get_paths()["purelib"])
        top = sorted(p.name for p in site.iterdir()) if site.is_dir() else []
        native = sorted(str(p.relative_to(site)).replace("\\", "/") for p in site.rglob("*")
                        if p.suffix.lower() in (".pyd", ".dll"))
        pth = [{"name": p.name, "lines": p.read_text(encoding="utf-8", errors="replace")
                .splitlines()} for p in site.glob("*.pth")]
        return {"collected": True, "site_packages": str(site), "top_level": top,
                "native": native, "pth": pth}

    def _collect_onedrive(self) -> Mapping[str, Any]:
        roots = [v for k, v in self.environ.items() if k.upper().startswith("ONEDRIVE") and v]
        repo = os.path.normcase(str(self.repo))
        placeholders = []
        for path in (p for p in self.repo.rglob("*") if p.is_file()):
            attributes = getattr(os.stat(path), "st_file_attributes", 0)
            if attributes & PLACEHOLDER_ATTRIBUTES:
                placeholders.append(str(path.relative_to(self.repo)).replace("\\", "/"))
        return {"collected": True, "roots": roots, "placeholders": placeholders,
                "repo_under_onedrive": any(repo.startswith(os.path.normcase(r)) for r in roots)}

    def _collect_repository(self) -> Mapping[str, Any]:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import calibrate_generator as harness
        files = sorted(str(p.relative_to(self.repo)).replace("\\", "/")
                       for top in ("benchmarks", "workload-generator", "demo-app")
                       for p in (self.repo / top).rglob("*") if p.is_file())
        return {"collected": True, "root": str(self.repo),
                "head": harness._read_git_head(self.repo),
                "git_kind": "directory" if (self.repo / ".git").is_dir() else "file",
                "files": files}

    def _collect_staging_parent(self) -> Mapping[str, Any]:
        parent = self.environ.get("LOCALAPPDATA")
        if not parent:
            return {"collected": True, "path": None, "exists": False}
        root = Path(parent) / STAGING_DIR_NAME
        return {"collected": True, "path": parent, "exists": Path(parent).is_dir(),
                "writable": os.access(parent, os.W_OK), "root_exists": root.exists()}

    def _collect_firewall_profiles(self) -> Mapping[str, Any]:
        base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        profiles = {}
        for name, key in (("domain", "DomainProfile"), ("private", "StandardProfile"),
                          ("public", "PublicProfile")):
            profiles[name] = bool(self._registry_value("HKEY_LOCAL_MACHINE", f"{base}\\{key}",
                                                       "EnableFirewall"))
        return {"collected": True, "enabled": profiles}

    def _collect_services(self) -> Mapping[str, Any]:
        return dict(NOT_IMPLEMENTED)

    def _collect_appcontainer_profiles(self) -> Mapping[str, Any]:
        return dict(NOT_IMPLEMENTED)

    def _collect_loopback_exemptions(self) -> Mapping[str, Any]:
        return dict(NOT_IMPLEMENTED)

    def _collect_privileges(self) -> Mapping[str, Any]:
        return dict(NOT_IMPLEMENTED)

    def _collect_agentops_baseline(self) -> Mapping[str, Any]:
        return dict(NOT_IMPLEMENTED)


def collect_inventory(source: Any, names: Sequence[str] = COLLECTORS) -> dict[str, Any]:
    """Every collector's data.  A collector that fails is recorded as not
    collected; a disabled real source refuses as a whole."""
    inventory: dict[str, Any] = {}
    for name in names:
        try:
            data = source.collect(name)
        except InventoryDisabled:
            raise
        except Exception as exc:  # recorded; the plan treats it as missing evidence
            data = {"collected": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
        inventory[name] = dict(data) if isinstance(data, Mapping) else {
            "collected": False, "error": "collector returned no mapping"}
    return inventory


def _sha256_file(path: Path) -> str:
    _require_inventory()
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _xy(version: Sequence[int]) -> str:
    return f"{version[0]}{version[1]}"


def _python_runtime_files(version: Sequence[int]) -> list[str]:
    return [f.format(xy=_xy(version)) for f in PYTHON_RUNTIME_FILES]


# ---------------------------------------------------------------------------
# Inventory validation (pure)
# ---------------------------------------------------------------------------

def _collected(inventory: Mapping[str, Any], name: str) -> Optional[Mapping[str, Any]]:
    data = inventory.get(name)
    if not isinstance(data, Mapping) or data.get("collected") is not True:
        return None
    return data


def inventory_findings(inventory: Mapping[str, Any], *,
                       expected_head: Optional[str]) -> list[Finding]:
    """Blockers, risks and notes from an inventory (pure)."""
    findings: list[Finding] = []
    for name in COLLECTORS:
        if _collected(inventory, name) is None:
            data = inventory.get(name) if isinstance(inventory.get(name), Mapping) else {}
            why = data.get("reason") or data.get("error") or "no data"
            findings.append(_blocker(name, f"not collected ({why})"))

    windows = _collected(inventory, "windows")
    if windows is not None:
        if windows.get("architecture") not in SUPPORTED_ARCHITECTURES \
                or windows.get("pointer_bits") != 64:
            findings.append(_blocker("windows", f"unsupported architecture "
                                                f"{windows.get('architecture')!r} / "
                                                f"{windows.get('pointer_bits')!r}-bit"))
        findings.append(_info("windows", f"{windows.get('edition')} build {windows.get('build')}"))

    python = _collected(inventory, "python")
    if python is not None:
        version = python.get("version") or []
        if len(version) < 2:
            findings.append(_blocker("python", "Python version unknown"))
        else:
            missing = sorted(set(_python_runtime_files(version)) - set(python.get("files") or []))
            for relative in missing:
                findings.append(_blocker("python", f"missing Python runtime file {relative}"))

    venv = _collected(inventory, "venv")
    if venv is not None:
        top = set(venv.get("top_level") or [])
        native = list(venv.get("native") or [])
        if not top:
            findings.append(_blocker("venv", "incomplete dependency inventory (no top-level "
                                             "packages listed)"))
        for package, extension in REQUIRED_PACKAGES.items():
            if package not in top:
                findings.append(_blocker("venv", f"required package {package} missing"))
            elif extension and not any(n.startswith(extension) and n.endswith(".pyd")
                                       for n in native):
                findings.append(_blocker("venv", f"native extension {extension}*.pyd missing"))
        for pth in venv.get("pth") or []:
            executes = any(line.lstrip().startswith("import ") for line in pth.get("lines", []))
            findings.append(_info("venv", f"{pth.get('name')}: "
                                          + ("executes code at startup; review it"
                                             if executes else "adds paths")))
        findings.append(_risk("venv", "the DLL dependencies of native extensions are not "
                                      "analysed; the whole site-packages must be copied"))

    onedrive = _collected(inventory, "onedrive")
    if onedrive is not None:
        for path in onedrive.get("placeholders") or []:
            findings.append(_blocker("onedrive", f"OneDrive placeholder (not local): {path}"))
        if onedrive.get("repo_under_onedrive"):
            findings.append(_risk("onedrive", "the repository is under OneDrive; the staging "
                                              "copy must be outside it"))

    repository = _collected(inventory, "repository")
    if repository is not None:
        head = repository.get("head")
        if not isinstance(head, str) or not _HEAD_RE.fullmatch(head):
            findings.append(_blocker("repository", "the repository HEAD is unknown"))
        elif expected_head and head != expected_head:
            findings.append(_blocker("repository", f"incorrect Git HEAD {head[:12]}, expected "
                                                   f"{expected_head[:12]}"))
        _, missing = required_repository_files(repository.get("files") or [])
        for relative in missing:
            findings.append(_blocker("repository", f"required source file missing: {relative}"))

    staging = _collected(inventory, "staging_parent")
    if staging is not None:
        if not staging.get("path") or not staging.get("exists"):
            findings.append(_blocker("staging_parent", "the staging parent (%LOCALAPPDATA%) "
                                                       "is missing or inaccessible"))
        elif staging.get("writable") is not True:
            findings.append(_blocker("staging_parent", "the staging parent is not writable"))
        if staging.get("root_exists"):
            findings.append(_blocker("staging_parent", "the staging root already exists; it "
                                                       "is never reused"))
        if onedrive is not None and staging.get("path") and any(
                os.path.normcase(str(staging["path"])).startswith(os.path.normcase(r))
                for r in onedrive.get("roots") or []):
            findings.append(_blocker("staging_parent", "the staging parent is under OneDrive"))

    services = _collected(inventory, "services")
    if services is not None:
        for name in ("MpsSvc", "BFE"):
            state = (services.get(name) or {})
            if state.get("status") != "Running" or state.get("start") != "Automatic":
                findings.append(_blocker("services", f"{name} is not Running/Automatic "
                                                     f"({state.get('status')}, "
                                                     f"{state.get('start')})"))

    firewall = _collected(inventory, "firewall_profiles")
    if firewall is not None:
        disabled = sorted(k for k, v in (firewall.get("enabled") or {}).items() if not v)
        if disabled:
            findings.append(_risk("firewall_profiles", "firewall profiles disabled: "
                                  + ", ".join(disabled) + " (AppContainer enforcement with "
                                  "disabled profiles is unverified)"))

    profiles = _collected(inventory, "appcontainer_profiles")
    if profiles is not None:
        for entry in profiles.get("profiles") or []:
            if entry.get("name") == PROFILE_NAME:
                findings.append(_blocker("appcontainer_profiles",
                                         f"a profile named {PROFILE_NAME} already exists "
                                         f"(SID {entry.get('sid')}); it is never reused or "
                                         "deleted"))

    loopback = _collected(inventory, "loopback_exemptions")
    if loopback is not None:
        exempt = list(loopback.get("sids") or [])
        names = list(loopback.get("names") or [])
        if PROFILE_NAME in names:
            findings.append(_blocker("loopback_exemptions",
                                     f"{PROFILE_NAME} has a loopback exemption"))
        if exempt:
            findings.append(_info("loopback_exemptions",
                                  f"{len(exempt)} other loopback exemption(s) exist; they "
                                  "must be identical after rollback"))

    privileges = _collected(inventory, "privileges")
    if privileges is not None:
        if privileges.get("is_admin"):
            findings.append(_risk("privileges", "running elevated; the plan expects a "
                                                "standard user"))
        if "SeChangeNotifyPrivilege" not in (privileges.get("privileges") or []):
            findings.append(_risk("privileges", "SeChangeNotifyPrivilege (traverse) absent"))
    return findings


# ---------------------------------------------------------------------------
# Staging plan (pure)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StagingLayout:
    root: str
    python: str
    repo: str
    out: str

    def as_dict(self) -> dict[str, str]:
        return {"root": self.root, "python": self.python, "repo": self.repo, "out": self.out}


def propose_layout(parent: Optional[str]) -> StagingLayout:
    """The proposed staging tree under the given parent (no file system)."""
    base = PureWindowsPath(parent or "%LOCALAPPDATA%") / STAGING_DIR_NAME
    return StagingLayout(str(base), str(base / "python"), str(base / "repo"), str(base / "out"))


def required_repository_files(listing: Iterable[str]) -> tuple[list[str], list[str]]:
    """(the repository files the staged harness needs, missing anchors)."""
    files = sorted({f.replace("\\", "/") for f in listing})
    patterns = [re.compile(p) for p in REPOSITORY_PATTERNS]
    required = [f for f in files if any(p.fullmatch(f) for p in patterns)
                and "/tests/" not in f and "__pycache__" not in f]
    missing = sorted(set(REPOSITORY_ANCHORS) - set(required))
    return required, missing


def acl_intentions(layout: StagingLayout) -> list[dict[str, str]]:
    """Intended grants: the profile SID only, staging sub-roots only."""
    principal = "<SID of " + PROFILE_NAME + ">"
    return [
        {"path": layout.root, "principal": principal, "rights": "RX",
         "inheritance": "none (this directory only)"},
        {"path": layout.python, "principal": principal, "rights": "RX", "inheritance": "OI,CI"},
        {"path": layout.repo, "principal": principal, "rights": "RX", "inheritance": "OI,CI"},
        {"path": layout.out, "principal": principal, "rights": "M", "inheritance": "OI,CI"},
    ]


#: Git object formats and their blob-id hash functions.
OBJECT_FORMATS: Mapping[str, Callable[[bytes], Any]] = {
    "sha1": hashlib.sha1, "sha256": hashlib.sha256}


def git_blob_id(data: bytes, object_format: str = "sha1") -> str:
    """The Git blob id of exact bytes: hash of b"blob <size>\\0" + data in
    the repository's object format (no filters applied)."""
    if object_format not in OBJECT_FORMATS:
        raise PreflightError(f"unknown Git object format {object_format!r}")
    if not isinstance(data, (bytes, bytearray)):
        raise PreflightError("blob data must be bytes")
    return OBJECT_FORMATS[object_format](b"blob %d\0" % len(data) + bytes(data)).hexdigest()


def build_manifest(files: Iterable[tuple[str, bytes]], *, source_head: str,
                   staged_repo: str) -> dict[str, Any]:
    """The manifest of the staged source files, from (relative path, bytes)
    pairs supplied by the caller (nothing is read here)."""
    entries = []
    for relative, data in sorted(files):
        relative = relative.replace("\\", "/")
        entries.append({"source_relative": relative,
                        "staged_path": str(PureWindowsPath(staged_repo, *relative.split("/"))),
                        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                        "git_blob_sha1": git_blob_id(data)})
    return {"schema": SCHEMA_MANIFEST, "source_head": source_head, "staged_repo": staged_repo,
            "entries": entries}


def manifest_findings(manifest: Any, *, required: Sequence[str], expected_head: Optional[str],
                      ls_tree: Optional[Mapping[str, str]]) -> list[Finding]:
    """Why a manifest does not prove that the staged files are the committed
    files at the authoritative HEAD."""
    if not isinstance(manifest, Mapping) or manifest.get("schema") != SCHEMA_MANIFEST:
        return [_blocker("manifest", "no manifest in the expected format")]
    findings: list[Finding] = []
    head = manifest.get("source_head")
    if not isinstance(head, str) or not _HEAD_RE.fullmatch(head):
        findings.append(_blocker("manifest", "the manifest has no source HEAD"))
    elif expected_head and head != expected_head:
        findings.append(_blocker("manifest", f"incorrect Git HEAD {head[:12]} in the manifest, "
                                             f"expected {expected_head[:12]}"))
    staged_repo = str(manifest.get("staged_repo") or "")
    seen: set[str] = set()
    for entry in manifest.get("entries") or []:
        relative = entry.get("source_relative") if isinstance(entry, Mapping) else None
        if not isinstance(relative, str):
            findings.append(_blocker("manifest", "an entry has no source path"))
            continue
        if relative in seen:
            findings.append(_blocker("manifest", f"duplicate entry {relative}"))
        seen.add(relative)
        if not isinstance(entry.get("size"), int) or not _HEX64.fullmatch(
                str(entry.get("sha256"))) or not re.fullmatch(r"[0-9a-f]{40}",
                                                              str(entry.get("git_blob_sha1"))):
            findings.append(_blocker("manifest", f"incomplete entry {relative}"))
        expected_path = str(PureWindowsPath(staged_repo, *relative.split("/")))
        if not staged_repo or entry.get("staged_path") != expected_path:
            findings.append(_blocker("manifest", f"{relative} is not staged at its mirrored "
                                                 "path"))
        if ls_tree is not None:
            committed = ls_tree.get(relative)
            if committed is None:
                findings.append(_blocker("manifest", f"{relative} is not tracked at HEAD"))
            elif committed != entry.get("git_blob_sha1"):
                findings.append(_blocker("manifest", f"{relative} differs from the committed "
                                                     "file"))
    for relative in sorted(set(required) - seen):
        findings.append(_blocker("manifest", f"incomplete manifest: {relative} missing"))
    if ls_tree is None:
        findings.append(_blocker("manifest", "committed content not verified (no `git ls-tree "
                                             "-r HEAD` evidence supplied)"))
    return findings


GIT_HEAD_STRATEGY: Mapping[str, Any] = {
    "authoritative_head": "read from the ORIGINAL repository's .git files by the orchestrator "
                          "outside the AppContainer (read-only, no git process)",
    "staged_content": "every staged source file's Git blob id must equal the blob recorded "
                      "for that path by `git ls-tree -r <HEAD>` (separately authorized "
                      "read-only git run outside this tool); sizes and SHA-256 recorded too",
    "no_fabrication": "the staged copy contains no .git directory and no invented Git "
                      "metadata",
    "harness_incompatibility": "calibrate_generator reads the HEAD from <script>/../.git in "
                               "authorize()/authorize_probe() (_read_git_head); a staged copy "
                               "without .git therefore refuses to start, and running the "
                               "original repository's script would need grants on the "
                               "OneDrive repository.  A reviewed harness change is required "
                               "(e.g. the child verifies a manifest bound to the HEAD that "
                               "the orchestrator verified) before a staged probe can run.",
}


def recommend(findings: Sequence[Finding], verified: Mapping[str, bool]) -> tuple[str, list[str]]:
    """GO only with no blocker and every prerequisite independently verified."""
    reasons = [f"{f.area}: {f.message}" for f in findings if f.severity == "blocker"]
    reasons += [f"prerequisite not independently verified: {p}" for p in PREREQUISITES
                if verified.get(p) is not True]
    return ("GO" if not reasons else "NO-GO"), reasons


def build_plan(inventory: Mapping[str, Any], *, expected_head: Optional[str],
               manifest: Any = None, ls_tree: Optional[Mapping[str, str]] = None,
               verified: Optional[Mapping[str, bool]] = None) -> dict[str, Any]:
    """The dry-run staging plan (pure; nothing is created or copied)."""
    findings = inventory_findings(inventory, expected_head=expected_head)
    staging = _collected(inventory, "staging_parent") or {}
    layout = propose_layout(staging.get("path"))
    repository = _collected(inventory, "repository") or {}
    required, _ = required_repository_files(repository.get("files") or [])
    python = _collected(inventory, "python") or {}
    venv = _collected(inventory, "venv") or {}
    findings += manifest_findings(manifest, required=required, expected_head=expected_head,
                                  ls_tree=ls_tree)
    findings.append(_blocker("harness", GIT_HEAD_STRATEGY["harness_incompatibility"]))
    decision, reasons = recommend(findings, verified or {})
    return {
        "schema": SCHEMA_PLAN, "tool": "appcontainer_preflight",
        "host_inventory_enabled": HOST_INVENTORY_ENABLED, "profile_name": PROFILE_NAME,
        "expected_head": expected_head,
        "staging": {
            "layout": layout.as_dict(),
            "python_runtime_files": _python_runtime_files(python.get("version") or (3, 13)),
            "site_packages": {"source": venv.get("site_packages"),
                              "destination": str(PureWindowsPath(layout.python, "Lib",
                                                                 "site-packages")),
                              "copy": "whole tree (native DLL dependencies not analysed)",
                              "pth": "processed by the staged interpreter's own site module"},
            "repository_files": required,
            "native_extensions": [n for n in venv.get("native") or []],
        },
        "manifest_format": {"schema": SCHEMA_MANIFEST,
                            "fields": ["source_relative", "staged_path", "size", "sha256",
                                       "git_blob_sha1"],
                            "binding": ["source_head", "staged_repo"]},
        "git_head_strategy": dict(GIT_HEAD_STRATEGY),
        "permissions": acl_intentions(layout),
        "verification_checks": list(VERIFICATION_CHECKS),
        "host_side_effects": list(HOST_SIDE_EFFECTS),
        "rollback_prerequisites": list(ROLLBACK_PREREQUISITES),
        "unresolved_assumptions": list(UNRESOLVED_ASSUMPTIONS),
        "findings": [f.as_dict() for f in findings],
        "recommendation": decision, "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Staged identity: pure helpers (no file system, no Git, no process)
# ---------------------------------------------------------------------------

def object_format_of(config_text: str) -> str:
    """
    The object format declared by a repository's .git/config text: "sha1"
    or "sha256".  core.repositoryformatversion 0 (or absent) means SHA-1
    and allows no objectformat extension; version 1 may declare
    extensions.objectformat.  Unknown, repeated-conflicting or malformed
    declarations are rejected.
    """
    if not isinstance(config_text, str):
        raise PreflightError("the Git config must be text")
    section: Optional[str] = None
    values: dict[tuple[str, str], list[str]] = {}
    for number, raw in enumerate(config_text.splitlines(), start=1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        header = re.fullmatch(r'\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]', line)
        if header:
            section = header.group(1).lower()
            continue
        if line.startswith("["):
            raise PreflightError(f"malformed Git config section on line {number}")
        entry = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?", line)
        if entry is None or section is None:
            raise PreflightError(f"malformed Git config line {number}")
        value = (entry.group(2) or "").strip()
        value = re.split(r"\s[#;]", value, maxsplit=1)[0].strip().strip('"')
        values.setdefault((section, entry.group(1).lower()), []).append(value)
    versions = values.get(("core", "repositoryformatversion"), ["0"])
    formats = values.get(("extensions", "objectformat"), [])
    if len(set(versions)) != 1 or versions[0] not in ("0", "1"):
        raise PreflightError(f"unsupported or conflicting repositoryformatversion {versions}")
    if len(set(f.lower() for f in formats)) > 1:
        raise PreflightError(f"conflicting extensions.objectformat {formats}")
    if not formats:
        return "sha1"
    declared = formats[0].lower()
    if versions[0] != "1":
        raise PreflightError("extensions.objectformat requires repositoryformatversion 1")
    if declared not in OBJECT_FORMATS:
        raise PreflightError(f"unknown Git object format {formats[0]!r}")
    return declared


#: Canonical JSON: UTF-8, sorted keys, separators (",", ":"), no ASCII
#: escaping, no NaN/Infinity, no floats, string keys only.
CANONICAL_SEPARATORS: tuple[str, str] = (",", ":")


def _check_canonical(value: Any, where: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise PreflightError(f"{where}: floats are not canonical")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_canonical(item, f"{where}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PreflightError(f"{where}: non-string key {key!r}")
            _check_canonical(item, f"{where}.{key}")
        return
    raise PreflightError(f"{where}: {type(value).__name__} is not canonical JSON")


def canonical_json(data: Any) -> bytes:
    """Deterministic bytes of JSON data (see CANONICAL_SEPARATORS)."""
    _check_canonical(data)
    return json.dumps(data, sort_keys=True, separators=CANONICAL_SEPARATORS,
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical manifest.  A digest only identifies bytes; it
    authenticates nothing by itself, so a manifest may not carry one."""
    if not isinstance(manifest, Mapping):
        raise PreflightError("a manifest is a JSON object")
    if any(key in manifest for key in ("digest", "sha256", "manifest_sha256")):
        raise PreflightError("a manifest must not carry its own digest")
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)]
    + ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"])
_FORBIDDEN_CHARACTERS = set('<>:"|?*\\') | {chr(c) for c in range(32)}


def validate_relative_path(path: Any) -> str:
    """A staged path relative to its root: '/'-separated, no traversal, no
    absolute/drive/UNC form, no alternate data stream, no reserved device
    name, no trailing space or dot.  Returned unchanged when valid."""
    if not isinstance(path, str) or not path:
        raise PreflightError("a relative path is a non-empty string")
    if len(path) > 240:
        raise PreflightError(f"path too long: {path[:40]!r}...")
    if "\\" in path:
        raise PreflightError(f"invalid separator in {path!r}; only '/' is allowed")
    if path.startswith("/"):
        raise PreflightError(f"absolute or UNC path {path!r}")
    if ":" in path:
        raise PreflightError(f"drive or alternate data stream in {path!r}")
    for component in path.split("/"):
        if component in ("", ".", ".."):
            raise PreflightError(f"empty, '.' or '..' component in {path!r}")
        if component[-1] in " .":
            raise PreflightError(f"trailing space or dot in {path!r}")
        if any(ch in _FORBIDDEN_CHARACTERS for ch in component):
            raise PreflightError(f"forbidden character in {path!r}")
        if component.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_NAMES:
            raise PreflightError(f"reserved Windows name in {path!r}")
    return path


def _validated_paths(paths: Iterable[Any], what: str) -> list[str]:
    """Valid, unique paths; duplicates and case-insensitive collisions are
    rejected (Windows file names are case-insensitive)."""
    seen: dict[str, str] = {}
    result = []
    for path in paths:
        valid = validate_relative_path(path)
        folded = valid.casefold()
        if folded in seen:
            kind = "duplicate" if seen[folded] == valid else "case-insensitive collision"
            raise PreflightError(f"{kind} in the {what}: {seen[folded]!r} / {valid!r}")
        seen[folded] = valid
        result.append(valid)
    return result


def _manifest_paths(manifest: Mapping[str, Any]) -> list[str]:
    entries = manifest.get("entries") if isinstance(manifest, Mapping) else None
    if not isinstance(entries, list):
        raise PreflightError("the manifest has no entry list")
    paths = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise PreflightError("a manifest entry is not an object")
        paths.append(entry.get("path", entry.get("source_relative")))
    return _validated_paths(paths, "manifest")


def unexpected_files(listing: Iterable[Any], manifest: Mapping[str, Any]) -> dict[str, list[str]]:
    """{"missing": [...], "unexpected": [...]} between a directory listing
    supplied by the caller and a manifest (no file system is read)."""
    listed = _validated_paths(listing, "listing")
    expected = _manifest_paths(manifest)
    by_fold = {p.casefold(): p for p in listed}
    expected_fold = {p.casefold(): p for p in expected}
    missing = sorted(p for f, p in expected_fold.items() if f not in by_fold)
    unexpected = sorted(p for f, p in by_fold.items() if f not in expected_fold)
    mismatched = sorted(p for f, p in by_fold.items()
                        if f in expected_fold and expected_fold[f] != p)
    return {"missing": missing, "unexpected": sorted(unexpected + mismatched)}


RUNTIME_SCHEMA: str = "agentops-appcontainer-runtime-manifest/1"
#: Files the staged runtime must contain, and files it must not contain.
RUNTIME_FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {"pyvenv.cfg", "sitecustomize.py", "usercustomize.py"})


def build_runtime_manifest(files: Iterable[tuple[str, bytes]]) -> dict[str, Any]:
    """The runtime manifest (Python installation and site-packages) from
    (relative path, bytes) pairs supplied by the caller.  Its digest is
    manifest_digest(manifest)."""
    pairs = list(files)
    paths = _validated_paths((p for p, _ in pairs), "runtime manifest")
    entries = []
    for path, (_, data) in zip(paths, pairs):
        if not isinstance(data, (bytes, bytearray)):
            raise PreflightError(f"{path}: file data must be bytes")
        entries.append({"path": path, "size": len(data),
                        "sha256": hashlib.sha256(bytes(data)).hexdigest()})
    return {"schema": RUNTIME_SCHEMA, "entries": sorted(entries, key=lambda e: e["path"])}


def runtime_manifest_problems(manifest: Any, *, version: Sequence[int]) -> list[str]:
    """Why a runtime manifest is not complete and clean; empty when it is."""
    if not isinstance(manifest, Mapping) or manifest.get("schema") != RUNTIME_SCHEMA:
        return ["not a runtime manifest"]
    try:
        paths = _manifest_paths(manifest)
    except PreflightError as exc:
        return [str(exc)]
    problems = []
    for entry in manifest["entries"]:
        if not isinstance(entry.get("size"), int) or isinstance(entry.get("size"), bool) \
                or entry["size"] < 0 or not _HEX64.fullmatch(str(entry.get("sha256"))):
            problems.append(f"incomplete runtime entry {entry.get('path')}")
    folded = {p.casefold() for p in paths}
    for required in _python_runtime_files(version):
        if required.casefold() not in folded:
            problems.append(f"missing runtime file {required}")
    for path in paths:
        if path.rsplit("/", 1)[-1].casefold() in RUNTIME_FORBIDDEN_NAMES:
            problems.append(f"forbidden runtime file {path}")
    return problems


CONTEXT_SCHEMA: str = "agentops-staged-authorization-context/1"
#: The longest an authorization context may be valid.
CONTEXT_MAX_LIFETIME_SECONDS: int = 2 * 60 * 60
CONTEXT_FIELDS: tuple[str, ...] = (
    "schema", "head", "object_format", "repository_manifest_sha256",
    "runtime_manifest_sha256", "staging_root", "interpreter_path", "interpreter_sha256",
    "run_id", "app_container_sid", "preflight_sha256", "parent", "ownership_token",
    "created_utc", "expires_utc",
)
_RUN_ID_RE = re.compile(r"probe-0[1-5]|cal-a-(0[1-9]|1[0-9]|20)")
_SID_RE = re.compile(r"S-1-15-2(-\d{1,10}){7}")
_TOKEN_RE = re.compile(r"[0-9a-f]{32}")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
_DRIVE_PATH_RE = re.compile(r"[A-Za-z]:\\[^:]*")


def _parse_utc(text: Any) -> Optional[Any]:
    from datetime import datetime
    if not isinstance(text, str) or not _UTC_RE.fullmatch(text):
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _windows_absolute(path: Any) -> Optional[PureWindowsPath]:
    if not isinstance(path, str) or not _DRIVE_PATH_RE.fullmatch(path) or path.endswith("\\"):
        return None
    parts = path[3:].split("\\")
    try:
        _validated_paths(["/".join(parts)], "path")
    except PreflightError:
        return None
    return PureWindowsPath(path)


def context_problems(context: Any, *, now: Any) -> list[str]:
    """Why an authorization context is not well-formed or not current; empty
    when it is.  A valid context authorizes nothing by itself."""
    if not isinstance(context, Mapping):
        return ["the context is not a JSON object"]
    problems = []
    missing = [f for f in CONTEXT_FIELDS if f not in context]
    extra = sorted(set(context) - set(CONTEXT_FIELDS))
    if missing:
        problems.append("missing fields: " + ", ".join(missing))
    if extra:
        problems.append("unexpected fields: " + ", ".join(extra))
    if missing:
        return problems
    try:
        canonical_json(context)
    except PreflightError as exc:
        problems.append(f"not canonical: {exc}")
    if context["schema"] != CONTEXT_SCHEMA:
        problems.append("wrong schema")
    object_format = context["object_format"]
    if object_format not in OBJECT_FORMATS:
        problems.append("unknown object format")
    else:
        length = {"sha1": 40, "sha256": 64}[object_format]
        if not isinstance(context["head"], str) or not re.fullmatch(
                rf"[0-9a-f]{{{length}}}", context["head"]):
            problems.append(f"head is not a {object_format} commit id")
    for field_name in ("repository_manifest_sha256", "runtime_manifest_sha256",
                       "interpreter_sha256", "preflight_sha256"):
        if not isinstance(context[field_name], str) or not _HEX64.fullmatch(context[field_name]):
            problems.append(f"{field_name} is not a SHA-256")
    root = _windows_absolute(context["staging_root"])
    interpreter = _windows_absolute(context["interpreter_path"])
    if root is None:
        problems.append("staging_root is not a valid absolute path")
    if interpreter is None:
        problems.append("interpreter_path is not a valid absolute path")
    elif root is not None:
        inside = str(interpreter).casefold().startswith(str(root).casefold() + "\\")
        if not inside or interpreter.name.casefold() != "python.exe":
            problems.append("interpreter_path is not a python.exe inside staging_root")
    if not isinstance(context["run_id"], str) or not _RUN_ID_RE.fullmatch(context["run_id"]):
        problems.append("run_id is not an approved form")
    if not isinstance(context["app_container_sid"], str) or not _SID_RE.fullmatch(
            context["app_container_sid"]):
        problems.append("app_container_sid is not an AppContainer SID")
    parent = context["parent"]
    if not isinstance(parent, Mapping) or set(parent) != {"pid", "creation_time"} \
            or isinstance(parent.get("pid"), bool) or not isinstance(parent.get("pid"), int) \
            or parent["pid"] <= 0 or _parse_utc(parent.get("creation_time")) is None:
        problems.append("parent identity is malformed")
    if not isinstance(context["ownership_token"], str) or not _TOKEN_RE.fullmatch(
            context["ownership_token"]):
        problems.append("ownership_token is malformed")
    created, expires = _parse_utc(context["created_utc"]), _parse_utc(context["expires_utc"])
    if created is None or expires is None:
        problems.append("created_utc/expires_utc are malformed")
    else:
        lifetime = (expires - created).total_seconds()
        if lifetime <= 0:
            problems.append("expires_utc is not after created_utc")
        elif lifetime > CONTEXT_MAX_LIFETIME_SECONDS:
            problems.append("the context lifetime exceeds the maximum")
        if now < created:
            problems.append("the context is not yet valid (created in the future)")
        if now >= expires:
            problems.append("the context has expired")
    return problems


def context_digest(context: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical context.  It identifies the bytes only; a
    context must not carry its own digest."""
    if not isinstance(context, Mapping):
        raise PreflightError("a context is a JSON object")
    if any(key in context for key in ("digest", "context_sha256")):
        raise PreflightError("a context must not carry its own digest")
    return hashlib.sha256(canonical_json(context)).hexdigest()


def verify_context_binding(context: Any, *, expected_digest: Any,
                           expected: Mapping[str, Any], now: Any) -> list[str]:
    """
    Whether a context is exactly the one bound by values obtained
    independently: the digest received over a trusted channel (not from
    the context) and every expected field (from the authorization, the
    manifests, the profile, the process).  Every expected field is
    required; a missing expectation is itself a problem.  Returns problems
    only - it never grants authorization.
    """
    problems = context_problems(context, now=now)
    if problems:
        return problems
    if not isinstance(expected_digest, str) or not _HEX64.fullmatch(expected_digest):
        return ["no independently supplied context digest"]
    if context_digest(context) != expected_digest:
        problems.append("the context does not match the independently supplied digest")
    for field_name in CONTEXT_FIELDS:
        if field_name in ("schema", "created_utc", "expires_utc"):
            continue
        if field_name not in expected:
            problems.append(f"no independent expectation for {field_name}")
            continue
        actual, wanted = context[field_name], expected[field_name]
        if field_name in ("staging_root", "interpreter_path"):
            same = isinstance(wanted, str) and actual.casefold() == wanted.casefold()
        else:
            same = actual == wanted
        if not same:
            problems.append(f"{field_name} differs from the independent expectation")
    return problems


#: Prelaunch failure categories.
FAILURE_CATEGORIES: tuple[str, ...] = (
    "manifest_invalid", "head_mismatch", "executable_mismatch", "staging_incomplete",
    "lock_failed", "dacl_invalid", "context_invalid", "preflight_stale", "sid_mismatch",
    "id_mismatch", "job_failed", "evidence_write_failed",
)
#: Every prelaunch check and the category its failure belongs to.
CHECK_CATEGORIES: Mapping[str, str] = {
    "manifest_schema": "manifest_invalid", "manifest_digest": "manifest_invalid",
    "relative_paths": "manifest_invalid", "file_hashes": "manifest_invalid",
    "runtime_digest": "manifest_invalid",
    "head": "head_mismatch",
    "executable_identity": "executable_mismatch",
    "inventory_complete": "staging_incomplete", "reparse_points": "staging_incomplete",
    "link_counts": "staging_incomplete",
    "locks_acquired": "lock_failed",
    "dacl_readback": "dacl_invalid",
    "context_binding": "context_invalid",
    "preflight_hash": "preflight_stale", "preflight_fresh": "preflight_stale",
    "services": "preflight_stale", "profile": "preflight_stale",
    "sid": "sid_mismatch",
    "run_id": "id_mismatch",
    "job_created": "job_failed",
    "evidence_durable": "evidence_write_failed",
}
#: Checks a prelaunch record must contain (evidence durability is decided
#: after the record is written, by launch_permitted()).
REQUIRED_PRELAUNCH_CHECKS: tuple[str, ...] = tuple(
    name for name in CHECK_CATEGORIES if name != "evidence_durable")
PRELAUNCH_SCHEMA: str = "agentops-staged-prelaunch/1"


@dataclass(frozen=True)
class PrelaunchCheck:
    name: str
    ok: bool
    detail: str = ""

    @property
    def category(self) -> Optional[str]:
        return None if self.ok else CHECK_CATEGORIES.get(self.name)


def build_prelaunch_record(run_id: str, checks: Sequence[PrelaunchCheck], *, utc: str,
                           context_sha256: Optional[str] = None) -> dict[str, Any]:
    """The prelaunch evidence record (pure; nothing is written).  "passed"
    only when every required check is present exactly once and passed; a
    missing check counts as failed ("not performed")."""
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise PreflightError("run_id is not an approved form")
    if _parse_utc(utc) is None:
        raise PreflightError("utc is malformed")
    rows: list[dict[str, Any]] = []
    names: list[str] = []
    for check in checks:
        if not isinstance(check, PrelaunchCheck) or check.name not in CHECK_CATEGORIES:
            raise PreflightError(f"unknown prelaunch check {getattr(check, 'name', check)!r}")
        if check.name == "evidence_durable":
            raise PreflightError("evidence durability is decided by launch_permitted()")
        if check.name in names:
            raise PreflightError(f"duplicate prelaunch check {check.name}")
        names.append(check.name)
        rows.append({"name": check.name, "ok": bool(check.ok), "category": check.category,
                     "detail": str(check.detail)[:300]})
    for name in REQUIRED_PRELAUNCH_CHECKS:
        if name not in names:
            rows.append({"name": name, "ok": False, "category": CHECK_CATEGORIES[name],
                         "detail": "not performed"})
    failed = [row for row in rows if not row["ok"]]
    return {"schema": PRELAUNCH_SCHEMA, "run_id": run_id, "utc": utc,
            "checks": rows, "result": "refused" if failed else "passed",
            "failure_category": failed[0]["category"] if failed else None,
            "failure_categories": sorted({row["category"] for row in failed}),
            "context_sha256": context_sha256}


def build_evidence_failure_record(run_id: str, *, utc: str, path: str,
                                  error: str) -> dict[str, Any]:
    """The report of a failed evidence write (for stderr/operator summary;
    the launch is refused)."""
    return {"schema": PRELAUNCH_SCHEMA, "run_id": run_id, "utc": utc, "result": "refused",
            "failure_category": "evidence_write_failed",
            "failure_categories": ["evidence_write_failed"],
            "detail": {"path": path, "error": str(error)[:300]}}


def launch_permitted(record: Any, *, evidence_durable: bool) -> tuple[bool, str]:
    """Launch only with a passed record that was durably written."""
    if not isinstance(record, Mapping) or record.get("schema") != PRELAUNCH_SCHEMA:
        return False, "manifest_invalid: no prelaunch record"
    if record.get("result") != "passed" or record.get("failure_category") is not None:
        return False, f"{record.get('failure_category')}: prelaunch checks failed"
    names = [row.get("name") for row in record.get("checks") or []]
    if sorted(names) != sorted(REQUIRED_PRELAUNCH_CHECKS) or not all(
            row.get("ok") is True for row in record.get("checks") or []):
        return False, "context_invalid: the prelaunch record is not complete"
    if evidence_durable is not True:
        return False, "evidence_write_failed: the prelaunch record is not durable"
    return True, "passed"


# ---------------------------------------------------------------------------
# Job Object lifecycle policy: pure data and state machine (no Win32, no
# timers, no processes).  It describes what a future backend must prove; it
# enables nothing.
# ---------------------------------------------------------------------------

#: The reviewed timeout/termination policy: accepted as a design only.  It
#: does not enable execution or termination anywhere.
TERMINATION_POLICY: str = "conditionally_accepted_design_only"
SUPPORTED_TERMINATION_POLICIES: tuple[str, ...] = ("conditionally_accepted_design_only",)

NEVER_EXECUTED = "definitely_never_executed"
MAY_HAVE_EXECUTED = "may_have_executed"
STATE_UNKNOWN = "state_unknown"
CONFIRMED_EXITED = "confirmed_exited"
ALIVE_AT_LAST_CHECK = "alive_at_last_check"
EXECUTION_HISTORIES: tuple[str, ...] = (NEVER_EXECUTED, MAY_HAVE_EXECUTED, STATE_UNKNOWN)
LIVENESS_STATES: tuple[str, ...] = (CONFIRMED_EXITED, ALIVE_AT_LAST_CHECK, STATE_UNKNOWN)
JOB_ASSIGNMENTS: tuple[str, ...] = ("not_created", "assigned_at_creation",
                                    "assigned_before_resume", "assignment_failed", "unknown")
#: The only successful job assignment: the child joined the job AT creation
#: (PROC_THREAD_ATTRIBUTE_JOB_LIST).  The other JOB_ASSIGNMENTS values stay
#: recordable vocabulary; "assigned_before_resume" is always refused.
ACCEPTED_JOB_ASSIGNMENT: str = "assigned_at_creation"
TERMINATION_CAUSES: tuple[str, ...] = (
    "natural_exit", "discarded_before_resume", "job_terminated_timeout",
    "job_terminated_operator", "job_closed_parent_exit", "unknown")
EXIT_EVIDENCE_KINDS: tuple[str, ...] = ("wait+exit_code", "absent_from_process_table")
LIFECYCLE_PHASES: tuple[str, ...] = (
    "not_started", "created_suspended", "job_assigned", "assignment_failed", "validated",
    "rejected", "resumed", "resume_rejected", "exited", "termination_unverified",
    "parent_lost")

#: Exit codes a future backend uses, so an exit code proves who ended it.
DISCARD_EXIT_CODE: int = 0x0BAD
TIMEOUT_EXIT_CODE: int = 0x0BAE
OPERATOR_EXIT_CODE: int = 0x0BAF
TERMINATION_EXIT_CODES: Mapping[str, int] = {
    "discarded_before_resume": DISCARD_EXIT_CODE,
    "job_terminated_timeout": TIMEOUT_EXIT_CODE,
    "job_terminated_operator": OPERATOR_EXIT_CODE,
}
#: ResumeThread's failure return value.
RESUME_FAILED_VALUE: int = 0xFFFFFFFF


def policy_enables_execution() -> bool:
    """Always False: the lifecycle policy is design data only."""
    return False


@dataclass(frozen=True)
class LifecycleState:
    """The evidence about one child.  execution_history and liveness are
    separate; neither is ever upgraded without OS evidence."""
    phase: str = "not_started"
    process_created: bool = False
    pid: Optional[int] = None
    creation_time: Optional[str] = None
    job_assignment: str = "not_created"
    job_limits_verified: bool = False
    execution_history: Optional[str] = None
    liveness: Optional[str] = None
    termination_cause: Optional[str] = None
    exit_code: Optional[int] = None
    exit_evidence: Optional[str] = None
    handles_retained: bool = False
    cleanup_errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"phase": self.phase, "process_created": self.process_created,
                "pid": self.pid, "creation_time": self.creation_time,
                "job_assignment": self.job_assignment,
                "job_limits_verified": self.job_limits_verified,
                "execution_history": self.execution_history, "liveness": self.liveness,
                "termination_cause": self.termination_cause, "exit_code": self.exit_code,
                "exit_evidence": self.exit_evidence, "handles_retained": self.handles_retained,
                "cleanup_errors": list(self.cleanup_errors)}


class LifecycleError(PreflightError):
    """An illegal transition or contradictory evidence."""


def classify_resume(previous_or_error: Any) -> str:
    """ResumeThread's result as execution history: 1 resumed and 0 already
    running mean it may have executed; above 1 it is still suspended; a
    failed call (an exception, an error text, or 0xFFFFFFFF) is unknown."""
    if isinstance(previous_or_error, (BaseException, str)):
        return STATE_UNKNOWN
    if isinstance(previous_or_error, bool) or not isinstance(previous_or_error, int):
        raise LifecycleError(f"not a ResumeThread result: {previous_or_error!r}")
    if previous_or_error == RESUME_FAILED_VALUE:
        return STATE_UNKNOWN
    if previous_or_error < 0 or previous_or_error > RESUME_FAILED_VALUE:
        raise LifecycleError(f"impossible suspend count {previous_or_error}")
    return MAY_HAVE_EXECUTED if previous_or_error in (0, 1) else NEVER_EXECUTED


def _evidence_int(evidence: Mapping[str, Any], key: str, *, optional: bool = False) -> Any:
    value = evidence.get(key)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise LifecycleError(f"evidence {key} must be an integer")
    return value


def _evidence_bool(evidence: Mapping[str, Any], key: str) -> bool:
    value = evidence.get(key)
    if not isinstance(value, bool):
        raise LifecycleError(f"evidence {key} must be true or false")
    return value


def _same_process(state: LifecycleState, evidence: Mapping[str, Any]) -> None:
    if evidence.get("pid") != state.pid or evidence.get("creation_time") != state.creation_time:
        raise LifecycleError("the evidence is about another process (PID or creation time "
                             "differs)")


def _require_phase(state: LifecycleState, event: str, phases: Sequence[str]) -> None:
    if state.phase not in phases:
        raise LifecycleError(f"{event} is not allowed in phase {state.phase}")


def _add_error(state: LifecycleState, message: str) -> tuple[str, ...]:
    return state.cleanup_errors + (message,)


def _require_assigned_at_creation(state: LifecycleState, event: str) -> None:
    """Membership, validation and resume all need a child that joined a
    verified job at creation; nothing else is ever upgraded to that."""
    if state.job_assignment != ACCEPTED_JOB_ASSIGNMENT or state.job_limits_verified is not True:
        raise LifecycleError(f"{event} needs a child assigned to a verified job at creation "
                             f"(job_assignment {state.job_assignment!r}); assignment after "
                             "creation is refused")


#: Phases in which the child was not (validly) resumed yet.
_BEFORE_RESUME = ("created_suspended", "job_assigned", "assignment_failed", "validated",
                  "rejected", "resume_rejected")
#: Phases from which a termination may be requested (once; an unverified
#: termination is never retried - it goes to recovery inspection).
_TERMINABLE_PHASES = _BEFORE_RESUME + ("resumed",)


def lifecycle_transition(state: LifecycleState, event: str,
                         evidence: Optional[Mapping[str, Any]] = None) -> LifecycleState:
    """
    The next state for one event with its OS evidence (pure).  Illegal
    transitions and contradictory evidence raise LifecycleError.  A
    termination counts as confirmed only with a signalled wait and the
    expected exit code; an API success alone leaves the liveness unknown.
    """
    if not isinstance(state, LifecycleState):
        raise LifecycleError("not a LifecycleState")
    evidence = dict(evidence or {})

    if event == "created":
        _require_phase(state, event, ("not_started",))
        pid = _evidence_int(evidence, "pid")
        creation = evidence.get("creation_time")
        if pid <= 0 or _parse_utc(creation) is None:
            raise LifecycleError("created needs a positive PID and a UTC creation time")
        if _evidence_bool(evidence, "job_limits_verified") is not True:
            raise LifecycleError("a child may only be created after the job limits are "
                                 "verified")
        assignment = evidence.get("job_assignment")
        if not isinstance(assignment, str) or assignment != ACCEPTED_JOB_ASSIGNMENT:
            raise LifecycleError(f"created needs job_assignment {ACCEPTED_JOB_ASSIGNMENT} (the "
                                 "child joins the job at creation); assignment pending or "
                                 "after creation is refused")
        return replace(state, phase="created_suspended", process_created=True, pid=pid,
                       creation_time=creation, job_assignment=assignment,
                       job_limits_verified=True, execution_history=NEVER_EXECUTED,
                       liveness=ALIVE_AT_LAST_CHECK, handles_retained=True)

    if event == "job_assigned":
        _require_phase(state, event, ("created_suspended",))
        _same_process(state, evidence)
        if _evidence_bool(evidence, "in_job") is not True:
            raise LifecycleError("job_assigned needs in_job true; use assignment_failed")
        _require_assigned_at_creation(state, event)
        problems = job_membership_problems(evidence, expected_pid=state.pid,
                                           expected_creation_time=state.creation_time)
        if problems:
            raise LifecycleError("job membership is not verified: " + "; ".join(problems))
        return replace(state, phase="job_assigned")

    if event == "assignment_failed":
        _require_phase(state, event, ("created_suspended",))
        _same_process(state, evidence)
        return replace(state, phase="assignment_failed", job_assignment="assignment_failed",
                       cleanup_errors=_add_error(state, "job assignment failed: "
                                                 + str(evidence.get("reason", ""))[:200]))

    if event == "validated":
        _require_phase(state, event, ("job_assigned",))
        _same_process(state, evidence)
        _require_assigned_at_creation(state, event)
        ok = _evidence_bool(evidence, "token_ok") and _evidence_bool(evidence, "image_ok")
        return replace(state, phase="validated" if ok else "rejected")

    if event == "resume_result":
        _require_phase(state, event, ("validated",))
        _same_process(state, evidence)
        _require_assigned_at_creation(state, event)
        if _evidence_bool(evidence, "intent_durable") is not True:
            raise LifecycleError("no resume without durable resume-intent evidence")
        has_error = evidence.get("error") is not None
        has_previous = evidence.get("previous") is not None
        if has_error == has_previous:
            raise LifecycleError("resume_result needs exactly one of previous or error")
        result = evidence["error"] if has_error else _evidence_int(evidence, "previous")
        history = classify_resume(str(result) if has_error else result)
        resumed = not has_error and result == 1
        return replace(state, phase="resumed" if resumed else "resume_rejected",
                       execution_history=history)

    if event == "wait_result":
        _require_phase(state, event, ("resumed",))
        _same_process(state, evidence)
        signaled = _evidence_bool(evidence, "signaled")
        exit_code = _evidence_int(evidence, "exit_code", optional=True)
        if signaled and exit_code is None:
            raise LifecycleError("a signalled wait needs the exit code")
        if not signaled and exit_code is not None:
            raise LifecycleError("an exit code without a signalled wait is contradictory")
        if not signaled:
            return replace(state, liveness=ALIVE_AT_LAST_CHECK)
        return replace(state, phase="exited", liveness=CONFIRMED_EXITED,
                       termination_cause="natural_exit", exit_code=exit_code,
                       exit_evidence="wait+exit_code", handles_retained=False)

    if event == "terminate_result":
        _require_phase(state, event, _TERMINABLE_PHASES)
        _same_process(state, evidence)
        cause = evidence.get("cause")
        if cause not in TERMINATION_EXIT_CODES:
            raise LifecycleError(f"unknown termination cause {cause!r}")
        if cause == "discarded_before_resume" and state.phase not in _BEFORE_RESUME:
            raise LifecycleError("a discard is only possible before a valid resume")
        if cause != "discarded_before_resume" and state.phase not in (
                "resumed", "resume_rejected"):
            raise LifecycleError(f"{cause} needs a resumed (or resume-rejected) child")
        api_ok = _evidence_bool(evidence, "api_ok")
        signaled = _evidence_bool(evidence, "signaled")
        exit_code = _evidence_int(evidence, "exit_code", optional=True)
        if signaled and exit_code is None:
            raise LifecycleError("a signalled wait needs the exit code")
        if not signaled and exit_code is not None:
            raise LifecycleError("an exit code without a signalled wait is contradictory")
        if not signaled:
            note = ("termination requested but exit not verified" if api_ok
                    else "termination call failed")
            return replace(state, phase="termination_unverified", liveness=STATE_UNKNOWN,
                           handles_retained=True, cleanup_errors=_add_error(state, note))
        expected = TERMINATION_EXIT_CODES[cause]
        if exit_code != expected:
            history = (STATE_UNKNOWN if state.execution_history == NEVER_EXECUTED
                       else state.execution_history)
            return replace(state, phase="exited", liveness=CONFIRMED_EXITED,
                           termination_cause="unknown", exit_code=exit_code,
                           exit_evidence="wait+exit_code", execution_history=history,
                           handles_retained=True,
                           cleanup_errors=_add_error(state, f"exit code {exit_code} is not "
                                                            f"the {cause} code {expected}"))
        return replace(state, phase="exited", liveness=CONFIRMED_EXITED, termination_cause=cause,
                       exit_code=exit_code, exit_evidence="wait+exit_code",
                       handles_retained=False)

    if event == "parent_lost":
        if not state.process_created or state.phase in ("exited", "parent_lost"):
            raise LifecycleError("parent_lost needs a created child that has not exited")
        return replace(state, phase="parent_lost", liveness=STATE_UNKNOWN,
                       termination_cause="job_closed_parent_exit", handles_retained=False,
                       cleanup_errors=_add_error(state, "parent lost; recovery inspection "
                                                        "required"))

    if event == "recovery_inspection":
        _require_phase(state, event, ("parent_lost", "termination_unverified"))
        if evidence.get("pid") != state.pid:
            raise LifecycleError("the inspection is about another PID")
        found = _evidence_bool(evidence, "found")
        if not found:
            return replace(state, liveness=CONFIRMED_EXITED,
                           exit_evidence="absent_from_process_table", exit_code=None)
        creation_match = _evidence_bool(evidence, "creation_match")
        if not creation_match:                      # the PID now belongs to another process
            return replace(state, liveness=CONFIRMED_EXITED,
                           exit_evidence="absent_from_process_table", exit_code=None)
        signaled = evidence.get("signaled")
        exit_code = _evidence_int(evidence, "exit_code", optional=True)
        if signaled is True and exit_code is not None:
            return replace(state, liveness=CONFIRMED_EXITED, exit_evidence="wait+exit_code",
                           exit_code=exit_code)
        if signaled is False and exit_code is None:
            return replace(state, liveness=ALIVE_AT_LAST_CHECK,
                           cleanup_errors=_add_error(state, "child still alive at recovery "
                                                            "inspection"))
        return replace(state, liveness=STATE_UNKNOWN,
                       cleanup_errors=_add_error(state, "inconclusive recovery inspection"))

    raise LifecycleError(f"unknown lifecycle event {event!r}")


#: Upper bounds that keep any schedule finite.
TIMEOUT_BOUNDS: Mapping[str, float] = {
    "deadline_s": 3600.0, "grace_s": 600.0, "terminate_wait_s": 60.0,
    "observe_interval_s": 30.0, "observe_timeout_s": 30.0,
}


def timeout_schedule(deadline_s: Any = 180, grace_s: Any = 60, terminate_wait_s: Any = 5,
                     observe_interval_s: Any = 2, observe_timeout_s: Any = 5, *,
                     policy: str = TERMINATION_POLICY,
                     exit_verification: bool = True) -> dict[str, Any]:
    """
    The bounded timeout plan (a plan, not a timer): deadline, evidence,
    liveness inspection and operator notice, a bounded grace period, then
    durable terminate intent, termination through the job, and a required
    exit verification.  It never permits indefinite waiting.
    """
    values = {"deadline_s": deadline_s, "grace_s": grace_s,
              "terminate_wait_s": terminate_wait_s, "observe_interval_s": observe_interval_s,
              "observe_timeout_s": observe_timeout_s}
    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or value != value or value in (float("inf"), float("-inf")):
            raise LifecycleError(f"{name} must be a finite number")
        if value <= 0:
            raise LifecycleError(f"{name} must be positive")
        if value > TIMEOUT_BOUNDS[name]:
            raise LifecycleError(f"{name} exceeds its bound {TIMEOUT_BOUNDS[name]}")
    if observe_timeout_s > deadline_s or observe_interval_s > deadline_s:
        raise LifecycleError("observation must fit inside the deadline")
    if policy not in SUPPORTED_TERMINATION_POLICIES:
        raise LifecycleError(f"unsupported termination policy {policy!r}")
    if exit_verification is not True:
        raise LifecycleError("exit verification is required")
    hard = deadline_s + grace_s
    max_wall = hard + terminate_wait_s + observe_interval_s + observe_timeout_s
    actions = [
        {"at_s": 0, "action": "resume (only after durable resume-intent evidence)"},
        {"at_s": 0, "action": f"observe every {observe_interval_s} s (each look at most "
                              f"{observe_timeout_s} s); a natural exit ends the schedule"},
        {"at_s": deadline_s, "action": "record durable timeout evidence"},
        {"at_s": deadline_s, "action": "inspect liveness (wait 0 + exit code + one "
                                       "observation)"},
        {"at_s": deadline_s, "action": "notify the operator"},
        {"at_s": deadline_s, "action": f"bounded grace observation for {grace_s} s"},
        {"at_s": hard, "action": "record durable terminate-intent evidence"},
        {"at_s": hard, "action": f"terminate through the job with exit code "
                                 f"{TIMEOUT_EXIT_CODE:#x}"},
        {"at_s": hard, "action": f"verify the exit within {terminate_wait_s} s (signalled "
                                 f"wait AND exit code {TIMEOUT_EXIT_CODE:#x}); otherwise "
                                 "liveness state_unknown, handles retained"},
        {"at_s": hard, "action": "final inspection, staged-tree re-verification, complete "
                                 "evidence; ownership retained"},
    ]
    return {"policy": policy, "plan_only": True,
            "enables_execution": policy_enables_execution(),
            "deadline_s": deadline_s, "grace_s": grace_s, "hard_deadline_s": hard,
            "max_wall_s": max_wall, "actions": actions,
            "evidence_checkpoints": ["timeout", "terminate_intent", "terminate_result",
                                     "final_inspection", "complete"],
            "exit_verification": {"required": True, "signalled_wait": True,
                                  "exit_code": TIMEOUT_EXIT_CODE,
                                  "within_s": terminate_wait_s}}


#: JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags values (documented).
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

JOB_LIMIT_POLICY: Mapping[str, Any] = {
    "required_flags": (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                       | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION),
    "prohibited_flags": JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    "active_process_limit": 1,
    "job_handle_inheritable": False,
    "assignment_verified_before_resume": True,
}


_MALFORMED_FLAGS = "limit_flags missing or malformed"


def job_configuration_problems(readback: Any) -> list[str]:
    """Why a job's configuration (limit_flags, active_process_limit,
    job_handle_inheritable) does not match JOB_LIMIT_POLICY; empty when it
    does.  Membership is not configuration (job_membership_problems)."""
    if not isinstance(readback, Mapping):
        return ["no job read-back"]
    flags = readback.get("limit_flags")
    if isinstance(flags, bool) or not isinstance(flags, int) or flags < 0:
        return [_MALFORMED_FLAGS]
    problems = []
    required, prohibited = JOB_LIMIT_POLICY["required_flags"], JOB_LIMIT_POLICY["prohibited_flags"]
    if flags & required != required:
        problems.append(f"required limit flags missing: {required & ~flags:#x}")
    if flags & prohibited:
        problems.append(f"breakaway flags present: {flags & prohibited:#x}")
    if flags & ~(required | prohibited):
        problems.append(f"unexpected limit flags: {flags & ~(required | prohibited):#x}")
    limit = readback.get("active_process_limit")
    if limit != JOB_LIMIT_POLICY["active_process_limit"] or isinstance(limit, bool):
        problems.append(f"active process limit is {limit!r}, not 1")
    if readback.get("job_handle_inheritable") is not JOB_LIMIT_POLICY["job_handle_inheritable"]:
        problems.append("the job handle is (or may be) inheritable")
    return problems


#: Every field the membership evidence must carry; nothing is defaulted.
JOB_MEMBERSHIP_FIELDS: tuple[str, ...] = (
    "job_assignment", "in_job", "pid", "creation_time", "active_processes",
    "total_processes", "member_pids")


def _exact_count(evidence: Mapping[str, Any], key: str, what: str) -> Optional[str]:
    value = evidence[key]
    if isinstance(value, bool) or not isinstance(value, int):
        return f"{key} is malformed ({value!r})"
    if value != 1:
        return f"{value} {what}, not 1"
    return None


def job_membership_problems(evidence: Any, *, expected_pid: Any,
                            expected_creation_time: Any) -> list[str]:
    """Why the job-verification evidence does not prove that exactly the
    expected child - and never any other process - is in the job it joined
    at creation; empty when it does.  Missing fields are reported, never
    defaulted."""
    if not isinstance(evidence, Mapping):
        return ["no membership evidence"]
    missing = [key for key in JOB_MEMBERSHIP_FIELDS if key not in evidence]
    if missing:
        return ["membership evidence missing: " + ", ".join(missing)]
    problems = []
    if isinstance(expected_pid, bool) or not isinstance(expected_pid, int) or expected_pid <= 0 \
            or _parse_utc(expected_creation_time) is None:
        problems.append("no valid expected child identity")
    assignment = evidence["job_assignment"]
    if not isinstance(assignment, str) or assignment not in JOB_ASSIGNMENTS:
        problems.append(f"job_assignment is malformed ({assignment!r})")
    elif assignment == "assigned_before_resume":
        problems.append("assignment after creation (assigned_before_resume) is refused")
    elif assignment != ACCEPTED_JOB_ASSIGNMENT:
        problems.append(f"job_assignment is {assignment}, not {ACCEPTED_JOB_ASSIGNMENT}")
    in_job = evidence["in_job"]
    if not isinstance(in_job, bool):
        problems.append(f"in_job is malformed ({in_job!r})")
    elif not in_job:
        problems.append("the child is not in the job")
    pid = evidence["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid != expected_pid:
        problems.append(f"the PID {pid!r} is not the expected child's")
    if not isinstance(evidence["creation_time"], str) \
            or evidence["creation_time"] != expected_creation_time:
        problems.append("the creation time is not the expected child's")
    for key, what in (("active_processes", "active processes"),
                      ("total_processes", "processes have been in the job")):
        problem = _exact_count(evidence, key, what)
        if problem:
            problems.append(problem)
    members = evidence["member_pids"]
    if not isinstance(members, (list, tuple)) or any(
            isinstance(m, bool) or not isinstance(m, int) for m in members):
        problems.append(f"member_pids is malformed ({members!r})")
    elif list(members) != [expected_pid]:
        problems.append(f"the job members are {list(members)}, not [{expected_pid!r}]")
    return problems


def job_limits_problems(readback: Any) -> list[str]:
    """Backward-compatible check: the configuration plus the legacy
    in_job_before_resume flag.  New code checks configuration
    (job_configuration_problems) and membership (job_membership_problems)
    separately."""
    if not isinstance(readback, Mapping):
        return ["no job read-back"]
    problems = job_configuration_problems(readback)
    if problems == [_MALFORMED_FLAGS]:
        return problems
    if readback.get("in_job_before_resume") is not True:
        problems.append("job membership was not verified before resume")
    return problems


#: Durable evidence stages, in order.  The termination stage is optional.
LIFECYCLE_STAGES: tuple[str, ...] = (
    "prelaunch", "job_configured", "process_created", "job_verified_and_validated",
    "resume_intent", "resume_result", "timeout_or_termination", "final_inspection",
    "complete",
)
OPTIONAL_STAGES: frozenset[str] = frozenset({"timeout_or_termination"})


def next_stage_allowed(durable_stages: Sequence[str], evidence_failed: bool) -> dict[str, Any]:
    """
    What may happen next given the stages already durable.  The stages must
    be an in-order prefix (the optional termination stage may be skipped).
    No launch before the job is durable, no resume without durable
    resume intent, nothing new after an evidence failure - but a child
    that exists is still contained (discard before resume, or bounded
    termination once resume may have happened).
    """
    if not isinstance(evidence_failed, bool):
        raise LifecycleError("evidence_failed must be true or false")
    stages = list(durable_stages)
    if len(set(stages)) != len(stages) or any(s not in LIFECYCLE_STAGES for s in stages):
        raise LifecycleError("unknown or repeated stage")
    expected = [s for s in LIFECYCLE_STAGES if s in stages]
    if stages != expected:
        raise LifecycleError("stages are out of order")
    mandatory = [s for s in LIFECYCLE_STAGES if s not in OPTIONAL_STAGES]
    position = len([s for s in stages if s not in OPTIONAL_STAGES])
    if [s for s in stages if s not in OPTIONAL_STAGES] != mandatory[:position]:
        raise LifecycleError("a mandatory stage was skipped")
    if "timeout_or_termination" in stages and "resume_result" not in stages:
        raise LifecycleError("termination evidence needs a resume result")
    done = set(stages)
    remaining = [s for s in mandatory if s not in done]
    if evidence_failed:
        if "complete" in done:
            containment = "none"
            allowed = []
        elif "resume_intent" in done:
            containment = "bounded_termination"
            allowed = [s for s in ("timeout_or_termination", "final_inspection") if s not in done]
        elif "job_configured" in done:
            containment = "discard_if_created"
            allowed = ["final_inspection"] if "final_inspection" not in done else []
        else:
            containment = "none"
            allowed = []
        return {"allowed": allowed, "may_launch": False, "may_resume": False,
                "containment": containment, "series_blocked": True}
    following = remaining[:1]
    if following == ["final_inspection"] and "timeout_or_termination" not in done:
        following = ["timeout_or_termination", "final_inspection"]
    return {"allowed": following,
            "may_launch": following == ["process_created"],
            "may_resume": following == ["resume_result"],
            "containment": "none", "series_blocked": False}


#: The reviewed failure matrix (immutable).  action_class distinguishes a
#: prelaunch refusal, a discard before resume, possible execution, a
#: termination requested or verified, unknown liveness and incomplete
#: cleanup.  "requires_os_evidence" means confirmed_exited only with a
#: signalled wait and the expected exit code (or absence by PID+creation).
ACTION_CLASSES: tuple[str, ...] = (
    "prelaunch_refusal", "discard_before_resume", "possible_execution",
    "termination_requested", "termination_verified", "unknown_liveness",
    "cleanup_incomplete",
)


def _action(action_class: str, containment: str, history: Optional[str],
            liveness: str) -> Mapping[str, Any]:
    return MappingProxyType({
        "action_class": action_class, "containment": containment,
        "execution_history": history, "liveness": liveness, "ownership": "retained",
        "series_blocked": True})


FAILURE_ACTIONS: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "create_job_failed": _action("prelaunch_refusal", "none", None, "not_applicable"),
    "set_job_information_failed": _action("prelaunch_refusal", "none", None,
                                          "not_applicable"),
    "job_readback_mismatch": _action("prelaunch_refusal", "none", None, "not_applicable"),
    "inheritable_job_handle": _action("prelaunch_refusal", "none", None, "not_applicable"),
    "nested_job_incompatible": _action("prelaunch_refusal", "none", None, "not_applicable"),
    "assignment_failed": _action("discard_before_resume", "discard", NEVER_EXECUTED,
                                 "requires_os_evidence"),
    "not_in_job": _action("discard_before_resume", "discard", NEVER_EXECUTED,
                          "requires_os_evidence"),
    "validation_failed": _action("discard_before_resume", "discard", NEVER_EXECUTED,
                                 "requires_os_evidence"),
    "evidence_failure_before_resume": _action("discard_before_resume", "discard",
                                              NEVER_EXECUTED, "requires_os_evidence"),
    "resume_above_one": _action("discard_before_resume", "discard", NEVER_EXECUTED,
                                "requires_os_evidence"),
    "resume_api_failed": _action("possible_execution", "bounded_termination", STATE_UNKNOWN,
                                 "requires_os_evidence"),
    "resume_previous_zero": _action("possible_execution", "bounded_termination",
                                    MAY_HAVE_EXECUTED, "requires_os_evidence"),
    "evidence_failure_after_resume": _action("possible_execution", "bounded_termination",
                                             MAY_HAVE_EXECUTED, "requires_os_evidence"),
    "timeout_live_child": _action("termination_requested", "bounded_termination",
                                  MAY_HAVE_EXECUTED, "requires_os_evidence"),
    "termination_verified": _action("termination_verified", "none", MAY_HAVE_EXECUTED,
                                    CONFIRMED_EXITED),
    "termination_unverified": _action("unknown_liveness", "recovery_inspection",
                                      MAY_HAVE_EXECUTED, STATE_UNKNOWN),
    "parent_crash": _action("unknown_liveness", "recovery_inspection", "unchanged",
                            STATE_UNKNOWN),
    "parent_forced_termination": _action("unknown_liveness", "recovery_inspection",
                                         "unchanged", STATE_UNKNOWN),
    "interrupted_cleanup": _action("cleanup_incomplete", "recovery_inspection", "unchanged",
                                   STATE_UNKNOWN),
    # Classification only: none of these authorizes termination, discard, retry or recovery.
    "creation_failed": _action("unknown_liveness", "recovery_inspection", "unchanged",
                               STATE_UNKNOWN),
    "creation_no_child": _action("prelaunch_refusal", "none", None, "not_applicable"),
    "retention_failed": _action("unknown_liveness", "recovery_inspection", "unchanged",
                                STATE_UNKNOWN),
})


# ---------------------------------------------------------------------------
# Entry point (prints a plan; writes nothing)
# ---------------------------------------------------------------------------

def _load_json(path: Optional[str]) -> Any:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PreflightError(f"cannot read {path}: {type(exc).__name__}") from None


def main(argv: Optional[Sequence[str]] = None, *, stdout: Any = None,
         source_factory: Callable[[], Any] = RealHostSource) -> int:
    out = sys.stdout if stdout is None else stdout
    parser = argparse.ArgumentParser(prog="appcontainer_preflight",
                                     description="Dry-run AppContainer staging plan "
                                                 "(read-only; never changes the host).")
    parser.add_argument("--inventory-json", default=None,
                        help="a previously collected or reviewed inventory (JSON)")
    parser.add_argument("--manifest-json", default=None)
    parser.add_argument("--ls-tree-json", default=None,
                        help="{path: blob id} from `git ls-tree -r <HEAD>`")
    parser.add_argument("--expected-head", default=None)
    parser.add_argument("--collect", action="store_true",
                        help="collect the inventory from this host (disabled)")
    args = parser.parse_args(argv)
    try:
        if args.collect:
            inventory = collect_inventory(source_factory())
        else:
            inventory = _load_json(args.inventory_json) or {}
        plan = build_plan(inventory, expected_head=args.expected_head,
                          manifest=_load_json(args.manifest_json),
                          ls_tree=_load_json(args.ls_tree_json))
    except PreflightError as exc:
        sys.stderr.write(f"appcontainer_preflight: error: {exc}\n")
        return 2
    out.write(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
