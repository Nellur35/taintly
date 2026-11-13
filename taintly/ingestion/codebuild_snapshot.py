"""Read one CodeBuild project's configured buildspec from a local Git object."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path

from taintly.parsers.structural import EventKind, walk_workflow

PROJECT_ARN = re.compile(r"arn:aws:codebuild:[a-z0-9-]+:[0-9]{12}:project/[A-Za-z0-9_-]+")
_GITHUB_URL = re.compile(r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?")
_COMMIT_ID = re.compile(r"[0-9a-f]{40}")
_YAML_PATH = re.compile(r"(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\.ya?ml")
_MAX_BYTES = 1024 * 1024


class SnapshotError(ValueError):
    """Required evidence is absent, ambiguous or outside the supported profile."""


@dataclass(frozen=True)
class BoundBuildspec:
    repository: str
    commit: str
    path: str
    sha256: str
    content: str
    analysis_limit: str | None = None


def _git(root: Path, *args: str) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update(GIT_ALLOW_PROTOCOL="", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    try:
        # Fixed read-only Git commands, with no shell or transports.
        return subprocess.run(  # nosec B603 B607
            ["git", "--no-replace-objects", "-C", str(root), *args],
            env=env,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError("Required local Git evidence is unavailable") from exc


def _github_identity(url: object) -> str:
    match = _GITHUB_URL.fullmatch(url) if isinstance(url, str) else None
    if match is None or match[2] in {".", ".."}:
        raise SnapshotError("Expected a literal HTTPS GitHub.com repository URL")
    return f"{match[1]}/{match[2]}".lower()


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("Project snapshot contains duplicate JSON keys")
        result[key] = value
    return result


def _project(snapshot: Path, project_arn: str) -> dict[str, object]:
    try:
        with snapshot.open("rb") as handle:
            raw = handle.read(_MAX_BYTES + 1)
    except OSError as exc:
        raise SnapshotError("Project snapshot could not be read") from exc
    if len(raw) > _MAX_BYTES:
        raise SnapshotError("Project snapshot exceeds the input size limit")
    try:
        response = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SnapshotError("Project snapshot is not a supported UTF-8 JSON response") from exc
    if not isinstance(response, dict):
        raise SnapshotError("Expected a complete BatchGetProjects response")
    projects = response.get("projects")
    missing = response.get("projectsNotFound", [])
    if not isinstance(projects, list) or not all(isinstance(row, dict) for row in projects):
        raise SnapshotError("Project list is missing or malformed")
    if not isinstance(missing, list) or not all(isinstance(name, str) for name in missing):
        raise SnapshotError("Project not-found list is malformed")
    if project_arn in missing or project_arn.rsplit("/", 1)[1] in missing:
        raise SnapshotError("Requested project appears in projectsNotFound")
    matches = [row for row in projects if row.get("arn") == project_arn]
    if len(matches) != 1:
        raise SnapshotError("Expected exactly one row for the requested project ARN")
    project: dict[str, object] = matches[0]
    return project


def bind_buildspec(snapshot: Path, project_arn: str, root: Path, origin: str) -> BoundBuildspec:
    """Bind a full API snapshot to a trusted checkout, without reading its working files."""
    if not PROJECT_ARN.fullmatch(project_arn):
        raise SnapshotError("A full AWS CodeBuild project ARN is required")
    project = _project(snapshot, project_arn)
    source = project.get("source")
    if not isinstance(source, dict) or source.get("type") != "GITHUB":
        raise SnapshotError("The project has no supported primary GitHub source")
    identity = _github_identity(origin)
    if _github_identity(source.get("location")) != identity:
        raise SnapshotError("Project source does not match the supplied repository identity")
    revision = project.get("sourceVersion")
    if not isinstance(revision, str) or not _COMMIT_ID.fullmatch(revision):
        raise SnapshotError("Project sourceVersion is absent or is not a full commit ID")
    path = source.get("buildspec", "")
    if path == "":
        path = "buildspec.yml"
    if (
        not isinstance(path, str)
        or not _YAML_PATH.fullmatch(path)
        or any(part.endswith(".") for part in path.split("/"))
    ):
        raise SnapshotError("Buildspec selector is outside the literal repository-path profile")
    environment = project.get("environment")
    unsupported_environment = (
        not isinstance(environment, dict)
        or environment.get("type") not in ("LINUX_CONTAINER", "ARM_CONTAINER")
        or environment.get("environmentVariables") != []
        or "fleet" in environment
        or project.get("secondarySources", []) != []
    )

    if not root.is_dir():
        raise SnapshotError("The supplied local checkout is unavailable")
    top = _git(root, "rev-parse", "--show-toplevel").rstrip(b"\r\n")
    if Path(os.fsdecode(top)).resolve() != root:
        raise SnapshotError("The supplied checkout is not the Git repository root")
    remotes = _git(root, "config", "--local", "--no-includes", "--get-all", "remote.origin.url")
    try:
        urls = remotes.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise SnapshotError("Local checkout origin is unreadable") from exc
    if len(urls) != 1 or _github_identity(urls[0]) != identity:
        raise SnapshotError("Local checkout origin does not match the supplied repository identity")
    if _git(
        root, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"
    ).strip() != (revision.encode("ascii")):
        raise SnapshotError("Configured sourceVersion does not identify the exact local Git commit")
    entry = _git(root, "ls-tree", "--full-tree", "-z", revision, "--", path)
    blob = re.fullmatch(
        rb"(?:100644|100755) blob ([0-9a-f]{40})\t" + re.escape(path.encode("ascii")) + rb"\0",
        entry,
    )
    if blob is None:
        raise SnapshotError(
            "Selected buildspec is unavailable as a regular blob at the configured commit"
        )
    oid = blob[1].decode("ascii")
    if int(_git(root, "cat-file", "-s", oid)) > _MAX_BYTES:
        raise SnapshotError("Selected buildspec exceeds the input size limit")
    data = _git(root, "cat-file", "blob", oid)
    try:
        content = data.decode("utf-8")
    except UnicodeError as exc:
        raise SnapshotError("Selected buildspec is not UTF-8") from exc

    limit: str | None
    if unsupported_environment:
        limit = "Project execution context is outside the supported Linux profile"
    else:
        limit = _buildspec_structure_limit(path, content)
    return BoundBuildspec(
        identity, revision, path, hashlib.sha256(data).hexdigest(), content, limit
    )


def _buildspec_structure_limit(path: str, content: str) -> str | None:
    events = list(walk_workflow(path, content=content, include_keys=True))
    if any(event.kind in (EventKind.ERROR, EventKind.CUTOFF) for event in events):
        return "Selected buildspec has unsupported or malformed YAML structure"
    versions = [
        event.value
        for event in events
        if event.kind is EventKind.LEAF_SCALAR and event.path == ("version",)
    ]
    phase_keys = [
        event for event in events if event.kind is EventKind.MAP_KEY and event.path == ("phases",)
    ]
    version_keys = [
        event for event in events if event.kind is EventKind.MAP_KEY and event.path == ("version",)
    ]
    if (
        versions not in (["0.1"], ["0.2"])
        or len(version_keys) != 1
        or len(phase_keys) != 1
        or not any(
            event.kind is EventKind.MAP_KEY and len(event.path) == 2 and event.path[0] == "phases"
            for event in events
        )
    ):
        return "Selected blob has no supported native buildspec structure"
    return None
