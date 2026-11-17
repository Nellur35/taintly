"""Corroborate a CodeBuild-managed S3 ZIP and one source-bound archive member."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
import zlib
from email.utils import parsedate_to_datetime
from math import ceil, floor
from pathlib import Path
from typing import Any

from taintly.ingestion.codebuild_checkout import unambiguous_checkout_events
from taintly.ingestion.codebuild_deploy import _owned_record, _phase_window, _record
from taintly.ingestion.codebuild_snapshot import (
    BUILD_ID,
    SnapshotError,
    _buildspec_structure_limit,
    _github_identity,
    _read_capture,
    _require_git_revision,
)
from taintly.ingestion.codebuild_start import _blob, _need, _sha
from taintly.parsers.structural import EventKind

_REGION = r"[a-z]{2}-[a-z0-9-]+-[0-9]"
_BUILD_ARN = re.compile(rf"arn:aws:codebuild:({_REGION}):[0-9]{{12}}:build/({BUILD_ID.pattern})")
_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_PATH = rf"{_SEGMENT}(?:/{_SEGMENT})*"
_BUCKET = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
_SHA256 = re.compile(r"[a-f0-9]{64}")
_ZIP_GLOB = re.compile(r"[A-Za-z0-9_.-]*\*\.zip")
_PR_REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+")
_ARCHIVE_LIMIT = 3_000_000
_MEMBER_LIMIT = 131_072
_SCOPE = (
    "Trusted saved AWS and GitHub observations. The S3 receipt identifies the retrieved "
    "object and one PR-bound member. The exact build-to-object link requires independent "
    "evidence for that object. The effective upload principal, policy and later use remain "
    "unverified."
)
_Row = dict[str, Any]


def _map(value: object, label: str) -> _Row:
    if not isinstance(value, dict):
        raise SnapshotError(f"Expected the saved {label} record")
    return value


def _matches(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SnapshotError(f"Expected a supported {label}")
    return value


def _source_identity(cap: _Row, build: _Row, root: Path, origin: str) -> tuple[str, _Row, str]:
    pr = _map(cap.get("pr"), "GitHub PR")
    identity = _github_identity(origin)
    source = _map(build.get("source"), "CodeBuild source")
    repo = _matches(pr.get("repository"), _PR_REPO, "PR target repository")
    number = pr.get("number")
    _need(
        type(number) is int
        and 0 < number < 10**10
        and repo.lower() == identity
        and source.get("type") == "GITHUB"
        and _github_identity(source.get("location")) == identity
        and build.get("sourceVersion") == f"pr/{number}"
        and _sha(pr.get("head"))
        and _sha(pr.get("base"))
        and pr["head"] == build.get("resolvedSourceVersion")
        and pr["head"] != pr["base"],
        "The PR, repository or exact CodeBuild revision does not match",
    )
    _matches(pr.get("fork"), _PR_REPO, "PR source repository")
    _require_git_revision(root, identity, pr["head"], "PR head")
    _require_git_revision(root, identity, pr["base"], "PR base")
    inline = source.get("buildspec")
    _need(
        isinstance(inline, str) and "\n" in inline and len(inline) <= 32768,
        "The build does not contain a bounded inline buildspec",
    )
    return identity, pr, source["buildspec"]


def _observe_plan(inline: str, logs: _Row, build: _Row, filename: str) -> dict[str, object]:
    issue = _buildspec_structure_limit("buildspec.yml", inline, run=True)
    _need(issue is None, issue or "")
    events = unambiguous_checkout_events("buildspec.yml", inline)
    leaves = {event.path: event for event in events if event.kind is EventKind.LEAF_SCALAR}
    version = leaves.get(("version",))
    _need(version and version.value == "0.2", "Expected an unambiguous version 0.2 buildspec")
    command = [
        event
        for path, event in leaves.items()
        if path[:3] == ("phases", "build", "commands")
        and len(path) == 4
        and type(path[3]) is int
        and event.value == "make dist-src"
    ]
    globs = [
        event
        for path, event in leaves.items()
        if path[:2] == ("artifacts", "files")
        and len(path) == 3
        and type(path[2]) is int
        and isinstance(event.value, str)
        and _ZIP_GLOB.fullmatch(event.value)
        and filename.startswith(event.value[:-5])
    ]
    keys = {
        event.path[1]
        for event in events
        if event.kind is EventKind.MAP_KEY and len(event.path) == 2 and event.path[0] == "artifacts"
    }
    _need(
        len(command) == len(globs) == 1 and keys == {"files"},
        "The buildspec lacks the supported build command and unique root ZIP selector",
    )
    sources, rows = logs.get("selection"), logs.get("rows")
    _need(
        isinstance(sources, list) and len(sources) == 1 and isinstance(rows, list),
        "Saved phase records are unavailable",
    )
    selected, _ = _record(
        logs["selection"][0], r"YAML location is /codebuild/readonly/buildspec\.yml"
    )
    masks = (
        r"Running command make dist-src",
        r"Phase complete: BUILD State: SUCCEEDED",
        "Expanding " + re.escape(str(globs[0].value)),
        r"Phase complete: UPLOAD_ARTIFACTS State: SUCCEEDED",
    )
    times = []
    for pattern in masks:
        matches = [
            r
            for r in logs["rows"]
            if isinstance(r, str) and re.fullmatch(r"\[Container\] [0-9/ :.]+ " + pattern, r)
        ]
        _need(
            len(matches) == 1, "The saved log lacks a unique command, selector or completed phase"
        )
        when, _ = _record(matches[0], pattern)
        times.append(when)
    source_start, source_end = _phase_window(build, "DOWNLOAD_SOURCE")
    build_start, build_end = _phase_window(build, "BUILD")
    upload_start, upload_end = _phase_window(build, "UPLOAD_ARTIFACTS")
    _need(
        source_start
        <= selected
        <= source_end
        <= build_start
        <= times[0]
        < times[1]
        <= build_end
        <= upload_start
        <= times[2]
        < times[3]
        <= upload_end,
        "Saved buildspec, command and upload records are outside their owning phase order",
    )
    return {
        "kind": "provider-inline",
        "sha256": hashlib.sha256(inline.encode()).hexdigest(),
        "command": "make dist-src",
        "command_line": command[0].line,
        "artifact_selector": globs[0].value,
        "artifact_selector_line": globs[0].line,
    }


def _object(
    receipt: _Row, parent: Path, build_arn: str, region: str, build: _Row
) -> tuple[bytes, str, str, str, bool]:
    obs = _map(receipt.get("object"), "S3 response")
    headers = _map(obs.get("headers"), "S3 headers")
    provider = _owned_record(receipt.get("provider"), "build", build["id"])
    prefix = _matches(
        provider.get("s3Arn"),
        re.compile(rf"arn:aws:s3:::{_BUCKET}/{_PATH}"),
        "S3 output prefix",
    )
    key = prefix.removeprefix("arn:aws:s3:::")
    _need(
        build["id"].split(":")[1] in key.split("/")
        and obs.get("build_id") == build["id"]
        and obs.get("http_status") == 200
        and headers.get("x-amz-meta-codebuild-buildarn") == build_arn,
        "The S3 response is not bound to the exact CodeBuild run",
    )
    url_root = f"https://s3.{region}.amazonaws.com/{key}/"
    url = _matches(
        obs.get("url"), re.compile(re.escape(url_root) + rf"{_SEGMENT}\.zip"), "S3 ZIP object URL"
    )
    start, end = _phase_window(build, "UPLOAD_ARTIFACTS")
    modified_header = headers.get("Last-Modified")
    if not isinstance(modified_header, str) or not 0 < len(modified_header) <= 64:
        raise SnapshotError("Expected an S3 Last-Modified header")
    modified = parsedate_to_datetime(modified_header)
    _need(
        modified.tzinfo is not None and floor(start) <= modified.timestamp() <= ceil(end),
        "The S3 object's last modification is outside the observed upload phase",
    )
    digest = _matches(obs.get("archive_sha256"), _SHA256, "archive SHA-256")
    archive = parent / "archive.zip"
    _need(
        archive.is_file() and not archive.is_symlink() and archive.resolve() == archive,
        "Saved contained ZIP is unavailable",
    )
    with archive.open("rb") as stream:
        data = stream.read(_ARCHIVE_LIMIT + 1)
    _need(
        0 < len(data) <= _ARCHIVE_LIMIT
        and str(len(data)) == headers.get("Content-Length")
        and hashlib.sha256(data).hexdigest() == digest,
        "Saved ZIP differs from the observed S3 object",
    )
    # This lookup identifies a directory. The provider's artifact checksum
    # cannot authenticate an individually retrieved child of that directory.
    provider_claims_checksum = any(
        provider.get(field) not in (None, "") for field in ("sha256sum", "sha256Checksum")
    )
    return data, url, digest, prefix + "/" + url.rsplit("/", 1)[1], provider_claims_checksum


def _archive_witness(raw: bytes, witness: _Row, root: Path, pr: _Row) -> dict[str, object]:
    source_path = _matches(witness.get("source_path"), re.compile(_PATH), "changed source path")
    member_path = _matches(
        witness.get("archive_member"),
        re.compile(rf"{_SEGMENT}/{re.escape(source_path)}"),
        "exact archive member path",
    )
    latest, latest_ref = _blob(root, pr["head"], source_path)
    base, base_ref = _blob(root, pr["base"], source_path)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        matches = [info for info in members if info.filename == member_path]
        _need(len(members) <= 2048, "The ZIP exceeds the member limit")
        _need(len(matches) == 1, "The ZIP member is missing or ambiguous")
        info = matches[0]
        _need(
            info.orig_filename == member_path
            and 0 < info.file_size <= _MEMBER_LIMIT
            and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
            and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
            "The ZIP member is outside the regular-text profile",
        )
        with archive.open(info) as stream:
            contents = stream.read(_MEMBER_LIMIT + 1)
    eof = contents.decode("utf-8")
    texts = (base, latest, eof)
    _need(
        all("\x00" not in value and "\r" not in value.replace("\r\n", "") for value in texts),
        "The ZIP witness and Git blobs must use supported UTF-8 text and line endings",
    )
    prior, head, stored = (value.replace("\r\n", "\n") for value in texts)
    _need(
        prior != head and stored == head,
        "The ZIP member does not establish a different value from the PR base",
    )
    return {
        "source": latest_ref,
        "base": base_ref,
        "archive_member": member_path,
        "member_sha256": hashlib.sha256(contents).hexdigest(),
        "comparison": "exact" if eof == latest else "lf-crlf-equivalent",
    }


def codebuild_s3_observation(path: Path, root: Path, build_arn: str, origin: str) -> _Row:
    """Corroborate one retrieved output file without fetching or running anything."""
    try:
        expected = _BUILD_ARN.fullmatch(build_arn)
        _need(
            expected and path.is_file(),
            "A full CodeBuild ARN and regular saved receipt are required",
        )
        region, build_id = expected.groups() if expected else ("", "")
        cap = _read_capture(path, "CodeBuild managed S3 receipt")
        _need(
            cap.get("schema") == "codebuild-managed-s3-v1", "Unsupported managed S3 receipt schema"
        )
        build = _owned_record(cap.get("build"), "id", build_id)
        _need(
            "arn" not in build or build["arn"] == build_arn,
            "Saved provider build ARN conflicts with the selected CodeBuild run",
        )
        logs = _owned_record(cap.get("logs"), "build", build_id)
        artifact_config = _map(build.get("artifacts"), "primary artifact")
        _need(
            build.get("projectName") == build_id.split(":")[0]
            and build.get("buildComplete") is True
            and build.get("buildStatus") == "SUCCEEDED"
            and build.get("secondarySources") == []
            and build.get("secondaryArtifacts") == []
            and artifact_config.get("type") == "S3",
            "The run does not identify a completed primary S3 artifact publication profile",
        )
        _need(
            artifact_config.get("packaging") in (None, "NONE"),
            "The saved directory profile does not support packaged CodeBuild outputs",
        )
        root = root.resolve()
        identity, pr, inline = _source_identity(cap, build, root, origin)
        raw, url, digest, object_arn, provider_claims_checksum = _object(
            _map(cap.get("artifact"), "artifact"), path.resolve().parent, build_arn, region, build
        )
        sources = _observe_plan(inline, logs, build, object_arn.rsplit("/", 1)[1])
        witness = _archive_witness(raw, _map(cap.get("witness"), "archive witness"), root, pr)
        publication = {
            "operation": "codebuild-managed-s3-artifact-upload",
            "target": url,
            "sha256": digest,
            "object_arn": object_arn,
            "build_object_binding": "unverified",
            "service_role_session": "unverified",
        }
        if provider_claims_checksum:
            publication["provider_checksum_scope"] = "unverified-for-child-object"
        return {
            "state": "managed-s3-link-unverified",
            "build": build_id,
            "build_arn": build_arn,
            "repository": identity,
            "pull_request": pr["number"],
            "head": pr["head"],
            "source_scope": "same-repository" if pr["fork"].lower() == identity else "fork",
            "source_plan": sources,
            "influence": witness,
            "publication": publication,
            "scope": _SCOPE,
            "next_evidence": (
                "Obtain the S3 data event for this object and match its acting session "
                "to this build. For a successful write, verify the recorded object version "
                "or an independent full-object digest tied to that write."
            ),
        }
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        OverflowError,
        zipfile.BadZipFile,
        zlib.error,
        RuntimeError,
        NotImplementedError,
    ) as exc:
        reason = (
            str(exc)
            if isinstance(exc, SnapshotError)
            else "Malformed or unreadable managed S3 evidence"
        )
        return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
