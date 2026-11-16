"""Relate a saved CodeBuild deployment skip to its configured source and run."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from typing import Any

from taintly.ingestion.codebuild_checkout import unambiguous_checkout_events
from taintly.ingestion.codebuild_snapshot import (
    SnapshotError,
    _buildspec_structure_limit,
    _read_capture,
    bind_public_build_response,
)
from taintly.ingestion.codebuild_start import _blob, _need
from taintly.parsers.structural import EventKind

_PATH = r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*"
_WORKSPACE = r"/codebuild/output/src[0-9]+/src/github\.com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+"
_STAMP = r"([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6})"
_RECORD = r"\[Container\] " + _STAMP + " "
_GUARD = re.compile(
    r'if \[\[ "\$CODEBUILD_WEBHOOK_HEAD_REF" == "(refs/heads/[A-Za-z0-9_.-]+)" '
    r'&& \$\{CODEBUILD_SOURCE_VERSION:0:3\} != "pr/" \]\]; then'
)
_SCOPE = (
    "Trusted saved public build and runner records. The saved rows are consistent with the configured "
    "skip. Runtime script bytes, attribution of stdout to an individual process, "
    "other commands, build service role and effective permissions remain unverified."
)


def _record(line: object, pattern: str) -> tuple[float, tuple[str, ...]]:
    match = re.fullmatch(_RECORD + pattern, line) if isinstance(line, str) else None
    if match is None:
        raise SnapshotError("Expected the selected CodeBuild runner record")
    when = datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return when.timestamp(), match.groups()[1:]


def _timestamp(value: object) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not isfinite(value):
        raise SnapshotError("Expected finite numeric CodeBuild timestamps")
    return float(value)


def _phase_window(build: dict[str, Any], name: str) -> tuple[float, float]:
    phases = build.get("phases")
    matches = (
        [phase for phase in phases if isinstance(phase, dict) and phase.get("phaseType") == name]
        if isinstance(phases, list)
        else []
    )
    if len(matches) != 1 or matches[0].get("phaseStatus") != "SUCCEEDED":
        raise SnapshotError(f"The deployment receipt lacks a successful owning {name} phase")
    phase = matches[0]
    lower, upper = _timestamp(phase.get("startTime")), _timestamp(phase.get("endTime"))
    _need(
        _timestamp(build.get("startTime")) <= lower < upper <= _timestamp(build.get("endTime")),
        f"The {name} phase timestamps are outside the selected build",
    )
    return lower, upper


def _source_selector(download: object, build: dict[str, Any]) -> str:
    if not isinstance(download, list) or len(download) != 3:
        raise SnapshotError("The saved source selection records are unavailable")
    start, (workspace,) = _record(download[0], rf"CODEBUILD_SRC_DIR=({_WORKSPACE})")
    selected, _ = _record(
        download[1], "YAML location is " + re.escape(workspace) + r"/buildspec\.yml"
    )
    finished, _ = _record(download[2], "Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED")
    download_start, download_end = _phase_window(build, "DOWNLOAD_SOURCE")
    build_start, _ = _phase_window(build, "BUILD")
    if not download_start <= start < selected < finished <= download_end <= build_start:
        raise SnapshotError("Saved buildspec selection is outside the owning DOWNLOAD_SOURCE phase")
    source = build["source"]
    if not isinstance(source, dict) or source.get("buildspec", "buildspec.yml") not in (
        "buildspec.yml",
        "./buildspec.yml",
    ):
        raise SnapshotError("Saved buildspec selection conflicts with the build response")
    return workspace


def _deployment_run(trace: object, build: dict[str, Any]) -> tuple[str, str, str]:
    if not isinstance(trace, list) or len(trace) != 4:
        raise SnapshotError("The saved deployment invocation records are unavailable")
    started, (script,) = _record(trace[0], rf"Running command bash ({_PATH}\.sh)")
    stopped, _ = _record(trace[3], "Phase complete: BUILD State: SUCCEEDED")
    phase_start, phase_end = _phase_window(build, "BUILD")
    if not phase_start <= started < stopped <= phase_end:
        raise SnapshotError("The saved deployment records are outside their owning BUILD phase")
    values = (
        re.fullmatch(
            r"Current branch is (refs/heads/[A-Za-z0-9_./-]+) and source is (pr/[1-9][0-9]*)",
            trace[1],
        )
        if isinstance(trace[1], str)
        else None
    )
    if values is None or values[2] != build["sourceVersion"] or trace[2] != "No deploy needed.":
        raise SnapshotError("The saved invocation lacks a consistent PR ref and skip outcome")
    return script, values[1], values[2]


def _guarded_operations(script: str) -> tuple[str, list[dict[str, object]]]:
    _need("\r" not in script and "\x00" not in script, "Unsupported shell line encoding")
    rows = [
        (index, value)
        for index, line in enumerate(script.split("\n"), 1)
        if (value := line.strip(" \t")) and not value.startswith("#")
    ]
    if len(rows) != 8:
        raise SnapshotError("The deployment script is outside the supported guard profile")
    _need(
        rows[0][1]
        == "echo Current branch is $CODEBUILD_WEBHOOK_HEAD_REF and source is $CODEBUILD_SOURCE_VERSION"
        and [value for _, value in rows[-3:]] == ["else", "echo No deploy needed.", "fi"],
        "The saved deploy messages do not match the selected script profile",
    )
    guard = _GUARD.fullmatch(rows[1][1])
    if guard is None:
        raise SnapshotError("The selected script has no supported branch and PR guard")
    _need(
        rows[2][1] == "echo Deploying to S3 and invalidating CloudFront cache.",
        "The script's guarded branch does not match the supported profile",
    )
    sync = re.fullmatch(
        rf"aws s3 sync ({_PATH}/) s3://([a-z0-9][a-z0-9.-]{{1,61}}[a-z0-9])/ --delete",
        rows[3][1],
    )
    if sync is None or rows[4][1] != (
        'aws cloudfront create-invalidation --distribution-id $CLOUDFRONT_DIST_ID --paths "/*"'
    ):
        raise SnapshotError(
            "The guarded operations are outside the supported S3 and CloudFront profile"
        )
    operations: list[dict[str, object]] = [
        {
            "operation": "aws s3 sync",
            "target": f"s3://{sync[2]}/",
            "line": rows[3][0],
            "delete_option": True,
            "from": sync[1],
        },
        {"operation": "cloudfront create-invalidation", "target": "unverified", "line": rows[4][0]},
    ]
    return guard[1], operations


def _owned_record(value: object, field: str, build_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get(field) != build_id:
        raise SnapshotError("Build response and runner evidence must name the selected build")
    return value


def codebuild_deploy_observation(
    snapshot: Path, root: Path, origin: str, build_id: str
) -> dict[str, Any]:
    """Verify a trusted, explicitly supplied public runner observation."""
    try:
        capture = _read_capture(snapshot, "Public deploy observation")
        _need(
            capture.get("schema") == "codebuild-deploy-observation-v1",
            "Unexpected deploy observation schema",
        )
        build = _owned_record(capture.get("build"), "id", build_id)
        trace = _owned_record(capture.get("trace"), "build", build_id)
        workspace = _source_selector(trace.get("download"), build)
        selection = bind_public_build_response(
            {"build": {**build, "source": {**build["source"], "buildspec": "buildspec.yml"}}},
            build_id,
            root.resolve(),
            origin,
        )
        script, branch, ref = _deployment_run(trace.get("deployment"), build)
        structure_limit = _buildspec_structure_limit(
            selection.path, selection.content, run=True, allow_document_start=True
        )
        _need(structure_limit is None, structure_limit or "")
        events = unambiguous_checkout_events(selection.path, selection.content)
        _need(events, "The selected buildspec has incomplete or ambiguous structure")
        _need(
            workspace.lower().endswith("/" + selection.repository)
            and build.get("secondarySources") == []
            and isinstance(build.get("environment"), dict)
            and build["environment"].get("type") == "LINUX_CONTAINER",
            "The reported workspace does not match a supported primary GitHub checkout",
        )
        version = [
            event.value
            for event in events
            if event.path == ("version",) and event.kind is EventKind.LEAF_SCALAR
        ]
        _need(version == ["0.2"], "Expected an unambiguous CodeBuild buildspec version 0.2")
        commands = [
            event
            for event in events
            if event.kind is EventKind.LEAF_SCALAR
            and len(event.path) == 4
            and event.path[:3] == ("phases", "build", "commands")
            and isinstance(event.path[3], int)
            and event.value == f"bash {script}"
        ]
        _need(
            len(commands) == 1,
            "The deploy command lacks a unique owning buildspec declaration",
        )
        body, source = _blob(root.resolve(), selection.commit, script)
        expected_branch, operations = _guarded_operations(body)
        return {
            "state": "guard-skip-reported",
            "build": build_id,
            "repository": selection.repository,
            "revision": selection.commit,
            "pull_request_ref": ref,
            "reported_head_ref": branch,
            "source": {
                "path": selection.path,
                "sha256": selection.sha256,
                "line": commands[0].line,
            },
            "configured_script": source,
            "configured_operations": operations,
            "guard": {"head_ref_matches": branch == expected_branch, "is_pull_request": True},
            "effective_authority": "unverified",
            "runtime_stdout_producer": "unverified",
            "scope": _SCOPE,
        }
    except (SnapshotError, KeyError, TypeError, ValueError, OverflowError) as error:
        reason = (
            str(error)
            if isinstance(error, SnapshotError)
            else "Malformed CodeBuild deployment evidence"
        )
        return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
