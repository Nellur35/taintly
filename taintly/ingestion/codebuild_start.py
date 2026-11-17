"""Bind saved GitHub delegation evidence to returned AWS CodeBuild runs."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from taintly.ingestion.codebuild_snapshot import (
    _COMMIT_ID,
    _MAX_BYTES,
    BUILD_ID,
    BoundBuildspec,
    SnapshotError,
    _git,
    _github_identity,
    _read_capture,
    _regular_blob,
    _require_git_revision,
    bind_public_build_response,
)
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.rules.github._workflow_run_artifact import _Index, _is_exact_identifier_expression
from taintly.workflow_corpus import WorkflowSummary

_PART = r"\.?[A-Za-z0-9_][A-Za-z0-9_.-]*"
_PATH = rf"{_PART}(?:/{_PART})*"
_ROLE = re.compile(r"arn:aws:iam::[0-9]{12}:role/([A-Za-z0-9_+=,.@-]{1,64})")
_REGION = r"[a-z]{2}-[a-z0-9-]+-[0-9]"
_LAUNCH_ENTRY = re.compile(
    rf'[ \t]+"([A-Za-z0-9][A-Za-z0-9_-]{{1,149}})(?: ({_REGION}) no-batch)?"'
)
_LAUNCH_PROGRAM = "c3496e1609dbeec883cbcdc6fc2828beef3990984f2e73bcc54609af8a7d7ec1"
_GUARD_OPEN = 'if [[ "$permission" == "admin" || "$permission" == "write" ]]; then'
_COPY = re.compile(r"nix copy --to \$([A-Za-z_][A-Za-z0-9_]*) (\.#[A-Za-z0-9_.-]+)")
_BUCKET = re.compile(rf"s3://([a-z0-9][a-z0-9.-]{{1,61}}[a-z0-9])\?region=({_REGION})")
_SCOPE = (
    "Trusted saved source and run records. The GitHub role is the caller of CodeBuild. "
    "The CodeBuild service identity, effective publication permissions and successful "
    "object writes need separate evidence. A successful phase can copy zero objects."
)
_Row = dict[str, Any]


def _need(condition: object, reason: str) -> None:
    if not condition:
        raise SnapshotError(reason)


def _sha(value: object) -> bool:
    return isinstance(value, str) and _COMMIT_ID.fullmatch(value) is not None


def _blob(root: Path, revision: str, path: str) -> tuple[str, _Row]:
    _need(re.fullmatch(_PATH, path), "caller file path is not a supported repository path")
    blob = _regular_blob(root, revision, path)
    if blob is None or int(_git(root, "cat-file", "-s", blob)) > _MAX_BYTES:
        raise SnapshotError("required caller source blob is unavailable or oversized")
    data = _git(root, "cat-file", "blob", blob)
    return data.decode("utf-8"), {
        "path": path,
        "revision": revision,
        "git_blob": blob,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _field(index: _Index, path: tuple[object, ...]) -> Event:
    values = index.values.get(path, [])
    _need(
        len(index.keys.get(path, ())) == len(values) == 1
        and not values[0].merge_origins
        and isinstance(values[0].value, str)
        and values[0].value_kind in {"plain", "quoted", "block_literal"},
        "required caller workflow field is missing or ambiguous",
    )
    return values[0]


def _step(index: _Index, owner: tuple[object, ...], name: str) -> tuple[object, ...]:
    candidates = [
        key[:-1]
        for key, rows in index.values.items()
        if len(key) == 5
        and key[:3] == owner
        and key[4] == "name"
        and any(row.value == name for row in rows)
    ]
    _need(len(candidates) == 1, "selected caller step name is missing or ambiguous")
    _field(index, (*candidates[0], "name"))
    return candidates[0]


def _field_path(index: _Index, path: tuple[object, ...], expected: str) -> None:
    _need(
        _is_exact_identifier_expression(str(_field(index, path).value), expected),
        "required source, permission subject or role-session expression is unsupported",
    )


def _only_inputs(index: _Index, step: tuple[object, ...], inputs: set[str]) -> None:
    path = (*step, "with")
    _need(
        len(index.keys.get(path, ())) == 1
        and {key[-1] for key in index.keys if key and key[:-1] == path} == inputs,
        "caller action input ownership or overrides are unsupported",
    )


def _guard_launcher(body: str, permission_step: str) -> str:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    assignment = (
        "permission=$(jq -r '.permission' <<< '${{ steps." + permission_step + ".outputs.data }}')"
    )
    _need(
        len(lines) >= 7
        and lines[0] == assignment
        and lines[1] == "echo \"$pr_author has permission '$permission'\"."
        and lines[2] == _GUARD_OPEN
        and lines[4] == "else"
        and lines[-1] == "fi"
        and lines[5] == 'echo "$pr_author does not have write permissions."',
        "caller shell guard is outside the exact supported authorization branch",
    )
    command = re.fullmatch(rf"\./({_PATH}) \$source_pr", lines[3])
    if command is None or any(
        re.fullmatch(r'echo "[^"\x00-\x1f`\\$]*"', line) is None for line in lines[6:-1]
    ):
        raise SnapshotError("caller guard arms contain unmodeled commands")
    return command[1]


def _start_targets(launcher: str, repo: str) -> tuple[dict[str, str], int]:
    """Read the targets of the reviewed Bash launcher without evaluating Shell."""
    lines = launcher.split("\n")
    message = "The pinned launcher does not implement the reviewed source-bound StartBuild command"
    _need(
        re.fullmatch(r"[\x20-\x7e\t\n]+", launcher)
        and lines[0] == "#!/bin/bash"
        and "BUILDS=(" in lines,
        message,
    )
    opening = lines.index("BUILDS=(")
    _need(")" in lines[opening + 1 :], message)
    closing = lines.index(")", opening + 1)
    preamble = [line for line in lines[:opening] if line.strip(" \t") and not line.startswith("#")]
    suffix = lines[closing + 1 :]
    default_repo = "REPO=${2:-" + repo + "}"
    _need(preamble == ["set -e"] and suffix.count(default_repo) == 1, message)
    # Preserve physical lines and whitespace in the executable recipe, including
    # the backslash-newline continuations of the AWS command.
    normalized = "\n".join(
        "REPO=<checked default repository>" if line == default_repo else line for line in suffix
    )
    _need(hashlib.sha256(normalized.encode()).hexdigest() == _LAUNCH_PROGRAM, message)
    seen, singles = set(), {}
    for line in lines[opening + 1 : closing]:
        entry = _LAUNCH_ENTRY.fullmatch(line)
        if entry is None or entry[1] in seen:
            raise SnapshotError("The pinned launcher target list is unsupported or ambiguous")
        project, region = entry.groups()
        seen.add(project)
        if region is not None:
            singles[project] = region
    offset = next(i for i, line in enumerate(suffix) if line.startswith("    aws --region "))
    return singles, closing + offset + 2


def _caller_source(root: Path, repo: str, revision: str, path: str, job: _Row) -> tuple[_Row, str]:
    _require_git_revision(root, repo, revision, "Caller checkout")
    _need(
        re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", path),
        "caller workflow path is unsupported",
    )
    text, identity = _blob(root, revision, path)
    index = _Index.build(WorkflowSummary(path, text, text.splitlines()))
    owner = ("jobs", job["name"], "steps")
    _need(
        index.error is None
        and all(
            len(index.keys.get(key, ())) == 1
            for key in (("on",), ("on", "pull_request_target"), ("jobs",), owner[:2], owner)
        )
        and not any(
            (*owner[:2], key) in index.keys
            for key in ("strategy", "uses", "container", "defaults", "name")
        )
        and ("defaults",) not in index.keys,
        "caller source job, event or workspace is outside the supported profile",
    )
    checkout = (*owner, 0)
    _need(
        _field(index, (*checkout, "uses")).value == "actions/checkout@v7"
        and {key[-1] for key in index.keys if key[:-1] == checkout} == {"uses"},
        "caller does not use the supported default base checkout",
    )
    permission = _step(index, owner, "Get permissions")
    role_step = _step(index, owner, "Get credentials")
    launcher = _step(index, owner, "Start Codebuild for PR")
    _need(
        all(isinstance(step[-1], int) for step in (permission, role_step, launcher))
        and [step[-1] for step in (permission, role_step, launcher)] == [1, 2, 4]
        and all((*step, "run") not in index.keys for step in (permission, role_step))
        and (*launcher, "uses") not in index.keys
        and (*launcher, "shell") not in index.keys
        and _field(index, (*launcher, "if")).value == "github.event_name == 'pull_request_target'"
        and _field(index, (*permission, "if")).value == "github.event_name == 'pull_request_target'"
        and _field(index, (*permission, "uses")).value == "octokit/request-action@v3.0.0"
        and _field(index, (*permission, "with", "route")).value
        == "GET /repos/{repo}/collaborators/{author}/permission"
        and _field(index, (*role_step, "uses")).value
        == "aws-actions/configure-aws-credentials@v6.3.0"
        and {key[-1] for key in index.keys if key[:-1] == role_step} == {"name", "uses", "with"}
        and _field(index, (*owner[:2], "env", "source_pr")).value
        == "pr/${{ github.event.pull_request.number }}"
        and (*launcher, "env") not in index.keys
        and (*launcher, "working-directory") not in index.keys,
        "caller permission, credentials or PR source binding is unsupported",
    )
    environment = (*owner[:2], "env")
    permission_env = (*permission, "env")
    _need(
        ("env",) not in index.keys
        and len(index.keys.get(environment, ())) == 1
        and {key[-1] for key in index.keys if key[:-1] == environment}
        == {"source_pr", "source_sha", "pr_author"}
        and len(index.keys.get(permission_env, ())) == 1
        and {key[-1] for key in index.keys if key[:-1] == permission_env} == {"GITHUB_TOKEN"}
        and _field(index, (*permission_env, "GITHUB_TOKEN")).value == "${{ secrets.GITHUB_TOKEN }}",
        "caller workflow supplies an unsupported environment override",
    )
    _field_path(index, (*permission, "with", "repo"), "github.repository")
    _field_path(index, (*permission, "with", "author"), "github.event.pull_request.user.login")
    _field_path(index, (*owner[:2], "env", "pr_author"), "github.event.pull_request.user.login")
    _field_path(index, (*role_step, "with", "role-session-name"), "github.run_id")
    _only_inputs(index, permission, {"route", "repo", "author"})
    _only_inputs(index, role_step, {"role-to-assume", "role-session-name", "aws-region"})
    _need(
        _field(index, (*owner[:2], "permissions", "id-token")).value == "write",
        "caller lacks the expected job-owned OIDC permission",
    )
    step_id = str(_field(index, (*permission, "id")).value)
    _need(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", step_id),
        "permission-producing step ID is unsupported",
    )
    body = _field(index, (*launcher, "run"))
    helper = _guard_launcher(str(body.value), step_id)
    non_pr = (*owner, 3)
    _need(
        {key[-1] for key in index.keys if key[:-1] == non_pr} == {"name", "if", "run"}
        and _field(index, (*non_pr, "name")).value == "Start Codebuild for SHA"
        and _field(index, (*non_pr, "if")).value == "github.event_name != 'pull_request_target'"
        and _field(index, (*non_pr, "run")).value == f"./{helper} $source_sha",
        "pinned caller's separate non-PR launcher does not match the skipped step",
    )
    launcher_text, script = _blob(root, revision, helper)
    role = _field(index, (*role_step, "with", "role-to-assume"))
    region = _field(index, (*role_step, "with", "aws-region"))
    match = _ROLE.fullmatch(str(role.value))
    if match is None or re.fullmatch(_REGION, str(region.value)) is None:
        raise SnapshotError("caller role or default region is unsupported")
    return {
        "workflow": identity,
        "launcher": script,
        "launcher_line": body.line,
        "configured_role": role.value,
        "role_line": role.line,
        "role_name": match[1],
        "configured_region": region.value,
    }, launcher_text


def _time(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _need(stamp.utcoffset() is not None, "timestamp does not carry a time offset")
    return stamp


def _step_window(job: _Row, name: str) -> tuple[datetime, datetime]:
    steps = [step for step in job["steps"] if step["name"] == name]
    _need(
        len(steps) == 1 and steps[0]["conclusion"] == "success",
        "selected step was not uniquely successful",
    )
    start, end = (_time(steps[0][key]) for key in ("started_at", "completed_at"))
    _need(
        _time(job["started_at"]) <= start <= end <= _time(job["completed_at"]),
        "selected step is outside the saved job time window",
    )
    return start, end


def _receipts(trace: list[_Row], job: _Row, kind: str, step: str) -> list[_Row]:
    start, end = _step_window(job, step)
    return [
        record
        for record in trace
        if record["role"] == kind
        and all(type(record[key]) is int for key in ("job_id", "run_id", "attempt"))
        and record["job_id"] == job["id"]
        and record["run_id"] == job["run_id"]
        and record["attempt"] == job["run_attempt"]
        and start <= _time(record["time"]).replace(microsecond=0) <= end
    ]


def _one_receipt(trace: list[_Row], job: _Row, kind: str, step: str) -> _Row:
    rows = _receipts(trace, job, kind, step)
    _need(len(rows) == 1, f"missing or ambiguous {kind} receipt")
    return rows[0]


def _command_evidence(
    selection: BoundBuildspec, records: list[_Row], phases: list[_Row]
) -> list[_Row]:
    lines = selection.content.splitlines()
    reported = []
    for item in selection.checkout_scripts:
        ref = item.reference
        windows = [
            phase
            for phase in phases
            if phase["phaseType"] == ref.phase.upper() and phase.get("phaseStatus") == "SUCCEEDED"
        ]
        if len(windows) != 1 or not item.git_blob:
            continue
        command = lines[ref.line - 1][ref.column - 1 :].rstrip()
        window = windows[0]
        if any(
            row["kind"] == "running-command"
            and row["command"] == command
            and window["startTime"] <= _time(row["time"]).timestamp() <= window["endTime"]
            for row in records
        ):
            reported.append(
                {
                    "path": ref.path,
                    "git_blob": item.git_blob,
                    "line": ref.line,
                    "phase": ref.phase,
                }
            )
    return reported


def _configured_copy(
    selection: BoundBuildspec, records: list[_Row], phases: list[_Row]
) -> list[_Row]:
    if selection.pull_request_ref is None or not selection.checkout_scripts:
        return []
    events = list(walk_workflow(selection.path, content=selection.content, include_keys=True))
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return []
    values = {event.path: event for event in events if event.kind is EventKind.LEAF_SCALAR}
    result = []
    for key, event in values.items():
        if (
            len(key) != 4
            or key[:3] != ("phases", "post_build", "commands")
            or event.value_kind != "plain"
        ):
            continue
        match = _COPY.fullmatch(str(event.value))
        if match is None:
            continue
        target = values.get(("env", "variables", match[1]))
        bucket = _BUCKET.fullmatch(str(target.value)) if target is not None else None
        if bucket is not None and target is not None:
            windows = [
                phase
                for phase in phases
                if phase["phaseType"] == "POST_BUILD" and phase.get("phaseStatus") == "SUCCEEDED"
            ]
            counts = [
                row["paths"]
                for window in windows
                if len(windows) == 1
                and sum(
                    value.value == event.value
                    for owner, value in values.items()
                    if owner[:3] == ("phases", "post_build", "commands")
                )
                == 1
                for row in records
                if row["kind"] == "nix-copy-summary"
                and row["command"] == event.value
                and type(row["paths"]) is int
                and 0 <= row["paths"] < 10**9
                and window["startTime"] <= _time(row["time"]).timestamp() <= window["endTime"]
            ]
            result.append(
                {
                    "operation": "nix-copy-to-s3-cache",
                    "bucket": bucket[1],
                    "region": bucket[2],
                    "installable": match[2],
                    "line": event.line,
                    "destination_line": target.line,
                    "reported_nix_paths": counts[0] if len(counts) == 1 else None,
                    "object_write": "unverified",
                }
            )
    return result


def _build_result(
    response: _Row,
    build_id: str,
    root: Path,
    origin: str,
    caller: _Row,
    start: _Row,
    permission: _Row,
    start_request: _Row,
    head: str,
    commands: list[_Row],
) -> _Row:
    record = response["build"]
    ref = start_request["source_version"]
    account = caller["configured_role"].split(":")[4]
    expected_arn = f"arn:aws:codebuild:{start_request['region']}:{account}:build/{build_id}"
    _need(
        "arn" not in record or record["arn"] == expected_arn,
        "Returned AWS build ARN conflicts with the selected request or configured role",
    )
    _need(
        record["initiator"] == f"{caller['role_name']}/{start['run_id']}"
        and record["sourceVersion"] == ref
        and record["resolvedSourceVersion"] == head
        and _time(permission["time"]).timestamp()
        <= record["startTime"]
        <= _time(start["time"]).timestamp(),
        "returned AWS build, source ref, role session or start time differs from the caller",
    )
    selection = bind_public_build_response(response, build_id, root, origin)
    exact_commands = [
        row
        for row in commands
        if row["build_id"] == build_id
        and record["startTime"] <= _time(row["time"]).timestamp() <= record["endTime"]
    ]
    return {
        "build_id": build_id,
        "start_request": start_request,
        "provider_build_arn": record.get("arn"),
        "project": record["projectName"],
        "source_ref": ref,
        "revision": selection.commit,
        "buildspec": selection.path,
        "sha256": selection.sha256,
        "status": record["buildStatus"],
        "managed_artifacts": record["artifacts"]["type"],
        "reported_checkout_commands": _command_evidence(
            selection, exact_commands, record["phases"]
        ),
        "configured_publication": _configured_copy(selection, exact_commands, record["phases"]),
        "analysis_limit": selection.analysis_limit,
    }


def _assess(data: _Row, root: Path, origin: str, run_id: int, job_id: int) -> _Row:
    repo = _github_identity(origin)
    run, job, pr, trace = data["run"], data["job"], data["pr"], data["observations"]
    _need(
        type(run["id"]) is int
        and run["id"] == job["run_id"] == run_id
        and type(job["id"]) is int
        and job["id"] == job_id
        and type(run["run_attempt"]) is int
        and run["run_attempt"] > 0
        and type(job["run_attempt"]) is int
        and job["run_attempt"] == run["run_attempt"]
        and run["html_url"] == f"https://github.com/{repo}/actions/runs/{run_id}"
        and run["event"] == "pull_request_target"
        and run["conclusion"] == job["conclusion"] == "success"
        and _sha(run["head_sha"])
        and job["head_sha"] == run["head_sha"] == pr["head"]["sha"]
        and pr["base"]["repo"].lower() == repo
        and run["head_repository"].lower() == pr["head"]["repo"].lower() != repo
        and type(pr["number"]) is int
        and 0 < pr["number"] < 10**19
        and _sha(pr["base"]["sha"])
        and re.fullmatch(r"[A-Za-z0-9_-]+", job["name"]),
        "saved run, job and fork PR identities do not agree",
    )
    checkout = _one_receipt(trace, job, "local checkout revision", "Run actions/checkout@v7")
    role = _one_receipt(trace, job, "role assumed with exact GitHub run session", "Get credentials")
    permission = _one_receipt(
        trace, job, "repository permission reported by job", "Start Codebuild for PR"
    )
    _need(
        checkout["value"] == pr["base"]["sha"]
        and type(role["value"]) is int
        and role["value"] == run_id
        and _time(checkout["time"]) < _time(role["time"]) < _time(permission["time"]),
        "base checkout, role-session identity or receipt order is unresolved",
    )
    caller, launcher_text = _caller_source(root, repo, checkout["value"], run["path"], job)
    caller["reported_role_session"] = role["value"]
    _step_window(job, "Get permissions")
    skipped_sha = [step for step in job["steps"] if step["name"] == "Start Codebuild for SHA"]
    _need(
        len(skipped_sha) == 1
        and skipped_sha[0]["conclusion"] == "skipped"
        and skipped_sha[0]["number"] == 5,
        "the separate non-PR launcher was not recorded as skipped at its expected position",
    )
    ref = f"pr/{pr['number']}"
    calls = _receipts(trace, job, "CodeBuild returned build id", "Start Codebuild for PR")
    stops = _receipts(trace, job, "no start when author lacks write", "Start Codebuild for PR")
    result: _Row = {
        "run": run_id,
        "job": job_id,
        "attempt": run["run_attempt"],
        "repository": repo,
        "pull_request_ref": ref,
        "head": run["head_sha"],
        "caller": caller,
        "observed_repository_permission": permission["value"],
        "scope": _SCOPE,
    }
    responses, commands = data["build_responses"], data["build_commands"]
    if permission["value"] in {"read", "triage", "none"}:
        _need(
            len(stops) == 1
            and stops[0]["value"] is True
            and _time(permission["time"]) < _time(stops[0]["time"])
            and not calls
            and responses == []
            and commands == [],
            "read-only branch lacks its specific denial or has conflicting build evidence",
        )
        return {**result, "state": "automatic-start-blocked", "builds": []}
    _need(
        permission["value"] in {"admin", "write"} and not stops and 0 < len(calls) <= 8,
        "specific successful single-build requests are missing or conflicting",
    )
    builds = {row["build"]["id"]: row for row in responses}
    returned = {row["value"]: row for row in calls}
    _need(
        len(builds) == len(responses) == len(returned) == len(calls)
        and builds.keys() == returned.keys()
        and all(
            isinstance(build_id, str) and BUILD_ID.fullmatch(build_id) for build_id in returned
        ),
        "CodeBuild response IDs do not match exactly the selected returned IDs",
    )
    launcher_path = caller["launcher"]["path"]
    _need(
        _regular_blob(root, checkout["value"], launcher_path, executable=True)
        == caller["launcher"]["git_blob"],
        "The pinned launcher does not implement a supported executable checkout",
    )
    projects, launcher_line = _start_targets(launcher_text, repo)
    requested = {}
    for build_id in returned:
        project = build_id.split(":", 1)[0]
        _need(project in projects, "Returned build targets a project not selected by the launcher")
        region = projects[project]
        _need(
            region == caller["configured_region"],
            "Launcher request region differs from the proven caller's supported region",
        )
        requested[build_id] = {
            "project": project,
            "region": region,
            "source_version": ref,
            "launcher_line": launcher_line,
        }
    return {
        **result,
        "state": "starts-observed",
        "operation": "codebuild:StartBuild",
        "review": "Bind reviewed PR commits to a full SHA. Check the build's own service identity and object-write permissions separately.",
        "builds": [
            _build_result(
                builds[build_id],
                build_id,
                root,
                origin,
                caller,
                receipt,
                permission,
                requested[build_id],
                run["head_sha"],
                commands,
            )
            for build_id, receipt in returned.items()
        ],
    }


def codebuild_start_observation(
    capture: Path, root: Path, origin: str, run_id: int, job_id: int
) -> _Row:
    try:
        data = _read_capture(capture, "CodeBuild start capture")
        _need(data.get("schema") == "codebuild-start-v1", "unsupported start observation schema")
        return _assess(data, root.resolve(), origin, run_id, job_id)
    except SnapshotError as exc:
        reason = str(exc)
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        OverflowError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        reason = "required caller, build, or source evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
