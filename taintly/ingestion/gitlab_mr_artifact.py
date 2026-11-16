"""Tie a target-project fork MR job to a retrieved managed job artifact."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from itertools import pairwise
from pathlib import Path
from typing import Any

from taintly.ingestion.gitlab_registry_job import (
    _PROJECT,
    _SHA,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _owned_workflow_events,
    _source_bytes,
    _time,
    _value,
)
from taintly.parsers.structural import Event, EventKind
from taintly.rules.gitlab.mr_publish import command_text

_Row = dict[str, Any]
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,100}(?::[A-Za-z0-9_.-]{1,100})?")
_PART = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_PATH = re.compile(rf"{_PART}(?:/{_PART})*")
_BUILD = re.compile(r"(?:bun|yarn) run build(?::[a-z0-9:_-]+)?")
_MOVE = re.compile(rf"mv ({_PART}(?:/{_PART})*) ({_PART}(?:/{_PART})*)")
_EVENT = "$CI_PIPELINE_SOURCE == 'merge_request_event'"
_SAME_PROJECT = "$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID"
_SCOPE = (
    "Trusted saved GitLab project, job, runner and public artifact records. The reported "
    "authority covers the job-scoped archive upload only. Protected credentials, registry "
    "push, live Pages deployment and arbitrary content provenance remain separate questions."
)


def _need(condition: object, reason: str) -> None:
    if not condition:
        raise RegistryJobError(reason)


class _Config:
    def __init__(self, source: str) -> None:
        source = source.replace("\r\n", "\n").replace("\r", "\n")
        self.lines = source.splitlines()
        events = _owned_workflow_events(source)
        self.keys = Counter(row.path for row in events if row.kind is EventKind.MAP_KEY)
        self.merges = {row.path[:-1] for row in events if row.value_kind == "merge_key"}
        self.leaves: dict[tuple[object, ...], list[Event]] = {}
        for row in events:
            if row.kind is EventKind.LEAF_SCALAR:
                self.leaves.setdefault(row.path, []).append(row)

    def owner(self, path: tuple[object, ...]) -> None:
        _need(self.keys[path] == 1, "selected source owner is missing or ambiguous")
        _need(
            not any(path[: len(merge)] == merge for merge in self.merges),
            "GitLab source contains a merge in the selected source owner",
        )

    def scalar(self, path: tuple[object, ...]) -> Event:
        self.owner(path)
        rows = self.leaves.get(path, [])
        _need(
            len(rows) == 1
            and not rows[0].merge_origins
            and rows[0].value_kind in {"plain", "quoted"},
            "owned source field is unsupported",
        )
        return rows[0]

    def sequence(self, path: tuple[object, ...]) -> list[Event]:
        self.owner(path)
        entries = [
            (key[-1], rows)
            for key, rows in self.leaves.items()
            if key[:-1] == path and isinstance(key[-1], int)
        ]
        rows = []
        for expected, (index, matches) in enumerate(sorted(entries)):
            _need(
                index == expected and len(matches) == 1 and not matches[0].merge_origins,
                "source sequence elements are missing or ambiguous",
            )
            rows.append(matches[0])
        _need(rows, "selected source sequence is empty")
        return rows


def _manual(data: _Row, cfg: _Config, name: str) -> _Row:
    job = data["job"]
    _need(
        job["started_at"] is None
        and job["finished_at"] is None
        and job["artifacts"] == []
        and data["trace"] == []
        and data["artifact"] is None
        and cfg.keys[(name, "extends")] == 0,
        "manual status conflicts with execution evidence or lacks direct rule ownership",
    )
    cfg.owner((name, "rules"))
    first = cfg.scalar((name, "rules", 0, "if"))
    second = cfg.scalar((name, "rules", 1, "if"))
    gate = cfg.scalar((name, "rules", 1, "when"))
    terms = {value.strip() for value in str(first.value).split("&&")}
    builtin_names = {"CI_PIPELINE_SOURCE", "CI_PROJECT_ID", "CI_MERGE_REQUEST_SOURCE_PROJECT_ID"}
    _need(
        terms == {_EVENT, _SAME_PROJECT, "$CI_PROJECT_ID == $CANONICAL_PROJECT_ID"}
        and second.value == _EVENT
        and gate.value == "manual"
        and {key[2] for key in cfg.keys if len(key) > 3 and key[:2] == (name, "rules")} == {0, 1},
        "source does not establish the supported same-project exception and manual fallback",
    )
    _need(
        not any(
            len(key) >= 2
            and key[-2] == "variables"
            and key[-1] in builtin_names
            and (len(key) == 2 or key[0] in {name, "workflow"})
            for key in cfg.keys
        ),
        "source overrides a builtin value required for the manual decision",
    )
    return {
        "state": "manual-job-not-started",
        "guard_line": first.line,
        "manual_line": gate.line,
        "same_project_guard_for_recorded_project_ids": "false",
        "effective_variables": "unverified",
        "manual_start_permission": "unverified",
    }


def _artifact_owner(cfg: _Config, name: str) -> str:
    if cfg.keys[(name, "script")] or cfg.keys[(name, "artifacts")]:
        return name
    parent = _value(cfg.scalar((name, "extends")).value, _JOB, "local job template")
    cfg.owner((parent,))
    _need(
        parent != name and not cfg.keys[(parent, "extends")],
        "inherited artifact source is outside the single-local-template profile",
    )
    return parent


def _successful(
    data: _Row, root: Path, cfg: _Config, pipeline: _Row, name: str, job_url: str
) -> _Row:
    job = data["job"]
    _need(job["status"] == "success", "selected job has no recorded successful upload")
    archives = [a for a in job["artifacts"] if a["file_type"] == "archive"]
    _need(
        len(archives) == 1 and _identifier(archives[0]["size"], "archive size"),
        "selected job has no unique nonempty managed archive",
    )
    owner = _artifact_owner(cfg, name)
    cfg.owner((owner, "artifacts"))
    selectors = cfg.sequence((owner, "artifacts", "paths"))
    _need(len(selectors) == 1, "archive scope is outside the single literal directory profile")
    selector = _value(selectors[0].value, _PATH, "artifact directory")
    steps = cfg.sequence((owner, "script"))
    commands = [(event, command_text(event, cfg.lines)) for event in steps]
    builds = [(event, cmd) for event, cmd in commands if cmd and _BUILD.fullmatch(cmd)]
    _need(len(builds) == 1, "source has no unique supported build command")
    build, cmd = builds[0]
    receipt = data["trace"]
    shape = [r["kind"] for r in receipt]
    moves = [
        (event, text)
        for event, text in commands
        if text and (match := _MOVE.fullmatch(text)) and match[2] == selector
    ]
    _need(
        len(moves) <= 1
        and shape == ["checkout", "command", *(["command"] if moves else []), "upload"],
        "saved runner records do not show the exact checkout, build and archive upload",
    )
    times = [_time(row["time"], "runner observation time") for row in receipt]
    start = _time(job["started_at"], "job start")
    end = _time(job["finished_at"], "job end")
    owning_pipeline = job["pipeline"]
    _need(
        _time(owning_pipeline["created_at"], "owning pipeline creation")
        <= start
        <= end
        <= _time(owning_pipeline["updated_at"], "owning pipeline last update"),
        "selected job is outside the recorded pipeline window",
    )
    _need(
        start <= times[0] and times[-1] <= end and all(a < b for a, b in pairwise(times)),
        "saved runner observations are outside the job window or out of order",
    )
    _need(
        receipt[0]["sha_prefix"] == pipeline["sha"][:8]
        and receipt[0]["ref"] == pipeline["ref"]
        and receipt[1]["command"] == cmd
        and receipt[-1]["job"] == job["id"]
        and receipt[-1]["http_status"] == 201,
        "saved checkout, build command or coordinator receipt does not match its owner",
    )
    if moves:
        event, move = moves[0]
        _need(
            receipt[2]["command"] == move and event.line > build.line,
            "archive directory move is not owned by the supported command sequence",
        )
    artifact = data["artifact"]
    path = _value(artifact["path"], _PATH, "archive member path")
    url = f"{job_url}/artifacts/raw/{path}"
    _need(
        path.startswith(selector + "/")
        and artifact["url"] == url
        and artifact["http_status"] == 200
        and _time(artifact["observed_at"], "artifact retrieval time") >= end,
        "retrieved artifact does not belong to the selected job and directory",
    )
    raw = _source_bytes(root, root / "published-file.bin", "selected artifact member")
    digest = hashlib.sha256(raw).hexdigest()
    _need(
        0 < len(raw) <= 131072 and len(raw) == artifact["size"] and digest == artifact["sha256"],
        "saved artifact member differs from public retrieval size or digest",
    )
    return {
        "state": "job-artifact-observed",
        "command": cmd,
        "command_line": build.line,
        "declaration_owner": owner,
        "artifact_path_line": selectors[0].line,
        "publication": {
            "operation": "gitlab-job-artifact-upload",
            "authority": "gitlab-runner-job-scoped-upload",
            "target": url,
            "member_path": path,
            "sha256": digest,
        },
    }


def _assess(data: _Row, root: Path, project_id: int, pipeline_id: int, job_id: int) -> _Row:
    project, pr, pipe, merge, job = (data[k] for k in ("project", "mr", "pipeline", "merge", "job"))
    for label, value in (
        ("project", project["id"]),
        ("pipeline", pipe["id"]),
        ("job", job["id"]),
        ("source project", pr["source_project_id"]),
    ):
        _identifier(value, label)
    path = _value(project["path"], _PROJECT, "GitLab target project path")
    iid = _identifier(pr["iid"], "merge request IID")
    head = _value(pr["sha"], _SHA, "fork head")
    revision = _value(pipe["sha"], _SHA, "selected revision")
    job_url = f"https://gitlab.com/{path}/-/jobs/{job_id}"
    _need(
        project["id"] == pr["target_project_id"] == pipe["project_id"] == project_id
        and pipe["id"] == pipeline_id
        and job["id"] == job_id
        and job["web_url"] == job_url
        and all(
            job["pipeline"][key] == pipe[key]
            for key in ("id", "project_id", "sha", "ref", "source")
        )
        and pr["source_project_id"] != project_id
        and pipe["source"] == "merge_request_event"
        and pipe["ref"] == f"refs/merge-requests/{iid}/merge"
        and merge["id"] == revision
        and isinstance(merge["parent_ids"], list)
        and len(merge["parent_ids"]) == 2
        and merge["parent_ids"][1] == head
        and _SHA.fullmatch(str(merge["parent_ids"][0])),
        "MR, fork head, target project, pipeline, job or merged-result commit do not agree",
    )
    name = _value(job["name"], _JOB, "job name")
    raw = _source_bytes(root, root / ".gitlab-ci.yml", "selected GitLab source")
    _need(
        hashlib.sha256(raw).hexdigest() == data["source_sha256"],
        "GitLab configuration differs from saved pipeline source",
    )
    cfg = _Config(raw.decode("utf-8"))
    cfg.owner((name,))
    detail = (
        _manual(data, cfg, name)
        if job["status"] == "manual"
        else _successful(data, root, cfg, pipe, name, job_url)
    )
    return {
        "repository": path,
        "project": project_id,
        "source_project": pr["source_project_id"],
        "pipeline": pipeline_id,
        "job": job_id,
        "job_name": name,
        "mr": iid,
        "fork_head": head,
        "revision": revision,
        "source_path": ".gitlab-ci.yml",
        "source_sha256": data["source_sha256"],
        "scope": _SCOPE,
        **detail,
    }


def mr_artifact_observation(
    snapshot: Path, root: Path, project: int, pipeline: int, job: int
) -> _Row:
    try:
        data = _load_job_receipt(snapshot)
        _need(
            data.get("schema") == "gitlab-mr-artifact-v1", "unsupported artifact observation schema"
        )
        return _assess(data, root.resolve(), project, pipeline, job)
    except RegistryJobError as exc:
        reason = str(exc)
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        reason = "required GitLab source, pipeline or artifact evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
