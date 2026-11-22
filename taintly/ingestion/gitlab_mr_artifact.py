"""Tie a target-project fork MR job to a retrieved managed job artifact."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from fnmatch import fnmatchcase
from io import BytesIO
from itertools import pairwise
from pathlib import Path
from typing import Any
from zipfile import is_zipfile

from taintly.ingestion.gitlab_coverage_source import coverage_source_observation
from taintly.ingestion.gitlab_registry_job import (
    _PROJECT,
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _owned_workflow_events,
    _parse_int,
    _source_bytes,
    _time,
    _unique_keys,
    _value,
)
from taintly.parsers.structural import Event, EventKind
from taintly.rules.gitlab.mr_publish import command_text

_Row = dict[str, Any]
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,100}(?::[A-Za-z0-9_.-]{1,100})?")
_FAILED_JOB = re.compile(r"[A-Za-z0-9_.-][A-Za-z0-9_.: -]{0,99}")
_PART = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_PATH = re.compile(rf"{_PART}(?:/{_PART})*")
_ARCHIVE_COMPONENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,239}"
_ARCHIVE_LISTED_PATH = re.compile(rf"(?:{_ARCHIVE_COMPONENT}/)?{_ARCHIVE_COMPONENT}")
_FAILED_COMMAND = (
    r"(?:\./gradlew(?: :[A-Za-z0-9:_-]{1,128}){1,2}|yarn [A-Za-z0-9:_-]{1,128}"
    rf"|yarn [A-Za-z0-9_][A-Za-z0-9:_-]{{0,127}} {_PART}(?:/{_PART})+)"
)
_BUILD = re.compile(r"(?:bun|yarn) run build(?::[a-z0-9:_-]+)?")
_MOVE = re.compile(rf"mv ({_PART}(?:/{_PART})*) ({_PART}(?:/{_PART})*)")
# Verified GitLab.com linux/amd64 Runner revisions, helper index and config
# digests, and the executable digest from the corresponding image layer.
_ARCHIVE_HELPERS = {
    "7a0f126423ab4aefa71be5cda32668e29bc59b2d": (
        "sha256:604025ad1395452e28268e5ca722452d8e3a3badfd7bee628941a6bfb7ead975",
        "sha256:060c57dea4e06ce034c9959e734771d2542983156682d85447a6f9152e64ecd4",
        "3da2f76c0857d674b22a300f078786494b248ea4f73ffd549afbb4a0e54c0c50",
    ),
    "d22d8753a6b96df6131d1d500decb4192d7f6f31": (
        "sha256:6fa6131930f0200667b536f3269fa038c09338763e864b80153b7bf0591d5bc8",
        "sha256:ea7a461bccb1b352892e9fbbf7430a63c0b9ffacd7b28ae6ca2e786ba4d34de2",
        "eda88cf7ce99060eb557f4d83f7937081bbe305d6bab9df5018d520a5fc8e810",
    ),
}
_CORRELATION = re.compile(r"[0-9a-f]{32}")
_EVENT = "$CI_PIPELINE_SOURCE == 'merge_request_event'"
_SAME_PROJECT = "$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID"
_SCOPE = (
    "Trusted saved GitLab project, job, runner and public artifact records. The reported "
    "authority covers the job-scoped archive upload only. Protected credentials, registry "
    "push, live Pages deployment and arbitrary content provenance remain separate questions."
)
_PAGES_SCOPE = (
    "This observation covers the deployment reported in the owning GitLab environment record "
    "for this Pages preview job. Serving the archive bytes at that URL, live access policy, "
    "other previews and production deployment remain unverified."
)
_FAILED_SCOPE = (
    "Trusted saved runner records report a job-scoped archive upload after script failure. "
    "The checkout and logged command identify the invocation. Effective configuration, "
    "the effect of PR code on the retrieved member, protected credentials and other "
    "destinations remain unverified."
)


_CANCELED_SCOPE = (
    "Trusted saved GitLab train, job and runner records describe the accepted archive request. "
    "The selected source checkout and final canceled status describe the same job. "
    "Archive bytes, retention, content provenance, wider credential grants and download audience "
    "require separate evidence."
)
_DETACHED_CANCELED_SCOPE = (
    "Trusted saved records bind the historical fork checkout and HTTP 201 archive response "
    "to a canceled job in the target project. Archive contents, current availability, "
    "the exact credential, and other permissions require separate evidence."
)
_ARTIFACT_ORIGIN = re.compile(
    r"https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
)
_CANONICAL_PROJECT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+")
_FORK_ARCHIVE_SCHEMA = "gitlab-fork-project-archive-v1"
_TARGET_HEAD_ARCHIVE_SCHEMA = "gitlab-target-project-head-archive-v1"
_TARGET_HEAD_ARCHIVE_SCOPE = (
    "Trusted saved GitLab records tie a fork head checkout to its accepted job archive "
    "in the target project. Effective configuration, exact credentials, content ancestry, "
    "deployment and present download access require separate evidence."
)
_TARGET_HEAD_DOWNLOAD_SCOPE = (
    "Trusted saved GitLab job and download records tie these ZIP bytes to the accepted "
    "target-project job archive. Effective configuration, exact credentials, content ancestry, "
    "present access and deployment remain unverified."
)
_MAX_FORK_ARCHIVE_BYTES = 5_000_000
_FORK_DOWNLOAD_SCOPE = (
    "Trusted saved GitLab job and download records tie these ZIP bytes to the accepted "
    "fork-job archive. Effective configuration, content ancestry, current access, broader "
    "audience and rights in the MR target project require separate evidence."
)
_FORK_ARCHIVE_SCOPE = (
    "Trusted saved GitLab MR, project, pipeline, job and runner records establish "
    "the accepted archive request for this job in the fork project. Artifact bytes, "
    "effective configuration, content ancestry, and authority in the MR target project "
    "require separate evidence."
)
_EXPLICIT_FORK_ARCHIVE_SCOPE = (
    "Trusted saved GitLab evidence identifies an accepted archive from a failed job in "
    "the fork project, on the explicitly selected origin. Artifact bytes, the exact "
    "credential, effective configuration and authority in the target project remain unverified."
)
_FORK_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")


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


def _archived_member(
    data: _Row, root: Path, job_url: str, end: datetime, selector: str | None = None
) -> _Row:
    artifact = data["artifact"]
    path = _value(artifact["path"], _PATH, "archive member path")
    url = f"{job_url}/artifacts/raw/{path}"
    _need(
        (selector is None or path.startswith(selector + "/"))
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
        "operation": "gitlab-job-artifact-upload",
        "authority": "gitlab-runner-job-scoped-upload",
        "target": url,
        "member_path": path,
        "sha256": digest,
    }


def _native_archive_authority(
    data: _Row,
    job_url: str,
    project_path: str,
    upload: _Row,
    *,
    phase_rows: tuple[_Row, _Row, _Row] | None = None,
    phase_owner: str = "fork",
) -> _Row:
    """Bind the known native uploader to this previously corroborated archive."""
    try:
        evidence = data["archive_runner_evidence"]
        job, pipe = data["job"], data["pipeline"]
        _need(
            _identifier(evidence["job"], "runner evidence job") == job["id"]
            and _identifier(evidence["pipeline"], "runner evidence pipeline") == pipe["id"]
            and evidence["revision"] == pipe["sha"]
            and evidence["trace_url"] == job_url + "/raw",
            "runner evidence belongs to another job, pipeline or revision",
        )
        revision = _value(evidence["runner_revision"], _SHA, "archive runner revision")
        _need(revision in _ARCHIVE_HELPERS, "runner is outside the verified archive profile")
        helper = _ARCHIVE_HELPERS[revision]
        _need(
            evidence["executor"] == "docker+machine"
            and (evidence["helper_index"], evidence["helper_config"]) == helper[:2],
            "runner or helper image is outside the verified archive profile",
        )
        cwd = f"/builds/{project_path}"
        _need(evidence["checkout_directory"] == cwd, "runner checkout directory does not match")
        lines = [
            _identifier(evidence[key], key)
            for key in (
                "runner_line",
                "helper_line",
                "archive_start_line",
                "archive_line",
                "archive_end_line",
            )
        ]
        start = _time(evidence["archive_start_time"], "archive stage start")
        finish = _time(evidence["archive_end_time"], "archive stage end")
        received = _time(evidence["archive_time"], "archive response")
        _need(
            all(a < b for a, b in pairwise(lines))
            and _time(job["started_at"], "job start")
            <= start
            <= received
            <= finish
            <= _time(job["finished_at"], "job end")
            and received == _time(upload["time"], "saved archive response"),
            "archive response does not match the recorded job and upload stage",
        )
        correlation = _value(evidence["correlation_id"], _CORRELATION, "archive correlation ID")
        trace_digest = _value(evidence["trace_sha256"], _SHA256, "runner trace digest")
        if phase_rows is None:
            # The compact trace already corroborates the successful upload.
            # Bind its original response identity before adding a credential.
            _need(
                upload.get("trace_sha256") == trace_digest
                and upload.get("correlation_id") == correlation
                and type(upload.get("line")) is int
                and upload["line"] == lines[3],
                "runner evidence does not match the verified merged-job archive response",
            )
        else:
            phase_start, phase_reply, phase_end = phase_rows
            phase_spans = [
                (
                    _identifier(row["line"], f"{phase_owner} archive trace line"),
                    _time(row["time"], f"{phase_owner} archive trace time"),
                )
                for row in (phase_start, phase_reply, phase_end)
            ]
            _need(
                trace_digest == upload.get("trace_sha256")
                and phase_spans == list(zip(lines[2:], (start, received, finish), strict=True))
                and f" correlation_id={correlation} " in phase_reply["value"],
                f"runner evidence does not match the verified {phase_owner} archive response",
            )
        return {
            "state": "native-archive-write-observed",
            "credential": "runner-job-token",
            "job": job["id"],
            "method": "POST",
            "route": f"jobs/{job['id']}/artifacts",
            "http_status": upload["http_status"],
            "correlation_id": correlation,
            "trace_sha256": trace_digest,
            "archive_response_line": lines[3],
            "runner_revision": revision,
            "checkout_directory": cwd,
            "helper_image_executable": "/usr/bin/gitlab-runner-helper",
            "helper_image_executable_sha256": helper[2],
            "scope": (
                "The verified helper image and Runner implementation bind the credential class to "
                "this job archive. The running process bytes, mounts, token instance, registry "
                "permissions and deployment permissions remain unverified."
            ),
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        reason = "saved archive runner evidence is incomplete or malformed"
    return {"state": "unresolved", "reason": reason}


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
    publication = _archived_member(data, root, job_url, end, selector)
    return {
        "state": "job-artifact-observed",
        "command": cmd,
        "command_line": build.line,
        "declaration_owner": owner,
        "artifact_path_line": selectors[0].line,
        "review_action": (
            "Review who can download this job archive. If a privileged deployment consumes it, "
            "verify the approved producer and revision, and compare the consumed member with "
            "an independently approved digest."
        ),
        "publication": publication,
    }


def _historical_head(
    data: _Row, path: str, project: int, pipeline: int, iid: int, profile: str
) -> str:
    captured = data[profile]
    event = "merge_train" if profile == "canceled_archive" else "merged_result"
    view, fork = captured["historical_pipeline"], captured["fork_commit"]
    head = _value(view["source_sha"], _SHA, "saved pipeline fork head")
    target = _value(view["target_sha"], _SHA, "saved pipeline target head")
    _need(
        view["url"] == f"https://gitlab.com/{path}/-/pipelines/{pipeline}.json"
        and _identifier(view["project"], "saved project") == project
        and _identifier(view["pipeline"], "saved pipeline") == pipeline
        and _identifier(view["mr"], "saved MR") == iid
        and view["event"] == event
        and view["revision"] == data["pipeline"]["sha"]
        and data["merge"]["parent_ids"] == [target, head]
        and _identifier(fork["project"], "saved fork project") == data["mr"]["source_project_id"]
        and fork["sha"] == head
        and _SHA256.fullmatch(str(view["sha256"]))
        and _SHA256.fullmatch(str(fork["receipt_sha256"])),
        "saved historical pipeline or fork revision does not match the selected MR",
    )
    return head


def _failed_upload(data: _Row, root: Path, job_url: str) -> _Row:
    job, pipeline = data["job"], data["pipeline"]
    log = data["failed_archive"]["log"]
    archives = [part for part in job["artifacts"] if part["file_type"] == "archive"]
    _need(
        job["status"] == "failed"
        and job["failure_reason"] == "script_failure"
        and len(archives) == 1
        and _identifier(archives[0]["size"], "saved archive size")
        and archives[0]["file_format"] == "zip"
        and all(job["pipeline"][key] == pipeline[key] for key in ("created_at", "updated_at"))
        and _identifier(log["job"], "runner trace job") == job["id"]
        and log["url"] == job_url + "/raw"
        and _SHA256.fullmatch(str(log["sha256"])),
        "saved trace and archive inventory do not identify a failed producer job",
    )
    start = _time(job["started_at"], "failed job start")
    end = _time(job["finished_at"], "failed job end")
    _need(
        _time(pipeline["created_at"], "owning pipeline creation")
        <= start
        <= end
        <= _time(pipeline["updated_at"], "owning pipeline last update"),
        "selected failed job is outside the recorded pipeline window",
    )
    section_start = r"00O\+section_start:([0-9]{1,12}):"
    section_end = r"00O section_end:([0-9]{1,12}):"
    checkout = (
        f"01O Checking out {pipeline['sha'][:8]} as detached HEAD (ref is {pipeline['ref']})..."
    )
    patterns = (
        section_start + "get_sources",
        re.escape(checkout),
        section_end + "get_sources",
        section_start + "step_script",
        rf"01O \$ ({_FAILED_COMMAND})",
        section_end + "step_script",
        section_start + "upload_artifacts_on_failure",
        rf"01E ({_PART}(?:/{_PART})*/?): found ([1-9][0-9]*) matching artifact files and directories",
        r'01E Uploading artifacts as "archive" to coordinator\.\.\. 201 Created +'
        r"(?:correlation_id=(?:[0-9a-f]+|[0-9a-f]{16}-[A-Z]{3}) +)?"
        rf"id={job['id']} (?:responseStatus=201 Created )?status=201(?: Created)?",
        section_end + "upload_artifacts_on_failure",
        r"00O ERROR: Job failed: exit code [1-9][0-9]{0,2}",
    )
    rows = log["rows"]
    _need(
        isinstance(rows, list) and len(rows) == len(patterns),
        "saved runner log is missing the complete failure-upload sequence",
    )
    times, markers = [], []
    for row, pattern in zip(rows, patterns, strict=True):
        time, value = row["time"], row["value"]
        when = _time(time, "failed job trace time")
        marker = (
            re.fullmatch(pattern, value) if isinstance(value, str) and len(value) <= 1024 else None
        )
        if not marker or hashlib.sha256(f"{time} {value}".encode()).hexdigest() != row["sha256"]:
            raise RegistryJobError("saved failure-upload line does not match its evidence or phase")
        _need(
            not pattern.startswith((section_start, section_end))
            or int(marker[1]) == int(when.timestamp()),
            "runner section epoch conflicts with its trace timestamp",
        )
        times.append(when)
        markers.append(marker)
    _need(
        start <= times[0] and times[-1] <= end and all(a < b for a, b in pairwise(times)),
        "saved failure-upload lines are outside the job or out of phase order",
    )
    member = _archived_member(data, root, job_url, end)
    selection, count = markers[7].groups()
    # Runner recursively enumerates a literal directory even when the path has no trailing slash.
    directory = selection.endswith("/") or count != "1"
    _need(
        member["member_path"].startswith(selection.rstrip("/") + "/")
        if directory
        else member["member_path"] == selection,
        "retrieved member is outside the runner-reported artifact selection",
    )
    return {
        "state": "job-artifact-uploaded-after-failure",
        "command": markers[4][1],
        "command_basis": "runner-step-script",
        "job_status": "failed",
        "runner_selection": selection,
        "effective_configuration": "unverified",
        "member_origin": "unverified",
        "scope": _FAILED_SCOPE,
        "publication": {
            **member,
            "http_status": 201,
            "upload_at": rows[8]["time"],
            "upload_line_sha256": rows[8]["sha256"],
            "trace_sha256": log["sha256"],
        },
    }


def _canceled_upload(data: _Row, job_url: str) -> _Row:
    job, pipeline = data["job"], data["pipeline"]
    log = data["canceled_archive"]["log"]
    archives = [item for item in job["artifacts"] if item["file_type"] == "archive"]
    _need(
        job["status"] == pipeline["status"] == "canceled"
        and len(archives) == 1
        and _identifier(archives[0]["size"], "saved archive size")
        and archives[0]["file_format"] == "zip"
        and all(job["pipeline"][key] == pipeline[key] for key in ("created_at", "updated_at"))
        and _identifier(log["job"], "runner trace job") == job["id"]
        and log["url"] == job_url + "/raw"
        and _SHA256.fullmatch(str(log["sha256"])),
        "saved trace and archive inventory do not identify the canceled producer job",
    )
    reply = (
        r'01E Uploading artifacts as "archive" to coordinator\.\.\. 201 Created +'
        rf"correlation_id=[0-9a-f]{{32}} id={job['id']} status=201"
    )
    phase, response = _archive_upload_rows(log, pipeline, job, reply, "canceled-job")
    return {
        "state": "job-artifact-accepted-canceled-job",
        "job_status": "canceled",
        "upload_phase": phase,
        "scope": _CANCELED_SCOPE,
        "publication": _archive_receipt(job_url, log, response, archives[0]["size"]),
    }


def _archive_receipt(job_url: str, log: _Row, response: _Row, size: int) -> _Row:
    return {
        "operation": "gitlab-runner-job-archive",
        "artifact_type": "archive",
        "authority": "owning-job-upload",
        "http_status": 201,
        "reported_at": response["time"],
        "upload_line_sha256": response["sha256"],
        "trace_sha256": log["sha256"],
        "target": job_url + "/artifacts/download",
        "inventory_bytes": size,
        "retrieval": "unverified",
    }


def _archive_upload_rows(
    log: _Row,
    pipeline: _Row,
    job: _Row,
    reply: str,
    label: str,
    *,
    accept_plain_start: bool = False,
    live_parent_observed_at: datetime | None = None,
) -> tuple[str, _Row]:
    _need("rows_format" not in log, "unsupported timestamped archive runner row format")
    rows = log["rows"]
    _need(
        isinstance(rows, list) and len(rows) == 8,
        "saved runner trace lacks the complete checkout, script and archive phase sequence",
    )
    start_prefix = r"00O[+ ]section_start:" if accept_plain_start else r"00O\+section_start:"
    upload_phase = re.fullmatch(
        start_prefix + r"[0-9]{1,12}:(upload_artifacts_on_(?:success|failure))",
        str(rows[5]["value"]),
    )
    if upload_phase is None:
        raise RegistryJobError("the saved result is outside a supported runner upload phase")
    phase = upload_phase[1]
    start = start_prefix + r"([0-9]{1,12}):"
    end = r"00O section_end:([0-9]{1,12}):"
    checkout = (
        f"01O Checking out {pipeline['sha'][:8]} as detached HEAD (ref is {pipeline['ref']})..."
    )
    patterns = (
        start + "get_sources",
        re.escape(checkout),
        end + "get_sources",
        start + "step_script",
        end + "step_script",
        start + phase,
        reply,
        end + phase,
    )
    times = []
    job_label = label.replace("-", " ")
    for row, pattern in zip(rows, patterns, strict=True):
        value = row["value"]
        stamp = row["time"]
        when = _time(stamp, f"{job_label} trace time")
        line = (
            re.fullmatch(pattern, value) if isinstance(value, str) and len(value) <= 1024 else None
        )
        if line is None or hashlib.sha256(f"{stamp} {value}".encode()).hexdigest() != row["sha256"]:
            raise RegistryJobError(f"saved {label} line does not match its owning runner phase")
        _need(
            not line.lastindex or int(line[1]) == int(when.timestamp()),
            "runner section epoch conflicts with its trace timestamp",
        )
        times.append(when)
    ties = {index for index, (left, right) in enumerate(pairwise(times)) if left == right}
    if ties:
        # An end marker and the next phase's start marker can be emitted
        # together. Their saved row positions must independently show order.
        _need(ties <= {2, 4}, "shared trace time is outside a runner phase transition")
        positions = [_identifier(row.get("line"), "runner trace row position") for row in rows]
        _need(
            all(left < right for left, right in pairwise(positions)),
            "shared trace time lacks ordered runner row positions",
        )
    parent_updated_at = _time(pipeline["updated_at"], "owning pipeline last update")
    if live_parent_observed_at is not None:
        _need(
            parent_updated_at <= live_parent_observed_at,
            "live pipeline receipt predates the saved parent update",
        )
    _need(
        _time(pipeline["created_at"], "owning pipeline creation")
        <= _time(job["started_at"], f"{job_label} start")
        <= times[0]
        < times[-1]
        <= _time(job["finished_at"], f"{job_label} end")
        <= (live_parent_observed_at or parent_updated_at)
        and all(a <= b for a, b in pairwise(times)),
        f"saved {label} runner rows are outside the job or out of phase order",
    )
    return phase, rows[6]


def _detached_archive(
    data: _Row,
    root: Path,
    project_id: int,
    pipeline_id: int,
    job_id: int,
    *,
    target_owned: bool,
    origin: str | None = None,
) -> _Row:
    target, fork, mr = data["target"], data["fork"], data["mr"]
    pipeline, job, log = data["pipeline"], data["job"], data["log"]
    explicit_origin = origin is not None
    canceled = (
        explicit_origin and target_owned and not (pipeline["status"] == job["status"] == "failed")
    )
    base = origin or "https://gitlab.com"
    source_path = _value(
        fork["path_with_namespace"], _CANONICAL_PROJECT, "GitLab fork project path"
    )
    target_path = _value(target["path_with_namespace"], _CANONICAL_PROJECT, "GitLab MR target path")
    source_project = _identifier(fork["id"], "fork project")
    destination = _identifier(target["id"], "MR target project")
    iid = _identifier(mr["iid"], "merge request IID")
    revision = _value(pipeline["sha"], _SHA, "detached pipeline revision")
    ref = (
        f"refs/merge-requests/{iid}/head"
        if target_owned
        else _value(mr["source_branch"], _FORK_BRANCH, "MR source branch")
    )
    fork_url = f"{base}/{source_path}"
    target_url = f"{base}/{target_path}"
    owner = destination if target_owned else source_project
    owning_url = target_url if target_owned else fork_url
    pipeline_url = f"{owning_url}/-/pipelines/{pipeline_id}"
    job_url = f"{owning_url}/-/jobs/{job_id}"
    _need(
        project_id == owner
        and source_project == _identifier(mr["source_project_id"], "MR source project")
        and destination == _identifier(mr["target_project_id"], "MR target project")
        and source_project != destination
        and source_path != target_path
        and fork["forked_from"] == {"id": destination, "path_with_namespace": target_path}
        and fork["web_url"] == fork_url
        and target["web_url"] == target_url
        and mr["web_url"] == f"{target_url}/-/merge_requests/{iid}",
        "requested project does not own this target-project job or match the recorded fork"
        if target_owned
        else "requested project does not own this fork job or match the recorded MR target",
    )
    membership = data["mr_pipeline"]
    current_head = _value(mr["sha"], _SHA, "current MR head")
    history = data.get("historical_pipeline")
    live_fork = (
        not target_owned
        and not explicit_origin
        and pipeline["status"] == "running"
        and history is None
        and job["status"] in {"success", "failed"}
    )
    if explicit_origin:
        _need(
            not {
                "archive_download",
                "archive_runner_evidence",
                "archive_member_origin",
                "failed_archive",
                "canceled_archive",
                "pages_preview",
                "publication_admission",
            }.intersection(data),
            "explicit origin covers only the selected job's archive acceptance",
        )
    if canceled:
        _need(
            pipeline["status"] == job["status"] == "canceled"
            and isinstance(history, dict)
            and revision == job["commit"]["id"],
            "the selected origin requires a canceled target-project job with historical checkout evidence",
        )
    elif explicit_origin:
        _need(
            pipeline["status"] == job["status"] == "failed"
            and history is None
            and revision == current_head == job["commit"]["id"],
            "the selected origin requires a failed target-project job at the recorded MR head"
            if target_owned
            else "the selected origin requires a failed fork-owned job at the recorded MR head",
        )
    elif target_owned:
        _need(
            not {
                "historical_pipeline",
                "archive_member_origin",
                "failed_archive",
                "canceled_archive",
                "pages_preview",
                "publication_admission",
            }.intersection(data)
            and pipeline["status"] == job["status"]
            and job["status"] in {"success", "failed"}
            and revision == current_head == job["commit"]["id"],
            "target-project archive requires a matching terminal job at the recorded fork head",
        )
    _need(
        _identifier(pipeline["id"], "detached pipeline") == pipeline_id
        and pipeline["project_id"] == owner
        and pipeline["source"] == "merge_request_event"
        and (live_fork or canceled or pipeline["status"] in {"success", "failed"})
        and pipeline["ref"] == ref
        and pipeline["web_url"] == pipeline_url
        and all(
            membership[key] == pipeline[key]
            for key in ("id", "project_id", "sha", "ref", "web_url")
        )
        and revision == data["commit"]["id"]
        and (revision == current_head or isinstance(history, dict))
        and data["commit"]["web_url"] == f"{fork_url}/-/commit/{revision}",
        "saved fork commit, current MR head or pipeline membership does not agree",
    )
    if "historical_pipeline" in data:
        _need(
            isinstance(history, dict)
            and history["url"] == pipeline_url + ".json"
            and _identifier(history["project"], "saved pipeline owner") == owner
            and _identifier(history["pipeline"], "saved detached pipeline") == pipeline_id
            and history["mr_url"] == mr["web_url"]
            and history["event"] == "detached"
            and history["source"] == pipeline["source"]
            and history["revision"] == revision
            and history["ref"] == ref
            and history["created_at"] == pipeline["created_at"]
            and _SHA256.fullmatch(str(history["sha256"])),
            "saved detached pipeline does not match the selected fork, MR or checkout",
        )
    archives = [item for item in job["artifacts"] if item["file_type"] == "archive"]
    status = job.get("status")
    success = status == "success"
    expected_failure = None if success or canceled else "script_failure"
    _need(
        _identifier(job["id"], "fork job") == job_id
        and job["web_url"] == job_url
        and (canceled or success or status == "failed")
        and job.get("failure_reason") == expected_failure
        and (not live_fork or job["commit"]["id"] == revision)
        and all(
            job["pipeline"][key] == pipeline[key]
            for key in ("id", "project_id", "sha", "ref", "source")
        )
        and (
            not explicit_origin
            or all(
                job["pipeline"][key] == pipeline[key]
                for key in ("status", "created_at", "updated_at", "web_url")
            )
        )
        and len(archives) == 1
        and _identifier(archives[0]["size"], "saved archive size")
        and archives[0]["file_format"] == "zip"
        and _identifier(log["job"], "fork runner trace job") == job_id
        and log["url"] == job_url + "/raw"
        and _SHA256.fullmatch(str(log["sha256"])),
        "saved runner trace and archive inventory do not match the target-project job"
        if target_owned
        else (
            "saved runner trace and archive inventory do not match the fork-owned successful job"
            if success
            else "saved runner trace and archive inventory do not match the fork-owned failed job"
        ),
    )
    source_hash = hashlib.sha256(
        _source_bytes(root, root / ".gitlab-ci.yml", "selected fork GitLab source")
    ).hexdigest()
    _need(
        source_hash == data["source_sha256"], "GitLab configuration differs from saved fork source"
    )
    correlation = (
        r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
        if explicit_origin
        else r"(?:[0-9a-f]{32}|[0-9a-f]{16}-[A-Z]{3})"
    )
    # The reviewed hosted Windows custom executor also relays successful uploads on stdout.
    windows_runner = not explicit_origin and _hosted_windows_archive_runner(job)
    accepts_stdout = windows_runner or (target_owned and status == "failed")
    receipt_stream = r"01[EO]" if accepts_stdout else "01E"
    reply = (
        rf'{receipt_stream} Uploading artifacts as "archive" to coordinator\.\.\. 201 Created +'
        rf"correlation_id={correlation} id={job_id} (?:status=201|responseStatus=201 Created)"
    )
    trace_label = "target-project-job" if target_owned else "fork-job"
    live_parent_observed_at = None
    if live_fork:
        receipt = data.get("live_pipeline_receipt")
        if not (
            isinstance(receipt, dict)
            and receipt.get("url")
            == f"https://gitlab.com/api/v4/projects/{owner}/pipelines/{pipeline_id}"
            and type(receipt.get("http_status")) is int
            and receipt["http_status"] == 200
            and isinstance(receipt.get("sha256"), str)
            and _SHA256.fullmatch(receipt["sha256"])
        ):
            raise RegistryJobError(
                "the completed fork job needs a dated observation of its live pipeline"
            )
        live_parent_observed_at = _time(receipt.get("observed_at"), "live pipeline observation")
    phase, response = _archive_upload_rows(
        log,
        pipeline,
        job,
        reply,
        trace_label,
        accept_plain_start=canceled,
        live_parent_observed_at=live_parent_observed_at,
    )
    expected_phase = "upload_artifacts_on_success" if success else "upload_artifacts_on_failure"
    _need(
        phase == expected_phase,
        "fork archive is outside the success-upload phase"
        if success
        else "fork archive is outside the failure-upload phase",
    )
    windows_stdout_receipt = windows_runner and response["value"].startswith("01O ")
    if target_owned or explicit_origin or windows_stdout_receipt or live_fork:
        source_file = data.get("source_file")
        expected_url = (
            f"{base}/api/v4/projects/{source_project}/"
            f"repository/files/.gitlab-ci.yml?ref={revision}"
        )
        _need(
            isinstance(source_file, dict)
            and source_file["url"] == expected_url
            and source_file["file_path"] == ".gitlab-ci.yml"
            and source_file["commit_id"] == revision
            and source_file["content_sha256"] == source_hash
            and (not windows_stdout_receipt or job["commit"]["id"] == revision),
            "saved fork configuration record does not match the selected checkout and bytes",
        )
    publication = _archive_receipt(job_url, log, response, archives[0]["size"])
    result = {
        "state": (
            "target-project-head-archive-accepted-canceled-job"
            if canceled
            else "target-project-head-archive-upload-observed"
            if target_owned
            else "fork-project-archive-upload-observed"
        ),
        "repository": target_path if target_owned else source_path,
        "project": owner,
        "target_repository": target_path,
        "target_project": destination,
        "pipeline": pipeline_id,
        "job": job_id,
        "mr": iid,
        "revision": revision,
        "source_path": ".gitlab-ci.yml",
        "source_sha256": source_hash,
        "job_status": status,
        "upload_phase": phase,
        "scope": (
            _DETACHED_CANCELED_SCOPE
            if canceled
            else _TARGET_HEAD_ARCHIVE_SCOPE
            if target_owned
            else _EXPLICIT_FORK_ARCHIVE_SCOPE
            if explicit_origin
            else _FORK_ARCHIVE_SCOPE
        ),
        "publication": publication,
    }
    if explicit_origin:
        result["origin"] = base
    if live_parent_observed_at is not None:
        result["pipeline_status"] = pipeline["status"]
    if target_owned:
        result["source_repository"] = source_path
        result["source_project"] = source_project
        result["job_name"] = _value(job["name"], _FAILED_JOB, "target-project job name")
    if "archive_tree" in data:
        result["archive_tree"] = (
            _archive_tree_member(data["archive_tree"], root, result)
            if not explicit_origin
            else {"state": "unresolved", "reason": "archive tree requires a GitLab.com job"}
        )
    if "archive_windows_helper" in data:
        result["archive_windows_helper"] = (
            _windows_archive_helper(data["archive_windows_helper"], log, job)
            if (target_owned and not explicit_origin) or windows_stdout_receipt
            else {
                "state": "unresolved",
                "reason": "requires the reviewed GitLab.com Windows upload profile",
            }
        )
    if isinstance(history, dict):
        result["historical_pipeline"] = {
            "url": history["url"],
            "sha256": history["sha256"],
            "current_mr_head": current_head,
        }
    if "archive_runner_evidence" in data:
        result["archive_runner_authority"] = _native_archive_authority(
            data,
            job_url,
            target_path if target_owned else source_path,
            {
                "time": response["time"],
                "http_status": publication["http_status"],
                "trace_sha256": log["sha256"],
            },
            phase_rows=(log["rows"][-3], response, log["rows"][-1]),
            phase_owner="target-project" if target_owned else "fork",
        )
    archive_bytes = None
    if "archive_download" in data:
        download, archive_bytes = _detached_archive_download(data, root, result, target_owned)
        result["archive_download"] = download
        if download["state"] != "unresolved":
            publication["retrieval"] = "verified"
            result["scope"] = download["scope"]
    if "pages_handoff" in data:
        if live_fork:
            result["pages_handoff"] = {
                "state": "unresolved",
                "reason": "Pages handoff needs a terminal fork pipeline inventory",
            }
        else:
            from taintly.ingestion.gitlab_pages_handoff import pages_handoff

            result["pages_handoff"] = pages_handoff(data, root)
    if "archive_member_origin" in data:
        result["archive_member_origin"] = coverage_source_observation(
            data, root, archive_bytes, result
        )
    if live_parent_observed_at is not None:
        result["scope"] += " The parent pipeline was still running in the saved observation."
    return result


def _hosted_windows_archive_runner(job: _Row) -> bool:
    runner, manager = job.get("runner"), job.get("runner_manager")
    return (
        isinstance(runner, dict)
        and isinstance(manager, dict)
        and manager.get("revision") == "d22d8753"
        and runner.get("is_shared") is True
        and runner.get("description") == "k8s.saas-windows-medium-amd64.runners-manager.gitlab.com"
    )


def _windows_archive_helper(evidence: _Row, log: _Row, job: _Row) -> _Row:
    """Bind the helper's reported version to the owned upload phase."""
    try:
        _need(
            _identifier(evidence["job"], "Windows uploader job") == log["job"]
            and evidence["trace_url"] == log["url"]
            and evidence["trace_sha256"] == log["sha256"]
            and evidence["executor"] == "custom"
            and _hosted_windows_archive_runner(job),
            "Windows uploader evidence belongs to another trace or executor",
        )
        start, response, _ = log["rows"][-3:]
        version, revision, platform = evidence["banner"]
        rows = (start, version, revision, platform, response)
        _need(
            all(
                _identifier(a["line"], "Windows uploader trace line")
                < _identifier(b["line"], "Windows uploader trace line")
                and _time(a["time"], "Windows uploader trace time")
                <= _time(b["time"], "Windows uploader trace time")
                for a, b in pairwise(rows)
            ),
            "Windows helper banner is outside the owning archive request",
        )
        _need(
            (
                version["value"],
                revision["value"],
                platform["value"],
            )
            == (
                "01O Version:      19.3.0",
                "01O Git revision: 9cbf0074",
                "01O OS/Arch:      windows/amd64",
            )
            and all(
                hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
                == row["sha256"]
                for row in (version, revision, platform)
            ),
            "Windows helper banner does not match the reviewed release",
        )
        return {
            "state": "windows-helper-version-reported",
            "executor": "custom",
            "platform": "windows/amd64",
            "version": "19.3.0",
            "revision": "9cbf0074ddb0e2f79d79f44406cafebf09117b64",
            "banner_lines": [row["line"] for row in (version, revision, platform)],
            "archive_response_line": response["line"],
            "scope": (
                "The upload phase reports the helper version. The reviewed stock uploader uses "
                "the runner job-token class for the archive POST. Actual process bytes, "
                "credential identity, and permission beyond this operation remain unverified."
            ),
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (KeyError, TypeError, ValueError, AttributeError):
        reason = "Windows helper evidence is incomplete or malformed"
    return {"state": "unresolved", "reason": reason}


def _archive_tree_member(receipt: _Row, root: Path, result: _Row) -> _Row:
    """Verify one file from the owned archive's root or one directory listing."""
    try:
        project, job = result["project"], result["job"]
        member = _value(receipt["member"], _ARCHIVE_LISTED_PATH, "archive member")
        directory, _, basename = member.rpartition("/")
        url = f"https://gitlab.com/api/v4/projects/{project}/jobs/{job}/artifacts/tree"
        if directory:
            url += f"?path={directory}"
        _need(
            _identifier(receipt["project"], "archive tree project") == project
            and _identifier(receipt["job"], "archive tree job") == job
            and receipt["url"] == url
            and _identifier(receipt["status"], "archive tree HTTP status") == 200
            and _time(receipt["observed_at"], "archive tree observation time")
            >= _time(result["publication"]["reported_at"], "archive upload time"),
            "archive tree receipt does not match the selected job and upload",
        )
        raw = _source_bytes(root, root / "archive-tree.json", "archive tree", max_bytes=131_072)
        digest = hashlib.sha256(raw).hexdigest()
        _need(digest == receipt["sha256"], "saved archive tree does not match its receipt")
        entries = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_keys, parse_int=_parse_int
        )
        _need(isinstance(entries, list), "saved archive tree is not a native listing")
        matches = [
            entry
            for entry in entries
            if isinstance(entry, dict)
            and (entry.get("path") == member or (not directory and entry.get("name") == basename))
        ]
        _need(
            len(matches) == 1
            and matches[0].get("name") == basename
            and matches[0].get("path") == member
            and matches[0].get("type") == "file"
            and type(matches[0].get("size")) is int
            and matches[0]["size"] >= 0,
            "saved archive tree does not identify the selected root file uniquely"
            if not directory
            else "saved archive tree does not identify the selected file uniquely",
        )
        return {
            "state": "archive-member-listed",
            "member": member,
            "member_bytes": matches[0]["size"],
            "url": url,
            "observed_at": receipt["observed_at"],
            "tree_sha256": digest,
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError, OverflowError):
        reason = "saved archive tree receipt is incomplete or malformed"
    return {"state": "unresolved", "reason": reason}


def _recorded_archive_download(
    receipt: _Row, root: Path, result: _Row, target_owned: bool
) -> tuple[_Row, bytes]:
    publication = result["publication"]
    size = publication["inventory_bytes"]
    responses = receipt["responses"]
    _need(
        _identifier(receipt["job"], "download job") == result["job"]
        and receipt["url"] == publication["target"]
        and isinstance(responses, list)
        and 1 <= len(responses) <= 2
        and all(isinstance(row, dict) and type(row.get("status")) is int for row in responses)
        and responses
        in (
            [{"status": 200, "host": "gitlab.com"}],
            [
                {"status": 302, "host": "gitlab.com"},
                {"status": 200, "host": "cdn.artifacts.gitlab-static.net"},
            ],
        )
        and _time(receipt["observed_at"], "archive download time")
        >= _time(publication["reported_at"], "archive upload time"),
        "download receipt does not identify the selected job archive"
        if target_owned
        else "download receipt does not identify the selected fork job archive",
    )
    _need(
        type(receipt["bytes"]) is int
        and 0 < size <= _MAX_FORK_ARCHIVE_BYTES
        and receipt["bytes"] == size,
        "download receipt differs from the bounded job archive inventory",
    )
    content = _source_bytes(
        root,
        root / "published-archive.zip",
        "target-project job archive" if target_owned else "fork job archive",
        max_bytes=size,
    )
    digest = hashlib.sha256(content).hexdigest()
    _need(
        len(content) == size and receipt["sha256"] == digest and is_zipfile(BytesIO(content)),
        "saved archive differs from the downloaded ZIP size or digest",
    )
    return {
        "state": (
            "target-project-archive-retrieved" if target_owned else "fork-project-archive-retrieved"
        ),
        "target": publication["target"],
        "sha256": digest,
        "bytes": size,
        "observed_at": receipt["observed_at"],
        "scope": _TARGET_HEAD_DOWNLOAD_SCOPE if target_owned else _FORK_DOWNLOAD_SCOPE,
    }, content


def _detached_archive_download(
    data: _Row, root: Path, result: _Row, target_owned: bool
) -> tuple[_Row, bytes | None]:
    try:
        return _recorded_archive_download(data["archive_download"], root, result, target_owned)
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        reason = "required archive download evidence is missing or malformed"
    scope = _TARGET_HEAD_DOWNLOAD_SCOPE if target_owned else _FORK_DOWNLOAD_SCOPE
    return {"state": "unresolved", "reason": reason, "scope": scope}, None


def _recorded_pages_account(evidence: _Row, job: _Row, pipe: _Row, deployment: int) -> _Row:
    try:
        _need(
            _identifier(evidence["job_id"], "account job ID") == job["id"]
            and _identifier(evidence["pipeline_id"], "account pipeline ID") == pipe["id"]
            and evidence["sha"] == pipe["sha"]
            and _identifier(evidence["deployment_id"], "account deployment ID") == deployment,
            "account evidence does not belong to the owning job, revision and deployment",
        )
        account = _identifier(evidence["deployment_user_id"], "deployment account ID")
        _need(
            _identifier(evidence["job_user_id"], "owning job account ID") == account,
            "the saved job and deployment accounts do not agree",
        )
    except RegistryJobError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (KeyError, TypeError):
        return {"state": "unresolved", "reason": "saved deployment account evidence is malformed"}
    return {
        "state": "deployment-account-recorded",
        "account_id": account,
        "scope": "GitLab records this account on the exact preview deployment and job. "
        "The credential, wider permissions and future access remain unverified.",
    }


def _recorded_pages_preview(
    data: _Row, cfg: _Config, detail: _Row, path: str, job_url: str
) -> _Row:
    saved, job, pipe = data["pages_preview"], data["job"], data["pipeline"]
    name = job["name"]
    pages, env = (name, "pages"), (name, "environment")
    cfg.owner(pages)
    cfg.owner(env)
    env_fields = {key[-1] for key in cfg.keys if key[:-1] == env}
    _need(
        {"name", "url"} <= env_fields <= {"name", "url", "action", "auto_stop_in"}
        and ("action" not in env_fields or cfg.scalar((*env, "action")).value == "start"),
        "source does not declare a supported start environment for the Pages preview",
    )
    variable_owners = {name, "workflow"}
    if cfg.keys[(name, "extends")]:
        parent = _value(cfg.scalar((name, "extends")).value, _JOB, "local preview job template")
        cfg.owner((parent,))
        _need(
            parent != name
            and not any(cfg.keys[(parent, field)] for field in ("extends", "environment", "pages")),
            "job inherits unsupported Pages or environment settings",
        )
        variable_owners.add(parent)
    _need(
        not any(
            key[-2:] == ("variables", "CI_COMMIT_REF_SLUG")
            and (len(key) == 2 or key[0] in variable_owners)
            for key in cfg.keys
        ),
        "source overrides the supported Pages preview slug variable",
    )
    _need(
        detail["state"] == "job-artifact-observed"
        and detail["publication"]["member_path"] == "public/index.html"
        and {key[-1] for key in cfg.keys if key[:-1] == pages} == {"path_prefix", "expire_in"}
        and cfg.scalar((*pages, "path_prefix")).value == "$CI_COMMIT_REF_SLUG"
        and cfg.scalar((*env, "url")).value == "$CI_PAGES_URL",
        "source is outside the supported default-directory Pages preview profile",
    )
    environment_name = cfg.scalar((*env, "name"))
    literal = re.fullmatch(
        r"([a-z][a-z0-9_-]{0,40})/\$CI_COMMIT_REF_SLUG", str(environment_name.value)
    )
    if literal is None:
        raise RegistryJobError("source does not declare the supported Pages preview environment")
    _need(
        saved["job_id"] == job["id"]
        and type(saved["job_id"]) is int
        and saved["job_name"] == name
        and saved["url"] == f"{job_url}.json"
        and _SHA256.fullmatch(str(saved["sha256"]))
        and saved["action"] == "start",
        "saved GitLab job view does not identify the selected Pages preview job",
    )
    environment = saved["environment"]
    current = environment["last_deployment"]
    environment_id = _identifier(environment["id"], "Pages environment ID")
    deployment = _identifier(current["id"], "Pages deployment ID")
    iid = _identifier(current["iid"], "Pages deployment IID")
    prefix = str(environment["name"]).removeprefix(f"{literal[1]}/")
    namespace, project_path = path.split("/", 1)
    target = f"https://{namespace}.gitlab.io/{project_path}/{prefix}"
    _need(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?", prefix)
        and environment["name"] == f"{literal[1]}/{prefix}"
        and environment["external_url"] == target
        and environment["state"] in {"available", "stopped"},
        "saved environment does not identify the exact supported Pages preview target",
    )
    _need(
        saved["status"] == "last"
        and current["is_last"] is True
        and current["status"] == "success"
        and current["sha"] == pipe["sha"]
        and current["ref"] == pipe["ref"]
        and current["web_path"] == f"/{path}/-/environments/{environment_id}/deployments/{iid}"
        and current["deployable"]
        == {
            "name": name,
            "build_path": job_url.removeprefix("https://gitlab.com"),
        },
        "latest Pages preview deployment does not belong to the selected job and revision",
    )
    completed = _time(current["deployed_at"], "preview deployment time")
    _need(
        _time(job["pipeline"]["created_at"], "preview pipeline creation")
        <= _time(current["created_at"], "preview deployment creation")
        <= _time(job["started_at"], "preview job start")
        <= _time(job["finished_at"], "preview job end")
        <= completed
        <= _time(job["pipeline"]["updated_at"], "preview pipeline last update")
        <= _time(saved["observed_at"], "preview record observation"),
        "Pages deployment timestamps are inconsistent with the selected pipeline and job",
    )
    preview: _Row = {
        "state": "pages-preview-deployment-recorded",
        "operation": "gitlab-pages-preview-environment-deployment",
        "environment_id": environment_id,
        "deployment_id": deployment,
        "environment_state": environment["state"],
        "target": target,
        "deployed_at": current["deployed_at"],
        "availability": "unverified",
        "source_line": environment_name.line,
        "evidence_url": saved["url"],
        "evidence_sha256": saved["sha256"],
        "scope": _PAGES_SCOPE,
    }
    if "account" in saved:
        preview["account"] = _recorded_pages_account(saved["account"], job, pipe, deployment)
    return preview


def _pages_preview(data: _Row, cfg: _Config, detail: _Row, path: str, job_url: str) -> _Row:
    try:
        return _recorded_pages_preview(data, cfg, detail, path, job_url)
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        reason = "required Pages source or deployment evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _PAGES_SCOPE}


def _npm_gate(cfg: _Config, name: str) -> tuple[str, str, int, list[int]]:
    cfg.owner((name,))
    _need(
        not any(
            cfg.keys[(name, key)] for key in ("rules", "only", "except", "parallel", "trigger")
        ),
        "publisher overrides the supported local template",
    )
    parent = _value(cfg.scalar((name, "extends")).value, _JOB, "publisher template")
    cfg.owner((parent,))
    cfg.owner((parent, "rules"))
    _need(
        not any(cfg.keys[(parent, key)] for key in ("only", "except", "parallel", "trigger")),
        "publisher template has unsupported admission fields",
    )
    builtin = "CI_MERGE_REQUEST_SOURCE_PROJECT_ID"
    _need(
        not any(key[-2:] == ("variables", builtin) for key in cfg.keys),
        "source overrides the project identity used by the declared gate",
    )
    fields = {"<<", "if", "when", "allow_failure"}
    by_rule = {key[2] for key in cfg.keys if len(key) == 4 and key[:2] == (parent, "rules")}
    _need(
        by_rule == {0, 1}
        and all(
            len(key) == 4 and key[-1] in fields and count == 1 and key[2] in by_rule
            for key, count in cfg.keys.items()
            if len(key) > 2 and key[:2] == (parent, "rules")
        )
        and all(
            len(key) == 4 and key[-1] in fields and key[2] in by_rule and len(values) == 1
            for key, values in cfg.leaves.items()
            if len(key) > 2 and key[:2] == (parent, "rules")
        ),
        "publisher rule list is outside the supported two-rule profile",
    )
    lines = []
    for i in (0, 1):
        rule = (parent, "rules", i)
        rows = cfg.leaves.get((*rule, "if"), [])
        _need(
            len(rows) == 1
            and isinstance(rows[0].value, str)
            and rows[0].value_kind in {"plain", "quoted"},
            "unsupported condition in the publisher rule list",
        )
        condition = rows[0].value
        if not isinstance(condition, str):
            raise RegistryJobError("publisher condition is not a string")
        clause = r'\$[A-Z_]+\s*==\s*(?:\$[A-Z_]+|"[A-Za-z0-9_.-]+"|null)'
        _need(
            re.fullmatch(rf"{clause}(?:\s*&&\s*{clause}){{0,4}}", condition)
            and f"${builtin} == null" in {item.strip() for item in condition.split("&&")}
            and len(cfg.leaves.get((*rule, "when"), [])) == 1
            and cfg.leaves[(*rule, "when")][0].value == "manual",
            "publisher rules do not require an absent merge-request source project",
        )
        lines.append(rows[0].line)

    commands = cfg.sequence((name, "script"))
    _need(len(commands) == 2, "publisher script is outside the supported npm shape")
    selector, command = (command_text(row, cfg.lines) or "" for row in commands)
    match = re.fullmatch(
        r'export ([A-Z_]+)="\$\((?:find) (tmp/packages) -name "([A-Za-z0-9_.-]+)\*\.tgz" -type f\)"',
        selector,
    )
    if match is None:
        raise RegistryJobError("publisher lacks a bounded archive selector")
    variable, directory, prefix = match.groups()
    _need(
        re.fullmatch(rf"npm publish --tag \$[A-Z_]+ --access public \${variable}", command),
        "requested job is outside the non-dry-run npm publication profile",
    )
    _need(
        cfg.scalar((parent, "id_tokens", "NPM_ID_TOKEN", "aud")).value == "npm:registry.npmjs.org",
        "publisher has no supported configured npm identity audience",
    )
    needs = (parent, "needs")
    expected_need = {(*needs, 0, "job"), (*needs, 0, "artifacts")}
    _need(
        {key for key in cfg.keys if len(key) > 2 and key[:2] == needs} == expected_need
        and {key for key in cfg.leaves if key[:2] == needs} == expected_need
        and cfg.scalar((parent, "needs", 0, "artifacts")).value == "true"
        and not cfg.keys[(name, "needs")]
        and not cfg.keys[(name, "id_tokens")],
        "publisher does not identify one local artifact-producing job",
    )
    producer = _value(cfg.scalar((parent, "needs", 0, "job")).value, _JOB, "publisher artifact job")
    paths = cfg.sequence((producer, "artifacts", "paths"))
    _need(
        len(paths) == 1 and paths[0].value == directory, "package archive directory does not match"
    )
    return producer, prefix, commands[-1].line, lines


def _complete_page(packet: _Row, rows: object, expected_url: str, after: object) -> None:
    _need(
        packet["url"] == expected_url
        and _identifier(packet["page"], "inventory page") == 1
        and _identifier(packet["total_pages"], "inventory pages") == 1
        and packet["next_page"] == ""
        and isinstance(rows, list)
        and 1 <= len(rows) <= 100
        and _identifier(packet["total"], "inventory total") == len(rows)
        and _time(packet["observed_at"], "inventory time") >= _time(after, "inventory lower bound"),
        "inventory is missing, incomplete or unowned",
    )


def _npm_admission(data: _Row, cfg: _Config, path: str, name: str) -> _Row:
    try:
        publisher = _value(name, _JOB, "requested npm publisher")
        producer, prefix, line, gates = _npm_gate(cfg, publisher)
        packet = data["publication_inventory"]
        rows = packet["jobs"]
        pipe, job = data["pipeline"], data["job"]
        owning_pipeline = job["pipeline"]
        url = f"https://gitlab.com/api/v4/projects/{pipe['project_id']}/pipelines/{pipe['id']}/jobs"
        _need(owning_pipeline["status"] in ("success", "failed"), "parent pipeline is unfinished")
        _complete_page(
            packet, rows, url + "?per_page=100&include_retried=true", owning_pipeline["updated_at"]
        )
        if "updated_at" in pipe:
            _need(
                _time(packet["observed_at"], "inventory time")
                >= _time(pipe["updated_at"], "pipeline evidence update"),
                "inventory predates the supplied pipeline update",
            )
        ids = set()
        for row in rows:
            identifier = _identifier(row["id"], "inventory job")
            owned = row["pipeline"]
            job_name = row["name"]
            _need(
                isinstance(job_name, str) and job_name.isprintable() and bool(job_name.strip()),
                "inventory has an unnamed or malformed job",
            )
            _need(
                identifier not in ids
                and all(
                    owned[key] == pipe[key] for key in ("id", "project_id", "sha", "ref", "source")
                )
                and row["web_url"] == f"https://gitlab.com/{path}/-/jobs/{identifier}",
                "job inventory contains duplicate or different pipeline evidence",
            )
            ids.add(identifier)
        _need(
            any(
                row["id"] == job["id"]
                and row["name"] == job["name"]
                and row["status"] == job["status"]
                for row in rows
            )
            and all(
                row["name"] != publisher and not row["name"].startswith(publisher + ":")
                for row in rows
            ),
            "requested publisher is present or selected artifact job is absent",
        )
        sources = [row for row in rows if row["name"] == producer]
        _need(
            len(sources) == 1
            and sources[0]["status"] == "success"
            and sources[0]["archive_present"] is True,
            "publisher's declared producer lacks a unique completed archive job",
        )
        origin = sources[0]
        _need(
            _time(owning_pipeline["created_at"], "pipeline creation")
            <= _time(origin["started_at"], "producer start")
            <= _time(origin["finished_at"], "producer finish")
            <= _time(owning_pipeline["updated_at"], "pipeline update"),
            "archive producer is outside the recorded pipeline window",
        )
        listing = data["publisher_artifact_listing"]
        entries = listing["entries"]
        tree_url = (
            f"https://gitlab.com/api/v4/projects/{pipe['project_id']}/jobs/{origin['id']}"
            "/artifacts/tree?path=tmp%2Fpackages&per_page=100"
        )
        _complete_page(listing, entries, tree_url, origin["finished_at"])
        candidates = [
            entry
            for entry in entries
            if entry["type"] == "file" and fnmatchcase(entry["name"], prefix + "*.tgz")
        ]
        _need(
            len(candidates) == 1 and _identifier(candidates[0]["size"], "package size"),
            "saved producer directory does not show one matching top-level file",
        )
        item = candidates[0]
        member = _value(item["path"], _PATH, "matching package path")
        _need(
            member == f"tmp/packages/{item['name']}", "package path is outside the saved directory"
        )
        return {
            "state": "publish-job-absent",
            "job_name": publisher,
            "operation": "npm-publish",
            "command_line": line,
            "local_rule_lines": gates,
            "local_rules_using_recorded_source_project": "do-not-match",
            "artifact_producer": origin["web_url"],
            "archive_member": member,
            "matching_archive": f"{origin['web_url']}/artifacts/raw/{member}",
            "recursive_selection": "unverified",
            "configured_oidc_audience": "npm:registry.npmjs.org",
            "effective_configuration": "unverified",
            "authorization": "unverified",
            "scope": "The named npm publisher is absent from this saved pipeline. "
            "The visible local rules require no MR source project. The saved directory "
            "shows a matching file. Recursive selection, historical includes, runtime "
            "settings and other publication routes remain unverified.",
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        reason = "required publisher source or pipeline inventory is unavailable or malformed"
    return {"state": "unresolved", "reason": reason}


def _assess(
    data: _Row,
    root: Path,
    project_id: int,
    pipeline_id: int,
    job_id: int,
    publisher: str | None,
) -> _Row:
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
    failed_archive = "failed_archive" in data
    canceled_archive = "canceled_archive" in data
    _need(not (failed_archive and canceled_archive), "conflicting archive observation profiles")
    profile = "canceled_archive" if canceled_archive else "failed_archive"
    ref_suffix = "train" if canceled_archive else "merge"
    head = (
        _historical_head(data, path, project_id, pipeline_id, iid, profile)
        if failed_archive or canceled_archive
        else _value(pr["sha"], _SHA, "fork head")
    )
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
        and pipe["ref"] == f"refs/merge-requests/{iid}/{ref_suffix}"
        and merge["id"] == revision
        and isinstance(merge["parent_ids"], list)
        and len(merge["parent_ids"]) == 2
        and merge["parent_ids"][1] == head
        and _SHA.fullmatch(str(merge["parent_ids"][0])),
        "MR, fork head, target project, pipeline, job or merged-result commit do not agree",
    )
    name = _value(
        job["name"], _FAILED_JOB if failed_archive or canceled_archive else _JOB, "job name"
    )
    raw = _source_bytes(root, root / ".gitlab-ci.yml", "selected GitLab source")
    _need(
        hashlib.sha256(raw).hexdigest() == data["source_sha256"],
        "GitLab configuration differs from saved pipeline source",
    )
    if canceled_archive:
        _need(
            publisher is None and "pages_preview" not in data,
            "canceled archive evidence covers its own upload only",
        )
        detail = _canceled_upload(data, job_url)
    elif failed_archive:
        detail = _failed_upload(data, root, job_url)
        if publisher is not None:
            detail["publication_admission"] = {
                "state": "unresolved",
                "reason": "the runner response does not establish npm publisher admission",
            }
        if "pages_preview" in data:
            detail["pages_preview"] = {
                "state": "unresolved",
                "reason": "the failure-upload profile does not establish a Pages deployment",
            }
    else:
        cfg = _Config(raw.decode("utf-8"))
        cfg.owner((name,))
        detail = (
            _manual(data, cfg, name)
            if job["status"] == "manual"
            else _successful(data, root, cfg, pipe, name, job_url)
        )
        if publisher is not None:
            detail["publication_admission"] = _npm_admission(data, cfg, path, publisher)
        if "pages_preview" in data:
            detail["pages_preview"] = _pages_preview(data, cfg, detail, path, job_url)
    if "archive_runner_evidence" in data:
        if failed_archive:
            log = data["failed_archive"]["log"]
            start, _, response, end, _ = log["rows"][-5:]
            detail["archive_runner_authority"] = _native_archive_authority(
                data,
                job_url,
                path,
                {
                    "time": response["time"],
                    "http_status": detail["publication"]["http_status"],
                    "trace_sha256": log["sha256"],
                },
                phase_rows=(start, response, end),
                phase_owner="failed-job",
            )
        elif detail["state"] == "job-artifact-observed":
            detail["archive_runner_authority"] = _native_archive_authority(
                data, job_url, path, data["trace"][-1]
            )
        else:
            detail["archive_runner_authority"] = {
                "state": "unresolved",
                "reason": "runner evidence requires an observed successful job archive",
            }
    if "pages_publication" in data:
        from taintly.ingestion.gitlab_pages_publication import pages_publication

        detail["pages_publication"] = pages_publication(data, root, detail)
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
    snapshot: Path,
    root: Path,
    project: int,
    pipeline: int,
    job: int,
    *,
    publisher: str | None = None,
    origin: str | None = None,
) -> _Row:
    scope = _DETACHED_CANCELED_SCOPE if origin is not None else _SCOPE
    try:
        data = _load_job_receipt(snapshot)
        _need(
            "pages_handoff" not in data
            or (data.get("schema") == _FORK_ARCHIVE_SCHEMA and origin is None),
            "Pages handoff requires a GitLab.com fork-project archive observation",
        )
        _need(
            "pages_publication" not in data
            or (data.get("schema") == "gitlab-mr-artifact-v1" and origin is None),
            "Pages publication requires a GitLab.com target-project merge observation",
        )
        if origin is not None:
            _need(
                isinstance(origin, str)
                and len(origin) <= 253
                and _ARTIFACT_ORIGIN.fullmatch(origin),
                "the expected artifact origin must be a bare HTTPS hostname",
            )
            _need(
                publisher is None
                and data.get("schema") in (_FORK_ARCHIVE_SCHEMA, _TARGET_HEAD_ARCHIVE_SCHEMA),
                "the explicit origin requires a detached archive observation schema",
            )
            target_owned = data["schema"] == _TARGET_HEAD_ARCHIVE_SCHEMA
            if target_owned:
                saved_pipeline, saved_job = data.get("pipeline"), data.get("job")
                scope = (
                    _TARGET_HEAD_ARCHIVE_SCOPE
                    if isinstance(saved_pipeline, dict)
                    and isinstance(saved_job, dict)
                    and saved_pipeline.get("status") == saved_job.get("status") == "failed"
                    else _DETACHED_CANCELED_SCOPE
                )
            else:
                scope = _EXPLICIT_FORK_ARCHIVE_SCOPE
            return _detached_archive(
                data,
                root.resolve(),
                project,
                pipeline,
                job,
                target_owned=target_owned,
                origin=origin,
            )
        from taintly.ingestion.gitlab_branch_image import SCHEMA, SCOPE, branch_image_observation

        if data.get("schema") == SCHEMA:
            scope = SCOPE
            _need(
                publisher is None, "the image observation does not assess npm publisher admission"
            )
            return branch_image_observation(data, root.resolve(), project, pipeline, job)
        if data.get("schema") in (_FORK_ARCHIVE_SCHEMA, _TARGET_HEAD_ARCHIVE_SCHEMA):
            target_owned = data["schema"] == _TARGET_HEAD_ARCHIVE_SCHEMA
            scope = _TARGET_HEAD_ARCHIVE_SCOPE if target_owned else _FORK_ARCHIVE_SCOPE
            _need(
                publisher is None,
                "target-project archive evidence covers its own upload only"
                if target_owned
                else "fork archive evidence covers its own upload only",
            )
            return _detached_archive(
                data, root.resolve(), project, pipeline, job, target_owned=target_owned
            )
        _need(
            data.get("schema") == "gitlab-mr-artifact-v1", "unsupported artifact observation schema"
        )
        return _assess(data, root.resolve(), project, pipeline, job, publisher)
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
    return {"state": "unresolved", "reason": reason, "scope": scope}
