"""Tie a target-project fork MR job to a retrieved managed job artifact."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from fnmatch import fnmatchcase
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
    if publisher is not None:
        detail["publication_admission"] = _npm_admission(data, cfg, path, publisher)
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
) -> _Row:
    try:
        data = _load_job_receipt(snapshot)
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
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
