"""Correlate trusted saved GitLab.com records for a pre-job fork admission stop."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from taintly.ingestion.gitlab_registry_job import (
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _record,
    _time,
    _value,
)

_Row = dict[str, Any]
_ORIGIN = "https://gitlab.com"
_SCHEMA = "gitlab-fork-admission-v1"
_STATE = "fork-pipeline-admission-blocked"
_REASON = "The pipeline failed due to the user not being verified."
_EVENT = "merge_request_event"
_PATH = r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+"
_MR_SUFFIX = re.compile(rf"{re.escape(_ORIGIN)}/{_PATH}/-/merge_requests/[1-9][0-9]{{0,17}}")
_PROJECT_PATH = re.compile(_PATH)
_SCOPE = (
    "This check covers a recorded pre-job identity verification stop for the selected "
    "GitLab.com fork pipeline. Other pipelines, upload permissions and current admission "
    "policy require separate evidence."
)


def _require(condition: object, message: str) -> None:
    if not condition:
        raise RegistryJobError(message)


def _source(sources: _Row, name: str, url: str) -> _Row:
    source = _record(sources[name], f"{name} source")
    _require(
        type(source["status"]) is int and source["status"] == 200 and source["url"] == url,
        f"{name} must be the selected successful GitLab response",
    )
    _value(source["sha256"], _SHA256, f"{name} response digest")
    return source


def _assess(receipt: _Row, project: int, pipeline: int) -> _Row:
    _require(receipt.get("schema") == _SCHEMA, "unsupported GitLab fork admission schema")
    observed_at = receipt["observed_at"]
    if isinstance(observed_at, str) and observed_at.endswith("+00:00"):
        observed_at = observed_at.removesuffix("+00:00") + "Z"
    observed = _time(observed_at, "admission receipt time")
    sources = receipt["sources"]
    api = f"{_ORIGIN}/api/v4/projects"
    pipeline_url = f"{api}/{project}/pipelines/{pipeline}"
    rest = _source(sources, "pipeline", pipeline_url)["body"]
    revision = _value(rest["sha"], _SHA, "pipeline revision")
    _require(
        _identifier(rest["id"], "pipeline") == pipeline
        and _identifier(rest["project_id"], "pipeline project") == project
        and rest["source"] == _EVENT,
        "pipeline does not identify the requested MR execution context",
    )
    graph_url = sources["graphql"]["url"]
    parsed = urlsplit(graph_url)
    _require(
        parsed.scheme == "https"
        and parsed.netloc == "gitlab.com"
        and parsed.path == "/api/graphql"
        and bool(parsed.query)
        and not parsed.fragment,
        "GraphQL evidence must be from GitLab.com",
    )
    graph_body = _source(sources, "graphql", graph_url)["body"]
    _require(not graph_body.get("errors"), "GitLab GraphQL reply contains errors")
    graph_project = graph_body["data"]["project"]
    repository = _value(graph_project["fullPath"], _PROJECT_PATH, "fork repository")
    graph = graph_project["pipeline"]
    _require(
        rest["web_url"] == f"{_ORIGIN}/{repository}/-/pipelines/{pipeline}"
        and graph["id"] == f"gid://gitlab/Ci::Pipeline/{pipeline}"
        and graph["source"] == _EVENT
        and graph["sha"] == revision
        and graph["ref"] == rest["ref"],
        "REST and GraphQL refer to different pipeline identities",
    )
    mr = sources["mr"]["body"]
    target = _identifier(mr["target_project_id"], "target project")
    iid = _identifier(mr["iid"], "merge request")
    mr_url = _value(mr["web_url"], _MR_SUFFIX, "merge request URL")
    _require(
        target != project
        and _identifier(mr["source_project_id"], "MR source project") == project
        and mr_url.endswith(f"/-/merge_requests/{iid}"),
        "the selected pipeline is outside its owning fork project",
    )
    mr_api = f"{api}/{target}/merge_requests/{iid}"
    _source(sources, "mr", mr_api)
    membership = _source(sources, "mr_pipelines", mr_api + "/pipelines?per_page=12")["body"]
    membership_error = (
        "the saved MR pipeline membership does not identify the selected fork revision"
    )
    _require(isinstance(membership, list), membership_error)
    matches = [
        row for row in membership if _identifier(row["id"], "MR pipeline membership") == pipeline
    ]
    _require(len(matches) == 1, membership_error)
    member = matches[0]
    _require(
        _identifier(member["project_id"], "MR pipeline owner") == project
        and member["source"] == _EVENT
        and member["sha"] == revision
        and member["ref"] == rest["ref"],
        membership_error,
    )
    _require(
        rest["status"] == "failed"
        and graph["status"] == "FAILED"
        and rest["started_at"] is None
        and graph["startedAt"] is None
        and rest["yaml_errors"] is None
        and graph["yamlErrors"] is False
        and graph["failureReason"] == _REASON,
        "GitLab does not report the supported verification stop before pipeline start",
    )
    finished = _time(rest["finished_at"], "pipeline failure time")
    _require(
        finished <= observed
        and finished.replace(microsecond=0) == _time(graph["finishedAt"], "GraphQL failure time"),
        "REST and GraphQL describe different failure times",
    )
    jobs = _source(sources, "jobs", pipeline_url + "/jobs?include_retried=true&per_page=25")
    _require(
        jobs["body"] == [] and jobs["next_page"] == "",
        "complete selected-pipeline job inventory must be empty",
    )
    return {
        "state": _STATE,
        "repository": repository,
        "project": project,
        "pipeline": pipeline,
        "target_project": target,
        "mr": iid,
        "revision": revision,
        "failure_time": finished.isoformat(),
        "reason": "GitLab reported that user verification was required before the pipeline started",
        "publication": "not-reached",
        "scope": _SCOPE,
    }


def fork_admission_observation(snapshot: Path, project: int, pipeline: int) -> _Row:
    """Read an explicit historical receipt without querying GitLab or evaluating a job."""
    try:
        return _assess(
            _load_job_receipt(snapshot),
            _identifier(project, "requested project"),
            _identifier(pipeline, "requested pipeline"),
        )
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        reason = "required GitLab fork admission evidence is malformed or missing"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
