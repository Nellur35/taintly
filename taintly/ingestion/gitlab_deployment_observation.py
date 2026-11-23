"""Bind a saved GitLab.com environment deployment to its selected CI job."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from taintly.ingestion.gitlab_mr_artifact import _Config, _need, _Row
from taintly.ingestion.gitlab_package_file import _Pipeline, _response
from taintly.ingestion.gitlab_registry_job import (
    _PROJECT,
    _SHA256,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _record,
    _source_bytes,
    _time,
    _value,
)

_SCHEMA = "gitlab-environment-deployment-v1"
_ORIGIN = "https://gitlab.com"
_PATH = ".gitlab-ci.yml"
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,100}")
_ENV = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
_SCOPE = (
    "This assessment covers one saved GitLab environment deployment and its owning CI job. "
    "Historical effective configuration, approver identity, downstream service writes, "
    "job credentials and future deployment authority require separate evidence."
)


def _source_plan(data: _Row, root: Path, run: _Pipeline, job: str, target: str) -> _Row:
    url = f"{_ORIGIN}/api/v4/projects/{run.project}/repository/files/{_PATH}?ref={run.revision}"
    row = _record(_response(data, "source", url).get("row"), "source row")
    digest = _value(row.get("content_sha256"), _SHA256, "workflow SHA-256")
    raw = _source_bytes(root, root / _PATH, "workflow source")
    _need(
        row.get("file_path") == _PATH
        and row.get("commit_id") == run.revision
        and hashlib.sha256(raw).hexdigest() == digest,
        "workflow source does not match the selected pipeline revision",
    )
    cfg = _Config(raw.decode("utf-8"))
    cfg.owner((job,))
    owner = job
    if cfg.keys[(job, "extends")]:
        owner = _value(cfg.scalar((job, "extends")).value, _NAME, "local job template")
        cfg.owner((owner,))
        _need(
            owner.startswith(".")
            and not cfg.keys[(owner, "extends")]
            and not cfg.keys[(job, "environment")],
            "environment inheritance is outside the single-template profile",
        )
    environment = cfg.scalar((owner, "environment", "name"))
    fields = {key[2] for key in cfg.keys if key[:2] == (owner, "environment") and len(key) == 3}
    _need(
        environment.value == target
        and (
            "action" not in fields or cfg.scalar((owner, "environment", "action")).value == "start"
        ),
        "workflow does not declare this deployment target for the selected job",
    )
    return {
        "path": _PATH,
        "revision": run.revision,
        "sha256": digest,
        "job": job,
        "environment_owner": owner,
        "environment_line": environment.line,
    }


def _job_row(row: object, run: _Pipeline, job: int, repository: str) -> _Row:
    entry: _Row = _record(row, "job row")
    _need(
        _identifier(entry.get("id"), "job") == job
        and entry.get("web_url") == f"{_ORIGIN}/{repository}/-/jobs/{job}"
        and _Pipeline.read(entry.get("pipeline"), run.project, repository) == run
        and _record(entry.get("commit"), "job commit").get("id") == run.revision
        and entry.get("ref") == run.ref,
        "job evidence belongs to another invocation or revision",
    )
    return entry


def _state(deployment: _Row, job: _Row, run_row: _Row) -> str:
    deployment_status = deployment.get("status")
    execution = (job["started_at"], job["finished_at"])
    if deployment_status in ("blocked", "created"):
        expected_job = "manual" if deployment_status == "blocked" else "pending"
        _need(
            job.get("status") == expected_job
            and execution == (None, None)
            and job.get("runner_assigned") is False,
            "deployment state conflicts with the selected job lifecycle",
        )
        return (
            "deployment-blocked-before-job"
            if deployment_status == "blocked"
            else "deployment-created-job-pending"
        )
    _need(
        deployment_status == "success"
        and job.get("status") == "success"
        and _time(run_row["created_at"], "pipeline creation")
        <= _time(execution[0], "job start")
        <= _time(execution[1], "job finish")
        <= _time(deployment["updated_at"], "deployment update"),
        "GitLab does not corroborate a supported deployment outcome",
    )
    return "deployment-reported-success"


def _observe(
    data: _Row, root: Path, project: int, pipeline: int, job: int, deployment: int
) -> _Row:
    _need(data.get("schema") == _SCHEMA, "unsupported GitLab environment deployment schema")
    base = f"{_ORIGIN}/api/v4/projects/{project}"
    project_row = _record(_response(data, "project", base)["row"], "project row")
    _need(
        _identifier(project_row.get("id"), "project") == project
        and project_row["ci_config_path"] in (None, "", _PATH),
        "project or workflow path is outside the supported profile",
    )
    repository = _value(project_row.get("path_with_namespace"), _PROJECT, "project path")
    _need(project_row.get("web_url") == f"{_ORIGIN}/{repository}", "project URL does not match")
    pipeline_url = f"{base}/pipelines/{pipeline}"
    run_row: _Row = _record(_response(data, "pipeline", pipeline_url)["row"], "pipeline row")
    run = _Pipeline.read(run_row, project, repository)
    _need(run.id == pipeline, "saved pipeline does not match the requested pipeline")
    job_url = f"{base}/jobs/{job}"
    selected = _job_row(_response(data, "job", job_url)["row"], run, job, repository)
    deployment_url = f"{base}/deployments/{deployment}"
    deployed: _Row = _record(_response(data, "deployment", deployment_url)["row"], "deployment row")
    _need(
        _identifier(deployed.get("id"), "deployment") == deployment
        and deployed.get("sha") == run.revision
        and deployed.get("ref") == run.ref,
        "deployment evidence belongs to another source or target invocation",
    )
    embedded = _job_row(deployed.get("deployable"), run, job, repository)
    fields = ("name", "status", "started_at", "finished_at", "runner_assigned")
    _need(
        all(
            field in selected and field in embedded and selected[field] == embedded[field]
            for field in fields
        ),
        "job and deployment describe different job states",
    )
    name = _value(selected["name"], _NAME, "job name")
    env = _record(deployed.get("environment"), "environment row")
    target = _value(env.get("name"), _ENV, "deployment environment")
    state = _state(deployed, selected, run_row)
    pending = deployed.get("pending_approval_count")
    approval = (
        {"state": "pending-reported", "count": pending}
        if state == "deployment-blocked-before-job" and type(pending) is int and pending > 0
        else {"state": "unresolved"}
    )
    return {
        "state": state,
        "repository": repository,
        "project": project,
        "pipeline": pipeline,
        "pipeline_event": run.event,
        "pipeline_status": run_row.get("status"),
        "job": job,
        "job_name": name,
        "job_status": selected["status"],
        "deployment": deployment,
        "target": {"id": _identifier(env.get("id"), "environment"), "name": target},
        "approval": approval,
        "source": _source_plan(data, root, run, name, target),
        "evidence": {"pipeline": pipeline_url, "job": job_url, "deployment": deployment_url},
        "scope": _SCOPE,
    }


def deployment_observation(
    receipt: Path, root: Path, project: int, pipeline: int, job: int, deployment: int
) -> _Row:
    """Assess an explicit saved receipt without network calls or credential access."""
    try:
        return _observe(_load_job_receipt(receipt), root, project, pipeline, job, deployment)
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "required GitLab environment deployment evidence is malformed or missing"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
