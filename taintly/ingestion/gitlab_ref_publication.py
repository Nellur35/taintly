"""Correlate trusted saved GitLab publisher, checkout and native ref evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from taintly.ingestion.gitlab_mr_artifact import _Config, _need, _Row
from taintly.ingestion.gitlab_registry_job import (
    _PROJECT,
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _source_bytes,
    _time,
    _value,
)

_SCHEMA = "gitlab-production-ref-v1"
_JOB = "deploy-production"
_BRANCH = "production"
_SCOPE = (
    "Trusted saved GitLab.com source and provider evidence. The report covers the selected "
    "job and production branch. Compiled workflow bytes, credential instances, historical "
    "policy and permission for a future request require separate evidence."
)
_PREFIX = re.compile(r"[0-9a-f]{6,40}")
_MR = re.compile(r"refs/merge-requests/([1-9][0-9]{0,17})/merge")
_CREDENTIAL = "GITLAB_JOB_DEPLOY_PRODUCTION_ACCESS_TOKEN"
_COMMON_PATH = ".gitlab/ci_templates/cki-common.yml"
_TEMPLATE_PATH = ".gitlab/ci_templates/cki-templates.yml"
_CONFIGURED_COMMAND = (
    "if [[ ${CI_COMMIT_BRANCH:-} != production ]]; then git push --force --no-verify "
    '"https://git:${GITLAB_JOB_DEPLOY_PRODUCTION_ACCESS_TOKEN}@${CI_SERVER_HOST}/'
    '${CI_PROJECT_PATH}.git" "HEAD:refs/heads/${DEPLOY_TAG}"; fi'
)


def _configuration(root: Path, data: _Row, filename: str, label: str) -> _Config:
    raw = _source_bytes(root, root / filename, label)
    _need(
        hashlib.sha256(raw).hexdigest() == _value(data["content_sha256"], _SHA256, label),
        f"{label} does not match the supplied source digest",
    )
    text = raw.decode("utf-8").replace("\r\n", "\n")
    # Preserve evidence line numbers when accepting one opening document marker.
    if text.startswith("---\n"):
        text = text[3:]
    return _Config(text)


def _shared_template(data: _Row, cfg: _Config, root: Path, revision: str) -> _Config:
    common, template = data["shared_common"], data["historical_template"]
    repository = _value(template["repository"], _PROJECT, "shared template repository")
    template_revision = _value(template["commit_id"], _SHA, "historical template revision")
    _need(
        common["repository"] == repository
        and common["file_path"] == _COMMON_PATH
        and template["file_path"] == _TEMPLATE_PATH,
        "shared materialization belongs to another project or path",
    )
    include: tuple[object, ...] = ("include", 0)
    if cfg.keys[(*include, "local")]:
        _need(
            cfg.scalar((*include, "local")).value == _COMMON_PATH
            and repository == data["repository"]
            and common["commit_id"] == revision,
            "local shared configuration does not belong to the selected source revision",
        )
    else:
        _need(
            cfg.scalar((*include, "project")).value == repository
            and cfg.scalar((*include, "file")).value == _COMMON_PATH
            and cfg.scalar((*include, "ref")).value == _BRANCH
            and common["commit_id"] == template_revision,
            "project include does not identify the shared configuration",
        )
    reader = _configuration(root, common, "cki-common.yml", "shared configuration")
    url = f"https://gitlab.com/{repository}/-/raw/{_BRANCH}/{_TEMPLATE_PATH}"
    remote = [
        key
        for key in reader.leaves
        if len(key) == 3
        and key[0] == "include"
        and key[2] == "remote"
        and reader.scalar(key).value == url
    ]
    _need(len(remote) == 1, "shared configuration does not identify the recorded template include")
    return _configuration(root, template, "cki-templates.yml", "shared template")


def _source_plan(data: _Row, root: Path, revision: str) -> _Row:
    source, template = data["source"], data["historical_template"]
    _need(source["commit_id"] == revision, "root source does not own the selected checkout")
    cfg = _configuration(root, source, ".gitlab-ci.yml", "root configuration")
    library = _shared_template(data, cfg, root, revision)
    inherit = cfg.scalar((_JOB, "extends"))
    names = [entry.value for entry in library.sequence((".deploy_production_tag", "extends"))]
    target = library.scalar((".deploy_production", "variables", "DEPLOY_TAG"))
    commands = library.sequence((".deploy_tag", "script"))
    for template_name in (".deploy_production_tag", ".deploy_production", ".deploy_tag"):
        library.owner((template_name,))
    inheritance_keys = {key[-1] for key in library.keys if key[:-1] == (".deploy_production_tag",)}
    _need(
        inherit.value == ".deploy_production_tag"
        and not any(
            key[:-1] == (_JOB,) and key[-1] not in {"extends", "variables"} for key in cfg.keys
        )
        and {key[-1] for key in cfg.keys if key[:-1] == (_JOB, "variables")} <= {"DEPLOY_GIT_TAG"}
        and cfg.keys[(_JOB, "variables")] <= 1
        and inheritance_keys == {"extends"}
        and library.scalar((".deploy_production", "extends")).value == ".deploy"
        and not library.keys[(".deploy_tag", "extends")]
        and names == [".deploy_production", ".deploy_tag"]
        and target.value == _BRANCH
        and commands[0].value == _CONFIGURED_COMMAND,
        "the saved configuration is outside the supported production ref source shape",
    )
    return {
        "root_path": ".gitlab-ci.yml",
        "root_line": inherit.line,
        "template_repository": template["repository"],
        "template_revision": template["commit_id"],
        "template_line": commands[0].line,
        "configured_credential_reference": _CREDENTIAL,
    }


def _job_identity(data: _Row, project: int, pipeline: int, job: int) -> _Row:
    run, selected = data["pipeline"], data["job"]
    path = _value(data["repository"], _PROJECT, "project path")
    url = f"https://gitlab.com/{path}/-"
    revision = _value(run["sha"], _SHA, "pipeline checkout")
    _need(
        _identifier(run["project_id"], "pipeline project") == project
        and _identifier(run["id"], "pipeline") == pipeline
        and _identifier(selected["id"], "job") == job
        and (selected["project_id"], selected["pipeline_id"], selected["revision"])
        == (project, pipeline, revision)
        and run["web_url"] == f"{url}/pipelines/{pipeline}"
        and selected["web_url"] == f"{url}/jobs/{job}"
        and selected["ref"] == run["ref"]
        and selected["name"] == _JOB,
        "pipeline, job, project or checkout evidence belongs to another invocation",
    )
    return {
        "repository": path,
        "project": project,
        "pipeline": pipeline,
        "job": job,
        "revision": revision,
    }


def _unstarted(data: _Row, identity: _Row) -> _Row:
    run, job, trace = data["pipeline"], data["job"], data["trace"]
    mr, parents = data["mr"], data["checkout_parents"]
    ref = _MR.fullmatch(run["ref"])
    _need(
        ref is not None
        and int(ref[1]) == _identifier(mr["iid"], "merge request")
        and mr["target_project_id"] == identity["project"]
        and _identifier(mr["source_project_id"], "fork project") != identity["project"]
        and isinstance(parents, list)
        and len(parents) == 2
        and _value(parents[0], _SHA, "target parent")
        and _value(parents[1], _SHA, "fork parent") == mr["source_head"],
        "saved evidence does not identify a target-owned fork merged result",
    )
    membership = data["mr_pipeline"]
    _need(
        (membership["id"], membership["project_id"], membership["sha"], membership["ref"])
        == (identity["pipeline"], identity["project"], identity["revision"], run["ref"]),
        "saved MR pipeline membership conflicts with the selected invocation",
    )
    _need(
        job["status"] in {"manual", "skipped"}
        and job["runner_id"] is None
        and job["started_at"] is None
        and job["finished_at"] is None
        and type(trace["bytes"]) is int
        and trace["bytes"] == 0
        and trace["sha256"] == hashlib.sha256(b"").hexdigest()
        and "ref_event" not in data,
        "the saved publisher is not established as unstarted",
    )
    return {
        "state": "fork-publisher-not-started",
        "job_status": job["status"],
        "mr": mr["iid"],
        "fork_project": mr["source_project_id"],
        "fork_parent": mr["source_head"],
        "publication": "not-reached",
    }


def _current_rule(data: _Row, identity: _Row, actor: int, event_time: str) -> _Row:
    if "policy" not in data:
        return {"state": "unresolved", "reason": "saved exact branch rule is missing"}
    policy = data["policy"]
    project, branch = identity["project"], _BRANCH
    _need(
        policy["url"] == f"https://gitlab.com/api/v4/projects/{project}/protected_branches/{branch}"
        and policy["rule"]["name"] == branch
        and policy["rule"]["inherited"] is False
        and _time(event_time, "ref event") <= _time(policy["read_at"], "policy read"),
        "current branch rule belongs to another ref, project or time",
    )
    rule = _identifier(policy["rule"]["id"], "project branch rule")
    entries = [
        entry
        for entry in policy["push_entries"]
        if type(entry["user_id"]) is int
        and entry["user_id"] == actor
        and entry["group_id"] is None
        and entry["deploy_key_id"] is None
    ]
    if len(entries) != 1:
        return {
            "state": "unresolved",
            "reason": "no unique user-specific push entry for the recorded writer",
        }
    return {
        "state": "writer-listed-in-current-project-rule",
        "rule": rule,
        "entry": _identifier(entries[0]["id"], "push permission entry"),
        "actor": actor,
        "read_at": policy["read_at"],
    }


def _observed_write(data: _Row, identity: _Row) -> _Row:
    run, job, trace, event = data["pipeline"], data["job"], data["trace"], data["ref_event"]
    revision, project = identity["revision"], identity["project"]
    update = event["push"]
    checkout, write = trace["checkout"], trace["write"]
    first, push, final = (
        _identifier(checkout["line"], "checkout line"),
        _identifier(write["line"], "branch update line"),
        _identifier(trace["step_end"], "script end"),
    )
    when = _time(event["created_at"], "ref update time")
    _need(
        run["ref"] == "main"
        and job["status"] == "success"
        and _time(job["started_at"], "job start") <= when <= _time(job["finished_at"], "job end")
        and first < _identifier(trace["step_start"], "script start") < push < final
        and trace["url"] == job["web_url"] + "/raw"
        and revision.startswith(_value(checkout["revision_prefix"], _PREFIX, "checkout prefix"))
        and checkout["ref"] == run["ref"]
        and write["branch"] == _BRANCH
        and (event["project_id"], update["action"], update["ref_type"], update["ref"])
        == (project, "pushed", "branch", _BRANCH)
        and update["commit_to"] == revision
        and update["commit_from"] != revision
        and revision.startswith(_value(write["after_prefix"], _PREFIX, "write destination prefix"))
        and _value(update["commit_from"], _SHA, "prior branch revision").startswith(
            _value(write["before_prefix"], _PREFIX, "prior branch prefix")
        ),
        "native branch update does not corroborate this job, checkout or target",
    )
    writer = _identifier(event["author_id"], "ref writer")
    result = {
        "state": "production-ref-update-observed",
        "operation": "git-ref-update",
        "event": _identifier(event["id"], "ref event ID"),
        "event_time": event["created_at"],
        "actor": writer,
        "prior_revision": update["commit_from"],
        "log_sha256": _value(trace["sha256"], _SHA256, "runner trace digest"),
        "log_line": push,
    }
    try:
        result["current_rule"] = _current_rule(data, identity, writer, event["created_at"])
    except (RegistryJobError, AttributeError, KeyError, TypeError, ValueError):
        result["current_rule"] = {
            "state": "unresolved",
            "reason": "current exact branch rule could not be bound",
        }
    return result


def ref_observation(snapshot: Path, root: Path, project: int, pipeline: int, job: int) -> _Row:
    """Corroborate one saved publisher outcome without using network or credentials."""
    try:
        data: _Row = _load_job_receipt(snapshot)
        _need(data.get("schema") == _SCHEMA, "unsupported GitLab production ref schema")
        identity = _job_identity(data, project, pipeline, job)
        _need(
            data["trace"]["url"] == data["job"]["web_url"] + "/raw",
            "trace URL belongs to another job",
        )
        plan = _source_plan(data, root.resolve(), identity["revision"])
        event = data["pipeline"]["source"]
        _need(
            event in {"push", "merge_request_event"},
            "pipeline event is outside the supported profile",
        )
        outcome = _observed_write(data, identity) if event == "push" else _unstarted(data, identity)
        return {
            **identity,
            **outcome,
            "target": "refs/heads/production",
            "source": plan,
            "scope": _SCOPE,
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "required ref publication evidence is malformed or missing"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
