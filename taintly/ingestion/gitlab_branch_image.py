"""Compare one recorded GitLab branch-tag push with the observed OCI manifest."""

from __future__ import annotations

import hashlib
import json
import re
from itertools import pairwise, takewhile
from pathlib import Path

from taintly.ingestion.gitlab_mr_artifact import _PATH, _Config, _need, _Row
from taintly.ingestion.gitlab_registry_job import (
    _DIGEST,
    _JOB_NAME,
    _PROJECT,
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _source_bytes,
    _time,
    _value,
)
from taintly.parsers.structural import Event
from taintly.rules.gitlab.mr_publish import command_text

SCHEMA = "gitlab-mr-branch-image-v1"
SCOPE = (
    "Trusted saved GitLab job, source and runner records for one same-project MR. "
    "The selected Dockerfile and credential binding are source-bound. The registry credential's "
    "runtime identity, effective configuration, other grants, exclusive writer and "
    "current write permission are unverified."
)
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_IMAGE = re.compile(r"\$CI_REGISTRY_IMAGE/([a-z0-9][a-z0-9_.-]{0,99}):\$CI_COMMIT_REF_NAME")
_LOGIN = "docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY"
_BUILD = "docker build -f $DOCKERFILE -t $IMAGE_TAG ."
_PUSH = "docker push $IMAGE_TAG"
_CREDENTIAL_NAMES = {
    "CI_COMMIT_REF_NAME",
    "CI_REGISTRY",
    "CI_REGISTRY_IMAGE",
    "CI_REGISTRY_PASSWORD",
    "CI_REGISTRY_USER",
    "DOCKERFILE",
    "IMAGE_TAG",
}


def _check_plain_script(lines: list[str], commands: list[Event]) -> None:
    # Empty and nested list entries may contribute no scalar events. Corroborate
    # the whole literal, single-line script list enclosing these owned events.
    kept = [
        (number, text)
        for number, text in enumerate(lines, 1)
        if text.strip() and not text.lstrip().startswith("#")
    ]
    first = next((i for i, (number, _) in enumerate(kept) if number == commands[0].line), -1)
    _need(first > 0, "source script header is missing")
    header = kept[first - 1][1]
    _need(
        re.fullmatch(r" *script: *(?:#.*)?", header),
        "source script is outside the plain block-list profile",
    )
    indent = len(header) - len(header.lstrip(" "))
    block = list(
        takewhile(lambda entry: len(entry[1]) - len(entry[1].lstrip(" ")) > indent, kept[first:])
    )
    _need(
        [number for number, _ in block] == [event.line for event in commands],
        "source script contains additional or unsupported entries",
    )


def _check_observed_admission(cfg: _Config, rules: tuple[str, str]) -> None:
    cfg.owner(rules)
    entries = {key[2] for key in cfg.keys if len(key) > 2 and key[:2] == rules}
    _need(
        0 in entries and all(isinstance(entry, int) for entry in entries),
        "selected source rules must be a nonempty sequence",
    )
    first = (*rules, 0)
    when = (*first, "when")
    conditions = {key[-1] for key in cfg.keys if key[:-1] == first}
    if cfg.keys[when] and first not in cfg.merges and not conditions & {"if", "changes", "exists"}:
        _need(cfg.scalar(when).value != "never", "source unconditionally excludes the selected job")


def _job_source(raw: bytes, name: str) -> tuple[str, str, list[int]]:
    cfg = _Config(raw.decode("utf-8"))
    cfg.owner((name,))
    _check_observed_admission(cfg, (name, "rules"))
    if cfg.keys[("workflow", "rules")]:
        _check_observed_admission(cfg, ("workflow", "rules"))
    variables = (name, "variables")
    recipe = _value(cfg.scalar((*variables, "DOCKERFILE")).value, _PATH, "configured Dockerfile")
    image = _IMAGE.fullmatch(str(cfg.scalar((*variables, "IMAGE_TAG")).value))
    _need(
        not any(
            cfg.keys[path]
            for path in (
                (name, "extends"),
                (name, "before_script"),
                (name, "hooks"),
                (name, "parallel"),
                (name, "when"),
                (name, "only"),
                (name, "except"),
                ("default", "before_script"),
                ("default", "hooks"),
                ("before_script",),
            )
        )
        and not any(
            len(key) >= 2
            and key[-2] == "variables"
            and key[-1] in _CREDENTIAL_NAMES
            and key not in {(*variables, "DOCKERFILE"), (*variables, "IMAGE_TAG")}
            and (len(key) == 2 or key[0] in {name, "workflow"})
            for key in cfg.keys
        ),
        "source overrides the selected checkout, registry values or command ownership",
    )
    commands = cfg.sequence((name, "script"))
    text = [" ".join((command_text(event, cfg.lines) or "").split()) for event in commands]
    _need(
        image is not None and text == [_LOGIN, _BUILD, _PUSH],
        "source does not configure the bounded branch-tagged login, build and push",
    )
    _check_plain_script(cfg.lines, commands)
    assert image is not None  # nosec B101
    return recipe, image[1], [event.line for event in commands]


def _source(data: _Row, root: Path, revisions: _Row, name: str) -> _Row:
    snapshots = data["source"]
    config = _source_bytes(root, root / ".gitlab-ci.yml", "selected GitLab configuration")
    recipe, suffix, lines = _job_source(config, name)
    hashes = {
        ".gitlab-ci.yml": hashlib.sha256(config).hexdigest(),
        recipe: hashlib.sha256(
            _source_bytes(root, root / recipe, "selected Dockerfile")
        ).hexdigest(),
    }
    for key, revision in revisions.items():
        snapshot = snapshots[key]
        _need(snapshot["revision"] == revision, "source snapshots belong to another revision")
        for path, digest in hashes.items():
            receipt = snapshot["files"][path]
            _need(
                receipt["url"]
                == (
                    f"https://gitlab.com/api/v4/projects/{data['project']['id']}/repository/files/"
                    f"{path.replace('/', '%2F')}/raw?ref={revision}"
                ),
                "source snapshot route does not identify the selected revision and file",
            )
            if key == "base" and path == ".gitlab-ci.yml":
                _need(
                    receipt["status"] == 200 and _SHA256.fullmatch(str(receipt["sha256"])),
                    "the selected base snapshot is unavailable",
                )
            if key != "base":
                _need(
                    receipt["status"] == 200 and receipt["sha256"] == digest,
                    "local bytes do not match the selected MR and checkout snapshots",
                )
    base_recipe = snapshots["base"]["files"][recipe]
    _need(
        (base_recipe["status"] == 404 and "sha256" not in base_recipe)
        or (
            base_recipe["status"] == 200
            and _SHA256.fullmatch(str(base_recipe["sha256"]))
            and base_recipe["sha256"] != hashes[recipe]
        ),
        "saved base source does not establish a different Dockerfile",
    )
    return {
        "path": ".gitlab-ci.yml",
        "sha256": hashes[".gitlab-ci.yml"],
        "dockerfile": recipe,
        "dockerfile_sha256": hashes[recipe],
        "login_line": lines[0],
        "build_line": lines[1],
        "push_line": lines[2],
        "image_suffix": suffix,
    }


def _recorded_push(
    trace: _Row,
    job: _Row,
    url: str,
    revision: str,
    ref: str,
    image: str,
    tag: str,
) -> str:
    _need(
        trace["url"] == f"{url}/raw"
        and trace["job_id"] == job["id"]
        and trace["status"] == 200
        and _identifier(trace["job_id"], "trace job ID")
        and _SHA256.fullmatch(str(trace["sha256"])),
        "saved runner trace belongs to a different job",
    )
    sections = trace["sections"]
    stages = ("get_sources", "step_script", "cleanup_file_variables")
    _need(
        isinstance(sections, list)
        and [(row["stage"], row["event"]) for row in sections]
        == [(stage, event) for stage in stages for event in ("start", "end")],
        "runner sections are incomplete or out of order",
    )
    section_lines = [_identifier(row["line"], "section line") for row in sections]
    times = [_identifier(row["seconds"], "runner section time") for row in sections]
    _need(
        all(a < b for a, b in pairwise(section_lines))
        and all(a <= b for a, b in pairwise(times))
        and int(_time(job["started_at"], "job start").timestamp())
        <= times[0]
        <= times[-1]
        <= int(_time(job["finished_at"], "job end").timestamp()),
        "runner section bounds do not fit the selected job window",
    )
    rows = trace["rows"]
    patterns = (
        rf"Checking out ({revision[:8]}[a-f0-9]{{0,32}}) as detached HEAD \(ref is {re.escape(ref)}\)\.\.\.",
        re.escape("$ " + _LOGIN),
        "Login Succeeded",
        r"\$ docker build -f \$DOCKERFILE +\-t \$IMAGE_TAG \.",
        re.escape("$ " + _PUSH),
        re.escape(f"The push refers to repository [{image}]"),
        rf"{re.escape(tag)}: digest: (sha256:[a-f0-9]{{64}}) size: [1-9][0-9]{{0,9}}",
        "Job succeeded",
    )
    _need(isinstance(rows, list) and len(rows) == len(patterns), "saved runner rows are incomplete")
    lines = [_identifier(row["line"], "runner row line") for row in rows]
    _need(
        all(a < b for a, b in pairwise(lines))
        and section_lines[0] < lines[0] < section_lines[1]
        and section_lines[2] < lines[1] <= lines[-2] < section_lines[3]
        and section_lines[-1] < lines[-1],
        "checkout, build or push result does not belong to its recorded runner section",
    )
    values = [row["row"] for row in rows]
    _need(
        all(re.fullmatch(pattern, value) for pattern, value in zip(patterns, values, strict=True))
        and all(hashlib.sha256(row["row"].encode()).hexdigest() == row["sha256"] for row in rows)
        and revision.startswith(values[0].split()[2])
        and trace["script_commands"] == [values[1], values[3], values[4]],
        "saved runner markers do not match the selected checkout, shell commands and image",
    )
    return _value(values[-2].split()[2], _DIGEST, "runner image digest")


def _registry_match(data: _Row, root: Path, image: str, tag: str, digest: str, end: str) -> bool:
    registry = data.get("registry")
    if not isinstance(registry, dict):
        return False
    repository = image.removeprefix("registry.gitlab.com/")
    sizes = []
    for key, reference in (("tag", tag), ("digest", digest)):
        row = registry.get(key)
        if (
            not isinstance(row, dict)
            or row.get("url")
            != f"https://registry.gitlab.com/v2/{repository}/manifests/{reference}"
            or row.get("reference") != reference
            or row.get("status") != 200
            or row.get("server_digest") != digest
            or row.get("calculated_digest") != digest
            or row.get("digest_matches") is not True
            or type(row.get("bytes")) is not int
        ):
            return False
        try:
            if _time(row.get("time"), "registry observation") <= _time(end, "job end"):
                return False
        except RegistryJobError:
            return False
        sizes.append(row["bytes"])
    try:
        manifest = _source_bytes(root, root / "image-manifest.json", "saved registry manifest")
        payload = json.loads(manifest)
    except (ValueError, RecursionError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schemaVersion") == 2
        and sizes == [len(manifest)] * 2
        and "sha256:" + hashlib.sha256(manifest).hexdigest() == digest
    )


def branch_image_observation(
    data: _Row,
    root: Path,
    project_id: int,
    pipeline_id: int,
    job_id: int,
) -> _Row:
    project, pr, pipe, view, job, merge = (
        data[key] for key in ("project", "mr", "pipeline", "historical_view", "job", "merge")
    )
    path = _value(project["path"], _PROJECT, "GitLab project path")
    name = _value(job["name"], _JOB_NAME, "GitLab job name")
    iid = _identifier(pr["iid"], "merge request IID")
    branch = _value(pr["source_branch"], _TAG, "recorded MR branch tag")
    revision = _value(pipe["sha"], _SHA, "pipeline revision")
    head = _value(view["source_sha"], _SHA, "historical MR head")
    base = _value(view["target_sha"], _SHA, "historical target")
    mode = view["event_type"]
    _need(mode in ("merge_train", "merged_result"), "unsupported historical MR event class")
    ref = f"refs/merge-requests/{iid}/" + ("train" if mode == "merge_train" else "merge")
    job_url = f"https://gitlab.com/{path}/-/jobs/{job_id}"
    parent_ids = merge["parent_ids"]
    _need(
        all(
            _identifier(v, "GitLab receipt ID") == project_id
            for v in (
                project["id"],
                pipe["project_id"],
                pr["source_project_id"],
                pr["target_project_id"],
            )
        )
        and _identifier(job["id"], "job ID") == job_id
        and _identifier(pipe["id"], "pipeline ID") == pipeline_id
        and _identifier(view["id"], "historical pipeline ID") == pipeline_id
        and job["web_url"] == job_url
        and job["ref"] == ref
        and job["commit"]["id"] == revision
        and job["status"] in ("success", "canceled")
        and job["pipeline"] == pipe
        and pipe["source"] == view["source"] == "merge_request_event"
        and pipe["ref"] == view["ref"] == ref
        and view["url"] == f"https://gitlab.com/{path}/-/pipelines/{pipeline_id}.json"
        and view["status"] == 200
        and _time(pipe["created_at"], "pipeline start")
        <= _time(job["started_at"], "job start")
        <= _time(job["finished_at"], "job end")
        <= _time(pipe["updated_at"], "pipeline update")
        and _SHA256.fullmatch(str(view["sha256"]))
        and merge["id"] == view["revision"] == revision
        and isinstance(parent_ids, list)
        and len(parent_ids) == 2
        and parent_ids[0] == base
        and _SHA.fullmatch(str(parent_ids[1]))
        and len({revision, base, head}) == 3
        and parent_ids[1] not in {base, revision}
        and (mode == "merge_train" or parent_ids[1] == head),
        "same-project MR, historical view, pipeline, checkout or job identities do not agree",
    )
    configured = _source(
        data,
        root,
        {
            "executed": revision,
            "base": base,
            "merge_input": parent_ids[1],
            "mr_historical_head": head,
        },
        name,
    )
    image = f"registry.gitlab.com/{path}/{configured['image_suffix']}"
    digest = _recorded_push(data["trace"], job, job_url, revision, ref, image, branch)
    confirmed = _registry_match(data, root, image, branch, digest, job["finished_at"])
    return {
        "state": "registry-image-push-observed" if confirmed else "registry-image-push-reported",
        "repository": path,
        "project": project_id,
        "pipeline": pipeline_id,
        "job": job_id,
        "job_name": name,
        "job_status": job["status"],
        "mr": iid,
        "mr_head": head,
        "source_project": project_id,
        "revision": revision,
        "merge_input": parent_ids[1],
        "event_type": mode,
        "configured": configured,
        "operation": {
            "name": "docker-push",
            "target": f"{image}:{branch}",
            "reported_digest": digest,
            "registry_confirmation": "matched" if confirmed else "unverified",
        },
        "credential": {
            "configured": ["CI_REGISTRY_USER", "CI_REGISTRY_PASSWORD"],
            "runtime_identity": "unverified",
        },
        "scope": SCOPE,
    }
