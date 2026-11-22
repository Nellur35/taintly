"""Attribute a saved GitLab.com generic package file to its recorded pipeline."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from taintly.ingestion.gitlab_registry_job import (
    _PROJECT,
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _load_job_receipt,
    _record,
    _source_bytes,
    _time,
    _value,
)

_SCHEMA = "gitlab-package-file-v1"
_SCOPE = (
    "Trusted saved GitLab.com file metadata and revision-bound source. The file record names "
    "a pipeline. The publishing job, exact command, credential instance, effective permission, "
    "file bytes and current availability require separate evidence."
)
_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,239}")
_REF = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
_EVENT = re.compile(r"[a-z_]{1,40}")
_Row = dict[str, Any]


@dataclass(frozen=True)
class _Pipeline:
    project: int
    id: int
    revision: str
    ref: str
    event: str

    @classmethod
    def read(cls, row: object, project: int, repository: str) -> _Pipeline:
        record = _record(row, "pipeline row")
        identity = cls(
            _identifier(record.get("project_id"), "pipeline project"),
            _identifier(record.get("id"), "pipeline"),
            _value(record.get("sha"), _SHA, "pipeline revision"),
            _value(record.get("ref"), _REF, "pipeline ref"),
            _value(record.get("source"), _EVENT, "pipeline event"),
        )
        if identity.project != project or record.get("web_url") != (
            f"https://gitlab.com/{repository}/-/pipelines/{identity.id}"
        ):
            raise RegistryJobError("pipeline evidence belongs to another project")
        return identity


def _response(data: _Row, key: str, url: str) -> _Row:
    response = _record(data.get(key), f"{key} response")
    if response.get("url") != url or response.get("status") != 200:
        raise RegistryJobError(f"{key} response is unavailable or from a different endpoint")
    return response


def _package_file(rows: object, file_id: int, package: int) -> _Row:
    if not isinstance(rows, list):
        raise RegistryJobError("package file response does not contain a file list")
    records = [_record(row, "package file") for row in rows]
    matches = [row for row in records if _identifier(row.get("id"), "file row ID") == file_id]
    if len(matches) != 1:
        raise RegistryJobError("selected package file is missing or ambiguous")
    row = matches[0]
    if _identifier(row.get("package_id"), "file package") != package:
        raise RegistryJobError("selected file belongs to another package")
    return row


def _observe(
    data: _Row, root: Path, project: int, pipeline: int, package: int, file_id: int
) -> _Row:
    if data.get("schema") != _SCHEMA:
        raise RegistryJobError("unsupported GitLab package file observation schema")

    base = f"https://gitlab.com/api/v4/projects/{project}"
    repo = _record(_response(data, "project", base).get("row"), "project row")
    if _identifier(repo.get("id"), "project") != project:
        raise RegistryJobError("saved project row belongs to another project")
    repository = _value(repo.get("path_with_namespace"), _PROJECT, "project path")

    pipeline_url = f"{base}/pipelines/{pipeline}"
    run_row = _record(_response(data, "pipeline", pipeline_url).get("row"), "selected pipeline row")
    run = _Pipeline.read(run_row, project, repository)
    if run.id != pipeline:
        raise RegistryJobError("saved pipeline row belongs to another invocation")

    source_url = f"{base}/repository/files/.gitlab-ci.yml/raw?ref={run.revision}"
    source = _response(data, "source", source_url)
    source_sha = _value(source.get("sha256"), _SHA256, "source SHA-256")
    raw = _source_bytes(root, root / ".gitlab-ci.yml", "workflow source")
    if hashlib.sha256(raw).hexdigest() != source_sha:
        raise RegistryJobError("workflow source bytes differ from the selected revision")

    package_url = f"{base}/packages/{package}"
    metadata = _record(_response(data, "package", package_url).get("row"), "package row")
    if (
        _identifier(metadata.get("id"), "package") != package
        or metadata.get("package_type") != "generic"
    ):
        raise RegistryJobError("selected package is not the recorded generic package")
    name = _value(metadata.get("name"), _COMPONENT, "package name")
    version = _value(metadata.get("version"), _COMPONENT, "package version")

    file_url = f"{package_url}/package_files?per_page=100"
    file_row = _package_file(_response(data, "files", file_url).get("rows"), file_id, package)
    filename = _value(file_row.get("file_name"), _COMPONENT, "package file name")
    digest = _value(file_row.get("file_sha256"), _SHA256, "provider-reported file SHA-256")
    created_at = file_row.get("created_at")
    _time(created_at, "package file creation time")
    owners = file_row.get("pipelines")
    if not isinstance(owners, list) or len(owners) != 1:
        raise RegistryJobError("selected package file has no unique recorded pipeline")
    owner = _Pipeline.read(owners[0], project, repository)
    same_pipeline = owner.id == run.id
    if same_pipeline and owner != run:
        raise RegistryJobError("file pipeline conflicts with the exact pipeline record")

    result = {
        "state": "file-pipeline-confirmed" if same_pipeline else "file-pipeline-differs",
        "repository": repository,
        "selected_pipeline": asdict(run),
        "recorded_pipeline": asdict(owner),
        "package": {"id": package, "name": name, "version": version},
        "file": {
            "id": file_id,
            "name": filename,
            "provider_sha256": digest,
            "created_at": created_at,
        },
        "source": {"path": ".gitlab-ci.yml", "revision": run.revision, "sha256": source_sha},
        "evidence": {"pipeline": pipeline_url, "files": file_url, "source": source_url},
    }

    if "upload" in data:
        from taintly.ingestion.gitlab_package_upload import observe_package_upload

        result["upload"] = observe_package_upload(data["upload"], result, raw)
    return result


def package_file_observation(
    snapshot: Path, root: Path, project: int, pipeline: int, package: int, file_id: int
) -> _Row:
    """Assess a file's exact provider association using saved inputs only."""
    try:
        for value in (project, pipeline, package, file_id):
            _identifier(value, "selected observation ID")
        report = _observe(_load_job_receipt(snapshot), root, project, pipeline, package, file_id)
    except RegistryJobError as exc:
        report = {"state": "unresolved", "reason": str(exc)}
    return {**report, "request_authority": "unresolved", "scope": _SCOPE}
