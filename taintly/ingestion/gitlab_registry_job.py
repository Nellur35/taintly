"""Bind an explicitly supplied GitLab.com MR job observation to one source path."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from taintly.path_safety import is_within_repo

_MAX_RECEIPT_BYTES = 1_048_576
_MAX_SOURCE_BYTES = 2_097_152
_ID = re.compile(r"[1-9][0-9]{0,17}")
_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z")
_PROJECT = re.compile(r"[a-z0-9_-][a-z0-9_.-]*(?:/[a-z0-9_-][a-z0-9_.-]*)+")
_MR_REF = re.compile(r"refs/merge-requests/[1-9][0-9]{0,17}/merge")
_JOB_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_LINE = re.compile(r"(\S+) [0-9]{2}[OE] (.*)")
_SGR = re.compile(r"\x1b\[[0-9;]*m")
_LOGIN = '$ echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"'


class RegistryJobError(ValueError):
    """The supplied records do not support the requested link."""


@dataclass(frozen=True)
class RegistryPath:
    job: str
    login_line: int
    build_line: int
    push_line: int
    dockerfile: str
    image_suffix: str
    tag_length: int
    skips_existing: bool


@dataclass(frozen=True)
class RegistryObservation:
    tag: str
    note: str


@dataclass(frozen=True)
class _RegistryManifest:
    reference: str
    digest: str
    observed_at: datetime


@dataclass(frozen=True)
class GitLabRegistryJob:
    project_id: int
    project_path: str
    pipeline_id: int
    ref: str
    revision: str
    job_id: int
    job_name: str
    start: datetime
    end: datetime
    config_sha256: str
    dockerfile_sha256: str
    trace: str
    registry: _RegistryManifest | None

    def observe(
        self, repo: Path, config_path: Path, scanned_content: str, path: RegistryPath
    ) -> RegistryObservation:
        if path.job != self.job_name or config_path != repo / ".gitlab-ci.yml":
            raise RegistryJobError("The selected job does not own a supported root-config path")
        if not 1 <= path.tag_length <= 64:
            raise RegistryJobError("The tag is outside the supported SHA-256 prefix profile")
        config = _source_bytes(repo, config_path, "Root configuration")
        if hashlib.sha256(config).hexdigest() != self.config_sha256:
            raise RegistryJobError("Root configuration bytes do not match the selected revision")
        try:
            parsed_config = config.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as exc:
            raise RegistryJobError("Root configuration is not UTF-8") from exc
        if parsed_config != scanned_content:
            raise RegistryJobError("Root configuration differs from the parsed source")
        events = _owned_workflow_events(parsed_config)
        if any(
            event.value_kind == "merge_key"
            and event.path[0] in {path.job, "variables", "workflow", "default"}
            for event in events
        ):
            raise RegistryJobError("GitLab source uses a merge in the selected registry context")
        recipe = _source_bytes(repo, repo / path.dockerfile, "Dockerfile")
        recipe_sha = hashlib.sha256(recipe).hexdigest()
        if recipe_sha != self.dockerfile_sha256:
            raise RegistryJobError("Dockerfile bytes do not match the selected revision")

        image = f"registry.gitlab.com/{self.project_path}/{path.image_suffix}"
        version = recipe_sha[: path.tag_length]
        target = f"{image}:{version}"
        checkout = re.compile(
            r"Checking out ([a-f0-9]{7,40}) as detached HEAD \(ref is "
            + re.escape(self.ref)
            + r"\)\.\.\."
        )
        pushed = re.compile(
            re.escape(version) + r": digest: (sha256:[a-f0-9]{64}) size: [0-9]{1,12}"
        )
        lines = self._job_lines()
        checkouts = [index for index, line in enumerate(lines) if line.startswith("Checking out ")]
        if (
            len(checkouts) != 1
            or not (match := checkout.fullmatch(lines[checkouts[0]]))
            or not self.revision.startswith(match[1])
        ):
            raise RegistryJobError("Trace lacks a unique checkout of the selected MR revision")
        login = _one_line(lines, _LOGIN)
        login_ok = _one_line(lines, "Login Succeeded")
        tag = _one_line(lines, f"$ TAG=$(sha256sum {path.dockerfile} | cut -c1-{path.tag_length})")
        assignment = _one_line(lines, f'$ IMAGE="${{CI_REGISTRY_IMAGE}}/{path.image_suffix}"')
        success = _one_line(lines, "Job succeeded")
        if not checkouts[0] < login < login_ok < tag < assignment < success:
            raise RegistryJobError("Trace command ordering does not match the supported CI path")

        pushes = [
            (index, match[1])
            for index, line in enumerate(lines)
            if (match := pushed.fullmatch(line))
        ]
        push_headers = [
            index
            for index, line in enumerate(lines)
            if line.startswith("The push refers to repository [")
        ]
        existing = [index for index, line in enumerate(lines) if line == f"{target} already exists"]
        basis = (
            f"Supplied GitLab.com records for project {self.project_id}, pipeline {self.pipeline_id}, "
            f"job {self.job_id}, revision {self.revision}. "
        )
        limits = (
            " The supplied trace is job output. It does not establish the principal's policy or "
            "current permissions."
        )
        if path.skips_existing and len(existing) == 1 and not pushes and not push_headers:
            if assignment < existing[0] < success:
                return RegistryObservation(
                    "gitlab-trace-reports-existing-tag",
                    basis + f"The trace reports that {target} already existed. "
                    "The marker matches the configured branch that skips this push." + limits,
                )
        if len(push_headers) != 1 or len(pushes) != 1 or existing:
            raise RegistryJobError(
                "Trace does not identify one unambiguous push or existing-tag branch"
            )
        header = push_headers[0]
        result, digest = pushes[0]
        if not (
            assignment < header < result < success
            and lines[header] == f"The push refers to repository [{image}]"
        ):
            raise RegistryJobError(
                "Trace push target or order does not match the supported CI path"
            )
        registry = self.registry
        if (
            registry is None
            or registry.reference != target
            or registry.digest != digest
            or registry.observed_at <= self.end
        ):
            raise RegistryJobError(
                "No matching registry manifest observation after this job finished"
            )
        return RegistryObservation(
            "gitlab-trace-push-registry-match",
            basis + f"The trace reports a push of {target} at {digest}. "
            "The supplied registry response matches that reference and digest." + limits,
        )

    def _job_lines(self) -> list[str]:
        result = []
        time = self.start
        for raw in self.trace.splitlines():
            if not (match := _LINE.fullmatch(_SGR.sub("", raw))):
                continue
            date = _time(match[1], "trace")
            if date < time or date > self.end:
                raise RegistryJobError(
                    "Trace timestamps do not belong to the selected job interval"
                )
            time = date
            result.append(match[2])
        return result


def _one_line(lines: list[str], expected: str) -> int:
    indices = [index for index, line in enumerate(lines) if line == expected]
    if len(indices) != 1:
        raise RegistryJobError("Trace lacks a unique required command or completion marker")
    return indices[0]


def _owned_workflow_events(content: str) -> list[Event]:
    if "\ufeff" in content or re.search(r"^(?:(?:---|\.\.\.)(?:[ \t]|$)|%)", content, re.MULTILINE):
        raise RegistryJobError("GitLab source contains unsupported document boundaries")
    try:
        for token in tokenize(content):
            if token.kind is TokenKind.KEY and "\\" in token.value:
                raise RegistryJobError("GitLab source contains ambiguous key ownership")
    except TokenizerError as exc:
        raise RegistryJobError("GitLab source tokenization is incomplete") from exc
    events = list(
        walk_workflow(
            ".gitlab-ci.yml", content=content, include_keys=True, include_merge_origins=True
        )
    )
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        raise RegistryJobError("GitLab source structural analysis is incomplete")
    if any(event.value_kind == "merge_key" and event.path == ("<<",) for event in events):
        raise RegistryJobError("GitLab source contains ambiguous root merge ownership")
    return events


def _source_bytes(
    repo: Path, path: Path, label: str, *, max_bytes: int = _MAX_SOURCE_BYTES
) -> bytes:
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RegistryJobError(f"{label} bytes are unavailable") from exc
    if not is_within_repo(str(repo), str(path)) or not path.is_file():
        raise RegistryJobError(f"{label} is not a regular in-repository file")
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise RegistryJobError(f"{label} bytes are unavailable") from exc
    if len(data) > max_bytes:
        raise RegistryJobError(f"{label} exceeds the observation size limit")
    return data


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryJobError("GitLab job receipt contains duplicate JSON keys")
        result[key] = value
    return result


def _parse_int(value: str) -> int:
    if len(value) > 18:
        raise RegistryJobError("GitLab job receipt contains an oversized integer")
    return int(value)


def _record(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RegistryJobError(f"{label} must be a JSON object")
    return value


def _identifier(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value < 10**18:
        raise RegistryJobError(f"{label} must be a positive integer identifier")
    return value


def _value(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or len(value) > 1024 or not pattern.fullmatch(value):
        raise RegistryJobError(f"{label} is missing or malformed")
    return value


def _time(value: object, label: str) -> datetime:
    try:
        return datetime.fromisoformat(_value(value, _TIMESTAMP, label).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryJobError(f"{label} requires a valid UTC timestamp") from exc


def _load_job_receipt(path: Path) -> dict[str, object]:
    try:
        if not path.is_file():
            raise RegistryJobError("GitLab job receipt must be a regular file")
        with path.open("rb") as handle:
            raw = handle.read(_MAX_RECEIPT_BYTES + 1)
    except OSError as exc:
        raise RegistryJobError("GitLab job receipt is not readable") from exc
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise RegistryJobError("GitLab job receipt exceeds the input size limit")
    try:
        receipt = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_keys, parse_int=_parse_int
        )
    except RegistryJobError:
        raise
    except (OSError, ValueError, RecursionError) as exc:
        raise RegistryJobError("GitLab job receipt is not readable UTF-8 JSON") from exc

    return _record(receipt, "receipt")


def load_registry_job(path: Path, project_id: str, job_id: str) -> GitLabRegistryJob:
    """Read one saved receipt without making requests or reading credentials."""
    if not _ID.fullmatch(project_id) or not _ID.fullmatch(job_id):
        raise RegistryJobError("Select a literal GitLab project ID and job ID")
    receipt = _load_job_receipt(path)
    project = _record(receipt.get("project"), "project")
    job = _record(receipt.get("job"), "job")
    run = _record(job.get("pipeline"), "pipeline")
    source = _record(receipt.get("source"), "source")
    trace = _record(receipt.get("trace"), "trace")
    project_num = _identifier(project.get("id"), "project ID")
    job_num = _identifier(job.get("id"), "job ID")
    if (
        project_num != int(project_id)
        or job_num != int(job_id)
        or _identifier(run.get("project_id"), "pipeline project ID") != project_num
        or _identifier(trace.get("job_id"), "trace job ID") != job_num
    ):
        raise RegistryJobError("Project, pipeline, job and trace identities do not match")
    revision = _value(run.get("sha"), _SHA, "pipeline revision")
    ref = _value(run.get("ref"), _MR_REF, "merged-result MR ref")
    if (
        run.get("source") != "merge_request_event"
        or job.get("status") != "success"
        or job.get("ref") != ref
        or _record(job.get("commit"), "job commit").get("id") != revision
        or source.get("revision") != revision
    ):
        raise RegistryJobError(
            "Job and source must match the selected successful merged-result MR run"
        )
    start = _time(job.get("started_at"), "job start")
    end = _time(job.get("finished_at"), "job finish")
    text = trace.get("text")
    if end < start or not isinstance(text, str) or not text:
        raise RegistryJobError("Job interval or trace is incomplete")
    registry = None
    if receipt.get("registry") is not None:
        row = _record(receipt["registry"], "registry")
        reference = row.get("reference")
        if not isinstance(reference, str):
            raise RegistryJobError("Registry reference is missing")
        registry = _RegistryManifest(
            reference,
            _value(row.get("digest"), _DIGEST, "registry digest"),
            _time(row.get("observed_at"), "registry observation"),
        )
    return GitLabRegistryJob(
        project_num,
        _value(project.get("path_with_namespace"), _PROJECT, "project path"),
        _identifier(run.get("id"), "pipeline ID"),
        ref,
        revision,
        job_num,
        _value(job.get("name"), _JOB_NAME, "job name"),
        start,
        end,
        _value(source.get("config_sha256"), _SHA256, "configuration SHA-256"),
        _value(source.get("dockerfile_sha256"), _SHA256, "Dockerfile SHA-256"),
        text,
        registry,
    )
