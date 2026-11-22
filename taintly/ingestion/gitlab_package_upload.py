"""Check a redacted verbose upload observation within its owning GitLab job."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from taintly.ingestion.gitlab_mr_artifact import _Config, _need
from taintly.ingestion.gitlab_registry_job import (
    _SHA256,
    RegistryJobError,
    _identifier,
    _record,
    _time,
    _value,
)

_Row = dict[str, Any]
_JOB_NAME = re.compile(r"[A-Za-z0-9_.:-]+(?: [A-Za-z0-9_.:-]+)*")
_REVISION_PREFIX = re.compile(r"[0-9a-f]{8,40}")
_REQUEST_ID = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{16}-[A-Z]{3})")
_VARIABLE = r"\$(?:[A-Z][A-Z0-9_]*|\{[A-Z][A-Z0-9_]*\})"
_COMPONENT = rf"(?:{_VARIABLE}|[A-Za-z0-9_][A-Za-z0-9_.-]*)"
_CURL_HEADER = re.compile(
    r'curl (?:-v|--verbose)(?: --fail-with-body)?(?: --location)? --header "JOB-TOKEN: \$(?:CI_JOB_TOKEN|\{CI_JOB_TOKEN\})"'
)


def _package_variable(cfg: _Config, job: str, variable: str) -> str | None:
    owned = (job, "variables", variable)
    return cfg.scalar(owned if cfg.keys[owned] else ("variables", variable)).value


def _command_line(
    cfg: _Config, job: str, package: str, file: str, first_line_digest: str, empty: bool
) -> int:
    commands = cfg.sequence((job, "script"))
    url = re.compile(
        rf'"\$(?:CI_API_V4_URL|\{{CI_API_V4_URL\}})/projects/'
        rf"\$(?:CI_PROJECT_ID|\{{CI_PROJECT_ID\}})/packages/generic/{re.escape(package)}"
        rf'/{_COMPONENT}/{_COMPONENT}"'
    )
    matches = []
    for event in commands:
        if event.value_kind != "block_literal" or event.block_lines is None:
            continue
        lines = [(number, line.strip()) for number, line in event.block_lines if line.strip()]
        if len(lines) != 3:
            continue
        (number, head), (_, upload), (_, target) = lines
        if not head.endswith("\\") or not upload.endswith("\\"):
            continue
        head = head[:-1].rstrip()
        if (
            not _CURL_HEADER.fullmatch(head)
            or hashlib.sha256(head.encode()).hexdigest() != first_line_digest
        ):
            continue
        upload = upload[:-1].rstrip()
        if url.fullmatch(target) and re.fullmatch(rf"--upload-file {_COMPONENT}", upload):
            matches.append(number)
        elif empty and target == "$PACKAGE_URL" and upload == "--upload-file $PACKAGE_FILE":
            declared = (
                f"$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/{package}"
                "/$CI_COMMIT_TAG/$PACKAGE_FILE"
            )
            if (
                _package_variable(cfg, job, "PACKAGE_URL") == declared
                and _package_variable(cfg, job, "PACKAGE_FILE") == file
            ):
                matches.append(number)
    _need(len(matches) == 1, "no unique matching verbose package upload in the selected source job")
    return matches[0]


def _owned_job(upload: _Row, provenance: _Row) -> _Row:
    run = provenance["selected_pipeline"]
    project, pipeline = run["project"], run["id"]
    jobs = _record(upload.get("jobs"), "pipeline job response")
    _need(
        jobs.get("url")
        == f"https://gitlab.com/api/v4/projects/{project}/pipelines/{pipeline}/jobs"
        "?include_retried=true&per_page=100"
        and jobs.get("status") == 200,
        "job evidence came from a different pipeline endpoint",
    )
    job = _record(jobs.get("row"), "job row")
    job_id = _identifier(job.get("id"), "job")
    _value(job.get("name"), _JOB_NAME, "job name")
    _need(
        job.get("pipeline")
        == {"id": pipeline, "project_id": project, "sha": run["revision"], "ref": run["ref"]}
        and job.get("revision") == run["revision"]
        and job.get("ref") == run["ref"]
        and job.get("web_url") == f"https://gitlab.com/{provenance['repository']}/-/jobs/{job_id}",
        "job row belongs to another invocation",
    )
    return job


def _source_phase(
    trace: _Row, job: _Row, provenance: _Row, cfg: _Config, script_start: int
) -> _Row:
    if "empty_checkout" not in trace:
        checkout = _record(trace.get("checkout"), "trace checkout")
        revision = _value(
            checkout.get("revision_prefix"), _REVISION_PREFIX, "trace checkout revision"
        )
        checkout_line = _identifier(checkout.get("line"), "checkout line")
        _need(
            job["revision"].startswith(revision) and checkout_line < script_start,
            "trace checkout does not precede the selected job script at its recorded revision",
        )
        return {}

    skip = _record(trace["empty_checkout"], "skipped checkout trace")
    first, setup, skipped_checkout, end = (
        _identifier(skip.get(key), "Git source phase line")
        for key in (
            "source_start_line",
            "setup_skipped_line",
            "checkout_skipped_line",
            "source_end_line",
        )
    )
    _need(
        "checkout" not in trace
        and first < setup < skipped_checkout < end < script_start
        and job.get("tag") is True
        and job["ref"] == provenance["package"]["version"]
        and cfg.scalar((job["name"], "variables", "GIT_STRATEGY")).value == "empty",
        "empty-workspace source evidence does not bind this tagged job's skipped checkout",
    )
    return {"runner_workspace": "checkout-skipped", "package_content_ancestry": "unresolved"}


def _trace_request(trace: _Row, job: _Row, provenance: _Row, raw: bytes) -> _Row:
    _need(
        trace.get("url") == f"{job['web_url']}/raw" and trace.get("status") == 200,
        "trace response belongs to another job or is unavailable",
    )
    trace_sha = _value(trace.get("sha256"), _SHA256, "trace SHA-256")
    if "script" not in trace:
        raise RegistryJobError("trace has no exact package HTTP request and response section")
    script = _record(trace["script"], "exact package request trace section")
    start = _record(script.get("start"), "script start")
    end = _record(script.get("end"), "script end")
    start_line = _identifier(start.get("line"), "script start line")
    end_line = _identifier(end.get("line"), "script end line")
    start_second = _identifier(start.get("epoch"), "script start time")
    end_second = _identifier(end.get("epoch"), "script end time")
    file = provenance["file"]
    _need(
        int(_time(job.get("started_at"), "job start").timestamp())
        <= start_second
        <= int(_time(file["created_at"], "stored file time").timestamp())
        <= end_second
        <= int(_time(job.get("finished_at"), "job finish").timestamp()),
        "file creation time is outside the selected job's script section",
    )
    command = _record(trace.get("command"), "trace upload command")
    command_line = _identifier(command.get("line"), "trace command line")
    digest = _value(command.get("known_command_sha256"), _SHA256, "trace command SHA-256")
    commands = script.get("command_lines")
    if not isinstance(commands, list) or command_line not in commands:
        raise RegistryJobError("upload command is missing from the traced script boundaries")
    command_lines = [_identifier(line, "script command boundary") for line in commands]
    _need(
        command_lines == sorted(set(command_lines))
        and all(start_line < line < end_line for line in command_lines),
        "script command boundaries are invalid",
    )

    events = script.get("events")
    kinds = (
        "request",
        "host",
        "masked_header",
        "response",
        "response_request_id",
    )
    if not isinstance(events, list):
        raise RegistryJobError("exact HTTP request and response trace rows are missing")
    rows = [_record(event, "trace event") for event in events]
    _need(
        len(rows) == 7
        and rows[0].get("kind") == "tls"
        and rows[1].get("kind") in ("connected", "authority")
        and tuple(row.get("kind") for row in rows[2:]) == kinds,
        "HTTP request and response are incomplete or ambiguous in the script trace",
    )
    event_lines = [_identifier(row.get("line"), "trace event line") for row in rows]
    next_command = next((line for line in command_lines if line > command_line), end_line)
    _need(
        start_line < command_line < event_lines[0]
        and event_lines == sorted(set(event_lines))
        and event_lines[-1] < next_command,
        "HTTP response crosses the selected command or script boundary",
    )
    tls, peer, request, host, header, response, request_id = (row.get("value") for row in rows)
    peer_matches = (rows[1].get("kind"), peer) in (
        ("connected", "gitlab.com:443"),
        ("authority", "gitlab.com"),
    )
    run = provenance["selected_pipeline"]
    package = provenance["package"]
    route = f"/api/v4/projects/{run['project']}/packages/generic/{package['name']}/{package['version']}/{file['name']}"
    _need(
        tls is True
        and peer_matches
        and request == {"method": "PUT", "path": route, "protocol": "2"}
        and host == "gitlab.com"
        and header == "JOB-TOKEN"
        and response == {"status": 201, "protocol": "2"},
        "trace does not show an accepted TLS package PUT to the exact registered file",
    )
    correlation_id = _value(request_id, _REQUEST_ID, "package response request ID")
    try:
        cfg = _Config(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise RegistryJobError("workflow source is not UTF-8") from exc
    cfg.owner((job["name"],))
    workspace = _source_phase(trace, job, provenance, cfg, start_line)
    source_line = _command_line(
        cfg, job["name"], package["name"], file["name"], digest, bool(workspace)
    )
    return {
        "state": "trace-request-observed",
        "job": job["id"],
        "job_name": job["name"],
        "source_line": source_line,
        "trace_url": trace["url"],
        "trace_sha256": trace_sha,
        "trace_command_line": command_line,
        "request_line": event_lines[2],
        "response_line": event_lines[5],
        "method": "PUT",
        "target": f"https://gitlab.com{route}",
        "response_status": 201,
        "request_id": correlation_id,
        "reported_credential_header": "JOB-TOKEN",
        **workspace,
    }


def observe_package_upload(upload: object, provenance: _Row, raw: bytes) -> _Row:
    """Keep client trace corroboration distinct from request authority."""
    try:
        _need(
            provenance["state"] == "file-pipeline-confirmed",
            "upload evidence cannot be attached to a different file-owning pipeline",
        )
        receipt = _record(upload, "upload observation")
        job = _owned_job(receipt, provenance)
        return _trace_request(_record(receipt.get("trace"), "job trace"), job, provenance, raw)
    except RegistryJobError as exc:
        return {"state": "unresolved", "reason": str(exc)}
