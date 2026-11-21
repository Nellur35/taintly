"""Corroborate an upstream Pages artifact handoff beside a fork-owned archive."""

from __future__ import annotations

import hashlib
import re
import stat
import zlib
from io import BytesIO
from itertools import pairwise
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile

from taintly.ingestion.gitlab_mr_artifact import (
    _FORK_BRANCH,
    _JOB,
    _MAX_FORK_ARCHIVE_BYTES,
    _PATH,
    _archive_upload_rows,
    _complete_page,
    _Config,
    _need,
    _Row,
)
from taintly.ingestion.gitlab_registry_job import (
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _record,
    _source_bytes,
    _time,
    _value,
)
from taintly.parsers.structural import Event

_PIPELINE_IDENTITY = ("id", "project_id", "sha", "ref", "web_url", "source")
_SCOPE = (
    "The saved jobs establish the fork archive and a separate upstream Pages archive handoff. "
    "Serving the site, the underlying token instance, and permissions outside these jobs are unverified."
)
_PUBLISHER = "pages"
_REDIRECT_SOURCE = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}")


def _fork_inventory(data: _Row, packet: _Row, producer: str) -> None:
    pipe, job = data["pipeline"], data["job"]
    rows = packet["jobs"]
    url = f"https://gitlab.com/api/v4/projects/{pipe['project_id']}/pipelines/{pipe['id']}/jobs"
    _complete_page(packet, rows, url + "?per_page=100&include_retried=true", pipe["updated_at"])
    ids = {_identifier(row["id"], "fork inventory job") for row in rows}
    _need(
        _SHA256.fullmatch(str(packet["sha256"]))
        and len(ids) == len(rows)
        and all(
            all(row["pipeline"][field] == pipe[field] for field in _PIPELINE_IDENTITY)
            and isinstance(row["name"], str)
            for row in rows
        ),
        "saved fork inventory contains unowned or ambiguous jobs",
    )
    _need(
        not any(row["name"] == _PUBLISHER for row in rows)
        and any(
            row["id"] == job["id"]
            and row["name"] == job["name"] == producer
            and row["web_url"] == job["web_url"]
            and row["status"] == job["status"] == "success"
            for row in rows
        ),
        "fork inventory does not establish the owned producer and absence of the Pages job",
    )


def _upstream(data: _Row, handoff: _Row) -> _Row:
    project = handoff["upstream_project"]
    pipe = _record(handoff["upstream_pipeline"], "upstream pipeline")
    target = data["target"]
    repo = target["path_with_namespace"]
    owner = _identifier(project["id"], "upstream project")
    pipeline_id = _identifier(pipe["id"], "upstream pipeline")
    branch = _value(project["default_branch"], _FORK_BRANCH, "upstream default branch")
    revision = _value(pipe["sha"], _SHA, "upstream checkout")
    source = handoff["upstream_config"]
    api = f"https://gitlab.com/api/v4/projects/{owner}/repository/files/"
    _need(
        owner == target["id"] == pipe["project_id"]
        and owner != data["fork"]["id"]
        and pipeline_id != data["pipeline"]["id"]
        and revision != data["pipeline"]["sha"]
        and project["path_with_namespace"] == repo
        and project["web_url"] == target["web_url"]
        and pipe["web_url"] == f"{target['web_url']}/-/pipelines/{pipeline_id}"
        and pipe["source"] == "push"
        and pipe["status"] == "success"
        and pipe["ref"] == branch
        and source["url"] == f"{api}.gitlab-ci.yml?ref={revision}"
        and source["sha256"] == data["source_sha256"],
        "the saved push and matching configuration do not belong to the MR target's default branch",
    )
    return pipe


def _archive(
    record: _Row, root: Path, pipe: _Row, project_url: str, name: str, filename: str
) -> tuple[int, _Row, bytes]:
    job, log, archive = record["job"], record["log"], record["archive"]
    job_id = _identifier(job["id"], "upstream job")
    url = f"{project_url}/-/jobs/{job_id}"
    entries = [row for row in job["artifacts"] if row["file_type"] == "archive"]
    _need(
        job["name"] == name
        and job["status"] == "success"
        and not job.get("failure_reason")
        and job["web_url"] == url
        and all(job["pipeline"][field] == pipe[field] for field in _PIPELINE_IDENTITY)
        and job["commit"]["id"] == pipe["sha"]
        and log["job"] == job_id
        and log["url"] == url + "/raw"
        and _SHA256.fullmatch(str(log["sha256"]))
        and len(entries) == 1
        and entries[0]["file_format"] == "zip",
        "upstream job, archive inventory or runner trace is unowned",
    )
    phase, response = _archive_upload_rows(
        log,
        pipe,
        job,
        r'01E Uploading artifacts as "archive" to coordinator\.\.\. 201 Created +'
        rf"correlation_id=[0-9a-f]{{32}} id={job_id} status=201",
        "upstream-job",
    )
    row_positions = [_identifier(row.get("line"), "archive trace position") for row in log["rows"]]
    size = _identifier(entries[0]["size"], "upstream archive size")
    api = f"https://gitlab.com/api/v4/projects/{pipe['project_id']}/jobs/{job_id}/artifacts"
    _need(
        phase == "upload_artifacts_on_success"
        and all(a < b for a, b in pairwise(row_positions))
        and archive["api"] == api
        and archive["bytes"] == size <= _MAX_FORK_ARCHIVE_BYTES,
        "saved ZIP does not identify the accepted archive for this upstream job",
    )
    raw = _source_bytes(root, root / filename, "saved upstream archive", max_bytes=size)
    _need(
        len(raw) == size and hashlib.sha256(raw).hexdigest() == archive["zip_sha256"],
        "saved upstream archive differs from the recorded ZIP",
    )
    return job_id, response, raw


def _transfer(
    publisher: _Row, producer: str, producer_id: int, copy_commands: tuple[str, str]
) -> list[int]:
    log, transfer = publisher["log"], publisher["transfer"]
    source_end, script_start, script_end = log["rows"][2:5]
    patterns = (
        r"00O\+section_start:(\d{1,12}):download_artifacts",
        re.escape(f"01O Downloading artifacts for {producer} ({producer_id})..."),
        r"01E Downloading artifacts from coordinator\.\.\. ok +"
        rf"correlation_id=[0-9a-f]{{32}} id={producer_id} status=200",
        r"00O section_end:(\d{1,12}):download_artifacts",
        *(re.escape(f"01O $ {command}") for command in copy_commands),
    )
    _need(len(transfer) == len(patterns), "Pages trace lacks the complete download and copy")
    for row, pattern in zip(transfer, patterns, strict=True):
        stamp, value = row["time"], row["value"]
        match = (
            re.fullmatch(pattern, value) if isinstance(value, str) and len(value) <= 1024 else None
        )
        _need(
            match is not None
            and hashlib.sha256(f"{stamp} {value}".encode()).hexdigest() == row["sha256"],
            "Pages trace does not match the selected artifact job and file commands",
        )
        if match is not None and match.lastindex:
            _need(
                int(match[1]) == int(_time(stamp, "download section time").timestamp()),
                "Pages download section epoch conflicts with its trace time",
            )
    order = [source_end, *transfer[:4], script_start, *transfer[4:], script_end]
    positions = [_identifier(row["line"], "Pages trace position") for row in order]
    times = [_time(row["time"], "Pages download or script time") for row in order]
    _need(
        all(a < b for a, b in pairwise(positions)) and all(a <= b for a, b in pairwise(times)),
        "Pages trace download and copy are not inside the owning job phases",
    )
    return [row["line"] for row in transfer]


def _members(raw: bytes, directory: str) -> dict[str, str]:
    members: dict[str, str] = {}
    prefix = directory + "/"
    with ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        _need(
            len(entries) <= 512 and sum(item.file_size for item in entries) <= 16_000_000,
            "saved ZIP exceeds the Pages member comparison budget",
        )
        seen = set()
        for item in entries:
            name = item.orig_filename.rstrip("/")
            _need(
                len(name) <= 256
                and (name == directory or name.startswith(prefix))
                and all(part not in ("", ".", "..") for part in name.split("/"))
                and "\\" not in name
                and all(32 <= ord(char) < 127 for char in name)
                and name not in seen,
                "saved ZIP contains ambiguous or out-of-profile members",
            )
            seen.add(name)
            if item.is_dir():
                continue
            _need(
                name != directory
                and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                and item.file_size <= 4_000_000
                and item.compress_type in (ZIP_STORED, ZIP_DEFLATED)
                and not item.flag_bits & 1,
                "saved ZIP uses unsupported file entries",
            )
            with archive.open(item) as stream:
                content = stream.read(item.file_size + 1)
            _need(
                len(content) == item.file_size, "saved ZIP member differs from its inventory size"
            )
            members[name.removeprefix(prefix)] = hashlib.sha256(content).hexdigest()
    _need(
        all(
            str(parent) not in members
            for member in members
            for parent in PurePosixPath(member).parents
        ),
        "saved ZIP contains colliding file and directory members",
    )
    return members


def _literal_sequence(cfg: _Config, path: tuple[str, ...]) -> list[Event]:
    _need(
        not any(
            key[: len(path)] == path and len(key) > len(path) + 1
            for key in (*cfg.keys, *cfg.leaves)
        ),
        "Pages source uses a nested sequence outside this handoff profile",
    )
    return cfg.sequence(path)


def pages_handoff(data: _Row, root: Path) -> _Row:
    try:
        handoff = data["pages_handoff"]
        raw = _source_bytes(root, root / ".gitlab-ci.yml", "Pages handoff source")
        cfg = _Config(raw.decode("utf-8"))
        cfg.owner((_PUBLISHER,))
        dependencies = _literal_sequence(cfg, (_PUBLISHER, "dependencies"))
        producer = _value(dependencies[0].value, _JOB, "Pages artifact producer")
        cfg.owner((producer,))
        paths = _literal_sequence(cfg, (producer, "artifacts", "paths"))
        directory = _value(paths[0].value, _PATH, "Pages input directory")
        script = _literal_sequence(cfg, (_PUBLISHER, "script"))
        redirects = handoff["redirects_source"]
        redirect_file = _value(redirects["file"], _REDIRECT_SOURCE, "root redirects source")
        copy_commands = (f"mv {directory} public", f"cp {redirect_file} public/_redirects")
        _need(
            len(dependencies) == len(paths) == 1
            and producer != _PUBLISHER
            and directory != "public"
            and not directory.startswith("public/")
            and not cfg.keys[(_PUBLISHER, "needs")]
            and not cfg.keys[(_PUBLISHER, "extends")]
            and redirect_file not in (".", "..")
            and tuple(row.value for row in script) == copy_commands
            and [row.value for row in _literal_sequence(cfg, (_PUBLISHER, "artifacts", "paths"))]
            == ["public"],
            "Pages configuration is outside the explicit same-pipeline archive handoff profile",
        )
        _fork_inventory(data, handoff["fork_inventory"], producer)
        pipe = _upstream(data, handoff)
        project = data["target"]["web_url"]
        source_id, upload, source = _archive(
            handoff["producer"], root, pipe, project, producer, "pages-input.zip"
        )
        page_id, pages_upload, output = _archive(
            handoff["publisher"], root, pipe, project, _PUBLISHER, "pages-output.zip"
        )
        lines = _transfer(handoff["publisher"], producer, source_id, copy_commands)
        _need(
            source_id != page_id
            and data["job"]["id"] not in {source_id, page_id}
            and _time(upload["time"], "upstream producer upload")
            < _time(handoff["publisher"]["transfer"][1]["time"], "Pages artifact request"),
            "Pages requested an unrelated, reused or not-yet-uploaded artifact",
        )
        inputs, outputs = _members(source, directory), _members(output, "public")
        api = f"https://gitlab.com/api/v4/projects/{pipe['project_id']}/repository/files/"
        _need(
            inputs
            and "index.html" in inputs
            and "_redirects" not in inputs
            and redirects["api"] == f"{api}{redirect_file}?ref={pipe['sha']}"
            and redirects["commit"] == pipe["sha"]
            and redirects["job"] == page_id
            and _SHA256.fullmatch(str(redirects["sha256"]))
            and outputs == inputs | {"_redirects": redirects["sha256"]},
            "Pages output bytes do not match its upstream input and checked-out redirects",
        )
        return {
            "state": "upstream-pages-handoff-observed",
            "fork_pages_job": "absent-from-saved-inventory",
            "upstream_pipeline": pipe["id"],
            "upstream_revision": pipe["sha"],
            "artifact_producer_job": source_id,
            "pages_job": page_id,
            "matched_members": len(inputs),
            "source_lines": [dependencies[0].line, script[0].line, script[1].line],
            "consumer_trace_lines": lines,
            "producer_post": {"http_status": 201, "line_sha256": upload["sha256"]},
            "pages_post": {"http_status": 201, "line_sha256": pages_upload["sha256"]},
            "scope": _SCOPE,
        }
    except RegistryJobError as exc:
        reason = str(exc)
    except (
        AttributeError,
        BadZipFile,
        EOFError,
        IndexError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        zlib.error,
    ):
        reason = "required Pages job, source or archive evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
