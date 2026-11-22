"""Bind a saved post-merge Pages publication to selected public response bytes."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from taintly.ingestion.gitlab_mr_artifact import (
    _PATH,
    _Config,
    _native_archive_authority,
    _need,
    _Row,
)
from taintly.ingestion.gitlab_pages_handoff import _archive_request, _literal_sequence, _transfer
from taintly.ingestion.gitlab_registry_job import (
    _SHA,
    _SHA256,
    RegistryJobError,
    _identifier,
    _source_bytes,
    _time,
    _value,
)

_REF = re.compile(r"[a-zA-Z0-9_-]{1,100}")
_SITE_PROJECT = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/[a-zA-Z0-9_.-]{1,100}")
_DIGEST_LIMIT = 64 * 1024 * 1024
_MEMBER_LIMIT = 128 * 1024
_SCOPE = (
    "The saved evidence covers selected responses from the observed post-merge Pages archive. "
    "Other artifact downloads, unsampled files, the internal deployment record, and effective "
    "token identity remain unverified. Matching bytes alone do not identify an MR deployment."
)


def _push(data: _Row, bundle: _Row) -> tuple[_Row, str, str]:
    owner = data["project"]["id"]
    repo = _value(data["project"]["path"], _SITE_PROJECT, "GitLab Pages project")
    namespace, project_name = repo.split("/")
    project_url = f"https://gitlab.com/{repo}"
    site = f"https://{namespace}.gitlab.io/{project_name}/"
    project, pipe = bundle["project"], bundle["pipeline"]
    api = f"https://gitlab.com/api/v4/projects/{owner}"
    pipe_id = _identifier(pipe["id"], "Pages push pipeline")
    revision = _value(pipe["sha"], _SHA, "Pages push revision")
    branch = _value(project["default_branch"], _REF, "Pages default branch")
    merge = bundle["merge"]
    commit = _value(merge["merge_commit_sha"], _SHA, "admitted merge commit")
    root_config = bundle["upstream_config"]
    merge_base = bundle["merge_base"]
    query = urlencode({"refs[]": [commit, revision]}, doseq=True)
    _need(
        project_name not in {".", ".."}
        and project["id"] == pipe["project_id"] == owner
        and project["path_with_namespace"] == repo
        and project["web_url"] == project_url
        and pipe["web_url"] == f"{project_url}/-/pipelines/{pipe_id}"
        and pipe_id != data["pipeline"]["id"]
        and revision != data["pipeline"]["sha"]
        and pipe["source"] == "push"
        and pipe["ref"] == branch
        and pipe["status"] in {"success", "manual"}
        and root_config["url"] == f"{project_url}/-/raw/{revision}/.gitlab-ci.yml"
        and root_config["sha256"] == data["source_sha256"],
        "the saved Pages run is outside the target project's default-branch profile",
    )
    mr = data["mr"]
    _need(
        merge["url"] == f"{api}/merge_requests/{mr['iid']}"
        and merge["iid"] == mr["iid"]
        and merge["source_project_id"] == mr["source_project_id"]
        and merge["target_project_id"] == owner
        and merge["sha"] == mr["sha"]
        and merge["state"] == "merged"
        and merge_base["url"] == f"{api}/repository/merge_base?{query}"
        and merge_base["id"] == commit
        and _time(data["job"]["finished_at"], "MR build finish")
        < _time(merge["merged_at"], "MR merge time")
        < _time(pipe["created_at"], "Pages push creation"),
        "MR, admitted merge and later push are not bound by the saved ancestry and timing",
    )
    return pipe, project_url, site


def _archive_digest(root: Path, size: int) -> str:
    # Digest the saved container file without inspecting its ZIP directory or expanding any entry.
    _need(size <= _DIGEST_LIMIT, "Pages archive exceeds the digest-only byte budget")
    path = (root / "pages-publication.zip").resolve(strict=True)
    _need(
        path.is_relative_to(root) and path.is_file(),
        "saved Pages archive is not a regular in-repository file",
    )
    digest = hashlib.sha256()
    with path.open("rb") as content:
        remaining = size
        while remaining:
            chunk = content.read(min(remaining, 256 * 1024))
            _need(chunk, "saved Pages archive ends before its recorded size")
            remaining -= len(chunk)
            digest.update(chunk)
        _need(content.read(1) == b"", "saved Pages archive exceeds its recorded size")
    return digest.hexdigest()


def _build_row(producer: _Row, command: str) -> int:
    start, end = producer["log"]["rows"][3:5]
    row = producer["build"]
    line = _identifier(row["line"], "Pages producer command line")
    _need(
        start["line"] < line < end["line"]
        and _time(start["time"], "producer script start")
        <= _time(row["time"], "producer command time")
        <= _time(end["time"], "producer script end")
        and row["value"] == f"01O $ {command}"
        and hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest() == row["sha256"],
        "Pages producer trace does not contain the selected build command in its script phase",
    )
    return line


def _body(root: Path, record: _Row, filename: str, url: str, after: datetime) -> bytes:
    _need(
        record["url"] == url
        and record["http_status"] == 200
        and _time(record["observed_at"], "Pages response capture time") >= after,
        "saved member response belongs to a different route, status or time",
    )
    body = _source_bytes(
        root, root / filename, "saved Pages member response", max_bytes=_MEMBER_LIMIT
    )
    _need(
        0 < len(body) == record["size"] and hashlib.sha256(body).hexdigest() == record["sha256"],
        "saved Pages member response differs from its receipt",
    )
    return body


def _samples(
    root: Path,
    rows: list[_Row],
    site: str,
    producer_url: str,
    pages_url: str,
    source_dir: str,
    digest: str,
    uploaded_at: datetime,
    finished_at: datetime,
) -> list[_Row]:
    _need(isinstance(rows, list) and 1 <= len(rows) <= 4, "unsupported number of Pages samples")
    seen = set()
    checked = []
    for index, row in enumerate(rows):
        path = _value(row["path"], _PATH, "Pages sample path")
        _need(path not in seen, "saved Pages response path is duplicated")
        seen.add(path)
        build = _body(
            root,
            row["producer"],
            f"pages-producer-{index}.bin",
            f"{producer_url}/artifacts/raw/{source_dir}/{path}",
            uploaded_at,
        )
        archived = _body(
            root,
            row["archive"],
            f"pages-archive-{index}.bin",
            f"{pages_url}/artifacts/raw/public/{path}",
            finished_at,
        )
        url = site if path == "index.html" and row["site"]["url"] == site else site + path
        served = _body(root, row["site"], f"pages-served-{index}.bin", url, finished_at)
        _need(
            build == archived == served and row["site"]["etag"] == f'"{digest}"',
            "sample bytes or site ETag differ from the owned Pages archive",
        )
        checked.append({"path": path, "url": url, "sha256": hashlib.sha256(served).hexdigest()})
    _need("index.html" in seen, "Pages samples lack the published index member")
    return checked


def pages_publication(data: _Row, root: Path, mr_result: _Row) -> _Row:
    try:
        bundle = data["pages_publication"]
        _need(
            mr_result["state"] == "job-artifact-observed",
            "Pages publication requires the original MR job artifact",
        )
        pipe, project_url, site = _push(data, bundle)
        raw = _source_bytes(root, root / ".gitlab-ci.yml", "Pages publication source")
        config = _Config(raw.decode("utf-8"))
        producer, publisher = bundle["producer"], bundle["publisher"]
        producer_name = data["job"]["name"]
        original_member = mr_result["publication"]["member_path"]
        config.owner((producer_name,))
        config.owner(("pages",))
        paths = _literal_sequence(config, (producer_name, "artifacts", "paths"))
        directory = _value(paths[0].value, _PATH, "Pages producer directory")
        move = f"mv {directory} public"
        script = _literal_sequence(config, ("pages", "script"))
        _need(
            producer_name != "pages"
            and len(paths) == 1
            and original_member.startswith(directory + "/")
            and directory.split("/")[0] != "public"
            and mr_result["declaration_owner"] == producer_name
            and not config.keys[("pages", "needs")]
            and not config.keys[("pages", "dependencies")]
            and [event.value for event in script] == [move]
            and [
                event.value for event in _literal_sequence(config, ("pages", "artifacts", "paths"))
            ]
            == ["public"],
            "Pages source is outside the implicit download and single move profile",
        )
        source_id, source_post, _ = _archive_request(producer, pipe, project_url, producer_name)
        page_id, pages_post, size = _archive_request(publisher, pipe, project_url, "pages")
        source_log_line = _build_row(producer, mr_result["command"])
        transfer = _transfer(publisher, producer_name, source_id, (move,))
        source_time = _time(source_post["time"], "producer archive upload")
        pages_end = _time(publisher["job"]["finished_at"], "Pages job finish")
        _need(
            len({source_id, page_id, data["job"]["id"]}) == 3
            and source_time < _time(publisher["transfer"][1]["time"], "Pages producer download"),
            "Pages artifact request reused a job identity or preceded the producer upload",
        )
        archive = bundle["archive"]
        pages_url = f"{project_url}/-/jobs/{page_id}"
        _need(
            archive["url"] == pages_url + "/artifacts/download"
            and archive["http_status"] == 200
            and archive["size"] == size
            and _time(archive["observed_at"], "Pages ZIP capture time") >= pages_end,
            "saved output ZIP is outside the observed Pages job route and time",
        )
        digest = _value(archive["sha256"], _SHA256, "saved Pages archive digest")
        _need(digest == _archive_digest(root, size), "saved Pages ZIP differs from its receipt")
        samples = _samples(
            root,
            bundle["members"],
            site,
            f"{project_url}/-/jobs/{source_id}",
            pages_url,
            directory,
            digest,
            source_time,
            pages_end,
        )
        result = {
            "state": "post-merge-pages-publication-observed",
            "merge_commit": bundle["merge"]["merge_commit_sha"],
            "upstream_pipeline": pipe["id"],
            "upstream_revision": pipe["sha"],
            "source_job": source_id,
            "pages_job": page_id,
            "build": {
                "command": mr_result["command"],
                "trace_line": source_log_line,
                "source_line": mr_result["command_line"],
            },
            "download": {"http_status": 200, "trace_line": transfer[2]},
            "move": {"command": move, "source_line": script[0].line, "trace_line": transfer[4]},
            "publication": {
                "target": site,
                "operation": "gitlab-pages-archive",
                "authority": "owning-job-archive-upload",
                "http_status": 201,
                "archive_sha256": digest,
                "upload_trace_line": pages_post["line"],
            },
            "members": samples,
            "scope": _SCOPE,
        }
        if "archive_runner_evidence" in publisher:
            log = publisher["log"]
            start, response, end = log["rows"][-3:]
            result["archive_runner_authority"] = _native_archive_authority(
                publisher | {"pipeline": pipe},
                pages_url,
                data["project"]["path"],
                pages_post | {"http_status": 201, "trace_sha256": log["sha256"]},
                phase_rows=(start, response, end),
                phase_owner="Pages",
            )
        return result
    except RegistryJobError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        reason = "required Pages publication evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
