"""Corroborate a Pages deployment from one saved fork-produced archive."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import pairwise
from pathlib import Path

from taintly.ingestion.github_preview import (
    _REPOSITORY,
    _SHA,
    PreviewEvidenceError,
    _field,
    _id,
    _Index,
    _job_steps,
    _matches,
    _observation_capture,
    _observed_step,
    _one,
    _parent_binding,
    _require,
    _Row,
    _run,
    _run_identity,
    _run_window,
    _source,
    _step,
    _time,
)

SCHEMA = "github-workflow-run-pages-publication-v1"
UNRESOLVED_SCOPE = (
    "This Pages profile requires trusted saved workflow, run, log, archive, Git and "
    "deployment records. The requested publication and its authority remain unverified."
)
_PAGES_ACTION = "peaceiris/actions-gh-pages@v4"
_PAGES_SHA = "84c30a85c19949d7eee79c4ff27748b70285e453"
_WORKFLOW_HEAD = "${{ github.event.workflow_run.head_sha }}"


_ARCHIVE_LIMIT = 32 * 1024 * 1024


def _row(rows: list[_Row], job: _Row, step: _Row, kind: str, pattern: str) -> _Row:
    row = _one([item for item in rows if item["kind"] == kind], f"Expected one {kind} row")
    when = _time(row["time"]).replace(microsecond=0)
    _require(
        row["job"] == job["id"]
        and row["attempt"] == job["run_attempt"]
        and _matches(row["value"], pattern)
        and _time(step["started_at"]) <= when <= _time(step["completed_at"])
        and hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest() == row["sha256"],
        f"The {kind} row does not belong to the selected job and step",
    )
    return row


def _git_digest(kind: str, data: bytes) -> str:
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()


@contextmanager
def _saved_archive(root: Path, artifact: _Row) -> Iterator[zipfile.ZipFile]:
    path = (root / "publication.zip").resolve()
    _require(path.is_relative_to(root) and path.is_file(), "Publication archive is unavailable")
    with path.open("rb") as data:
        size = os.fstat(data.fileno()).st_size
        _require(
            0 < size <= _ARCHIVE_LIMIT and artifact["size"] == size,
            "Publication archive size differs from its bounded receipt",
        )
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = data.read(min(remaining, 1024 * 1024))
            _require(chunk, "Publication archive ended before its recorded size")
            digest.update(chunk)
            remaining -= len(chunk)
        _require(
            not data.read(1) and artifact["digest"] == f"sha256:{digest.hexdigest()}",
            "Publication archive digest does not match the selected artifact",
        )
        with zipfile.ZipFile(data) as archive:
            infos = archive.infolist()
            _require(
                0 < len(infos) <= 512 and len({entry.filename for entry in infos}) == len(infos),
                "Publication archive has unsupported or ambiguous members",
            )
            yield archive


def _member_path(name: str) -> bool:
    return len(name) <= 320 and all(
        segment not in (".", "..") and _matches(segment, r"[A-Za-z0-9_.-]{1,128}")
        for segment in name.split("/")
    )


def _member_bytes(archive: zipfile.ZipFile, name: str) -> bytes:
    entry = archive.getinfo(name)
    _require(
        _member_path(name)
        and entry.orig_filename == name
        and 0 < entry.file_size <= 2 * 1024 * 1024
        and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
        and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG),
        "The selected publication member is outside the supported profile",
    )
    with archive.open(entry) as member:
        content = member.read(entry.file_size + 1)
    _require(len(content) == entry.file_size, "Selected archive member size does not match")
    return content


def _check_members(archive: zipfile.ZipFile, blobs: dict[str, str]) -> None:
    _require(
        0 < len(blobs) <= 16 and all(_member_path(name) for name in blobs),
        "Expected bounded named archive and target members",
    )
    names = list(blobs)
    entries = {entry.filename: entry for entry in archive.infolist()}
    _require(set(names) <= entries.keys(), "Named publication member is missing")
    _require(
        sum(entries[name].file_size for name in names) <= 8 * 1024 * 1024,
        "Selected publication members exceed the expansion limit",
    )
    for name, blob in blobs.items():
        _require(
            _git_digest("blob", _member_bytes(archive, name)) == blob,
            "Selected archive member does not match the pushed Git blob",
        )


def _git_tree(objects: _Row, oid: str) -> dict[str, tuple[str, str]]:
    raw = objects[oid]
    _require(
        isinstance(raw, str) and _matches(raw, r"(?:[a-f0-9]{2}){1,16384}"),
        "The requested Git tree object is missing or exceeds the limit",
    )
    payload = bytes.fromhex(raw)
    _require(
        _git_digest("tree", payload) == oid, "Target Git tree object has a different object ID"
    )
    tree = {}
    while payload:
        header, separator, tail = payload.partition(b"\0")
        _require(separator and len(tail) >= 20, "Malformed target Git tree")
        mode, space, name = header.decode("utf8").partition(" ")
        _require(
            space and name and "/" not in name and name not in tree, "Malformed target Git entry"
        )
        tree[name] = (mode, tail[:20].hex())
        _require(len(tree) <= 512, "Target Git tree is outside the entry limit")
        payload = tail[20:]
    return tree


def _git_members(result: _Row, destination: str, names: list[str]) -> dict[str, str]:
    raw = result["commit_bytes"]
    _require(isinstance(raw, str) and 0 < len(raw) <= 16384, "Target Git commit is unavailable")
    commit = raw.encode("utf8")
    root = commit.partition(b"\n")[0].removeprefix(b"tree ").decode("ascii")
    _require(
        commit.startswith(b"tree ")
        and _matches(root, _SHA)
        and _git_digest("commit", commit) == result["commit"],
        "Target Git commit fails object identity verification",
    )
    objects = result["tree_objects"]
    _require(
        isinstance(objects, dict) and 0 < len(objects) <= 32, "Target tree proof is out of scope"
    )
    _require(
        isinstance(names, list)
        and 0 < len(names) <= 16
        and all(isinstance(name, str) and _member_path(name) for name in names)
        and len(set(names)) == len(names),
        "Expected distinct, bounded named publication files",
    )
    trees: dict[str, dict[str, tuple[str, str]]] = {}
    found = {}
    for name in names:
        components = (destination + "/" + name).split("/")
        _require(len(components) <= 12, "Target Git path exceeds the supported depth")
        oid = root
        for index, component in enumerate(components):
            if oid not in trees:
                trees[oid] = _git_tree(objects, oid)
            mode, oid = trees[oid][component]
            _require(
                mode == ("100644" if index == len(components) - 1 else "40000"),
                "Target Git path is not a regular file under the selected directories",
            )
        found[name] = oid
    return found


def _push_authority(event: _Row, result: _Row, command: _Row, completed: _Row) -> _Row:
    """Bind a recorded push account to the already corroborated branch update."""
    try:
        repo, payload, actor = (event[key] for key in ("repo", "payload", "actor"))
        when = _time(event["created_at"])
        _require(
            event["type"] == "PushEvent"
            and _matches(event["id"], r"[1-9][0-9]{0,29}")
            and _id(payload["push_id"])
            and _id(repo["id"])
            and _id(payload["repository_id"])
            and repo["id"] == payload["repository_id"]
            and repo["name"] == result["repository"]
            and payload["ref"] == f"refs/heads/{result['branch']}"
            and payload["before"] == result["previous"]
            and payload["head"] == result["commit"],
            "PushEvent does not identify the selected repository and ref update",
        )
        _require(
            _time(command["time"]).replace(microsecond=0)
            <= when
            <= _time(completed["time"]).replace(microsecond=0),
            "PushEvent falls outside the owned push command and result",
        )
        _require(
            _id(actor["id"])
            and _matches(actor["login"], r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?"),
            "PushEvent does not identify a supported account",
        )
    except PreviewEvidenceError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (AttributeError, KeyError, TypeError, ValueError):
        return {"state": "unresolved", "reason": "Malformed saved PushEvent"}
    return {
        "state": "push-actor-observed",
        "actor": {"id": actor["id"], "login": actor["login"]},
        "event_id": event["id"],
        "push_id": payload["push_id"],
        "time": event["created_at"],
        "scope": "GitHub attributes this historical ref update to this account. "
        "The specific token, other grants and future permissions remain unverified.",
    }


def _pages_deployment(capture: _Row, target: str, ref: str, commit: str, push: _Row) -> _Row:
    deployment, success, run, job = (
        capture[key] for key in ("deployment", "success", "run", "job")
    )
    deployment_id = deployment["id"]
    _require(
        _id(deployment_id) and _id(run["id"]), "Pages record lacks a provider deployment or run"
    )
    _run(run, job, target, run["id"], "dynamic")
    selected = _observed_step(job, "Deploy to GitHub Pages")
    site = f"https://{target.split('/')[0]}.github.io/{target.split('/')[1]}/"
    _require(
        deployment["sha"] == run["head_sha"] == commit
        and deployment["environment"] == "github-pages"
        and deployment["ref"] == ref
        and deployment["task"] == "deploy"
        and run["path"] == "dynamic/pages/pages-build-deployment"
        and job["name"] == "deploy"
        and success["state"] == "success"
        and _id(success["id"])
        and success["deployment_url"]
        == f"https://api.github.com/repos/{target}/deployments/{deployment_id}"
        and success["log_url"] == f"{run['html_url']}/job/{job['id']}"
        and success["environment_url"] == site
        and _time(push["time"]).replace(microsecond=0)
        <= _time(deployment["created_at"])
        <= _time(success["created_at"])
        and _time(selected["started_at"])
        <= _time(success["created_at"])
        <= _time(run["updated_at"]),
        "Saved Pages success does not belong to the selected commit, site or deploying job",
    )
    return {
        "id": deployment_id,
        "run": run["id"],
        "job": job["id"],
        "site": site,
        "succeeded_at": success["created_at"],
    }


def _graph_revision(index: _Row, points: object, head: str, sample: float) -> int:
    """Relate one measured value to the head's unique published ordinal."""
    revisions = [key for key, commit in index["revision_to_hash"].items() if commit == head]
    _require(
        len(revisions) == 1 and _matches(revisions[0], r"[0-9]{1,10}"),
        "Graph index does not identify one exact fork revision",
    )
    revision = int(revisions[0])
    if not isinstance(points, list):
        raise PreviewEvidenceError("Malformed published ASV series")
    samples = [
        point
        for point in points
        if isinstance(point, list)
        and len(point) == 2
        and type(point[0]) is int
        and point[0] == revision
    ]
    _require(
        len(samples) == 1 and type(samples[0][1]) in (int, float) and samples[0][1] == sample,
        "Published graph point differs from the recorded fork sample",
    )
    return revision


def _benchmark_execution(
    cap: _Row,
    src: _Index,
    build: _Row,
    head: str,
    checkout: _Row,
    generated: _Row,
    archive: zipfile.ZipFile,
    prefix: str,
    blobs: dict[str, str],
) -> _Row:
    """Corroborate one unparameterized ASV value already in the published graph."""
    benchmark = cap.get("benchmark")
    if not isinstance(benchmark, dict):
        return {"state": "unresolved", "reason": "No saved benchmark execution projection"}
    try:
        ((path, step),) = _job_steps(
            src, build, [benchmark["step"]], expected_workflow_shell="bash -l {0}"
        )
        script = _field(src, (*path, "run"), literal_block=True)
        command = "asv run -a rounds=1 HASHFILE:commit_hashes.txt | tee asv-output-PR.log"
        _require(
            [line.rstrip() for line in (script.value or "").splitlines()[:3]]
            == [
                "echo $(git rev-parse HEAD) > commit_hashes.txt",
                "echo $(git rev-parse master) >> commit_hashes.txt",
                command,
            ],
            "The selected benchmark does not pass the checked-out head to ASV",
        )
        name, file, rows = benchmark["name"], benchmark["result"], benchmark["rows"]
        _require(
            _matches(name, r"[A-Za-z_][A-Za-z0-9_.]{0,119}")
            and _matches(
                file,
                rf"\.asv/results/[A-Za-z0-9_-]{{1,80}}/{head[:8]}-[A-Za-z0-9_.-]{{1,110}}\.json",
            )
            and isinstance(rows, list)
            and len(rows) == 3,
            "The selected ASV result or log is outside the supported profile",
        )
        graph = f"graphs/summary/{name}.json"
        _require(
            graph in blobs and "index.json" in blobs,
            "Published graph and index must both be verified",
        )
        seen_command = _row(rows, build, step, "command", re.escape(command) + r" *")
        seen_head = _row(
            rows,
            build,
            step,
            "head",
            rf"\[ *[0-9.]+%\] \xb7 For [A-Za-z0-9_.-]+ commit {head[:8]}:",
        )
        seen_sample = _row(
            rows,
            build,
            step,
            "sample",
            rf"\[ *[0-9.]+%\] \xb7{{3}} {re.escape(name)} +[0-9.]+(?:\xb1[0-9.]+)?s",
        )
        times = [
            _time(row["time"])
            for row in (checkout, seen_command, seen_head, seen_sample, generated)
        ]
        _require(
            all(a < b for a, b in pairwise(times)),
            "Benchmark evidence is outside checkout and generation",
        )
        result = json.loads(_member_bytes(archive, file))
        index = json.loads(_member_bytes(archive, prefix + "index.json"))
        points = json.loads(_member_bytes(archive, prefix + graph))
        columns = result["result_columns"]
        entry = result["results"][name]
        values = entry[columns.index("result")]
        started = entry[columns.index("started_at")]
        _require(
            result["commit_hash"] == head
            and result["version"] == 2
            and columns.count("result")
            == columns.count("started_at")
            == columns.count("params")
            == 1
            and entry[columns.index("params")] == []
            and isinstance(values, list)
            and len(values) == 1
            and type(values[0]) in (int, float)
            and math.isfinite(values[0])
            and values[0] > 0
            and type(started) is int
            and times[2].timestamp() * 1000 <= started <= times[3].timestamp() * 1000,
            "Saved ASV sample does not bind the head, time and supported result format",
        )
        revision = _graph_revision(index, points, head, values[0])
    except PreviewEvidenceError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
        OverflowError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        return {"state": "unresolved", "reason": "Malformed or missing saved benchmark evidence"}
    return {
        "state": "fork-sample-observed-in-published-graph",
        "commit": head,
        "step": step["number"],
        "command_line": script.line + 3,
        "benchmark": name,
        "result_member": file,
        "graph_member": graph,
        "graph_revision": revision,
        "seconds": values[0],
        "scope": "The archived ASV record and published graph agree. Benchmark validity is unverified.",
    }


def pages_publication(
    cap: _Row, root: Path, repository: str, producer_id: int, consumer_id: int
) -> _Row:
    producer, consumer, pr = (cap[key] for key in ("producer", "consumer", "pr"))
    build, job = producer["job"], consumer["job"]
    _run_identity(
        producer, build, repository, producer_id, "pull_request", allow_sibling_workflows=True
    )
    _run_window(producer, build)
    _run(consumer, job, repository, consumer_id, "workflow_run")
    head = producer["head_sha"]
    _require(
        producer_id != consumer_id
        and _id(pr["number"])
        and _matches(pr["head_repository"], _REPOSITORY)
        and pr["head_repository"].lower() != repository.lower()
        and pr["head_repository"] == producer["head_repository"]
        and pr["base_repository"] == consumer["head_repository"] == repository
        and pr["head_sha"] == head
        and producer["conclusion"] == build["conclusion"] == "success"
        and _time(build["completed_at"]) <= _time(job["started_at"]),
        "The recorded fork and invocation do not match the selected runs",
    )
    src, src_info = _source(root, producer, cap["producer_source"], head)
    dst, dst_info = _source(root, consumer, cap["source"], consumer["head_sha"])
    _parent_binding(src, dst)

    names = cap["steps"]
    # A run can contain a reusable job. Check the selected producer's own steps and runner.
    owner = ("jobs", build["name"])
    _field(src, (*owner, "runs-on"))
    (checkout_path, checkout), (upload_path, upload) = _job_steps(
        src, build, [names["checkout"], names["upload"]], expected_workflow_shell="bash -l {0}"
    )
    _require(
        _field(src, (*checkout_path, "uses")).value == "actions/checkout@v6"
        and _field(src, (*checkout_path, "with", "ref")).value
        == "${{ github.event.pull_request.head.sha }}"
        and _field(src, (*upload_path, "uses")).value == "actions/upload-artifact@v7",
        "The producer does not own a supported direct fork checkout and artifact upload",
    )
    (download_path, download), (guard_path, guard) = _job_steps(
        dst, job, [names["download"], names["guard"]]
    )
    consumer_owner = ("jobs", job["name"])
    download_root = _field(dst, (*download_path, "with", "path")).value or ""
    upload_name = "asv-benchmark-results-" + head
    guard_script = _field(dst, (*guard_path, "run"), literal_block=True)
    guard_id = _field(dst, (*guard_path, "id")).value
    content = cap["archive_prefix"]
    _require(
        isinstance(download_root, str)
        and _member_path(download_root)
        and isinstance(content, str)
        and _member_path(content)
        and _matches(guard_id, r"[a-z][a-z0-9_-]{0,30}")
        and _field(dst, (*download_path, "uses")).value == "actions/download-artifact@v8"
        and _field(dst, (*download_path, "with", "run-id")).value
        == "${{ github.event.workflow_run.id }}"
        and _field(dst, (*download_path, "with", "name")).value
        == "asv-benchmark-results-${{ env.PR_SHA }}"
        and _field(dst, (*consumer_owner, "env", "PR_SHA")).value == _WORKFLOW_HEAD
        and (guard_script.value or "").rstrip("\n")
        == (
            f"if [[ -d {download_root}/{content} ]]; then\n"
            '  echo "enabled=true" >> "${GITHUB_OUTPUT}"\n'
            'else\n  echo "enabled=false" >> "${GITHUB_OUTPUT}"\nfi'
        ),
        "The consumer does not bind its downloaded archive and directory guard",
    )
    deploy = _one(
        [step for step in job["steps"] if step["name"] == names["deploy"]],
        "The selected job does not identify one Pages publication step",
    )
    deploy_path = _step(dst, deploy, (*consumer_owner, "steps"))
    action = _field(dst, (*deploy_path, "uses"))
    _require(
        action.value == _PAGES_ACTION
        and _field(dst, (*deploy_path, "if")).value == f"steps.{guard_id}.outputs.enabled == 'true'"
        and _field(dst, (*deploy_path, "with", "publish_dir")).value == f"{download_root}/{content}"
        and _time(guard["completed_at"]) <= _time(deploy["started_at"]),
        "The Pages invocation is not guarded by the owned artifact directory check",
    )
    artifact, proof, rows = cap["artifact"], cap["producer_rows"], cap["rows"]
    aid = artifact["id"]
    _require(
        _id(aid)
        and artifact["run"] == producer_id
        and artifact["head"] == head
        and artifact["name"] == upload_name
        and isinstance(proof, list)
        and 2 <= len(proof) <= 4
        and isinstance(rows, list)
        and 3 <= len(rows) <= 20,
        "Saved rows or artifact do not match the selected producer",
    )
    seen_checkout = _row(
        proof,
        build,
        checkout,
        "checkout",
        rf"\[command\]/usr/bin/git checkout --progress --force {head}",
    )
    seen_upload = _row(
        proof,
        build,
        upload,
        "upload",
        rf"Artifact {upload_name} successfully finalized\. Artifact ID {aid}",
    )
    seen_download = [
        _row(rows, job, download, "run", rf"  run-id: {producer_id}"),
        _row(
            rows,
            job,
            download,
            "artifact",
            re.escape(f"Downloading artifact '{aid}' from '{repository}'"),
        ),
        _row(rows, job, download, "downloaded", r"Artifact download completed successfully\."),
    ]
    starts = [_time(row["time"]) for row in [seen_checkout, seen_upload, *seen_download]]
    _require(
        all(a < b for a, b in pairwise(starts)),
        "Source, upload and download evidence is out of order",
    )
    common = {
        "repository": repository,
        "pr": pr,
        "producer_run": producer_id,
        "producer_job": build["id"],
        "consumer_run": consumer_id,
        "job": job["id"],
        "producer_source": src_info,
        "source": dst_info,
        "artifact_id": aid,
    }
    with _saved_archive(root, artifact) as archive:
        prefix = content + "/"
        # Require successful check and provider-recorded skip alongside archive directory absence.
        if deploy["conclusion"] == "skipped":
            _require(
                not any(
                    item.filename == content or item.filename.startswith(prefix)
                    for item in archive.infolist()
                ),
                "A skipped Pages step does not establish absence of the required archive directory",
            )
            return {
                "state": "pages-publication-skipped",
                **common,
                "scope": "The selected archive lacks the required HTML directory and the Pages step was skipped. "
                "The authority to publish remains unverified.",
            }

        ((generate_path, generate),) = _job_steps(
            src, build, [names["generate"]], expected_workflow_shell="bash -l {0}"
        )
        _require(
            _field(src, (*generate_path, "run")).value == "asv publish",
            "The selected producer has no supported HTML generation command",
        )
        generated = _row(proof, build, generate, "generate", "asv publish")
        _require(
            _time(seen_checkout["time"]) < _time(generated["time"]) < _time(seen_upload["time"]),
            "The selected HTML generation is outside the owning checkout and upload",
        )
        deploy = _observed_step(job, names["deploy"])
        setup = _observed_step(job, "Set up job", number=1)
        binding = _field(dst, (*deploy_path, "with", "personal_token"))
        result = cap["result"]
        target = _field(dst, (*deploy_path, "with", "external_repository")).value or ""
        branch = _field(dst, (*consumer_owner, "env", "DEPLOY_BRANCH")).value or ""
        destination = f"pull/{pr['number']}"
        _require(
            isinstance(target, str)
            and _matches(target, _REPOSITORY)
            and target != repository
            and isinstance(branch, str)
            and _matches(branch, r"[a-zA-Z][a-zA-Z0-9_-]{0,63}")
            and result["repository"] == target
            and result["branch"] == branch
            and _matches(result["previous"], _SHA)
            and _matches(result["commit"], _SHA)
            and result["commit"] != result["previous"]
            and _matches(binding.value, r"\$\{\{ secrets\.[A-Za-z_][A-Za-z0-9_]{0,127} \}\}")
            and not any(
                (*deploy_path, "with", alternate) in dst.keys
                for alternate in ("deploy_key", "github_token")
            )
            and _field(dst, (*deploy_path, "with", "publish_branch")).value
            == "${{ env.DEPLOY_BRANCH }}"
            and _field(dst, (*deploy_path, "with", "destination_dir")).value
            == "pull/${{ steps.pr.outputs.number }}",
            "The named target, selected destination or personal-token binding is unsupported",
        )
        _row(
            rows,
            job,
            setup,
            "action",
            re.escape(f"Download action repository '{_PAGES_ACTION}' (SHA:{_PAGES_SHA})"),
        )
        confirmations = (
            ("credential", r"  personal_token: \*\*\*"),
            ("destination", re.escape(f"  destination_dir: {destination}")),
            ("repository", re.escape(f"  external_repository: {target}")),
            ("token-setup", r"\[INFO\] setup personal access token"),
            (
                "copy",
                rf"\[INFO\] copy /[^\r\n]+/{re.escape(download_root + '/' + content)} to /[^\r\n]+/{destination}",
            ),
            ("command", re.escape(f"[command]/usr/bin/git push origin {branch}")),
            ("remote", re.escape(f"To https://github.com/{target}.git")),
            (
                "result",
                rf" +{result['previous'][:9]}\.\.{result['commit'][:9]}  {re.escape(branch)} -> {re.escape(branch)}",
            ),
        )
        evidence = {kind: _row(rows, job, deploy, kind, pattern) for kind, pattern in confirmations}
        times = [_time(row["time"]) for row in [seen_download[-1], *evidence.values()]]
        _require(
            all(a < b for a, b in pairwise(times)),
            "Saved download and Git push rows are out of order",
        )
        blobs = _git_members(result, destination, cap["members"])
        _check_members(archive, {prefix + name: blob for name, blob in blobs.items()})
        benchmark_execution = _benchmark_execution(
            cap, src, build, head, seen_checkout, generated, archive, prefix, blobs
        )
    publication = {
        "repository": target,
        "target": f"refs/heads/{branch}",
        "commit": result["commit"],
        "prefix": destination,
        "matched_members": blobs,
        "matched_files": len(blobs),
        "archive_sha256": artifact["digest"][7:],
        "command": f"git push origin {branch}",
        "action": _PAGES_ACTION,
        "action_line": action.line,
    }
    deployment = _pages_deployment(
        cap["pages"], target, branch, result["commit"], evidence["result"]
    )
    observed = {
        "state": "pages-deployment-observed",
        **common,
        "publication": publication,
        "deployment": deployment,
        "benchmark_execution": benchmark_execution,
        "credential_binding": binding.value,
        "credential_line": binding.line,
        "scope": "Trusted saved provider and Git records show the historical Pages deployment. "
        "Only the named files were compared. The effective personal-token principal, "
        "wider policy and current deployed revision remain unverified.",
    }
    if "push_event" in cap:
        authority = _push_authority(
            cap["push_event"], result, evidence["command"], evidence["result"]
        )
        observed["push_authority"] = authority
        if authority["state"] == "push-actor-observed":
            observed["scope"] = (
                "Trusted saved provider and Git records show the historical Pages deployment. "
                "Only the named files were compared. The current deployed revision remains unverified."
            )
    return observed


def pages_observation(
    snapshot: Path, root: Path, repository: str, source_id: int, run_id: int
) -> _Row:
    """Read a bounded saved Pages receipt without opening a network connection."""
    try:
        cap = _observation_capture(snapshot, SCHEMA)
        _require(
            _matches(repository, _REPOSITORY) and cap["repository"] == repository,
            "Wrong repository",
        )
        return pages_publication(cap, root.resolve(), repository, source_id, run_id)
    except PreviewEvidenceError as exc:
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
        zipfile.BadZipFile,
        zlib.error,
    ):
        reason = (
            "Saved workflow, run, archive, Git or deployment evidence is unavailable or malformed"
        )
    return {"state": "unresolved", "reason": reason, "scope": UNRESOLVED_SCOPE}
