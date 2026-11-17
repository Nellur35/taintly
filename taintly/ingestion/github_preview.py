"""Join one saved GitHub fork build and one Wrangler Preview observation."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from taintly.parsers.structural import Event
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from taintly.rules.github._workflow_run_artifact import (
    _Index,
    _is_exact_identifier_expression,
    _step_owners,
    _unique_scalar,
)

_CHECKOUT = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
_UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
_DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
_WRANGLER = "cloudflare/wrangler-action@ebbaa1584979971c8614a24965b4405ff95890e0"
_WORKFLOW = r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml"
_REPOSITORY = r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+"
_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_EXPR_ID = r"[A-Za-z_][A-Za-z0-9_-]{0,127}"
_WORKER = r"[a-z0-9][a-z0-9-]{0,62}"
_SHA = r"[0-9a-f]{40}"
_DIGEST = r"[0-9a-f]{64}"
_MAX_BYTES = 1024 * 1024
_SCOPE = (
    "Trusted saved source and run records only. The records report this Preview operation. "
    "Capture authenticity, archive contents, code executed from the archive, Cloudflare "
    "principal identity, wider permissions and production routing are unverified."
)

_Row = dict[str, Any]
_StepPath = tuple[str, str, str, int]


class PreviewEvidenceError(ValueError):
    """The selected publication cannot be joined within this profile."""


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise PreviewEvidenceError(reason)


def _one(rows: list[_Row], reason: str) -> _Row:
    if len(rows) != 1:
        raise PreviewEvidenceError(reason)
    return rows[0]


def _matches(value: object, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _id(value: object) -> bool:
    return type(value) is int and 0 < value < 10**19


def _keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        _require(key not in result, "capture contains duplicate JSON keys")
        result[key] = value
    return result


def _integer(value: str) -> int:
    _require(len(value) <= 20, "capture contains an oversized integer")
    return int(value)


def _bounded_read(path: Path) -> bytes:
    _require(path.is_file(), "source or observation is not an available regular file")
    with path.open("rb") as file:
        data = file.read(_MAX_BYTES + 1)
    _require(len(data) <= _MAX_BYTES, "source or observation exceeds the input limit")
    return data


def _source(root: Path, run: _Row, source: _Row, revision: str) -> tuple[_Index, _Row]:
    path = run["path"]
    _require(_matches(path, _WORKFLOW), "run lacks a supported workflow path")
    raw, identity = _source_bytes(root, source, path, revision)
    return _workflow_source_index(path, raw), identity


def _workflow_source_index(path: str, raw: bytes) -> _Index:
    text = raw.decode("utf-8").replace("\r\n", "\n")
    _require(
        "\r" not in text
        and "\ufeff" not in text
        and not re.search(r"^(?:(?:---|\.\.\.)(?:[ \t]|$)|%)", text, re.MULTILINE),
        "workflow source contains unsupported document boundaries",
    )
    try:
        _require(
            not any(
                tok.kind in {TokenKind.ALIAS, TokenKind.MERGE_KEY}
                or (tok.kind is TokenKind.KEY and "\\" in tok.value)
                for tok in tokenize(text)
            ),
            "workflow source contains ambiguous keys or aliases",
        )
    except TokenizerError as exc:
        raise PreviewEvidenceError("workflow source tokenization is incomplete") from exc
    index = _Index.from_source(path, text)
    _require(
        index.error is None and len(index.keys.get(("on",), ())) == 1,
        "workflow structure is incomplete or ambiguous",
    )
    return index


def _source_bytes(root: Path, source: _Row, path: str, revision: str) -> tuple[bytes, _Row]:
    _require(
        source["path"] == path
        and source["revision"] == revision
        and _matches(source["sha256"], _DIGEST),
        "run, source path and source revision do not agree",
    )
    # Read only the literal run path within the supplied projection.
    resolved = (root / path).resolve()
    _require(resolved.is_relative_to(root), "workflow path leaves the source projection")
    raw = _bounded_read(resolved)
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == source["sha256"], "workflow bytes differ from the saved source")
    return raw, {"path": path, "revision": revision, "sha256": digest}


def _run_identity(run: _Row, job: _Row, repository: str, run_id: int, event: str) -> None:
    _require(
        run["id"] == run_id
        and _id(run["id"])
        and run["html_url"] == f"https://github.com/{repository}/actions/runs/{run_id}"
        and run["event"] == event
        and _matches(run["head_sha"], _SHA)
        and _id(job["id"])
        and _id(run["run_attempt"])
        and job["run_id"] == run_id
        and job["run_attempt"] == run["run_attempt"]
        and job["head_sha"] == run["head_sha"]
        and run["referenced_workflows"] == [],
        "saved run and job do not identify one direct invocation",
    )


def _run(run: _Row, job: _Row, repository: str, run_id: int, event: str) -> None:
    try:
        _run_identity(run, job, repository, run_id, event)
    except PreviewEvidenceError as exc:
        raise PreviewEvidenceError(
            "saved run and job do not identify one successful direct invocation"
        ) from exc
    _require(
        run["conclusion"] == job["conclusion"] == "success" and _matches(job["name"], _NAME),
        "saved run and job do not identify one successful direct invocation",
    )
    _run_window(run, job)


def _time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(result.utcoffset() is not None, "observation timestamp has no offset")
    return result


def _run_window(run: _Row, job: _Row) -> None:
    start, end = _time(job["started_at"]), _time(job["completed_at"])
    upper = run.get("updated_at")
    _require(
        _time(run["created_at"]) <= start <= end and (upper is None or end <= _time(upper)),
        "selected job timestamps are outside the recorded run",
    )


def _observed_step(job: _Row, name: str, *, number: object = None) -> _Row:
    _require(number is None or _id(number), "saved step number is invalid")
    step = _one(
        [
            row
            for row in job["steps"]
            if row["name"] == name and (number is None or row["number"] == number)
        ],
        "saved job does not identify one selected step",
    )
    _require(
        step["conclusion"] == "success"
        and _id(step["number"])
        and _time(job["started_at"])
        <= _time(step["started_at"])
        <= _time(step["completed_at"])
        <= _time(job["completed_at"]),
        "selected step did not complete successfully within the saved job",
    )
    return step


def _receipt(trace: list[_Row], step: _Row, job: _Row, kind: str) -> str:
    values = {
        row["value"]
        for row in trace
        if row["kind"] == kind
        and row["job_id"] == job["id"]
        and row["run_id"] == job["run_id"]
        and row["attempt"] == job["run_attempt"]
        # The jobs API reports whole seconds, while log lines include fractions.
        and _time(step["started_at"])
        <= _time(row["time"]).replace(microsecond=0)
        <= _time(step["completed_at"])
    }
    _require(
        len(values) == 1 and all(isinstance(v, str) for v in values),
        f"missing or conflicting {kind} receipt within the selected step",
    )
    value = next(iter(values))
    if not isinstance(value, str):
        raise PreviewEvidenceError("malformed saved receipt value")
    return value


def _step(index: _Index, step: _Row, prefix: tuple[str, str, str]) -> _StepPath:
    matches: list[_StepPath] = []
    for key in index.keys:
        if not (
            len(key) == 5 and key[:3] == prefix and isinstance(key[3], int) and key[4] == "name"
        ):
            continue
        name, event, error = _unique_scalar(index, key, _step_owners(prefix[1], key[3]))
        _require(error is None, "workflow step name is ambiguous")
        if name == step["name"] and event is not None:
            matches.append((*prefix, key[3]))
    _require(len(matches) == 1, "saved step name is not unique in its source job")
    return matches[0]


def _field(index: _Index, path: tuple[object, ...], *, literal_block: bool = False) -> Event:
    keys = index.keys.get(path, ())
    values = index.values.get(path, [])
    allowed = {"plain", "quoted", "block_literal"} if literal_block else {"plain", "quoted"}
    _require(
        len(keys) == len(values) == 1
        and not values[0].merge_origins
        and isinstance(values[0].value, str)
        and values[0].value_kind in allowed,
        "owned workflow field is missing or ambiguous",
    )
    return values[0]


def _inputs(index: _Index, step: tuple[object, ...], names: set[str]) -> dict[str, Event]:
    path = (*step, "with")
    actual = {key[-1] for key in index.keys if key[:-1] == path}
    _require(
        actual == names and len(index.keys.get(path, ())) == (1 if names else 0),
        "action inputs depart from the supported profile",
    )
    return {name: _field(index, (*path, name), literal_block=name == "path") for name in names}


def _job_steps(index: _Index, job: _Row, selected: list[str]) -> list[tuple[_StepPath, _Row]]:
    prefix = ("jobs", job["name"], "steps")
    _require(
        all(len(index.keys.get(path, ())) == 1 for path in (prefix[:1], prefix[:2], prefix))
        and not any(
            (*prefix[:2], key) in index.keys for key in ("name", "strategy", "container", "uses")
        )
        and not any((*path, "defaults") in index.keys for path in ((), prefix[:2])),
        "selected job, runner workspace or defaults are outside the supported profile",
    )
    rows = [_observed_step(job, name) for name in selected]
    paths = [_step(index, row, prefix) for row in rows]
    slots = list(zip(paths, rows, strict=True))
    _require(
        all(
            first_path[-1] < second_path[-1]
            and first["number"] < second["number"]
            and _time(first["completed_at"]) <= _time(second["started_at"])
            for (first_path, first), (second_path, second) in pairwise(slots)
        ),
        "saved steps and workflow steps are not in the same execution order",
    )
    return slots


def _parent_binding(producer: _Index, consumer: _Index) -> None:
    parent = _field(producer, ("name",)).value
    base = ("on", "workflow_run")
    workflows = (*base, "workflows")
    types = (*base, "types")
    _require(
        all(len(producer.keys.get(path, ())) == 1 for path in (("on",), ("on", "pull_request")))
        and all(len(consumer.keys.get(path, ())) == 1 for path in (("on",), base, workflows, types))
        and [
            (key[-1], row.value)
            for key, rows in consumer.values.items()
            if key[:-1] == workflows
            for row in rows
        ]
        == [(0, parent)]
        and [
            (key[-1], row.value)
            for key, rows in consumer.values.items()
            if key[:-1] == types
            for row in rows
        ]
        == [(0, "completed")],
        "consumer workflow does not select the producer as its completed parent",
    )


def _publish(
    capture: _Row, root: Path, repository: str, producer_id: int, consumer_id: int
) -> _Row:
    producer, consumer = capture["producer"], capture["consumer"]
    build_job, deploy_job = capture["producer_job"], capture["consumer_job"]
    _run(producer, build_job, repository, producer_id, "pull_request")
    _run(consumer, deploy_job, repository, consumer_id, "workflow_run")
    pr, merge = capture["pr"], capture["merge"]
    _require(
        producer_id != consumer_id
        and _id(pr["number"])
        and _matches(producer["head_repo"], _REPOSITORY)
        and producer["head_repo"] == pr["head_repo"]
        and producer["head_repo"].lower() != repository.lower()
        and pr["base_repo"] == consumer["head_repo"] == repository
        and pr["head"] == producer["head_sha"]
        and _matches(pr["base"], _SHA)
        and merge["parents"] == [pr["base"], pr["head"]]
        and _matches(merge["sha"], _SHA)
        and _time(build_job["completed_at"]) <= _time(deploy_job["started_at"]),
        "PR, fork checkout or chronological producer and consumer identity is unresolved",
    )
    builds, source = _source(root, producer, capture["producer_source"], merge["sha"])
    deploys, target_source = _source(
        root, consumer, capture["consumer_source"], consumer["head_sha"]
    )
    _parent_binding(builds, deploys)
    selection, trace = capture["steps"], capture["receipts"]
    (checkout, co_obs), (build, _), (upload, up_obs) = _job_steps(
        builds, build_job, [selection[key] for key in ("checkout", "build", "upload")]
    )
    (download, down_obs), (publish, pub_obs) = _job_steps(
        deploys, deploy_job, [selection[key] for key in ("download", "publish")]
    )
    _require(
        _field(builds, (*checkout, "uses")).value == _CHECKOUT
        and _field(builds, (*upload, "uses")).value == _UPLOAD
        and _field(deploys, (*download, "uses")).value == _DOWNLOAD
        and _field(deploys, (*publish, "uses")).value == _WRANGLER
        and publish[-1] == download[-1] + 1
        and pub_obs["number"] == down_obs["number"] + 1
        and all(
            (*step, "run") not in index.keys
            for index, step in (
                (builds, checkout),
                (builds, upload),
                (deploys, download),
                (deploys, publish),
            )
        ),
        "pinned checkout, artifact actions or adjacent Preview consumer is unsupported",
    )
    _inputs(builds, checkout, set())
    build_command = _field(builds, (*build, "run"))
    _require(
        _matches(build_command.value, r"(?:pnpm|npm|yarn) (?:run )?build")
        and (*build, "uses") not in builds.keys
        and (*build, "shell") not in builds.keys
        and (*build, "working-directory") not in builds.keys
        and (*build, "shell") not in builds.keys,
        "build command or its workspace is unsupported",
    )
    up = _inputs(builds, upload, {"name", "path"})
    down = _inputs(deploys, download, {"name", "run-id", "github-token"})
    name = up["name"].value
    selectors = str(up["path"].value).splitlines()
    _require(
        name == down["name"].value
        and _matches(name, _NAME)
        and "wrangler.jsonc" in selectors
        and all(_matches(path, rf"{_NAME}(?:/{_NAME})*/?") for path in selectors)
        and _is_exact_identifier_expression(
            str(down["run-id"].value), "github.event.workflow_run.id"
        )
        and _is_exact_identifier_expression(str(down["github-token"].value), "github.token"),
        "download does not bind the same named artifact from the exact triggering run",
    )
    artifact = _one(
        [row for row in capture["artifacts"] if row["name"] == name],
        "saved producer artifact name does not identify one archive",
    )
    _require(
        _id(artifact["id"])
        and _matches(artifact["digest"], f"sha256:{_DIGEST}")
        and _id(artifact["size_in_bytes"])
        and artifact["run"] == producer_id
        and artifact["head_sha"] == producer["head_sha"]
        and _time(up_obs["started_at"])
        <= _time(artifact["created_at"])
        <= _time(up_obs["completed_at"])
        and _receipt(trace, co_obs, build_job, "checkout") == merge["sha"]
        and _receipt(trace, up_obs, build_job, "upload-id") == str(artifact["id"])
        and _receipt(trace, down_obs, deploy_job, "producer-id") == str(producer_id)
        and _receipt(trace, down_obs, deploy_job, "download-id") == str(artifact["id"])
        and _receipt(trace, down_obs, deploy_job, "download-digest") == artifact["digest"],
        "checkout or producer/archive identity differs from the saved download",
    )
    operation = _inputs(deploys, publish, {"apiToken", "command"})
    secret_reference = re.fullmatch(
        r"\$\{\{[ \t]*secrets\.[A-Za-z_][A-Za-z0-9_]*[ \t]*\}\}",
        str(operation["apiToken"].value),
    )
    command = re.fullmatch(
        rf'preview --worker-name ({_WORKER}) --name "\$\{{\{{[ \t]*steps\.{_EXPR_ID}\.outputs\.{_EXPR_ID}[ \t]*\}}\}}"',
        str(operation["command"].value),
    )
    runtime = re.fullmatch(
        rf"wrangler preview --worker-name ({_WORKER}) --name ({_WORKER})",
        _receipt(trace, pub_obs, deploy_job, "preview-command"),
    )
    if not (secret_reference and command and runtime and command[1] == runtime[1]):
        raise PreviewEvidenceError("configured and reported Preview command or credential disagree")
    url = _receipt(trace, pub_obs, deploy_job, "version-url")
    _require(
        _matches(url, r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)+"),
        "Preview record lacks a supported version URL",
    )
    return {
        "state": "preview-reported",
        "repository": repository,
        "pr": {"number": pr["number"], "head_repository": pr["head_repo"], "head": pr["head"]},
        "producer": {
            **source,
            "run": producer_id,
            "job": build_job["id"],
            "attempt": producer["run_attempt"],
            "build": build_command.value,
            "build_line": build_command.line,
            "upload_line": up["name"].line,
        },
        "artifact": {
            "id": artifact["id"],
            "name": name,
            "digest": artifact["digest"],
            "selectors": selectors,
        },
        "consumer": {
            **target_source,
            "run": consumer_id,
            "job": deploy_job["id"],
            "attempt": consumer["run_attempt"],
            "operation": "workers-preview",
            "worker": runtime[1],
            "alias": runtime[2],
            "credential_binding": "github-actions-secret-reference",
            "credential_line": operation["apiToken"].line,
            "version_url": url,
            "download_line": down["name"].line,
            "command_line": operation["command"].line,
        },
        "scope": _SCOPE,
        "review": "Review which PR-supplied build outputs this credential can publish to the named Preview.",
    }


def preview_observation(
    snapshot: Path, root: Path, repository: str, producer_id: int, consumer_id: int
) -> _Row:
    """Return a bounded decision from a trusted offline capture and source projection."""
    try:
        _require(_matches(repository, _REPOSITORY), "expected a literal GitHub repository")
        capture = _observation_capture(snapshot, "github-preview-v1")
        return _publish(capture, root.resolve(), repository, producer_id, consumer_id)
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "required observation fields or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}


def _observation_capture(snapshot: Path, schema: str, *other_schemas: str) -> _Row:
    capture = json.loads(
        _bounded_read(snapshot).decode("utf-8"), object_pairs_hook=_keys, parse_int=_integer
    )
    if not isinstance(capture, dict) or capture.get("schema") not in (schema, *other_schemas):
        raise PreviewEvidenceError("unsupported observation schema")
    return capture
