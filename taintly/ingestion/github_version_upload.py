"""Check a saved same-run Wrangler version upload or an observed fork skip."""

from __future__ import annotations

import json
import re
from itertools import pairwise
from pathlib import Path

from taintly.eventguard import event_guard_verdict
from taintly.ingestion.github_preview import (
    _NAME,
    _REPOSITORY,
    _SHA,
    _WORKER,
    PreviewEvidenceError,
    _field,
    _id,
    _inputs,
    _integer,
    _keys,
    _matches,
    _observation_capture,
    _observed_step,
    _receipt,
    _require,
    _Row,
    _run_identity,
    _run_window,
    _source,
    _source_bytes,
    _step,
    _time,
)
from taintly.rules.github._workflow_run_artifact import _Index, _is_exact_identifier_expression

_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
_WRANGLER = "cloudflare/wrangler-action@953926a2e2182532811c01a25e53647d93bf07c0"
_PATH = rf"{_NAME}(?:/{_NAME})*"
_AXIS = r"[A-Za-z_][A-Za-z0-9_-]*"
_TEMPLATE = re.compile(rf"([^$\r\n]*)\$\{{\{{[ \t]*matrix\.({_AXIS})\.name[ \t]*\}}\}}")
_SECRET = re.compile(r"\$\{\{[ \t]*secrets\.([A-Za-z_][A-Za-z0-9_]*)[ \t]*\}\}")
_VERSION_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_JSONC_TOKENS = re.compile(r'("(?:[^"\\]|\\.)*")|//[^\r\n]*|/\*[\s\S]*?\*/')
_SCOPE = (
    "Trusted saved source and run records only. This profile separates a Worker version upload "
    "from route changes or production deployment. Capture authenticity, exact deployed bytes, "
    "Cloudflare principal identity and wider permissions are unverified."
)


def _owned_job(index: _Index, requested: str, observed_name: str) -> tuple[str, str]:
    _require(_matches(requested, _NAME), "capture lacks a literal source job ID")
    job = ("jobs", requested)
    _require(
        all(len(index.keys.get(path, ())) == 1 for path in (job[:1], job, (*job, "steps")))
        and not any((*job, key) in index.keys for key in ("container", "uses", "defaults"))
        and ("defaults",) not in index.keys
        and all(len(index.keys.get(path, ())) == 1 for path in (("on",), ("on", "pull_request"))),
        "job, event or workspace is outside the supported source profile",
    )
    for other in index.keys:
        if len(other) != 2 or other[0] != "jobs" or other == job:
            continue
        name_path = (*other, "name")
        name = str(_field(index, name_path).value) if name_path in index.keys else str(other[1])
        match = _TEMPLATE.fullmatch(name)
        _require(
            name != observed_name
            and (
                "${{" not in name or (match is not None and not observed_name.startswith(match[1]))
            ),
            "another source job could have the same observed name",
        )
    return requested, str(_field(index, (*job, "name")).value)


def _fork_skip(capture: _Row, root: Path, repository: str, run: _Row, job: _Row) -> _Row:
    _require(
        run["conclusion"] == job["conclusion"] == "skipped"
        and job["steps"] == []
        and capture["receipts"] == []
        and run["head_repo"].lower() != repository.lower(),
        "no matching skipped external-fork job with empty step records",
    )
    index, identity = _source(root, run, capture["source"], run["head_sha"])
    owner, name = _owned_job(index, capture["source_job"], job["name"])
    _require(name == job["name"] and _TEMPLATE.fullmatch(name), "skipped job owner is ambiguous")
    guard = _field(index, ("jobs", owner, "if"))
    verdict = event_guard_verdict(
        str(guard.value),
        "pull_request",
        path_equalities={
            frozenset({"github.event.pull_request.head.repo.full_name", "github.repository"}): False
        },
    )
    _require(verdict is False, "supplied source does not prove that this fork fails the job guard")
    return {
        "state": "fork-job-skipped",
        "repository": repository,
        "run": run["id"],
        "job": job["id"],
        "attempt": run["run_attempt"],
        "head_repository": run["head_repo"],
        "source": identity,
        "guard_line": guard.line,
        "supplied_source_excludes_fork": True,
        "historical_skip_cause": "unverified",
        "scope": _SCOPE,
    }


def _matrix_row(index: _Index, owner: str, axis: str, name: str) -> tuple[object, ...]:
    strategy = ("jobs", owner, "strategy")
    matrix = (*strategy, "matrix")
    path = (*matrix, axis)
    _require(
        all(len(index.keys.get(key, ())) == 1 for key in (strategy, matrix, path))
        and {key for key in index.keys if key[:-1] == matrix} == {path},
        "selected matrix has additional axes, overrides or ambiguous ownership",
    )
    rows = [
        key[:-1]
        for key, values in index.values.items()
        if key[:-2] == path
        and isinstance(key[-2], int)
        and key[-1] == "name"
        and any(event.value == name for event in values)
    ]
    _require(len(rows) == 1, "saved job does not select one literal matrix row")
    _field(index, (*rows[0], "name"))
    return rows[0]


def _matrix_values(
    index: _Index, owner: str, name_template: str, saved_name: str
) -> tuple[str, str, str]:
    match = _TEMPLATE.fullmatch(name_template)
    if match is None or not saved_name.startswith(match[1]):
        raise PreviewEvidenceError("saved job name does not identify a supported matrix row")
    name = saved_name[len(match[1]) :]
    _require(_matches(name, _NAME), "selected matrix name is not a literal")
    row = _matrix_row(index, owner, match[2], name)
    working = _field(index, (*row, "working_directory")).value
    config = _field(index, (*row, "wrangler_config")).value
    _require(
        _matches(working, _PATH) and _matches(config, rf"{_PATH}\.jsonc?"),
        "selected workspace or Wrangler config path is not a supported literal",
    )
    return match[2], str(working), str(config)


def _upload(capture: _Row, root: Path, repository: str, run: _Row, job: _Row) -> _Row:
    pr, merge = capture["pr"], capture["merge"]
    _require(
        run["conclusion"] == job["conclusion"] == "success"
        and pr["head_repo"] == pr["base_repo"] == run["head_repo"] == repository
        and pr["head"] == run["head_sha"]
        and _id(pr["number"])
        and _matches(pr["base"], _SHA)
        and _matches(merge["sha"], _SHA)
        and merge["parents"] == [pr["base"], pr["head"]],
        "PR merge and successful same-repository invocation are unresolved",
    )
    _run_window(run, job)
    index, identity = _source(root, run, capture["source"], merge["sha"])
    owner, template = _owned_job(index, capture["source_job"], job["name"])
    axis, workdir, config = _matrix_values(index, owner, template, job["name"])
    path = f"{workdir}/{config}"
    config_bytes, config_identity = _source_bytes(
        root, capture["config_source"], path, merge["sha"]
    )
    config_data = json.loads(
        _JSONC_TOKENS.sub(
            lambda token: token[1] if token[1] is not None else " ", config_bytes.decode("utf-8")
        ),
        object_pairs_hook=_keys,
        parse_int=_integer,
    )
    worker = config_data["name"]
    _require(_matches(worker, _WORKER), "saved Wrangler config lacks one literal Worker name")

    prefix = ("jobs", owner, "steps")
    checkout = (*prefix, 0)
    checkout_obs = _observed_step(job, f"Run {_CHECKOUT}")
    build_obs = _observed_step(job, capture["steps"]["build"])
    upload_obs = _observed_step(job, capture["steps"]["upload"])
    build, upload = (_step(index, step, prefix) for step in (build_obs, upload_obs))
    _require(
        _field(index, (*checkout, "uses")).value == _CHECKOUT
        and (*checkout, "name") not in index.keys
        and _inputs(index, checkout, {"persist-credentials"})["persist-credentials"].value
        == "false"
        and _field(index, (*upload, "uses")).value == _WRANGLER
        and all((*step, "run") not in index.keys for step in (checkout, upload))
        and (*build, "uses") not in index.keys
        and checkout[-1] < build[-1] < upload[-1]
        and all(
            first["number"] < second["number"]
            and _time(first["completed_at"]) <= _time(second["started_at"])
            for first, second in pairwise((checkout_obs, build_obs, upload_obs))
        ),
        "checkout, build and upload are not ordered supported steps of the selected job",
    )
    fields = _inputs(index, upload, {"apiToken", "accountId", "workingDirectory", "command"})
    token = _SECRET.fullmatch(str(fields["apiToken"].value))
    account = _SECRET.fullmatch(str(fields["accountId"].value))
    build_command = _field(index, (*build, "run"))
    working_expr = f"matrix.{axis}.working_directory"
    dynamic_command = re.fullmatch(
        rf"versions upload --config (\$\{{\{{[ \t]*matrix\.{axis}\.wrangler_config[ \t]*\}}\}})"
        r" --preview-alias pr-(\$\{\{[ \t]*github\.event\.pull_request\.number[ \t]*\}\})",
        str(fields["command"].value),
    )
    _require(
        _matches(build_command.value, r"(?:vp|pnpm|npm|yarn) (?:run )?build")
        and (*build, "shell") not in index.keys
        and _is_exact_identifier_expression(
            str(_field(index, (*build, "working-directory")).value), working_expr
        )
        and _is_exact_identifier_expression(str(fields["workingDirectory"].value), working_expr)
        and dynamic_command is not None,
        "build and upload do not share one supported workspace and version command",
    )
    if token is None or account is None:
        raise PreviewEvidenceError("version upload lacks supported symbolic credential selectors")
    trace = capture["receipts"]
    alias = f"pr-{pr['number']}"
    expected = f"versions upload --config {config} --preview-alias {alias}"
    _require(
        _receipt(trace, checkout_obs, job, "checkout") == merge["sha"]
        and _receipt(trace, upload_obs, job, "workspace") == workdir
        and _receipt(trace, upload_obs, job, "version-command") == expected
        and _receipt(trace, upload_obs, job, "reported-worker") == worker,
        "the actual checkout, workspace, command or Worker differs from the selected source",
    )
    version = _receipt(trace, upload_obs, job, "worker-version")
    _require(_matches(version, _VERSION_ID), "selected upload lacks a supported Worker version ID")
    return {
        "state": "version-upload-reported",
        "repository": repository,
        "run": run["id"],
        "job": job["id"],
        "attempt": run["run_attempt"],
        "pr_number": pr["number"],
        "head": pr["head"],
        "source": identity,
        "build": {"command": build_command.value, "line": build_command.line, "workspace": workdir},
        "publication": {
            "operation": "workers-versions-upload",
            "worker": worker,
            "version_id": version,
            "alias": alias,
            "config": config_identity,
            "command": expected,
            "command_line": fields["command"].line,
            "credential_binding": f"secrets.{token[1]}",
            "account_binding": f"secrets.{account[1]}",
        },
        "scope": _SCOPE,
    }


def version_upload_observation(
    snapshot: Path, root: Path, repository: str, run_id: int, job_id: int
) -> _Row:
    """Assess an owned workspace version upload or separately supported observed skip."""
    try:
        _require(_matches(repository, _REPOSITORY), "expected a literal GitHub repository")
        capture = _observation_capture(snapshot, "github-version-upload-v1")
        run, job = capture["run"], capture["job"]
        _run_identity(run, job, repository, run_id, "pull_request")
        _require(
            job["id"] == job_id and _matches(run["head_repo"], _REPOSITORY),
            "job or source repository identity differs from the requested subject",
        )
        resolved = root.resolve()
        if job["conclusion"] == "skipped":
            return _fork_skip(capture, resolved, repository, run, job)
        return _upload(capture, resolved, repository, run, job)
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "required observation fields or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
