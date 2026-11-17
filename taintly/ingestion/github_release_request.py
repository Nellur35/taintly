"""Corroborate recorded outcomes of a GitHub draft Release request."""

import hashlib
import re
from itertools import pairwise, takewhile
from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _REPOSITORY,
    _WORKFLOW,
    PreviewEvidenceError,
    _field,
    _id,
    _matches,
    _observation_capture,
    _observed_step,
    _require,
    _Row,
    _run_identity,
    _run_window,
    _source,
    _source_bytes,
    _time,
    _workflow_source_index,
)
from taintly.rules.github._workflow_run_artifact import _Index, _is_exact_identifier_expression

_SCHEMA = "github-draft-release-request-v1"
_ACTION = "release-drafter/release-drafter@v6"
_PUSH_ACTION = "release-drafter/release-drafter@v7"
_VERIFIED_ACTION = "978bb0b30c5ee8cdd332ced253758157150d43f0"
_PUSH_BRANCH = r"(?:main|master|'(?:main|master)'|\"(?:main|master)\")"
_DENIAL = "Resource not accessible by integration"
_SCOPE = (
    "Trusted saved GitHub check annotations and run records. The reported response is scoped "
    "to one draft-create request. "
    "The supplied workflow is the fork-head source. Exact merged workflow bytes, runtime token "
    "identity, the policy behind the denial, other requests and artifact publication are unverified."
)
_PUSH_SCOPE = (
    "Trusted saved GitHub job records and Release Drafter log. The pinned action logs completion "
    "after the create call returns. The exact HTTP status, response fields, runtime token "
    "identity and wider permissions are unverified. The selected job ran on push to the base "
    "repository. Fork write access, public release and asset publication remain unverified."
)


def _source_plan(index: _Index, job_name: str, *, event: str = "pull_request") -> _Row:
    owner = ("jobs", job_name)
    steps = (*owner, "steps")
    step = (*steps, 0)
    env = (*step, "env")
    _require(
        all(
            len(index.keys.get(path, ())) == 1
            for path in (
                ("on", event),
                owner[:1],
                owner,
                steps,
                (*owner, "permissions"),
                env,
            )
        )
        and {key[-1] for key in index.keys if key[:-1] == owner[:1]} == {job_name}
        and {key[-1] for key in index.keys if key[:-1] == owner}
        == {"steps", "permissions", "runs-on"}
        and {key[len(steps)] for key in index.keys if key[: len(steps)] == steps and key != steps}
        == {0}
        and {key[-1] for key in index.keys if key[:-1] == step} == {"uses", "env"}
        and {key[-1] for key in index.keys if key[:-1] == env} == {"GITHUB_TOKEN"}
        and not any((key,) in index.keys for key in ("env", "defaults")),
        "Workflow source is outside the supported single-action draft job profile",
    )
    action = _field(index, (*step, "uses"))
    token = _field(index, (*env, "GITHUB_TOKEN"))
    permission = _field(index, (*owner, "permissions", "contents"))
    _require(
        action.value == (_PUSH_ACTION if event == "push" else _ACTION)
        and _is_exact_identifier_expression(str(token.value), "secrets.GITHUB_TOKEN")
        and permission.value == "write",
        "Workflow source lacks the supported draft action, token binding or requested permission",
    )
    return {
        "action": action.value,
        "action_line": action.line,
        "credential_binding": "GITHUB_TOKEN",
        "credential_line": token.line,
        "requested_permission": "contents: write",
        "permission_line": permission.line,
    }


def _draft_creation(cap: _Row, root: Path, repo: str, run_id: int, job_id: int) -> _Row:
    run, job, creation = cap["run"], cap["job"], cap["creation"]
    _run_identity(run, job, repo, run_id, "push")
    _run_window(run, job)
    branch = run["head_branch"]
    _require(
        job["id"] == job_id
        and _id(job["run_attempt"])
        and run["head_repository"] == repo
        and branch in ("main", "master")
        and run["conclusion"] == job["conclusion"] == "success"
        and _matches(job["name"], _NAME)
        and creation["run"] == run_id
        and creation["job"] == job_id
        and creation["attempt"] == run["run_attempt"]
        and all(_id(creation[key]) for key in ("run", "job", "attempt"))
        and _matches(creation["log_sha256"], _DIGEST)
        and "denial" not in cap,
        "Saved creation log is not from the selected successful repository push job and attempt",
    )
    path = run["path"]
    _require(_matches(path, _WORKFLOW), "Run lacks a supported workflow path")
    raw, source = _source_bytes(root, cap["source"], path, run["head_sha"])
    index = _workflow_source_index(path, raw)
    _require(
        _literal_push_branch(index, raw, branch), "Workflow lacks the selected literal push branch"
    )
    configured = _source_plan(index, job["name"], event="push")
    setup = _observed_step(job, "Set up job")
    drafter = _observed_step(job, f"Run {_PUSH_ACTION}")
    finish = _observed_step(job, "Complete job")
    _require(
        (setup["number"], drafter["number"], finish["number"]) == (1, 2, 3)
        and len(job["steps"]) == 3
        and _time(setup["completed_at"]) <= _time(drafter["started_at"])
        and _time(drafter["completed_at"]) <= _time(finish["started_at"]),
        "Saved job does not have the supported single-action execution order",
    )
    patterns = (
        re.escape(f"Download action repository '{_PUSH_ACTION}' (SHA:{_VERIFIED_ACTION})"),
        re.escape(f"##[group]Run {_PUSH_ACTION}"),
        r"  tag: +([0-9]{1,12}\.[0-9]{1,12}\.[0-9]{1,12})",
        r"  targetCommitish: +" + re.escape(branch),
        r"  draft: +true",
        r"Creating new release\.\.\.",
        r"Release created!",
        r"Cleaning up orphan processes",
    )
    rows = creation["rows"]
    _require(
        isinstance(rows, list) and len(rows) == len(patterns),
        "Saved log lacks the complete draft creation sequence",
    )
    times = []
    owners = (setup,) + (drafter,) * (len(patterns) - 2) + (finish,)
    for row, pattern, step in zip(rows, patterns, owners, strict=True):
        when = _time(row["time"])
        _require(
            _matches(row["value"], pattern)
            and _time(step["started_at"])
            <= when.replace(microsecond=0)
            <= _time(step["completed_at"])
            and hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
            == row["sha256"],
            "Saved log row does not match its evidence, owned step or draft creation profile",
        )
        times.append(when)
    _require(all(a < b for a, b in pairwise(times)), "Draft creation log order is ambiguous")
    return {
        "state": "draft-release-create-reported",
        "repository": repo,
        "run": run_id,
        "job": job_id,
        "attempt": run["run_attempt"],
        "source": source,
        "source_role": "repository-push",
        "configured": configured,
        "operation": {
            "method": "POST",
            "url": f"https://api.github.com/repos/{repo}/releases",
            "draft": True,
            "requested_tag": rows[2]["value"].split()[-1],
            "target_commitish": branch,
            "action_commit": _VERIFIED_ACTION,
            "completion_at": rows[-2]["time"],
            "completion_line_sha256": rows[-2]["sha256"],
            "log_sha256": creation["log_sha256"],
        },
        "scope": _PUSH_SCOPE,
    }


def _literal_push_branch(index: _Index, raw: bytes, branch: str) -> bool:
    branch_path = ("on", "push", "branches")
    keys = index.keys.get(branch_path, ())
    if (
        {path[-1] for path in index.keys if path[:-1] == ("on",)} != {"push"}
        or {path[-1] for path in index.keys if path[:-1] == ("on", "push")} != {"branches"}
        or len(keys) != 1
    ):
        return False
    # The structural events locate the field. Empty nested sequences and maps
    # have no scalar events, so also check the complete literal list in place.
    line, indent = keys[0].line, keys[0].column - 1
    lines = raw.decode("utf-8").splitlines()
    header = re.fullmatch(
        rf" {{{indent}}}(?:branches|'branches'|\"branches\"):(.*)", lines[line - 1]
    )
    if header is None:
        return False
    inline = header[1].split("#", 1)[0].strip()
    children = list(
        takewhile(
            lambda row: len(row) - len(row.lstrip(" ")) > indent,
            (row for row in lines[line:] if row.strip() and not row.lstrip().startswith("#")),
        )
    )
    if inline:
        if children or not re.fullmatch(rf"\[ *{_PUSH_BRANCH}( *, *{_PUSH_BRANCH})? *\]", inline):
            return False
        return branch in re.findall(r"main|master", inline)
    items = [re.fullmatch(rf" +-[ ]+({_PUSH_BRANCH})(?: +#.*)? *", row) for row in children]
    return (
        1 <= len(items) <= 2
        and all(items)
        and any(item is not None and item[1].strip("'\"") == branch for item in items)
    )


def _draft_denial(cap: _Row, root: Path, repo: str, run_id: int, job_id: int) -> _Row:
    run, job, check = cap["run"], cap["job"], cap["check_run"]
    _run_identity(run, job, repo, run_id, "pull_request")
    _run_window(run, job)
    _require(
        job["id"] == job_id
        and _id(job["run_attempt"])
        and _matches(job["name"], _NAME)
        and _id(check["id"])
        and check["id"] == job_id
        and check["app"] == "github-actions"
        and check["head_sha"] == run["head_sha"]
        and _id(run["check_suite_id"])
        and _id(check["check_suite_id"])
        and check["check_suite_id"] == run["check_suite_id"]
        and job["check_run_url"] == f"https://api.github.com/repos/{repo}/check-runs/{job_id}"
        and check["details_url"] == f"{run['html_url']}/job/{job_id}"
        and check["started_at"] == job["started_at"]
        and check["completed_at"] == job["completed_at"]
        and check["conclusion"] == job["conclusion"]
        and run["conclusion"] in {"success", "failure"}
        and job["conclusion"] in {"success", "failure"},
        "Saved GitHub check run is not the selected job and attempt",
    )
    pr = cap["pr"]
    _require(
        _id(pr["number"])
        and pr["base_repository"] == repo
        and _matches(pr["head_repository"], _REPOSITORY)
        and pr["head_repository"].lower() != repo.lower()
        and run["head_repository"] == pr["head_repository"]
        and run["head_sha"] == pr["head_sha"],
        "Saved pull request does not match the selected fork invocation",
    )
    request = cap.get("denial")
    if not isinstance(request, dict):
        raise PreviewEvidenceError("No owned draft-create API denial was supplied")
    target = f"https://api.github.com/repos/{repo}/releases"
    ref = f"refs/pull/{pr['number']}/merge"
    _require(
        request["check_run"] == check["id"]
        and _id(request["check_run"])
        and request["run"] == run_id
        and _id(request["run"])
        and _id(request["attempt"])
        and request["attempt"] == run["run_attempt"]
        and request["action"] == _ACTION
        and _matches(request["annotation_sha256"], _DIGEST)
        and _matches(request["action_annotation_sha256"], _DIGEST)
        and request["annotation_sha256"] != request["action_annotation_sha256"]
        and _matches(request["request_id"], r"[0-9A-F]{1,12}(?::[0-9A-F]{1,16}){2,5}")
        and _time(job["started_at"]) <= _time(request["response_at"]) <= _time(job["completed_at"])
        and request["method"] == "POST"
        and request["url"] == target
        and type(request["status"]) is int
        and request["status"] == 403
        and request["message"] == _DENIAL
        and request["accepted_permissions"] == "contents=write; contents=write,workflows=write"
        and request["draft"] is True
        and request["target_commitish"] == ref,
        "Saved response does not bind the selected draft-create request and PR merge ref",
    )
    index, source = _source(root, run, cap["source"], run["head_sha"])
    configured = _source_plan(index, job["name"])
    return {
        "state": "draft-release-create-denied",
        "repository": repo,
        "run": run_id,
        "job": job_id,
        "attempt": run["run_attempt"],
        "run_conclusion": run["conclusion"],
        "job_conclusion": job["conclusion"],
        "pr": {key: pr[key] for key in ("number", "head_repository", "head_sha")},
        "source": source,
        "source_role": "fork-head",
        "configured": configured,
        "operation": {
            key: request[key]
            for key in (
                "method",
                "url",
                "status",
                "message",
                "request_id",
                "response_at",
                "target_commitish",
                "draft",
                "accepted_permissions",
                "annotation_sha256",
                "action_annotation_sha256",
            )
        },
        "scope": _SCOPE,
    }


def release_request_observation(
    snapshot: Path, root: Path, repository: str, run_id: int, job_id: int
) -> _Row:
    """Qualify an owned request using operation-specific evidence."""
    scope = _SCOPE
    try:
        _require(_matches(repository, _REPOSITORY), "Expected a literal GitHub repository")
        cap = _observation_capture(snapshot, _SCHEMA)
        _require(cap["repository"] == repository, "Receipt belongs to another repository")
        if "creation" in cap:
            scope = _PUSH_SCOPE
            return _draft_creation(cap, root.resolve(), repository, run_id, job_id)
        return _draft_denial(cap, root.resolve(), repository, run_id, job_id)
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "Required request, job metadata or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": scope}
