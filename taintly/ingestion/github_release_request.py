"""Corroborate recorded outcomes of a GitHub draft Release request."""

import hashlib
import re
from itertools import pairwise, takewhile
from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _REPOSITORY,
    _SHA,
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
_CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
_LOGGED_ACTION_SHA = "34d80673e067bdc0c24568d3af899c216adcfaa9"
_LOGGED_ACTION = f"release-drafter/release-drafter@{_LOGGED_ACTION_SHA}"
_LOGGED_ACTOR_GUARD = "github.actor != 'dependabot[bot]' && github.actor != 'github-actions[bot]'"
_LOGGED_CREATE_ERROR = (
    "Resource not accessible by integration - "
    "https://docs.github.com/rest/releases/releases#create-a-release"
)
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


_LOGGED_SCOPE = (
    "Trusted saved GitHub Actions job and log records. The setup log reports "
    "the job token's Contents grant. The pinned action reports a rejected draft-create "
    "attempt. The exact HTTP status, request ID, policy behind the grant, other "
    "requests and artifact publication are unverified."
)


def _source_plan(index: _Index, job_name: str, *, event: str = "pull_request") -> _Row:
    owner = ("jobs", job_name)
    steps = (*owner, "steps")
    step = (*steps, 0)
    env = (*step, "env")
    permission_owner: tuple[str, ...] = (*owner, "permissions")
    job_keys = {"steps", "permissions", "runs-on"}
    if event == "push" and permission_owner not in index.keys:
        permission_owner = ("permissions",)
        job_keys.remove("permissions")
    _require(
        all(
            len(index.keys.get(path, ())) == 1
            for path in (
                ("on", event),
                owner[:1],
                owner,
                steps,
                permission_owner,
                env,
            )
        )
        and {key[-1] for key in index.keys if key[:-1] == owner[:1]} == {job_name}
        and {key[-1] for key in index.keys if key[:-1] == owner} == job_keys
        and {key[len(steps)] for key in index.keys if key[: len(steps)] == steps and key != steps}
        == {0}
        and {key[-1] for key in index.keys if key[:-1] == step} == {"uses", "env"}
        and {key[-1] for key in index.keys if key[:-1] == env} == {"GITHUB_TOKEN"}
        and not any((key,) in index.keys for key in ("env", "defaults")),
        "Workflow source is outside the supported single-action draft job profile",
    )
    action = _field(index, (*step, "uses"))
    token = _field(index, (*env, "GITHUB_TOKEN"))
    permission = _field(index, (*permission_owner, "contents"))
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
    patterns: tuple[str, ...] = (
        re.escape(f"Download action repository '{_PUSH_ACTION}' (SHA:{_VERIFIED_ACTION})"),
        re.escape(f"##[group]Run {_PUSH_ACTION}"),
        r"  tag: +v?[0-9]{1,12}\.[0-9]{1,12}\.[0-9]{1,12}",
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
    owners = (setup,) + (drafter,) * (len(patterns) - 2) + (finish,)
    grant_rows = creation.get("effective_permission_rows", [])
    if "effective_permission_rows" in creation:
        _require(
            isinstance(grant_rows, list) and len(grant_rows) == 3,
            "Saved log lacks the complete job token permission group",
        )
        patterns = (
            re.escape("##[group]GITHUB_TOKEN Permissions"),
            r"Contents: write",
            re.escape("##[endgroup]"),
            *patterns,
        )
        owners = (setup, setup, setup, *owners)
    times = []
    for row, pattern, step in zip([*grant_rows, *rows], patterns, owners, strict=True):
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
    result: _Row = {
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
    if grant_rows:
        result["effective_permission"] = {
            "credential": "GITHUB_TOKEN",
            "contents": "write",
            "time": grant_rows[1]["time"],
            "line_sha256": grant_rows[1]["sha256"],
        }
    return result


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


def _logged_source_plan(index: _Index, job_name: str) -> _Row:
    owner = ("jobs", job_name)
    trigger = ("on", "pull_request")
    trigger_types = {
        key: rows for key, rows in index.values.items() if key[: len(trigger)] == trigger
    }
    steps = (*owner, "steps")
    checkout, drafter, summary = ((*steps, number) for number in range(3))
    env, inputs = (*drafter, "env"), (*drafter, "with")
    expected_children = {
        trigger: {"types"},
        owner: {"runs-on", "permissions", "if", "steps"},
        checkout: {"name", "uses"},
        drafter: {"name", "uses", "env", "with"},
        summary: {"name", "run"},
        env: {"GITHUB_TOKEN"},
        inputs: {"config-name", "commitish", "disable-autolabeler"},
    }
    _require(
        all(
            {key[-1] for key in index.keys if key[:-1] == parent} == children
            and all(len(index.keys[(*parent, child)]) == 1 for child in children)
            for parent, children in expected_children.items()
        )
        and {key[len(steps)] for key in index.keys if key[: len(steps)] == steps and key != steps}
        == {0, 1, 2}
        and len(index.keys.get(trigger, ())) == 1
        and len(index.keys.get(owner, ())) == 1
        and set(trigger_types) == {(*trigger, "types", number) for number in range(3)}
        and all(len(rows) == 1 for rows in trigger_types.values())
        and {rows[0].value for rows in trigger_types.values()}
        == {"opened", "reopened", "synchronize"}
        and not any((key,) in index.keys for key in ("env", "defaults")),
        "Workflow source is outside the supported checkout and pinned draft profile",
    )
    action = _field(index, (*drafter, "uses"))
    token = _field(index, (*env, "GITHUB_TOKEN"))
    permission = _field(index, (*owner, "permissions", "contents"))
    target = _field(index, (*inputs, "commitish"))
    _require(
        _field(index, (*checkout, "name")).value == "Checkout code"
        and _field(index, (*checkout, "uses")).value == _CHECKOUT
        and _field(index, (*owner, "if")).value == _LOGGED_ACTOR_GUARD
        and _field(index, (*drafter, "name")).value == "Release Drafter"
        and action.value == _LOGGED_ACTION
        and _field(index, (*inputs, "config-name")).value == "release-drafter.yml"
        and str(_field(index, (*inputs, "disable-autolabeler")).value).lower() == "false"
        and _field(index, (*summary, "name")).value == "Summary"
        and _is_exact_identifier_expression(str(token.value), "secrets.GITHUB_TOKEN")
        and permission.value == "write"
        and _matches(target.value, r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}"),
        "Workflow does not bind the pinned checkout, draft action and configured job token",
    )
    return {
        "action": action.value,
        "action_line": action.line,
        "credential_binding": "GITHUB_TOKEN",
        "credential_line": token.line,
        "requested_permission": "contents: write",
        "permission_line": permission.line,
        "target_commitish": target.value,
    }


def _logged_denial(cap: _Row, root: Path, repo: str) -> _Row:
    run, job, pr, observation = cap["run"], cap["job"], cap["pr"], cap["verified_log"]
    merge, base = observation["merge_commit"], observation["base_commit"]
    custody, annotation = cap["custody"], observation["failure_annotation"]
    _require(
        all(
            _id(observation[key]) and observation[key] == identity
            for key, identity in (
                ("run", run["id"]),
                ("job", job["id"]),
                ("attempt", run["run_attempt"]),
            )
        )
        and all(
            _matches(observation[key], _DIGEST)
            for key in ("log_sha256", "merge_record_sha256", "annotation_list_sha256")
        )
        and _matches(merge, _SHA)
        and _matches(base, _SHA)
        and len({merge, base, run["head_sha"]}) == 3
        and observation["merge_parents"] == [base, run["head_sha"]]
        and observation["action_commit"] == _LOGGED_ACTION_SHA
        and _matches(run["actor"], r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?")
        and run["actor"].lower() not in {"dependabot[bot]", "github-actions[bot]"}
        and custody["log_sha256"] == observation["log_sha256"]
        and custody["annotation_list_sha256"] == observation["annotation_list_sha256"]
        and _id(annotation["check_run"])
        and annotation["check_run"] == cap["check_run"]["id"]
        and annotation["level"] == "failure"
        and annotation["message"] == _LOGGED_CREATE_ERROR
        and run["conclusion"] == job["conclusion"] == "failure",
        "Saved log or merged revision does not belong to the selected failed fork job",
    )
    index, source = _source(root, run, cap["source"], merge)
    configured = _logged_source_plan(index, job["name"])
    setup = _observed_step(job, "Set up job", number=1)
    checkout = _observed_step(job, "Checkout code", number=2)
    cleanup = _observed_step(job, "Post Checkout code", number=8)
    finish = _observed_step(job, "Complete job", number=9)
    steps = job["steps"]
    drafter, summary = steps[2:4]
    _require(
        [(step["number"], step["name"]) for step in steps]
        == [
            (1, "Set up job"),
            (2, "Checkout code"),
            (3, "Release Drafter"),
            (4, "Summary"),
            (8, "Post Checkout code"),
            (9, "Complete job"),
        ]
        and all(_id(step["number"]) for step in steps)
        and drafter["conclusion"] == "failure"
        and summary["conclusion"] == "skipped"
        and _time(setup["completed_at"]) <= _time(checkout["started_at"])
        and _time(checkout["completed_at"])
        <= _time(drafter["started_at"])
        <= _time(drafter["completed_at"])
        <= _time(summary["started_at"])
        <= _time(job["completed_at"]),
        "Saved steps do not place the failed draft action immediately after the owned checkout",
    )
    config_ref = f"refs/pull/{pr['number']}/merge"
    target = configured["target_commitish"]
    patterns = (
        re.escape("##[group]GITHUB_TOKEN Permissions"),
        r"Contents: read",
        re.escape("##[endgroup]"),
        re.escape(f"Download action repository '{_LOGGED_ACTION}' (SHA:{_LOGGED_ACTION_SHA})"),
        re.escape(f"##[group]Run {_CHECKOUT}"),
        re.escape(merge),
        re.escape(f"##[group]Run {_LOGGED_ACTION}"),
        re.escape(f'Config fetched from "{repo}/.github/release-drafter.yml@{config_ref}".'),
        r"No draft release found",
        r" +targetCommitish: +" + re.escape(target),
        r" +draft: +true",
        re.escape("Creating new release..."),
        re.escape(f"##[error]{_LOGGED_CREATE_ERROR}"),
        re.escape("Post job cleanup."),
        re.escape("Cleaning up orphan processes"),
    )
    rows = observation["rows"]
    _require(
        isinstance(rows, list) and len(rows) == len(patterns),
        "Saved log lacks the complete owned grant and draft-create sequence",
    )
    owners = (setup,) * 4 + (checkout,) * 2 + (drafter,) * 7 + (cleanup, finish)
    times = []
    for row, pattern, step in zip(rows, patterns, owners, strict=True):
        when = _time(row["time"])
        _require(
            _matches(row["value"], pattern)
            and _time(step["started_at"])
            <= when.replace(microsecond=0)
            <= _time(step["completed_at"])
            and hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
            == row["sha256"],
            "Saved log row does not match its evidence, owning step or recorded draft action",
        )
        times.append(when)
    _require(all(a < b for a, b in pairwise(times)), "Grant and rejection log order is ambiguous")
    rejection = rows[-3]
    return {
        "state": "draft-release-create-rejection-reported",
        "repository": repo,
        "run": run["id"],
        "job": job["id"],
        "attempt": run["run_attempt"],
        "job_conclusion": job["conclusion"],
        "pr": {key: pr[key] for key in ("number", "head_repository", "head_sha")},
        "source": source,
        "source_role": "pull-request-merge",
        "configured": configured,
        "effective_permission": {
            "credential": "GITHUB_TOKEN",
            "contents": "read",
            "time": rows[1]["time"],
            "line_sha256": rows[1]["sha256"],
        },
        "operation": {
            "method": "POST",
            "url": f"https://api.github.com/repos/{repo}/releases",
            "draft": True,
            "target_commitish": target,
            "status": None,
            "message": _DENIAL,
            "time": rejection["time"],
            "log_sha256": observation["log_sha256"],
            "failure_line_sha256": rejection["sha256"],
            "action_commit": _LOGGED_ACTION_SHA,
        },
        "scope": _LOGGED_SCOPE,
    }


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
    if "verified_log" in cap:
        _require("denial" not in cap, "Receipt combines different draft observation profiles")
        return _logged_denial(cap, root, repo)
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
            _require(
                "verified_log" not in cap, "Receipt combines different draft observation profiles"
            )
            scope = _PUSH_SCOPE
            return _draft_creation(cap, root.resolve(), repository, run_id, job_id)
        if "verified_log" in cap:
            scope = _LOGGED_SCOPE
        return _draft_denial(cap, root.resolve(), repository, run_id, job_id)
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "Required request, job metadata or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": scope}
