"""Corroborate saved Release Drafter outcomes from a single reusable invocation."""

import hashlib
import re
from itertools import pairwise
from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _SHA,
    _WORKFLOW,
    _id,
    _matches,
    _observed_step,
    _require,
    _Row,
    _source_bytes,
    _time,
    _workflow_source_index,
)
from taintly.ingestion.github_release_request import (
    _PUSH_ACTION,
    _REVIEWED_V7_COMMITS,
    _bound_fork,
    _bound_job,
    _literal_push_branch,
    _reusable_plan,
)

_TAG = r"  tag: +v?[0-9]{1,12}\.[0-9]{1,12}\.[0-9]{1,12}"
_WRITES = {
    "create": ("Creating new release...", "Release created!"),
    "update": ("Updating existing release...", "Release updated!"),
}
SCOPE = (
    "Trusted saved GitHub run and job logs. The grant is the runner-reported Contents "
    "permission. The selected action reports its behavior for this draft and target. "
    "The HTTP response, exact token identity, stored release, asset publication, "
    "and wider authority are unverified."
)


def _merge_target(cap: _Row, repo: str) -> tuple[str, str]:
    pr = _bound_fork(cap, repo)
    record = pr["merge"]
    revision = record["sha"]
    parents = record["parents"]
    head = cap["run"]["head_sha"]
    _require(
        _matches(revision, _SHA)
        and isinstance(parents, list)
        and len(parents) == 2
        and _matches(parents[0], _SHA)
        and parents[1] == head
        and len({revision, *parents}) == 3
        and _time(record["committer_at"]) <= _time(cap["run"]["created_at"]),
        "Saved draft target does not match the historical fork merge",
    )
    return revision, f"refs/pull/{pr['number']}/merge"


def _reusable_v7_rows(
    job: _Row, observation: _Row, target: str, fork_ref: str, kind: str
) -> tuple[_Row, _Row]:
    setup = _observed_step(job, "Set up job", number=1)
    action = _observed_step(job, f"Run {_PUSH_ACTION}", number=2)
    finish = _observed_step(job, "Complete job", number=3)
    _require(
        len(job["steps"]) == 3
        and _time(setup["completed_at"]) <= _time(action["started_at"])
        and _time(action["completed_at"]) <= _time(finish["started_at"]),
        "Saved reusable draft job has an unsupported step order",
    )
    rows = observation["rows"]
    grant = "read" if fork_ref else "write"
    patterns: tuple[str, ...] = (
        r"##\[group\]GITHUB_TOKEN Permissions",
        f"Contents: {grant}",
        r"##\[endgroup\]",
        re.escape(
            f"Download action repository '{_PUSH_ACTION}' (SHA:{observation['action_commit']})"
        ),
        re.escape(f"##[group]Run {_PUSH_ACTION}"),
    )
    target_rows = (_TAG, r"  targetCommitish: +" + re.escape(target), r"  draft: +true")
    if fork_ref:
        warning = (
            f"##[warning]{fork_ref} points to an ephemeral pull request merge commit; "
            "forcing dry-run mode and disabling publish. Set dry-run: true explicitly to suppress this warning."
        )
        patterns += (
            re.escape(warning),
            *target_rows,
            re.escape("[dry-run] Would create a new release with payload: {"),
        )
        tag_index = 6
    else:
        patterns += (*target_rows, *(re.escape(message) for message in _WRITES[kind]))
        tag_index = 5
    patterns += ("Cleaning up orphan processes",)
    _require(
        isinstance(rows, list) and len(rows) == len(patterns),
        "Saved log lacks the complete reusable draft outcome sequence",
    )
    owners = (setup,) * 4 + (action,) * 6 + (finish,)
    times = []
    for row, pattern, owner in zip(rows, patterns, owners, strict=True):
        instant = _time(row["time"])
        _require(
            _matches(row["value"], pattern)
            and _time(owner["started_at"])
            <= instant.replace(microsecond=0)
            <= _time(owner["completed_at"])
            and hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
            == row["sha256"],
            "Saved log row does not match the selected step, target or draft outcome",
        )
        times.append(instant)
    _require(all(a < b for a, b in pairwise(times)), "Saved reusable draft log order is ambiguous")
    operation = {
        "kind": kind,
        "draft": True,
        "requested_tag": rows[tag_index]["value"].removeprefix("  tag:").strip(),
        "target_commitish": target,
        **({"target_ref": fork_ref} if fork_ref else {}),
        "action_commit": observation["action_commit"],
        "outcome_at": rows[-2]["time"],
        "outcome_line_sha256": rows[-2]["sha256"],
        "log_sha256": observation["log_sha256"],
    }
    return operation, {
        "credential": "GITHUB_TOKEN",
        "contents": grant,
        "time": rows[1]["time"],
        "line_sha256": rows[1]["sha256"],
    }


def reusable_v7_observation(cap: _Row, root: Path, repo: str, run_id: int, job_id: int) -> _Row:
    """Bind a recorded protection or reported write to its reusable job."""
    run, job, observation = cap["run"], cap["job"], cap["reusable_v7_log"]
    outcome = observation["outcome"]
    _require(
        outcome in ("dry-run", "create", "update")
        and not any(
            key in cap for key in ("denial", "creation", "verified_log", "effective_permission_log")
        ),
        "Receipt combines incompatible reusable draft outcomes",
    )
    event = "pull_request" if outcome == "dry-run" else "push"
    _bound_job(cap, repo, run_id, job_id, event, reusable=True)
    _require(
        run["conclusion"] == job["conclusion"] == "success"
        and all(
            _id(observation[key]) and observation[key] == identity
            for key, identity in (("run", run_id), ("job", job_id), ("attempt", run["run_attempt"]))
        )
        and observation["action_commit"] in _REVIEWED_V7_COMMITS
        and _matches(observation["log_sha256"], _DIGEST)
        and cap["custody"]["job_log_sha256"] == observation["log_sha256"],
        "Saved log lacks the selected reusable job, attempt or reviewed action identity",
    )
    fork_ref = ""
    if event == "pull_request":
        revision, fork_ref = _merge_target(cap, repo)
        target, kind, source_role = revision, "create", "fork-merge-projection"
    else:
        target = run["head_branch"]
        _require(
            run["head_repository"] == repo and _matches(target, _NAME) and "pr" not in cap,
            "Saved push does not identify the selected repository branch",
        )
        revision, kind, source_role = run["head_sha"], outcome, "repository-push"
    path = run["path"]
    _require(_matches(path, _WORKFLOW), "Run lacks a supported workflow path")
    raw, source = _source_bytes(root, cap["source"], path, revision)
    caller = _workflow_source_index(path, raw)
    if event == "push":
        _require(
            _literal_push_branch(caller, raw, target, reusable=True),
            "Caller lacks the selected literal push branch",
        )
    configured, invocation = _reusable_plan(
        cap, root, caller, repo, caller_event=event, uses_action_token_input=True
    )
    operation, grant = _reusable_v7_rows(job, observation, target, fork_ref, kind)
    return {
        "state": "reusable-draft-dry-run-reported" if fork_ref else "reusable-draft-write-reported",
        "repository": repo,
        "run": run_id,
        "job": job_id,
        "attempt": run["run_attempt"],
        "source": source,
        "source_role": source_role,
        "configured": configured,
        "reusable_invocation": invocation,
        "effective_permission": grant,
        "operation": operation,
        "scope": SCOPE,
    }
