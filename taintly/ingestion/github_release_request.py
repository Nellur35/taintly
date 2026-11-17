"""Corroborate a recorded GitHub API denial for a draft Release request."""

from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _REPOSITORY,
    PreviewEvidenceError,
    _field,
    _id,
    _matches,
    _observation_capture,
    _require,
    _Row,
    _run_identity,
    _run_window,
    _source,
    _time,
)
from taintly.rules.github._workflow_run_artifact import _Index, _is_exact_identifier_expression

_SCHEMA = "github-draft-release-request-v1"
_ACTION = "release-drafter/release-drafter@v6"
_DENIAL = "Resource not accessible by integration"
_SCOPE = (
    "Trusted saved GitHub check annotations and run records. The reported response is scoped "
    "to one draft-create request. "
    "The supplied workflow is the fork-head source. Exact merged workflow bytes, runtime token "
    "identity, the policy behind the denial, other requests and artifact publication are unverified."
)


def _source_plan(index: _Index, job_name: str) -> _Row:
    owner = ("jobs", job_name)
    steps = (*owner, "steps")
    step = (*steps, 0)
    env = (*step, "env")
    _require(
        all(
            len(index.keys.get(path, ())) == 1
            for path in (
                ("on", "pull_request"),
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
        action.value == _ACTION
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
    """Separate the owned API response from the conclusion of its GitHub job."""
    try:
        _require(_matches(repository, _REPOSITORY), "Expected a literal GitHub repository")
        cap = _observation_capture(snapshot, _SCHEMA)
        _require(cap["repository"] == repository, "Receipt belongs to another repository")
        return _draft_denial(cap, root.resolve(), repository, run_id, job_id)
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "Required request, job metadata or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
