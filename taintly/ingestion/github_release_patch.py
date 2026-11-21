"""Bind a saved Release PATCH comparison to one direct repository push job."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _SHA,
    PreviewEvidenceError,
    _bounded_read,
    _id,
    _matches,
    _observed_step,
    _require,
    _Row,
    _run_identity,
    _run_window,
    _source,
    _time,
)
from taintly.rules.github._workflow_run_artifact import _Index, _unique_scalar

PATCH_SCHEMA = "github-release-patch-comparison-v1"
PATCH_SCOPE = (
    "Trusted saved source, job and response logs for a direct repository push. "
    "The comparison reports the selected metadata requests and job-token grant. "
    "Exact token or process bytes, the server's internal denial reason, fork access "
    "and asset publication require separate evidence."
)
_DENIAL = "Resource not accessible by integration"
# Match the bounded wrapper that takes status and error text from gh api's
# response headers and body. Unchecked shell prefixes cannot supply a result.
_PROBE = (
    "probe() {",
    'local label="$1"; shift',
    "local out status msg",
    'out=$(gh api -i "$@" 2>&1) || true',
    r"""status=$(printf '%s\n' "$out" | awk 'toupper($1) ~ /^HTTP\// {print $2; exit}')""",
    r"""msg=$(printf '%s\n' "$out" | grep -o '"message":"[^"]*"' | head -1)""",
)
_PROBE_RESULT = re.compile(
    r"""printf '%-[1-9][0-9]s HTTP %s %s\\n' "\$label" "\$\{status:-\?\?\?\}" "\$msg" """.rstrip()
)
_LABEL = r"(?P<label>[A-Za-z0-9. ()_{}=-]{1,120})"
_TARGET_CALL = re.compile(
    rf'probe "{_LABEL}" +-X PATCH "repos/\$REPO/releases/\$(?P<id>A|PUBLISHED_ID)"'
    r' -f target_commitish="\$(?P<target>MAIN_SHA|OLD_SHA|PUBLISHED_SHA)"'
)
_METADATA_CALL = re.compile(
    rf'probe "{_LABEL}" +-X PATCH "repos/\$REPO/releases/\$PUBLISHED_ID" '
    r"""(?P<field>--input - <<< '\{\}'|-f name="\$NAME"|-f tag_name="\$PUBLISHED_TAG")"""
)


@dataclass(frozen=True)
class _Request:
    label: str
    line: int
    field: str | None
    target_variable: str | None = None


def _scalar(index: _Index, path: tuple[object, ...]) -> str:
    owners = (path[:i] for i in range(1, len(path)) if isinstance(path[i - 1], str))
    value, _, error = _unique_scalar(index, path, owners)
    if error is not None or value is None:
        raise PreviewEvidenceError("Release PATCH source has an ambiguous field")
    return value


def _owned_profile(index: _Index, job_name: str, branch: str) -> tuple[str, _Row, list[str], int]:
    owner = ("jobs", job_name)
    env_path = (*owner, "env")
    step = (*owner, "steps", 0)
    job_keys = {p[-1] for p in index.keys if p[:-1] == owner}
    steps = {p for p in index.keys if p[:-1] == step}
    _require(
        {p for p in index.keys if len(p) == 1} <= {("name",), ("on",), ("permissions",), ("jobs",)}
        and {p for p in index.keys if p[:-1] == ("on",)} == {("on", "push")}
        and len(index.keys.get(("on", "push", "branches"), [])) == 1
        and len(index.values.get(("on", "push", "branches", 0), [])) == 1
        and index.values[("on", "push", "branches", 0)][0].value == branch
        and {p for p in index.values if p[:3] == ("on", "push", "branches")}
        == {("on", "push", "branches", 0)}
        and _scalar(index, ("permissions", "contents")) == "write"
        and {p for p in index.keys if p[:-1] == ("jobs",)} == {owner}
        and job_keys == {"runs-on", "env", "steps"}
        and _matches(_scalar(index, (*owner, "runs-on")), r"ubuntu-(?:latest|[0-9]{2}\.04)")
        and {p[3] for p in index.keys if p[:3] == (*owner, "steps") and len(p) > 3} == {0}
        and steps == {(*step, "name"), (*step, "run")},
        "Workflow is outside the single direct push Release PATCH profile",
    )
    env = {str(p[-1]): _scalar(index, p) for p in index.keys if p[:-1] == env_path}
    _require(
        env.get("GH_TOKEN") == "${{ secrets.GITHUB_TOKEN }}"
        and env.get("REPO") == "${{ github.repository }}",
        "Release PATCH token or repository source is unresolved",
    )
    leaves = index.values.get((*step, "run"), [])
    _require(
        len(index.keys.get((*step, "run"), [])) == len(leaves) == 1
        and leaves[0].value_kind == "block_literal",
        "Release PATCH step does not contain an owned literal shell body",
    )
    event = leaves[0]
    if not isinstance(event.value, str):
        raise PreviewEvidenceError("Release PATCH shell body is missing")
    body = [line.strip() for line in event.value.split("\n")]
    return _scalar(index, (*step, "name")), env, body, event.line


def _recorded_row(row: _Row, step: _Row, pattern: str) -> re.Match[str]:
    value = row["value"]
    when = _time(row["time"])
    match = re.fullmatch(pattern, value)
    if match is None:
        raise PreviewEvidenceError("Saved Release PATCH response differs from the selected source")
    _require(
        _id(row["line"])
        and _time(step["started_at"]) <= when.replace(microsecond=0) <= _time(step["completed_at"])
        and hashlib.sha256(f"{row['time']} {value}".encode()).hexdigest() == row["sha256"],
        "Saved Release PATCH log row does not match the owned step or evidence",
    )
    return match


def _draft_requests(prefix: list[tuple[int, str]], env: _Row) -> tuple[list[_Request], str]:
    fixed = (
        'MAIN_SHA=$(gh api "repos/$REPO/commits/main" --jq .sha)',
        'echo "main: $MAIN_SHA"',
        'echo "old:  $OLD_SHA"',
        'echo "Workflow files that differ between them:"',
    )
    lines = [line for _, line in prefix]
    identity = (
        re.fullmatch(r'echo "([A-Za-z0-9. (),=_ -]+->) \$A"', lines[7]) if len(lines) >= 8 else None
    )
    if identity is None:
        raise PreviewEvidenceError("Draft comparison does not report the selected release ID")
    _require(
        set(env) == {"GH_TOKEN", "REPO", "OLD_SHA"}
        and _matches(env["OLD_SHA"], _SHA)
        and tuple(lines[:4]) == fixed
        and len(lines) >= 11
        and lines[4]
        == """gh api "repos/$REPO/compare/$OLD_SHA...$MAIN_SHA" --jq '[.files[].filename | select(startswith(".github/workflows/"))] | if length == 0 then "  (none)" else .[] | "  " + . end'"""
        and re.fullmatch(r'echo "== [A-Za-z0-9. ]+"', lines[5])
        and re.fullmatch(
            r'A=\$\(gh api -X POST "repos/\$REPO/releases" -f tag_name=[a-z0-9-]+'
            r' -f name="[a-z0-9 ]+" -F draft=true -f target_commitish="\$MAIN_SHA"'
            r" --jq \.id 2>&1\) \|\| true",
            lines[6],
        )
        and lines[8] == 'if [[ "$A" =~ ^[0-9]+$ ]]; then',
        "Draft comparison has an unmodeled source prefix",
    )
    requests = [_target_request(line, n, "A") for n, line in prefix[9:]]
    _require(
        [request.target_variable for request in requests] == ["MAIN_SHA", "OLD_SHA", "MAIN_SHA"],
        "Draft comparison lacks its complete target sequence",
    )
    return requests, identity[1]


def _target_request(line: str, number: int, release_var: str) -> _Request:
    match = _TARGET_CALL.fullmatch(line)
    if match is None or match["id"] != release_var:
        raise PreviewEvidenceError("Release PATCH targets another release")
    return _Request(match["label"], number, "target_commitish", match["target"])


def _published_requests(prefix: list[tuple[int, str]], env: _Row) -> list[_Request]:
    lines = [line for _, line in prefix]
    _require(
        set(env) == {"GH_TOKEN", "REPO", "PUBLISHED_ID", "PUBLISHED_TAG", "PUBLISHED_SHA"}
        and _matches(env["PUBLISHED_SHA"], _SHA)
        and re.fullmatch(r"[1-9][0-9]{0,17}", env["PUBLISHED_ID"])
        and len(lines) == 7
        and lines[0] == 'NAME=$(gh api "repos/$REPO/releases/$PUBLISHED_ID" --jq .name)'
        and lines[1] == 'echo "== Published release ($PUBLISHED_TAG)"'
        and re.fullmatch(
            r'probe "[0-9]+\. GET release" +"repos/\$REPO/releases/\$PUBLISHED_ID"', lines[2]
        ),
        "Published comparison has an unmodeled source prefix",
    )
    requests = []
    for (number, line), expected in zip(
        prefix[3:6],
        ("--input - <<< '{}'", '-f name="$NAME"', '-f tag_name="$PUBLISHED_TAG"'),
        strict=True,
    ):
        match = _METADATA_CALL.fullmatch(line)
        if match is None or match["field"] != expected:
            raise PreviewEvidenceError("Published PATCH fields disagree")
        field = expected.split()[1].split("=")[0] if expected.startswith("-f ") else None
        requests.append(_Request(match["label"], number, field))
    requests.append(_target_request(lines[-1], prefix[-1][0], "PUBLISHED_ID"))
    _require(requests[-1].target_variable == "PUBLISHED_SHA", "Published target commit is unbound")
    return requests


def patch_comparison(receipt: _Row, root: Path, repo: str, run_id: int, job_id: int) -> _Row:
    run, job, log = receipt["run"], receipt["job"], receipt["patch_log"]
    _run_identity(run, job, repo, run_id, "push")
    _run_window(run, job)
    _require(
        set(receipt) == {"schema", "repository", "run", "job", "source", "patch_log"}
        and job["id"] == job_id
        and job["html_url"] == f"https://github.com/{repo}/actions/runs/{run_id}/job/{job_id}"
        and run["head_repository"] == repo
        and run["conclusion"] == job["conclusion"] == "success"
        and _matches(job["name"], _NAME)
        and log["url"] == f"https://api.github.com/repos/{repo}/actions/jobs/{job_id}/logs"
        and _matches(log["sha256"], _DIGEST),
        "Saved Release PATCH evidence belongs to another run, job or profile",
    )
    index, source = _source(root, run, receipt["source"], run["head_sha"])
    step_name, env, body, start_line = _owned_profile(index, job["name"], run["head_branch"])
    setup = _observed_step(job, "Set up job", number=1)
    step = _observed_step(job, step_name, number=2)
    finish = _observed_step(job, "Complete job", number=3)
    _require(
        len(job["steps"]) == 3
        and _time(setup["completed_at"]) <= _time(step["started_at"])
        and _time(step["completed_at"]) <= _time(finish["started_at"]),
        "Release PATCH requires one ordered execution step",
    )
    grant_rows = log["permissions"]
    for row, expected in zip(
        grant_rows,
        ("##[group]GITHUB_TOKEN Permissions", "Contents: write", "Metadata: read", "##[endgroup]"),
        strict=True,
    ):
        _recorded_row(row, setup, re.escape(expected))
    commands = [(start_line + i, line) for i, line in enumerate(body, 1) if line]
    wrapper = [line for _, line in commands[:8]]
    _require(
        len(wrapper) == 8
        and tuple(wrapper[:6]) == _PROBE
        and _PROBE_RESULT.fullmatch(wrapper[6])
        and wrapper[7] == "}",
        "Release PATCH response wrapper is outside the supported profile",
    )
    stop = log["last_source_line"]
    _require(_id(stop), "Release PATCH source span is invalid")
    prefix = [(n, line) for n, line in commands[8:] if n <= stop]
    _require(bool(prefix) and prefix[-1][0] == stop, "Release PATCH source span is unbound")
    if "OLD_SHA" in env:
        plan, release_label = _draft_requests(prefix, env)
        main, old, identity = log["bindings"]
        main_sha = _recorded_row(main, step, rf"main: ({_SHA})")[1]
        _recorded_row(old, step, "old:  " + re.escape(env["OLD_SHA"]))
        _require(main_sha != env["OLD_SHA"], "Compared Release target commits are identical")
        release_id = int(
            _recorded_row(identity, step, re.escape(release_label) + r" ([1-9][0-9]{0,17})")[1]
        )
        targets = {"MAIN_SHA": main_sha, "OLD_SHA": env["OLD_SHA"]}
    else:
        _require(log["bindings"] == [], "Published Release uses literal source references")
        plan = _published_requests(prefix, env)
        release_id = int(env["PUBLISHED_ID"])
        targets = {"PUBLISHED_SHA": env["PUBLISHED_SHA"]}
    rows = [*grant_rows, *log["bindings"], *log["responses"]]
    log_path = (root / "release-patch.log").resolve()
    _require(log_path.is_relative_to(root), "Release PATCH log leaves the source projection")
    raw = _bounded_read(log_path)
    _require(
        hashlib.sha256(raw).hexdigest() == log["sha256"],
        "Release PATCH job log differs from the recorded evidence",
    )
    lines = raw.decode("utf-8").split("\n")
    _require(
        all(
            _id(row["line"])
            and row["line"] <= len(lines)
            and lines[row["line"] - 1].rstrip() == f"{row['time']} {row['value']}"
            for row in rows
        ),
        "Release PATCH log rows do not occur in the saved job log",
    )
    _require(
        all(
            a["line"] < b["line"] and _time(a["time"]) < _time(b["time"]) for a, b in pairwise(rows)
        ),
        "Release PATCH log rows are duplicated or out of order",
    )
    operations = []
    for request, row in zip(plan, log["responses"], strict=True):
        match = _recorded_row(
            row, step, re.escape(request.label) + r' +HTTP (200|403)(?: "message":"([^"]+)")?'
        )
        status = int(match[1])
        _require(
            (status == 200 and match[2] is None) or (status == 403 and match[2] == _DENIAL),
            "Release PATCH response is outside the supported acceptance or refusal",
        )
        operations.append(
            {
                "field": request.field,
                "target_commitish": targets.get(request.target_variable)
                if request.target_variable
                else None,
                "status": status,
                "source_line": request.line,
                "response_line": row["line"],
                "response_sha256": row["sha256"],
            }
        )
    _require(
        {r["status"] for r in operations} == {200, 403}, "Release PATCH contrast is incomplete"
    )
    return {
        "state": "release-patch-comparison-reported",
        "repository": repo,
        "run": run_id,
        "job": job_id,
        "attempt": run["run_attempt"],
        "job_conclusion": job["conclusion"],
        "source": source,
        "effective_permission": {"credential": "GITHUB_TOKEN", "contents": "write"},
        "operation": {
            "method": "PATCH",
            "url": f"https://api.github.com/repos/{repo}/releases/{release_id}",
        },
        "requests": operations,
        "log_sha256": log["sha256"],
        "scope": PATCH_SCOPE,
    }
