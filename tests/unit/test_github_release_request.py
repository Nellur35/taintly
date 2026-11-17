"""Authored comparisons for API response ownership and source scope."""

import hashlib
import json

import pytest

from taintly.ingestion.github_release_request import release_request_observation

SOURCE = """\
on:
  pull_request:
    types: [synchronize]
jobs:
  draft:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: release-drafter/release-drafter@v6
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""
REPO = "team/project"
HEAD = "a" * 40
PATH = ".github/workflows/draft.yml"
RUN_URL = f"https://github.com/{REPO}/actions/runs/10"
STARTED = "2026-05-13T00:23:16Z"
COMPLETED = "2026-05-13T00:23:23Z"


@pytest.fixture
def capture(tmp_path):
    def bind(content=SOURCE):
        path = tmp_path / PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
        return {
            "path": PATH,
            "revision": HEAD,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
        }

    job_window = {
        "head_sha": HEAD,
        "started_at": STARTED,
        "completed_at": COMPLETED,
        "conclusion": "success",
    }
    cap = {
        "schema": "github-draft-release-request-v1",
        "repository": REPO,
        "run": {
            "id": 10,
            "html_url": RUN_URL,
            "event": "pull_request",
            "head_sha": HEAD,
            "head_repository": "fork/project",
            "run_attempt": 1,
            "conclusion": "success",
            "referenced_workflows": [],
            "path": PATH,
            "check_suite_id": 30,
            "created_at": "2026-05-13T00:23:05Z",
            "updated_at": COMPLETED,
        },
        "job": {
            **job_window,
            "id": 20,
            "run_id": 10,
            "run_attempt": 1,
            "name": "draft",
            "check_run_url": f"https://api.github.com/repos/{REPO}/check-runs/20",
        },
        "check_run": {
            **job_window,
            "id": 20,
            "app": "github-actions",
            "check_suite_id": 30,
            "details_url": f"{RUN_URL}/job/20",
        },
        "pr": {
            "number": 40,
            "base_repository": REPO,
            "head_repository": "fork/project",
            "head_sha": HEAD,
        },
        "source": bind(),
        "denial": {
            "check_run": 20,
            "run": 10,
            "attempt": 1,
            "status": 403,
            "message": "Resource not accessible by integration",
            "method": "POST",
            "url": f"https://api.github.com/repos/{REPO}/releases",
            "draft": True,
            "target_commitish": "refs/pull/40/merge",
            "action": "release-drafter/release-drafter@v6",
            "response_at": "2026-05-13T00:23:21Z",
            "request_id": "2411:342B08:95AE9B",
            "annotation_sha256": "b" * 64,
            "action_annotation_sha256": "c" * 64,
            "accepted_permissions": "contents=write; contents=write,workflows=write",
        },
    }

    def assess():
        evidence = tmp_path / "capture.json"
        evidence.write_text(json.dumps(cap), encoding="utf-8")
        return release_request_observation(evidence, tmp_path, REPO, 10, 20)

    return cap, bind, assess


def test_job_success_can_coexist_with_owned_request_denial(capture):
    _, _, assess = capture
    result = assess()
    assert result["state"] == "draft-release-create-denied"
    assert result["job_conclusion"] == "success"
    assert result["operation"]["target_commitish"] == "refs/pull/40/merge"
    assert result["configured"]["credential_binding"] == "GITHUB_TOKEN"
    assert result["source_role"] == "fork-head"
    assert "publication" not in result


@pytest.mark.parametrize(
    ("record", "key", "wrong"),
    [
        ("check_run", "app", "other-integration"),
        ("check_run", "check_suite_id", 31),
        ("denial", "check_run", 21),
        ("denial", "attempt", True),
        ("denial", "response_at", "2026-05-13T00:23:25Z"),
        ("denial", "target_commitish", "refs/pull/41/merge"),
        ("denial", "status", 403.0),
        ("denial", "message", "API rate limit exceeded"),
        ("denial", "action_annotation_sha256", "b" * 64),
        ("pr", "head_sha", "b" * 40),
    ],
)
def test_mismatched_owner_or_response_remains_unresolved(capture, record, key, wrong):
    cap, _, assess = capture
    cap[record][key] = wrong
    result = assess()
    assert result["state"] == "unresolved" and "operation" not in result


def test_missing_response_cannot_be_inferred_from_source_or_status(capture):
    cap, _, assess = capture
    del cap["denial"]
    assert "No owned draft-create API denial" in assess()["reason"]


def test_source_with_intervening_command_has_no_unique_action_binding(capture):
    cap, bind, assess = capture
    cap["source"] = bind(SOURCE.replace("    steps:\n", "    steps:\n      - run: echo other\n"))
    assert assess()["state"] == "unresolved"


@pytest.fixture
def push_capture(capture):
    cap, bind, assess = capture
    action = "release-drafter/release-drafter@v7"
    source = SOURCE.replace("pull_request:\n    types: [synchronize]", "push:\n    branches: [master]")
    cap["source"] = bind(source.replace("@v6", "@v7"))
    cap["run"].update(event="push", head_repository=REPO, head_branch="master")
    del cap["denial"]
    timings = [
        ("Set up job", 16, 17),
        (f"Run {action}", 18, 22),
        ("Complete job", 22, 23),
    ]
    cap["job"]["steps"] = [
        {
            "name": name,
            "number": number,
            "started_at": f"2026-05-13T00:23:{start}Z",
            "completed_at": f"2026-05-13T00:23:{end}Z",
            "conclusion": "success",
        }
        for number, (name, start, end) in enumerate(timings, 1)
    ]
    action_commit = "978bb0b30c5ee8cdd332ced253758157150d43f0"
    rows = []
    for second, value in (
        ("16.100", f"Download action repository '{action}' (SHA:{action_commit})"),
        ("18.100", f"##[group]Run {action}"),
        ("20.100", "  tag:    2.3.4"),
        ("20.200", "  targetCommitish: master"),
        ("20.300", "  draft:  true"),
        ("20.400", "Creating new release..."),
        ("20.800", "Release created!"),
        ("22.150", "Cleaning up orphan processes"),
    ):
        time = f"2026-05-13T00:23:{second}Z"
        rows.append({"time": time, "value": value, "sha256": hashlib.sha256(f"{time} {value}".encode()).hexdigest()})
    cap["creation"] = {"run": 10, "job": 20, "attempt": 1, "log_sha256": "a" * 64, "rows": rows}
    return cap, source, bind, assess


def test_success_is_scoped_to_owned_draft_create(push_capture):
    _, _, _, assess = push_capture
    result = assess()
    assert result["state"] == "draft-release-create-reported"
    assert result["source_role"] == "repository-push"
    op = result["operation"]
    assert op["url"] == f"https://api.github.com/repos/{REPO}/releases"
    assert (op["method"], op["draft"], op["requested_tag"], op["target_commitish"]) == (
        "POST", True, "2.3.4", "master",
    )
    assert "status" not in op and "publication" not in result


@pytest.mark.parametrize(
    ("record", "key", "wrong"),
    [
        ("run", "event", "pull_request"),
        ("run", "head_repository", "fork/project"),
        ("run", "head_branch", "main"),
        ("job", "run_attempt", True),
        ("creation", "job", 21),
        ("creation", "attempt", True),
    ],
)
def test_push_creation_does_not_cross_an_invocation(push_capture, record, key, wrong):
    cap, _, _, assess = push_capture
    cap[record][key] = wrong
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(
    ("row_index", "field", "wrong"),
    [
        (0, "value", "Download action repository 'other/action@v7' (SHA:" + "a" * 40 + ")"),
        (3, "value", "  targetCommitish: main"),
        (4, "value", "  draft:  false"),
        (5, "value", "[dry-run] Would create release"),
        (6, "value", "Updating existing release..."),
        (6, "time", "2026-05-13T00:23:17.900Z"),
        (6, "time", "2026-05-13T00:23:20.350Z"),
        (6, "time", "2026-05-13T00:23:22.200Z"),
    ],
)
def test_owned_log_must_affirm_the_exact_operation(push_capture, row_index, field, wrong):
    cap, _, _, assess = push_capture
    row = cap["creation"]["rows"][row_index]
    row[field] = wrong
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["state"] == "unresolved"


def test_draft_creation_does_not_infer_success_or_accept_unverified_rows(push_capture):
    cap, _, _, assess = push_capture
    rows = cap["creation"]["rows"]
    completion = rows.pop(-2)
    assert assess()["state"] == "unresolved"
    rows.insert(-1, {**completion, "sha256": "e" * 64})
    assert assess()["state"] == "unresolved"


def test_nondefault_action_inputs_are_outside_the_push_profile(push_capture):
    cap, source, bind, assess = push_capture
    cap["source"] = bind(source.replace("@v6\n", "@v7\n        with:\n          dry-run: true\n"))
    assert assess()["state"] == "unresolved"


def test_branch_exclusions_are_outside_the_literal_push_profile(push_capture):
    cap, source, bind, assess = push_capture
    source = source.replace("@v6", "@v7").replace("[master]", "[master, '!master']")
    cap["source"] = bind(source)
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize("extra", ["- []", "- {}", "-", "- [elsewhere]", "- master: foo"])
def test_literal_push_list_checks_invisible_and_nested_items(push_capture, extra):
    cap, source, bind, assess = push_capture
    block = source.replace("@v6", "@v7").replace("[master]", "\n      - main\n      - master")
    cap["source"] = bind(block)
    assert assess()["state"] == "draft-release-create-reported"
    cap["source"] = bind(block.replace("      - master", f"      - master\n      {extra}"))
    assert assess()["state"] == "unresolved"
