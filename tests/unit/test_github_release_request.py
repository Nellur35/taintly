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
