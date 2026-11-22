import json
from pathlib import Path
from typing import Any

import pytest

from taintly.ingestion.gitlab_fork_admission import fork_admission_observation


@pytest.fixture
def receipt() -> dict[str, Any]:
    revision = "a" * 40
    origin = "https://gitlab.com"
    pipeline = f"{origin}/api/v4/projects/21/pipelines/51"
    mr = f"{origin}/api/v4/projects/34/merge_requests/2"
    membership = {
        "id": 51,
        "project_id": 21,
        "sha": revision,
        "source": "merge_request_event",
        "ref": "proposed-docs",
    }
    sources = {
        "pipeline": (
            pipeline,
            {
                **membership,
                "web_url": f"{origin}/sample/project/-/pipelines/51",
                "status": "failed",
                "started_at": None,
                "finished_at": "2026-09-04T10:00:00.900Z",
                "yaml_errors": None,
            },
        ),
        "graphql": (
            f"{origin}/api/graphql?query=authored-example",
            {
                "data": {
                    "project": {
                        "fullPath": "sample/project",
                        "pipeline": {
                            "id": "gid://gitlab/Ci::Pipeline/51",
                            "sha": revision,
                            "source": "merge_request_event",
                            "ref": "proposed-docs",
                            "status": "FAILED",
                            "startedAt": None,
                            "finishedAt": "2026-09-04T10:00:00Z",
                            "yamlErrors": False,
                            "failureReason": "The pipeline failed due to the user not being verified.",
                        },
                    },
                },
            },
        ),
        "mr": (
            mr,
            {
                "iid": 2,
                "source_project_id": 21,
                "target_project_id": 34,
                "web_url": f"{origin}/canonical/project/-/merge_requests/2",
            },
        ),
        "mr_pipelines": (mr + "/pipelines?per_page=12", [membership]),
        "jobs": (pipeline + "/jobs?include_retried=true&per_page=25", []),
    }
    return {
        "schema": "gitlab-fork-admission-v1",
        "observed_at": "2026-09-05T10:00:00Z",
        "sources": {
            key: {"url": url, "status": 200, "sha256": "b" * 64, "body": body, "next_page": ""}
            for key, (url, body) in sources.items()
        },
    }


def _observe(
    tmp_path: Path, receipt: dict[str, Any], project: int = 21, pipeline: int = 51
) -> dict[str, Any]:
    file = tmp_path / "receipt.json"
    file.write_text(json.dumps(receipt), encoding="utf-8")
    return fork_admission_observation(file, project, pipeline)


def test_records_pre_job_stop_without_claiming_an_upload(tmp_path, receipt):
    result = _observe(tmp_path, receipt)
    assert result["state"] == "fork-pipeline-admission-blocked"
    assert result["publication"] == "not-reached"
    assert (result["project"], result["pipeline"], result["mr"], result["revision"]) == (
        21,
        51,
        2,
        "a" * 40,
    )


def test_selects_exact_membership_among_multiple_pipelines(tmp_path, receipt):
    membership = receipt["sources"]["mr_pipelines"]["body"]
    selected = membership[0]
    membership[:] = [
        {**selected, "id": 53, "sha": "c" * 40},
        selected,
        {**selected, "id": 50, "source": "push"},
    ]
    result = _observe(tmp_path, receipt)
    assert result["state"] == "fork-pipeline-admission-blocked"
    assert result["pipeline"] == 51


@pytest.mark.parametrize("selected_matches", [[], [{"project_id": 34}], [{}, {}]])
def test_missing_wrong_owner_or_duplicate_membership_remains_unresolved(
    tmp_path, receipt, selected_matches
):
    membership = receipt["sources"]["mr_pipelines"]["body"]
    selected = membership[0]
    membership[:] = [
        {**selected, "id": 50, "source": "push"},
        *({**selected, **fields} for fields in selected_matches),
    ]
    result = _observe(tmp_path, receipt)
    assert result["state"] == "unresolved"
    assert "publication" not in result


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("pipeline", "body", "started_at"), "2026-09-04T09:59:59Z"),
        (("jobs", "body"), [{"id": 101, "status": "failed"}]),
        (("jobs", "status"), 403),
        (("jobs", "next_page"), "2"),
        (("jobs", "url"), "https://gitlab.com/api/v4/projects/21/pipelines/52/jobs"),
        (("mr", "body", "target_project_id"), 21),
        (("mr_pipelines", "body", 0, "sha"), "c" * 40),
        (("graphql", "body", "data", "project", "pipeline", "id"), "gid://gitlab/Ci::Pipeline/52"),
        (("graphql", "body", "data", "project", "pipeline", "failureReason"), "Unknown failure"),
    ],
)
def test_missing_or_conflicting_ownership_remains_unresolved(tmp_path, receipt, path, value):
    target = receipt["sources"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    result = _observe(tmp_path, receipt)
    assert result["state"] == "unresolved"
    assert "publication" not in result


def test_other_pipeline_and_missing_jobs_remain_unresolved(tmp_path, receipt):
    assert _observe(tmp_path, receipt, pipeline=52)["state"] == "unresolved"
    del receipt["sources"]["jobs"]
    assert _observe(tmp_path, receipt)["state"] == "unresolved"
