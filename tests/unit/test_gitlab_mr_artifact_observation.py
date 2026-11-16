"""Authored boundaries for the saved fork MR artifact evidence path."""

import hashlib
import json

import pytest

from taintly.ingestion.gitlab_mr_artifact import mr_artifact_observation

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40
JOB = "https://gitlab.com/team/repo/-/jobs/33"
BUILDSPEC = """\
package:
  script:
    - bun run build
  artifacts:
    paths: [output]
"""
MANUAL = """\
package:
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event' && $CI_PROJECT_ID == $CANONICAL_PROJECT_ID && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID
      changes: [contents/**]
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
      when: manual
  script: echo placeholder
"""


def time(second):
    return f"2026-11-16T00:00:{second:02d}Z"


@pytest.fixture
def capture(tmp_path):
    payload = b"example job output"
    (tmp_path / "published-file.bin").write_bytes(payload)
    run = {
        "id": 22,
        "project_id": 1,
        "sha": MERGE,
        "ref": "refs/merge-requests/9/merge",
        "source": "merge_request_event",
    }
    return {
        "schema": "gitlab-mr-artifact-v1",
        "project": {"id": 1, "path": "team/repo"},
        "mr": {"iid": 9, "source_project_id": 2, "target_project_id": 1, "sha": HEAD},
        "pipeline": run,
        "merge": {"id": MERGE, "parent_ids": [BASE, HEAD]},
        "job": {
            "id": 33,
            "name": "package",
            "status": "success",
            "pipeline": {**run, "created_at": time(0), "updated_at": time(7)},
            "web_url": JOB,
            "started_at": time(1),
            "finished_at": time(5),
            "artifacts": [{"file_type": "archive", "size": 99}],
        },
        "trace": [
            {"kind": "checkout", "time": time(2), "sha_prefix": MERGE[:8], "ref": run["ref"]},
            {"kind": "command", "time": time(3), "command": "bun run build"},
            {"kind": "upload", "time": time(4), "job": 33, "http_status": 201},
        ],
        "artifact": {
            "path": "output/index.html",
            "url": JOB + "/artifacts/raw/output/index.html",
            "http_status": 200,
            "observed_at": time(6),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
    }


def evaluate(root, evidence, source=BUILDSPEC):
    content = source.encode("utf-8")
    (root / ".gitlab-ci.yml").write_bytes(content)
    evidence["source_sha256"] = hashlib.sha256(content).hexdigest()
    snapshot = root / "observation.json"
    snapshot.write_text(json.dumps(evidence), encoding="utf-8")
    return mr_artifact_observation(snapshot, root, 1, 22, 33)


def test_explicit_artifact_and_job_authority_are_scoped(tmp_path, capture):
    result = evaluate(tmp_path, capture)
    assert result["state"] == "job-artifact-observed", result
    assert result["publication"]["authority"] == "gitlab-runner-job-scoped-upload"
    assert result["publication"]["member_path"] == "output/index.html"
    assert result["source_project"] == 2


def test_wrong_parent_cannot_supply_fork_source(tmp_path, capture):
    capture["merge"]["parent_ids"] = [BASE, "0" * 40]
    assert evaluate(tmp_path, capture)["state"] == "unresolved"


def test_artifact_retrieval_has_to_follow_job(tmp_path, capture):
    capture["artifact"]["observed_at"] = time(0)
    assert evaluate(tmp_path, capture)["state"] == "unresolved"


def test_pipeline_cannot_begin_after_the_selected_job(tmp_path, capture):
    capture["job"]["pipeline"]["created_at"] = time(2)
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert result["reason"] == "selected job is outside the recorded pipeline window"


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ("---\npackage: {}\n", "GitLab source contains unsupported document boundaries"),
        ("...\npackage: {}\n", "GitLab source contains unsupported document boundaries"),
        ('"p\\u0061ckage": {}\n', "GitLab source contains ambiguous key ownership"),
        (".more: &extra\n  package: {}\n<<: *extra\n", "GitLab source contains ambiguous root merge ownership"),
        ("<<: {package: {script: echo other}}\n", "GitLab source structural analysis is incomplete"),
    ],
)
def test_document_and_key_ambiguity_cannot_prove_ownership(tmp_path, capture, extra, reason):
    result = evaluate(tmp_path, capture, BUILDSPEC + extra)
    assert result["state"] == "unresolved"
    assert result["reason"] == reason


def test_merge_under_job_rules_does_not_change_observed_build_ownership(tmp_path, capture):
    source = ".allow: &allow\n  when: always\n" + BUILDSPEC.replace(
        "  script:", "  rules:\n    - <<: *allow\n  script:"
    )
    assert evaluate(tmp_path, capture, source)["state"] == "job-artifact-observed"


def test_manual_job_preserves_unknown_effective_values_and_start_permission(tmp_path, capture):
    capture["job"].update(status="manual", started_at=None, finished_at=None, artifacts=[])
    capture.update(trace=[], artifact=None)
    result = evaluate(tmp_path, capture, MANUAL)
    assert result["state"] == "manual-job-not-started", result
    assert result["same_project_guard_for_recorded_project_ids"] == "false"
    assert result["manual_start_permission"] == "unverified"
    spoof = 'variables:\n  CI_MERGE_REQUEST_SOURCE_PROJECT_ID: "1"\n' + MANUAL
    assert evaluate(tmp_path, capture, spoof)["state"] == "unresolved"
