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


def evaluate(root, evidence, source=BUILDSPEC, *, publisher=None):
    content = source.encode("utf-8")
    (root / ".gitlab-ci.yml").write_bytes(content)
    evidence["source_sha256"] = hashlib.sha256(content).hexdigest()
    snapshot = root / "observation.json"
    snapshot.write_text(json.dumps(evidence), encoding="utf-8")
    return mr_artifact_observation(snapshot, root, 1, 22, 33, publisher=publisher)


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
        (
            ".more: &extra\n  package: {}\n<<: *extra\n",
            "GitLab source contains ambiguous root merge ownership",
        ),
        (
            "<<: {package: {script: echo other}}\n",
            "GitLab source structural analysis is incomplete",
        ),
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


NPM_SOURCE = (
    BUILDSPEC
    + """\
.if-main: &if-main
  if: '$CI_COMMIT_REF_NAME == "main" && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == null'
.if-security: &if-security
  if: '$CI_PROJECT_ID == $SECURITY_PROJECT_ID && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == null'
.npm:
  rules:
    - <<: *if-main
      when: manual
    - <<: *if-security
      when: manual
  id_tokens:
    NPM_ID_TOKEN:
      aud: 'npm:registry.npmjs.org'
  needs:
    - job: npm-input
      artifacts: true
npm-input:
  artifacts:
    paths: [tmp/packages]
publish:
  extends: .npm
  script:
    - export INPUT="$(find tmp/packages -name "example-*.tgz" -type f)"
    - npm publish --tag $PUBLISH_TAG --access public $INPUT
"""
)


@pytest.fixture
def npm_capture(capture):
    pipe = capture["pipeline"]
    job = capture["job"]
    job["pipeline"]["status"] = "success"
    pub_jobs = [
        {"id": 33, "name": "package", "status": "success", "pipeline": pipe, "web_url": JOB},
        {
            "id": 34,
            "name": "npm-input",
            "status": "success",
            "pipeline": pipe,
            "web_url": "https://gitlab.com/team/repo/-/jobs/34",
            "archive_present": True,
            "started_at": time(2),
            "finished_at": time(6),
        },
        {
            "id": 35,
            "name": "publish-dry-run",
            "status": "manual",
            "pipeline": pipe,
            "web_url": "https://gitlab.com/team/repo/-/jobs/35",
        },
    ]
    query = {"page": 1, "total_pages": 1, "next_page": "", "observed_at": time(8)}
    capture["publication_inventory"] = {
        **query,
        "total": len(pub_jobs),
        "jobs": pub_jobs,
        "url": "https://gitlab.com/api/v4/projects/1/pipelines/22/jobs?per_page=100&include_retried=true",
    }
    capture["publisher_artifact_listing"] = {
        **query,
        "total": 1,
        "url": "https://gitlab.com/api/v4/projects/1/jobs/34/artifacts/tree?path=tmp%2Fpackages&per_page=100",
        "entries": [
            {
                "type": "file",
                "name": "example-1.tgz",
                "path": "tmp/packages/example-1.tgz",
                "size": 12,
            }
        ],
    }
    return capture


def test_absent_real_publisher_uses_exact_producer_and_keeps_authority_unverified(
    tmp_path, npm_capture
):
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["state"] == "job-artifact-observed"
    admission = result["publication_admission"]
    assert admission["state"] == "publish-job-absent"
    assert admission["matching_archive"].endswith("/34/artifacts/raw/tmp/packages/example-1.tgz")
    assert admission["recursive_selection"] == "unverified"
    assert admission["authorization"] == "unverified"
    assert admission["effective_configuration"] == "unverified"
    assert "publication_admission" not in evaluate(tmp_path, npm_capture, NPM_SOURCE)


@pytest.mark.parametrize("field", ["publication_inventory", "publisher_artifact_listing"])
def test_partial_inventory_preserves_observed_artifact_and_refuses_admission(
    tmp_path, npm_capture, field
):
    npm_capture[field]["next_page"] = "2"
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["state"] == "job-artifact-observed"
    assert result["publication_admission"]["state"] == "unresolved"


def test_publish_job_presence_contradicts_exclusion(tmp_path, npm_capture):
    npm_capture["publication_inventory"]["jobs"][-1]["name"] = "publish"
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["publication_admission"]["state"] == "unresolved"


def test_or_branch_cannot_be_counted_as_a_null_guard(tmp_path, npm_capture):
    source = NPM_SOURCE.replace(
        "$CI_PROJECT_ID == $SECURITY_PROJECT_ID &&", "$CI_PROJECT_ID == $SECURITY_PROJECT_ID ||"
    )
    result = evaluate(tmp_path, npm_capture, source, publisher="publish")
    assert result["publication_admission"]["state"] == "unresolved"


def test_archive_listing_cannot_be_borrowed_from_other_job(tmp_path, npm_capture):
    listing = npm_capture["publisher_artifact_listing"]
    listing["url"] = listing["url"].replace("/jobs/34/", "/jobs/35/")
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["publication_admission"]["state"] == "unresolved"


@pytest.mark.parametrize("name", ["", "publish\nother"])
def test_unnamed_or_multiline_job_prevents_absence_claim(tmp_path, npm_capture, name):
    npm_capture["publication_inventory"]["jobs"][-1]["name"] = name
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["state"] == "job-artifact-observed"
    assert result["publication_admission"]["reason"] == "inventory has an unnamed or malformed job"


def test_producer_must_fit_the_pipeline_window(tmp_path, npm_capture):
    npm_capture["publication_inventory"]["jobs"][1]["finished_at"] = "2024-01-01T00:00:00Z"
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["publication_admission"]["reason"] == (
        "archive producer is outside the recorded pipeline window"
    )


def test_older_inventory_cannot_cover_the_supplied_pipeline_update(tmp_path, npm_capture):
    npm_capture["pipeline"]["updated_at"] = time(9)
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert (
        result["publication_admission"]["reason"]
        == "inventory predates the supplied pipeline update"
    )


def test_second_matching_top_level_archive_prevents_unique_match_claim(tmp_path, npm_capture):
    listing = npm_capture["publisher_artifact_listing"]
    listing["entries"].append(
        {
            "type": "file",
            "name": "example-+other.tgz",
            "path": "tmp/packages/example-+other.tgz",
            "size": 12,
        }
    )
    listing["total"] = 2
    result = evaluate(tmp_path, npm_capture, NPM_SOURCE, publisher="publish")
    assert result["publication_admission"]["state"] == "unresolved"


def test_extra_unowned_needs_entry_prevents_local_producer_claim(tmp_path, npm_capture):
    source = NPM_SOURCE.replace("      artifacts: true", "      artifacts: true\n    - unknown-job")
    result = evaluate(tmp_path, npm_capture, source, publisher="publish")
    assert result["publication_admission"]["state"] == "unresolved"
