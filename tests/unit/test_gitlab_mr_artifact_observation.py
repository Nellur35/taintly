"""Authored boundaries for the saved fork MR artifact evidence path."""

import hashlib
import json
import re
from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

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


PAGES = (
    BUILDSPEC.replace("[output]", "[public]")
    + """\
  pages:
    path_prefix: "$CI_COMMIT_REF_SLUG"
    expire_in: 1 week
  environment:
    name: "preview/$CI_COMMIT_REF_SLUG"
    url: "$CI_PAGES_URL"
    auto_stop_in: 1 week
"""
)


@pytest.fixture
def pages_capture(capture):
    capture["artifact"].update(
        path="public/index.html", url=JOB + "/artifacts/raw/public/index.html"
    )
    capture["pages_preview"] = {
        "url": JOB + ".json",
        "sha256": "f" * 64,
        "observed_at": time(12),
        "job_id": 33,
        "job_name": "package",
        "action": "start",
        "status": "last",
        "environment": {
            "id": 11,
            "name": "preview/branch",
            "state": "stopped",
            "external_url": "https://team.gitlab.io/repo/branch",
            "last_deployment": {
                "id": 55,
                "iid": 9,
                "sha": MERGE,
                "ref": capture["pipeline"]["ref"],
                "status": "success",
                "created_at": time(1),
                "deployed_at": time(6),
                "is_last": True,
                "web_path": "/team/repo/-/environments/11/deployments/9",
                "deployable": {"name": "package", "build_path": "/team/repo/-/jobs/33"},
            },
        },
    }
    return capture


def test_pages_deployment_preserves_later_stopped_state(tmp_path, pages_capture):
    result = evaluate(tmp_path, pages_capture, PAGES)
    assert result["state"] == "job-artifact-observed"
    preview = result["pages_preview"]
    assert preview["state"] == "pages-preview-deployment-recorded"
    assert preview["environment_state"] == "stopped"
    assert preview["deployment_id"] == 55
    assert preview["availability"] == "unverified"


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("sha", BASE),
        ("deployable", {"name": "package", "build_path": "/team/repo/-/jobs/34"}),
        ("deployed_at", time(4)),
    ],
)
def test_wrong_preview_does_not_erase_owned_archive(tmp_path, pages_capture, field, wrong):
    pages_capture["pages_preview"]["environment"]["last_deployment"][field] = wrong
    result = evaluate(tmp_path, pages_capture, PAGES)
    assert result["state"] == "job-artifact-observed"
    assert result["pages_preview"]["state"] == "unresolved"
    assert "target" not in result["pages_preview"]


@pytest.mark.parametrize(
    "source",
    [
        PAGES + "    action: stop\n",
        ".base:\n  environment:\n    action: stop\n"
        + PAGES.replace("package:\n", "package:\n  extends: .base\n", 1),
    ],
)
def test_pages_cannot_borrow_start_for_stop_source(tmp_path, pages_capture, source):
    result = evaluate(tmp_path, pages_capture, source)
    assert result["state"] == "job-artifact-observed"
    assert result["pages_preview"]["state"] == "unresolved"


def test_pages_cannot_borrow_prefix_when_source_overrides_the_slug(tmp_path, pages_capture):
    source = PAGES.replace("  script:", "  variables:\n    CI_COMMIT_REF_SLUG: other\n  script:")
    result = evaluate(tmp_path, pages_capture, source)
    assert result["state"] == "job-artifact-observed"
    assert "overrides the supported" in result["pages_preview"]["reason"]


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


def _failure_trace_row(stamp, message):
    return {"time": stamp, "value": message,
            "sha256": hashlib.sha256(f"{stamp} {message}".encode()).hexdigest()}


@pytest.fixture
def failed_capture(capture):
    capture["pipeline"].update(created_at=time(0), updated_at=time(18))
    capture["job"].update(
        status="failed", failure_reason="script_failure", name="test artifacts",
        finished_at=time(15),
        pipeline={**capture["pipeline"]},
        artifacts=[{"file_type": "archive", "file_format": "zip", "size": 123}],
    )
    capture["mr"]["sha"] = "d" * 40
    capture["artifact"]["observed_at"] = time(17)
    messages = [
        "00O+section_start:123:get_sources",
        f"01O Checking out {MERGE[:8]} as detached HEAD (ref is refs/merge-requests/9/merge)...",
        "00O section_end:124:get_sources",
        "00O+section_start:125:step_script",
        "01O $ yarn test:integration",
        "00O section_end:126:step_script",
        "00O+section_start:127:upload_artifacts_on_failure",
        "01E output/: found 1 matching artifact files and directories",
        '01E Uploading artifacts as "archive" to coordinator... 201 Created  id=33 status=201',
        "00O section_end:128:upload_artifacts_on_failure",
        "00O ERROR: Job failed: exit code 1",
    ]
    rows = []
    for i, value in enumerate(messages, 2):
        stamp = time(i)
        epoch = int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
        value = re.sub(r"(section_(?:start|end):)[0-9]+:", rf"\g<1>{epoch}:", value)
        rows.append(_failure_trace_row(stamp, value))
    capture["failed_archive"] = {
        "historical_pipeline": {
            "url": "https://gitlab.com/team/repo/-/pipelines/22.json", "project": 1, "pipeline": 22,
            "mr": 9, "revision": MERGE, "source_sha": HEAD, "target_sha": BASE,
            "event": "merged_result", "sha256": "e" * 64,
        },
        "fork_commit": {"project": 2, "sha": HEAD, "receipt_sha256": "f" * 64},
        "log": {"job": 33, "url": JOB + "/raw", "sha256": "a" * 64, "rows": rows},
    }
    return capture


def test_failed_job_has_an_observed_upload_independent_of_config_analysis(tmp_path, failed_capture):
    result = evaluate(tmp_path, failed_capture, publisher="deploy")
    assert result["state"] == "job-artifact-uploaded-after-failure"
    assert result["fork_head"] == HEAD and result["job_status"] == "failed"
    assert result["publication"]["http_status"] == 201
    assert result["publication"]["member_path"] == "output/index.html"
    assert result["command"] == "yarn test:integration"
    assert result["member_origin"] == result["effective_configuration"] == "unverified"
    assert result["publication_admission"]["state"] == "unresolved"


@pytest.mark.parametrize(
    ("record", "key", "wrong"),
    [
        ("historical_pipeline", "pipeline", 23),
        ("historical_pipeline", "source_sha", "d" * 40),
        ("historical_pipeline", "url", "https://gitlab.com/team/fork/-/pipelines/22.json"),
        ("historical_pipeline", "event", "merge_train"),
        ("fork_commit", "project", 3),
        ("log", "job", 34),
        ("log", "url", JOB + "/trace"),
    ],
)
def test_failed_upload_refuses_foreign_evidence(tmp_path, failed_capture, record, key, wrong):
    failed_capture["failed_archive"][record][key] = wrong
    result = evaluate(tmp_path, failed_capture)
    assert result["state"] == "unresolved" and "publication" not in result


@pytest.mark.parametrize(
    ("slot", "replacement"),
    [
        (4, "01O $ echo yarn test:integration"),
        (6, "00O+section_start:127:step_script"),
        (7, "01E output: found 1 matching artifact files and directories"),
        (8, '01E Uploading artifacts as "archive" to coordinator... 201 Created  id=34 status=201'),
        (8, '01O Uploading artifacts as "archive" to coordinator... 201 Created  id=33 status=201'),
        (8, '01E Uploading artifacts as "archive" to coordinator... 403 Forbidden  id=33 status=403'),
        (9, "00O section_end:128:upload_artifacts_on_success"),
    ],
)
def test_failed_upload_refuses_wrong_command_phase_or_operation(tmp_path, failed_capture, slot, replacement):
    rows = failed_capture["failed_archive"]["log"]["rows"]
    rows[slot] = _failure_trace_row(rows[slot]["time"], replacement)
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


def test_failed_upload_refuses_member_from_sibling_job(tmp_path, failed_capture):
    failed_capture["artifact"]["url"] = JOB.replace("/33", "/34") + "/artifacts/raw/output/index.html"
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


def test_failed_upload_cannot_be_inferred_within_script_or_without_its_receipt(tmp_path, failed_capture):
    rows = failed_capture["failed_archive"]["log"]["rows"]
    upload = rows[8]
    rows[8] = _failure_trace_row(time(6), upload["value"])
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"
    del rows[8]
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


def test_failure_upload_requires_consistent_section_clock(tmp_path, failed_capture):
    rows = failed_capture["failed_archive"]["log"]["rows"]
    rows[6] = _failure_trace_row(rows[6]["time"], "00O+section_start:1:upload_artifacts_on_failure")
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


def test_failure_upload_requires_consistent_pipeline_windows(tmp_path, failed_capture):
    failed_capture["job"]["pipeline"]["updated_at"] = time(0)
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


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

@pytest.fixture
def canceled_capture(failed_capture):
    data = failed_capture
    data.pop("artifact")
    evidence = data.pop("failed_archive")
    evidence["historical_pipeline"]["event"] = "merge_train"
    data["canceled_archive"] = evidence
    data["pipeline"].update(status="canceled", ref="refs/merge-requests/9/train")
    data["job"].update(status="canceled", failure_reason=None, pipeline={**data["pipeline"]})
    rows = evidence["log"]["rows"]
    rows[1] = _failure_trace_row(rows[1]["time"], rows[1]["value"].replace("/merge)", "/train)"))
    rows[8] = _failure_trace_row(
        rows[8]["time"], '01E Uploading artifacts as "archive" to coordinator... '
        '201 Created  correlation_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa id=33 status=201'
    )
    evidence["log"]["rows"] = [rows[index] for index in (0, 1, 2, 3, 5, 6, 8, 9)]
    return data


def test_canceled_job_retains_archive_acceptance(tmp_path, canceled_capture):
    result = evaluate(tmp_path, canceled_capture)
    assert result["state"] == "job-artifact-accepted-canceled-job"
    assert result["job_status"] == "canceled"
    assert result["fork_head"] == HEAD
    assert result["publication"]["http_status"] == 201
    assert result["publication"]["retrieval"] == "unverified"


@pytest.mark.parametrize("bad_receipt", (
    '01E Uploading artifacts as "archive" to coordinator... '
    '403 Forbidden  correlation_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa id=33 status=403',
    '01E Uploading artifacts as "archive" to coordinator... '
    '201 Created  correlation_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa id=34 status=201',
))
def test_canceled_job_requires_its_own_archive_acceptance(tmp_path, canceled_capture, bad_receipt):
    rows = canceled_capture["canceled_archive"]["log"]["rows"]
    rows[6] = _failure_trace_row(rows[6]["time"], bad_receipt)
    result = evaluate(tmp_path, canceled_capture)
    assert result["state"] == "unresolved"
    assert "publication" not in result


@pytest.fixture
def fork_upload(canceled_capture):
    target_url, fork_url = "https://gitlab.com/team/repo", "https://gitlab.com/team/fork"
    ref = "branch-from-fork"
    pipeline = canceled_capture["pipeline"]
    pipeline.update(project_id=2, ref=ref, sha=HEAD, status="success", web_url=f"{fork_url}/-/pipelines/22")
    job = canceled_capture["job"]
    job.update(status="failed", failure_reason="script_failure", pipeline={**pipeline}, web_url=f"{fork_url}/-/jobs/33")
    log = canceled_capture["canceled_archive"]["log"]
    log["url"] = job["web_url"] + "/raw"
    log["rows"][1] = _failure_trace_row(log["rows"][1]["time"],
        f"01O Checking out {HEAD[:8]} as detached HEAD (ref is {ref})...")
    return {
        "schema": "gitlab-fork-project-archive-v1",
        "target": {"id": 1, "path_with_namespace": "team/repo", "web_url": target_url},
        "fork": {"id": 2, "path_with_namespace": "team/fork", "web_url": fork_url,
                 "forked_from": {"id": 1, "path_with_namespace": "team/repo"}},
        "mr": {"iid": 9, "source_project_id": 2, "target_project_id": 1,
               "source_branch": ref, "sha": HEAD, "web_url": f"{target_url}/-/merge_requests/9"},
        "pipeline": pipeline,
        "mr_pipeline": {**pipeline},
        "commit": {"id": HEAD, "web_url": f"{fork_url}/-/commit/{HEAD}"},
        "job": job,
        "log": log,
    }


def _evaluate_fork(root, data, selected=2):
    source = BUILDSPEC.encode()
    (root / ".gitlab-ci.yml").write_bytes(source)
    data["source_sha256"] = hashlib.sha256(source).hexdigest()
    snapshot = root / "observation.json"
    snapshot.write_text(json.dumps(data), encoding="utf-8")
    return mr_artifact_observation(snapshot, root, selected, 22, 33)


@pytest.mark.parametrize("mutation", [None, "repository", "mr", "commit", "event", "time"])
def test_advanced_mr_head_requires_exact_detached_pipeline_view(tmp_path, fork_upload, mutation):
    fork_upload["mr"]["sha"] = BASE
    pipeline = fork_upload["pipeline"]
    view = {
        "url": pipeline["web_url"] + ".json",
        "sha256": "a" * 64,
        "project": 2,
        "pipeline": 22,
        "mr_url": fork_upload["mr"]["web_url"],
        "event": "detached",
        "source": pipeline["source"],
        "ref": pipeline["ref"],
        "revision": HEAD,
        "created_at": pipeline["created_at"],
    }
    incorrect = {
        "repository": ("project", 1),
        "mr": ("mr_url", fork_upload["mr"]["web_url"] + "0"),
        "commit": ("revision", BASE),
        "event": ("event", "merged_result"),
        "time": ("created_at", pipeline["updated_at"]),
    }
    if mutation is not None:
        key, value = incorrect[mutation]
        view[key] = value
    fork_upload["historical_pipeline"] = view
    result = _evaluate_fork(tmp_path, fork_upload)
    if mutation is not None:
        assert result["state"] == "unresolved"
        assert "publication" not in result
    else:
        assert result["state"] == "fork-project-archive-upload-observed"
        assert result["revision"] == HEAD
        assert result["historical_pipeline"]["current_mr_head"] == BASE


@pytest.mark.parametrize("suffix", ["status=201", "responseStatus=201 Created"])
def test_fork_archive_acceptance_identifies_fork_and_parent_separately(tmp_path, fork_upload, suffix):
    row = fork_upload["log"]["rows"][6]
    fork_upload["log"]["rows"][6] = _failure_trace_row(row["time"],
        f'01E Uploading artifacts as "archive" to coordinator... 201 Created  '
        f'correlation_id=0123456789abcdef-SJC id=33 {suffix}')
    result = _evaluate_fork(tmp_path, fork_upload)
    assert result["state"] == "fork-project-archive-upload-observed"
    assert (result["project"], result["target_project"]) == (2, 1)
    assert result["publication"]["target"] == "https://gitlab.com/team/fork/-/jobs/33/artifacts/download"
    assert result["publication"]["retrieval"] == "unverified"


@pytest.mark.parametrize("mutation", ["canonical-target", "wrong-membership", "new-mr-head", "denied-response"])
def test_fork_archive_refuses_contradictory_source_or_result(tmp_path, fork_upload, mutation):
    project = 2
    if mutation == "canonical-target":
        project = 1
    elif mutation == "wrong-membership":
        fork_upload["mr_pipeline"]["id"] = 23
    elif mutation == "new-mr-head":
        fork_upload["mr"]["sha"] = BASE
    else:
        row = fork_upload["log"]["rows"][6]
        fork_upload["log"]["rows"][6] = _failure_trace_row(row["time"],
            row["value"].replace("201 Created", "403 Forbidden").replace("status=201", "status=403"))
    result = _evaluate_fork(tmp_path, fork_upload, project)
    assert result["state"] == "unresolved"
    assert "publication" not in result


@pytest.mark.parametrize(
    "contrast", [None, "direct", "wrong-job", "foreign-cdn", "bad-size", "bad-digest", "not-zip"]
)
def test_fork_archive_download_preserves_the_upload_decision(tmp_path, fork_upload, contrast):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("build.txt", "observed archive bytes")
    data = buffer.getvalue() if contrast != "not-zip" else b"not a zip"
    (tmp_path / "published-archive.zip").write_bytes(data)
    archive, = [entry for entry in fork_upload["job"]["artifacts"] if entry["file_type"] == "archive"]
    archive["size"] = len(data)
    job_url = fork_upload["job"]["web_url"]
    receipt = {
        "job": 33,
        "url": job_url + "/artifacts/download",
        "observed_at": fork_upload["job"]["finished_at"],
        "responses": [
            {"status": 302, "host": "gitlab.com"},
            {"status": 200, "host": "cdn.artifacts.gitlab-static.net"},
        ],
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if contrast == "direct":
        receipt["responses"] = [{"status": 200, "host": "gitlab.com"}]
    elif contrast == "wrong-job":
        receipt["url"] = job_url.replace("/33", "/34") + "/artifacts/download"
    elif contrast == "foreign-cdn":
        receipt["responses"][-1]["host"] = "example.test"
    elif contrast == "bad-size":
        receipt["bytes"] += 1
    elif contrast == "bad-digest":
        receipt["sha256"] = "a" * 64
    fork_upload["archive_download"] = receipt
    result = _evaluate_fork(tmp_path, fork_upload)
    assert result["state"] == "fork-project-archive-upload-observed"
    assert result["publication"]["http_status"] == 201
    if contrast in (None, "direct"):
        assert result["archive_download"]["sha256"] == receipt["sha256"]
        assert result["archive_download"]["state"] == "fork-project-archive-retrieved"
        assert result["publication"]["retrieval"] == "verified"
    else:
        assert result["archive_download"]["state"] == "unresolved"
        assert result["publication"]["retrieval"] == "unverified"
