"""Authored boundaries for the saved fork MR artifact evidence path."""

import hashlib
import json
import re
import sys
from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

import pytest

from taintly import __main__ as cli
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
            {
                "kind": "upload",
                "time": time(4),
                "job": 33,
                "http_status": 201,
                "line": 8,
                "trace_sha256": "d" * 64,
                "correlation_id": "e" * 32,
            },
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



def _runner_archive_evidence():
    return {
        "job": 33,
        "pipeline": 22,
        "revision": MERGE,
        "trace_url": JOB + "/raw",
        "trace_sha256": "d" * 64,
        "executor": "docker+machine",
        "runner_revision": "7a0f126423ab4aefa71be5cda32668e29bc59b2d",
        "helper_index": "sha256:604025ad1395452e28268e5ca722452d8e3a3badfd7bee628941a6bfb7ead975",
        "helper_config": "sha256:060c57dea4e06ce034c9959e734771d2542983156682d85447a6f9152e64ecd4",
        "checkout_directory": "/builds/team/repo",
        "runner_line": 1,
        "helper_line": 2,
        "archive_start_line": 3,
        "archive_line": 8,
        "archive_end_line": 9,
        "archive_start_time": time(3),
        "archive_time": time(4),
        "archive_end_time": time(5),
        "correlation_id": "e" * 32,
    }


@pytest.mark.parametrize(
    ("changed", "value", "expected"),
    [
        ("job", 33, "native-archive-write-observed"),
        ("job", 34, "unresolved"),
        ("revision", BASE, "unresolved"),
        ("archive_time", time(3), "unresolved"),
        ("archive_end_line", 8, "unresolved"),
        ("helper_config", "sha256:" + "a" * 64, "unresolved"),
        ("checkout_directory", "/other", "unresolved"),
        ("correlation_id", "bad\rvalue", "unresolved"),
        ("trace_sha256", "f" * 64, "unresolved"),
        ("correlation_id", "f" * 32, "unresolved"),
        ("archive_line", 7, "unresolved"),
    ],
)
def test_native_archive_authority_binds_the_owned_runner(tmp_path, capture, changed, value, expected):
    capture["archive_runner_evidence"] = _runner_archive_evidence()
    capture["archive_runner_evidence"][changed] = value
    result = evaluate(tmp_path, capture)
    assert result["state"] == "job-artifact-observed"
    authority = result["archive_runner_authority"]
    assert authority["state"] == expected
    if expected == "native-archive-write-observed":
        assert authority["credential"] == "runner-job-token"
        assert authority["route"] == "jobs/33/artifacts"
        assert authority["archive_response_line"] == 8
        assert authority["correlation_id"] == "e" * 32
    else:
        assert "credential" not in authority


@pytest.mark.parametrize("missing", ["trace_sha256", "correlation_id", "line"])
def test_merged_archive_remains_observed_without_runner_response_identity(tmp_path, capture, missing):
    capture["archive_runner_evidence"] = _runner_archive_evidence()
    del capture["trace"][-1][missing]
    result = evaluate(tmp_path, capture)
    assert result["state"] == "job-artifact-observed"
    assert result["archive_runner_authority"] == {
        "state": "unresolved",
        "reason": "runner evidence does not match the verified merged-job archive response",
    }


@pytest.mark.parametrize("borrowed_index", [False, True])
def test_new_runner_requires_its_own_helper_image(tmp_path, capture, borrowed_index):
    evidence = _runner_archive_evidence()
    evidence.update(
        runner_revision="d22d8753a6b96df6131d1d500decb4192d7f6f31",
        helper_config="sha256:ea7a461bccb1b352892e9fbbf7430a63c0b9ffacd7b28ae6ca2e786ba4d34de2",
    )
    if not borrowed_index:
        evidence["helper_index"] = (
            "sha256:6fa6131930f0200667b536f3269fa038c09338763e864b80153b7bf0591d5bc8"
        )
    capture["archive_runner_evidence"] = evidence
    result = evaluate(tmp_path, capture)
    assert result["state"] == "job-artifact-observed"
    authority = result["archive_runner_authority"]
    if borrowed_index:
        assert authority["state"] == "unresolved"
        assert "credential" not in authority
    else:
        assert authority["credential"] == "runner-job-token"
        assert authority["helper_image_executable_sha256"] == (
            "eda88cf7ce99060eb557f4d83f7937081bbe305d6bab9df5018d520a5fc8e810"
        )


def test_report_distinguishes_fork_head_and_checkout(tmp_path, capture, monkeypatch, capsys):
    evaluate(tmp_path, capture)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "taintly",
            str(tmp_path),
            "--no-config",
            "--gitlab-mr-artifact-observation",
            str(tmp_path / "observation.json"),
            "1",
            "22",
            "33",
        ],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == 0
    text = capsys.readouterr().out
    assert f"Pipeline 22 checked out merged revision {MERGE}." in text
    assert f"Fork head: {HEAD}." in text


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


@pytest.mark.parametrize("command", [
    "yarn test:integration",
    "yarn test:integration tests/integration/example.test.ts",
])
def test_failed_job_has_an_observed_upload_independent_of_config_analysis(tmp_path, failed_capture, command):
    rows = failed_capture["failed_archive"]["log"]["rows"]
    rows[4] = _failure_trace_row(rows[4]["time"], f"01O $ {command}")
    result = evaluate(tmp_path, failed_capture, publisher="deploy")
    assert result["state"] == "job-artifact-uploaded-after-failure"
    assert result["fork_head"] == HEAD and result["job_status"] == "failed"
    assert result["publication"]["http_status"] == 201
    assert result["publication"]["member_path"] == "output/index.html"
    assert result["command"] == command
    assert result["member_origin"] == result["effective_configuration"] == "unverified"
    assert result["publication_admission"]["state"] == "unresolved"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [(None, None), ("job", 34), ("archive_line", 11),
     ("archive_end_line", 13), ("correlation_id", "f" * 32), ("trace_sha256", "b" * 64)],
)
def test_failed_archive_keeps_upload_when_runner_authority_disagrees(
    tmp_path, failed_capture, field, replacement
):
    log = failed_capture["failed_archive"]["log"]
    rows = log["rows"]
    rows[8] = _failure_trace_row(
        rows[8]["time"],
        '01E Uploading artifacts as "archive" to coordinator... 201 Created '
        f'correlation_id={"e" * 32} id=33 status=201',
    )
    evidence = _runner_archive_evidence()
    for slot, key, line in [(6, "archive_start", 7), (8, "archive", 10), (9, "archive_end", 12)]:
        rows[slot]["line"] = evidence[f"{key}_line"] = line
        evidence[f"{key}_time"] = rows[slot]["time"]
    evidence["trace_sha256"] = log["sha256"]
    if field:
        evidence[field] = replacement
    failed_capture["archive_runner_evidence"] = evidence
    result = evaluate(tmp_path, failed_capture)
    assert result["state"] == "job-artifact-uploaded-after-failure"
    assert result["publication"]["http_status"] == 201
    authority = result["archive_runner_authority"]
    if field:
        assert authority["state"] == "unresolved"
        assert "credential" not in authority
    else:
        assert authority["state"] == "native-archive-write-observed"
        assert authority["route"] == "jobs/33/artifacts"
        assert authority["credential"] == "runner-job-token"


def test_failed_gradle_job_binds_recursive_artifact_selection(tmp_path, failed_capture):
    rows = failed_capture["failed_archive"]["log"]["rows"]
    for slot, message in (
        (4, "01O $ ./gradlew :app:assembleDefault :app:testFullDebugUnitTest"),
        (7, "01E output: found 2 matching artifact files and directories"),
        (8, '01E Uploading artifacts as "archive" to coordinator... 201 Created '
            'correlation_id=0123456789abcdef-PDX id=33 status=201'),
    ):
        rows[slot] = _failure_trace_row(rows[slot]["time"], message)

    result = evaluate(tmp_path, failed_capture)
    assert result["state"] == "job-artifact-uploaded-after-failure"
    assert result["command"] == "./gradlew :app:assembleDefault :app:testFullDebugUnitTest"
    assert result["publication"]["member_path"] == "output/index.html"
    assert result["member_origin"] == "unverified"

    failed_capture["artifact"].update(
        path="output-other/index.html", url=JOB + "/artifacts/raw/output-other/index.html"
    )
    assert evaluate(tmp_path, failed_capture)["state"] == "unresolved"


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
        (4, "01O $ ./gradlew $FLAG :app:connectedAndroidTest"),
        (4, "01O $ yarn test:integration $TEST_PATH"),
        (4, "01O $ yarn test:integration tests/../example.test.ts"),
        (4, "01O $ yarn test:integration --file tests/example.test.ts"),
        (4, "01O $ yarn test:integration tests/example.test.ts && true"),
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
def empty_upload(canceled_capture):
    log = canceled_capture["canceled_archive"]["log"]
    job, pipeline = canceled_capture["job"], canceled_capture["pipeline"]
    job["artifacts"] = [{"file_type": "trace"}]
    row = log["rows"][6]
    log["rows"][6] = _failure_trace_row(row["time"], "01E ERROR: No files to upload")
    for line, item in enumerate(log["rows"], 10):
        item["line"] = line
    log["no_payload_runner"] = {
        "job": job["id"],
        "pipeline": pipeline["id"],
        "revision": pipeline["sha"],
        "trace_url": log["url"],
        "trace_sha256": log["sha256"],
        "executor": "docker+machine",
        "runner_revision": "7a0f126423ab4aefa71be5cda32668e29bc59b2d",
        "helper_index": "sha256:604025ad1395452e28268e5ca722452d8e3a3badfd7bee628941a6bfb7ead975",
        "helper_config": "sha256:060c57dea4e06ce034c9959e734771d2542983156682d85447a6f9152e64ecd4",
        "checkout_directory": "/builds/team/repo",
        "runner_line": 1,
        "helper_line": 9,
    }
    return canceled_capture


def test_empty_uploader_stopped_before_the_request(tmp_path, empty_upload):
    result = evaluate(tmp_path, empty_upload)

    assert result["state"] == "artifact-upload-not-reached"
    assert result["upload"]["authorization"] == "unverified"
    assert [row["line"] for row in result["upload"]["markers"]] == [16]
    assert "publication" not in result


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job", 34),
        ("trace_sha256", "0" * 64),
        ("helper_index", "sha256:" + "0" * 64),
        ("helper_line", 17),
    ],
)
def test_empty_uploader_needs_matching_runner_evidence(tmp_path, empty_upload, field, value):
    empty_upload["canceled_archive"]["log"]["no_payload_runner"][field] = value

    result = evaluate(tmp_path, empty_upload)

    assert result["state"] == "unresolved"
    assert "publication" not in result
    assert "pre-request stop has not been verified" in result["scope"]


def test_empty_marker_cannot_qualify_a_coordinator_refusal(tmp_path, empty_upload):
    rows = empty_upload["canceled_archive"]["log"]["rows"]
    reply = '01E Uploading artifacts as "archive" to coordinator... 403 Forbidden id=33 status=403'
    rows[6] = {**_failure_trace_row(rows[6]["time"], reply), "line": 16}

    assert evaluate(tmp_path, empty_upload)["state"] == "unresolved"


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


@pytest.mark.parametrize(
    ("status", "contrast"),
    [
        ("success", None),
        ("failed", None),
        ("running", None),
        ("success", "missing-source"),
        ("success", "different-checkout"),
        ("success", "foreign-parent"),
        ("success", "before-job-finish"),
        ("success", "wrong-phase"),
        ("success", "pages-handoff"),
    ],
)
def test_completed_fork_job_archive_with_live_parent(tmp_path, fork_upload, status, contrast):
    pipeline = fork_upload["pipeline"]
    pipeline.update(status="running", updated_at=time(1))
    job = fork_upload["job"]
    job.update(status=status, commit={"id": HEAD})
    if status == "success":
        job["failure_reason"] = None
    if status == "success" and contrast != "wrong-phase":
        rows = fork_upload["log"]["rows"]
        for index in (5, 7):
            row = rows[index]
            rows[index] = _failure_trace_row(
                row["time"], row["value"].replace("on_failure", "on_success")
            )
    receipt = {
        "url": "https://gitlab.com/api/v4/projects/2/pipelines/22",
        "http_status": 200,
        "observed_at": job["finished_at"],
        "sha256": "a" * 64,
    }
    fork_upload["live_pipeline_receipt"] = receipt
    if contrast != "missing-source":
        fork_upload["source_file"] = {
            "url": f"https://gitlab.com/api/v4/projects/2/repository/files/.gitlab-ci.yml?ref={HEAD}",
            "file_path": ".gitlab-ci.yml",
            "commit_id": HEAD,
            "content_sha256": hashlib.sha256(BUILDSPEC.encode()).hexdigest(),
        }
    if contrast == "different-checkout":
        job["commit"]["id"] = BASE
    if contrast == "foreign-parent":
        receipt["url"] = receipt["url"].replace("/22", "/23")
    if contrast == "before-job-finish":
        receipt["observed_at"] = pipeline["updated_at"]
    if contrast == "pages-handoff":
        fork_upload["pages_handoff"] = {}

    result = _evaluate_fork(tmp_path, fork_upload)

    if status == "running" or contrast not in {None, "pages-handoff"}:
        assert result["state"] == "unresolved"
        assert "publication" not in result
    else:
        assert result["state"] == "fork-project-archive-upload-observed"
        assert result["pipeline_status"] == "running"
        assert result["job_status"] == status
        assert result["publication"]["http_status"] == 201
        if contrast == "pages-handoff":
            assert result["pages_handoff"] == {
                "state": "unresolved",
                "reason": "Pages handoff needs a terminal fork pipeline inventory",
            }


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


@pytest.mark.parametrize("mismatched_url", [False, True])
def test_fork_archive_keeps_gitlab_namespace_case(tmp_path, fork_upload, mismatched_url):
    source = "https://gitlab.com/Contributor/fork"
    fork_upload["fork"].update(path_with_namespace="Contributor/fork", web_url=source)
    for record in ("pipeline", "mr_pipeline", "commit", "job"):
        value = fork_upload[record]
        value["web_url"] = value["web_url"].replace("https://gitlab.com/team/fork", source)
    job = fork_upload["job"]
    job["pipeline"]["web_url"] = fork_upload["pipeline"]["web_url"]
    fork_upload["log"]["url"] = job["web_url"] + "/raw"
    if mismatched_url:
        fork_upload["commit"]["web_url"] = fork_upload["commit"]["web_url"].lower()
    result = _evaluate_fork(tmp_path, fork_upload)
    if mismatched_url:
        assert result["state"] == "unresolved"
        assert "publication" not in result
    else:
        assert result["repository"] == "Contributor/fork"
        assert result["publication"]["target"] == source + "/-/jobs/33/artifacts/download"


@pytest.mark.parametrize("contrast", [None, "wrong-phase", "failure-reason", "wrong-job"])
def test_successful_fork_archive_requires_its_exact_success_phase_and_status(
    tmp_path, fork_upload, contrast
):
    job = fork_upload["job"]
    job["status"] = "success"
    if contrast != "failure-reason":
        job.pop("failure_reason")
    rows = fork_upload["log"]["rows"]
    if contrast != "wrong-phase":
        for index in (5, 7):
            row = rows[index]
            rows[index] = _failure_trace_row(
                row["time"], row["value"].replace("on_failure", "on_success")
            )
    if contrast == "wrong-job":
        row = rows[6]
        rows[6] = _failure_trace_row(row["time"], row["value"].replace("id=33", "id=34"))
    result = _evaluate_fork(tmp_path, fork_upload)
    if contrast:
        assert result["state"] == "unresolved"
        assert "publication" not in result
    else:
        assert result["state"] == "fork-project-archive-upload-observed"
        assert result["job_status"] == "success"
        assert result["upload_phase"] == "upload_artifacts_on_success"
        assert result["publication"]["http_status"] == 201


@pytest.mark.parametrize(
    ("changed", "value"),
    [
        (None, None),
        ("trace_sha256", "f" * 64),
        ("archive_line", 11),
        ("correlation_id", "f" * 32),
    ],
)
@pytest.mark.parametrize("job_succeeded", [True, False])
def test_fork_runner_authority_binds_the_verified_archive(tmp_path, fork_upload, changed, value, job_succeeded):
    log = fork_upload["log"]
    rows = log["rows"]
    if job_succeeded:
        fork_upload["job"].update(status="success", failure_reason=None)
        for index in (5, 7):
            row = rows[index]
            rows[index] = _failure_trace_row(row["time"], row["value"].replace("on_failure", "on_success"))
    for number, row in enumerate(rows, start=3):
        row["line"] = number

    evidence = _runner_archive_evidence()
    evidence.update(
        revision=HEAD, trace_url=log["url"], trace_sha256=log["sha256"],
        checkout_directory="/builds/team/fork",
        archive_start_line=rows[5]["line"], archive_line=rows[6]["line"], archive_end_line=rows[7]["line"],
        archive_start_time=rows[5]["time"], archive_time=rows[6]["time"], archive_end_time=rows[7]["time"],
        correlation_id=rows[6]["value"].split("correlation_id=")[1].split()[0],
    )
    if changed is not None:
        evidence[changed] = value
    fork_upload["archive_runner_evidence"] = evidence

    result = _evaluate_fork(tmp_path, fork_upload)
    assert result["state"] == "fork-project-archive-upload-observed"
    assert result["publication"]["http_status"] == 201
    authority = result["archive_runner_authority"]
    if changed is None:
        assert authority["credential"] == "runner-job-token"
        assert authority["route"] == "jobs/33/artifacts"
        assert authority["trace_sha256"] == log["sha256"]
    else:
        assert authority["state"] == "unresolved"
        assert "credential" not in authority


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
    "contrast",
    [None, "foreign-job-commit", "foreign-source-owner", "foreign-source-commit",
     "foreign-source-path", "foreign-source-digest"],
)
def test_terminal_fork_archive_checks_supplied_job_and_source_identity(tmp_path, fork_upload, contrast):
    fork_upload["job"]["commit"] = {"id": HEAD}
    source_file = {
        "url": f"https://gitlab.com/api/v4/projects/2/repository/files/.gitlab-ci.yml?ref={HEAD}",
        "file_path": ".gitlab-ci.yml",
        "commit_id": HEAD,
        "content_sha256": hashlib.sha256(BUILDSPEC.encode()).hexdigest(),
    }
    fork_upload["source_file"] = source_file
    if contrast == "foreign-job-commit":
        fork_upload["job"]["commit"]["id"] = BASE
    elif contrast == "foreign-source-owner":
        source_file["url"] = source_file["url"].replace("projects/2", "projects/1")
    elif contrast == "foreign-source-commit":
        source_file["commit_id"] = BASE
    elif contrast == "foreign-source-path":
        source_file["file_path"] = "other.yml"
    elif contrast == "foreign-source-digest":
        source_file["content_sha256"] = "0" * 64

    result = _evaluate_fork(tmp_path, fork_upload)
    if contrast is None:
        assert result["state"] == "fork-project-archive-upload-observed"
        assert result["publication"]["http_status"] == 201
    else:
        assert result["state"] == "unresolved"
        assert "publication" not in result
        if contrast == "foreign-job-commit":
            assert "job commit differs" in result["reason"]
        else:
            assert "configuration record does not match" in result["reason"]


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


@pytest.mark.parametrize(
    "contrast", [None, "wrong-archive", "missing-download", "same-display", "wrong-parent",
                 "wrong-source", "opaque-panel", "ambiguous-id", "wrong-display", "wrong-member", "non-renderer-escape"]
)
def test_fork_archive_origin_needs_the_bound_zip_and_distinct_display_source(
    tmp_path, fork_upload, contrast
):
    source = b"package main\n\t// <fork display>\n"
    parent = source.replace(b"fork", b"prior")
    if contrast == "same-display":
        parent = source.replace(b"\t", b" " * 8)
    path = "internal/sample.go"
    artifact = "coverage.html"
    fork_upload["commit"]["parent_ids"] = [BASE]
    claim = {
        "format": "go-cover-html-v1", "member": artifact,
        "path": path, "package": "example.test/project/internal",
    }
    for label, revision, raw in (("source", HEAD, source), ("parent", BASE, parent)):
        (tmp_path / f"coverage-{label}.go").write_bytes(raw)
        claim[label] = {
            "url": f"https://gitlab.com/api/v4/projects/2/repository/files/internal%2Fsample.go?ref={revision}",
            "file_path": path, "commit": revision, "size": len(raw),
            "blob_id": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                                    usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    if contrast == "wrong-parent":
        claim["parent"]["commit"] = HEAD
    elif contrast == "wrong-source":
        claim["source"]["blob_id"] = claim["parent"]["blob_id"]
    elif contrast == "wrong-member":
        claim["member"] = "other.html"
    fork_upload["archive_member_origin"] = claim
    panel = (b'<pre class="file" id="file0" style="display: none">package main\n'
             b'<span class="cov1" title="1">        // &lt;fork display&gt;</span>\n</pre>')
    if contrast == "opaque-panel":
        panel = b"<!--" + panel + b"-->"
    elif contrast == "wrong-display":
        panel = panel.replace(b"fork", b"prior")
    elif contrast == "non-renderer-escape":
        panel = panel.replace(b"&lt;", b"&#60;")
    option = b'<option value="file0">example.test/project/internal/sample.go (0.0%)</option>'
    if contrast == "ambiguous-id":
        option += b'<option value="file0">example.test/project/internal/other.go (0.0%)</option>'
    payload = b'<select id="files">' + option + b'</select><div id="content">' + panel + b"</div>"
    buffer = BytesIO()
    with ZipFile(buffer, "w") as z:
        z.writestr(artifact, payload)
    raw_zip = buffer.getvalue()
    (tmp_path / "published-archive.zip").write_bytes(raw_zip)
    saved, = [r for r in fork_upload["job"]["artifacts"] if r["file_type"] == "archive"]
    saved["size"] = len(raw_zip)
    if contrast != "missing-download":
        fork_upload["archive_download"] = {
            "job": 34 if contrast == "wrong-archive" else 33,
            "url": fork_upload["job"]["web_url"] + "/artifacts/download",
            "observed_at": fork_upload["job"]["finished_at"],
            "responses": [{"status": 200, "host": "gitlab.com"}],
            "bytes": len(raw_zip), "sha256": hashlib.sha256(raw_zip).hexdigest(),
        }
    result = _evaluate_fork(tmp_path, fork_upload)
    assert result["publication"]["http_status"] == 201
    origin = result["archive_member_origin"]
    assert origin["state"] == ("unresolved" if contrast else "fork-source-display-matched")
    if contrast is None:
        assert origin["display_sha256"] == hashlib.sha256(source.replace(b"\t", b" " * 8)).hexdigest()
        assert origin["archive_sha256"] == result["archive_download"]["sha256"]
        assert origin["revision"] == HEAD
        assert origin["parent"] == BASE
    else:
        assert "member_sha256" not in origin


@pytest.mark.parametrize(
    ("conflict", "wrong"),
    [
        ("", None),
        ("job_id", 34),
        ("pipeline_id", 99),
        ("sha", BASE),
        ("job_user_id", 104),
        ("deployment_user_id", True),
    ],
)
def test_pages_account_requires_the_same_owned_deployment_and_job(
    tmp_path, pages_capture, conflict, wrong
):
    projection = {
        "job_id": 33,
        "pipeline_id": pages_capture["pipeline"]["id"],
        "sha": MERGE,
        "deployment_id": 55,
        "job_user_id": 103,
        "deployment_user_id": 103,
    }
    if conflict:
        projection[conflict] = wrong
    pages_capture["pages_preview"]["account"] = projection
    result = evaluate(tmp_path, pages_capture, PAGES)
    assert result["state"] == "job-artifact-observed"
    preview = result["pages_preview"]
    assert preview["state"] == "pages-preview-deployment-recorded"
    assert preview["availability"] == "unverified"
    observed = preview["account"]
    if conflict:
        assert observed["state"] == "unresolved"
        assert "account_id" not in observed
    else:
        assert observed["state"] == "deployment-account-recorded"
        assert observed["account_id"] == 103


@pytest.fixture
def target_head_upload(fork_upload):
    data = fork_upload
    data["schema"] = "gitlab-target-project-head-archive-v1"
    target_url = data["target"]["web_url"]
    project = data["target"]["id"]
    job = data["job"]
    ref = "refs/merge-requests/9/head"
    data["pipeline"].update(
        project_id=project, ref=ref, web_url=f"{target_url}/-/pipelines/22"
    )
    data["mr_pipeline"] = {**data["pipeline"]}
    job.update(
        status="success", failure_reason=None, pipeline={**data["pipeline"]},
        web_url=f"{target_url}/-/jobs/33", name="Build documentation", commit={"id": HEAD},
    )
    log = data["log"]
    log["url"] = job["web_url"] + "/raw"
    rows = log["rows"]
    rows[1] = _failure_trace_row(
        rows[1]["time"], f"01O Checking out {HEAD[:8]} as detached HEAD (ref is {ref})..."
    )
    for index in (5, 7):
        row = rows[index]
        rows[index] = _failure_trace_row(
            row["time"], row["value"].replace("on_failure", "on_success")
        )
    data["source_file"] = {
        "url": f"https://gitlab.com/api/v4/projects/2/repository/files/.gitlab-ci.yml?ref={HEAD}",
        "commit_id": HEAD,
        "file_path": ".gitlab-ci.yml",
        "content_sha256": hashlib.sha256(BUILDSPEC.encode()).hexdigest(),
    }
    return data


@pytest.mark.parametrize(
    ("job_status", "pipeline_status", "allow_failure", "accepted"),
    [
        ("failed", "failed", None, True),
        ("success", "success", None, False),
        ("failed", "success", True, True),
        ("failed", "success", None, False),
        ("failed", "success", False, False),
        ("failed", "success", "true", False),
        ("failed", "canceled", True, False),
    ],
)
def test_explicit_origin_requires_failed_current_head_target_archive(
    tmp_path, target_head_upload, job_status, pipeline_status, allow_failure, accepted
):
    origin = "https://ci.example.org"
    data = json.loads(json.dumps(target_head_upload).replace("https://gitlab.com", origin))
    data["job"]["status"] = job_status
    data["pipeline"]["status"] = pipeline_status
    data["job"]["pipeline"]["status"] = data["mr_pipeline"]["status"] = pipeline_status
    data["job"]["failure_reason"] = "script_failure" if job_status == "failed" else None
    if allow_failure is not None:
        data["job"]["allow_failure"] = allow_failure
    rows = data["log"]["rows"]
    if job_status == "failed":
        for index in (5, 7):
            row = rows[index]
            rows[index] = _failure_trace_row(
                row["time"], row["value"].replace("on_success", "on_failure")
            )
    response = rows[6]
    rows[6] = _failure_trace_row(
        response["time"],
        re.sub(r"correlation_id=\S+", "correlation_id=" + "0" * 26, response["value"]),
    )
    source = BUILDSPEC.encode()
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    data["source_sha256"] = hashlib.sha256(source).hexdigest()
    packet = tmp_path / "observation.json"
    packet.write_text(json.dumps(data), encoding="utf-8")
    result = mr_artifact_observation(packet, tmp_path, 1, 22, 33, origin=origin)
    if not accepted:
        assert result["state"] == "unresolved"
        assert "publication" not in result
    else:
        assert result["state"] == "target-project-head-archive-upload-observed"
        assert result["origin"] == origin
        assert result["job_status"] == "failed"
        assert result["upload_phase"] == "upload_artifacts_on_failure"
        assert result["publication"]["http_status"] == 201
        assert result["publication"]["target"] == f"{origin}/team/repo/-/jobs/33/artifacts/download"
        if pipeline_status == "success":
            assert result["pipeline_status"] == "success"
            assert result["job_allow_failure"] is True
        else:
            assert "job_allow_failure" not in result


@pytest.mark.parametrize(
    "contrast",
    [
        None,
        "missing-origin",
        "foreign-origin",
        "origin-with-path",
        "different-job",
        "job-status",
        "foreign-trace",
        "foreign-file",
        "missing-history",
        "bad-epoch",
        "foreign-tree",
    ],
)
def test_explicit_origin_binds_canceled_detached_archive(tmp_path, target_head_upload, contrast):
    origin = "https://ci.example.org"
    data = json.loads(json.dumps(target_head_upload).replace("https://gitlab.com", origin))
    data["mr"]["sha"] = BASE
    data["pipeline"]["status"] = data["job"]["status"] = "canceled"
    data["job"]["pipeline"]["status"] = data["mr_pipeline"]["status"] = "canceled"
    pipe = data["pipeline"]
    data["historical_pipeline"] = {
        "url": pipe["web_url"] + ".json",
        "sha256": "f" * 64,
        "project": 1,
        "pipeline": 22,
        "mr_url": data["mr"]["web_url"],
        "event": "detached",
        "source": pipe["source"],
        "revision": HEAD,
        "ref": pipe["ref"],
        "created_at": pipe["created_at"],
    }
    rows = data["log"]["rows"]
    for index in (5, 7):
        row = rows[index]
        rows[index] = _failure_trace_row(
            row["time"], row["value"].replace("on_success", "on_failure").replace("00O+", "00O ")
        )
    response = rows[6]
    rows[6] = _failure_trace_row(
        response["time"],
        re.sub(r"correlation_id=\S+", "correlation_id=" + "0" * 26, response["value"]),
    )
    if contrast == "missing-origin":
        origin = None
    elif contrast == "foreign-origin":
        origin = "https://other.example.org"
    elif contrast == "origin-with-path":
        origin += "/team"
    elif contrast == "different-job":
        rows[6] = _failure_trace_row(rows[6]["time"], rows[6]["value"].replace("id=33", "id=34"))
    elif contrast == "job-status":
        data["job"]["status"] = "failed"
    elif contrast == "foreign-trace":
        data["log"]["url"] = data["log"]["url"].replace("ci.example.org", "other.example.org")
    elif contrast == "foreign-file":
        data["source_file"]["url"] = data["source_file"]["url"].replace(
            "ci.example.org", "other.example.org"
        )
    elif contrast == "missing-history":
        del data["historical_pipeline"]
    elif contrast == "foreign-tree":
        body = b'[{"name":"build.zip","path":"build.zip","type":"file","size":25}]'
        (tmp_path / "archive-tree.json").write_bytes(body)
        data["archive_tree"] = {
            "project": 1,
            "job": 33,
            "member": "build.zip",
            "url": "https://gitlab.com/api/v4/projects/1/jobs/33/artifacts/tree",
            "status": 200,
            "observed_at": data["job"]["finished_at"],
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    elif contrast == "bad-epoch":
        rows[5] = _failure_trace_row(
            rows[5]["time"], re.sub(r"section_start:\d+:", "section_start:0:", rows[5]["value"])
        )
    source = BUILDSPEC.encode()
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    data["source_sha256"] = hashlib.sha256(source).hexdigest()
    packet = tmp_path / "observation.json"
    packet.write_text(json.dumps(data), encoding="utf-8")
    result = mr_artifact_observation(packet, tmp_path, 1, 22, 33, origin=origin)
    if contrast not in {None, "foreign-tree"}:
        assert result["state"] == "unresolved"
        assert "publication" not in result
        assert "archive upload outcome for the selected GitLab job remains unverified" in result["scope"]
        return
    if contrast == "foreign-tree":
        assert result["archive_tree"]["state"] == "unresolved"
    assert result["state"] == "target-project-head-archive-accepted-canceled-job"
    assert "HTTP 201 archive response" in result["scope"]
    assert result["job_status"] == "canceled"
    assert result["historical_pipeline"]["current_mr_head"] == BASE
    assert result["revision"] == HEAD
    assert result["publication"]["http_status"] == 201
    assert result["publication"]["retrieval"] == "unverified"


@pytest.mark.parametrize(
    "contrast",
    [
        None, "selected-fork", "membership", "merge-ref", "advanced-head",
        "job-checkout", "fork-file", "job-url", "no-receipt", "wrong-phase",
        "different-upload-job", "unsupported-profile",
    ],
)
def test_target_head_archive_requires_consistent_source_execution_and_upload(
    tmp_path, target_head_upload, contrast
):
    data = target_head_upload
    selected = 1
    if contrast == "selected-fork":
        selected = 2
    elif contrast == "membership":
        data["mr_pipeline"]["project_id"] = 2
    elif contrast == "merge-ref":
        for pipeline in (data["pipeline"], data["mr_pipeline"], data["job"]["pipeline"]):
            pipeline["ref"] = "refs/merge-requests/9/merge"
    elif contrast == "advanced-head":
        data["mr"]["sha"] = BASE
    elif contrast == "job-checkout":
        data["job"]["commit"]["id"] = BASE
    elif contrast == "fork-file":
        data["source_file"]["url"] = data["source_file"]["url"].replace("projects/2", "projects/1")
    elif contrast == "job-url":
        data["job"]["web_url"] = data["job"]["web_url"].replace("team/repo", "team/fork")
    elif contrast == "no-receipt":
        del data["log"]["rows"][6]
    elif contrast in ("wrong-phase", "different-upload-job"):
        rows = data["log"]["rows"]
        indices = (5, 7) if contrast == "wrong-phase" else (6,)
        for index in indices:
            row = rows[index]
            value = row["value"].replace("on_success", "on_failure").replace("id=33", "id=34")
            rows[index] = _failure_trace_row(row["time"], value)
    elif contrast == "unsupported-profile":
        data["pages_preview"] = {}
    result = _evaluate_fork(tmp_path, data, selected)
    if contrast is None:
        assert result["state"] == "target-project-head-archive-upload-observed"
        assert (result["source_project"], result["project"], result["target_project"]) == (2, 1, 1)
        assert result["job_name"] == "Build documentation"
        assert result["publication"]["target"] == "https://gitlab.com/team/repo/-/jobs/33/artifacts/download"
        assert result["publication"]["retrieval"] == "unverified"
    else:
        assert result["state"] == "unresolved"
        assert "publication" not in result


@pytest.mark.parametrize(
    "contrast",
    [
        None,
        "owner-case",
        "phase",
        "failure-reason",
        "status",
        "wrong-receipt",
        "missing-archive",
        "success-stdout",
    ],
)
def test_target_head_failure_binds_own_archive_and_preserves_job_result(
    tmp_path, target_head_upload, contrast
):
    # Keep the case used by the provider in every identity field.
    data = json.loads(json.dumps(target_head_upload).replace("team/repo", "Team/Repo"))
    pipeline, job = data["pipeline"], data["job"]
    for item in (pipeline, job["pipeline"], data["mr_pipeline"], job):
        item["status"] = "failed"
    job["failure_reason"] = "script_failure"
    rows = data["log"]["rows"]
    for i in (5, 7):
        item = rows[i]
        rows[i] = _failure_trace_row(
            item["time"], item["value"].replace("on_success", "on_failure")
        )
    rows[6] = _failure_trace_row(rows[6]["time"], rows[6]["value"].replace("01E ", "01O "))
    if contrast == "owner-case":
        data["target"]["web_url"] = data["target"]["web_url"].lower()
    elif contrast == "phase":
        for i in (5, 7):
            item = rows[i]
            rows[i] = _failure_trace_row(
                item["time"], item["value"].replace("on_failure", "on_success")
            )
    elif contrast == "failure-reason":
        job["failure_reason"] = "runner_system_failure"
    elif contrast == "status":
        pipeline["status"] = "success"
    elif contrast == "wrong-receipt":
        rows[6] = _failure_trace_row(rows[6]["time"], rows[6]["value"].replace("id=33", "id=34"))
    elif contrast == "missing-archive":
        job["artifacts"] = [item for item in job["artifacts"] if item["file_type"] != "archive"]
    elif contrast == "success-stdout":
        for item in (pipeline, job["pipeline"], data["mr_pipeline"], job):
            item["status"] = "success"
        job["failure_reason"] = None
        for i in (5, 7):
            item = rows[i]
            rows[i] = _failure_trace_row(
                item["time"], item["value"].replace("on_failure", "on_success")
            )
    result = _evaluate_fork(tmp_path, data, 1)
    if contrast is None:
        assert result["state"] == "target-project-head-archive-upload-observed"
        assert result["repository"] == "Team/Repo"
        assert result["job_status"] == "failed"
        assert result["upload_phase"] == "upload_artifacts_on_failure"
        assert result["publication"]["http_status"] == 201
        assert result["publication"]["retrieval"] == "unverified"
        assert "archive_runner_authority" not in result
    else:
        assert result["state"] == "unresolved"
        assert "publication" not in result


@pytest.mark.parametrize(
    "contrast",
    [None, "wrong-job", "wrong-url", "stale", "denied", "float-status", "digest", "duplicate", "other-member"],
)
def test_target_archive_tree_qualifies_named_member(tmp_path, target_head_upload, contrast):
    data = target_head_upload
    entry = {"name": "build.zip", "path": "build.zip", "type": "file", "size": 25}
    body = json.dumps([entry, entry] if contrast == "duplicate" else [entry]).encode()
    (tmp_path / "archive-tree.json").write_bytes(body)
    tree = {
        "project": 1,
        "job": 33,
        "member": "build.zip",
        "url": "https://gitlab.com/api/v4/projects/1/jobs/33/artifacts/tree",
        "status": 200,
        "observed_at": data["job"]["finished_at"],
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    data["archive_tree"] = tree
    if contrast == "wrong-job":
        tree["job"] = 34
    elif contrast == "wrong-url":
        tree["url"] += "?path=other"
    elif contrast == "stale":
        tree["observed_at"] = data["job"]["started_at"]
    elif contrast == "denied":
        tree["status"] = 403
    elif contrast == "float-status":
        tree["status"] = 200.0
    elif contrast == "digest":
        tree["sha256"] = hashlib.sha256(b"foreign").hexdigest()
    elif contrast == "other-member":
        tree["member"] = "other.zip"
    result = _evaluate_fork(tmp_path, data, 1)
    assert result["state"] == "target-project-head-archive-upload-observed"
    assert result["publication"]["retrieval"] == "unverified"
    if contrast is None:
        assert result["archive_tree"]["state"] == "archive-member-listed"
        assert result["archive_tree"]["member"] == "build.zip"
        assert result["archive_tree"]["member_bytes"] == 25
    else:
        assert result["archive_tree"]["state"] == "unresolved"


@pytest.mark.parametrize(
    "contrast", [None, "omitted", "other-job", "earlier-banner", "wrong-digest"]
)
def test_target_archive_helper_binds_reported_windows_banner(
    tmp_path, target_head_upload, contrast
):
    data = target_head_upload
    log = data["log"]
    for index, row in enumerate(log["rows"], 1):
        row["line"] = 10 * index
    start, response, _ = log["rows"][-3:]
    data["job"]["runner_manager"] = {"revision": "d22d8753"}
    data["job"]["runner"] = {
        "is_shared": True,
        "description": "k8s.saas-windows-medium-amd64.runners-manager.gitlab.com",
    }
    banner = [
        {
            **_failure_trace_row(start["time"], value),
            "line": start["line"] + index,
        }
        for index, value in enumerate(
            (
                "01O Version:      19.3.0",
                "01O Git revision: 9cbf0074",
                "01O OS/Arch:      windows/amd64",
            ),
            1,
        )
    ]
    helper = {
        "job": 33,
        "trace_url": log["url"],
        "trace_sha256": log["sha256"],
        "executor": "custom",
        "banner": banner,
    }
    if contrast != "omitted":
        data["archive_windows_helper"] = helper
    if contrast == "other-job":
        helper["job"] = 34
    elif contrast == "earlier-banner":
        banner[0]["line"] = start["line"] - 1
    elif contrast == "wrong-digest":
        banner[1]["sha256"] = "0" * 64

    result = _evaluate_fork(tmp_path, data, 1)
    assert result["state"] == "target-project-head-archive-upload-observed"
    assert result["publication"]["http_status"] == 201
    assert "archive_runner_authority" not in result
    if contrast == "omitted":
        assert "archive_windows_helper" not in result
    elif contrast is None:
        observed = result["archive_windows_helper"]
        assert observed["state"] == "windows-helper-version-reported"
        assert observed["version"] == "19.3.0"
        assert observed["archive_response_line"] == response["line"]
    else:
        assert result["archive_windows_helper"]["state"] == "unresolved"


@pytest.mark.parametrize("bad_download", [False, True])
def test_target_head_archive_download_preserves_upload_when_zip_fails(
    tmp_path, target_head_upload, bad_download, monkeypatch, capsys
):
    data = target_head_upload
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("docs/index.html", "documentation")
    content = buffer.getvalue()
    (tmp_path / "published-archive.zip").write_bytes(content)
    job = data["job"]
    next(item for item in job["artifacts"] if item["file_type"] == "archive")["size"] = len(content)
    data["archive_download"] = {
        "job": 33,
        "url": job["web_url"] + "/artifacts/download",
        "observed_at": job["finished_at"],
        "responses": [{"status": 200, "host": "gitlab.com"}],
        "bytes": len(content),
        "sha256": "f" * 64 if bad_download else hashlib.sha256(content).hexdigest(),
    }
    _evaluate_fork(tmp_path, data, 1)
    monkeypatch.setattr(
        sys, "argv",
        ["taintly", str(tmp_path), "--format", "json", "--no-config",
         "--gitlab-mr-artifact-observation", str(tmp_path / "observation.json"), "1", "22", "33"],
    )
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    report = json.loads(capsys.readouterr().out)["gitlab_mr_artifact_observation"]
    assert report["state"] == "target-project-head-archive-upload-observed"
    assert report["publication"]["http_status"] == 201
    if bad_download:
        assert exit_info.value.code == 11
        assert report["publication"]["retrieval"] == "unverified"
        assert report["archive_download"]["state"] == "unresolved"
    else:
        assert exit_info.value.code == 0
        assert report["publication"]["retrieval"] == "verified"
        assert report["archive_download"]["state"] == "target-project-archive-retrieved"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (None, None),
        ("checkout_directory", "/builds/team/fork"),
        ("trace_sha256", "f" * 64),
        ("correlation_id", "f" * 32),
        ("runner_revision", "c" * 40),
        ("helper_config", "sha256:" + "f" * 64),
        ("archive_line", 5),
    ],
)
def test_target_head_archive_keeps_accepted_upload_when_runner_evidence_disagrees(
    tmp_path, target_head_upload, field, value, monkeypatch, capsys
):
    data = target_head_upload
    log = data["log"]
    for number, row in enumerate(log["rows"], start=3):
        row["line"] = number
    start, reply, end = log["rows"][-3:]
    runner = _runner_archive_evidence()
    runner.update(
        revision=HEAD, trace_sha256=log["sha256"],
        archive_start_line=start["line"], archive_line=reply["line"], archive_end_line=end["line"],
        archive_start_time=start["time"], archive_time=reply["time"], archive_end_time=end["time"],
        correlation_id=reply["value"].split("correlation_id=")[1].split()[0],
    )
    if field is not None:
        runner[field] = value
    data["archive_runner_evidence"] = runner
    _evaluate_fork(tmp_path, data, 1)
    monkeypatch.setattr(
        sys, "argv",
        ["taintly", str(tmp_path), "--format", "json", "--no-config",
         "--gitlab-mr-artifact-observation", str(tmp_path / "observation.json"), "1", "22", "33"],
    )
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    report = json.loads(capsys.readouterr().out)["gitlab_mr_artifact_observation"]
    assert report["state"] == "target-project-head-archive-upload-observed"
    assert report["publication"]["http_status"] == 201
    authority = report["archive_runner_authority"]
    if field is None:
        assert exit_info.value.code == 0
        assert authority["credential"] == "runner-job-token"
        assert authority["checkout_directory"] == "/builds/team/repo"
        assert authority["route"] == "jobs/33/artifacts"
    else:
        assert exit_info.value.code == 11
        assert authority["state"] == "unresolved"
        assert "credential" not in authority


@pytest.mark.parametrize(
    "contrast",
    [
        None, "alternate-origin", "wrong-project", "wrong-checkout", "missing-source",
        "wrong-source-commit", "wrong-job", "wrong-phase", "denied", "unsupported-runner",
        "unknown-format", "null-format", "ordered-tie", "missing-line", "duplicate-line",
        "reversed-line", "tied-response", "allowed-failure", "missing-allow-failure",
        "allowed-failure-parent-mismatch", "allowed-failure-wrong-phase",
    ],
)
def test_explicit_origin_binds_failed_fork_archive(tmp_path, fork_upload, contrast):
    origin = "https://ci.example.org"
    data = json.loads(json.dumps(fork_upload).replace("https://gitlab.com", origin))
    data["pipeline"]["status"] = data["job"]["pipeline"]["status"] = "failed"
    data["job"]["commit"] = {"id": HEAD}
    source = BUILDSPEC.encode()
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    data["source_sha256"] = hashlib.sha256(source).hexdigest()
    data["source_file"] = {
        "url": f"{origin}/api/v4/projects/2/repository/files/.gitlab-ci.yml?ref={HEAD}",
        "file_path": ".gitlab-ci.yml",
        "commit_id": HEAD,
        "content_sha256": data["source_sha256"],
    }
    rows = data["log"]["rows"]
    response = rows[6]
    value = re.sub(r"correlation_id=\S+", "correlation_id=" + "0" * 26, response["value"])
    rows[6] = _failure_trace_row(response["time"], value)
    selected_project = 2
    if contrast in {
        "allowed-failure", "missing-allow-failure",
        "allowed-failure-parent-mismatch", "allowed-failure-wrong-phase",
    }:
        data["pipeline"]["status"] = data["mr_pipeline"]["status"] = "success"
        if contrast != "allowed-failure-parent-mismatch":
            data["job"]["pipeline"]["status"] = "success"
        if contrast != "missing-allow-failure":
            data["job"]["allow_failure"] = True
    if contrast == "alternate-origin":
        origin = "https://other.example.org"
    elif contrast == "wrong-project":
        selected_project = 1
    elif contrast == "wrong-checkout":
        data["job"]["commit"]["id"] = BASE
    elif contrast == "missing-source":
        del data["source_file"]
    elif contrast == "wrong-source-commit":
        data["source_file"]["commit_id"] = BASE
    elif contrast == "wrong-job":
        rows[6] = _failure_trace_row(response["time"], value.replace("id=33", "id=34"))
    elif contrast in {"wrong-phase", "allowed-failure-wrong-phase"}:
        for index in (5, 7):
            row = rows[index]
            rows[index] = _failure_trace_row(
                row["time"], row["value"].replace("on_failure", "on_success")
            )
    elif contrast == "denied":
        denied = value.replace("201 Created", "403 Forbidden").replace("status=201", "status=403")
        rows[6] = _failure_trace_row(response["time"], denied)
    elif contrast == "unsupported-runner":
        data["archive_runner_evidence"] = {}
    elif contrast in {"unknown-format", "null-format"}:
        data["log"]["rows_format"] = "future-format" if contrast == "unknown-format" else None
    elif contrast in {"ordered-tie", "missing-line", "duplicate-line", "reversed-line", "tied-response"}:
        stamp = rows[4]["time"]
        epoch = int(datetime.fromisoformat(stamp).timestamp())
        boundary = re.sub(r"section_start:\d+:", f"section_start:{epoch}:", rows[5]["value"])
        rows[5] = _failure_trace_row(stamp, boundary)
        if contrast == "tied-response":
            rows[6] = _failure_trace_row(stamp, rows[6]["value"])
        for number, row in enumerate(rows, 1):
            row["line"] = number
        if contrast == "missing-line":
            del rows[5]["line"]
        elif contrast == "duplicate-line":
            rows[5]["line"] = rows[4]["line"]
        elif contrast == "reversed-line":
            rows[4]["line"], rows[5]["line"] = rows[5]["line"], rows[4]["line"]
    packet = tmp_path / "observation.json"
    packet.write_text(json.dumps(data), encoding="utf-8")
    result = mr_artifact_observation(packet, tmp_path, selected_project, 22, 33, origin=origin)
    if contrast not in {None, "ordered-tie", "allowed-failure"}:
        assert result["state"] == "unresolved"
        assert "publication" not in result
        return
    assert result["state"] == "fork-project-archive-upload-observed"
    assert (result["project"], result["target_project"]) == (2, 1)
    assert result["job_status"] == "failed"
    assert result["upload_phase"] == "upload_artifacts_on_failure"
    assert result["origin"] == origin
    assert result["publication"]["http_status"] == 201
    assert result["publication"]["retrieval"] == "unverified"
    assert "archive_runner_authority" not in result
    if contrast == "allowed-failure":
        assert result["pipeline_status"] == "success"
        assert result["job_allow_failure"] is True


@pytest.mark.parametrize(
    "contrast", [None, "withheld", "other-runner", "other-commit", "missing-source", "other-banner"]
)
def test_fork_windows_stdout_archive_is_bound_to_the_exact_job(
    tmp_path, fork_upload, contrast
):
    data = fork_upload
    job, log = data["job"], data["log"]
    job.update(status="success", failure_reason=None, commit={"id": HEAD})
    job["runner_manager"] = {"revision": "d22d8753"}
    job["runner"] = {
        "is_shared": True,
        "description": "k8s.saas-windows-medium-amd64.runners-manager.gitlab.com",
    }
    for index, row in enumerate(log["rows"], 1):
        value = row["value"].replace("upload_artifacts_on_failure", "upload_artifacts_on_success")
        if index == 7:
            value = value.replace("01E ", "01O ", 1)
        row.update(_failure_trace_row(row["time"], value), line=10 * index)
    start, response, _ = log["rows"][-3:]
    data["source_file"] = {
        "url": f"https://gitlab.com/api/v4/projects/2/repository/files/.gitlab-ci.yml?ref={HEAD}",
        "file_path": ".gitlab-ci.yml",
        "commit_id": HEAD,
        "content_sha256": hashlib.sha256(BUILDSPEC.encode()).hexdigest(),
    }
    helper = {
        "job": 33,
        "trace_url": log["url"],
        "trace_sha256": log["sha256"],
        "executor": "custom",
        "banner": [
            {
                **_failure_trace_row(start["time"], value),
                "line": start["line"] + offset,
            }
            for offset, value in enumerate(
                (
                    "01O Version:      19.3.0",
                    "01O Git revision: 9cbf0074",
                    "01O OS/Arch:      windows/amd64",
                ),
                1,
            )
        ],
    }
    if contrast != "withheld":
        data["archive_windows_helper"] = helper
    if contrast == "other-runner":
        job["runner"]["is_shared"] = False
    elif contrast == "other-commit":
        job["commit"]["id"] = BASE
    elif contrast == "missing-source":
        data.pop("source_file")
    elif contrast == "other-banner":
        helper["job"] = 34

    result = _evaluate_fork(tmp_path, data)
    if contrast in {"other-runner", "other-commit", "missing-source"}:
        assert result["state"] == "unresolved"
        assert "publication" not in result
        return

    assert result["state"] == "fork-project-archive-upload-observed"
    assert result["project"] == 2
    assert result["target_project"] == 1
    assert result["publication"]["http_status"] == 201
    if contrast == "withheld":
        assert "archive_windows_helper" not in result
    elif contrast == "other-banner":
        assert result["archive_windows_helper"]["state"] == "unresolved"
    else:
        observed = result["archive_windows_helper"]
        assert observed["state"] == "windows-helper-version-reported"
        assert observed["archive_response_line"] == response["line"]


@pytest.mark.parametrize(
    "contrast", [None, "other-job", "basename-only", "wrong-directory", "unrelated-entry"]
)
def test_fork_archive_listing_identifies_the_selected_file_in_its_directory(
    tmp_path, fork_upload, contrast
):
    member = "build/package.zip"
    entries = [{"name": "package.zip", "path": member, "type": "file", "size": 124}]
    if contrast == "unrelated-entry":
        entries[0]["path"] = "dist/package.zip"
    raw = json.dumps(entries).encode()
    (tmp_path / "archive-tree.json").write_bytes(raw)
    receipt = {
        "project": 2,
        "job": 33,
        "url": "https://gitlab.com/api/v4/projects/2/jobs/33/artifacts/tree?path=build",
        "status": 200,
        "observed_at": fork_upload["job"]["finished_at"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "member": member,
    }
    if contrast == "other-job":
        receipt["job"] = 34
        receipt["url"] = receipt["url"].replace("/33/", "/34/")
    elif contrast == "basename-only":
        receipt["member"] = "package.zip"
    elif contrast == "wrong-directory":
        receipt["member"] = "dist/package.zip"
    fork_upload["archive_tree"] = receipt

    result = _evaluate_fork(tmp_path, fork_upload)
    assert result["state"] == "fork-project-archive-upload-observed"
    assert result["publication"]["http_status"] == 201
    tree = result["archive_tree"]
    if contrast is None:
        assert tree["state"] == "archive-member-listed"
        assert tree["member"] == member
        assert tree["member_bytes"] == 124
    else:
        assert tree["state"] == "unresolved"
