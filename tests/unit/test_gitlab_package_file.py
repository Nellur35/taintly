import copy
import hashlib
import json
from pathlib import Path

import pytest

from taintly.ingestion.gitlab_package_file import package_file_observation

_PROJECT_URL = "https://gitlab.com/api/v4/projects/1"
_PACKAGE_URL = f"{_PROJECT_URL}/packages/3"
_PIPELINE_URL = f"{_PROJECT_URL}/pipelines/2"
_REF_URL = "https://gitlab.com/example/project/-/pipelines/"
_REVISION = "a" * 40
_SOURCE = b"build:\n  script: echo marker\n"


@pytest.fixture()
def receipt(tmp_path):
    def response(url, row):
        return {"url": url, "status": 200, "row": row}

    pipeline = {
        "id": 2,
        "project_id": 1,
        "sha": _REVISION,
        "ref": "main",
        "source": "push",
        "web_url": f"{_REF_URL}2",
        "status": "failed",
    }
    package = {"id": 3, "name": "build", "version": "v1", "package_type": "generic"}
    file = {
        "id": 4,
        "package_id": 3,
        "file_name": "marker.txt",
        "file_sha256": "b" * 64,
        "created_at": "2026-11-23T00:00:00Z",
        "pipelines": [dict(pipeline, status="running")],
    }
    (tmp_path / ".gitlab-ci.yml").write_bytes(_SOURCE)
    return {
        "schema": "gitlab-package-file-v1",
        "project": response(_PROJECT_URL, {"id": 1, "path_with_namespace": "example/project"}),
        "pipeline": response(_PIPELINE_URL, pipeline),
        "package": response(_PACKAGE_URL, package),
        "files": {
            "url": f"{_PACKAGE_URL}/package_files?per_page=100",
            "status": 200,
            "rows": [file],
        },
        "source": {
            "url": f"{_PROJECT_URL}/repository/files/.gitlab-ci.yml/raw?ref={_REVISION}",
            "status": 200,
            "sha256": hashlib.sha256(_SOURCE).hexdigest(),
        },
    }


def _observation(tmp_path, receipt):
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return package_file_observation(path, tmp_path, 1, 2, 3, 4)


def test_file_provenance_matches_identity_across_pipeline_status_changes(tmp_path, receipt):
    report = _observation(tmp_path, receipt)
    assert report["state"] == "file-pipeline-confirmed"
    assert report["selected_pipeline"] == report["recorded_pipeline"]
    assert report["file"]["provider_sha256"] == "b" * 64
    assert report["request_authority"] == "unresolved"


def test_same_revision_cannot_assign_file_to_a_different_run(tmp_path, receipt):
    owner = receipt["files"]["rows"][0]["pipelines"][0]
    owner.update(id=5, web_url=f"{_REF_URL}5", source="merge_request_event")
    report = _observation(tmp_path, receipt)
    assert report["state"] == "file-pipeline-differs"
    assert report["selected_pipeline"]["id"] == 2
    assert report["recorded_pipeline"]["id"] == 5
    assert report["recorded_pipeline"]["revision"] == report["selected_pipeline"]["revision"]


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("wrong-source", "source bytes differ"),
        ("wrong-file-list-url", "different endpoint"),
        ("wrong-package", "file belongs to another package"),
        ("owner-omitted", "no unique recorded pipeline"),
        ("ambiguous-owner", "no unique recorded pipeline"),
        ("duplicate-file", "file is missing or ambiguous"),
        ("conflicting-revision", "conflicts with the exact pipeline"),
        ("other-project", "belongs to another project"),
        ("source-with-control-character", "pipeline ref is missing or malformed"),
    ],
)
def test_unresolved_keeps_unbound_output_out_of_report(tmp_path, receipt, defect, reason):
    row = receipt["files"]["rows"][0]
    if defect == "wrong-source":
        (tmp_path / ".gitlab-ci.yml").write_bytes(_SOURCE + b"\n")
    elif defect == "wrong-file-list-url":
        receipt["files"]["url"] = f"{_PACKAGE_URL}/pipelines"
    elif defect == "wrong-package":
        row["package_id"] = 8
    elif defect == "owner-omitted":
        row.pop("pipelines")
    elif defect == "ambiguous-owner":
        row["pipelines"].append(dict(row["pipelines"][0], id=8))
    elif defect == "duplicate-file":
        receipt["files"]["rows"].append(copy.deepcopy(row))
    elif defect == "conflicting-revision":
        row["pipelines"][0]["sha"] = "c" * 40
    elif defect == "other-project":
        row["pipelines"][0]["project_id"] = 8
    elif defect == "source-with-control-character":
        row["pipelines"][0]["ref"] = "\x1b[31m"
    report = _observation(tmp_path, receipt)
    assert report["state"] == "unresolved"
    assert reason in report["reason"]
    assert "recorded_pipeline" not in report
    assert "file" not in report


@pytest.fixture()
def upload_receipt(tmp_path, receipt):
    source = b"""build:
  script:
    - |
      curl -v --header "JOB-TOKEN: $CI_JOB_TOKEN" \\
      --upload-file marker.txt \\
      "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/build/v1/marker.txt"
"""
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    receipt["source"]["sha256"] = hashlib.sha256(source).hexdigest()
    first_line = source.splitlines()[3].strip()[:-1].strip()
    timestamp = 1795392000
    receipt["files"]["rows"][0]["created_at"] = "2026-11-23T00:00:00.500Z"
    job_url = "https://gitlab.com/example/project/-/jobs/5"
    receipt["upload"] = {
        "jobs": {
            "url": f"{_PROJECT_URL}/pipelines/2/jobs?include_retried=true&per_page=100",
            "status": 200,
            "row": {
                "id": 5,
                "name": "build",
                "web_url": job_url,
                "ref": "main",
                "revision": _REVISION,
                "pipeline": {"id": 2, "project_id": 1, "ref": "main", "sha": _REVISION},
                "started_at": "2026-11-22T23:59:57Z",
                "finished_at": "2026-11-23T00:00:08Z",
            },
        },
        "trace": {
            "url": f"{job_url}/raw",
            "status": 200,
            "sha256": "c" * 64,
            "checkout": {"line": 8, "revision_prefix": _REVISION[:8]},
            "command": {"line": 11, "known_command_sha256": hashlib.sha256(first_line).hexdigest()},
            "script": {
                "start": {"line": 10, "epoch": timestamp - 1},
                "end": {"line": 24, "epoch": timestamp + 2},
                "command_lines": [11, 23],
                "events": [
                    {"line": 12, "kind": "tls", "value": True},
                    {"line": 13, "kind": "connected", "value": "gitlab.com:443"},
                    {
                        "line": 14,
                        "kind": "request",
                        "value": {
                            "method": "PUT",
                            "path": "/api/v4/projects/1/packages/generic/build/v1/marker.txt",
                            "protocol": "2",
                        },
                    },
                    {"line": 16, "kind": "host", "value": "gitlab.com"},
                    {"line": 17, "kind": "masked_header", "value": "JOB-TOKEN"},
                    {"line": 18, "kind": "response", "value": {"status": 201, "protocol": "2"}},
                    {"line": 19, "kind": "response_request_id", "value": "d" * 32},
                ],
            },
        },
    }
    return receipt


def test_upload_attaches_request_without_asserting_server_authority(tmp_path, upload_receipt):
    report = _observation(tmp_path, upload_receipt)
    assert report["state"] == "file-pipeline-confirmed"
    assert report["upload"]["state"] == "trace-request-observed"
    assert report["upload"]["job"] == 5
    assert report["upload"]["source_line"] == 4
    assert report["upload"]["request_id"] == "d" * 32
    assert report["upload"]["response_status"] == 201
    assert report["request_authority"] == "unresolved"


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("wrong-job", "another job"),
        ("different-request", "exact registered file"),
        ("different-credential-header", "exact registered file"),
        ("later-archive-response", "crosses the selected command"),
        ("intervening-response", "incomplete or ambiguous"),
        ("different-revision", "does not precede"),
        ("unbound-command", "no unique matching verbose"),
        ("outside-file-window", "outside the selected job"),
        ("missing-script", "no exact package HTTP"),
    ],
)
def test_upload_never_borrows_a_different_request(tmp_path, upload_receipt, defect, reason):
    trace = upload_receipt["upload"]["trace"]
    events = trace["script"]["events"]
    if defect == "wrong-job":
        trace["url"] = trace["url"].replace("/5/raw", "/6/raw")
    elif defect == "different-request":
        events[2]["value"]["path"] = "/api/v4/projects/1/jobs/5/artifacts"
    elif defect == "different-credential-header":
        events[4]["value"] = "Authorization"
    elif defect == "later-archive-response":
        events[-1]["line"] = 31
    elif defect == "intervening-response":
        events.insert(
            4, {"line": 15, "kind": "response", "value": {"status": 201, "protocol": "2"}}
        )
    elif defect == "different-revision":
        trace["checkout"]["revision_prefix"] = "0" * 8
    elif defect == "unbound-command":
        trace["command"]["known_command_sha256"] = "0" * 64
    elif defect == "outside-file-window":
        upload_receipt["files"]["rows"][0]["created_at"] = "2026-11-23T00:00:04Z"
    elif defect == "missing-script":
        del trace["script"]
    report = _observation(tmp_path, upload_receipt)
    assert report["state"] == "file-pipeline-confirmed"
    assert report["upload"]["state"] == "unresolved"
    assert reason in report["upload"]["reason"]
    assert "job" not in report["upload"]
    assert report["request_authority"] == "unresolved"


@pytest.fixture()
def tagged_upload(tmp_path, upload_receipt):
    source = b"""variables:
  PACKAGE_FILE: marker.txt
  PACKAGE_URL: $CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/build/$CI_COMMIT_TAG/$PACKAGE_FILE

build release package:
  variables:
    GIT_STRATEGY: empty
  script:
    - |
      curl -v --fail-with-body --location --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \\
      --upload-file $PACKAGE_FILE \\
      $PACKAGE_URL
"""
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    upload_receipt["source"]["sha256"] = hashlib.sha256(source).hexdigest()
    upload_receipt["pipeline"]["row"]["ref"] = "v1"
    upload_receipt["files"]["rows"][0]["pipelines"][0]["ref"] = "v1"
    job = upload_receipt["upload"]["jobs"]["row"]
    job.update(name="build release package", ref="v1", tag=True)
    job["pipeline"]["ref"] = "v1"
    trace = upload_receipt["upload"]["trace"]
    del trace["checkout"]
    trace["empty_checkout"] = {
        "source_start_line": 3,
        "setup_skipped_line": 5,
        "checkout_skipped_line": 6,
        "source_end_line": 8,
    }
    command = source.splitlines()[9].strip().removesuffix(b"\\").rstrip()
    trace["command"]["known_command_sha256"] = hashlib.sha256(command).hexdigest()
    trace["script"]["events"][1].update(kind="authority", value="gitlab.com")
    trace["script"]["events"][-1]["value"] = "aaaaaaaaaaaaaaaa-ATL"
    return upload_receipt


def test_tagged_empty_runner_does_not_imply_package_content_checkout(tmp_path, tagged_upload):
    actual = _observation(tmp_path, tagged_upload)
    assert actual["state"] == "file-pipeline-confirmed"
    assert actual["upload"]["state"] == "trace-request-observed"
    assert actual["upload"]["runner_workspace"] == "checkout-skipped"
    assert actual["upload"]["package_content_ancestry"] == "unresolved"
    assert actual["request_authority"] == "unresolved"


@pytest.mark.parametrize(
    "contrast",
    ["not-a-tag", "wrong-source-phase", "other-variable-owner", "none-strategy", "other-peer"],
)
def test_tagged_upload_keeps_other_profiles_unresolved(tmp_path, tagged_upload, contrast):
    trace = tagged_upload["upload"]["trace"]
    if contrast == "not-a-tag":
        tagged_upload["upload"]["jobs"]["row"]["tag"] = False
    elif contrast == "wrong-source-phase":
        trace["empty_checkout"]["checkout_skipped_line"] = 17
    elif contrast in ("other-variable-owner", "none-strategy"):
        file = tmp_path / ".gitlab-ci.yml"
        data = file.read_bytes()
        strategy = b"GIT_STRATEGY: empty"
        altered = (
            b"GIT_STRATEGY: none"
            if contrast == "none-strategy"
            else strategy + b"\n    PACKAGE_URL: https://invalid.example/"
        )
        data = data.replace(strategy, altered)
        file.write_bytes(data)
        tagged_upload["source"]["sha256"] = hashlib.sha256(data).hexdigest()
    else:
        trace["script"]["events"][1]["value"] = "invalid.example"
    actual = _observation(tmp_path, tagged_upload)
    assert actual["state"] == "file-pipeline-confirmed"
    assert actual["upload"]["state"] == "unresolved"
    assert "job" not in actual["upload"]
    assert actual["request_authority"] == "unresolved"
