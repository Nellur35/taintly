import hashlib
import json
from pathlib import Path

import pytest

from taintly.__main__ import main
from taintly.ingestion.gitlab_ref_publication import ref_observation

REVISION = "a" * 40
OLD = "b" * 40
URL = "https://gitlab.com/example/builds"
COMMON = ".gitlab/ci_templates/cki-common.yml"
TEMPLATE = ".gitlab/ci_templates/cki-templates.yml"


def _source(root, filename, contents, *, path=None, revision=REVISION):
    raw = contents.encode("utf-8")
    (root / filename).write_bytes(raw)
    return {
        "repository": "example/builds",
        "commit_id": revision,
        "file_path": path or filename,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.fixture
def receipt(tmp_path):
    root = _source(
        tmp_path,
        ".gitlab-ci.yml",
        f"---\ninclude:\n  - local: {COMMON}\ndeploy-production:\n"
        "  extends: .deploy_production_tag\n",
    )
    common = _source(
        tmp_path,
        "cki-common.yml",
        f"include:\n  - local: {TEMPLATE}\n"
        '    rules: [{if: ($CI_SERVER_URL == "https://gitlab.com")}]\n'
        f"  - remote: {URL}/-/raw/production/{TEMPLATE}\n"
        '    rules: [{if: ($CI_SERVER_URL != "https://gitlab.com")}]\n',
        path=COMMON,
    )
    template = _source(
        tmp_path,
        "cki-templates.yml",
        """.deploy_production:
  extends: .deploy
  variables:
    DEPLOY_TAG: production
.deploy_tag:
  script:
    - if [[ ${CI_COMMIT_BRANCH:-} != production ]]; then
        git push --force --no-verify
        "https://git:${GITLAB_JOB_DEPLOY_PRODUCTION_ACCESS_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git"
        "HEAD:refs/heads/${DEPLOY_TAG}";
      fi
.deploy_production_tag:
  extends: [.deploy_production, .deploy_tag]
""",
        path=TEMPLATE,
    )
    return {
        "schema": "gitlab-production-ref-v1",
        "repository": "example/builds",
        "pipeline": {
            "id": 51,
            "project_id": 21,
            "sha": REVISION,
            "ref": "main",
            "source": "push",
            "created_at": "2026-08-13T11:00:00Z",
            "web_url": f"{URL}/-/pipelines/51",
        },
        "job": {
            "id": 101,
            "project_id": 21,
            "pipeline_id": 51,
            "revision": REVISION,
            "ref": "main",
            "name": "deploy-production",
            "web_url": f"{URL}/-/jobs/101",
            "status": "success",
            "started_at": "2026-08-13T11:01:00Z",
            "finished_at": "2026-08-13T11:02:00Z",
        },
        "trace": {
            "url": f"{URL}/-/jobs/101/raw",
            "sha256": "c" * 64,
            "checkout": {"line": 2, "revision_prefix": REVISION[:8], "ref": "main"},
            "write": {
                "line": 4,
                "branch": "production",
                "before_prefix": OLD[:8],
                "after_prefix": REVISION[:8],
            },
            "step_start": 3,
            "step_end": 5,
        },
        "ref_event": {
            "id": 301,
            "project_id": 21,
            "author_id": 77,
            "created_at": "2026-08-13T11:01:30Z",
            "push": {
                "action": "pushed",
                "ref_type": "branch",
                "ref": "production",
                "commit_from": OLD,
                "commit_to": REVISION,
            },
        },
        "policy": {
            "url": "https://gitlab.com/api/v4/projects/21/protected_branches/production",
            "rule": {"id": 401, "name": "production", "inherited": False},
            "read_at": "2026-08-14T11:00:00Z",
            "push_entries": [
                {
                    "id": 501,
                    "user_id": 78,
                    "group_id": None,
                    "deploy_key_id": None,
                    "label": "publisher",
                },
                {
                    "id": 502,
                    "user_id": 77,
                    "group_id": None,
                    "deploy_key_id": None,
                    "label": "publisher",
                },
            ],
        },
        "source": root,
        "shared_common": common,
        "historical_template": template,
    }


def _save(root, receipt):
    path = root / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def _observe(root, receipt, job=101):
    return ref_observation(_save(root, receipt), root, 21, 51, job)


def test_local_include_follows_the_containing_revision(tmp_path, receipt):
    result = _observe(tmp_path, receipt)
    assert result["state"] == "production-ref-update-observed"
    assert result["actor"] == 77
    assert result["current_rule"]["entry"] == 502
    assert result["source"]["template_revision"] == REVISION


def test_cross_project_include_has_its_own_revision(tmp_path, receipt):
    receipt["source"] = _source(
        tmp_path,
        ".gitlab-ci.yml",
        f"include:\n  - project: example/shared\n    file: {COMMON}\n"
        "    ref: production\ndeploy-production:\n  extends: .deploy_production_tag\n",
    )
    for key in ("shared_common", "historical_template"):
        receipt[key].update(repository="example/shared", commit_id=OLD)
    result = _observe(tmp_path, receipt)
    assert result["state"] == "production-ref-update-observed"
    assert result["source"]["template_repository"] == "example/shared"
    assert result["source"]["template_revision"] == OLD


def test_remote_template_for_other_instance_cannot_supply_the_source(tmp_path, receipt):
    receipt["historical_template"]["commit_id"] = OLD
    result = _observe(tmp_path, receipt)
    assert result["state"] == "unresolved"
    assert "containing file project and revision" in result["reason"]


def test_duplicate_deployment_owner_is_unresolved(tmp_path, receipt):
    original = (tmp_path / ".gitlab-ci.yml").read_text(encoding="utf-8")
    receipt["source"] = _source(tmp_path, ".gitlab-ci.yml", original + "deploy-production: {}\n")
    assert _observe(tmp_path, receipt)["state"] == "unresolved"


def test_remote_only_shared_configuration_is_unresolved(tmp_path, receipt):
    common = (tmp_path / "cki-common.yml").read_text(encoding="utf-8")
    receipt["shared_common"] = _source(
        tmp_path,
        "cki-common.yml",
        "include:\n" + common.splitlines(keepends=True)[3] + common.splitlines(keepends=True)[4],
        path=COMMON,
    )
    assert _observe(tmp_path, receipt)["state"] == "unresolved"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("same-tag", "tag"),
        ("pipeline-time", "2026-08-13T12:00:00Z"),
        ("trace-owner", f"{URL}/-/jobs/102/raw"),
        ("different-job", 102),
        ("same-hash", "1" * 64),
        ("event-project", 91),
        ("unsupported-event", "schedule"),
    ],
)
def test_unrelated_evidence_cannot_establish_a_write(tmp_path, receipt, field, value):
    if field == "same-tag":
        receipt["ref_event"]["push"]["ref_type"] = value
    elif field == "pipeline-time":
        receipt["pipeline"]["created_at"] = value
    elif field == "trace-owner":
        receipt["trace"]["url"] = value
    elif field == "same-hash":
        receipt["source"]["content_sha256"] = value
    elif field == "event-project":
        receipt["ref_event"]["project_id"] = value
    elif field == "unsupported-event":
        receipt["pipeline"]["source"] = value
    result = _observe(tmp_path, receipt, job=value if field == "different-job" else 101)
    assert result["state"] == "unresolved"
    assert "actor" not in result


def _fork(receipt, status):
    ref = "refs/merge-requests/3/merge"
    receipt["pipeline"].update(ref=ref, source="merge_request_event")
    receipt["job"].update(ref=ref, status=status, started_at=None, finished_at=None, runner_id=None)
    receipt["trace"].update(bytes=0, sha256=hashlib.sha256(b"").hexdigest())
    receipt.pop("ref_event")
    receipt["mr"] = {"iid": 3, "target_project_id": 21, "source_project_id": 22, "source_head": OLD}
    receipt["mr_pipeline"] = {k: receipt["pipeline"][k] for k in ("id", "project_id", "sha", "ref")}
    receipt["checkout_parents"] = ["d" * 40, OLD]


@pytest.mark.parametrize("status", ["manual", "skipped"])
def test_fork_job_observed_unstarted_without_a_permission_decision(tmp_path, receipt, status):
    _fork(receipt, status)
    result = _observe(tmp_path, receipt)
    assert result["state"] == "fork-publisher-not-started"
    assert result["job_status"] == status
    assert result["publication"] == "not-reached"
    assert "actor" not in result


def test_missing_fork_ownership_evidence_stays_unresolved(tmp_path, receipt):
    _fork(receipt, "manual")
    receipt["mr_pipeline"]["id"] = 52
    assert _observe(tmp_path, receipt)["state"] == "unresolved"


def test_assigned_runner_cannot_be_reported_as_unstarted(tmp_path, receipt):
    _fork(receipt, "manual")
    receipt["job"]["runner_id"] = 42
    assert _observe(tmp_path, receipt)["state"] == "unresolved"


@pytest.mark.parametrize("kind", ["json", "text"])
def test_cli_preserves_observed_write_with_unresolved_rule(
    tmp_path, receipt, monkeypatch, capsys, kind
):
    receipt["policy"]["url"] = "https://gitlab.com/api/v4/projects/91/protected_branches/production"
    fixture = _save(tmp_path, receipt)
    monkeypatch.setattr(
        "sys.argv",
        [
            "taintly",
            str(tmp_path),
            "--gitlab-ref-observation",
            str(fixture),
            "21",
            "51",
            "101",
            "--format",
            kind,
            "--no-config",
        ],
    )
    with pytest.raises(SystemExit) as result:
        main()
    output = capsys.readouterr()
    assert result.value.code == 11
    assert "77" in output.out and "unresolved" in output.out
    assert output.err == ""
