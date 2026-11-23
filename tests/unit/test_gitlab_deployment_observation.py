import json
from copy import deepcopy
from hashlib import sha256

import pytest

from taintly.ingestion.gitlab_deployment_observation import deployment_observation

REVISION = "a" * 40
SOURCE = b"""publish:
  extends: .deploy
.deploy:
  script: echo marker
  environment:
    name: pre-release
"""
BASE = "https://gitlab.com"
REPO = BASE + "/team/project"
API = BASE + "/api/v4/projects/10"


def packet(source=SOURCE):
    pipeline = {
        "id": 20,
        "project_id": 10,
        "source": "push",
        "sha": REVISION,
        "ref": "main",
        "web_url": REPO + "/-/pipelines/20",
        "status": "success",
        "created_at": "2026-11-01T09:00:00Z",
    }
    job = {
        "id": 30,
        "pipeline": pipeline,
        "name": "publish",
        "ref": "main",
        "commit": {"id": REVISION},
        "status": "manual",
        "runner_assigned": False,
        "web_url": REPO + "/-/jobs/30",
        "started_at": None,
        "finished_at": None,
    }
    deploy = {
        "id": 40,
        "sha": REVISION,
        "ref": "main",
        "status": "blocked",
        "deployable": job,
        "pending_approval_count": 0,
        "environment": {"id": 50, "name": "pre-release"},
    }
    project = {
        "id": 10,
        "path_with_namespace": "team/project",
        "web_url": REPO,
        "ci_config_path": None,
    }
    config = {
        "commit_id": REVISION,
        "file_path": ".gitlab-ci.yml",
        "content_sha256": sha256(source).hexdigest(),
    }
    records = {
        "project": ("", project),
        "pipeline": ("/pipelines/20", pipeline),
        "job": ("/jobs/30", job),
        "deployment": ("/deployments/40", deploy),
        "source": (f"/repository/files/.gitlab-ci.yml?ref={REVISION}", config),
    }
    return {
        "schema": "gitlab-environment-deployment-v1",
        **{
            key: {"url": API + url, "status": 200, "row": row}
            for key, (url, row) in records.items()
        },
    }


def observe(tmp_path, data, source=SOURCE):
    snapshot = tmp_path / "receipt.json"
    snapshot.write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / ".gitlab-ci.yml").write_bytes(source)
    return deployment_observation(snapshot, tmp_path, 10, 20, 30, 40)


def test_blocked_deployment_does_not_use_pipeline_success_or_infer_approval(tmp_path):
    data = packet()
    report = observe(tmp_path, data)
    assert report["state"] == "deployment-blocked-before-job"
    assert report["pipeline_status"] == "success"
    assert report["target"] == {"id": 50, "name": "pre-release"}
    assert report["source"]["environment_owner"] == ".deploy"
    assert report["source"]["environment_line"] == 6
    assert report["approval"] == {"state": "unresolved"}
    data["deployment"]["row"]["pending_approval_count"] = 1
    assert observe(tmp_path, data)["approval"] == {"state": "pending-reported", "count": 1}


def test_reported_success_is_bound_to_job_and_source(tmp_path):
    source = b"publish:\n  environment:\n    name: pre-release\n"
    data = packet(source)
    job = data["job"]["row"]
    job.update(
        status="success", started_at="2026-11-01T09:01:00Z", finished_at="2026-11-01T09:02:00Z"
    )
    data["deployment"]["row"].update(status="success", updated_at="2026-11-01T09:02:01Z")
    report = observe(tmp_path, data, source)
    assert report["state"] == "deployment-reported-success"
    assert report["source"]["environment_owner"] == "publish"
    assert report["approval"] == {"state": "unresolved"}


@pytest.mark.parametrize("altered", ["job", "timing", "source", "target", "response"])
def test_rejects_incompatible_deployment_identity(tmp_path, altered):
    data = packet()
    if altered == "job":
        copy = deepcopy(data["job"]["row"])
        copy["pipeline"]["id"] = 21
        data["deployment"]["row"]["deployable"] = copy
    elif altered == "timing":
        data["job"]["row"]["started_at"] = "2026-11-01T09:01:00Z"
    elif altered == "source":
        data["source"]["row"]["content_sha256"] = "b" * 64
    elif altered == "target":
        data["deployment"]["row"]["environment"]["name"] = "production"
    else:
        data["deployment"]["status"] = 403
    assert observe(tmp_path, data)["state"] == "unresolved"


def test_dynamic_environment_remains_unresolved(tmp_path):
    source = SOURCE.replace(b"pre-release", b"$DEPLOY_TARGET")
    assert observe(tmp_path, packet(source), source)["state"] == "unresolved"


@pytest.mark.parametrize("extends", [".deploy", "[.deploy]", "\n    - .deploy"])
def test_local_environment_name_overrides_one_parent(tmp_path, extends):
    source = (
        f"publish:\n  extends: {extends}\n  environment:\n    name: pre-release\n"
        ".deploy:\n  environment:\n    name: other\n    action: start\n"
    ).encode()
    report = observe(tmp_path, packet(source), source)
    assert report["state"] == "deployment-blocked-before-job"
    assert report["source"]["environment_owner"] == "publish"


def test_inherited_stop_requires_explicit_start_override(tmp_path):
    source = b"""publish:
  extends:
    - .deploy
  environment:
    name: pre-release
.deploy:
  environment:
    name: other
    action: stop
"""
    assert observe(tmp_path, packet(source), source)["state"] == "unresolved"
    changed = source.replace(b"name: pre-release\n", b"name: pre-release\n    action: start\n")
    assert observe(tmp_path, packet(changed), changed)["state"] == "deployment-blocked-before-job"


@pytest.mark.parametrize(
    "extends", ["[.deploy, .other]", "[.deploy, {}]", "[.deploy, []]", "\n    - .deploy\n    -"]
)
def test_other_parent_sequence_shapes_stay_unresolved(tmp_path, extends):
    source = (
        f"publish:\n  extends: {extends}\n  environment:\n    name: pre-release\n"
        ".deploy:\n  environment:\n    url: https://example.test\n"
    ).encode()
    assert observe(tmp_path, packet(source), source)["state"] == "unresolved"


@pytest.mark.parametrize("value", ["null", "{}", "pre-release"])
def test_unmodeled_child_environment_does_not_borrow_parent_name(tmp_path, value):
    source = SOURCE.replace(
        b"  extends: .deploy\n", f"  extends: .deploy\n  environment: {value}\n".encode()
    )
    assert observe(tmp_path, packet(source), source)["state"] == "unresolved"


@pytest.mark.parametrize(
    "extends", ["[.deploy, .rules:branch]", "\n    - .deploy\n    - .rules:branch"]
)
def test_two_local_templates_keep_name_and_action_precedence(tmp_path, extends):
    source = (
        f"publish:\n  extends: {extends}\n  environment:\n    name: pre-release\n"
        ".deploy:\n  environment:\n    name: other\n    action: stop\n"
        ".rules:branch:\n  environment:\n    name: last-parent\n    action: start\n"
    ).encode()
    report = observe(tmp_path, packet(source), source)
    assert report["state"] == "deployment-blocked-before-job"
    assert report["source"]["environment_owner"] == "publish"
    wrong_action = source.replace(b"    action: start", b"    action: prepare")
    assert observe(tmp_path, packet(wrong_action), wrong_action)["state"] == "unresolved"
