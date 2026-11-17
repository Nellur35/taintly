"""Authored contrasts for source-bound GitLab registry observations."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from taintly.ingestion.gitlab_mr_artifact import mr_artifact_observation

PROJECT = 100
PIPELINE = 200
JOB = 300
PATH = "sample/project"
JOB_URL = f"https://gitlab.com/{PATH}/-/jobs/{JOB}"
IMAGE = f"registry.gitlab.com/{PATH}/runner"
TAG = "review-branch"
DOCKERFILE = "ci/image.Dockerfile"
RECIPE = b"FROM debian:stable-slim\n"
WORKFLOW = """\
publish:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  variables:
    DOCKERFILE: ci/image.Dockerfile
    IMAGE_TAG: $CI_REGISTRY_IMAGE/runner:$CI_COMMIT_REF_NAME
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -f $DOCKERFILE -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
"""
START = "2026-07-01T00:00:00Z"
END = "2026-07-01T00:01:00Z"
REGISTRY_TIME = "2026-07-01T00:02:00Z"
CONFIG = ".gitlab-ci.yml"


def checksum(value):
    return sha256(value).hexdigest()


@pytest.fixture
def evidence(tmp_path):
    manifest = b'{"schemaVersion":2,"layers":[],"config":{}}\n'
    digest = "sha256:" + checksum(manifest)
    (tmp_path / DOCKERFILE).parent.mkdir()
    (tmp_path / DOCKERFILE).write_bytes(RECIPE)
    (tmp_path / "image-manifest.json").write_bytes(manifest)
    head, base, parent, revision = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)
    ref = "refs/merge-requests/10/train"
    pipe = {
        "id": PIPELINE,
        "project_id": PROJECT,
        "sha": revision,
        "source": "merge_request_event",
        "ref": ref,
        "created_at": START,
        "updated_at": END,
    }
    source = {}
    rows = [
        (22, f"Checking out {revision[:8]} as detached HEAD (ref is {ref})..."),
        (31, "$ docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY"),
        (32, "Login Succeeded"),
        (34, "$ docker build -f $DOCKERFILE -t $IMAGE_TAG ."),
        (42, "$ docker push $IMAGE_TAG"),
        (43, f"The push refers to repository [{IMAGE}]"),
        (45, f"{TAG}: digest: {digest} size: 300"),
        (52, "Job succeeded"),
    ]
    docs = {
        "schema": "gitlab-mr-branch-image-v1",
        "project": {"id": PROJECT, "path": PATH},
        "mr": {
            "iid": 10,
            "source_branch": TAG,
            "source_project_id": PROJECT,
            "target_project_id": PROJECT,
        },
        "pipeline": pipe,
        "job": {
            "id": JOB,
            "pipeline": deepcopy(pipe),
            "name": "publish",
            "status": "success",
            "started_at": START,
            "finished_at": END,
            "web_url": JOB_URL,
            "ref": ref,
            "commit": {"id": revision},
        },
        "historical_view": {
            "id": PIPELINE,
            "url": f"https://gitlab.com/{PATH}/-/pipelines/{PIPELINE}.json",
            "status": 200,
            "sha256": "e" * 64,
            "source": "merge_request_event",
            "event_type": "merge_train",
            "source_sha": head,
            "target_sha": base,
            "ref": ref,
            "revision": revision,
        },
        "merge": {"id": revision, "parent_ids": [base, parent]},
        "source": source,
        "trace": {
            "url": JOB_URL + "/raw",
            "job_id": JOB,
            "sha256": "f" * 64,
            "status": 200,
            "rows": [
                {"line": n, "row": value, "sha256": checksum(value.encode())} for n, value in rows
            ],
            "sections": [
                {"line": line, "seconds": 1782864000 + offset, "stage": stage, "event": event}
                for stage, event, line, offset in (
                    ("get_sources", "start", 20, 1),
                    ("get_sources", "end", 27, 5),
                    ("step_script", "start", 30, 5),
                    ("step_script", "end", 46, 52),
                    ("cleanup_file_variables", "start", 47, 52),
                    ("cleanup_file_variables", "end", 50, 53),
                )
            ],
            "script_commands": [rows[i][1] for i in (1, 3, 4)],
        },
        "registry": {
            key: {
                "reference": reference,
                "url": f"https://{IMAGE.split('/')[0]}/v2/{PATH}/runner/manifests/{reference}",
                "status": 200,
                "server_digest": digest,
                "calculated_digest": digest,
                "digest_matches": True,
                "bytes": len(manifest),
                "time": REGISTRY_TIME,
            }
            for key, reference in (("tag", TAG), ("digest", digest))
        },
    }

    def stage_workflow(workflow=WORKFLOW):
        raw = workflow.encode()
        (tmp_path / CONFIG).write_bytes(raw)
        source.clear()
        for name, rev in (
            ("executed", revision),
            ("base", base),
            ("merge_input", parent),
            ("mr_historical_head", head),
        ):
            api = f"https://gitlab.com/api/v4/projects/{PROJECT}/repository/files/"
            recipe = {"url": api + "ci%2Fimage.Dockerfile/raw?ref=" + rev}
            recipe.update(
                {"status": 404} if name == "base" else {"status": 200, "sha256": checksum(RECIPE)}
            )
            source[name] = {
                "revision": rev,
                "files": {
                    CONFIG: {
                        "url": api + CONFIG + "/raw?ref=" + rev,
                        "status": 200,
                        "sha256": checksum(raw),
                    },
                    DOCKERFILE: recipe,
                },
            }

    def assess():
        packet = tmp_path / "receipt.json"
        packet.write_text(json.dumps(docs), encoding="utf-8")
        return mr_artifact_observation(packet, tmp_path, PROJECT, PIPELINE, JOB)

    stage_workflow()
    return docs, stage_workflow, assess, digest


def test_same_project_train_binds_branch_tag_and_registry_object(evidence):
    docs, _, assess, digest = evidence
    result = assess()
    assert result["state"] == "registry-image-push-observed"
    assert result["mr_head"] != result["merge_input"]
    assert result["event_type"] == "merge_train"
    assert result["operation"] == {
        "name": "docker-push",
        "target": f"{IMAGE}:{TAG}",
        "reported_digest": digest,
        "registry_confirmation": "matched",
    }
    assert result["credential"]["runtime_identity"] == "unverified"
    assert result["revision"] == docs["pipeline"]["sha"]


def test_canceled_job_can_report_a_push_with_unconfirmed_manifest(evidence):
    docs, _, assess, digest = evidence
    docs["job"]["status"] = "canceled"
    docs["registry"]["tag"].update(server_digest="sha256:" + "e" * 64)
    result = assess()
    assert result["state"] == "registry-image-push-reported"
    assert result["job_status"] == "canceled"
    assert result["operation"]["reported_digest"] == digest
    assert result["operation"]["registry_confirmation"] == "unverified"


def test_missing_manifest_preserves_reported_push(evidence, tmp_path):
    _, _, assess, digest = evidence
    (tmp_path / "image-manifest.json").unlink()
    result = assess()
    assert result["state"] == "registry-image-push-reported"
    assert result["operation"]["reported_digest"] == digest


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("mr", "source_project_id"), 999),
        (("historical_view", "event_type"), "merged_result"),
        (("job", "pipeline", "sha"), "e" * 40),
        (("job", "ref"), "refs/heads/main"),
        (("job", "commit", "id"), "e" * 40),
        (("historical_view", "status"), 404),
        (("trace", "status"), 404),
        (("trace", "job_id"), True),
        (("trace", "rows", 6, "line"), 49),
        (("trace", "sections", 3, "seconds"), 1782864400),
        (("trace", "script_commands", 1), "$ make something-else"),
        (("source", "mr_historical_head", "revision"), "e" * 40),
        (("source", "merge_input", "files", DOCKERFILE, "sha256"), "f" * 64),
    ],
)
def test_mismatched_job_source_or_execution_section_is_unresolved(evidence, path, value):
    docs, _, assess, _ = evidence
    item = docs
    for part in path[:-1]:
        item = item[part]
    item[path[-1]] = value
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(
    "prefix",
    [
        "variables:\n  CI_REGISTRY_IMAGE: other/image\n",
        "before_script:\n  - echo unexpected\n",
    ],
)
def test_unmodeled_source_context_cannot_satisfy_the_profile(evidence, prefix):
    _, bind, assess, _ = evidence
    bind(prefix + WORKFLOW)
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(("key", "value"), [("bytes", 1), ("digest_matches", False)])
def test_registry_provenance_disagreement_retains_the_runner_report(evidence, key, value):
    docs, _, assess, _ = evidence
    docs["registry"]["tag"][key] = value
    assert assess()["state"] == "registry-image-push-reported"


def test_unconditional_source_denial_is_inconsistent_with_runs(evidence):
    _, bind, assess, _ = evidence
    bind(WORKFLOW.replace(WORKFLOW.splitlines()[2].strip(), "- when: never"))
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize("extra", ["    -\n", "    - []\n", "    - {}\n"])
def test_invisible_extra_script_entries_are_unsupported(evidence, extra):
    _, bind, assess, _ = evidence
    bind(WORKFLOW + extra)
    assert assess()["state"] == "unresolved"


def test_unconditional_workflow_denial_is_inconsistent_with_runs(evidence):
    _, bind, assess, _ = evidence
    bind("workflow:\n  rules:\n    - when: never\n" + WORKFLOW)
    assert assess()["state"] == "unresolved"
