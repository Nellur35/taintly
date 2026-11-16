"""Authored checks of matrix selection and supported fork-guard conclusions."""

import hashlib
import json

import pytest

from taintly.ingestion.github_version_upload import (
    _matrix_values,
    version_upload_observation,
)
from taintly.rules.github._workflow_run_artifact import _Index

WORKFLOW = """\
on:
  pull_request:
jobs:
  deploy:
    name: Deploy ${{ matrix.site.name }}
    if: github.event.pull_request.head.repo.full_name == github.repository
    strategy:
      matrix:
        site:
          - name: site-a
            working_directory: examples/a
            wrangler_config: config/wrangler.jsonc
          - name: site-b
            working_directory: examples/b
            wrangler_config: config/b.json
    steps:
      - name: Upload
        run: printf placeholder
"""


@pytest.mark.parametrize(
    ("observed", "workspace", "config"),
    [
        ("Deploy site-a", "examples/a", "config/wrangler.jsonc"),
        ("Deploy site-b", "examples/b", "config/b.json"),
    ],
)
def test_literal_matrix_keeps_workspace_and_config_in_same_row(observed, workspace, config):
    index = _Index.from_source("source.yml", WORKFLOW)
    assert _matrix_values(index, "deploy", "Deploy ${{ matrix.site.name }}", observed) == (
        "site",
        workspace,
        config,
    )


@pytest.fixture
def skip_capture():
    head = "a" * 40
    return {
        "schema": "github-version-upload-v1",
        "source_job": "deploy",
        "receipts": [],
        "source": {"path": ".github/workflows/source.yml", "revision": head},
        "run": {
            "id": 40,
            "run_attempt": 1,
            "head_sha": head,
            "head_repo": "fork/project",
            "html_url": "https://github.com/team/project/actions/runs/40",
            "event": "pull_request",
            "conclusion": "skipped",
            "path": ".github/workflows/source.yml",
            "referenced_workflows": [],
        },
        "job": {
            "id": 41,
            "run_id": 40,
            "run_attempt": 1,
            "head_sha": head,
            "conclusion": "skipped",
            "steps": [],
            "name": "Deploy ${{ matrix.site.name }}",
        },
    }


def evaluate(root, data, text):
    content = text.encode()
    path = root / data["source"]["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    data["source"]["sha256"] = hashlib.sha256(content).hexdigest()
    saved = root / "saved.json"
    saved.write_text(json.dumps(data), encoding="utf-8")
    return version_upload_observation(saved, root, "team/project", 40, 41)


def test_skip_preserves_distinction_between_source_guard_and_historical_cause(
    tmp_path, skip_capture
):
    result = evaluate(tmp_path, skip_capture, WORKFLOW)
    assert result["state"] == "fork-job-skipped", result
    assert result["supplied_source_excludes_fork"]
    assert result["historical_skip_cause"] == "unverified"
    assert "publication" not in result


def test_missing_fork_guard_never_makes_skip_an_exclusion(tmp_path, skip_capture):
    workflow = WORKFLOW.replace(
        "github.event.pull_request.head.repo.full_name == github.repository",
        "vars.RUNTIME_ALLOW == 'yes'",
    )
    assert evaluate(tmp_path, skip_capture, workflow)["state"] == "unresolved"


def test_conflicting_source_job_names_prevent_historical_binding(tmp_path, skip_capture):
    workflow = WORKFLOW + "  sibling:\n    name: Deploy ${{ matrix.site.name }}\n"
    assert evaluate(tmp_path, skip_capture, workflow)["state"] == "unresolved"
