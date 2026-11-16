"""Authored contract checks for the offline Preview observation mode."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from taintly.ingestion.github_preview import preview_observation

ROOT = Path(__file__).resolve().parents[2]
BASE, HEAD, MERGE = "a" * 40, "b" * 40, "c" * 40
DIGEST = "sha256:" + "9" * 64
PRODUCER = """\
name: Build
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - name: Build
        run: npm run build
      - name: Upload
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: site
          path: |
            dist/
            wrangler.jsonc
"""
CONSUMER = """\
on:
  workflow_run:
    workflows: [Build]
    types: [completed]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - name: Download
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: site
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - name: Publish
        uses: cloudflare/wrangler-action@ebbaa1584979971c8614a24965b4405ff95890e0
        with:
          apiToken: ${{ secrets.PREVIEW_TOKEN }}
          command: preview --worker-name site --name "${{ steps.metadata.outputs.alias }}"
"""


def time(second):
    return f"2026-11-16T00:00:{second:02d}Z"


def saved_source(root, role, source, revision):
    path = f".github/workflows/{role}.yml"
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    content = source.encode()
    (root / path).write_bytes(content)
    return {"path": path, "revision": revision, "sha256": hashlib.sha256(content).hexdigest()}


def run_and_job(run, job, head, name, path, specs):
    return (
        {
            "id": run,
            "head_sha": head,
            "head_repo": "contributor/site" if run == 1 else "team/site",
            "html_url": f"https://github.com/team/site/actions/runs/{run}",
            "event": "pull_request" if run == 1 else "workflow_run",
            "run_attempt": 1,
            "conclusion": "success",
            "path": path,
            "created_at": time(specs[0][1]),
            "referenced_workflows": [],
        },
        {
            "id": job,
            "run_id": run,
            "run_attempt": 1,
            "head_sha": head,
            "name": name,
            "conclusion": "success",
            "started_at": time(specs[0][1]),
            "completed_at": time(specs[-1][1] + 1),
            "steps": [
                {
                    "name": step,
                    "number": index,
                    "conclusion": "success",
                    "started_at": time(second),
                    "completed_at": time(second + 1),
                }
                for index, (step, second) in enumerate(specs, 1)
            ],
        },
    )


@pytest.fixture
def capture(tmp_path):
    p = saved_source(tmp_path, "build", PRODUCER, MERGE)
    c = saved_source(tmp_path, "preview", CONSUMER, BASE)
    producer, pjob = run_and_job(
        1, 3, HEAD, "build", p["path"], [("Checkout", 0), ("Build", 2), ("Upload", 4)]
    )
    consumer, cjob = run_and_job(
        2, 4, BASE, "preview", c["path"], [("Download", 10), ("Publish", 12)]
    )
    return {
        "schema": "github-preview-v1",
        "producer": producer,
        "consumer": consumer,
        "producer_job": pjob,
        "consumer_job": cjob,
        "producer_source": p,
        "consumer_source": c,
        "pr": {
            "number": 5,
            "head": HEAD,
            "base": BASE,
            "head_repo": "contributor/site",
            "base_repo": "team/site",
        },
        "merge": {"sha": MERGE, "parents": [BASE, HEAD]},
        "artifacts": [
            {
                "id": 6,
                "name": "site",
                "digest": DIGEST,
                "run": 1,
                "head_sha": HEAD,
                "created_at": time(5),
                "size_in_bytes": 100,
            }
        ],
        "steps": {
            "checkout": "Checkout",
            "build": "Build",
            "upload": "Upload",
            "download": "Download",
            "publish": "Publish",
        },
        "receipts": [
            {
                "run_id": run,
                "job_id": job,
                "attempt": 1,
                "kind": kind,
                "time": time(second),
                "value": value,
            }
            for run, job, kind, second, value in (
                (1, 3, "checkout", 0, MERGE),
                (1, 3, "upload-id", 4, "6"),
                (2, 4, "producer-id", 10, "1"),
                (2, 4, "download-id", 10, "6"),
                (2, 4, "download-digest", 11, DIGEST),
                (2, 4, "preview-command", 12, "wrangler preview --worker-name site --name pr-5"),
                (2, 4, "version-url", 13, "https://version.preview.example"),
            )
        ],
    }


def evaluate(root, data):
    snapshot = root / "observation.json"
    snapshot.write_text(json.dumps(data), encoding="utf-8")
    return preview_observation(snapshot, root, "team/site", 1, 2)


def test_preview_observation_reports_owned_source_operation_and_scope(tmp_path, capture):
    report = evaluate(tmp_path, capture)
    assert report["state"] == "preview-reported", report
    assert report["producer"]["revision"] == MERGE
    assert report["artifact"]["selectors"] == ["dist/", "wrangler.jsonc"]
    assert report["consumer"]["operation"] == "workers-preview"
    assert report["consumer"]["credential_binding"] == "secrets.PREVIEW_TOKEN"
    assert "principal identity" in report["scope"]


def test_successful_preview_requires_run_and_job_chronology(tmp_path, capture):
    capture["producer"]["created_at"] = time(20)
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert result["reason"] == "selected job timestamps are outside the recorded run"


@pytest.mark.parametrize("addition", ['\n---\non: {}\n', '\n"j\\u006fbs": {}\n'])
def test_source_projection_requires_unambiguous_job_and_event_owner(tmp_path, capture, addition):
    path = tmp_path / capture["producer_source"]["path"]
    raw = path.read_bytes() + addition.encode()
    path.write_bytes(raw)
    capture["producer_source"]["sha256"] = hashlib.sha256(raw).hexdigest()
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"


@pytest.mark.parametrize(
    ("receipt", "key", "value"),
    [
        ("checkout", "value", HEAD),
        ("download-id", "job_id", 999),
        ("download-id", "attempt", 2),
        ("download-digest", "value", "sha256:" + "8" * 64),
        ("preview-command", "value", "wrangler preview --worker-name different --name pr-5"),
        ("version-url", "time", time(0)),
    ],
)
def test_incompatible_evidence_cannot_complete_publication(tmp_path, capture, receipt, key, value):
    row = next(row for row in capture["receipts"] if row["kind"] == receipt)
    row[key] = value
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "consumer" not in result and "artifact" not in result


def test_upload_exclusion_cannot_use_literal_selector_profile(tmp_path, capture):
    modified = PRODUCER.replace(
        "            wrangler.jsonc\n", "            wrangler.jsonc\n            !wrangler.jsonc\n"
    )
    capture["producer_source"] = saved_source(tmp_path, "build", modified, MERGE)
    assert evaluate(tmp_path, capture)["state"] == "unresolved"


def test_missing_source_is_unresolved_through_cli(tmp_path, capture):
    (tmp_path / capture["consumer_source"]["path"]).unlink()
    evaluate(tmp_path, capture)
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(tmp_path),
            "--github-preview-observation",
            str(tmp_path / "observation.json"),
            "team/site",
            "1",
            "2",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert run.returncode == 11
    assert json.loads(run.stdout)["github_preview_observation"]["state"] == "unresolved"
