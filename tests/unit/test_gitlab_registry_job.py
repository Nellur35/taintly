"""Authored controls for binding saved run evidence to one configured path."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from taintly.__main__ import main

_CONFIG = """\
preview:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: [preview/Containerfile]
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"
    - TAG=$(sha256sum preview/Containerfile | cut -c1-8)
    - IMAGE="${CI_REGISTRY_IMAGE}/preview"
    - |
      if docker manifest inspect "${IMAGE}:${TAG}" >/dev/null 2>&1; then
        echo "${IMAGE}:${TAG} already exists"
      else
        docker build -t "${IMAGE}:${TAG}" -f preview/Containerfile preview
        docker push "${IMAGE}:${TAG}"
      fi
"""
_RECIPE = b"FROM scratch\n"
_RECIPE_HASH = hashlib.sha256(_RECIPE).hexdigest()
_TAG = _RECIPE_HASH[:8]
_DIGEST = "sha256:" + "b" * 64
_IMAGE = "registry.gitlab.com/testing/example/preview"
_TARGET = f"{_IMAGE}:{_TAG}"
_REF = "refs/merge-requests/1/merge"
_REV = "a" * 40


def _as_trace(lines: list[str]) -> str:
    return "\n".join(
        f"2026-10-27T10:00:{index:02d}Z 01O {line}" for index, line in enumerate(lines, start=1)
    )


def _receipt(branch: list[str]) -> dict:
    return {
        "project": {"id": 10, "path_with_namespace": "testing/example"},
        "job": {
            "id": 30,
            "name": "preview",
            "status": "success",
            "started_at": "2026-10-27T10:00:00Z",
            "finished_at": "2026-10-27T10:00:10Z",
            "ref": _REF,
            "commit": {"id": _REV},
            "pipeline": {
                "project_id": 10,
                "id": 20,
                "sha": _REV,
                "ref": _REF,
                "source": "merge_request_event",
            },
        },
        "source": {
            "revision": _REV,
            "config_sha256": hashlib.sha256(_CONFIG.encode()).hexdigest(),
            "dockerfile_sha256": _RECIPE_HASH,
        },
        "trace": {
            "job_id": 30,
            "text": _as_trace(
                [
                    f"Checking out {_REV[:8]} as detached HEAD (ref is {_REF})...",
                    '$ echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"',
                    "Login Succeeded",
                    "$ TAG=$(sha256sum preview/Containerfile | cut -c1-8)",
                    '$ IMAGE="${CI_REGISTRY_IMAGE}/preview"',
                    *branch,
                    "Job succeeded",
                ]
            ),
        },
    }


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    (tmp_path / ".gitlab-ci.yml").write_bytes(_CONFIG.encode())
    (tmp_path / "preview").mkdir()
    (tmp_path / "preview/Containerfile").write_bytes(_RECIPE)
    return tmp_path


@pytest.fixture
def push_receipt() -> dict:
    receipt = _receipt(
        [f"The push refers to repository [{_IMAGE}]", f"{_TAG}: digest: {_DIGEST} size: 120"]
    )
    receipt["registry"] = {
        "reference": _TARGET,
        "digest": _DIGEST,
        "observed_at": "2026-10-27T10:45:00Z",
    }
    return receipt


def _scan(
    repo: Path, receipt: dict | None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> tuple[int, dict, str]:
    args = ["taintly", str(repo), "--platform", "gitlab", "--format", "json", "--no-config"]
    if receipt is not None:
        path = repo / "evidence.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        args.extend(["--gitlab-job-evidence", str(path), "10", "30"])
    monkeypatch.setattr(sys, "argv", args)
    with pytest.raises(SystemExit) as exc:
        main()
    output = capsys.readouterr()
    return exc.value.code, json.loads(output.out) if output.out else {}, output.err


def _chain(report: dict) -> dict:
    (chain,) = [item for item in report["findings"] if item["rule_id"] == "CHAIN-GL-101"]
    return chain


def test_registry_observation_changes_only_the_matched_finding(
    repository: Path,
    push_receipt: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    baseline_status, baseline, _ = _scan(repository, None, monkeypatch, capsys)
    status, observed, _ = _scan(repository, push_receipt, monkeypatch, capsys)
    finding = _chain(observed)
    assert finding["context_tags"].pop() == "gitlab-trace-push-registry-match"
    note = finding["context_notes"].pop()
    assert _TARGET in note
    assert _DIGEST in note
    assert "supplied registry response matches" in note
    assert finding["review_needed"]
    assert status == baseline_status
    assert observed == baseline


def test_registry_observation_reports_skip_without_assuming_a_push(
    repository: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _, observed, _ = _scan(repository, _receipt([f"{_TARGET} already exists"]), monkeypatch, capsys)
    finding = _chain(observed)
    assert finding["context_tags"] == ["gitlab-trace-reports-existing-tag"]
    assert "configured branch that skips this push" in finding["context_notes"][-1]


def test_registry_observation_binds_raw_bytes_not_normalized_yaml(
    repository: Path,
    push_receipt: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    windows_source = _CONFIG.replace("\n", "\r\n").encode()
    (repository / ".gitlab-ci.yml").write_bytes(windows_source)
    _, changed, _ = _scan(repository, push_receipt, monkeypatch, capsys)
    assert changed["coverage_status"] == "incomplete"
    assert not _chain(changed).get("context_tags")
    push_receipt["source"]["config_sha256"] = hashlib.sha256(windows_source).hexdigest()
    _, supplied, _ = _scan(repository, push_receipt, monkeypatch, capsys)
    assert _chain(supplied)["context_tags"] == ["gitlab-trace-push-registry-match"]


@pytest.mark.parametrize(
    ("section", "field", "value", "reason"),
    [
        ("trace", "job_id", 31, "identities do not match"),
        ("source", "revision", "e" * 40, "selected successful merged-result MR run"),
        ("source", "config_sha256", "1" * 64, "Root configuration bytes do not match"),
        ("source", "dockerfile_sha256", "1" * 64, "Dockerfile bytes do not match"),
        ("job", "name", "different-job", "No supported root-config path"),
        ("job", "started_at", "2026-10-27T10:00:03Z", "Trace timestamps"),
        (
            "registry",
            "reference",
            "registry.gitlab.com/testing/elsewhere:unmatched",
            "No matching registry",
        ),
        ("registry", "digest", "sha256:" + "e" * 64, "No matching registry"),
        ("registry", "observed_at", "2026-10-27T10:00:10Z", "No matching registry"),
    ],
)
def test_registry_observation_rejects_wrong_identity_or_missing_link(
    repository: Path,
    push_receipt: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    section: str,
    field: str,
    value: str | int,
    reason: str,
) -> None:
    push_receipt[section][field] = value
    status, report, errors = _scan(repository, push_receipt, monkeypatch, capsys)
    if not report:
        assert status == 2
        assert reason in errors
        return
    assert not _chain(report).get("context_tags")
    assert report["coverage_status"] == "incomplete"
    assert any(
        finding["rule_id"] == "ENGINE-ERR" and reason in finding["description"]
        for finding in report["findings"]
    )


@pytest.mark.parametrize(
    "branch",
    [
        [],
        [f"The push refers to repository [{_IMAGE}]", f"{_TAG}: digest: {_DIGEST} size: 120"],
        [f"{_TARGET} already exists", f"The push refers to repository [{_IMAGE}]"],
        [f'$ printf "%s\n" "{_TARGET} already exists"'],
    ],
)
def test_registry_observation_keep_missing_or_conflicting_branches_unresolved(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    branch: list[str],
) -> None:
    _, observed, _ = _scan(repository, _receipt(branch), monkeypatch, capsys)
    assert not _chain(observed).get("context_tags")
    assert observed["coverage_status"] == "incomplete"
