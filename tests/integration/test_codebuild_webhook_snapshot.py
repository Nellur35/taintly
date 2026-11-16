"""Authored cases for the offline CodeBuild webhook CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PROJECT = "public:us-east-1:" + "a" * 64
_ORIGIN = "https://github.com/example-ci/example"
_EVENT = "PULL_REQUEST_UPDATED"
_SENDER = "987654321"


def _filter(kind, pattern, exclude=False):
    return {"type": kind, "pattern": pattern, "excludeMatchedPattern": exclude}


@pytest.fixture
def receipt():
    return {
        "project_id": _PROJECT,
        "region": "us-east-1",
        "observed_at": "2026-11-16T10:38:07Z",
        "project": {
            "name": "demo",
            "source": {"type": "GITHUB", "location": _ORIGIN + ".git"},
            "webhook": {
                "filterGroups": [
                    [
                        _filter("EVENT", "PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED"),
                        _filter("ACTOR_ACCOUNT_ID", "^(76543|1234)$"),
                        _filter("FILE_PATH", "buildspec.yml", exclude=True),
                    ],
                ],
            },
        },
    }


def _invoke(
    tmp_path, receipt, *, project=_PROJECT, origin=_ORIGIN, sender=_SENDER, fmt="json", extra=()
):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        receipt if isinstance(receipt, str) else json.dumps(receipt), encoding="utf-8"
    )
    args = [
        sys.executable,
        "-m",
        "taintly",
        "--format",
        fmt,
        "--no-config",
        "--codebuild-webhook-snapshot",
        str(snapshot),
        project,
        origin,
        _EVENT,
    ]
    if sender is not None:
        args.extend(("--codebuild-webhook-sender", sender))
    return subprocess.run(
        [*args, *extra],
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=20,
        env={**os.environ, "PYTHONUTF8": "1"},
    )


@pytest.mark.parametrize(
    ("sender", "expected", "exit_code"),
    [
        (_SENDER, "excluded", 0),
        ("76543", "unresolved", 11),
        (None, "unresolved", 11),
    ],
)
def test_source_bound_filter_exclusion_and_unresolved_inputs(
    tmp_path: Path, receipt, sender, expected, exit_code
):
    result = _invoke(tmp_path, receipt, sender=sender)
    assert result.returncode == exit_code, result.stderr
    decision = json.loads(result.stdout)["codebuild_webhook"]
    assert decision["filter_outcome"] == expected
    assert decision["repository"] == "example-ci/example"
    assert decision["observed_at"] == receipt["observed_at"]
    assert decision["groups"][0]["filters"][2]["matches"] is None
    assert "effective publication permissions are unverified" in decision["scope"]
    assert decision["approval"] == "unverified"
    assert decision["execution"] == "unverified"
    assert decision["publication_authority"] == "unverified"


def test_matching_group_wins_without_claiming_approval(tmp_path: Path, receipt):
    receipt["project"]["webhook"]["filterGroups"].append([_filter("EVENT", _EVENT)])
    result = _invoke(tmp_path, receipt, fmt="text")
    assert result.returncode == 0, result.stderr
    assert "CodeBuild webhook filters: filter-match" in result.stdout
    assert "Group 1: miss" in result.stdout
    assert "Group 2: match" in result.stdout
    assert (
        "approval, actual execution and effective publication permissions are unverified"
        in result.stdout
    )
    assert "^(76543|1234)$" not in result.stdout


@pytest.mark.parametrize(
    ("pattern", "exclude", "expected", "exit_code"),
    [
        ("76543|1234", False, "filter-match", 0),
        ("76543|1234", True, "excluded", 0),
        ("(?<=98)76543", False, "unresolved", 11),
        ("(?<=98)76543", True, "unresolved", 11),
    ],
)
def test_actor_regex_uses_bounded_re2_subset(
    tmp_path: Path, receipt, pattern, exclude, expected, exit_code
):
    receipt["project"]["webhook"]["filterGroups"] = [
        [_filter("EVENT", _EVENT), _filter("ACTOR_ACCOUNT_ID", pattern, exclude)]
    ]
    result = _invoke(tmp_path, receipt)
    assert result.returncode == exit_code, result.stderr
    assert json.loads(result.stdout)["codebuild_webhook"]["filter_outcome"] == expected


@pytest.mark.parametrize(
    ("project", "origin", "reason"),
    [
        ("public:us-east-1:" + "b" * 64, _ORIGIN, "selected public project identity"),
        ("public:us-west-2:" + "a" * 64, _ORIGIN, "selected public project identity"),
        (_PROJECT, "https://github.com/example-ci/elsewhere", "selected GitHub source repository"),
    ],
)
def test_other_project_or_repository_cannot_supply_filter_proof(
    tmp_path: Path, receipt, project, origin, reason
):
    result = _invoke(tmp_path, receipt, project=project, origin=origin)
    assert result.returncode == 11, result.stderr
    decision = json.loads(result.stdout)["codebuild_webhook"]
    assert decision["filter_outcome"] == "unresolved"
    assert reason in decision["reason"]
    assert "groups" not in decision


def test_duplicate_project_identity_cannot_supply_filter_proof(tmp_path: Path, receipt):
    data = json.dumps(receipt)
    result = _invoke(tmp_path, '{"project_id":"elsewhere",' + data[1:])
    assert result.returncode == 11, result.stderr
    decision = json.loads(result.stdout)["codebuild_webhook"]
    assert "duplicate JSON keys" in decision["reason"]


def test_empty_groups_do_not_imply_exclusion(tmp_path: Path, receipt):
    receipt["project"]["webhook"]["filterGroups"] = []
    result = _invoke(tmp_path, receipt)
    assert result.returncode == 11, result.stderr
    assert json.loads(result.stdout)["codebuild_webhook"]["filter_outcome"] == "unresolved"


@pytest.mark.parametrize(
    "extra", [("--require-files",), ("--platform", "github"), ("--fail-on", "HIGH")]
)
def test_webhook_query_cannot_claim_coverage_from_a_security_scan(tmp_path: Path, receipt, extra):
    result = _invoke(tmp_path, receipt, extra=extra)
    assert result.returncode == 2
    assert not result.stdout
