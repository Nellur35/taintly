"""Authored boundaries for CodeBuild delegation and cache evidence."""

from pathlib import Path

import pytest

from taintly.ingestion.codebuild_checkout import CheckoutScriptReference
from taintly.ingestion.codebuild_snapshot import BoundBuildspec, BoundScriptReference, SnapshotError
from taintly.ingestion.codebuild_start import (
    _configured_copy,
    _guard_launcher,
    codebuild_start_observation,
)

GUARD = """\
permission=$(jq -r '.permission' <<< '${{ steps.permissions.outputs.data }}')
echo "$pr_author has permission '$permission'".
if [[ "$permission" == "admin" || "$permission" == "write" ]]; then
  ./ci/start.sh $source_pr
else
  echo "$pr_author does not have write permissions."
  echo "No launch"
fi
"""

COPY = """\
version: 0.2
env:
  shell: bash
  variables:
    CACHE: "s3://example-test-cache?region=us-west-2"
phases:
  build:
    commands:
      - nix develop .#env --command bash -c 'source ./ci/build.sh && unit'
  post_build:
    commands:
      - nix copy --to $CACHE .#cache
"""
PHASE = {
    "phaseType": "POST_BUILD",
    "phaseStatus": "SUCCEEDED",
    "startTime": 1780000000,
    "endTime": 1780000002,
}
RECORD = {
    "kind": "nix-copy-summary",
    "command": "nix copy --to $CACHE .#cache",
    "paths": 0,
    "time": "2026-05-28T20:26:41Z",
}


def selection(text):
    return BoundBuildspec(
        "team/example",
        "b" * 40,
        "buildspec.yml",
        "0" * 64,
        text,
        checkout_scripts=(
            BoundScriptReference(
                CheckoutScriptReference("build", 0, 9, 9, "ci/build.sh"), "1" * 40
            ),
        ),
        pull_request_ref="pr/7",
    )


def test_guard_does_not_confuse_denial_message_for_a_guard():
    assert _guard_launcher(GUARD, "permissions") == "ci/start.sh"
    invalid = GUARD.replace('echo "No launch"', "./ci/start.sh $source_pr")
    with pytest.raises(SnapshotError, match="unmodeled commands"):
        _guard_launcher(invalid, "permissions")


def test_reported_zero_paths_does_not_establish_object_outcome():
    rows = _configured_copy(selection(COPY), [RECORD], [PHASE])
    assert rows[0]["bucket"] == "example-test-cache"
    assert rows[0]["reported_nix_paths"] == 0
    assert rows[0]["object_write"] == "unverified"


@pytest.mark.parametrize(
    "records", [[], [{**RECORD, "time": "2026-05-28T20:26:43Z"}], [RECORD, RECORD]]
)
def test_copy_without_owned_unique_count_keeps_uncertainty(records):
    assert _configured_copy(selection(COPY), records, [PHASE])[0]["reported_nix_paths"] is None


def test_cache_read_does_not_become_configured_publication():
    assert _configured_copy(selection(COPY.replace("--to", "--from")), [RECORD], [PHASE]) == []


def test_missing_capture_remains_unresolved(tmp_path: Path):
    result = codebuild_start_observation(
        tmp_path / "missing.json", tmp_path, "https://github.com/team/example", 1, 2
    )
    assert result["state"] == "unresolved"
