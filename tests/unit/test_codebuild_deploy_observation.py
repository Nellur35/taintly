"""Authored contrasts for the saved CodeBuild deployment observation."""

import pytest

from taintly.ingestion.codebuild_deploy import _deployment_run, _guarded_operations, _source_selector
from taintly.ingestion.codebuild_snapshot import SnapshotError


SCRIPT = """#!/bin/bash
echo Current branch is $CODEBUILD_WEBHOOK_HEAD_REF and source is $CODEBUILD_SOURCE_VERSION
if [[ "$CODEBUILD_WEBHOOK_HEAD_REF" == "refs/heads/release" && ${CODEBUILD_SOURCE_VERSION:0:3} != "pr/" ]]; then
    echo Deploying to S3 and invalidating CloudFront cache.
    aws s3 sync build/out/ s3://example-release/ --delete
    aws cloudfront create-invalidation --distribution-id $CLOUDFRONT_DIST_ID --paths "/*"
else
    echo No deploy needed.
fi
"""
BUILD = {
    "startTime": 1780000000,
    "endTime": 1780000005,
    "source": {},
    "sourceVersion": "pr/17",
    "phases": [{
        "phaseType": "DOWNLOAD_SOURCE", "phaseStatus": "SUCCEEDED",
        "startTime": 1780000000, "endTime": 1780000001,
    }, {
        "phaseType": "BUILD", "phaseStatus": "SUCCEEDED",
        "startTime": 1780000001, "endTime": 1780000004,
    }],
}
WORKSPACE = "/codebuild/output/src42/src/github.com/example/release"
DOWNLOAD = [
    f"[Container] 2026/05/28 20:26:40.120000 CODEBUILD_SRC_DIR={WORKSPACE}",
    f"[Container] 2026/05/28 20:26:40.220000 YAML location is {WORKSPACE}/buildspec.yml",
    "[Container] 2026/05/28 20:26:40.430000 Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED",
]
DEPLOYMENT = [
    "[Container] 2026/05/28 20:26:41.120000 Running command bash ci/deploy.sh",
    "Current branch is refs/heads/release and source is pr/17",
    "No deploy needed.",
    "[Container] 2026/05/28 20:26:43.100000 Phase complete: BUILD State: SUCCEEDED",
]


def test_guard_identifies_branch_checks_and_configured_target():
    branch, ops = _guarded_operations(SCRIPT)
    assert branch == "refs/heads/release"
    assert ops[0]["target"] == "s3://example-release/"
    assert ops[1]["target"] == "unverified"
    assert _source_selector(DOWNLOAD, BUILD) == WORKSPACE
    assert _deployment_run(DEPLOYMENT, BUILD) == ("ci/deploy.sh", "refs/heads/release", "pr/17")


@pytest.mark.parametrize("body", [
    SCRIPT.replace("&&", "||"),
    SCRIPT.replace('!= "pr/"', '== "pr/"'),
    SCRIPT.replace("echo No deploy needed.", "echo No deploy needed.\n    aws s3 sync out/ s3://another/"),
    SCRIPT.replace("build/out/", "$TARGET_DIR/"),
    SCRIPT.replace("\nif ", "\vif "),
])
def test_matching_skip_message_is_insufficient_for_different_guard(body):
    with pytest.raises(SnapshotError):
        _guarded_operations(body)


def test_unowned_source_and_skip_records_remain_unresolved():
    with pytest.raises(SnapshotError, match="YAML|runner"):
        _source_selector([DOWNLOAD[0], DOWNLOAD[1].replace("src42", "src43"), DOWNLOAD[2]], BUILD)
    shifted = [row.replace("20:26:40", "20:26:42") for row in DOWNLOAD]
    with pytest.raises(SnapshotError, match="owning DOWNLOAD_SOURCE"):
        _source_selector(shifted, BUILD)
    with pytest.raises(SnapshotError, match="conflicts"):
        _source_selector(DOWNLOAD, {**BUILD, "source": {"buildspec": "ci/elsewhere.yml"}})
    with pytest.raises(SnapshotError, match="PR ref"):
        _deployment_run([DEPLOYMENT[0], DEPLOYMENT[1].replace("pr/17", "pr/99"), *DEPLOYMENT[2:]], BUILD)
    with pytest.raises(SnapshotError, match="phase"):
        _deployment_run([DEPLOYMENT[0].replace("41.120000", "40.120000"), *DEPLOYMENT[1:]], BUILD)
