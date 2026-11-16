"""Authored guards for the saved signed-release profile."""

import hashlib

import pytest

from taintly.ingestion.github_preview import PreviewEvidenceError, _observed_step
from taintly.ingestion.github_signed_release import _condition, _program, _published_asset, _step
from taintly.rules.github._workflow_run_artifact import _Index

TIME = "2026-11-16T16:22:35Z"
DEST = "team/releases"
TAG = "pr-42"


def test_owned_program_rejects_shadowed_target_even_with_the_same_upload_line():
    script = (
        "set -euo pipefail\n"
        "repo=team/releases\n"
        'gh release upload "$tag" signed/* -R "$repo" --clobber'
    )
    fingerprint = hashlib.sha256(
        script.replace("repo=team/releases", "repo=<destination>").encode()
    ).hexdigest()
    step = ("jobs", "publish", "steps", 0)

    def indexed(body):
        indented = "\n".join(f"          {line}" for line in body.split("\n"))
        return _Index.from_source(
            ".github/workflows/publish.yml",
            "jobs:\n  publish:\n    steps:\n      - run: |\n" + indented,
        )

    command = "gh release upload "
    assert _program(indexed(script), step, fingerprint, command, target=DEST) == 7
    bad = script.replace("gh release upload", "repo=team/other\ngh release upload")
    with pytest.raises(PreviewEvidenceError, match="outside the supported release profile"):
        _program(indexed(bad), step, fingerprint, command, target=DEST)


def test_same_name_steps_can_select_only_one_valid_invocation():
    steps = [
        {
            "name": "Upload",
            "number": number,
            "conclusion": "success",
            "started_at": TIME,
            "completed_at": TIME,
        }
        for number in (1, 2)
    ]
    job = {"started_at": TIME, "completed_at": TIME, "steps": steps}
    assert _observed_step(job, "Upload", number=2) == steps[1]
    with pytest.raises(PreviewEvidenceError, match="saved job does not identify"):
        _observed_step(job, "Upload")
    with pytest.raises(PreviewEvidenceError, match="number is invalid"):
        _observed_step(job, "Upload", number=True)


def test_saved_source_cannot_attach_a_run_to_a_disabled_job_or_step():
    content = """\
jobs:
  publish:
    if: false
    steps:
      - name: Release
        if: false
        run: gh release upload
"""
    index = _Index.from_source(".github/workflows/release.yml", content)
    with pytest.raises(PreviewEvidenceError, match="unsupported execution condition"):
        _condition(index, ("jobs", "publish"), None)
    with pytest.raises(PreviewEvidenceError, match="unsupported execution condition"):
        _step(index, "publish", {("name",): "Release"})
    plain = _Index.from_source(
        ".github/workflows/release.yml",
        content.replace("false", "inputs.run_id != ''"),
    )
    assert _step(plain, "publish", {("name",): "Release"}, condition="inputs.run_id != ''") == (
        "jobs",
        "publish",
        "steps",
        0,
    )


@pytest.mark.parametrize("mode", [" ", "*"])
def test_released_asset_binds_one_manifest_line_under_both_gnu_modes(tmp_path, mode):
    digest = "1" * 64
    asset_name = "test-PR.42-a1b2c3d.apk"
    path = tmp_path / "published-SHA256SUMS.txt"
    body = f"{digest} {mode}{asset_name}\n".encode()
    path.write_bytes(body)
    bot = {"id": 17, "login": "test-app[bot]"}

    def asset(name, identifier, digest, size):
        return {
            "name": name,
            "id": identifier,
            "digest": "sha256:" + digest,
            "size": size,
            "state": "uploaded",
            "created_at": TIME,
            "uploader": bot,
            "browser_download_url": f"https://github.com/{DEST}/releases/download/{TAG}/{name}",
        }

    manifest = asset("SHA256SUMS.txt", 2, hashlib.sha256(body).hexdigest(), len(body))
    release = {
        "id": 709,
        "draft": False,
        "tag_name": TAG,
        "html_url": f"https://github.com/{DEST}/releases/tag/{TAG}",
        "assets": [asset(asset_name, 1, digest, 2048), manifest],
    }
    step = {"started_at": TIME, "completed_at": TIME}
    result = _published_asset({"release": release}, tmp_path, DEST, TAG, asset_name, digest, step)
    assert result["recorded_uploader"] == bot
    assert result["manifest_asset_id"] == 2

    duplicate = body + f"{'2' * 64} *{asset_name}\n".encode()
    path.write_bytes(duplicate)
    manifest.update(size=len(duplicate), digest="sha256:" + hashlib.sha256(duplicate).hexdigest())
    with pytest.raises(PreviewEvidenceError, match="manifest is malformed or ambiguous"):
        _published_asset({"release": release}, tmp_path, DEST, TAG, asset_name, digest, step)
