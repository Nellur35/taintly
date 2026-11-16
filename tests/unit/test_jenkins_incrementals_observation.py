"""Authored evidence controls for the offline Jenkins Incrementals profile."""

import hashlib
import io
import json
import zipfile

import pytest

from taintly.ingestion.jenkins_incrementals import incrementals_observation

HEAD, BASE = "a" * 40, "b" * 40
DIRECTORY = "https://repo.jenkins-ci.org/incrementals/org/jenkins-ci/plugins/git/1.2/"


def package(head):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            f"Implementation-Build: {head}\r\nImplementation-Version: 1.2\r\n",
        )
    return stream.getvalue()


@pytest.fixture
def capture(tmp_path):
    source = b"buildPlugin(platform: 'linux')\n"
    for name in ("Jenkinsfile", "base.Jenkinsfile"):
        (tmp_path / name).write_bytes(source)
    raw = package(HEAD)
    (tmp_path / "package.zip").write_bytes(raw)
    sha = hashlib.sha256(source).hexdigest()
    blob = hashlib.sha1(
        b"blob " + str(len(source)).encode() + b"\0" + source, usedforsecurity=False
    ).hexdigest()
    return {
        "schema": "jenkins-incrementals-v1",
        "repository": "jenkinsci/git-plugin",
        "pr": {"number": 7, "head_repo": "example/git-plugin", "head": HEAD, "base": BASE},
        "source": {
            "head": {"commit": HEAD, "sha256": sha, "blob": blob},
            "base": {"commit": BASE, "sha256": sha, "blob": blob},
        },
        "registry": {
            "repo": "incrementals",
            "path": "/org/jenkins-ci/plugins/git/1.2/git-1.2.hpi",
            "created": "2026-11-16T00:00:01.009Z",
            "createdBy": "registry-writer",
            "modifiedBy": "registry-writer",
            "checksums": {"sha256": hashlib.sha256(raw).hexdigest()},
            "size": str(len(raw)),
        },
        "checks": [
            {
                "id": 11,
                "app": {"id": 74951, "slug": "ci-jenkins-io"},
                "name": "Jenkins",
                "conclusion": "success",
                "head_sha": HEAD,
                "external_id": "Plugins/git-plugin/PR-7#2",
                "started_at": "2026-11-16T00:00:00Z",
                "completed_at": "2026-11-16T00:00:02Z",
                "details_url": "https://ci.jenkins.io/job/Plugins/job/git-plugin/job/PR-7/2/display/redirect",
            },
            {
                "id": 12,
                "app": {"id": 164119, "slug": "jenkins-incrementals-publisher"},
                "name": "Incrementals",
                "conclusion": "success",
                "head_sha": HEAD,
                "completed_at": "2026-11-16T00:00:01Z",
                "details_url": DIRECTORY,
                "summary": f"[git]({DIRECTORY})",
                "external_id": "",
            },
        ],
    }


def evaluate(root, capture):
    path = root / "observation.json"
    path.write_text(json.dumps(capture), encoding="utf-8")
    return incrementals_observation(path, root, "jenkinsci/git-plugin", 7, 11)


def test_observed_registry_permission_preserves_missing_handoff(tmp_path, capture):
    result = evaluate(tmp_path, capture)
    assert result["state"] == "publication-observed", result
    assert result["publication"]["registry_actor"] == "registry-writer"
    assert result["publication"]["manifest_revision"] == HEAD
    assert result["jenkins"]["publisher_handoff"] == "unverified"


def test_successful_check_does_not_replace_artifact_bytes(tmp_path, capture):
    (tmp_path / "package.zip").unlink()
    assert evaluate(tmp_path, capture)["state"] == "unresolved"


def test_valid_checksum_does_not_link_package_to_unrelated_revision(tmp_path, capture):
    raw = package(BASE)
    (tmp_path / "package.zip").write_bytes(raw)
    capture["registry"]["size"] = str(len(raw))
    capture["registry"]["checksums"]["sha256"] = hashlib.sha256(raw).hexdigest()
    assert evaluate(tmp_path, capture)["reason"].startswith("published package manifest")


def test_groovy_comment_does_not_establish_publisher_call(tmp_path, capture):
    source = b"// buildPlugin(platform: 'linux')\n"
    for name in ("Jenkinsfile", "base.Jenkinsfile"):
        (tmp_path / name).write_bytes(source)
    for entry in capture["source"].values():
        entry["sha256"] = hashlib.sha256(source).hexdigest()
        entry["blob"] = hashlib.sha1(
            b"blob " + str(len(source)).encode() + b"\0" + source, usedforsecurity=False
        ).hexdigest()
    assert (
        evaluate(tmp_path, capture)["reason"] == "Jenkinsfile lacks one supported configured call"
    )
