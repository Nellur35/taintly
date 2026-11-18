"""Authored evidence controls for the offline Jenkins Incrementals profile."""

import hashlib
import io
import json
import zipfile

import pytest

from taintly.ingestion.jenkins_incrementals import (
    IncrementalsEvidenceError,
    _manifest,
    incrementals_observation,
)

HEAD, BASE = "a" * 40, "b" * 40
DIRECTORY = "https://repo.jenkins-ci.org/incrementals/org/jenkins-ci/plugins/git/1.2/"


def package(head, *, compression=zipfile.ZIP_STORED, extra=""):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            f"Implementation-Build: {head}\r\nImplementation-Version: 1.2\r\n{extra}",
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


@pytest.mark.parametrize(
    ("namespace", "expected"),
    [
        ("io/jenkins/plugins", "publication-observed"),
        ("org/jenkins-ci/plugins/workflow", "publication-observed"),
        ("io/other/plugins", "unresolved"),
        ("org/jenkins-ci/plugins/other", "unresolved"),
        ("org/jenkins-ci/plugins/workflow/other", "unresolved"),
    ],
)
def test_plugin_coordinates_allow_only_supported_namespaces(tmp_path, capture, namespace, expected):
    original = "org/jenkins-ci/plugins"
    capture["registry"]["path"] = capture["registry"]["path"].replace(original, namespace)
    directory = DIRECTORY.replace(original, namespace)
    capture["checks"][1].update(details_url=directory, summary=f"[git]({directory})")
    result = evaluate(tmp_path, capture)
    assert result["state"] == expected
    if expected == "publication-observed":
        assert result["publication"]["object_url"] == directory + "git-1.2.hpi"


def test_publisher_target_must_match_registry_even_if_summary_has_both_links(tmp_path, capture):
    other = DIRECTORY.replace("/git/", "/another-plugin/")
    capture["checks"][1].update(
        details_url=other,
        summary=f"[git]({DIRECTORY})\n[another plugin]({other})",
    )
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert (
        result["reason"]
        == "publisher check, registry target and recorded write identity do not agree"
    )


def test_core_multi_module_publisher_can_link_to_another_listed_module(tmp_path, capture):
    source = b"infra.maybePublishIncrementals()\n"
    blob = hashlib.sha1(
        b"blob " + str(len(source)).encode("ascii") + b"\0" + source, usedforsecurity=False
    ).hexdigest()
    for filename in ("Jenkinsfile", "base.Jenkinsfile"):
        (tmp_path / filename).write_bytes(source)
    for entry in capture["source"].values():
        entry.update(sha256=hashlib.sha256(source).hexdigest(), blob=blob)
    capture["repository"] = "jenkinsci/jenkins"
    capture["checks"][0].update(
        external_id="Core/jenkins/PR-7#2",
        details_url="https://ci.jenkins.io/job/Core/job/jenkins/job/PR-7/2/display/redirect",
    )
    path = "org/jenkins-ci/main"
    capture["registry"]["path"] = f"/{path}/websocket-spi/1.2/websocket-spi-1.2.jar"
    war = f"https://repo.jenkins-ci.org/incrementals/{path}/jenkins-war/1.2/"
    selected = f"https://repo.jenkins-ci.org/incrementals/{path}/websocket-spi/1.2/"
    capture["checks"][1].update(details_url=war, summary=f"[war]({war})\n[spi]({selected})")
    receipt = tmp_path / "observation.json"
    receipt.write_text(json.dumps(capture), encoding="utf-8")
    result = incrementals_observation(receipt, tmp_path, "jenkinsci/jenkins", 7, 11)
    assert result["state"] == "publication-observed"
    assert result["publication"]["object_url"] == selected + "websocket-spi-1.2.jar"


def test_lzma_manifest_is_unresolved_before_decompression(tmp_path, capture):
    raw = package(HEAD, compression=zipfile.ZIP_LZMA)
    (tmp_path / "package.zip").write_bytes(raw)
    capture["registry"]["size"] = str(len(raw))
    capture["registry"]["checksums"]["sha256"] = hashlib.sha256(raw).hexdigest()
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert result["reason"] == "package manifest uses unsupported ZIP compression"


@pytest.mark.parametrize("line_end", ["\r\n", "\n", "\r"])
def test_case_variant_of_an_existing_main_manifest_header_is_ambiguous(tmp_path, capture, line_end):
    raw = package(HEAD, extra=f"implementation-build: {BASE}{line_end}")
    (tmp_path / "package.zip").write_bytes(raw)
    capture["registry"]["size"] = str(len(raw))
    capture["registry"]["checksums"]["sha256"] = hashlib.sha256(raw).hexdigest()
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert result["reason"] == "package manifest is malformed or ambiguous"


@pytest.mark.parametrize(
    ("filename", "body", "reason"),
    [
        ("META-\u0131NF/MANIFEST.MF", "Implementation-Build: abc\n", "manifest is missing"),
        ("META-INF/MANIFEST.MF", "Implementation-Build: abc", "unterminated physical line"),
        ("META-INF/MANIFEST.MF", "Kelvin-\u212a: abc\n", "manifest is malformed"),
        ("META-INF/MANIFEST.MF", "Implementation-\n Build: abc\n", "manifest is malformed"),
        ("META-INF/MANIFEST.MF", " Implementation-Build: abc\n", "orphan continuation"),
    ],
)
def test_manifest_checks_actual_archive_name_and_physical_header_syntax(filename, body, reason):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(filename, body)
    with pytest.raises(IncrementalsEvidenceError, match=reason):
        _manifest(stream.getvalue())


def test_manifest_continuations_keep_main_section_ownership():
    body = (
        "Manifest-Version: 1.0\r\n"
        "Implementation-Build: ab\r\n"
        " cd\r\n\r\n"
        " Implementation-Version: 2.0\r\n"
    )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", body)
    fields = _manifest(stream.getvalue())
    assert fields["implementation-build"] == "abcd"
    assert "implementation-version" not in fields


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
