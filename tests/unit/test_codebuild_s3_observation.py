"""Regression controls for a bounded S3 archive source witness."""

import hashlib
import io
import zipfile

import pytest

from taintly.ingestion import codebuild_s3
from taintly.ingestion.codebuild_snapshot import SnapshotError


def zipped(name_version, data, duplicate=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(name_version, data)
        if duplicate:
            archive.writestr(name_version.replace("WRONGtail", "OTHERtail"), data)
    return stream.getvalue()


@pytest.fixture
def compare(monkeypatch, tmp_path):
    def blob(_root, revision, source_path):
        return {"head": "updated\n", "base": "prior\n"}[revision], {"path": source_path}

    monkeypatch.setattr(codebuild_s3, "_blob", blob)

    def witness(raw):
        return codebuild_s3._archive_witness(
            raw,
            {"source_path": "src/Makefile", "archive_member": "source/src/Makefile"},
            tmp_path,
            {"head": "head", "base": "base"},
        )

    return witness


@pytest.mark.parametrize(
    ("bytes_", "kind"),
    [
        (b"updated\n", "exact"),
        (b"updated\r\n", "lf-crlf-equivalent"),
    ],
)
def test_pr_member_requires_matching_bytes_or_known_newline_conversion(compare, bytes_, kind):
    assert compare(zipped("source/src/Makefile", bytes_))["comparison"] == kind


def test_archive_witness_rejects_base_and_ambiguous_stored_names(compare):
    with pytest.raises(SnapshotError, match="does not establish"):
        compare(zipped("source/src/Makefile", b"prior\n"))
    raw = zipped("source/src/MakefileWRONGtail", b"updated\n").replace(b"WRONGtail", b"\0RONGtail")
    with pytest.raises(SnapshotError, match="regular-text"):
        compare(raw)
    dup = zipped("source/src/MakefileWRONGtail", b"updated\n", duplicate=True)
    dup = dup.replace(b"WRONGtail", b"\0RONGtail").replace(b"OTHERtail", b"\0THERtail")
    with pytest.raises(SnapshotError, match="ambiguous"):
        compare(dup)


def test_artifact_directory_checksum_keeps_child_object_link_unverified(tmp_path, monkeypatch):
    build_id = "project:01234567-89ab-cdef-0123-456789abcdef"
    arn = f"arn:aws:codebuild:us-east-1:123456789012:build/{build_id}"
    raw = zipped("source/Makefile", b"updated\n")
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / "archive.zip").write_bytes(raw)
    capture = tmp_path / "capture.json"
    capture.touch()
    monkeypatch.setattr(codebuild_s3, "_phase_window", lambda *_: (0, 2))
    monkeypatch.setattr(
        codebuild_s3,
        "_source_identity",
        lambda *_: (
            "example/repo",
            {
                "head": "head",
                "base": "base",
                "fork": "other/repo",
                "number": 1,
            },
            "script",
        ),
    )
    monkeypatch.setattr(codebuild_s3, "_observe_plan", lambda *_: {})
    monkeypatch.setattr(
        codebuild_s3,
        "_blob",
        lambda _root, revision, _: ({"head": "updated\n", "base": "prior\n"}[revision], revision),
    )
    directory = "test-bucket/builds/01234567-89ab-cdef-0123-456789abcdef"
    provider = {"build": build_id, "s3Arn": f"arn:aws:s3:::{directory}"}
    observed = {
        "build_id": build_id,
        "http_status": 200,
        "url": f"https://s3.us-east-1.amazonaws.com/{directory}/output.zip",
        "archive_sha256": digest,
        "headers": {
            "x-amz-meta-codebuild-buildarn": arn,
            "Last-Modified": "Thu, 01 Jan 1970 00:00:01 GMT",
            "Content-Length": str(len(raw)),
        },
    }
    artifacts = {"type": "S3", "packaging": "NONE"}
    receipt = {
        "schema": "codebuild-managed-s3-v1",
        "build": {
            "id": build_id,
            "projectName": "project",
            "buildComplete": True,
            "buildStatus": "SUCCEEDED",
            "secondarySources": [],
            "secondaryArtifacts": [],
            "artifacts": artifacts,
        },
        "logs": {"build": build_id},
        "artifact": {"provider": provider, "object": observed},
        "witness": {"source_path": "Makefile", "archive_member": "source/Makefile"},
    }
    monkeypatch.setattr(codebuild_s3, "_read_capture", lambda *_: receipt)

    def assess():
        return codebuild_s3.codebuild_s3_observation(
            capture, tmp_path, arn, "https://github.com/example/repo"
        )

    without_checksum = assess()
    assert without_checksum["state"] == "managed-s3-link-unverified"
    assert without_checksum["influence"]["comparison"] == "exact"
    receipt["build"]["arn"] = arn
    assert assess() == without_checksum
    for conflicting in (None, arn.replace("us-east-1", "us-west-2")):
        receipt["build"]["arn"] = conflicting
        rejected = assess()
        assert rejected["state"] == "unresolved"
        assert "ARN conflicts" in rejected["reason"]
        assert "publication" not in rejected
    del receipt["build"]["arn"]
    for field in ("sha256sum", "sha256Checksum"):
        provider[field] = digest
        result = assess()
        assert result["publication"].pop("provider_checksum_scope") == "unverified-for-child-object"
        assert result == without_checksum
        del provider[field]

    provider["sha256sum"] = digest
    artifacts["packaging"] = "ZIP"
    outside_profile = assess()
    assert outside_profile["state"] == "unresolved"
    assert "does not support packaged CodeBuild outputs" in outside_profile["reason"]

    artifacts["packaging"] = "NONE"
    observed["archive_sha256"] = "0" * 64
    corrupt = assess()
    assert corrupt["state"] == "unresolved"
    assert "Saved ZIP differs" in corrupt["reason"]
