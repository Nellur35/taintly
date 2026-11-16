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


@pytest.mark.parametrize(("bytes_", "kind"), [
    (b"updated\n", "exact"),
    (b"updated\r\n", "lf-crlf-equivalent"),
])
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


def test_saved_object_digest_does_not_replace_provider_bound_artifact_digest(tmp_path, monkeypatch):
    build_id = "project:governed-build"
    arn = f"arn:aws:codebuild:us-east-1:123456789012:build/{build_id}"
    raw = zipped("source/Makefile", b"updated\n")
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / "archive.zip").write_bytes(raw)
    monkeypatch.setattr(codebuild_s3, "_phase_window", lambda *_: (0, 2))
    provider = {"build": build_id, "s3Arn": "arn:aws:s3:::test-bucket/builds/governed-build"}
    observed = {
        "build_id": build_id,
        "http_status": 200,
        "url": "https://s3.us-east-1.amazonaws.com/test-bucket/builds/governed-build/output.zip",
        "archive_sha256": digest,
        "headers": {
            "x-amz-meta-codebuild-buildarn": arn,
            "Last-Modified": "Thu, 01 Jan 1970 00:00:01 GMT",
            "Content-Length": str(len(raw)),
        },
    }
    receipt = {"provider": provider, "object": observed}

    def bind():
        return codebuild_s3._object(receipt, tmp_path, arn, "us-east-1", {"id": build_id})

    assert bind()[-1] is False
    provider["sha256sum"] = digest
    assert bind()[-1] is True
    provider["sha256Checksum"] = "0" * 64
    with pytest.raises(SnapshotError, match="recorded artifact digest conflicts"):
        bind()
