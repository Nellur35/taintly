"""Regression controls for a bounded S3 archive source witness."""

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
