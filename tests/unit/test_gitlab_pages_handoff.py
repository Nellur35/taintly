"""Validation for saved Pages handoff ZIP and runner evidence."""
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile, ZipInfo

import pytest

from taintly.ingestion.gitlab_pages_handoff import _members, _transfer
from taintly.ingestion.gitlab_registry_job import RegistryJobError


def _zip_bytes(entries: list[tuple[str | ZipInfo, bytes]]) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def test_saved_pages_directory_compares_content_by_relative_member():
    archive = _zip_bytes([("website/", b""), ("website/docs/index.html", b"website")])
    assert _members(archive, "website") == {"docs/index.html": sha256(b"website").hexdigest()}


@pytest.mark.parametrize(
    "entries",
    [
        [("website/../public/index.html", b"x")],
        [("website/a", b"x"), ("website/a/index.html", b"y")],
        [("public/index.html", b"x")],
    ],
)
def test_saved_pages_archive_does_not_assign_ambiguous_members(entries):
    with pytest.raises(RegistryJobError, match="members"):
        _members(_zip_bytes(entries), "website")


def test_saved_pages_archive_rejects_a_raw_backslash_in_the_zip_name():
    raw_name = ZipInfo("website/index.html")
    raw_name.filename = r"website\index.html"
    data = _zip_bytes([(raw_name, b"site")])
    with ZipFile(BytesIO(data)) as archive:
        assert archive.infolist()[0].orig_filename == r"website\index.html"
    with pytest.raises(RegistryJobError, match="members"):
        _members(data, "website")


def test_saved_pages_archive_rejects_nonregular_member():
    link = ZipInfo("website/index.html")
    link.create_system = 3
    link.external_attr = 0o120777 << 16
    with pytest.raises(RegistryJobError, match="unsupported file entries"):
        _members(_zip_bytes([(link, b"index-source.html")]), "website")


def _row(line: int, value: str) -> dict[str, object]:
    time = "2026-01-01T00:00:00Z"
    return {"line": line, "time": time, "value": value, "sha256": sha256(f"{time} {value}".encode()).hexdigest()}


def test_pages_handoff_checks_named_download_and_script_order():
    publisher = {
        "log": {"rows": [None, None, _row(10, "sources end"), _row(15, "script start"), _row(18, "script end")]},
        "transfer": [
            _row(11, "00O+section_start:1767225600:download_artifacts"),
            _row(12, "01O Downloading artifacts for site-builder (11)..."),
            _row(13, "01E Downloading artifacts from coordinator... ok correlation_id=" + "a" * 32 + " id=11 status=200"),
            _row(14, "00O section_end:1767225600:download_artifacts"),
            _row(16, "01O $ mv website public"),
            _row(17, "01O $ cp redirects.txt public/_redirects"),
        ],
    }
    commands = ("mv website public", "cp redirects.txt public/_redirects")
    assert _transfer(publisher, "site-builder", 11, commands) == [11, 12, 13, 14, 16, 17]
    publisher["transfer"][-1] = _row(14, "01O $ cp redirects.txt public/_redirects")
    with pytest.raises(RegistryJobError, match="not inside the owning job phases"):
        _transfer(publisher, "site-builder", 11, commands)
