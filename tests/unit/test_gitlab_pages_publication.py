"""Keep the saved Pages receipt, archive digest and sampled response identities tied."""

from datetime import datetime, timezone
from hashlib import sha256

import pytest

from taintly.ingestion.gitlab_pages_publication import _archive_digest, _samples
from taintly.ingestion.gitlab_registry_job import RegistryJobError


_SITE = "https://docs-team.gitlab.io/example/"
_PRODUCER = "https://gitlab.com/docs-team/example/-/jobs/100"
_PAGES = "https://gitlab.com/docs-team/example/-/jobs/101"
_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_pages_digest_checks_only_the_exact_bounded_file(tmp_path, monkeypatch):
    path = tmp_path / "pages-publication.zip"
    data = b"saved archive" * 25_000
    path.write_bytes(data)
    assert _archive_digest(tmp_path, len(data)) == sha256(data).hexdigest()
    with pytest.raises(RegistryJobError, match="before its recorded size"):
        _archive_digest(tmp_path, len(data) + 1)
    with pytest.raises(RegistryJobError, match="exceeds its recorded size"):
        _archive_digest(tmp_path, len(data) - 1)
    monkeypatch.setattr("taintly.ingestion.gitlab_pages_publication._DIGEST_LIMIT", len(data) - 1)
    with pytest.raises(RegistryJobError, match="digest-only byte budget"):
        _archive_digest(tmp_path, len(data))


def _response(url):
    raw = b"<p>Example</p>"
    return {
        "url": url,
        "http_status": 200,
        "observed_at": "2026-01-01T00:00:01Z",
        "size": len(raw),
        "sha256": sha256(raw).hexdigest(),
    }


@pytest.mark.parametrize(
    "change, message",
    [
        ({}, None),
        ({"url": _SITE + "index.html"}, None),
        ({"url": _SITE + "../index.html"}, "route"),
        ({"etag": '"' + "b" * 64 + '"'}, "site ETag"),
        ({"observed_at": "2025-12-31T23:59:59Z"}, "time"),
    ],
)
def test_pages_samples_check_owner_bytes_and_archive_etag(tmp_path, change, message):
    digest = "a" * 64
    for name in ("producer", "archive", "served"):
        (tmp_path / f"pages-{name}-0.bin").write_bytes(b"<p>Example</p>")
    rows = [
        {
            "path": "index.html",
            "producer": _response(_PRODUCER + "/artifacts/raw/dist/index.html"),
            "archive": _response(_PAGES + "/artifacts/raw/public/index.html"),
            "site": _response(_SITE) | {"etag": f'"{digest}"'} | change,
        }
    ]
    args = (tmp_path, rows, _SITE, _PRODUCER, _PAGES, "dist", digest, _TIME, _TIME)
    if message:
        with pytest.raises(RegistryJobError, match=message):
            _samples(*args)
    else:
        assert _samples(*args) == [
            {"path": "index.html", "url": rows[0]["site"]["url"], "sha256": rows[0]["site"]["sha256"]}
        ]
