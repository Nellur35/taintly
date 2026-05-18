"""URL-construction tests for :class:`JenkinsClient._request`.

The method appends ``/api/json`` to the endpoint path automatically.
When a caller passes a path that already carries a query string
(``/?depth=1`` from :meth:`JenkinsClient.jobs`, or ``?tree=…`` shapes
that future endpoints may use), ``/api/json`` must be inserted before
the ``?`` so Jenkins receives a valid endpoint with the query
preserved — not a query whose value is ``1/api/json``.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any
from unittest.mock import patch

from taintly.platform.jenkins_client import JenkinsClient


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._buf = BytesIO(json.dumps(payload).encode())

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _capture_url(path: str) -> str:
    """Drive ``_request`` with ``path`` and return the URL the client
    handed to ``urllib.request.urlopen``."""
    client = JenkinsClient("https://jenkins.example.com", user="u", token="t")
    captured: dict[str, str] = {}

    def fake_urlopen(req: Any, timeout: int = 0) -> _FakeResponse:
        captured["url"] = req.full_url
        return _FakeResponse({"ok": True})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client._request(path)

    return captured["url"]


def test_request_appends_api_json_to_bare_root():
    assert _capture_url("/") == "https://jenkins.example.com/api/json"


def test_request_preserves_query_string_after_api_json():
    """``/?depth=1`` must produce ``/api/json?depth=1`` — not
    ``/?depth=1/api/json``, which Jenkins parses as a query value of
    ``1/api/json`` and rejects."""
    assert _capture_url("/?depth=1") == "https://jenkins.example.com/api/json?depth=1"


def test_request_preserves_query_on_subpath():
    assert (
        _capture_url("/job/foo?tree=builds[*]")
        == "https://jenkins.example.com/job/foo/api/json?tree=builds[*]"
    )


def test_request_does_not_double_append_api_json():
    assert _capture_url("/api/json") == "https://jenkins.example.com/api/json"


def test_request_handles_subpath_without_query():
    assert _capture_url("/pluginManager") == "https://jenkins.example.com/pluginManager/api/json"
