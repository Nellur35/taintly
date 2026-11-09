"""Native request-helper ownership, with inert responses and retained errors."""
from __future__ import annotations

import base64
import io
import json
import urllib.error
from unittest.mock import Mock

import pytest

from taintly.ingestion import github_api as gh, gitlab_api as gl
from taintly.source_inventory import SourceInventory


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_, **__):
        pytest.fail("ingestion lifetime tests must not reach a real network")
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.delenv("GITLAB_URL", raising=False)


def _request(monkeypatch, provider, response):
    if provider == "github-json":
        monkeypatch.setattr(gh.urllib.request, "urlopen", Mock(side_effect=response) if isinstance(response, Exception) else Mock(return_value=response))
        return lambda: gh._get("/repos/demo/workflows", "INERT")
    monkeypatch.setattr(gl, "open_gitlab", Mock(side_effect=response) if isinstance(response, Exception) else Mock(return_value=response))
    if provider == "gitlab-json":
        return lambda: gl._get("/projects", "INERT")
    return lambda: gl._get_raw("/source", "INERT")


@pytest.mark.parametrize("provider", ["github-json", "gitlab-json", "gitlab-raw"])
@pytest.mark.parametrize("status", [404, 403, 500])
def test_retained_original_error_is_closed_without_changing_status_or_identity(monkeypatch, provider, status):
    body = io.BytesIO(b"inert response")
    error = urllib.error.HTTPError("https://example.invalid/source", status, "inert", {}, body)
    request = _request(monkeypatch, provider, error)
    with pytest.raises(urllib.error.HTTPError) as raised:
        request()
    assert raised.value is error and raised.value.code == status
    # Keep the error alive: this tests deterministic ownership, not GC timing.
    assert body.closed


@pytest.mark.parametrize("provider", ["github-json", "gitlab-json", "gitlab-raw"])
def test_success_returns_the_same_content_and_closes_response(monkeypatch, provider):
    body = io.BytesIO(b'{"available":true}')
    result = _request(monkeypatch, provider, body)()
    assert result == (b'{"available":true}' if provider == "gitlab-raw" else {"available": True})
    assert body.closed


@pytest.mark.parametrize("provider", ["github-json", "gitlab-json"])
def test_decode_failure_also_closes_successfully_opened_response(monkeypatch, provider):
    body = io.BytesIO(b"not JSON")
    with pytest.raises(json.JSONDecodeError):
        _request(monkeypatch, provider, body)()
    assert body.closed


@pytest.mark.parametrize("status", [403, 500])
def test_gitlab_available_sibling_survives_closed_failure(monkeypatch, status):
    monkeypatch.setattr(gl, "list_group_projects", lambda *_: [
        {"id": 1, "path_with_namespace": "demo/good"}, {"id": 2, "path_with_namespace": "demo/missing"}])
    good = io.BytesIO(b"job:\n  script: echo hello\n")
    bad = io.BytesIO(b"inert error")
    error = urllib.error.HTTPError("https://gitlab.com/source", status, "inert", {}, bad)
    monkeypatch.setattr(gl, "open_gitlab", Mock(side_effect=[good, error]))
    result = gl.fetch_group_pipelines("demo", "INERT")
    assert result.items == (("demo/good/.gitlab-ci.yml", "job:\n  script: echo hello\n"),)
    assert not result.complete and len(result.issues) == 1
    assert result.issues[0].source == "demo/missing/.gitlab-ci.yml"
    assert good.closed and bad.closed


@pytest.mark.parametrize("status", [403, 500])
def test_github_available_sibling_survives_closed_failure(monkeypatch, status):
    directory = io.BytesIO(json.dumps([{"type": "file", "name": "good.yml"}, {"type": "file", "name": "missing.yml"}]).encode())
    good = io.BytesIO(json.dumps({"encoding": "base64", "content": base64.b64encode(b"on: push\n").decode()}).encode())
    bad = io.BytesIO(b"inert error")
    error = urllib.error.HTTPError("https://api.github.com/source", status, "inert", {}, bad)
    monkeypatch.setattr(gh.urllib.request, "urlopen", Mock(side_effect=[directory, good, error]))
    result = gh.fetch_workflow_files("demo/repo", "INERT")
    assert result.items == (("demo/repo/.github/workflows/good.yml", "on: push\n"),)
    assert not result.complete and len(result.issues) == 1
    assert result.issues[0].source.endswith("/missing.yml")
    assert directory.closed and good.closed and bad.closed


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_absent_source_policy_remains_absent_and_closed(monkeypatch, provider):
    body = io.BytesIO(b"not found")
    error = urllib.error.HTTPError("https://example.invalid/source", 404, "missing", {}, body)
    if provider == "github":
        monkeypatch.setattr(gh.urllib.request, "urlopen", Mock(side_effect=error))
        result = gh.fetch_workflow_files("demo/repo", "INERT")
        assert result == SourceInventory()
    else:
        monkeypatch.setattr(gl, "open_gitlab", Mock(side_effect=error))
        assert gl.fetch_gitlab_ci(1, "INERT") is None
    assert body.closed
