"""GitLab recipient/transport contracts; inert responses, no sockets or secrets."""
from __future__ import annotations

import io
import sys
import urllib.error
import urllib.request
from email.message import Message
from urllib.response import addinfourl

import pytest

from taintly import _gitlab_transport as transport
from taintly.ingestion import gitlab_api
from taintly.platform.gitlab_client import APIError, GitLabClient
from taintly.platform.token import TokenManager


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("GitLab transport tests must not use real network")
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.delenv("GITLAB_URL", raising=False)


def install_transport(monkeypatch, responses):
    calls, handles = [], []

    class InertHTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            calls.append(request)
            code, location, body = responses[len(calls) - 1]
            headers = Message()
            if location is not None:
                headers["Location"] = location
            response = addinfourl(io.BytesIO(body), headers, request.full_url, code)
            response.msg = "inert response"
            handles.append(response)
            return response

    original = urllib.request.build_opener
    monkeypatch.setattr(
        transport.urllib.request, "build_opener",
        lambda *handlers: original(urllib.request.ProxyHandler({}), InertHTTPS(), *handlers),
    )
    return calls, handles


BAD_BASES = [
    "http://gitlab.example.invalid", "ftp://gitlab.example.invalid", "file:///tmp/gitlab",
    "https://", "https://user:inert@gitlab.example.invalid", "https://@gitlab.example.invalid",
    "https://gitlab.example.invalid?", "https://gitlab.example.invalid#",
    "https://gitlab.example.invalid:bad", "https://gitlab.example.invalid:0",
    "https://gitlab.example.invalid:65536", "https://gitlab.example.invalid\n.other.invalid",
    " https://gitlab.example.invalid", "https://gitlab.example.invalid\\other.invalid",
]


@pytest.mark.parametrize("base", BAD_BASES)
@pytest.mark.parametrize("call", ["json", "raw", "posture"])
def test_invalid_base_rejects_before_open_or_credential_read(monkeypatch, base, call):
    monkeypatch.setenv("GITLAB_URL", base)
    monkeypatch.setattr(transport.urllib.request, "build_opener", lambda *_: pytest.fail("unexpected opener"))
    class UnreadableToken:
        @property
        def value(self):
            pytest.fail("invalid destination must not read credentials")
    with pytest.raises(ValueError, match="HTTPS instance URL"):
        if call == "posture":
            GitLabClient(UnreadableToken()).project("demo/repo")
        elif call == "json":
            gitlab_api._get("/projects", "INERT")
        else:
            gitlab_api._get_raw("/source", "INERT")


@pytest.mark.parametrize("base", [
    "https://gitlab.example.invalid", "https://gitlab.example.invalid:8443/prefix/",
    "https://GITLAB.EXAMPLE.INVALID:443/prefix",
])
@pytest.mark.parametrize("call", ["json", "raw", "posture"])
def test_valid_self_hosted_instance_preserves_source_and_authentication(monkeypatch, base, call):
    monkeypatch.setenv("GITLAB_URL", base)
    calls, handles = install_transport(monkeypatch, [(200, None, b'{"observed":true}')])
    if call == "posture":
        token = TokenManager("INERT", "test")
        try:
            assert GitLabClient(token).project("demo/repo") == {"observed": True}
        finally:
            token.clear()
    elif call == "json":
        assert gitlab_api._get("/projects?page=1", "INERT") == {"observed": True}
    else:
        assert gitlab_api._get_raw("/source?ref=HEAD", "INERT") == b'{"observed":true}'
    assert len(calls) == 1 and calls[0].full_url.startswith(base.rstrip("/") + "/api/v4/")
    assert calls[0].get_header("Private-token") == "INERT"
    assert handles[0].closed


@pytest.mark.parametrize("target", [
    "https://different.example.invalid/path", "http://gitlab.example.invalid/path",
    "https://gitlab.example.invalid:8443/path", "https://user:inert@gitlab.example.invalid/path",
])
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_actual_opener_blocks_cross_origin_and_downgrade_before_second_request(monkeypatch, target, code):
    calls, handles = install_transport(monkeypatch, [(code, target, b"inert redirect")])
    with pytest.raises(transport.GitLabTransportError, match="unsafe redirect") as result:
        gitlab_api._get("/projects", "INERT_PRIVATE_TEST")
    assert len(calls) == 1 and handles[0].closed
    assert "INERT_PRIVATE_TEST" not in str(result.value)


@pytest.mark.parametrize("target", [
    "/api/v4/moved?page=2", "https://GITLAB.COM:443/api/v4/moved?page=2",
])
def test_same_origin_redirect_retains_auth_and_parses_response(monkeypatch, target):
    calls, handles = install_transport(monkeypatch, [(302, target, b"redirect"), (200, None, b"[]")])
    assert gitlab_api._get("/projects", "INERT") == []
    assert len(calls) == 2 and all(request.get_header("Private-token") == "INERT" for request in calls)
    assert all(handle.closed for handle in handles)


def test_redirect_refusal_aborts_group_acquisition_without_success(monkeypatch):
    monkeypatch.setenv("GITLAB_URL", "https://gitlab.example.invalid")
    calls, handles = install_transport(monkeypatch, [
        (200, None, b'[{"id":1,"path_with_namespace":"demo/available"},{"id":2,"path_with_namespace":"demo/missing"}]'),
        (200, None, b"job:\n  script: echo inert\n"),
        (302, "https://other.example.invalid/source", b"redirect"),
    ])
    with pytest.raises(transport.GitLabTransportError, match="unsafe redirect"):
        gitlab_api.fetch_group_pipelines("demo", "INERT")
    assert len(calls) == 3 and all(handle.closed for handle in handles)


def test_invalid_group_url_has_non_successful_cli_outcome(monkeypatch, capsys):
    from taintly import __main__ as cli
    monkeypatch.setenv("GITLAB_URL", "http://gitlab.example.invalid")
    monkeypatch.setenv("GITLAB_TOKEN", "INERT_PRIVATE_TEST")
    monkeypatch.setattr(sys, "argv", ["taintly", "--gitlab-group", "demo", "--format", "json", "--no-config"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 3
    output = capsys.readouterr()
    assert not output.out.strip() and "INERT_PRIVATE_TEST" not in output.err
    assert "HTTPS instance URL" in output.err


def test_initial_request_cannot_be_bound_to_another_recipient(monkeypatch):
    monkeypatch.setattr(transport.urllib.request, "build_opener", lambda *_: pytest.fail("unexpected opener"))
    request = urllib.request.Request("https://other.example.invalid/source", headers={"PRIVATE-TOKEN": "INERT"})
    with pytest.raises(ValueError, match="configured HTTPS instance"):
        transport.open_gitlab(request, base_url="https://gitlab.example.invalid")


@pytest.mark.parametrize("code", [404, 403, 500])
def test_posture_error_response_is_closed_without_changing_absence_policy(monkeypatch, code):
    calls, handles = install_transport(monkeypatch, [(code, None, b"inert error")])
    token = TokenManager("INERT", "test")
    try:
        client = GitLabClient(token)
        if code == 404:
            assert client.project("demo/repo") is None
        else:
            with pytest.raises(APIError) as raised:
                client.project("demo/repo")
            assert raised.value.status == code
    finally:
        token.clear()
    assert len(calls) == 1 and handles[0].closed


def test_redirect_cleanup_failure_cannot_continue_to_another_recipient(monkeypatch):
    class FailedClose:
        def close(self):
            raise OSError("inert cleanup failure")
    handler = transport._SameOriginRedirect("https://gitlab.com")
    request = urllib.request.Request("https://gitlab.com/api/v4/projects")
    with pytest.raises(transport.GitLabTransportError, match="cleanup failed"):
        handler.redirect_request(request, FailedClose(), 302, "inert", {}, "https://other.invalid/path")


@pytest.mark.parametrize("mode", ["project", "group-source", "group-posture"])
def test_refused_recipient_reaches_actual_non_successful_cli(monkeypatch, capsys, mode):
    from taintly import __main__ as cli

    monkeypatch.setenv("GITLAB_URL", "https://gitlab.example.invalid")
    monkeypatch.setenv("GITLAB_TOKEN", "INERT_PRIVATE_TEST")
    responses = [(302, "https://other.example.invalid/source", b"inert redirect")]
    arguments = ["--platform-audit", "--gitlab-project", "demo/repo"]
    if mode == "group-source":
        responses.insert(0, (200, None, b'[{"id":1,"path_with_namespace":"demo/repo"}]'))
        arguments = ["--gitlab-group", "demo"]
    elif mode == "group-posture":
        monkeypatch.setattr(gitlab_api, "fetch_group_pipelines", lambda *_: [])
        monkeypatch.setattr(gitlab_api, "list_group_projects", lambda *_: [{"id": 1}])
        arguments = ["--gitlab-group", "demo"]
    calls, handles = install_transport(monkeypatch, responses)
    active_before = list(TokenManager._active)
    monkeypatch.setattr(sys, "argv", ["taintly", *arguments, "--format", "json", "--no-config"])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == (11 if mode == "group-posture" else 3)
    output = capsys.readouterr()
    if mode == "group-posture":
        import json

        assert len(json.loads(output.out)["errors"]) == 1
    else:
        assert not output.out.strip()
    assert "unsafe redirect" in output.err and "INERT_PRIVATE_TEST" not in output.err
    assert len(calls) == len(responses) and all(handle.closed for handle in handles)
    assert TokenManager._active == active_before


def test_refused_group_posture_keeps_previously_analyzed_source_findings(monkeypatch, capsys):
    import json

    from taintly import __main__ as cli

    source = "job:\n  script: curl https://example.invalid/tool.sh | bash\n"
    monkeypatch.setenv("GITLAB_URL", "https://gitlab.example.invalid")
    monkeypatch.setenv("GITLAB_TOKEN", "INERT_PRIVATE_TEST")
    monkeypatch.setattr(
        gitlab_api, "fetch_group_pipelines",
        lambda *_: [("demo/repo/.gitlab-ci.yml", source)],
    )
    monkeypatch.setattr(gitlab_api, "list_group_projects", lambda *_: [{"id": 1}])
    calls, handles = install_transport(
        monkeypatch, [(302, "https://other.example.invalid/source", b"inert redirect")]
    )
    monkeypatch.setattr(sys, "argv", [
        "taintly", "--gitlab-group", "demo", "--format", "json", "--no-config",
    ])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 1
    output = capsys.readouterr()
    document = json.loads(output.out)
    assert any(f["rule_id"] == "SEC6-GL-002" for f in document["findings"])
    assert len(document["errors"]) == 1
    assert "unsafe redirect" in document["errors"][0]["title"]
    assert "INERT_PRIVATE_TEST" not in output.out + output.err
    assert len(calls) == 1 and handles[0].closed


@pytest.mark.parametrize("mode", ["project", "group"])
@pytest.mark.parametrize("minimum", ["INFO", "CRITICAL"])
def test_refusal_keeps_completed_posture_checks_and_stops_remaining_requests(monkeypatch, capsys, mode, minimum):
    import json

    from taintly import __main__ as cli

    monkeypatch.setenv("GITLAB_URL", "https://gitlab.example.invalid")
    monkeypatch.setenv("GITLAB_TOKEN", "INERT_PRIVATE_TEST")
    arguments = ["--platform-audit", "--gitlab-project", "demo/repo"]
    if mode == "group":
        monkeypatch.setattr(gitlab_api, "fetch_group_pipelines", lambda *_: [])
        monkeypatch.setattr(gitlab_api, "list_group_projects", lambda *_: [{"id": "demo/repo"}, {"id": "unvisited/repo"}])
        arguments = ["--gitlab-group", "demo"]
    calls, handles = install_transport(monkeypatch, [
        (200, None, b'{"default_branch":"main"}'),
        (404, None, b"not protected"),
        (200, None, b'[{"approvals_required":0}]'),
        (302, "https://other.example.invalid/variables", b"refused"),
    ])
    active = list(TokenManager._active)
    monkeypatch.setattr(sys, "argv", ["taintly", *arguments, "--format", "json", "--no-config", "--min-severity", minimum])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    expected = {"PLAT-GL-001", "PLAT-GL-002"} if minimum == "INFO" else {"PLAT-GL-001"}
    actual = {f["rule_id"] for f in report["findings"] if f["rule_id"] != "ENGINE-ERR"}
    assert actual == expected
    assert all(f["file"] == "gitlab:demo/repo" for f in report["findings"])
    [error] = report["errors"]
    assert error["file"] == "gitlab:demo/repo"
    assert "PLAT-GL-003" in error["title"]
    assert "INERT_PRIVATE_TEST" not in captured.out + captured.err
    assert len(calls) == 4 and all(handle.closed for handle in handles)
    assert not any("unvisited" in request.full_url for request in calls)
    assert TokenManager._active == active
