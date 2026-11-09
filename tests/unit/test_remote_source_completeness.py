"""Known acquisition gaps must reach the actual report and exit decision."""
from __future__ import annotations

import base64
import json
import sys
from unittest.mock import Mock

import pytest

from taintly import __main__ as cli
from taintly.ingestion import github_api as gh, gitlab_api as gl
from taintly.source_inventory import SourceInventory, SourceIssue


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: pytest.fail("Unexpected network"))
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Unexpected socket"))


def test_empty_is_distinct_from_failed_inventory():
    assert SourceInventory().complete
    issue = SourceIssue("known/source", "Unavailable")
    assert not SourceInventory(issues=(issue,)).complete
    with pytest.raises(ValueError):
        SourceIssue("", "Unavailable")


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize("empty", [False, True])
def test_cli_known_missing_source_is_not_successful_empty(monkeypatch, capsys, provider, empty):
    import taintly.platform.github_checks as ghc
    import taintly.platform.gitlab_checks as glc
    monkeypatch.setenv("GITHUB_TOKEN", "INERT")
    monkeypatch.setenv("GITLAB_TOKEN", "INERT")
    monkeypatch.setattr(ghc, "run_all_checks", lambda *a: [])
    monkeypatch.setattr(ghc, "run_account_checks", lambda *a: [])
    monkeypatch.setattr(glc, "run_all_checks", lambda *a: [])
    monkeypatch.setattr(glc, "run_group_checks", lambda *a: [])
    if provider == "github":
        monkeypatch.setattr(gh, "list_org_repos", lambda *a: [] if empty else ["known/repo"])
        monkeypatch.setattr(gh, "_get", Mock(side_effect=OSError("PRIVATE DETAIL")))
    else:
        monkeypatch.setattr(gl, "list_group_projects", lambda *a: [] if empty else [{"id": 1}])
        monkeypatch.setattr(gl, "_get_raw", Mock(side_effect=OSError("PRIVATE DETAIL")))
    option = "--github-org" if provider == "github" else "--gitlab-group"
    monkeypatch.setattr(sys, "argv", ["taintly", option, "known", "--no-config", "--format", "json", "--min-severity", "CRITICAL"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert result.value.code == (0 if empty else 11)
    assert report["files_scanned"] == 0
    assert bool(report["errors"]) is not empty
    assert "PRIVATE DETAIL" not in output.out + output.err


@pytest.mark.parametrize("data", ["%%%", base64.b64encode(b"\xff").decode()])
def test_github_corrupt_source_is_unresolved_not_replacement_text(monkeypatch, data):
    monkeypatch.setattr(gh, "_get", lambda path, token: [{"name": "broken.yml", "type": "file"}]
                        if path.endswith("/workflows") else {"content": data})
    inventory = gh.fetch_workflow_files("known/repo", "INERT")
    assert not inventory.items and not inventory.complete
    assert inventory.issues[0].source == "known/repo/.github/workflows/broken.yml"


def test_empty_gitlab_file_is_available_not_failed_or_absent(monkeypatch):
    monkeypatch.setattr(gl, "list_group_projects", lambda *a: [{"id": 1}])
    monkeypatch.setattr(gl, "_get_raw", lambda *a: b"")
    inventory = gl.fetch_group_pipelines("known", "INERT")
    assert inventory.items == (("1/.gitlab-ci.yml", ""),) and inventory.complete


@pytest.mark.parametrize("payload", [{"unexpected": "response"}, [None]])
def test_github_bad_listing_is_not_complete_empty(monkeypatch, payload):
    monkeypatch.setattr(gh, "_get", lambda *a: payload)
    assert not gh.fetch_workflow_files("known/repo", "INERT").complete


def test_github_repository_failure_retains_other_repository(monkeypatch):
    monkeypatch.setattr(gh, "list_org_repos", lambda *a: ["known/bad", "known/good"])
    def fetch(repo, token):
        if repo.endswith("bad"):
            raise OSError("PRIVATE DETAIL")
        return SourceInventory((("known/good/.github/workflows/ci.yml", "on: push\n"),))
    monkeypatch.setattr(gh, "fetch_workflow_files", fetch)
    result = gh.fetch_org_workflows("known", "INERT")
    assert len(result.items) == len(result.issues) == 1
    assert result.issues[0].source == "known/bad/.github/workflows"
    assert "PRIVATE DETAIL" not in result.issues[0].reason
