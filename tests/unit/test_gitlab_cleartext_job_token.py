"""Authored contrasts for direct job-token form submission over HTTP."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.models import Platform
from taintly.reporters.json_report import format_json
from taintly.rules.registry import load_rules_for_platform


def _scan(tmp_path: Path, item: str, *, prefix: str = ""):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(prefix + "deploy:\n  script:\n    - " + item + "\n", encoding="utf8")
    return scan_file(str(path), load_rules_for_platform(Platform.GITLAB))


def _selected(findings):
    return [finding for finding in findings if finding.rule_id == "SEC6-GL-011"]


def test_direct_http_form_through_engine_and_json(tmp_path: Path) -> None:
    item = "'curl --request POST --form \"token=$CI_JOB_TOKEN\" http://ci.example.test/api/v4/projects/9/trigger/pipeline'"
    findings = _scan(tmp_path, item)
    selected = _selected(findings)
    assert len(selected) == 1
    assert selected[0].line == 3
    assert selected[0].review_needed
    notes = " ".join(selected[0].context_notes)
    assert hashlib.sha256((tmp_path / ".gitlab-ci.yml").read_bytes()).hexdigest() in notes
    assert "configured cleartext transport" in notes
    assert "intercepted" in notes

    report = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.GITLAB), platform=Platform.GITLAB
    )[0]
    output = json.loads(format_json(report))
    assert len([f for f in output["findings"] if f["rule_id"] == "SEC6-GL-011"]) == 1


def test_url_before_form_is_still_a_direct_path(tmp_path: Path) -> None:
    item = "'curl http://ci.example.test/trigger --form token=$CI_JOB_TOKEN'"
    assert len(_selected(_scan(tmp_path, item))) == 1


@pytest.mark.parametrize(
    "item",
    [
        "'curl --request POST --form \"token=$CI_JOB_TOKEN\" https://gitlab.example.test/api/v4/projects/9/trigger/pipeline'",
        "'curl --request POST -H \"JOB-TOKEN: $CI_JOB_TOKEN\" --form ref=main http://ci.example.test/api/v4/projects/9/trigger/pipeline'",
        "\"curl --request POST --form 'token=$CI_JOB_TOKEN' http://ci.example.test/api/v4/projects/9/trigger/pipeline\"",
        "'echo curl --form \"token=$CI_JOB_TOKEN\" http://ci.example.test/api/v4/projects/9/trigger/pipeline'",
    ],
)
def test_authentication_and_nonexecuting_contrasts_do_not_claim_cleartext_form(
    tmp_path: Path, item: str
) -> None:
    assert not _selected(_scan(tmp_path, item))


def test_comment_only_candidate_does_not_add_incomplete_diagnostic(tmp_path: Path) -> None:
    source = (
        "shared: &shared\n  script:\n    - echo ready\n"
        "deploy:\n  <<: *shared\n"
        "  # curl --form token=$CI_JOB_TOKEN http://ci.example.test/collect\n"
    )
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(source, encoding="utf8")
    findings = scan_file(str(path), load_rules_for_platform(Platform.GITLAB))
    assert not _selected(findings)
    assert not any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_source_override_remains_unresolved(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "'curl --form token=$CI_JOB_TOKEN http://ci.example.test/collect'",
        prefix="variables:\n  CI_JOB_TOKEN: replacement\n",
    )
    assert not _selected(findings)
    assert any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_unsupported_form_syntax_remains_unresolved(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "'curl --form=token=$CI_JOB_TOKEN http://ci.example.test/collect'")
    assert not _selected(findings)
    assert any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_token_embedded_in_form_value_remains_unresolved(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "'curl --form ref=prefix$CI_JOB_TOKEN http://ci.example.test/collect'"
    )
    assert not _selected(findings)
    assert any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_script_scalar_outside_list_item_profile_remains_unresolved(tmp_path: Path) -> None:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        "deploy:\n  script: 'curl --form token=$CI_JOB_TOKEN http://ci.example.test/collect'\n",
        encoding="utf8",
    )
    findings = scan_file(str(path), load_rules_for_platform(Platform.GITLAB))
    assert not _selected(findings)
    assert any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_override_in_another_job_does_not_change_this_jobs_binding(tmp_path: Path) -> None:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        "other:\n  variables:\n    CI_JOB_TOKEN: replacement\n  script:\n    - echo ready\n"
        "deploy:\n  script:\n    - 'curl --form token=$CI_JOB_TOKEN http://ci.example.test/collect'\n",
        encoding="utf8",
    )
    findings = scan_file(str(path), load_rules_for_platform(Platform.GITLAB))
    assert len(_selected(findings)) == 1
    assert not any(f.rule_id == "ENGINE-ERR" and "SEC6-GL-011" in f.description for f in findings)


def test_separate_jobs_cannot_supply_the_missing_token_form(tmp_path: Path) -> None:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        "first:\n  script:\n    - 'curl --form token=$CI_JOB_TOKEN https://gitlab.example.test/trigger'\n"
        "second:\n  script:\n    - 'curl --form token=$OTHER http://ci.example.test/trigger'\n",
        encoding="utf8",
    )
    assert not _selected(scan_file(str(path), load_rules_for_platform(Platform.GITLAB)))
