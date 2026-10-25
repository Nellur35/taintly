"""Authored Vault selector contrasts; they are not field-accuracy evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Severity
from taintly.rules.registry import get_rule_by_id


def _scan(tmp_path: Path, source: str):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(source, encoding="utf8")
    rule = get_rule_by_id("TAINT-GL-007")
    assert rule is not None
    return scan_file(str(path), [rule])


@pytest.mark.parametrize(
    "vault",
    [
        "vault:\n        engine: {name: kv-v2, path: ops}\n"
        '        path: "$CI_COMMIT_REF_NAME/db"\n'
        "        field: password",
        'vault: {engine: {name: kv-v2, path: ops}, path: "${CI_COMMIT_REF_NAME}/db", field: password}',
        '"vault":\n        "engine": {name: kv-v2, path: ops}\n'
        '        "path": "$CI_COMMIT_REF_NAME/db"\n'
        '        "field": password',
    ],
)
def test_structured_selector_is_review_candidate(tmp_path: Path, vault: str) -> None:
    source = f"job:\n  secrets:\n    TOKEN:\n      {vault}\n  script: echo done\n"
    findings = _scan(tmp_path, source)
    selected = [finding for finding in findings if finding.rule_id == "TAINT-GL-007"]
    assert len(selected) == 1
    assert selected[0].severity is Severity.HIGH
    assert selected[0].review_needed
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]


def test_short_form_is_unresolved_not_proven_selector(tmp_path: Path) -> None:
    source = (
        "job:\n  secrets:\n    TOKEN:\n"
        '      vault: "$CI_COMMIT_REF_NAME/db/password@ops"\n'
        "  script: echo done\n"
    )
    findings = _scan(tmp_path, source)
    assert not [finding for finding in findings if finding.rule_id == "TAINT-GL-007"]
    incomplete = [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    assert len(incomplete) == 1
    assert "short-form Vault variable expansion" in incomplete[0].description


@pytest.mark.parametrize(
    "source",
    [
        "job:\n  secrets:\n    TOKEN:\n      vault:\n"
        "        engine: {name: kv-v2, path: ops}\n"
        "        path: production/db\n        field: password\n",
        "job:\n  script: |\n    cat > example.yml <<'EOF'\n"
        "    vault: {engine: {name: kv-v2, path: ops}, "
        'path: "$CI_COMMIT_REF_NAME/db", field: password}\n    EOF\n',
        "job:\n  secrets:\n    TOKEN:\n      vault:\n"
        "        engine: {name: kv-v2, path: ops}\n"
        '        path: "$CI_ENVIRONMENT_NAME/db"\n        field: password\n',
    ],
)
def test_no_external_selector_path(tmp_path: Path, source: str) -> None:
    findings = _scan(tmp_path, source)
    assert not [
        finding for finding in findings if finding.rule_id in {"TAINT-GL-007", "ENGINE-ERR"}
    ]


def test_structured_path_without_explicit_engine_remains_unresolved(tmp_path: Path) -> None:
    source = (
        "job:\n  secrets:\n    TOKEN:\n      vault:\n"
        '        path: "$CI_COMMIT_REF_NAME/db"\n'
        "        field: password\n"
    )
    findings = _scan(tmp_path, source)
    assert not [finding for finding in findings if finding.rule_id == "TAINT-GL-007"]
    assert len([finding for finding in findings if finding.rule_id == "ENGINE-ERR"]) == 1


def test_hidden_vault_template_needs_concrete_owner(tmp_path: Path) -> None:
    source = (
        ".secrets_template:\n  secrets:\n    TOKEN:\n      vault:\n"
        "        engine: {name: kv-v2, path: ops}\n"
        '        path: "$CI_COMMIT_REF_NAME/db"\n'
        "        field: password\n"
    )
    findings = _scan(tmp_path, source)
    assert not [finding for finding in findings if finding.rule_id == "TAINT-GL-007"]
    assert len([finding for finding in findings if finding.rule_id == "ENGINE-ERR"]) == 1


def test_unrelated_jobs_are_not_joined(tmp_path: Path) -> None:
    source = (
        "example:\n  script: |\n"
        '    echo "vault: $CI_COMMIT_REF_NAME/db/password@ops"\n'
        "other:\n  secrets:\n    TOKEN:\n      vault:\n"
        "        engine: {name: kv-v2, path: ops}\n"
        "        path: production/db\n        field: password\n"
    )
    findings = _scan(tmp_path, source)
    assert not [
        finding for finding in findings if finding.rule_id in {"TAINT-GL-007", "ENGINE-ERR"}
    ]
