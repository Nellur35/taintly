"""Credential-shaped literals must be owned by executable buildspec commands."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def rules():
    return load_rules_for_platform(Platform.CODEBUILD)


def scan(tmp_path: Path, rules, command: str):
    body = "\n".join("        " + line for line in command.splitlines())
    (tmp_path / "buildspec.yml").write_text(
        "version: 0.2\nphases:\n  build:\n    commands:\n      - |\n" + body + "\n",
        encoding="utf-8",
    )
    return [
        f
        for r in scan_repo(str(tmp_path), rules, Platform.CODEBUILD)
        for f in r.findings
        if f.rule_id == "SEC6-CB-001"
    ]


@pytest.mark.parametrize(
    "command",
    [
        'export SERVICE_PASSWORD="synthetic literal"',
        "BUILD_API_TOKEN='dummy-fixed-value' ./release",
        "echo ready\nSIGNING_PRIVATE_KEY='synthetic-private-key'",
        "export APP_SECRET=fixture-only # bounded literal binding",
    ],
)
def test_literal_assignments_are_visible(tmp_path, rules, command):
    findings = scan(tmp_path, rules, command)
    assert len(findings) == 1
    assert "=" in findings[0].snippet


@pytest.mark.parametrize(
    "command",
    [
        "echo 'export SERVICE_PASSWORD=just-example-text'",
        'export SERVICE_PASSWORD="$MANAGED_PASSWORD"',
        'export SERVICE_PASSWORD="$(aws secretsmanager get-secret-value)"',
        'export SERVICE_PASSWORD=""',
        'export SERVICE_PASSWORD="***"',
        'export CACHE_KEY="linux-deps-v2"',
        'export DEPLOY_KEY="ambiguous-not-proven-sensitive"',
        'export PUBLIC_KEY="ssh-ed25519 public-key-data"',
        '"SERVICE_PASSWORD=not-an-assignment"',
        "# export SERVICE_PASSWORD=comment-only",
        "cat <<'DOC'\nexport SERVICE_PASSWORD=example-in-document\nDOC",
        'printf "%s\\n" "document starts\nSERVICE_PASSWORD=example-text\nends here"',
    ],
)
def test_inert_or_unproven_values_stay_quiet(tmp_path, rules, command):
    assert not scan(tmp_path, rules, command)


def test_managed_secret_alias_remains_quiet(tmp_path, rules):
    (tmp_path / "buildspec.yml").write_text(
        'version: 0.2\nenv:\n  secrets-manager:\n    SERVICE_PASSWORD: "prod/service:password"\n'
        'phases:\n  build:\n    commands:\n      - export SERVICE_PASSWORD="$SERVICE_PASSWORD"\n',
        encoding="utf-8",
    )
    assert not any(
        f.rule_id == "SEC6-CB-001"
        for r in scan_repo(str(tmp_path), rules, Platform.CODEBUILD)
        for f in r.findings
    )


def test_config_text_does_not_become_command(tmp_path, rules):
    (tmp_path / "buildspec.yml").write_text(
        'version: 0.2\nenv:\n  variables:\n    EXAMPLE: "export SERVICE_PASSWORD=example-text"\n'
        "phases:\n  build:\n    commands:\n      - echo ready\n",
        encoding="utf-8",
    )
    assert not any(
        f.rule_id == "SEC6-CB-001"
        for r in scan_repo(str(tmp_path), rules, Platform.CODEBUILD)
        for f in r.findings
    )


def test_folded_yaml_continuation_remains_command_data(tmp_path, rules):
    (tmp_path / "buildspec.yml").write_text(
        "version: 0.2\nphases:\n  build:\n    commands:\n      - >-\n"
        "        echo example\n        SERVICE_PASSWORD=not-an-assignment\n",
        encoding="utf-8",
    )
    assert not any(
        f.rule_id == "SEC6-CB-001"
        for r in scan_repo(str(tmp_path), rules, Platform.CODEBUILD)
        for f in r.findings
    )
