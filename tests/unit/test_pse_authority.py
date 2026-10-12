"""Regression tests for evidence-bound PSE IAM inventory enrichment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from taintly.models import Finding, Severity
from taintly.pse_enrichment import enrich_pse_findings

ROLE_ARN = "arn:aws:iam::123456789012:role/AgentRole"
OTHER_ACCOUNT_ROLE = "arn:aws:iam::999999999999:role/AgentRole"
AI_STEP = "      - uses: anthropics/claude-code-action@v1"


def _workflow(*, agent_job: str = "agent", extra_jobs: str = "", step_prefix: str = "") -> str:
    return (
        "name: AI review\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "  id-token: write\n"
        "jobs:\n"
        f"  {agent_job}:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{step_prefix}"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          aws-region: us-east-1\n"
        f"          role-to-assume: {ROLE_ARN}\n"
        f"{AI_STEP}\n"
        f"{extra_jobs}"
    )


def _finding(tmp_path: Path, workflow: str, name: str = "workflow.yml") -> Finding:
    path = tmp_path / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    ai_line = next(i for i, line in enumerate(workflow.splitlines(), 1) if AI_STEP in line)
    return Finding(
        rule_id="PSE-GH-001",
        severity=Severity.HIGH,
        title="AI agent with cloud-credential grant on a fork-reachable event",
        description="Base PSE-GH-001 finding.",
        file=str(path),
        line=ai_line,
        snippet=AI_STEP.strip(),
    )


def _inventory(role_arn: str = ROLE_ARN, *, statements=None) -> dict:
    if statements is None:
        statements = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]
    return {
        "RoleDetailList": [
            {
                "Arn": role_arn,
                "RolePolicyList": [
                    {
                        "PolicyName": "agent-inline-policy",
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
                    }
                ],
            }
        ]
    }


def _write_inventory(tmp_path: Path, document: dict, path: str = "iam/role-inventory.json") -> Path:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
    return target


def _enrich(tmp_path: Path, finding: Finding) -> Finding:
    return enrich_pse_findings([finding], str(tmp_path))[0]


def _full_text(finding: Finding) -> str:
    return "\n".join(
        [finding.title, finding.description, *finding.context_notes, finding.suppression_reason]
    )


def test_suffix_filename_is_candidate_not_effective_permission(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    policies = tmp_path / "iam"
    policies.mkdir()
    (policies / "AgentRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}',
        encoding="utf-8",
    )

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True
    assert "candidate" in _full_text(result).casefold()
    assert "arbitrary AWS-account impact" not in _full_text(result)


def test_role_name_in_unrelated_policy_description_is_not_attachment_evidence(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    _write_inventory(
        tmp_path,
        {
            "Description": "Documentation for AgentRole only; this does not attach a policy.",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
        },
    )

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True
    assert (
        "effective" not in _full_text(result).casefold()
        or "not established" in _full_text(result).casefold()
    )


def test_same_role_name_in_another_aws_account_does_not_match(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    _write_inventory(tmp_path, _inventory(OTHER_ACCOUNT_ROLE))

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True
    assert "999999999999" not in _full_text(result)


def test_inventory_in_different_job_does_not_attach_to_ai_job(tmp_path: Path):
    workflow = (
        "name: AI review\n"
        "on:\n  pull_request:\n"
        "permissions:\n  id-token: write\n"
        "jobs:\n"
        "  agent:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"{AI_STEP}\n"
        "  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          aws-region: us-east-1\n"
        f"          role-to-assume: {ROLE_ARN}\n"
    )
    finding = _finding(tmp_path, workflow)
    _write_inventory(tmp_path, _inventory())

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True


def test_role_key_text_inside_run_block_is_not_credential_configuration(tmp_path: Path):
    workflow = (
        "name: AI review\non:\n  pull_request:\npermissions:\n  id-token: write\n"
        "jobs:\n  agent:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Print example\n"
        "        run: |\n"
        f"          echo 'role-to-assume: {ROLE_ARN}'\n"
        f"{AI_STEP}\n"
    )
    finding = _finding(tmp_path, workflow)
    _write_inventory(tmp_path, _inventory())

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True


def test_trust_relationship_alone_is_not_an_attached_identity_policy(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Resource": "*",
            }
        ],
    }
    _write_inventory(
        tmp_path,
        {"RoleDetailList": [{"Arn": ROLE_ARN, "AssumeRolePolicyDocument": trust}]},
    )

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True


def test_duplicate_key_inventory_is_review_needed_not_positive_evidence(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    policy_file = tmp_path / "iam" / "role-inventory.json"
    policy_file.parent.mkdir(parents=True)
    policy_file.write_text(
        '{"RoleDetailList":[{"Arn":"'
        + ROLE_ARN
        + '","Arn":"'
        + OTHER_ACCOUNT_ROLE
        + '","RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}}]}]}',
        encoding="utf-8",
    )

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True
    assert (
        "duplicate" in _full_text(result).casefold() or "candidate" in _full_text(result).casefold()
    )


def test_exact_structured_inline_policy_is_qualified_as_local_upper_bound(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    inventory_path = _write_inventory(tmp_path, _inventory())
    digest = hashlib.sha256(inventory_path.read_bytes()).hexdigest()

    result = _enrich(tmp_path, finding)
    text = _full_text(result).casefold()
    title_and_description = (result.title + "\n" + result.description).casefold()

    assert result.severity == Severity.CRITICAL
    assert "upper bound" in title_and_description
    assert "snapshot" in title_and_description
    assert digest in _full_text(result)
    assert "role-inventory.json" in _full_text(result)
    assert "deny" in text
    assert "condition" in text
    assert "arbitrary AWS-account impact" not in _full_text(result)


def test_explicit_deny_does_not_create_an_allow_upper_bound(tmp_path: Path):
    finding = _finding(tmp_path, _workflow())
    _write_inventory(
        tmp_path,
        _inventory(statements=[{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]),
    )

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True


def test_changed_inventory_bytes_invalidate_prior_positive_witness(tmp_path: Path):
    workflow = _workflow()
    first = _finding(tmp_path, workflow)
    inventory_path = _write_inventory(tmp_path, _inventory())
    first_result = _enrich(tmp_path, first)
    first_text = _full_text(first_result)
    first_digest = hashlib.sha256(inventory_path.read_bytes()).hexdigest()

    inventory_path.write_text(
        json.dumps(
            _inventory(
                statements=[
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::docs/*"}
                ]
            )
        ),
        encoding="utf-8",
    )
    second = _finding(tmp_path, workflow, name="changed.yml")
    second_result = _enrich(tmp_path, second)

    assert first_digest in first_text
    assert second_result.severity == Severity.HIGH
    assert first_digest not in _full_text(second_result)
    assert second_result.review_needed is True


@pytest.mark.parametrize("malformed", [None, [], {"RoleDetailList": "not-a-list"}])
def test_malformed_inventory_shapes_never_claim_effective_permissions(tmp_path: Path, malformed):
    finding = _finding(tmp_path, _workflow())
    target = tmp_path / "iam" / "role-inventory.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(malformed), encoding="utf-8")

    result = _enrich(tmp_path, finding)

    assert result.severity == Severity.HIGH
    assert result.review_needed is True
    assert "arbitrary AWS-account impact" not in _full_text(result)
