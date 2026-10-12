"""Boundary controls for untrusted IAM snapshots and invocation association."""

import json
from urllib.parse import quote

import pytest

from taintly.models import Finding, Severity
from taintly.pse_enrichment import enrich_pse_findings

ARN = "arn:aws:iam::123456789012:role/AgentRole"
WORKFLOW = (
    "on: pull_request_target\npermissions:\n  id-token: write\n"
    "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: aws-actions/configure-aws-credentials@v4\n"
    "        with:\n"
    "          aws-region: us-east-1\n"
    f"          role-to-assume: {ARN}\n"
    "      - uses: anthropics/claude-code-action@v1\n"
)


def run(tmp_path, body, workflow=WORKFLOW):
    wf = tmp_path / ".github/workflows/test.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(workflow, encoding="utf-8")
    policy = tmp_path / "iam/AgentRole.json"
    policy.parent.mkdir(exist_ok=True)
    policy.write_text(body, encoding="utf-8")
    line = next(i for i, row in enumerate(workflow.splitlines(), 1) if "anthropics/" in row)
    finding = Finding("PSE-GH-001", Severity.HIGH, "Agent", "Base", str(wf), line=line)
    return enrich_pse_findings([finding], str(tmp_path))[0]


def inventory(document):
    return json.dumps(
        {
            "RoleDetailList": [
                {
                    "Arn": ARN,
                    "RolePolicyList": [
                        {"PolicyName": "inline", "PolicyDocument": document},
                    ],
                }
            ]
        }
    )


def policy(resource="*", **extra):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": resource,
                **extra,
            }
        ],
    }


def test_plain_json_string_preserves_percent_escaped_literal_resource(tmp_path):
    result = run(tmp_path, inventory(json.dumps(policy("arn:aws:iam::123456789012:role/%2A"))))
    assert result.severity == Severity.HIGH
    assert result.review_needed


def test_urlencoded_policy_document_is_decoded_once(tmp_path):
    result = run(tmp_path, inventory(quote(json.dumps(policy()), safe="")))
    assert result.severity == Severity.CRITICAL
    assert result.review_needed
    assert "/RoleDetailList/0/RolePolicyList/0/PolicyDocument" in result.description


@pytest.mark.parametrize(
    "body",
    ["[" * 1100 + "0" + "]" * 1100, '{"n":' + "9" * 5000 + "}"],
    ids=["depth-limit", "integer-limit"],
)
def test_adversarial_json_remains_unresolved_without_crashing(tmp_path, body):
    result = run(tmp_path, body)
    assert result.severity == Severity.HIGH
    assert result.review_needed
    assert any("unknown" in note.casefold() for note in result.context_notes)


@pytest.mark.parametrize("setting", ["if: false", "with:\n          output-env-credentials: false"])
def test_conditional_or_redirected_credential_step_does_not_certify_binding(tmp_path, setting):
    if setting.startswith("with:"):
        workflow = WORKFLOW.replace("        with:\n", "        " + setting + "\n")
    else:
        workflow = WORKFLOW.replace("        with:\n", f"        {setting}\n        with:\n")
    result = run(tmp_path, inventory(policy()), workflow)
    assert result.severity == Severity.HIGH
    assert result.review_needed


def test_later_role_configuration_cannot_supply_prior_agent_authority(tmp_path):
    rows = WORKFLOW.splitlines(keepends=True)
    workflow = "".join(rows[:7] + rows[-1:] + rows[7:-1])
    result = run(tmp_path, inventory(policy()), workflow)
    assert result.severity == Severity.HIGH
    assert result.review_needed


def test_allow_plus_deny_is_only_a_qualified_allow_upper_bound(tmp_path):
    document = policy()
    document["Statement"].append({"Effect": "Deny", "Action": "*", "Resource": "*"})
    result = run(tmp_path, inventory(document))
    assert result.severity == Severity.CRITICAL
    assert result.review_needed
    assert "before Deny" in result.description
    assert "does not prove" in result.description


def test_inline_policy_schema_with_unhashable_version_stays_unknown(tmp_path):
    document = policy()
    document["Version"] = []
    result = run(tmp_path, inventory(document))
    assert result.severity == Severity.HIGH
    assert result.review_needed


@pytest.mark.parametrize("extra", [{"NotAction": "iam:PassRole"}, {"NotResource": "*"}])
def test_contradictory_policy_elements_cannot_establish_inline_grant(tmp_path, extra):
    result = run(tmp_path, inventory(policy(**extra)))
    assert result.severity == Severity.HIGH
    assert result.review_needed


@pytest.mark.parametrize(
    "workflow",
    [
        WORKFLOW.replace("configure-aws-credentials@v4", "configure-aws-credentials"),
        WORKFLOW.replace("role-to-assume:", "role-arn:"),
        WORKFLOW.replace("          aws-region: us-east-1\n", ""),
        WORKFLOW.replace("  review:\n", "  review:\n    if: false\n"),
    ],
    ids=["missing-ref", "unsupported-input", "missing-required-region", "disabled-owning-job"],
)
def test_invalid_or_unreachable_configuration_remains_candidate(tmp_path, workflow):
    result = run(tmp_path, inventory(policy()), workflow)
    assert result.severity == Severity.HIGH
    assert result.review_needed


def test_iam_search_bound_is_disclosed_and_does_not_remove_base_finding(tmp_path, monkeypatch):
    import taintly.pse_enrichment as enrichment

    monkeypatch.setattr(enrichment, "_MAX_TOTAL_POLICY_BYTES", 1)
    result = run(tmp_path, inventory(policy()))
    assert result.severity == Severity.HIGH
    assert result.review_needed
    assert any("bounded" in note for note in result.context_notes)


def test_agent_command_inside_run_block_binds_to_exact_job(tmp_path):
    workflow = WORKFLOW.replace(
        "      - uses: anthropics/claude-code-action@v1\n",
        "      - run: |\n          echo start\n          anthropics/agent\n",
    )
    result = run(tmp_path, inventory(policy()), workflow)
    assert result.severity == Severity.CRITICAL
    assert result.review_needed
    assert "jobs/review/steps/1" in result.description


def test_invalid_condition_shape_cannot_certify_inline_policy(tmp_path):
    result = run(tmp_path, inventory(policy(Condition=[])))
    assert result.severity == Severity.HIGH
    assert result.review_needed


def test_urlencoded_document_with_invalid_utf8_stays_unknown(tmp_path):
    encoded = quote(json.dumps(policy()), safe="").replace("iam%3APassRole", "iam%3APassRole%FF")
    result = run(tmp_path, inventory(encoded))
    assert result.severity == Severity.HIGH
    assert result.review_needed
