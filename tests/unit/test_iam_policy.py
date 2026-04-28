"""Tests for the IAM policy blast-radius classifier.

Cases grouped by tier:
  * CRITICAL: wildcard actions, pivot primitives with broad resources
  * HIGH: wildcard actions narrowed by Resource, pivot primitives on
    specific resources
  * MODERATE: service-wildcard (non-critical service) on Resource:*
  * MINIMAL: specific read-only actions on narrow resources
  * UNKNOWN: parse errors
"""

from __future__ import annotations

import pytest

from taintly.iam_policy import BlastRadius, classify_policy

# ---------------------------------------------------------------------------
# CRITICAL tier
# ---------------------------------------------------------------------------


def test_full_wildcard_action_star_is_critical():
    verdict = classify_policy(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL
    assert any("*" in a for a in verdict.triggering_actions)


def test_iam_star_is_critical_on_wildcard_resource():
    verdict = classify_policy('{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}')
    assert verdict.radius == BlastRadius.CRITICAL


def test_sts_star_is_critical():
    verdict = classify_policy('{"Statement":[{"Effect":"Allow","Action":"sts:*","Resource":"*"}]}')
    assert verdict.radius == BlastRadius.CRITICAL


def test_secretsmanager_star_is_critical():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


def test_s3_star_is_critical():
    verdict = classify_policy('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')
    assert verdict.radius == BlastRadius.CRITICAL


def test_iam_pass_role_with_wildcard_resource_is_critical():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


def test_secretsmanager_getvalue_wildcard_resource_is_critical():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


def test_secrets_arn_with_service_wildcard_is_critical():
    # arn:aws:secretsmanager:*:*:secret:* — all secrets, all accounts.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue",'
        '"Resource":"arn:aws:secretsmanager:*:*:secret:*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


def test_role_arn_with_trailing_wildcard_is_critical_for_iam_actions():
    # arn:aws:iam::123:role/* — all roles in one account.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole",'
        '"Resource":"arn:aws:iam::123456789012:role/*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


# ---------------------------------------------------------------------------
# HIGH tier — wildcard action narrowed by specific resource
# ---------------------------------------------------------------------------


def test_s3_star_with_specific_bucket_is_high():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"s3:*",'
        '"Resource":"arn:aws:s3:::my-specific-bucket/*"}]}'
    )
    assert verdict.radius == BlastRadius.HIGH


def test_iam_passrole_with_specific_role_is_high():
    # Narrow role ARN — still HIGH because PassRole is a pivot
    # primitive, but not CRITICAL because the pivot target is known.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole",'
        '"Resource":"arn:aws:iam::123:role/specific-lambda-role"}]}'
    )
    assert verdict.radius == BlastRadius.HIGH


def test_lambda_star_on_specific_function_arn_is_high():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"lambda:*",'
        '"Resource":"arn:aws:lambda:us-east-1:123:function:specific"}]}'
    )
    assert verdict.radius == BlastRadius.HIGH


# ---------------------------------------------------------------------------
# MODERATE tier — non-critical service wildcard
# ---------------------------------------------------------------------------


def test_dynamodb_star_on_wildcard_resource_is_moderate():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.MODERATE


def test_cloudwatch_star_on_wildcard_resource_is_moderate():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"cloudwatch:*","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.MODERATE


# ---------------------------------------------------------------------------
# MINIMAL tier — narrow read-only
# ---------------------------------------------------------------------------


def test_s3_getobject_on_specific_bucket_is_minimal():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::my-bucket/config/*"}]}'
    )
    assert verdict.radius == BlastRadius.MINIMAL


def test_explicit_empty_allow_is_minimal():
    # Policy with no Allow statements — nothing matches.
    verdict = classify_policy('{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}')
    assert verdict.radius == BlastRadius.MINIMAL


# ---------------------------------------------------------------------------
# Multi-statement aggregation
# ---------------------------------------------------------------------------


def test_multi_statement_takes_worst_tier():
    # Two statements: one MINIMAL, one CRITICAL — verdict is CRITICAL.
    verdict = classify_policy(
        '{"Statement":['
        '{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"},'
        '{"Effect":"Allow","Action":"iam:*","Resource":"*"}'
        "]}"
    )
    assert verdict.radius == BlastRadius.CRITICAL
    assert any("iam:*" in a for a in verdict.triggering_actions)


def test_shorthand_single_statement_as_dict():
    # Some policies use a single-statement shorthand without the list.
    verdict = classify_policy('{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}')
    assert verdict.radius == BlastRadius.CRITICAL


def test_deny_statements_are_ignored_conservatively():
    # A Deny statement cannot narrow the Allow verdict — this is
    # intentional conservatism.
    verdict = classify_policy(
        '{"Statement":['
        '{"Effect":"Allow","Action":"iam:*","Resource":"*"},'
        '{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}'
        "]}"
    )
    # Still CRITICAL despite the Deny — we over-approximate.
    assert verdict.radius == BlastRadius.CRITICAL


# ---------------------------------------------------------------------------
# Action as list vs string
# ---------------------------------------------------------------------------


def test_action_as_list_mixed_criticality():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}]}'
    )
    # iam:PassRole on Resource:* → CRITICAL.
    assert verdict.radius == BlastRadius.CRITICAL


def test_resource_as_list():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole",'
        '"Resource":["arn:aws:iam::123:role/a","arn:aws:iam::123:role/b"]}]}'
    )
    # Specific (non-wildcard) resources → HIGH, not CRITICAL.
    assert verdict.radius == BlastRadius.HIGH


# ---------------------------------------------------------------------------
# UNKNOWN tier — parse failures
# ---------------------------------------------------------------------------


def test_invalid_json_is_unknown_with_error():
    verdict = classify_policy("{this is not json}")
    assert verdict.radius == BlastRadius.UNKNOWN
    assert verdict.parse_error
    assert "invalid JSON" in verdict.parse_error


def test_trust_policy_with_sts_assumerole_is_not_classified():
    # A trust policy has Principal and `sts:AssumeRole` — this describes
    # WHO can assume the role, not what the role can do.  Classifying it
    # as CRITICAL is a hard FP that fires on every sane CloudFormation
    # / CDK trust policy.  Verified as the dominant false positive when
    # this classifier was run across aws-cdk-examples (19 CRITICAL hits,
    # all on trust policies) before this filter landed.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},'
        '"Action":"sts:AssumeRole"}]}'
    )
    assert verdict.radius == BlastRadius.MINIMAL, (
        f"trust policy was classified {verdict.radius}; the Principal "
        "field should have disqualified it from identity-policy scoring"
    )


def test_identity_policy_with_sts_assumerole_is_still_critical():
    # Belt-and-braces: the FIX for the trust-policy FP must not suppress
    # the real case — an identity policy that genuinely grants
    # sts:AssumeRole on Resource: * is CRITICAL (the role can assume
    # anything).  No Principal field → identity policy → full scoring.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}'
    )
    assert verdict.radius == BlastRadius.CRITICAL


def test_cfn_fngetatt_resource_is_treated_as_specific_not_wildcard():
    # aws-cdk-examples regression: an iam:PassRole policy whose Resource
    # is a list of CloudFormation Fn::GetAtt references resolves to
    # specific role ARNs at deploy time.  A naive filter that drops
    # non-string entries and then treats "empty list" as "wildcard"
    # falsely classifies this as CRITICAL; the intent is HIGH.
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole",'
        '"Resource":[{"Fn::GetAtt":["MyRole","Arn"]},'
        '{"Fn::GetAtt":["OtherRole","Arn"]}]}]}'
    )
    assert verdict.radius == BlastRadius.HIGH, (
        f"CFN Fn::GetAtt resource list got {verdict.radius}; should be HIGH "
        "(deploy-time-specific ARNs are not wildcards)"
    )


def test_cfn_single_fngetatt_resource_is_specific():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":{"Fn::GetAtt":["MyBucket","Arn"]}}]}'
    )
    # A specific opaque Resource = MINIMAL (narrow read).
    assert verdict.radius == BlastRadius.MINIMAL


def test_cfn_ref_resource_is_specific():
    verdict = classify_policy(
        '{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":{"Ref":"MyFunction"}}]}'
    )
    # lambda:* on a specific Ref → HIGH (scoped, not CRITICAL).
    assert verdict.radius == BlastRadius.HIGH


def test_mixed_policy_trust_statement_and_identity_statement():
    # A policy with both a trust statement AND an identity statement —
    # only the identity statement drives the verdict.
    verdict = classify_policy(
        '{"Statement":['
        '{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},'
        '"Action":"sts:AssumeRole"},'
        '{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::my-bucket/*"}'
        "]}"
    )
    # Only the s3:GetObject statement counts — MINIMAL.
    assert verdict.radius == BlastRadius.MINIMAL


def test_non_object_root_is_unknown():
    verdict = classify_policy('["not","an","object"]')
    assert verdict.radius == BlastRadius.UNKNOWN
    assert "root must be an object" in verdict.parse_error


def test_statement_not_array_or_dict_is_unknown():
    verdict = classify_policy('{"Statement":"not a list"}')
    assert verdict.radius == BlastRadius.UNKNOWN
    assert "must be an array" in verdict.parse_error


def test_empty_policy_is_minimal():
    verdict = classify_policy("{}")
    assert verdict.radius == BlastRadius.MINIMAL


# ---------------------------------------------------------------------------
# Ordering invariant — sanity check the BlastRadius enum order
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weaker,stronger",
    [
        (BlastRadius.MINIMAL, BlastRadius.MODERATE),
        (BlastRadius.MODERATE, BlastRadius.HIGH),
        (BlastRadius.HIGH, BlastRadius.CRITICAL),
    ],
)
def test_blast_radius_ordering_is_stable(weaker: BlastRadius, stronger: BlastRadius) -> None:
    from taintly.iam_policy import _radius_order

    assert _radius_order(weaker) < _radius_order(stronger)
