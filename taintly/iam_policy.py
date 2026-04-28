"""IAM policy blast-radius classifier.

Pure-Python (stdlib ``json``) parser for AWS IAM policy documents.  Given
a policy JSON, returns a :class:`BlastRadius` verdict that categorises
the policy's potential impact if an attacker obtained the federated
token it grants.

Used by (future) PSE-GH-002 to escalate ``PSE-GH-001`` findings when a
local IAM policy file can be matched to the ``role-to-assume`` ARN
referenced in the workflow.  Shipped standalone here so the scoring
logic can be unit-tested and audited independently of the rule engine.

Limitations (intentional — "blast-radius signal" not "IAM emulator"):
  * Evaluates ``Allow`` statements only; ``Deny`` semantics are not
    implemented (would need full evaluation-logic fidelity).
  * Treats ``Resource: "*"`` + broad ``Action`` alternation as the
    strongest signal; narrower ``Resource:`` ARNs mute the signal one
    tier (HIGH → MEDIUM).
  * Ignores ``Condition`` keys.  A real IAM evaluator would fold these
    in; this classifier is deliberately conservative about the upper
    bound because "assume no conditions fire on attacker-triggered
    invocation" is the threat-model-correct default.
  * Does not resolve managed-policy ARNs (``arn:aws:iam::aws:policy/…``)
    to their contents.  Callers working against a repo with local
    policy JSON have the inline policies by construction; managed
    policies are out of scope until the follow-up integration PR.

References:
  * AWS IAM policy evaluation logic — https://docs.aws.amazon.com/IAM/
    latest/UserGuide/reference_policies_evaluation-logic.html
  * The Service Authorization Reference
    (action-list source of truth per AWS service).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum

# AWS action prefixes that grant broad write / exfil access on the
# "blast-radius of a single compromised agent call" axis.  Each entry
# is compared by ``action.startswith(prefix)`` — so ``iam:`` matches
# ``iam:PassRole``, ``iam:CreateAccessKey``, etc.
#
# Curated for attacker-utility, not completeness.  A narrow read-only
# like ``s3:GetObject`` on a non-secret bucket is not in this set even
# though its prefix ``s3:`` is — the prefix check runs against the
# wildcard ``s3:*`` form only.
_CRITICAL_WILDCARD_ACTION_PREFIXES: frozenset[str] = frozenset(
    {
        # Cross-service wildcards — nothing matches ``*:*`` except *:*.
        "*",
        # Broad IAM wildcards let the agent mint new access keys, pass
        # roles to Lambda/EC2, create login profiles.  Any iam:* is
        # effectively full account takeover.
        "iam:*",
        # Full STS lets an attacker trade the OIDC token for any role
        # the account trusts.
        "sts:*",
        # Broad secrets access is "read every secret" — trivial exfil.
        "secretsmanager:*",
        "ssm:*",
        # KMS Decrypt is the key under the encrypted lake.
        "kms:*",
        # S3 full — read all buckets, write to all buckets.  Includes
        # the terraform state bucket by default.
        "s3:*",
        # Lambda full — invoke any function, or Update + Invoke to
        # exfil secrets from any function's env.
        "lambda:*",
        # Cloud-wide writes — EC2/ECS/EKS full = pivot into compute.
        "ec2:*",
        "ecs:*",
        "eks:*",
        # CodeBuild / CodePipeline — run attacker-defined pipelines.
        "codebuild:*",
        "codepipeline:*",
        # Cross-account: organizations lets an attacker invite their
        # own account into your org as a member.
        "organizations:*",
    }
)

# Specific non-wildcard actions that individually are pivot primitives.
# An allow on any ONE of these is enough to escalate blast radius.
_CRITICAL_SPECIFIC_ACTIONS: frozenset[str] = frozenset(
    {
        # sts:AssumeRole can be chained if the returned role trusts
        # broader principals.  sts:AssumeRoleWithWebIdentity is the
        # OIDC entry point — having it callable by the agent AGAIN
        # is re-federation.
        "sts:AssumeRole",
        "sts:AssumeRoleWithWebIdentity",
        # Create access keys for any IAM user → persistent credentials.
        "iam:CreateAccessKey",
        # Update / attach / create policies = self-escalation.
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        # Grant an existing principal a new role — passes through
        # Lambda/EC2/ECS assume bounds.
        "iam:PassRole",
        # Control-plane login pathways.
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        # Read-all secrets forms (non-wildcard).
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",  # With Resource: * is broadly damaging.
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        # KMS decrypt — unlocks anything encrypted under account keys.
        "kms:Decrypt",
        "kms:ReEncrypt",
        # Lambda invoke + update = exfil any function's env secrets
        # (write permission covered by lambda:* but specific Update
        # alone warrants escalation).
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
    }
)


class BlastRadius(str, Enum):
    """Ordinal ranking of the policy's worst-case impact.

    Ordered from least to most severe.  ``UNKNOWN`` is distinct from
    ``MINIMAL`` — ``UNKNOWN`` means "we couldn't parse this" (treat
    defensively); ``MINIMAL`` means "we parsed it and it grants very
    narrow capabilities".
    """

    UNKNOWN = "unknown"
    MINIMAL = "minimal"  # Read-only on narrow resource.
    MODERATE = "moderate"  # Read-all or write-narrow.
    HIGH = "high"  # Specific high-impact actions OR broad read.
    CRITICAL = "critical"  # Wildcard actions or pivot primitives.


@dataclass
class PolicyVerdict:
    """Result of classifying a parsed IAM policy.

    :attr radius: The computed :class:`BlastRadius`.
    :attr triggering_actions: The specific actions that drove the
        verdict (for reporter output).  Includes resource-scoping
        notes when ``Resource`` is not ``"*"``.
    :attr parse_error: Populated if JSON parse or schema validation
        failed; ``radius`` is then :attr:`BlastRadius.UNKNOWN`.
    """

    radius: BlastRadius
    triggering_actions: list[str] = field(default_factory=list)
    parse_error: str = ""


def classify_policy(policy_json: str) -> PolicyVerdict:
    """Parse an IAM policy document and return its blast-radius verdict.

    Accepts the standard ``{"Version": "...", "Statement": [...]}``
    shape.  A single statement (dict) is also accepted as shorthand.
    """
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return PolicyVerdict(
            radius=BlastRadius.UNKNOWN, parse_error=f"invalid JSON: {e.msg} at line {e.lineno}"
        )

    if not isinstance(policy, dict):
        return PolicyVerdict(
            radius=BlastRadius.UNKNOWN, parse_error="policy root must be an object"
        )

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        # Shorthand: a single statement inline.
        statements = [statements]
    if not isinstance(statements, list):
        return PolicyVerdict(radius=BlastRadius.UNKNOWN, parse_error="Statement must be an array")

    # Accumulate the strongest signal across all Allow statements.
    verdict_radius = BlastRadius.MINIMAL
    triggering: list[str] = []
    saw_any_allow = False

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            # Deny semantics are out of scope.  Skipping Deny is
            # conservative: worst-case we assume no denies override,
            # which is the attacker's best-case scenario and the
            # right basis for a blast-radius upper bound.
            continue
        # A statement with ``Principal`` (or ``NotPrincipal``) is a
        # resource / trust policy statement: ``Action: "sts:AssumeRole"``
        # there describes "who may assume THIS role", not "what this
        # role can do".  Classifying that as CRITICAL is a hard FP — it
        # fires on every sane CloudFormation / CDK trust policy.  The
        # classifier is scoped to identity policies; skip trust
        # statements so they don't drive the verdict.
        if "Principal" in stmt or "NotPrincipal" in stmt:
            continue
        saw_any_allow = True

        actions = _normalize_list(stmt.get("Action"))
        # Resource semantics: we need to know whether the statement is
        # scoped or wildcard-ish.  ``_resource_is_wildcard`` looks at
        # the RAW value, so a list of CloudFormation ``Fn::GetAtt``
        # references (resolved to specific ARNs at deploy time) is
        # correctly treated as "specific resources" — not as an empty
        # list that ``_normalize_list`` would flatten to "wildcard".
        # This was an FP surfaced by running the classifier across
        # aws-cdk-examples: ``iam:PassRole`` + ``Resource: [Fn::GetAtt,
        # Fn::GetAtt, ...]`` was classified CRITICAL when the intent
        # was HIGH (specific roles, resolved at deploy time).
        raw_resource = stmt.get("Resource")
        has_wildcard_resource = _resource_is_wildcard(raw_resource)
        resources = _normalize_list(raw_resource)
        stmt_radius, stmt_hits = _classify_statement(actions, resources, has_wildcard_resource)

        if _radius_order(stmt_radius) > _radius_order(verdict_radius):
            verdict_radius = stmt_radius
            triggering = stmt_hits
        elif stmt_radius == verdict_radius:
            triggering.extend(stmt_hits)

    if not saw_any_allow:
        return PolicyVerdict(radius=BlastRadius.MINIMAL, triggering_actions=[], parse_error="")

    # Dedupe while preserving order for reporter stability.
    seen: set[str] = set()
    deduped: list[str] = []
    for a in triggering:
        if a not in seen:
            seen.add(a)
            deduped.append(a)

    return PolicyVerdict(radius=verdict_radius, triggering_actions=deduped)


def _classify_statement(
    actions: list[str], resources: list[str], has_wildcard_resource: bool
) -> tuple[BlastRadius, list[str]]:
    """Classify one Allow statement in isolation.

    ``has_wildcard_resource`` is pre-computed against the RAW Resource
    value (by ``_resource_is_wildcard``) so opaque entries — e.g.
    CloudFormation ``Fn::GetAtt`` dicts — don't get mis-treated as
    "absent" and inflate the verdict.
    """
    if not actions:
        return BlastRadius.MINIMAL, []

    triggering: list[str] = []
    worst = BlastRadius.MINIMAL

    for action in actions:
        # 1. Full wildcard — always CRITICAL regardless of Resource,
        #    because `*` includes IAM/STS/secretsmanager writes.
        if action == "*":
            triggering.append("*  (all actions)")
            return BlastRadius.CRITICAL, triggering

        # 2. Service-wildcard against a curated CRITICAL set — CRITICAL
        #    on ``Resource: *``, HIGH when narrowed by a specific Resource.
        if action in _CRITICAL_WILDCARD_ACTION_PREFIXES:
            if has_wildcard_resource:
                triggering.append(f"{action}  (Resource: *)")
                if _radius_order(BlastRadius.CRITICAL) > _radius_order(worst):
                    worst = BlastRadius.CRITICAL
            else:
                resource_note = resources[0] if len(resources) == 1 else f"{len(resources)} ARNs"
                triggering.append(f"{action}  (Resource: {resource_note})")
                if _radius_order(BlastRadius.HIGH) > _radius_order(worst):
                    worst = BlastRadius.HIGH
            continue

        # 3. Specific pivot-primitive actions — CRITICAL if resource
        #    is wildcard or a broad ARN (contains the service-level
        #    wildcard), HIGH otherwise.
        if action in _CRITICAL_SPECIFIC_ACTIONS:
            if has_wildcard_resource or _any_resource_is_broad(resources):
                triggering.append(f"{action}  (Resource: {_format_resources(resources)})")
                if _radius_order(BlastRadius.CRITICAL) > _radius_order(worst):
                    worst = BlastRadius.CRITICAL
            else:
                triggering.append(f"{action}  (Resource: {_format_resources(resources)})")
                if _radius_order(BlastRadius.HIGH) > _radius_order(worst):
                    worst = BlastRadius.HIGH
            continue

        # 4. A service-prefix-wildcard action not in the curated
        #    CRITICAL set (e.g. ``dynamodb:*``).  Counts as MODERATE
        #    on Resource:* and MINIMAL on a narrow resource — still
        #    worth surfacing on narrow triage, not an escalation.
        if action.endswith(":*"):
            if has_wildcard_resource:
                triggering.append(f"{action}  (service-wildcard, Resource: *)")
                if _radius_order(BlastRadius.MODERATE) > _radius_order(worst):
                    worst = BlastRadius.MODERATE

    return worst, triggering


def _radius_order(r: BlastRadius) -> int:
    return {
        BlastRadius.UNKNOWN: -1,
        BlastRadius.MINIMAL: 0,
        BlastRadius.MODERATE: 1,
        BlastRadius.HIGH: 2,
        BlastRadius.CRITICAL: 3,
    }[r]


def _normalize_list(value: object) -> list[str]:
    """Accept a string or a list of strings; return list of strings.

    Non-string entries (typically CloudFormation ``{"Fn::GetAtt": ...}``
    / ``{"Ref": ...}`` references resolved at deploy time) are dropped
    from the returned list.  Callers that need to know whether the
    ORIGINAL value was wildcard must use :func:`_resource_is_wildcard`
    against the raw value instead of inferring from the normalized
    list — otherwise ``[Fn::GetAtt, Fn::GetAtt]`` (specific deploy-time
    ARNs) collapses to ``[]`` and looks like "no Resource" = wildcard.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _resource_is_wildcard(raw_resource: object) -> bool:
    """Return True when the Resource is wildcard-like.

    Wildcard-like means:
      - absent entirely (``None``),
      - the literal string ``"*"``,
      - a list containing ``"*"``.

    A list of CloudFormation function references (``Fn::GetAtt``,
    ``Ref``, etc.) is specific-by-construction and NOT wildcard:
    those references resolve to concrete ARNs at deploy time and the
    classifier should treat them as bounded.
    """
    if raw_resource is None:
        return True
    if raw_resource == "*":
        return True
    return isinstance(raw_resource, list) and any(
        r == "*" for r in raw_resource if isinstance(r, str)
    )


def _any_resource_is_broad(resources: list[str]) -> bool:
    """Return True if ANY resource ARN uses a service-wildcard suffix
    or a partition/account wildcard — common patterns that defeat the
    narrow-resource muting.

    Examples:
      - ``arn:aws:secretsmanager:*:*:secret:*`` — all secrets in all
        accounts (CRITICAL).
      - ``arn:aws:iam::123456789012:role/*`` — all roles in one
        account (also CRITICAL for IAM actions).
    """
    for r in resources:
        if r == "*":
            return True
        if r.endswith(":*"):
            return True
        if "/*" in r and ":role/" in r:
            return True
        # Cross-account wildcard — `arn:aws:sts::*:...` lets the
        # token assume roles in other accounts.
        if "::*:" in r:
            return True
    return False


def _format_resources(resources: list[str]) -> str:
    if not resources:
        return "*"
    if len(resources) == 1:
        return resources[0]
    return f"{resources[0]} (+ {len(resources) - 1} more)"
