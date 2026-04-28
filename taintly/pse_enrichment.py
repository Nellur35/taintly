"""Permission Slip Effect — IAM-policy escalation pass (PSE-GH-002).

PSE-GH-001 fires at HIGH on the (fork-reachable trigger + AI agent +
cloud-credential grant) triangle without knowing what the federated
token actually unlocks.  PSE-GH-002 closes that loop: it walks the
repo for an IAM policy document attached to the role the workflow
assumes (``aws-actions/configure-aws-credentials@v* with: role-to-
assume:``) and, if the policy classifies as :class:`BlastRadius.CRITICAL`,
escalates the existing PSE-GH-001 finding to ``Severity.CRITICAL`` and
appends the triggering actions to its description.

Scoping (intentional, not accidental):

  * Absence of evidence is NOT escalation. If no local policy file
    matches the ARN, the finding stays at HIGH — we don't punish a
    repo for keeping IAM in a separate Terraform module.
  * Matching is "ARN string OR role name appears in the policy file"
    plus a successful :func:`classify_policy` parse.  Naïve substring
    matching keeps us zero-dep; HCL-aware matching is a follow-up.
  * Both ``*.json`` (CloudFormation, raw policies, CDK output) and
    ``*.tf`` (Terraform inline ``policy = jsonencode({...})`` /
    heredoc) are scanned.  HCL ``jsonencode({...})`` blocks are not
    valid JSON until evaluated by Terraform; we extract heredoc-
    delimited JSON blocks instead, which IS the dominant idiom (the
    Terraform docs themselves use this form).

Wired in :func:`taintly.engine.scan_repo` after the per-file scan so
the enrichment runs once per scan, not once per rule.
"""

from __future__ import annotations

import os
import re

from .iam_policy import BlastRadius, classify_policy
from .models import Finding, Severity

# Match `role-to-assume:` / `role-arn:` values in a YAML workflow.  Both
# the bare key form (`role-to-assume: arn:...`) and the quoted form
# (`role-to-assume: "arn:..."`) are accepted.  We anchor on the key so a
# bare ARN literal sitting in a comment or run-block doesn't false-match.
_ROLE_KEY_RE = re.compile(
    r"^\s*(?:role-to-assume|role-arn)\s*:\s*['\"]?(arn:aws:iam::[0-9]+:role/[A-Za-z0-9_+=,.@/\-]+)['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)

# IAM policy doc heuristic: a JSON-ish blob containing `"Statement"`.
# Used to triage candidate text inside .tf heredocs without first
# parsing it as JSON (which would fail on Terraform interpolations).
_LOOKS_LIKE_POLICY_DOC_RE = re.compile(r'"Statement"\s*:', re.MULTILINE)

# Heredoc body extractor for Terraform inline policy assignments.
# Matches `policy = <<EOF` / `policy = <<-EOF` / `policy = <<JSON` etc.
# Captures the body until the matching marker on its own line.  We only
# extract heredocs assigned to a `policy` / `assume_role_policy` /
# `inline_policy` style key — narrowing avoids over-extracting unrelated
# Terraform heredocs (e.g. user-data shell scripts).
_TF_HEREDOC_POLICY_RE = re.compile(
    r"\b(?:policy|assume_role_policy|inline_policy|policy_document)\s*=\s*<<-?(\w+)\s*\n(.*?)\n\s*\1\s*$",
    re.MULTILINE | re.DOTALL,
)

# Directory names that conventionally hold IAM policies. Restricting the
# walk to these (plus the repo root) keeps the enrichment cheap on large
# monorepos and avoids classifying random JSON found in node_modules /
# vendor / fixtures.  Repo root .json/.tf files are scanned regardless.
_POLICY_DIR_HINTS: frozenset[str] = frozenset(
    {"iam", "policies", "policy", "infrastructure", "infra", "terraform", "cloudformation", "cfn"}
)

# Skip these directories outright — large, noisy, and never the source
# of truth for repo IAM.
_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}
)

# Cap the number of policy files we'll classify per scan.  A pathological
# monorepo with 10k JSON files shouldn't blow up the scan budget.  Real
# repos have <50; pick 500 for headroom.
_MAX_POLICY_FILES = 500


def extract_role_arns(workflow_content: str) -> list[str]:
    """Return the list of IAM role ARNs the workflow assumes via OIDC.

    Empty list if no ``role-to-assume:`` / ``role-arn:`` key is present.
    Duplicates are preserved in source order — callers usually only
    need ``arns[0]`` but the whole list is available for jobs that
    assume multiple roles.
    """
    return [m.group(1) for m in _ROLE_KEY_RE.finditer(workflow_content)]


def _role_name_from_arn(arn: str) -> str:
    """Return the role name component of an IAM role ARN.

    For ``arn:aws:iam::123:role/MyRole`` returns ``"MyRole"``.  For
    ``arn:aws:iam::123:role/path/to/MyRole`` returns ``"MyRole"`` (the
    final path component) — IAM allows nested role paths.
    """
    if ":role/" not in arn:
        return ""
    tail = arn.split(":role/", 1)[1]
    return tail.rsplit("/", 1)[-1]


def _iter_candidate_files(repo_path: str) -> list[str]:
    """Yield .json and .tf files under repo_path likely to hold IAM policy.

    Includes:
      * Every .json / .tf at the repo root.
      * Every .json / .tf under a directory whose name matches
        :data:`_POLICY_DIR_HINTS` (recursively).

    Skips directories listed in :data:`_SKIP_DIRS`.  Capped at
    :data:`_MAX_POLICY_FILES` to bound the cost on monorepos.
    """
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune in-place so os.walk doesn't recurse into junk dirs.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        rel = os.path.relpath(dirpath, repo_path)
        rel_parts = [] if rel == "." else rel.split(os.sep)
        is_root = rel == "."
        is_in_policy_dir = any(p in _POLICY_DIR_HINTS for p in rel_parts)

        if not is_root and not is_in_policy_dir:
            continue

        for fname in filenames:
            if fname.endswith((".json", ".tf")):
                out.append(os.path.join(dirpath, fname))
                if len(out) >= _MAX_POLICY_FILES:
                    return out
    return out


def _candidate_policy_strings(filepath: str, content: str) -> list[str]:
    """Extract one or more candidate IAM policy JSON strings from a file.

    For ``.json`` the file content itself is the candidate (one string).
    For ``.tf`` we extract heredoc-delimited bodies assigned to
    ``policy`` / ``assume_role_policy`` / ``inline_policy`` /
    ``policy_document``.  Bodies that don't pass the
    :data:`_LOOKS_LIKE_POLICY_DOC_RE` triage are dropped before
    classification — saves us calling :func:`classify_policy` on
    bash heredocs that happened to be assigned to a policy-named key.
    """
    if filepath.endswith(".json"):
        return [content]
    if filepath.endswith(".tf"):
        return [
            body
            for _marker, body in _TF_HEREDOC_POLICY_RE.findall(content)
            if _LOOKS_LIKE_POLICY_DOC_RE.search(body)
        ]
    return []


def find_matching_policies(role_arn: str, repo_path: str) -> list[tuple[str, str]]:
    """Return (file, json_str) pairs whose content references ``role_arn``.

    A file is a candidate if it textually contains either the full ARN
    or the role-name suffix (last path component).  The role-name
    suffix is the practical signal: Terraform / CDK projects rarely
    embed the literal ARN — they reference the resource symbolically.

    Returns an empty list if no candidates are found.  This is
    distinguishable from "candidates found but none CRITICAL" by the
    caller (PSE-GH-002 only escalates on a CRITICAL hit).
    """
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return []

    matches: list[tuple[str, str]] = []
    for fpath in _iter_candidate_files(repo_path):
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        # Cheap gate before any regex / JSON work.  A file is
        # considered related when ANY of the following is true:
        #   * its basename contains the role name (the common
        #     ``MyRole.json`` / ``MyRole.tf`` convention);
        #   * the file content textually contains the full ARN;
        #   * the file content textually contains the role name.
        # Otherwise the file is unrelated to this finding.
        basename = os.path.basename(fpath)
        if role_name not in basename and role_arn not in content and role_name not in content:
            continue

        for candidate in _candidate_policy_strings(fpath, content):
            matches.append((fpath, candidate))

    return matches


def _format_triggering_actions(actions: list[str]) -> str:
    """Render the verdict's triggering_actions for inclusion in the
    finding description.  Keep the formatting compact and
    reporter-agnostic — callers append this to the existing text.
    """
    if not actions:
        return ""
    bullets = "\n".join(f"  - {a}" for a in actions[:8])  # Cap at 8 to keep reports tight
    suffix = f"\n  - … (+{len(actions) - 8} more)" if len(actions) > 8 else ""
    return bullets + suffix


def enrich_pse_findings(findings: list[Finding], repo_path: str) -> list[Finding]:
    """Escalate PSE-GH-001 findings to CRITICAL when a matching local
    IAM policy classifies as :attr:`BlastRadius.CRITICAL`.

    Mutation rules:
      * ``severity`` → :attr:`Severity.CRITICAL`
      * ``description`` → original text + an "IAM blast radius:
        CRITICAL" footer naming the policy file and triggering actions
      * ``title`` → prefixed with ``"[CRITICAL IAM blast radius] "``
        so the reporter's truncated views surface the escalation

    A finding is left unchanged when:
      * No ``role-to-assume:`` / ``role-arn:`` key in the workflow file
        (cannot resolve the IAM role).
      * No local policy file matches the ARN (absence of evidence).
      * All matching policies classify below CRITICAL (a HIGH/MODERATE
        verdict is consistent with PSE-GH-001's existing HIGH severity).

    Per-finding cost is bounded by :data:`_MAX_POLICY_FILES` and a single
    re-read of the workflow file.  In practice 0–3 PSE-GH-001 findings
    fire in any one scan.
    """
    pse_findings = [f for f in findings if f.rule_id == "PSE-GH-001"]
    if not pse_findings:
        return findings

    # Cache (file -> verdict) so two PSE findings on different workflows
    # that point at the same role pay for classification once.
    verdict_cache: dict[str, tuple[BlastRadius, list[str]]] = {}

    for finding in pse_findings:
        if not finding.file:
            continue
        try:
            with open(finding.file, encoding="utf-8", errors="replace") as f:
                workflow_content = f.read()
        except OSError:
            continue

        arns = extract_role_arns(workflow_content)
        if not arns:
            continue

        worst_radius = BlastRadius.MINIMAL
        worst_actions: list[str] = []
        worst_file = ""
        for arn in arns:
            for policy_path, policy_json in find_matching_policies(arn, repo_path):
                cache_key = f"{policy_path}::{policy_json[:64]}"
                if cache_key in verdict_cache:
                    radius, actions = verdict_cache[cache_key]
                else:
                    verdict = classify_policy(policy_json)
                    radius, actions = verdict.radius, verdict.triggering_actions
                    verdict_cache[cache_key] = (radius, actions)

                # Track the worst hit across all matched policies for
                # this finding — a workflow can assume more than one
                # role, and IAM auditors care about the upper bound.
                from .iam_policy import _radius_order

                if _radius_order(radius) > _radius_order(worst_radius):
                    worst_radius = radius
                    worst_actions = actions
                    worst_file = policy_path

        if worst_radius != BlastRadius.CRITICAL:
            continue

        finding.severity = Severity.CRITICAL
        finding.title = f"[CRITICAL IAM blast radius] {finding.title}"
        try:
            rel_policy_path = os.path.relpath(worst_file, repo_path)
        except ValueError:
            rel_policy_path = worst_file
        footer = (
            "\n\nPSE-GH-002 escalation — IAM blast radius: CRITICAL.\n"
            f"Matching policy: {rel_policy_path}\n"
            "Triggering actions:\n"
            f"{_format_triggering_actions(worst_actions)}\n"
            "The role assumed by this workflow grants pivot-primitive "
            "actions on a wildcard or broad resource.  An attacker who "
            "steers the agent into minting the federated token can "
            "exercise these actions for arbitrary AWS-account impact."
        )
        finding.description = finding.description + footer

    return findings
