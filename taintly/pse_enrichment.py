"""Source-bound IAM context for Permission Slip Effect findings.

Names in raw JSON/HCL identify review candidates, never policy attachments.
A saved IAM RoleDetailList inventory can establish a *snapshot-declared inline
attachment* to an exact role in the finding's owning job. Its Allow classification
is an upper bound on that represented policy contribution, not current effective
AWS access or a complete bound on every grant to the role. All remain review-needed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass

from .iam_policy import BlastRadius, classify_policy
from .models import Finding, Severity
from .parsers.structural import Event, EventKind, walk_workflow
from .path_safety import is_within_repo

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
_MAX_POLICY_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_POLICY_BYTES = 16 * 1024 * 1024
_MAX_INVENTORY_ROLES = 1000
_MAX_INLINE_POLICIES = 1000
_ROLE_ARN_RE = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/\-]+"
)


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
    # ``followlinks=False`` (the os.walk default) is set explicitly
    # so a repository whose policy directory is a symlink pointing
    # outside the repo is not silently scanned through the symlink.
    # Documented policy: taintly does not follow symlinks.
    for dirpath, dirnames, filenames in os.walk(repo_path, followlinks=False):
        # Prune in-place so os.walk doesn't recurse into junk dirs.
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)

        rel = os.path.relpath(dirpath, repo_path)
        rel_parts = [] if rel == "." else rel.split(os.sep)
        is_root = rel == "."
        is_in_policy_dir = any(p in _POLICY_DIR_HINTS for p in rel_parts)

        if not is_root and not is_in_policy_dir:
            continue

        for fname in sorted(filenames):
            if fname.endswith((".json", ".tf")):
                path = os.path.join(dirpath, fname)
                if os.path.islink(path) or not is_within_repo(repo_path, path):
                    continue
                out.append(path)
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

    These are unresolved candidates, NOT attachment evidence.
    A file is a candidate if it textually contains either the full ARN
    or the role-name suffix (last path component).  The role-name
    suffix is the practical signal: Terraform / CDK projects rarely
    embed the literal ARN — they reference the resource symbolically.

    Returns an empty list if no candidates are found.  This is
    distinguishable from "candidates found but none CRITICAL" by the
    caller (this pass only escalates on a CRITICAL hit).
    """
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return []

    matches: list[tuple[str, str]] = []
    for fpath in _iter_candidate_files(repo_path):
        try:
            with open(fpath, encoding="utf-8", errors="strict") as f:
                content = f.read(_MAX_POLICY_BYTES + 1)
            if len(content) > _MAX_POLICY_BYTES:
                continue
        except (OSError, UnicodeError):
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


@dataclass(frozen=True)
class _PolicyEvidence:
    path: str
    digest: str
    pointer: str
    policy: str
    snapshot_inline: bool


@dataclass(frozen=True)
class _PolicySource:
    path: str
    digest: str
    content: str
    document: object


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise ValueError(f"non-JSON constant: {value}")


def _strict_json(content: str) -> object:
    return json.loads(content, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)


def _inline_policy(body: object) -> str | None:
    # AWS APIs encode documents; CLI/SDK snapshots may already decode them.
    if isinstance(body, str):
        encoded = body
        try:
            body = _strict_json(encoded)
        except (ValueError, RecursionError):
            from urllib.parse import unquote

            try:
                body = _strict_json(unquote(encoded, errors="strict"))
            except (ValueError, RecursionError):
                return None
    if not isinstance(body, dict) or body.get("Version") not in ("2012-10-17", "2008-10-17"):
        return None
    if set(body) - {"Version", "Id", "Statement"} or (
        "Id" in body and not isinstance(body["Id"], str)
    ):
        return None
    statements = body.get("Statement")
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        return None
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            return None
        # A trust/resource policy is not a role's inline identity grant.
        if "Principal" in statement or "NotPrincipal" in statement:
            return None
        if "NotAction" in statement or "NotResource" in statement:
            return None
        if set(statement) - {"Sid", "Effect", "Action", "Resource", "Condition"}:
            return None
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            return None
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            return None
        for key in ("Action", "Resource"):
            value = statement.get(key)
            if not (
                (isinstance(value, str) and value)
                or (
                    isinstance(value, list)
                    and value
                    and all(isinstance(item, str) and item for item in value)
                )
            ):
                return None
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _load_policy_sources(repo_path: str) -> tuple[list[_PolicySource], bool]:
    sources: list[_PolicySource] = []
    paths = _iter_candidate_files(repo_path)
    bounded = len(paths) >= _MAX_POLICY_FILES
    total_bytes = 0
    for path in paths:
        try:
            with open(path, "rb") as stream:
                raw = stream.read(_MAX_POLICY_BYTES + 1)
            total_bytes += len(raw)
            if total_bytes > _MAX_TOTAL_POLICY_BYTES:
                bounded = True
                break
            if len(raw) > _MAX_POLICY_BYTES:
                bounded = True
                continue
            content = raw.decode("utf-8")
        except (OSError, UnicodeError):
            bounded = True
            continue
        digest = hashlib.sha256(raw).hexdigest()
        document: object = None
        if path.endswith(".json"):
            try:
                document = _strict_json(content)
            except (ValueError, RecursionError):
                pass
        sources.append(_PolicySource(path, digest, content, document))
    return sources, bounded


def _policy_evidence(role_arn: str, sources: list[_PolicySource]) -> list[_PolicyEvidence]:
    evidence: list[_PolicyEvidence] = []
    role_name = _role_name_from_arn(role_arn)
    for source in sources:
        path, digest, content, document = (
            source.path,
            source.digest,
            source.content,
            source.document,
        )
        if isinstance(document, dict) and "RoleDetailList" in document:
            roles = document["RoleDetailList"]
            if not isinstance(roles, list) or len(roles) > _MAX_INVENTORY_ROLES:
                continue
            # Duplicate role identities make a snapshot ambiguous.
            matching = [
                (i, role)
                for i, role in enumerate(roles)
                if isinstance(role, dict) and role.get("Arn") == role_arn
            ]
            if len(matching) != 1:
                continue
            index, role = matching[0]
            policies = role.get("RolePolicyList")
            if not isinstance(policies, list) or len(policies) > _MAX_INLINE_POLICIES:
                continue
            names = [item.get("PolicyName") for item in policies if isinstance(item, dict)]
            if any(not isinstance(name, str) or not name for name in names):
                continue
            if len(names) != len(policies) or len(set(names)) != len(names):
                continue
            for policy_index, item in enumerate(policies):
                body = _inline_policy(item.get("PolicyDocument"))
                if body is not None:
                    evidence.append(
                        _PolicyEvidence(
                            path,
                            digest,
                            f"/RoleDetailList/{index}/RolePolicyList/{policy_index}/PolicyDocument",
                            body,
                            True,
                        )
                    )
            continue
        if not role_name or (
            role_name not in os.path.basename(path)
            and role_arn not in content
            and role_name not in content
        ):
            continue
        for body in _candidate_policy_strings(path, content):
            evidence.append(_PolicyEvidence(path, digest, "", body, False))
    return evidence


def _owning_roles(content: str, finding: Finding) -> tuple[list[str], str]:
    """Resolve one prior same-job configuration; ambiguity remains unknown."""
    events = list(
        walk_workflow(
            finding.file,
            content=content,
            include_keys=True,
            include_merge_origins=True,
        )
    )
    keys: set[tuple[object, ...]] = set()
    leaves: dict[tuple[object, ...], Event] = {}
    owners: set[tuple[object, ...]] = set()
    for event in events:
        if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
            return [], "Workflow structure or merge precedence is unresolved."
        if event.kind == EventKind.MAP_KEY:
            if event.path in keys:
                return [], "Duplicate workflow keys make role scope unresolved."
            keys.add(event.path)
        elif event.kind == EventKind.LEAF_SCALAR:
            if event.path in leaves:
                return [], "Duplicate workflow values make role scope unresolved."
            leaves[event.path] = event
            path = event.path
            if (
                len(path) == 5
                and path[0] == "jobs"
                and path[2] == "steps"
                and isinstance(path[3], int)
                and path[4] in {"uses", "run"}
            ):
                physical = {line for line, _ in event.block_lines or ()}
                if finding.line == event.line or finding.line in physical:
                    owners.add(path[:4])
    if len(owners) != 1:
        return [], "The finding's executable step could not be uniquely resolved."
    owner = next(iter(owners))
    owner_index = owner[3]
    if not isinstance(owner_index, int):
        return [], "The finding's executable step index is unresolved."
    configurations = []
    for path, event in leaves.items():
        if (
            len(path) != 5
            or path[:3] != owner[:3]
            or path[4] != "uses"
            or not isinstance(path[3], int)
            or path[3] >= owner_index
        ):
            continue
        value = event.value or ""
        if value.split("@", 1)[0].casefold() != "aws-actions/configure-aws-credentials":
            continue
        if "@" not in value or not value.rsplit("@", 1)[1] or "${{" in value:
            return [], "The owning credential action reference is unresolved."
        configurations.append(path[:4])
    if len(configurations) != 1:
        return [], "No unique prior AWS credential configuration in the finding's own job."
    prefix = configurations[0]
    # Conditional/redirected credential output cannot establish that the
    # configured role supplies this invocation. Keep that relation unresolved.
    if any(
        path in leaves
        for path in (
            (*prefix, "if"),
            (*owner, "if"),
            (*owner[:2], "if"),
            (*prefix, "with", "export-environment-variables"),
            (*prefix, "with", "output-env-credentials"),
            (*prefix, "with", "output-credentials"),
            (*prefix, "with", "use-existing-credentials"),
        )
    ):
        return [], "Conditional or redirected AWS credentials require review of the owning step."
    region = leaves.get((*prefix, "with", "aws-region"))
    if region is None or not region.value or "${{" in region.value:
        return [], "The credential action's required AWS region is unresolved."
    roles = [
        leaves[path].value for path in ((*prefix, "with", "role-to-assume"),) if path in leaves
    ]
    if len(roles) != 1 or not isinstance(roles[0], str) or not _ROLE_ARN_RE.fullmatch(roles[0]):
        return [], "The owning credential step's exact AWS role identity is unresolved."
    return [roles[0]], f"jobs/{owner[1]}/steps/{owner[3]} (credential step {prefix[3]})"


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
    """Attach qualified local-policy evidence without certifying AWS access.

    Only an exact snapshot inline attachment and unique owning configuration
    can increase the configured severity. Raw policy matches stay candidates.
    Unknowns do not erase the underlying PSE finding or imply a safe role.
    """
    verdict_cache: dict[str, tuple[BlastRadius, list[str]]] = {}
    policy_cache: dict[str, list[_PolicyEvidence]] = {}
    policy_sources: list[_PolicySource] | None = None
    bounded_search = False
    for finding in findings:
        if finding.rule_id != "PSE-GH-001" or not finding.file:
            continue
        try:
            with open(finding.file, "rb") as stream:
                raw_workflow = stream.read(_MAX_POLICY_BYTES + 1)
            if len(raw_workflow) > _MAX_POLICY_BYTES:
                finding.review_needed = True
                finding.context_notes.append("IAM enrichment skipped: workflow exceeds read bound.")
                continue
            content = raw_workflow.decode("utf-8")
        except (OSError, UnicodeError):
            continue

        roles, scope = _owning_roles(content, finding)
        finding.review_needed = True
        finding.context_tags.append("iam_effective_access_unresolved")
        finding.context_notes.append(
            "IAM effective access is not established: local files do not prove deployed "
            "attachments, trust, execution, or effective permissions. Deny, conditions, "
            "permission boundaries, session policies and SCPs are not evaluated."
        )
        if not roles:
            finding.context_notes.append(scope)
            # Keep lexical evidence visible, but it cannot repair an unknown owner.
            candidate_roles = list(dict.fromkeys(extract_role_arns(content)))
            if len(candidate_roles) > 16:
                candidate_roles = candidate_roles[:16]
                finding.context_notes.append("Unresolved lexical role candidates limited to 16.")
        else:
            candidate_roles = roles
        if candidate_roles and policy_sources is None:
            policy_sources, bounded_search = _load_policy_sources(repo_path)
        if bounded_search:
            finding.context_notes.append(
                "Local IAM search was bounded or some sources were unreadable; "
                "no conclusion about absent permissions is supported."
            )
        positive: list[tuple[_PolicyEvidence, list[str], str]] = []
        candidate_notes: list[str] = []
        for role in candidate_roles:
            if role not in policy_cache:
                policy_cache[role] = _policy_evidence(role, policy_sources or [])
            for evidence in policy_cache[role]:
                if evidence.policy not in verdict_cache:
                    try:
                        verdict = classify_policy(evidence.policy)
                        verdict_cache[evidence.policy] = (
                            verdict.radius,
                            verdict.triggering_actions,
                        )
                    except (ValueError, RecursionError):
                        # Untrusted raw candidates may exceed the JSON reader's
                        # integer/depth limits. They supply no authority proof.
                        verdict_cache[evidence.policy] = (BlastRadius.UNKNOWN, [])
                radius, actions = verdict_cache[evidence.policy]
                relative = os.path.relpath(evidence.path, repo_path).replace(os.sep, "/")
                witness = f"{relative}{evidence.pointer}; SHA256 {evidence.digest}"
                if evidence.snapshot_inline and roles:
                    finding.context_notes.append(
                        f"Local snapshot inline-policy attachment: {role}; {witness}; "
                        f"invocation {scope}; workflow SHA256 "
                        f"{hashlib.sha256(raw_workflow).hexdigest()}. "
                        f"Represented Allow classification: {radius.value}; "
                        "this is not a complete bound on the role's other grants."
                    )
                    finding.context_tags.append("iam_snapshot_inline_attachment")
                    if radius == BlastRadius.CRITICAL:
                        positive.append((evidence, actions, role))
                else:
                    candidate_notes.append(
                        f"Unverified local IAM policy candidate: {witness}; "
                        f"Allow classification {radius.value}; attachment to the finding's "
                        "own role and executable configuration is not established. "
                        f"Candidate actions: {', '.join(actions[:8]) or 'unresolved/none'}."
                    )
        # Bound presentation only; all evidence above still participates in the decision.
        finding.context_notes.extend(candidate_notes[:8])
        if len(candidate_notes) > 8:
            finding.context_notes.append(f"{len(candidate_notes) - 8} more IAM candidates omitted.")
        if candidate_notes:
            finding.context_tags.append("iam_policy_candidate")
        if not positive:
            continue
        evidence, actions, role = positive[0]
        relative = os.path.relpath(evidence.path, repo_path).replace(os.sep, "/")
        finding.severity = Severity.CRITICAL
        finding.title = f"[CRITICAL configured inline-policy upper bound] {finding.title}"
        finding.description += (
            "\n\nLocal IAM snapshot — CRITICAL configured inline-policy Allow upper bound.\n"
            f"Role: {role}\n"
            f"Policy source: {relative}{evidence.pointer}\n"
            f"Source SHA256: {evidence.digest}\n"
            f"Owning invocation: {scope}\n"
            "Triggering actions:\n"
            f"{_format_triggering_actions(actions)}\n"
            "The local snapshot declares this inline identity policy under the exact role "
            "configured before the agent step. This bounds the represented Allow contribution "
            "before Deny, conditions and other controls; it does not prove deployed or effective "
            "AWS access, successful assumption, attacker execution, or the role's complete grants."
        )
        finding.remediation += (
            "\nVerify the source inventory against current AWS attachments and effective "
            "controls. Narrow the cited inline-policy actions/resources, and separate the "
            "agent from cloud credentials. Do not treat a policy filename as attachment proof."
        )
    return findings
