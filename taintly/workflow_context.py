"""Workflow context analysis — per-file exploitability signals.

The improvement report's Phase 2 ask is dual-dimension severity:

    base severity + contextual modifiers = final analyst-facing priority

The scoring model already down-weights low-confidence and review-needed
findings (v2 Phase 1).  This module adds the **file-level** context layer
the report called out: the same rule hit in two different workflows can
represent very different real-world risk depending on whether the
workflow sees secrets, runs on fork-controlled triggers, has write
permissions, or checks out untrusted code.

What we detect (intentionally shallow — regex only, no full YAML parse)
---------------------------------------------------------------------
* ``has_fork_triggered``       — pull_request / pull_request_target /
                                   issue_comment / workflow_run
* ``has_pr_target``            — pull_request_target specifically
                                   (secrets-exposed, write by default)
* ``has_checkout``             — any ``uses: actions/checkout``
* ``has_secrets_reference``    — any ``${{ secrets.X }}`` expansion
* ``has_write_permissions``    — an explicit ``*: write`` in a
                                   permissions block, OR ``write-all``
* ``has_explicit_permissions`` — a ``permissions:`` key at any level
* ``is_release_workflow``      — triggered by ``release`` / publishes
                                   to a registry
* ``runs_self_hosted``         — ``runs-on:`` self-hosted / runner group
* ``has_fork_identity_guard``  — ``if:`` condition that only allows the
                                   job to run when the PR comes from the
                                   same repository as the base (the
                                   ``github.event.pull_request.head.repo.
                                   full_name == github.repository`` idiom
                                   used by Anthropic Cookbook and
                                   similar). File-level detection, so
                                   presence anywhere downgrades AI
                                   exploitability for every finding in
                                   the file — imprecise when one job
                                   guards and a sibling job doesn't, but
                                   strictly more accurate than "no
                                   guard detection at all."

Why shallow regex
-----------------
The scanner already has a full YAML path extractor, but the context
signals needed here are textual — the goal is a best-effort "is this a
privileged context?" flag, not a strict parse.  Regex keeps the module
zero-dependency and fast enough to run on every scanned file without
noticeably slowing the scan.

Exploitability model
--------------------
``compute_exploitability`` combines a rule's family with the workflow
context to produce one of ``high`` / ``medium`` / ``low``:

* Script-injection family        + fork-triggered + secrets   -> high
* Script-injection family        + no fork / no secrets       -> medium
* Supply-chain family            + privileged context         -> high
* Supply-chain family            + read-only / no secrets     -> medium
* Credential-persistence family  + has secrets                -> high
* Credential-persistence family  + no secrets                 -> low
* Resource-controls family       + always                     -> low
* AI / ML family                 + fork-identity guard        -> low
* AI / ML family                 + pr_target / fork+token     -> high
* AI / ML family                 + fork-triggered only        -> medium
* AI / ML family                 + read-only / no secrets     -> low
* Everything else                                             -> medium

This is deliberately conservative.  We never escalate above ``high``
(that would require an authoritative privilege model) and we don't
rewrite severity — we attach a second dimension the reporter and
scorer can use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Signal detection — each regex is intentionally forgiving so trailing
# whitespace / quoting / YAML flow-style keys don't miss matches.
# ---------------------------------------------------------------------------

_RE_PR_TARGET = re.compile(r"^\s*pull_request_target\s*:", re.MULTILINE)
_RE_FORK_TRIGGER = re.compile(
    r"^\s*(pull_request|pull_request_target|issue_comment|workflow_run)\s*:",
    re.MULTILINE,
)
# GitLab / Jenkins fork-trigger equivalents: MR pipeline rules and
# Jenkins multibranch `pullRequest`/`ghprb*` webhooks bring attacker-
# controlled refs into the same trust domain as the target repo.
_RE_FORK_TRIGGER_OTHER = re.compile(
    r"\$CI_MERGE_REQUEST_|\$CI_EXTERNAL_PULL_REQUEST|"
    r"\bghprb\w+|\bCHANGE_(BRANCH|TITLE|AUTHOR)\b|\bpullRequest\s*\{",
)
_RE_CHECKOUT = re.compile(
    r"uses:\s*actions/checkout@|"
    r"\bcheckout\s+scm\b|\bgit\s+clone\b|\bgit\(\s*url:"
)
# GitHub Actions `${{ secrets.X }}`, GitLab `$VAULT_*` / `$CI_JOB_TOKEN`,
# Jenkins `credentials('id')` / `withCredentials` / `env.X_TOKEN`.
_RE_SECRETS_REF = re.compile(
    r"\$\{\{\s*secrets\.|"
    r"\bcredentials\s*\(\s*['\"]|"
    r"\bwithCredentials\s*\(|"
    r"\$CI_JOB_TOKEN\b|\$VAULT_\w+|\$CI_REGISTRY_PASSWORD\b"
)
_RE_WRITE_PERM = re.compile(
    r"^\s*(contents|packages|id-token|deployments|actions|pull-requests|issues|"
    r"statuses|checks|pages|security-events|attestations)\s*:\s*write",
    re.MULTILINE,
)
_RE_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\b", re.MULTILINE)
_RE_PERMISSIONS_BLOCK = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
_RE_RELEASE_TRIGGER = re.compile(r"^\s*release\s*:", re.MULTILINE)
_RE_REGISTRY_PUBLISH = re.compile(
    r"(npm\s+publish|pypi|twine\s+upload|docker\s+push|gh\s+release|"
    r"cargo\s+publish|gem\s+push|goreleaser|pack\s+publish)",
    re.IGNORECASE,
)
_RE_SELF_HOSTED = re.compile(
    r"^\s*runs-on\s*:\s*\[?\s*(self-hosted|[A-Za-z_][\w-]*-self-hosted)|"
    r"\bagent\s*\{\s*label\b|\bagent\s+any\b",
    re.MULTILINE,
)
# GitHub Enterprise "runner-group" form:
#   runs-on:
#     group: my-enterprise-runners
# Expands across two lines and doesn't contain "self-hosted" literal
# anywhere, so the primary regex misses it. Runner groups always
# resolve to self-hosted runners, so treat any group: child as a
# self-hosted signal for exploitability purposes.
_RE_SELF_HOSTED_GROUP = re.compile(
    r"^\s*runs-on\s*:\s*(\n\s+[A-Za-z_-]+\s*:\s*\S+\s*){0,4}\n?\s*group\s*:\s*\S",
    re.MULTILINE,
)
# Jenkins / GitLab untrusted-input surfaces that act like fork triggers
# for attack modelling: a parameter / MR variable flowing into sh is the
# same shape as a fork PR feeding attacker text into a workflow.
_RE_JENKINS_PARAMS = re.compile(
    r"\bparameters\s*\{|\bparams\s*\.\s*\w+|\benv\.(GIT_BRANCH|BRANCH_NAME|CHANGE_\w+|TAG_NAME)\b"
)

# Fork-identity guard: the Anthropic Cookbook / claude-code-action idiom
# that allows a job to run only when the PR head lives in the same
# repository as the base. The literal expression is
#   github.event.pull_request.head.repo.full_name == github.repository
# and it's the canonical mitigation against the "fork PR can trigger a
# privileged workflow" threat model that AI-GH-005/006/008/009/012/013
# flag on. Presence downgrades AI exploitability; absence doesn't escalate.
_RE_FORK_IDENTITY_GUARD = re.compile(
    r"github\.event\.pull_request\.head\.repo\.full_name\s*"
    r"(?:==|!=)\s*github\.repository"
)


@dataclass
class WorkflowContext:
    """File-level signals used for exploitability scoring.

    All fields default to False; an unknown / unparseable file therefore
    looks like a maximally-benign context.  That's the safe default —
    it means we never **escalate** a finding above its policy severity
    based on guessed context, only de-escalate when we have positive
    evidence of benignness.
    """

    file: str = ""
    has_fork_triggered: bool = False
    has_pr_target: bool = False
    has_checkout: bool = False
    has_secrets_reference: bool = False
    has_write_permissions: bool = False
    has_explicit_permissions: bool = False
    is_release_workflow: bool = False
    runs_self_hosted: bool = False
    has_fork_identity_guard: bool = False

    @property
    def is_privileged(self) -> bool:
        """Heuristic: does this workflow touch sensitive resources?

        True if the file has secrets available, write permissions, runs
        on privileged triggers, publishes releases, or runs on a self-
        hosted runner.  False means the rule fires in a context where
        exploitation would require attacker control the workflow does
        not offer.
        """
        return (
            self.has_secrets_reference
            or self.has_write_permissions
            or self.has_pr_target
            or self.is_release_workflow
            or self.runs_self_hosted
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "has_fork_triggered": self.has_fork_triggered,
            "has_pr_target": self.has_pr_target,
            "has_checkout": self.has_checkout,
            "has_secrets_reference": self.has_secrets_reference,
            "has_write_permissions": self.has_write_permissions,
            "has_explicit_permissions": self.has_explicit_permissions,
            "is_release_workflow": self.is_release_workflow,
            "runs_self_hosted": self.runs_self_hosted,
            "has_fork_identity_guard": self.has_fork_identity_guard,
            "is_privileged": self.is_privileged,
        }


def analyze(content: str, file: str = "") -> WorkflowContext:
    """Return a :class:`WorkflowContext` from raw YAML workflow content.

    Pure function: no I/O, no state.  Safe to call on arbitrarily large
    strings — the underlying regexes are anchored to start-of-line and
    short enough to avoid ReDoS.
    """
    if not content:
        return WorkflowContext(file=file)
    return WorkflowContext(
        file=file,
        has_fork_triggered=bool(
            _RE_FORK_TRIGGER.search(content)
            or _RE_FORK_TRIGGER_OTHER.search(content)
            or _RE_JENKINS_PARAMS.search(content)
        ),
        has_pr_target=bool(_RE_PR_TARGET.search(content)),
        has_checkout=bool(_RE_CHECKOUT.search(content)),
        has_secrets_reference=bool(_RE_SECRETS_REF.search(content)),
        has_write_permissions=bool(_RE_WRITE_PERM.search(content) or _RE_WRITE_ALL.search(content)),
        has_explicit_permissions=bool(_RE_PERMISSIONS_BLOCK.search(content)),
        is_release_workflow=bool(
            _RE_RELEASE_TRIGGER.search(content) or _RE_REGISTRY_PUBLISH.search(content)
        ),
        runs_self_hosted=bool(
            _RE_SELF_HOSTED.search(content) or _RE_SELF_HOSTED_GROUP.search(content)
        ),
        has_fork_identity_guard=bool(_RE_FORK_IDENTITY_GUARD.search(content)),
    )


# ---------------------------------------------------------------------------
# Exploitability mapping
# ---------------------------------------------------------------------------
#
# The mapping is keyed on family ID.  Anything not listed falls through
# to the ``_DEFAULT`` branch, which returns "medium" — a neutral hint
# that neither escalates nor de-escalates relative to severity.

_HIGH = "high"
_MEDIUM = "medium"
_LOW = "low"


def compute_exploitability(family_id: str, ctx: WorkflowContext) -> str:
    """Combine family + workflow context into an exploitability tier.

    Never escalates above ``high`` and never raises a finding's policy
    severity.  Produces a second signal the reporter ranks by and the
    scorer weights, so the same rule firing in a privileged workflow
    vs.  a sandbox workflow is distinguishable in both views.
    """
    if not family_id:
        return _MEDIUM

    # Script injection — needs attacker-controlled input AND privileged
    # context to be exploitable.
    if family_id == "script_injection":
        if ctx.has_fork_triggered and (ctx.has_secrets_reference or ctx.has_write_permissions):
            return _HIGH
        if ctx.has_fork_triggered or ctx.has_secrets_reference:
            return _MEDIUM
        return _LOW

    # Privileged PR-trigger exposure — severity IS context here.
    # ``pull_request_target`` is write-by-default unless an explicit
    # ``permissions:`` block narrows the token, so a workflow that sets
    # ``permissions: {}`` + no checkout + no secret references has nothing
    # an attacker can actually steal, while one that omits the block has
    # full write access implicitly.  The tier reflects that asymmetry.
    if family_id == "privileged_pr_trigger":
        # Effective privilege: either explicit write perms, a secret ref,
        # OR pull_request_target with no explicit permissions block
        # (which means GITHUB_TOKEN defaults to write).
        default_write = ctx.has_pr_target and not ctx.has_explicit_permissions
        has_exposure = ctx.has_secrets_reference or ctx.has_write_permissions or default_write
        if has_exposure and ctx.has_checkout:
            return _HIGH
        if has_exposure:
            return _MEDIUM
        return _LOW

    # Supply-chain immutability — mutable dependency matters most when
    # the dependency executes with privileges.  In a fully read-only,
    # no-secrets workflow the risk is lower (but not zero).
    if family_id == "supply_chain_immutability":
        if ctx.is_privileged:
            return _HIGH
        return _MEDIUM

    # Credential persistence / secret hygiene — only matters when the
    # workflow actually sees secrets to persist or leak.
    if family_id == "credential_persistence":
        if ctx.has_secrets_reference or ctx.has_write_permissions:
            return _HIGH
        return _LOW

    # Identity / access — broad permissions only matter if the token is
    # actually usable for something sensitive in this workflow.
    if family_id == "identity_access":
        if ctx.has_write_permissions or ctx.is_release_workflow:
            return _HIGH
        return _MEDIUM

    # Resource controls — always low exploitability relative to
    # security impact; these are hygiene, not attack surface.
    if family_id == "resource_controls":
        return _LOW

    # Release integrity — matters by construction in release workflows.
    if family_id == "release_integrity":
        if ctx.is_release_workflow:
            return _HIGH
        return _MEDIUM

    # Ungoverned services — self-hosted runner exposure is a real
    # escalation; otherwise default to medium.
    if family_id == "ungoverned_services":
        if ctx.runs_self_hosted or ctx.has_pr_target:
            return _HIGH
        return _MEDIUM

    # Logging / visibility — hygiene by default.
    if family_id == "logging_visibility":
        return _LOW

    # AI / ML model and agent risk — exploitability tracks "can the
    # attacker reach this file in a way that steers the model or feeds
    # a poisoned model to it?" The fork-identity guard mitigates the
    # prompt-injection / agent paths (AI-GH-005/006/008/009/012/013)
    # so heavily that those findings should be review-needed rather
    # than confirmed top-alarm; the model-deserialisation rules
    # (AI-GH-001/003/010) track privilege the same way supply-chain
    # rules do.
    if family_id == "ai_ml_model_risk":
        if ctx.has_fork_identity_guard:
            # Maintainer-only execution path; the agent / model still
            # carries whatever token the job binds, but an outside
            # attacker can't trigger the workflow at all.
            return _LOW
        if ctx.has_pr_target or (
            ctx.has_fork_triggered and (ctx.has_write_permissions or ctx.has_secrets_reference)
        ):
            return _HIGH
        if ctx.has_fork_triggered or ctx.is_release_workflow or ctx.runs_self_hosted:
            return _MEDIUM
        if ctx.has_secrets_reference and ctx.has_checkout:
            return _MEDIUM
        return _LOW

    return _MEDIUM
