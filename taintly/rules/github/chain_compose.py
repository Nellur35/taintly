"""GitHub Actions — finding-composition CHAIN rules (CHAIN-GH-1xx).

The CHAIN-GH-1xx family realises the user's "stack low → critical"
concept by composing *existing* findings into higher-severity
composite findings. Distinct from CHAIN-GH-001, which was a single
hard-coded threat shape (self-hosted-runner persistence) — these are
the generic composer's output, parameterised by which combinations
matter.

Architecture: see :mod:`taintly.composer`. Each rule is a closure-
rule callable that reads the composer Database and asserts
``CompositeFact`` entries when its join condition holds. The engine
emits one :class:`taintly.models.Finding` per asserted composite.

The 1xx range avoids collision with CHAIN-GH-001 (a single
hard-coded threat shape, kept separate from the generic
composer's output).

Initial three rules (all conjunctive; the join is what the engine
layer can't do):

* CHAIN-GH-101 — SEC4-GH-005 + fork-reachable + write-token =
  CRITICAL. The actions/checkout step persists a write-capable
  GITHUB_TOKEN onto a runner that any fork PR can execute code on.
* CHAIN-GH-102 — SEC3-GH-001 + fork-reachable = HIGH. An unpinned
  third-party action in a workflow attackers can fire; a single
  upstream compromise → arbitrary code in the fork-reachable job.
* CHAIN-GH-103 — TAINT-GH-001 + fork-reachable = HIGH. Attacker-
  controlled value reaches a shell in a job attackers can trigger;
  the fork-reachable trigger upgrades the taint finding from
  "review-needed" to "concrete pwn-request shape."

The conjuncts intentionally cite *existing* lab-shipped rules rather
than re-implementing their patterns. Composer rules earn their keep
exactly by NOT duplicating detection logic — they layer threat-level
implications on top of what's already detected.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from taintly.composer import CompositeFact, context_for, findings_by_rule
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import (
    CorpusFindings,
    CorpusPattern,
    WorkflowCorpus,
)

if TYPE_CHECKING:
    from taintly.taint_facts.relations import Database, Fact

# ---------------------------------------------------------------------------
# Composer rules (closure-rule callables)
# ---------------------------------------------------------------------------


def _compose_chain_gh_101(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC4-GH-005 + fork-reachable + write-token → CRITICAL.

    The pwn-request shape, derived from existing finding output rather
    than re-detected from YAML. Anchors at the SEC4-GH-005 finding's
    line — that's the actions/checkout that should have set
    ``persist-credentials: false``.

    Note: SEC4-GH-005B (INFO posture sibling, added 2026-05-19 by
    github-tanstack-posture-design-v1) does NOT feed this composer.
    SEC4-GH-005B fires only when no downstream credential consumer
    is detected — the "consumer present" gate is exactly what makes
    SEC4-GH-005 a confident pwn-request building block.  Composing
    SEC4-GH-005B into CHAIN-GH-101 would re-introduce the FP-density
    noise the May-17 SEC4-GH-005 precision tune eliminated.  The
    composer's input set is intentionally limited to confirmed-
    consumer findings (SEC4-GH-005 only).
    """
    for f in findings_by_rule(db, "SEC4-GH-005"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if not ctx.has_write_token:
            continue
        if ctx.trusted_bot_gate:
            continue
        snippet = (
            "CHAIN: actions/checkout without `persist-credentials: false` "
            "in a fork-reachable, write-token-holding job. A PR from a "
            "fork executes code with the persisted GITHUB_TOKEN — the "
            "classic pwn-request shape, composed from "
            "SEC4-GH-005 + fork trigger + write-scope permissions."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-101",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


def _compose_chain_gh_102(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC3-GH-001 (unpinned third-party action) + fork-reachable +
    high-blast-radius action → HIGH.

    Unpinned-action risk in isolation is MEDIUM (SEC3-GH-001's own
    severity). A fork-reachable workflow upgrades it ONLY when the
    action's blast radius is high: it consumes secrets, it's a
    container action, or it's a documented release / push / deploy
    action. Otherwise the upstream-compromise leg lands a malicious
    action in a setup/lint/cache step whose runtime authority is
    limited to the runner's own tree — already covered by SEC3-GH-001
    itself at lower severity.

    The blast-radius narrowing is what makes this rule pay rent: the
    unbounded form fires on every fork-reachable workflow that uses
    `pnpm/action-setup` or `Swatinem/rust-cache`, which is most of
    them. The narrowed form fires only when the supply-chain risk
    actually changes the threat tier.
    """
    for f in findings_by_rule(db, "SEC3-GH-001"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        if not _is_high_blast_radius_action(db, f.file, f.line):
            continue
        snippet = (
            "CHAIN: high-blast-radius third-party action used at a "
            "mutable ref (SEC3-GH-001) inside a fork-reachable "
            "workflow. The action handles secrets, runs in a "
            "container, or pushes/publishes/deploys — an upstream tag "
            "overwrite (by the action's maintainer or by an attacker "
            "who compromises them) silently lands "
            "attacker-controlled code in a workflow any external "
            "contributor can trigger, with the action's full runtime "
            "authority."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-102",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


# Actions whose name (case-insensitive) contains any of these tokens
# are documented push / deploy / publish actions whose runtime
# authority makes them high-blast-radius. Selected from real-world
# corpora; conservative — false-positives in this list yield only
# CHAIN-GH-102 fires that would otherwise have been classified
# correctly by SEC3-GH-001 at lower severity.
_HIGH_BLAST_RADIUS_NAME_TOKENS: tuple[str, ...] = (
    "publish",
    "deploy",
    "push",
    "release",
    "gh-pages",
    "auto-commit",
    "twine",
    "actions-gh-pages",
    "github-push",
)


def _is_high_blast_radius_action(db: Database, file: str, line: int) -> bool:  # noqa: ARG001
    """Inspect the step at ``file:line`` and decide whether the action
    is high-blast-radius. Three criteria, any of which qualifies:

    * The action's name (the ``uses:`` value) contains a token from
      :data:`_HIGH_BLAST_RADIUS_NAME_TOKENS`.
    * The action is a container action (``uses: docker://...`` or
      ``uses: ./.github/actions/<dir>`` with a Dockerfile — the
      docker form is what we can detect statically).
    * The step's ``with:`` block (next ~12 lines after the ``uses:``)
      contains ``${{ secrets.``, indicating the action consumes
      repo / org secrets.

    Returns False when the file isn't readable. Conservative: we'd
    rather miss a chain than emit FPs on cache / setup / lint
    actions which dominate the ordinary corpus.
    """
    import re

    # Resolve file content via the corpus we smuggled onto the db.
    # Composer rules don't get a direct corpus handle — we get the
    # workflow content from disk on-demand. CI files are bounded by
    # size so the cost is negligible.
    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return False
    if not (1 <= line <= len(lines)):
        return False
    uses_line = lines[line - 1]
    m = re.search(r"uses:\s*['\"]?([^@\s'\"]+)", uses_line)
    if not m:
        return False
    name = m.group(1).lower()
    if name.startswith("docker://"):
        return True
    for token in _HIGH_BLAST_RADIUS_NAME_TOKENS:
        if token in name:
            return True
    # Scan the with: block window for secret references. Bound at 12
    # lines past the uses: line — bigger than typical with: blocks but
    # small enough to stay step-local.
    window = "".join(lines[line - 1 : line + 12])
    if "${{ secrets." in window or "${{secrets." in window:  # noqa: SIM103
        return True
    return False


def _compose_chain_gh_103(db: Database) -> Iterable[tuple[str, Fact]]:
    """TAINT-GH-001 (tainted run) + fork-reachable → HIGH.

    TAINT-GH-001 normally flags "this `${{ github.event.X }}` reaches a
    shell"; on a non-fork-reachable trigger, the attack story is weak
    (only a maintainer can fire the trigger). Composed with a fork-
    reachable trigger, it becomes a concrete pwn-request shape:
    external attacker fires the workflow → injects shell → executes
    in the workflow's context.
    """
    for f in findings_by_rule(db, "TAINT-GH-001"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        snippet = (
            "CHAIN: tainted value reaches a shell run: in a fork-"
            "reachable workflow. TAINT-GH-001 by itself flagged the "
            "flow; the fork-reachable trigger upgrades that to a "
            "concrete external-attacker-injectable shell."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-103",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


def _compose_chain_gh_104(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC6-GH-010 (secret to action input without masking) +
    fork-reachable + unpinned action → HIGH.

    Three legs:
      (1) SEC6-GH-010: a credential-named action input takes
          ``${{ secrets.X }}`` directly (no env-block masking).
      (2) fork_reachable: the workflow fires on a trigger
          external contributors can reach.
      (3) SEC3-GH-001: the action at this step is unpinned
          (mutable ref, not SHA).

    Each leg in isolation is MEDIUM or review-needed.  Combined,
    the supply-chain + secret-disclosure shape is concrete: a fork
    PR fires the workflow, the action — published at a mutable
    ref — receives the secret in plaintext, and an upstream
    compromise (tag overwrite, maintainer takeover) immediately
    exfiltrates the secret.

    The unpinned-action leg is what makes this rule pay rent.
    Without it, ``secrets.GITHUB_TOKEN`` passed to official
    SHA-pinned actions (the dominant ordinary-corpus shape) fires
    as a false positive: SHA-pinned actions can't be silently
    swapped, so the supply-chain leg of the chain doesn't exist.
    Requiring SEC3-GH-001 narrows fires to the case where the
    chain is real end-to-end.
    """
    # Build (file, line) anchors of every UNPINNED THIRD-PARTY
    # action finding.  SEC3-GH-001 fires on the ``uses:`` line for
    # third-party actions only; SEC3-GH-001A fires on first-party
    # actions (``actions/*``, ``aws-actions/*``, ``github/*``,
    # ``microsoft/*``, ``Azure/*``) and is INTENTIONALLY EXCLUDED:
    # first-party publishers carry materially lower supply-chain
    # risk (operationally trusted, audit-attested by the vendor),
    # so the "upstream compromise" leg of the chain doesn't fire
    # in the same way.  SEC6-GH-010 itself flags the hardening
    # miss on first-party actions at its own severity.
    #
    # SEC6-GH-010 fires on the ``token: ${{ secrets.X }}`` line a
    # few lines below the ``uses:`` line inside the same step's
    # ``with:`` block.  A step is typically 2-12 lines tall, so a
    # SEC3-GH-001 finding within 15 lines BEFORE the SEC6-GH-010
    # line in the same file is the same step.
    unpinned_by_file: dict[str, set[int]] = {}
    for f in findings_by_rule(db, "SEC3-GH-001"):
        unpinned_by_file.setdefault(f.file, set()).add(f.line)

    for f in findings_by_rule(db, "SEC6-GH-010"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        # Leg (3): does the SEC6-GH-010-bearing step's ``uses:``
        # line itself have a SEC3-GH-001 finding?  This locks the
        # third leg to the actual step, not a nearby earlier step.
        unpinned_lines = unpinned_by_file.get(f.file, set())
        if not unpinned_lines:
            continue
        if not _has_unpinned_in_step_window(unpinned_lines, f.line, f.file):
            continue
        snippet = (
            "CHAIN: secret passed to an action input without env-block "
            "masking (SEC6-GH-010) in a fork-reachable workflow, and "
            "the action is pinned to a mutable ref (SEC3-GH-001). "
            "Any external PR fires the workflow; the action receives "
            "the secret in plaintext via `with:`; an upstream "
            "compromise of the action's tag or branch immediately "
            "exposes the secret to the attacker pool external "
            "contributors are in."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-104",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


# Step window: how many lines BEFORE a SEC6-GH-010 hit may the
# step's ``uses:`` line be?  A step typically opens with ``- uses:``
# on one line, then ``with:`` and 1-N input lines.  15 lines is the
# 99th-percentile step height in the corpus.
_STEP_LINE_WINDOW = 15


_USES_LINE_RE = re.compile(r"^\s*-?\s*uses\s*:")


def _step_uses_line(file: str, target_line: int) -> int:
    """Return the line number of the SEC6-GH-010-bearing step's
    ``uses:`` declaration, or -1 if not found within
    ``_STEP_LINE_WINDOW`` lines.

    The step's anchor is the FIRST ``uses:`` line found by scanning
    backward from ``target_line``.  This locks the chain to the
    actual step that holds the secret-passing input, not a nearby
    earlier step.
    """
    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return -1
    # Scan from (target_line - 1) backward up to _STEP_LINE_WINDOW
    # lines.  Python's list is 0-indexed; line numbers in findings
    # are 1-indexed.
    start_idx = min(target_line - 1, len(lines) - 1)
    lower = max(0, start_idx - _STEP_LINE_WINDOW)
    for idx in range(start_idx, lower - 1, -1):
        if _USES_LINE_RE.match(lines[idx]):
            return idx + 1  # back to 1-indexed
    return -1


def _has_unpinned_in_step_window(
    unpinned_lines: list[int],
    target_line: int,
    file: str,
) -> bool:
    """Return True iff the SEC6-GH-010-bearing step's ``uses:`` line
    is itself a SEC3-GH-001 finding line.

    The previous form (any unpinned anchor within a 15-line window)
    over-attributed: a workflow with two steps where step A has an
    unpinned third-party action and step B has a SHA-pinned (or
    first-party) action would falsely chain step A's unpinned signal
    to step B's secret-passing.

    Concrete FP this fixes: ``cloudflare/wrangler-action@v3`` at
    line 82-87 (unpinned third-party), then ``actions/github-script
    @v8`` at line 90-95 (first-party).  SEC6-GH-010 fires on the
    github-script step's ``token:`` line.  The cloudflare ``uses:``
    line is within 15 lines but it's not the github-script step's
    anchor; the chain doesn't hold for the github-script step.

    This form locks the anchor by finding the step's actual
    ``uses:`` line (the closest one above the SEC6-GH-010 finding)
    and asking whether THAT specific line is in the SEC3-GH-001 set.
    """
    step_line = _step_uses_line(file, target_line)
    if step_line == -1:
        return False
    return step_line in unpinned_lines


COMPOSER_RULES = [
    _compose_chain_gh_101,
    _compose_chain_gh_102,
    _compose_chain_gh_103,
    _compose_chain_gh_104,
]


# ---------------------------------------------------------------------------
# Rule registrations
# ---------------------------------------------------------------------------


def _make_chain_callback(chain_id: str):
    """Return a CorpusPattern callback that emits findings for one
    composite chain_id from the corpus + prior_findings.

    The callback reads ``corpus._prior_findings`` (a list smuggled in
    by :func:`taintly.engine._run_composer_rules`); when absent (e.g.
    a unit test invoking the corpus pass without seeding findings), the
    callback returns an empty list and never asserts anything.
    """

    def callback(corpus: WorkflowCorpus) -> CorpusFindings:
        prior = getattr(corpus, "_prior_findings", None)
        if prior is None:
            return []
        from taintly.composer import run_composer

        composites = run_composer(corpus, prior, COMPOSER_RULES)
        return [(c.file, c.anchor_line, c.snippet) for c in composites if c.chain_id == chain_id]

    return callback


RULES: list[Rule] = [
    Rule(
        id="CHAIN-GH-101",
        title=(
            "Composite: persisted checkout credential in a fork-reachable, "
            "write-token job (SEC4-GH-005 + fork trigger + write-scope)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "CHAIN-GH-101 composes three findings/contexts: "
            "(1) SEC4-GH-005 fires on an actions/checkout step that "
            "doesn't set `persist-credentials: false`; "
            "(2) the workflow's trigger is fork-reachable "
            "(`pull_request`, `pull_request_target`, `issue_comment`, "
            "`workflow_run`, ...); "
            "(3) the job holds a write-capable GITHUB_TOKEN.\n\n"
            "Individually each is MEDIUM/HIGH at most; combined, an "
            "external PR can execute code with the persisted "
            "write-token — the canonical pwn-request RCE shape."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-101")),
        remediation=(
            "Break any one of the three legs:\n"
            "  1. Set `persist-credentials: false` on the checkout step "
            "(addresses SEC4-GH-005);\n"
            "  2. Move the workflow off fork-reachable triggers (or "
            "use `pull_request` instead of `pull_request_target` if you "
            "don't need write-scope secrets);\n"
            "  3. Drop the job's permissions to the minimum needed "
            "(`permissions: contents: read`).\n"
            "Run `taintly --guide CHAIN-GH-101` for the full checklist."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["E", "T", "S"],
        threat_narrative=(
            "An external contributor opens a PR. The workflow fires "
            "on `pull_request_target` with the default write-capable "
            "GITHUB_TOKEN. The fork's code is checked out without "
            "`persist-credentials: false`, so the checkout step writes "
            "the workflow's GITHUB_TOKEN into the local git config. "
            "A later step in the same job runs `git push` (or any "
            "shell op an attacker landed in the fork) and uses that "
            "persisted token — now arbitrary writes against the host "
            "repo from a fork PR."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
    ),
    Rule(
        id="CHAIN-GH-102",
        title=(
            "Composite: unpinned third-party action in a fork-reachable "
            "workflow (SEC3-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "CHAIN-GH-102 composes: (1) SEC3-GH-001 fires on a "
            "third-party action used at a mutable ref (tag or branch); "
            "(2) the workflow is fork-reachable. Unpinned-action risk "
            "in isolation is MEDIUM; combined with a fork-reachable "
            "trigger, an upstream supply-chain compromise reaches "
            "the lowest-privilege attacker pool immediately."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-102")),
        remediation=(
            "Pin the third-party action to a full commit SHA "
            "(addresses SEC3-GH-001). The fork-reachable trigger is "
            "a property of the workflow's intent and may be unchangeable; "
            "pinning removes the upstream-compromise leg of the chain."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker who compromises a popular GitHub Action "
            "(via maintainer takeover or upstream account theft) "
            "publishes a malicious release under the existing tag. "
            "Every fork-reachable workflow that uses the action at "
            "that tag picks up the malicious code on the next PR — "
            "no maintainer action required by the victim repo."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
    ),
    Rule(
        id="CHAIN-GH-104",
        title=(
            "Composite: secret passed to unpinned action input "
            "without env-block masking in a fork-reachable workflow "
            "(SEC6-GH-010 + SEC3-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "CHAIN-GH-104 composes three legs: (1) SEC6-GH-010 fires "
            "on a credential-named action input that receives a "
            "`${{ secrets.X }}` value directly (no env-block masking); "
            "(2) the workflow is fork-reachable; (3) the action is "
            "pinned to a mutable ref (SEC3-GH-001), not a full SHA.\n\n"
            "Individually each is MEDIUM or review-needed. Combined: "
            "any external contributor's PR fires the workflow, the "
            "action — published at a mutable ref — receives the "
            "secret in plaintext via `with:`, and an upstream "
            "compromise (tag overwrite, maintainer takeover) "
            "exfiltrates the secret without needing any change to the "
            "host repo.\n\n"
            "The unpinned-action leg is what distinguishes a real "
            "supply-chain shape from the common hardening miss of "
            "passing `secrets.GITHUB_TOKEN` to an official "
            "SHA-pinned action: SHA-pinned actions can't be silently "
            "swapped, so the supply-chain leg of the chain doesn't "
            "exist."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-104")),
        remediation=(
            "Sanitise either leg:\n"
            "  1. Bind the secret to a step `env:` variable and pass "
            "`${{ env.NAME }}` (with the leading double-quoted shell "
            "form for run-blocks); GitHub's runner masks env-bound "
            "secrets in logs and on injection;\n"
            "  2. Pin the action to a full commit SHA and audit it "
            "(removes the upstream-compromise leg)."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets"
        ),
        test_positive=[],
        test_negative=[],
        stride=["I", "T", "E"],
        threat_narrative=(
            "An external contributor opens a PR. The workflow fires "
            "and invokes a third-party action that takes a "
            "`token:` input; the workflow passes `${{ secrets.PAT }}` "
            "to it without an env-block. The action's source — "
            "controlled by its upstream maintainer or anyone who "
            "compromises them — receives the secret in plaintext. "
            "The PR doesn't need to do anything except trigger; the "
            "secret leak is automatic."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
    ),
    Rule(
        id="CHAIN-GH-103",
        title=(
            "Composite: tainted value reaches shell in a fork-reachable "
            "workflow (TAINT-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "CHAIN-GH-103 composes: (1) TAINT-GH-001 fires on a "
            "`${{ github.event.X }}` value reaching a shell `run:` "
            "block; (2) the workflow is fork-reachable. Taint in "
            "isolation is review-needed; combined with a fork trigger "
            "it becomes a concrete external-attacker-injectable shell."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-103")),
        remediation=(
            "Sanitise the tainted input — bind to an env var, then use "
            '`"$VAR"` inside the run block; never expand '
            "`${{ ... }}` directly into shell. The fork-reachable "
            "trigger is workflow intent; sanitising the taint flow "
            "removes the injection leg."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "An external contributor opens a PR whose title contains "
            "shell metacharacters. The workflow's CI job inlines that "
            "title into a shell run via `${{ github.event.pull_request.title }}`. "
            "The shell interprets the metacharacters; arbitrary commands "
            "execute in the job's context with the workflow's secrets "
            "and token."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
    ),
]
