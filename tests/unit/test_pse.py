"""Tests for PSE-GH-006 — tokened checkout of fork PR head + shell run = RCE.

PSE-GH-006 fires when a single GitHub Actions job composes five
ingredients into an RCE chain: a fork-reachable write-context trigger,
a write-capable ``GITHUB_TOKEN``, an ``actions/checkout`` step that
splices the attacker's fork-head into ``ref:`` / ``repository:``, a
shell-running ``run:`` step in the same job, and NO ``if:`` gate that
restricts execution to a literal ``user.login`` / ``github.actor``.

Five tests cover the precision boundary:

  * test_pse_gh_006_fires_on_deployment_victim_shape — canonical
    ActionsTOCTOU ``deployment_victim`` shape, must fire.
  * test_pse_gh_006_fires_on_label_victim_shape — ``label_victim``
    shape (the known-weak ``safe-to-test`` label gate), must fire.
    A label gate is NOT a user-gate, so the suppression does not
    kick in.
  * test_pse_gh_006_suppressed_by_dependabot_autoapprove — the
    canonical FP shape, must NOT fire because the job's ``if:``
    restricts execution to ``github.actor == 'dependabot[bot]'``.
  * test_pse_gh_006_no_fire_on_pull_request_trigger — same anatomy
    on ``pull_request`` (not ``pull_request_target``), must NOT fire
    because the default token from a fork is read-only.
  * test_pse_gh_006_suppressed_by_maintainer_user_gate — same
    anatomy with ``if: github.actor == 'maintainer'``.  Any literal
    user-gate equality restricts fork-PR reachability; the rule's
    suppression covers all literal user gates, not only the
    trusted-bot allowlist.
"""

from __future__ import annotations

from taintly.rules.github.pse import RULES


def _get_pse_gh_006():
    for rule in RULES:
        if rule.id == "PSE-GH-006":
            return rule
    raise AssertionError("PSE-GH-006 not found in pse.RULES")


def _check(content: str):
    rule = _get_pse_gh_006()
    return rule.pattern.check(content, content.splitlines())


# ---------------------------------------------------------------------------
# Positive cases — must fire
# ---------------------------------------------------------------------------


def test_pse_gh_006_fires_on_deployment_victim_shape():
    """ActionsTOCTOU ``deployment_victim`` — pull_request_target +
    contents:write + tainted ref checkout + npm install."""
    workflow = (
        "on: pull_request_target\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install\n"
        "      - run: npm run build\n"
    )
    matches = _check(workflow)
    assert matches, "deployment_victim shape must fire PSE-GH-006"
    # The cited line should be the tainted ``ref:`` splice — the
    # actionable input for the reviewer.
    line_no, snippet = matches[0]
    assert "github.event.pull_request.head.sha" in snippet
    # Line number is 1-based and points at the ``ref:`` line (line 10
    # in the workflow above: ``on:`` =1, ``permissions:`` =2,
    # ``contents: write`` =3, ``jobs:`` =4, ``deploy:`` =5,
    # ``runs-on:`` =6, ``steps:`` =7, ``- uses:`` =8, ``with:`` =9,
    # ``ref:`` =10).
    assert line_no == 10, f"expected line 10 (the ref: line), got {line_no}"


def test_pse_gh_006_fires_on_label_victim_shape():
    """ActionsTOCTOU ``label_victim`` — the ``safe-to-test`` label
    gate is known-weak and is NOT a user.login gate, so the rule
    still fires.  Tests that:

      * block-form ``on:\\n  pull_request_target:\\n    types: [labeled]``
        is recognised as a fork-reachable trigger.
      * job-level ``permissions: contents: write`` (no workflow-level
        block) supplies the write token.
      * a ``contains(github.event.pull_request.labels.*.name, ...)``
        ``if:`` gate does NOT suppress (it's not a user.login literal).
      * ``ref: ${{ github.event.pull_request.head.ref }}`` (not ``.sha``)
        is recognised as tainted.
      * ``run: make test`` qualifies as a shell-running step.
    """
    workflow = (
        "on:\n  pull_request_target:\n    types: [labeled]\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')\n"
        "    permissions:\n      contents: write\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
        "      - run: make test\n"
    )
    matches = _check(workflow)
    assert matches, "label_victim shape must fire PSE-GH-006 (label gate is not a user-gate)"
    _, snippet = matches[0]
    assert "github.event.pull_request.head.ref" in snippet


def test_pse_gh_006_fires_on_workflow_run_chain():
    """workflow_run-chained variant — pull_request_target's sibling
    fork-reachable trigger.  Uses the ``repository:`` ``with:`` slot
    rather than ``ref:``, and ``go test`` as the shell-running step.

    The default ``GITHUB_TOKEN`` is write-capable on ``workflow_run``
    when no ``permissions:`` block is present, so no explicit grant
    is needed for the rule to fire.
    """
    workflow = (
        "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\n"
        "jobs:\n  rerun:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
        "      - run: go test ./...\n"
    )
    matches = _check(workflow)
    assert matches, "workflow_run chain shape must fire PSE-GH-006"
    _, snippet = matches[0]
    assert "head.repo.full_name" in snippet


# ---------------------------------------------------------------------------
# Negative cases — must NOT fire
# ---------------------------------------------------------------------------


def test_pse_gh_006_suppressed_by_dependabot_autoapprove():
    """Canonical FP shape.  Same pwn_request anatomy, but the
    ``if: github.actor == 'dependabot[bot]'`` gate
    means attacker-fork PRs cannot reach the job — dependabot's PRs
    come from the host repo's own bot account, not from external
    forks.  The rule's user-gate suppression must catch this.
    """
    workflow = (
        "on: pull_request_target\n"
        "permissions:\n  contents: write\n  pull-requests: write\n"
        "jobs:\n  autoapprove:\n    runs-on: ubuntu-latest\n"
        "    if: github.actor == 'dependabot[bot]'\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install\n"
        "      - run: npm test\n"
    )
    matches = _check(workflow)
    assert not matches, (
        "dependabot-autoapprove shape must NOT fire — the user-gate "
        "suppression should catch ``github.actor == 'dependabot[bot]'``."
    )


def test_pse_gh_006_no_fire_on_pull_request_trigger():
    """Same anatomy as ``deployment_victim`` but ``pull_request``
    (not ``pull_request_target``).  The default ``GITHUB_TOKEN`` for
    ``pull_request`` from a fork is READ-ONLY, so there is no
    write-token RCE primitive even if every other ingredient is
    present.  The rule's fork-reachable-trigger gate must reject
    ``pull_request``.
    """
    workflow = (
        "on: pull_request\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install\n"
        "      - run: npm test\n"
    )
    matches = _check(workflow)
    assert not matches, (
        "``pull_request`` (no ``_target``) must NOT fire — the default "
        "token for fork-PR ``pull_request`` is read-only."
    )


def test_pse_gh_006_suppressed_by_maintainer_user_gate():
    """Same anatomy as ``deployment_victim`` but the job has
    ``if: github.actor == 'maintainer'``.  A literal user-gate
    equality — even one against a non-bot username — restricts
    fork-PR reachability because the ``github.actor`` slot reflects
    the PR opener, which an external attacker can never set to a
    maintainer's login.  The rule's user-gate suppression must
    cover ALL literal-equality user gates, not only the bot
    allowlist.
    """
    workflow = (
        "on: pull_request_target\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  scoped:\n    runs-on: ubuntu-latest\n"
        "    if: github.actor == 'maintainer'\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install\n"
    )
    matches = _check(workflow)
    assert not matches, (
        "``if: github.actor == 'maintainer'`` must NOT fire — any "
        "literal user-gate equality restricts fork-PR reachability."
    )


# ---------------------------------------------------------------------------
# Rule-shape contract
# ---------------------------------------------------------------------------


def test_pse_gh_006_rule_metadata():
    """Pin the rule's identity, severity, and review-needed flags so
    downstream reporting (severity rollup, distinct-risk grouping)
    does not drift silently."""
    rule = _get_pse_gh_006()
    assert rule.id == "PSE-GH-006"
    assert rule.severity.value == "CRITICAL"
    assert rule.platform.value == "github"
    assert rule.owasp_cicd == "CICD-SEC-1"
    assert rule.confidence == "high"
    assert rule.review_needed is False
    assert "pwn_request" in rule.description.lower() or "pull_request_target" in rule.description
