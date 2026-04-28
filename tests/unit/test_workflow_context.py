"""Tests for taintly.workflow_context.

The context analyzer powers the v2 exploitability tier: the same rule
firing in a secrets-less sandbox workflow vs.  a release workflow with
full write permissions should produce different analyst-facing priority.
These tests pin down the signal detection so a regex tweak can't
silently flip a rule from "low exploitability" to "high" (or vice
versa) and surprise a user at the next scan.
"""

from __future__ import annotations

from taintly.workflow_context import analyze, compute_exploitability


# ---------------------------------------------------------------------------
# Signal detection
# ---------------------------------------------------------------------------


def test_detects_pull_request_target_trigger():
    ctx = analyze("on:\n  pull_request_target:\n    types: [opened]\n")
    assert ctx.has_pr_target is True
    assert ctx.has_fork_triggered is True


def test_detects_explicit_checkout():
    ctx = analyze("      - uses: actions/checkout@v4\n")
    assert ctx.has_checkout is True


def test_detects_secrets_reference():
    ctx = analyze('        env:\n          T: ${{ secrets.TOKEN }}\n')
    assert ctx.has_secrets_reference is True


def test_detects_write_permission():
    ctx = analyze("permissions:\n  contents: write\n  packages: write\n")
    assert ctx.has_write_permissions is True
    assert ctx.has_explicit_permissions is True


def test_detects_write_all_shorthand():
    ctx = analyze("permissions: write-all\n")
    assert ctx.has_write_permissions is True


def test_detects_release_trigger():
    ctx = analyze("on:\n  release:\n    types: [published]\n")
    assert ctx.is_release_workflow is True


def test_detects_registry_publish_step():
    ctx = analyze("      - run: npm publish\n")
    assert ctx.is_release_workflow is True


def test_detects_self_hosted_runner():
    ctx = analyze("    runs-on: self-hosted\n")
    assert ctx.runs_self_hosted is True


def test_empty_content_returns_all_false():
    ctx = analyze("")
    # Defaults should make the workflow look fully benign — never escalate
    # exploitability on an unparseable file.
    assert ctx.is_privileged is False
    assert ctx.has_fork_triggered is False


def test_is_privileged_heuristic():
    """Any of secrets / write-perms / pr_target / release / self-hosted
    should flip the aggregate privilege flag."""
    # Secrets alone is enough
    assert analyze("x: ${{ secrets.FOO }}").is_privileged is True
    # Write permission alone is enough
    assert analyze("permissions:\n  contents: write\n").is_privileged is True
    # Completely benign workflow
    benign = analyze(
        "on:\n  push:\n    branches: [main]\njobs:\n  lint:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    assert benign.is_privileged is False


# ---------------------------------------------------------------------------
# Exploitability mapping
# ---------------------------------------------------------------------------


def test_script_injection_high_in_fork_trigger_with_secrets():
    """A script-injection finding in a workflow that sees fork-controlled
    triggers AND secrets is the worst case — must be high."""
    ctx = analyze(
        "on:\n  pull_request_target:\n"
        "jobs:\n  x:\n    steps:\n"
        "      - run: echo ${{ secrets.TOKEN }}\n"
    )
    assert compute_exploitability("script_injection", ctx) == "high"


def test_script_injection_low_in_no_fork_no_secrets():
    """Same rule family in a scheduled cron job that doesn't touch
    secrets shouldn't be surfaced as a top risk."""
    ctx = analyze("on:\n  schedule:\n    - cron: '0 0 * * *'\n")
    assert compute_exploitability("script_injection", ctx) == "low"


def test_resource_controls_always_low():
    """timeout-minutes and similar hygiene findings are capped at low —
    they shouldn't dominate the ranking regardless of context."""
    ctx = analyze("on:\n  pull_request_target:\n\njobs:\n  x:\n")
    assert compute_exploitability("resource_controls", ctx) == "low"


def test_credential_persistence_low_without_secrets():
    """persist-credentials findings in a workflow that never references
    a secret have nothing to exfiltrate — mark as low."""
    ctx = analyze("on:\n  push:\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n")
    assert compute_exploitability("credential_persistence", ctx) == "low"


def test_supply_chain_high_when_privileged():
    ctx = analyze("permissions:\n  contents: write\n")
    assert compute_exploitability("supply_chain_immutability", ctx) == "high"


def test_unknown_family_defaults_to_medium():
    """An uncategorized finding should never accidentally get 'high'
    exploitability just because we don't know what to do with it."""
    ctx = analyze("on:\n  pull_request_target:\n")
    assert compute_exploitability("", ctx) == "medium"
    assert compute_exploitability("nonexistent_family", ctx) == "medium"


# ---------------------------------------------------------------------------
# Fork-identity guard + AI / ML exploitability
# ---------------------------------------------------------------------------


def test_detects_fork_identity_guard_equality():
    """The canonical Anthropic-Cookbook idiom: run the job only if the
    PR head lives in the same repo as the base."""
    ctx = analyze(
        "jobs:\n"
        "  review:\n"
        "    if: github.event.pull_request.head.repo.full_name == github.repository\n"
    )
    assert ctx.has_fork_identity_guard is True


def test_detects_fork_identity_guard_negation():
    """Inverted form (`!=`, used in skip-if conditions) is the same guard
    shape from the attacker's perspective — still prevents fork runs."""
    ctx = analyze(
        "jobs:\n"
        "  review:\n"
        "    if: github.event.pull_request.head.repo.full_name != github.repository\n"
    )
    assert ctx.has_fork_identity_guard is True


def test_no_fork_identity_guard_when_absent():
    ctx = analyze("on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n")
    assert ctx.has_fork_identity_guard is False


def test_ai_family_low_when_fork_identity_guard_present():
    """The cookbook shape: pull_request trigger + write perms + AI agent
    + fork-identity guard. The guard keeps outside contributors from
    running the workflow at all, so AI findings here should route to
    the review-needed bucket (low exploitability)."""
    content = (
        "on:\n  pull_request:\n    types: [opened]\n"
        "permissions:\n  pull-requests: write\n"
        "jobs:\n"
        "  review:\n"
        "    if: github.event.pull_request.head.repo.full_name == github.repository\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
    )
    ctx = analyze(content)
    assert ctx.has_fork_identity_guard is True
    assert compute_exploitability("ai_ml_model_risk", ctx) == "low"


def test_ai_family_high_on_pr_target_without_guard():
    content = (
        "on:\n  pull_request_target:\n"
        "permissions:\n  pull-requests: write\n"
        "jobs:\n  review:\n    runs-on: ubuntu-latest\n"
    )
    ctx = analyze(content)
    assert compute_exploitability("ai_ml_model_risk", ctx) == "high"


def test_ai_family_high_on_fork_plus_write_token():
    content = (
        "on:\n  pull_request:\n    types: [opened]\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  review:\n    runs-on: ubuntu-latest\n"
    )
    ctx = analyze(content)
    assert compute_exploitability("ai_ml_model_risk", ctx) == "high"


def test_ai_family_medium_on_fork_without_token():
    """Fork-triggered but no write scope and no secrets — attacker can
    inject a prompt but has little to steer the agent into abusing."""
    content = (
        "on:\n  pull_request:\n    types: [opened]\n"
        "jobs:\n  review:\n    runs-on: ubuntu-latest\n"
    )
    ctx = analyze(content)
    assert compute_exploitability("ai_ml_model_risk", ctx) == "medium"


def test_ai_family_low_on_push_only_with_no_secrets():
    content = (
        "on:\n  push:\n    branches: [main]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    )
    ctx = analyze(content)
    assert compute_exploitability("ai_ml_model_risk", ctx) == "low"
