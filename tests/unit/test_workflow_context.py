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


def test_detects_flow_style_pull_request_target_trigger():
    """YAML flow-style triggers (``on: { pull_request_target: ... }``)
    are legal and appear in real repos. A line-anchored regex missed
    them, collapsing the exploitability context for every finding in
    the file. Regression for the flow-style trigger detection gap."""
    ctx = analyze("on: { pull_request_target: { types: [opened] } }\n")
    assert ctx.has_pr_target is True
    assert ctx.has_fork_triggered is True


def test_detects_flow_style_fork_trigger_issue_comment():
    ctx = analyze("on: { issue_comment: { types: [created] } }\n")
    assert ctx.has_fork_triggered is True
    # issue_comment is fork-reachable but not pull_request_target.
    assert ctx.has_pr_target is False


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
    """Any of secrets / write-perms / pr_target / release / self-hosted /
    implicit-default-write should flip the aggregate privilege flag."""
    # Secrets alone is enough
    assert analyze("x: ${{ secrets.FOO }}").is_privileged is True
    # Write permission alone is enough
    assert analyze("permissions:\n  contents: write\n").is_privileged is True
    # Completely benign workflow: a GitHub workflow is only truly benign once
    # it pins an explicit read-only permissions block — otherwise it carries a
    # write-capable default GITHUB_TOKEN (P2.2 implicit-default-write).
    benign = analyze(
        "on:\n  push:\n    branches: [main]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  lint:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    assert benign.is_privileged is False
    # The same workflow WITHOUT a permissions block is now privileged: its
    # default token is write-capable (mirrors composer.py:229-235).
    no_block = analyze(
        "on:\n  push:\n    branches: [main]\njobs:\n  lint:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    assert no_block.is_privileged is True


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


# ---------------------------------------------------------------------------
# Harden-Runner egress-block — mitigating-control detection + temper
# ---------------------------------------------------------------------------

_HARDEN = (
    "      - uses: step-security/harden-runner@v2\n"
    "        with:\n          egress-policy: block\n"
)


def test_detects_harden_runner_egress_block():
    content = (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + _HARDEN
    )
    assert analyze(content).has_harden_runner_egress_block is True


def test_harden_runner_audit_mode_is_not_a_control():
    content = (
        "steps:\n      - uses: step-security/harden-runner@v2\n"
        "        with:\n          egress-policy: audit\n"
    )
    assert analyze(content).has_harden_runner_egress_block is False


def test_egress_block_in_comment_is_not_a_control():
    content = (
        "steps:\n      - uses: step-security/harden-runner@v2\n"
        "        with:\n"
        "          egress-policy: audit # TODO: change to 'egress-policy: block' later\n"
    )
    assert analyze(content).has_harden_runner_egress_block is False


def test_mixed_block_and_audit_is_not_credited():
    content = (
        "jobs:\n  a:\n    steps:\n      - uses: step-security/harden-runner@v2\n"
        "        with:\n          egress-policy: block\n"
        "  b:\n    steps:\n      - uses: step-security/harden-runner@v2\n"
        "        with:\n          egress-policy: audit\n"
    )
    assert analyze(content).has_harden_runner_egress_block is False


def test_supply_chain_privileged_tempered_high_to_medium():
    base = "on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ secrets.TOKEN }}\n"
    assert compute_exploitability("supply_chain_immutability", analyze(base)) == "high"
    assert compute_exploitability("supply_chain_immutability", analyze(base + _HARDEN)) == "medium"


def test_supply_chain_non_privileged_tempered_medium_to_low():
    # A genuinely non-privileged GitHub workflow needs an explicit read-only
    # permissions block — otherwise its default token is write-capable and the
    # workflow is privileged (P2.2 implicit-default-write), which would route
    # the unhardened case to HIGH instead of MEDIUM.
    base = (
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n  b:\n    steps:\n      - run: echo hi\n"
    )
    assert compute_exploitability("supply_chain_immutability", analyze(base)) == "medium"
    assert compute_exploitability("supply_chain_immutability", analyze(base + _HARDEN)) == "low"


def test_ungoverned_services_tempered_by_harden_runner():
    base = "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
    assert compute_exploitability("ungoverned_services", analyze(base)) == "high"
    assert compute_exploitability("ungoverned_services", analyze(base + _HARDEN)) == "medium"


# ---------------------------------------------------------------------------
# P2.1 — OIDC `id-token: write` signal (distinct from has_write_permissions)
# ---------------------------------------------------------------------------


def test_detects_id_token_write_oidc_signal():
    """`id-token: write` is OIDC federation — a dynamically-minted token, not
    a static secret. It must surface as its own flag (not just be folded into
    has_write_permissions)."""
    content = (
        "on:\n  push:\n"
        "permissions:\n  id-token: write\n  contents: read\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
    )
    ctx = analyze(content)
    assert ctx.has_id_token_write is True
    # Backward-compat: id-token still counts toward the generic write flag.
    assert ctx.has_write_permissions is True


def test_detects_id_token_write_no_space_form():
    """The `id-token:write` (no space) YAML form must also match."""
    ctx = analyze("permissions:\n  id-token:write\n")
    assert ctx.has_id_token_write is True


def test_no_id_token_write_when_other_write_only():
    """A plain `contents: write` (no id-token) must NOT set the OIDC flag,
    while still setting the generic write flag."""
    ctx = analyze("permissions:\n  contents: write\n")
    assert ctx.has_id_token_write is False
    assert ctx.has_write_permissions is True


def test_no_id_token_write_when_read():
    """`id-token: read` (rare, but valid) is not the OIDC-mint signal."""
    ctx = analyze("permissions:\n  id-token: read\n")
    assert ctx.has_id_token_write is False


# ---------------------------------------------------------------------------
# P2.2 — implicit default write (GitHub, no explicit permissions block)
# ---------------------------------------------------------------------------


def test_implicit_default_write_makes_no_perms_github_workflow_privileged():
    """A GitHub workflow with NO explicit permissions block runs with a
    write-capable default GITHUB_TOKEN — mirror composer.py's
    `wf_default_write = wf.workflow_permissions is None`. is_privileged must
    reflect that even with no secrets / no explicit write / no pr_target."""
    content = (
        "on:\n  push:\n    branches: [main]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n      - run: make\n"
    )
    ctx = analyze(content)
    assert ctx.is_github is True
    assert ctx.has_explicit_permissions is False
    assert ctx.has_implicit_default_write is True
    assert ctx.is_privileged is True


def test_explicit_permissions_block_suppresses_implicit_default_write():
    """Once the workflow declares ANY explicit permissions block, the default
    token no longer applies — implicit-default-write must be False (the
    explicit perms drive has_write_permissions instead)."""
    content = (
        "on:\n  push:\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )
    ctx = analyze(content)
    assert ctx.has_explicit_permissions is True
    assert ctx.has_implicit_default_write is False
    # read-only explicit perms + nothing else -> not privileged
    assert ctx.is_privileged is False


def test_implicit_default_write_scoped_to_github_only():
    """A GitLab pipeline also has has_explicit_permissions False (it never
    sets a GitHub permissions block), but it has no GITHUB_TOKEN default —
    must NOT be credited implicit-default-write."""
    gitlab = (
        "stages:\n  - build\n"
        "build-job:\n  stage: build\n  script:\n    - make\n"
    )
    ctx = analyze(gitlab)
    assert ctx.is_github is False
    assert ctx.has_implicit_default_write is False
    assert ctx.is_privileged is False


def test_implicit_default_write_does_not_change_existing_explicit_semantics():
    """is_privileged for a write-perms workflow stays True (regression guard
    that the new disjunct didn't disturb the existing branches)."""
    assert analyze("permissions:\n  contents: write\n").is_privileged is True
    assert analyze("x: ${{ secrets.FOO }}").is_privileged is True


# ---------------------------------------------------------------------------
# P2.3 — pull_request_target floor (dangerous even read-only when it checks
# out untrusted PR content)
# ---------------------------------------------------------------------------


def test_pr_target_with_checkout_floored_above_low_when_read_only():
    """pull_request_target runs in BASE-repo context: checking out untrusted
    PR HEAD content is itself the attack surface (pwn-request). Even with an
    explicit read-only permissions block and no secret refs, a checkout under
    pr_target must floor to MEDIUM — never bottom out at LOW."""
    content = (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm ci && npm run build\n"
    )
    ctx = analyze(content)
    # Sanity: this is exactly the narrowed-perms / no-secrets case that used
    # to score LOW before the floor.
    assert ctx.has_pr_target is True
    assert ctx.has_checkout is True
    assert ctx.has_explicit_permissions is True
    assert ctx.has_secrets_reference is False
    assert compute_exploitability("privileged_pr_trigger", ctx) == "medium"


def test_pr_target_with_checkout_no_perms_block_still_high():
    """The pre-existing HIGH path (exposure + checkout) must be preserved: a
    pr_target checkout with NO permissions block has implicit write exposure
    -> HIGH, not merely the MEDIUM floor."""
    content = (
        "on:\n  pull_request_target:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
    )
    ctx = analyze(content)
    assert compute_exploitability("privileged_pr_trigger", ctx) == "high"


def test_pr_target_read_only_no_checkout_stays_low():
    """No checkout + narrowed perms + no secrets really has nothing an
    attacker can reach — the floor must NOT over-fire here; stays LOW."""
    content = (
        "on:\n  pull_request_target:\n    types: [labeled]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  label:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo no-checkout\n"
    )
    ctx = analyze(content)
    assert ctx.has_pr_target is True
    assert ctx.has_checkout is False
    assert compute_exploitability("privileged_pr_trigger", ctx) == "low"
