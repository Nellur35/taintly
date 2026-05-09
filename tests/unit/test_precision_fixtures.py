"""Precision fixtures — enforces the 'subtle safe-vs-unsafe' distinctions
called out in the improvement report (Phase 3, item 14).

Each test runs the real engine on a fixture file and asserts on the
shape of the findings, not just "did something fire".  The whole point
of these fixtures is to catch a future regression where a rule tweak
would flip a safe pattern into a false-positive alarm, or silently
downgrade a dangerous pattern into "medium".

Fixtures live in ``tests/fixtures/precision/``.  Each fixture file
starts with a comment block naming the report scenario it represents
and the expected behavior — keep the file and the test assertion in
sync when adjusting either.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules

_FIX = Path(__file__).parent.parent / "fixtures" / "precision"
_SAFE_GH = Path(__file__).parent.parent / "fixtures" / "github" / "safe"


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


# ---------------------------------------------------------------------------
# pull_request_target + permissions:{} + no checkout + no secrets
#
# Report: "Review-needed or lower priority, not top-severity alarm"
# ---------------------------------------------------------------------------


def test_benign_pr_target_is_review_needed_not_top_alarm(gh_rules):
    findings = scan_file(str(_FIX / "pr_target_benign.yml"), gh_rules)
    # SEC4-GH-002 should fire — the trigger IS present.
    sec4_002 = [f for f in findings if f.rule_id == "SEC4-GH-002"]
    assert sec4_002, "SEC4-GH-002 must detect the pull_request_target trigger"

    # But every SEC4-GH-002 finding here must carry review_needed = True
    # and NOT be surfaced as a confirmed top-severity risk.
    for f in sec4_002:
        assert f.review_needed is True, (
            f"SEC4-GH-002 on a benign pull_request_target must be review-needed, "
            f"got review_needed={f.review_needed}"
        )

    # Exploitability should be LOW — no checkout, no secrets, empty
    # permissions block means there's nothing to steal.
    privileged_findings = [f for f in findings if f.finding_family == "privileged_pr_trigger"]
    assert privileged_findings, "privileged_pr_trigger family must have at least one finding"
    for f in privileged_findings:
        assert f.exploitability == "low", (
            f"{f.rule_id} in a benign PR-target workflow should be exploitability=low, "
            f"got {f.exploitability!r}"
        )


# ---------------------------------------------------------------------------
# Unpinned action in a release workflow with contents: write
#
# Report: "Strong finding"
# ---------------------------------------------------------------------------


def test_unpinned_release_is_high_exploitability(gh_rules):
    findings = scan_file(str(_FIX / "unpinned_release.yml"), gh_rules)
    unpinned = [f for f in findings if f.rule_id in ("SEC3-GH-001", "SEC3-GH-002")]
    assert unpinned, "Unpinned action in a release workflow must fire SEC3-GH-001/002"

    for f in unpinned:
        assert f.exploitability == "high", (
            f"{f.rule_id} in release+write context should be exploitability=high, "
            f"got {f.exploitability!r}"
        )
        assert f.finding_family == "supply_chain_immutability"
        assert f.severity >= Severity.HIGH


# ---------------------------------------------------------------------------
# SHA-pinned reusable workflow with minimal permissions
#
# Report: "No mutable-reference finding"
# ---------------------------------------------------------------------------


def test_sha_pinned_reusable_produces_no_mutable_findings(gh_rules):
    findings = scan_file(str(_FIX / "pinned_reusable_minimal.yml"), gh_rules)
    mutable = [f for f in findings if f.finding_family == "supply_chain_immutability"]
    rule_ids = [f.rule_id for f in mutable]
    assert not mutable, (
        f"SHA-pinned reusable workflow with minimal permissions must produce NO "
        f"mutable-reference findings, but got: {rule_ids}"
    )


# ---------------------------------------------------------------------------
# workflow_dispatch input routed through a step env var
#
# Report: "Lower or no injection finding"
# ---------------------------------------------------------------------------


def test_safe_workflow_dispatch_env_routing_does_not_fire_injection(gh_rules):
    findings = scan_file(str(_FIX / "workflow_dispatch_safe_input.yml"), gh_rules)
    injection = [f for f in findings if f.finding_family == "script_injection"]

    # If any script-injection rule fires, it must not be high-exploitability
    # and it must not be severity CRITICAL — the value never reaches the
    # run: block as a raw expansion.
    for f in injection:
        assert f.severity < Severity.CRITICAL, (
            f"Safe env-routed workflow_dispatch input triggered CRITICAL "
            f"injection finding ({f.rule_id}) — false positive"
        )
        assert f.exploitability != "high", (
            f"Safe env-routed workflow_dispatch input produced a HIGH-"
            f"exploitability injection finding ({f.rule_id})"
        )


# ---------------------------------------------------------------------------
# Placeholder password for local keychain setup
#
# Report: "Do not classify as likely secret without stronger evidence"
# ---------------------------------------------------------------------------


def test_placeholder_password_not_treated_as_confirmed_secret(gh_rules):
    """The placeholder 'temp-keychain-pw' must not be flagged as a real
    leaked secret.  Rules that identify genuine checkout / credential-
    persistence behavior are allowed to fire (they target structure,
    not the placeholder string) — only rules that do pattern-based
    secret-string heuristics are in scope.
    """
    findings = scan_file(str(_FIX / "placeholder_password.yml"), gh_rules)

    # Secret-string heuristic rules are the ones whose confidence was
    # explicitly downgraded from the default in taintly.families.
    # If any of THOSE fire, they must be confidence<high AND must match
    # the placeholder text specifically.
    from taintly.families import default_confidence
    for f in findings:
        if default_confidence(f.rule_id) == "high":
            continue  # High-confidence structural rules are not in scope
        if "temp-keychain-pw" in (f.snippet or ""):
            assert f.confidence != "high", (
                f"{f.rule_id} classified the placeholder password with HIGH confidence"
            )


# ---------------------------------------------------------------------------
# SEC5-GH-001 — modern OIDC publishers (uv / twine / cargo / npm)
#
# Workflows that grant ``id-token: write`` and invoke a modern
# trusted-publishing command via ``run:`` legitimately need the
# permission.  SEC5-GH-001 must not fire on these.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name",
    [
        "oidc_uv_publish.yml",
        "oidc_twine_use_oidc.yml",
        "oidc_cargo_publish.yml",
        "oidc_npm_provenance.yml",
    ],
)
def test_oidc_shell_publishers_do_not_trip_sec5_gh_001(fixture_name, gh_rules):
    findings = scan_file(str(_SAFE_GH / fixture_name), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC5-GH-001"]
    assert not fired, (
        f"{fixture_name}: SEC5-GH-001 fired on a workflow with a "
        f"recognised shell-form OIDC publisher: {fired}"
    )


# ---------------------------------------------------------------------------
# SEC4-GH-003 — workflow_run conclusion gate
#
# The missing-conclusion-gate finding is one per workflow, not one
# per ``github.event.workflow_run.*`` property reference.  Anchor
# matches the trigger declaration line only.
# ---------------------------------------------------------------------------


_VULN_GH = Path(__file__).parent.parent / "fixtures" / "github" / "vulnerable"


def test_sec4_gh_003_fires_once_per_workflow(gh_rules):
    findings = scan_file(str(_VULN_GH / "workflow_run_no_conclusion.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC4-GH-003"]
    assert len(fired) == 1, (
        f"SEC4-GH-003 must fire exactly once per workflow_run-triggered "
        f"workflow lacking the conclusion gate, got {len(fired)} findings: "
        f"{[(f.line, f.snippet) for f in fired]}"
    )
    # Anchor cites the trigger declaration line, not a property
    # reference deeper in the file.
    assert "workflow_run:" in fired[0].snippet, (
        f"Expected anchor on the workflow_run: declaration line, "
        f"got snippet: {fired[0].snippet!r}"
    )


# ---------------------------------------------------------------------------
# SEC6-GH-010 — Secret passed as action input without env-block masking
#
# The rule fires when a credential-shape ``with:`` input takes a
# ``${{ secrets.X }}`` value directly.  When the same job routes the
# secret through ``env:`` instead, the env-block declaration registers
# the value with the runner's log-redactor and the rule must not fire.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name",
    [
        "secret_in_with_but_also_env.yml",
        "with_input_no_secret.yml",
    ],
)
def test_sec6_gh_010_does_not_fire_on_safe_with_input(fixture_name, gh_rules):
    findings = scan_file(str(_SAFE_GH / fixture_name), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC6-GH-010"]
    assert not fired, (
        f"{fixture_name}: SEC6-GH-010 fired on a workflow whose "
        f"with-input is either env-masked or non-secret: {fired}"
    )


def test_sec6_gh_010_fires_on_unmasked_with_input(gh_rules):
    findings = scan_file(str(_VULN_GH / "secret_in_with_input.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC6-GH-010"]
    assert fired, (
        "SEC6-GH-010 must fire on a workflow that passes a secret as a "
        "credential-shape with-input without env-block routing"
    )
    # Cite the anchor line, not the surrounding context.
    assert all("secrets." in f.snippet for f in fired), (
        f"Expected anchor on the with-input line citing secrets.X, "
        f"got snippets: {[f.snippet for f in fired]}"
    )


# ---------------------------------------------------------------------------
# SEC1-GH-001 — job-scoped anchor (don't fire on trigger keywords)
#
# A workflow that triggers ``on: release: { types: [...] }`` AND runs a
# publish: job has two lines that lexically match the credential-shape
# regex.  Only the job line should fire; the trigger keyword is a
# false-positive shape.
# ---------------------------------------------------------------------------


def test_sec1_gh_001_does_not_fire_on_release_trigger(gh_rules):
    findings = scan_file(str(_SAFE_GH / "release_trigger_with_environment.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert not fired, (
        f"SEC1-GH-001 must not fire on a publish: job that has "
        f"environment: declared, regardless of the trigger keyword "
        f"shape on the on: block: {fired}"
    )


def test_sec1_gh_001_does_not_fire_on_release_automation_job(gh_rules):
    findings = scan_file(str(_SAFE_GH / "release_automation_no_environment.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert not fired, (
        "SEC1-GH-001 must not fire on release metadata automation "
        f"that is not itself a production deploy/publish job: {fired}"
    )


def test_sec1_gh_001_does_not_fire_on_release_metadata_job_with_custom_name(gh_rules):
    findings = scan_file(str(_SAFE_GH / "release_metadata_custom_name.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert not fired, (
        "SEC1-GH-001 must not fire on a custom-named metadata-only "
        f"release automation job: {fired}"
    )


def test_sec1_gh_001_does_not_fire_on_release_metadata_job_with_environment(gh_rules):
    findings = scan_file(str(_SAFE_GH / "release_metadata_with_environment.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert not fired, (
        "SEC1-GH-001 must not fire when release metadata automation "
        f"declares an explicit environment: {fired}"
    )


def test_sec1_gh_001_still_fires_on_release_automation_that_publishes(gh_rules):
    findings = scan_file(str(_VULN_GH / "release_please_with_publish_step.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert fired, (
        "SEC1-GH-001 must still fire when a release automation job "
        "performs real publish/deploy work without environment approval"
    )
    assert any("release-please:" in f.snippet for f in fired), (
        "SEC1-GH-001 should anchor on the publish-capable job context, "
        f"got snippets: {[f.snippet for f in fired]}"
    )


def test_sec1_gh_001_anchors_on_job_not_trigger(gh_rules):
    findings = scan_file(str(_VULN_GH / "publish_job_no_environment.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC1-GH-001"]
    assert len(fired) == 1, (
        f"SEC1-GH-001 must fire exactly once on a publish: job lacking "
        f"environment:, regardless of any same-shape trigger keyword "
        f"earlier in the file. Got {len(fired)} findings: "
        f"{[(f.line, f.snippet) for f in fired]}"
    )
    # The anchor cites the publish: line, not the release: trigger.
    assert "publish:" in fired[0].snippet, (
        f"Expected anchor on the publish: job line, "
        f"got snippet: {fired[0].snippet!r}"
    )


# ---------------------------------------------------------------------------
# SEC4-GH-018 — severity calibration on maintainer-gated triggers
#
# The unquoted-$GITHUB_REF_NAME vector is HIGH only when
# ``$GITHUB_REF_NAME`` is attacker-controlled.  Tag push and release
# events are maintainer-gated firing paths, so the same unquoted
# reference under those triggers is MEDIUM at most.
# ---------------------------------------------------------------------------


def test_sec4_gh_018_downgrades_to_medium_on_tag_push(gh_rules):
    from taintly.models import Severity

    findings = scan_file(str(_VULN_GH / "tag_push_unquoted_ref_name.yml"), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC4-GH-018"]
    assert fired, "SEC4-GH-018 must still fire on the unquoted vector"
    for f in fired:
        assert f.severity == Severity.MEDIUM, (
            f"On a tag-push-only trigger, SEC4-GH-018 should be downgraded "
            f"from HIGH to MEDIUM, got {f.severity!r}"
        )


def test_sec4_gh_018_stays_high_on_pull_request(gh_rules, tmp_path):
    """Same unquoted vector on a fork-reachable trigger must stay
    HIGH — the calibration only applies when the trigger set is
    exclusively maintainer-gated.
    """
    from taintly.models import Severity

    p = tmp_path / "pr.yml"
    p.write_text(
        "name: PR\n"
        "on:\n  pull_request:\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo Building $GITHUB_REF_NAME\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC4-GH-018"]
    assert fired
    for f in fired:
        assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# iter-6 (2026-05-09) precision regressions
#
# Each FP confirmed by the public-repo audit (chunks 4-7 of the audit
# triage) is pinned here. Future rule edits that re-introduce any of
# these FPs will fail one of these tests with a clear message
# pointing back to the FP.
# ---------------------------------------------------------------------------


def test_sec6_gh_001_skips_ephemeral_keychain_password(gh_rules, tmp_path):
    """iter-6 FP from gh/cli's deployment.yml: ``keychain_password=
    "password1"`` is the macOS code-signing ephemeral keychain
    pattern (the actual cert pwd is $APPLE_APPLICATION_CERT_PASSWORD).
    SEC6-GH-001 firing CRITICAL on this is wrong — variable name
    boundary regex prevents the substring-match on ``password``."""
    p = tmp_path / "macos_signing.yml"
    p.write_text(
        "jobs:\n  build:\n    runs-on: macos-latest\n    steps:\n"
        "      - run: |\n"
        "          keychain=\"$RUNNER_TEMP/buildagent.keychain\"\n"
        '          keychain_password="password1"\n'
        '          security create-keychain -p "$keychain_password" "$keychain"\n'
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC6-GH-001"]
    assert not fired, (
        f"SEC6-GH-001 must not fire on the ephemeral-keychain pattern; "
        f"got {[(f.line, f.snippet) for f in fired]}"
    )


def test_taint_gh_013_skips_safe_system_contexts(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's daily_fuzz.yaml: github-script
    body interpolating only ``${{ github.repository }}`` and
    ``${{ github.run_id }}`` — both system-controlled, never
    attacker-influenceable. Narrowed match requires an attacker-
    controlled token before firing."""
    p = tmp_path / "github_script_safe.yml"
    p.write_text(
        "jobs:\n  notify:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            await github.rest.issues.create({\n"
        "              body: 'Run https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}',\n"
        "            })\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "TAINT-GH-013"]
    assert not fired, (
        f"TAINT-GH-013 must not fire when interpolation contains only "
        f"system-controlled contexts; got {fired}"
    )


def test_sec5_gh_001_recognizes_codspeed_oidc(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's ci.yaml: ``id-token: write``
    granted for CodSpeed benchmarking, with the comment
    ``# required for OIDC authentication with CodSpeed``. CodSpeed
    is now in the OIDC-consumer allowlist."""
    p = tmp_path / "codspeed.yml"
    p.write_text(
        "name: bench\non: push\njobs:\n  bench:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: read\n      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n"
        "      - uses: CodSpeedHQ/action@c381be0bfd20e844fb45594f6aa182ffcd94545c # v4\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC5-GH-001"]
    assert not fired, (
        f"SEC5-GH-001 must recognize CodSpeedHQ/action as an OIDC consumer; "
        f"got {fired}"
    )


def test_sec6_gh_005_skips_env_block_assignments(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's publish-mirror.yml:
    secrets embedded in URL values inside ``env:`` blocks are the
    RECOMMENDED remediation form (env var path is masked by the
    runner). The rule's title says ``not via env var`` but it
    fired on env: assignments. Negative-lookahead exclude on
    non-run/script keys fixes it."""
    p = tmp_path / "env_secret.yml"
    p.write_text(
        "jobs:\n  upload:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Upload\n"
        "        env:\n"
        "          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}\n"
        "          AWS_ENDPOINT_URL: https://${{ secrets.ACCOUNT_ID }}.r2.example.com\n"
        "        run: aws s3 cp dist/ s3://bucket/\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC6-GH-005"]
    assert not fired, (
        f"SEC6-GH-005 must not fire on env: block assignments; got {fired}"
    )


def test_sec6_gh_005_still_fires_on_run_block_url(gh_rules, tmp_path):
    """Companion to the env-block test: secret embedded in a
    run: URL is the ACTUAL bad pattern and must still fire."""
    p = tmp_path / "run_secret.yml"
    p.write_text(
        "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: git clone https://${{ secrets.PAT }}@github.com/x/y.git out\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC6-GH-005"]
    assert fired, (
        "SEC6-GH-005 MUST still fire on secrets embedded in run: shell URLs"
    )


def test_lotp_gh_001_skips_non_pr_workflows(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's publish-{,ty-}playground.yml:
    workflow_call/workflow_dispatch only — no PR trigger. The
    workflow uses ``${{ github.head_ref || 'main' }}`` in a
    cloudflare wrangler-action's ``branch:`` parameter (NOT in
    actions/checkout's ``ref:``), so the head-ref reference doesn't
    select a code revision. Narrowed _PR_HEAD_CHECKOUT requires
    the reference to be on a ``ref:`` line."""
    p = tmp_path / "workflow_call_only.yml"
    p.write_text(
        "name: Publish playground\n"
        "on:\n  workflow_dispatch:\n  workflow_call:\n"
        "permissions: {}\n"
        "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - uses: cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd\n"
        "        with:\n"
        "          command: pages deploy --branch ${{ github.head_ref || 'main' }}\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "LOTP-GH-001"]
    assert not fired, (
        f"LOTP-GH-001 must not fire when head_ref is in a non-checkout-ref "
        f"context; got {[(f.line, f.snippet) for f in fired]}"
    )


def test_lotp_gh_005_skips_npm_self_upgrade(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's publish-wasm.yml:
    ``npm install -g npm@11.12.0`` upgrades the package manager
    itself (foundational infrastructure). It does NOT install an
    attacker-controllable dependency that could carry malicious
    lifecycle scripts. Excluded via the new ``-g (npm|pnpm|yarn|
    corepack)`` exclude pattern."""
    p = tmp_path / "npm_self_upgrade.yml"
    p.write_text(
        "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n    steps:\n"
        "      - run: npm install -g npm@11.12.0\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "LOTP-GH-005"]
    assert not fired, (
        f"LOTP-GH-005 must not fire on npm self-upgrade; got {fired}"
    )


def test_sec9_gh_002_requires_real_release_trigger(gh_rules, tmp_path):
    """iter-6 FP from astral-sh/ruff's ci.yaml (push:main + pull_request)
    and gh/cli's deployment.yml (workflow_dispatch with ``release:``
    as an INPUT name). Loose ``(release:|tags:)`` requires regex
    matched job names and input names. New regex requires the token
    to actually appear as part of an ``on:`` block."""
    p = tmp_path / "non_release.yml"
    p.write_text(
        "name: CI\n"
        "on:\n  push:\n    branches: [main]\n  pull_request:\n"
        "jobs:\n"
        "  cargo-test-linux-release:\n"  # job name contains "release"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC9-GH-002"]
    assert not fired, (
        f"SEC9-GH-002 must not fire when ``release`` only appears as a "
        f"job name (not in on: trigger); got {fired}"
    )


def test_sec3_gh_002_and_sec8_gh_003_no_double_fire_on_branch_pin(
    gh_rules, tmp_path
):
    """iter-6 dedup: ``uses: org/repo/.github/workflows/x.yml@main``
    used to fire BOTH SEC3-GH-002 (CRITICAL) AND SEC8-GH-003 (HIGH)
    on the exact same line. SEC8-GH-003 now excludes branch refs
    (SEC3-GH-002 owns those CRITICAL); SEC8-GH-003 keeps the
    tag-pin case."""
    p = tmp_path / "branch_pinned_reusable.yml"
    p.write_text(
        "on: push\njobs:\n  triage:\n"
        "    uses: external/shared-workflows/.github/workflows/triage.yml@main\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = sorted({f.rule_id for f in findings if f.rule_id in ("SEC3-GH-002", "SEC8-GH-003")})
    assert fired == ["SEC3-GH-002"], (
        f"On a branch-pinned external reusable workflow, only SEC3-GH-002 "
        f"should fire (CRITICAL — branch ref). SEC8-GH-003 should defer. "
        f"Got: {fired}"
    )


def test_sec4_gh_002_downgraded_to_medium(gh_rules, tmp_path):
    """iter-6: bare pull_request_target use is MEDIUM/review-needed,
    not HIGH. SEC4-GH-001 covers the dangerous combination
    (trigger + PR checkout) at CRITICAL."""
    from taintly.models import Severity

    p = tmp_path / "pr_target_label_only.yml"
    p.write_text(
        "on:\n  pull_request_target:\n    types: [labeled]\n"
        "jobs:\n  label:\n    runs-on: ubuntu-latest\n"
        "    permissions: {}\n"
        "    steps:\n      - run: echo 'no checkout'\n"
    )
    findings = scan_file(str(p), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC4-GH-002"]
    assert fired, "SEC4-GH-002 should still detect the trigger"
    for f in fired:
        assert f.severity == Severity.MEDIUM, (
            f"Bare pull_request_target should be MEDIUM after iter-6; got {f.severity}"
        )


def test_engine_handles_gitlab_reference_tag(gitlab_rules, tmp_path):
    """iter-6 engine fix: GitLab's ``!reference`` tag was treated as
    an unsupported custom tag, halting structural parsing for the
    rest of the file (gitlab-org/cli's .gitlab-ci.yml emitted
    ENGINE-ERR at line 367). Tokenizer now passes through.
    """
    p = tmp_path / "gitlab_with_reference.yml"
    p.write_text(
        ".auth: &auth\n  before_script:\n    - echo authenticated\n"
        "build:\n"
        "  before_script:\n"
        "    - !reference [.auth, before_script]\n"
        "  script:\n    - make build\n"
    )
    findings = scan_file(str(p), gitlab_rules)
    engine_err = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert not engine_err, (
        f"!reference must not trigger ENGINE-ERR; got {engine_err}"
    )
