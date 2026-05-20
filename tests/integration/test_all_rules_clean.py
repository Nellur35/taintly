"""Golden file integration tests.

The most important single test in the suite:
  fully_hardened.yml must produce ZERO findings from ALL rules.

This test fails whenever:
  - A new rule is added that fires on correctly hardened code (false positive)
  - An existing rule is loosened to the point it fires on safe code
  - The hardened fixture is accidentally made less secure

It is a living contract between the rule set and the definition of "secure."
If this test fails, either fix the false positive in the rule, or update the
fixture with justification.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform

FIXTURES = Path(__file__).parent.parent / "fixtures"


# =============================================================================
# Golden file: fully hardened workflows must produce ZERO findings
# =============================================================================


def _is_stub_rule(rule) -> bool:
    """Return True for rules that opt out of the per-file test-sample
    contract.

    Three cases:
      * AbsencePattern with INTENTIONALLY_DISABLED — always fires on
        every file and cannot be satisfied by any fixture.
      * CorpusPattern — cross-workflow rules whose test_positive /
        test_negative samples are MULTI-FILE repos rather than single
        YAML strings.  These rules are exercised by the integration
        tests in tests/unit/test_cross_workflow_rules.py.
      * Inventory-style review-needed INFO rules (SEC3-{GH,GL,JK}-006/
        005) — these fire on EVERY external dependency by design and
        ride the ``--baseline`` / ``--diff`` workflow rather than the
        "fix the FP" loop.  A hardened workflow that legitimately
        depends on a third-party action / GitLab include / Jenkins
        shared library still trips these rules; that's the intended
        behaviour.
    """
    from taintly.gitlab_workflow_corpus import GitLabCorpusPattern
    from taintly.models import AbsencePattern, Severity
    from taintly.rules.github.sec3_sec4_supply_chain_ppe import (
        ArchivedActionPattern,
        ImposterCommitPattern,
    )
    from taintly.rules.gitlab.sec3_sec6_supply_chain_creds import ArchivedIncludeProjectPattern
    from taintly.workflow_corpus import CorpusPattern

    if isinstance(rule.pattern, CorpusPattern):
        return True
    # GitLabCorpusPattern is the GL parallel of CorpusPattern —
    # CHAIN-GL composer rules whose test_positive / test_negative
    # samples are full ``.gitlab-ci.yml`` repos (with optional
    # ``include: local:`` files) rather than single YAML strings.
    # These rules are exercised by the integration tests in
    # tests/unit/test_chain_gl_composer.py.
    if isinstance(rule.pattern, GitLabCorpusPattern):
        return True
    # SEC3-GH-009 (imposter-commit) is opt-in via --check-imposter-commits
    # and depends on a network call.  Its samples live in
    # tests/unit/test_imposter_commits.py against a stub verifier;
    # the per-file test-sample contract isn't applicable.
    if isinstance(rule.pattern, ImposterCommitPattern):
        return True
    # SEC3-GH-010 (archived-uses) + SEC3-GL-008 (archived-includes) —
    # opt-in network-dependent rules with the same exemption rationale.
    if isinstance(rule.pattern, ArchivedActionPattern | ArchivedIncludeProjectPattern):
        return True
    if (
        getattr(rule, "review_needed", False)
        and rule.severity == Severity.INFO
        and getattr(rule, "finding_family", "") == "Mutable dependency references"
    ):
        return True
    return (
        isinstance(rule.pattern, AbsencePattern)
        and "INTENTIONALLY_DISABLED" in rule.pattern.absent
    )


def test_github_fully_hardened_produces_no_findings(github_rules):
    """ALL active GitHub rules must produce zero findings on a correctly hardened workflow.

    If this test fails:
      1. Check which rule fired — it may be a false positive.
      2. If the rule is correct, update the fixture to fix the actual issue.
      3. Never suppress this test with must_not_fire lists — fix the root cause.
    """
    active_rules = [r for r in github_rules if not _is_stub_rule(r)]
    fixture = FIXTURES / "github" / "safe" / "fully_hardened.yml"
    findings = scan_file(str(fixture), rules=active_rules)
    real_findings = [f for f in findings if f.rule_id != "ENGINE-ERR"]

    if real_findings:
        details = "\n".join(
            f"  {f.rule_id} [{f.severity.value}] line {f.line}: {f.snippet}"
            for f in real_findings
        )
        pytest.fail(
            f"fully_hardened.yml triggered {len(real_findings)} rule(s) — "
            f"these are false positives or the fixture needs updating:\n{details}"
        )


def test_gitlab_fully_hardened_produces_no_findings(gitlab_rules):
    """ALL active GitLab rules must produce zero findings on a hardened pipeline."""
    active_rules = [r for r in gitlab_rules if not _is_stub_rule(r)]
    fixture = FIXTURES / "gitlab" / "safe" / "fully_hardened.yml"
    findings = scan_file(str(fixture), rules=active_rules)
    real_findings = [f for f in findings if f.rule_id != "ENGINE-ERR"]

    if real_findings:
        details = "\n".join(
            f"  {f.rule_id} [{f.severity.value}] line {f.line}: {f.snippet}"
            for f in real_findings
        )
        pytest.fail(
            f"gitlab/fully_hardened.yml triggered {len(real_findings)} rule(s):\n{details}"
        )


def test_jenkins_fully_hardened_produces_no_findings(jenkins_rules):
    """ALL active Jenkins rules must produce zero findings on a hardened Jenkinsfile."""
    active_rules = [r for r in jenkins_rules if not _is_stub_rule(r)]
    fixture = FIXTURES / "jenkins" / "safe" / "Jenkinsfile"
    findings = scan_file(str(fixture), rules=active_rules)
    real_findings = [f for f in findings if f.rule_id != "ENGINE-ERR"]

    if real_findings:
        details = "\n".join(
            f"  {f.rule_id} [{f.severity.value}] line {f.line}: {f.snippet}"
            for f in real_findings
        )
        pytest.fail(
            f"jenkins/Jenkinsfile triggered {len(real_findings)} rule(s) — "
            f"these are false positives or the fixture needs updating:\n{details}"
        )


# =============================================================================
# Vulnerable fixtures must produce expected findings
# =============================================================================


@pytest.mark.parametrize(
    ("fixture_path", "expected_rules", "allowed_extras"),
    [
        # Each row pins both the rule(s) the fixture is FOR (expected_rules)
        # AND the additional rules legitimately allowed to co-fire on the
        # same fixture (allowed_extras). Anything outside expected_rules ∪
        # allowed_extras is an unexpected co-fire, treated as a real
        # regression — either a precision drift in some unrelated rule, or
        # a fixture that grew an incidental violation. The audit's
        # rationale: ``expected ⊆ fired`` was too lax; a rule whose regex
        # quietly broadens stops being noticed because the fixture's
        # original target rule still fires. Forcing maintainers to declare
        # co-fires explicitly turns silent broadening into a test failure.
        # ── GitHub ──────────────────────────────────────────────────────────────
        # The allowed_extras lists below were captured from the actual
        # rule pack against each fixture. They reflect the real, current
        # co-firing surface. Any drift — a rule that newly fires (or stops
        # firing) — surfaces immediately as a test failure. To accept a
        # legitimate new co-fire: edit the row. To investigate an
        # unexpected one: figure out whether it's a precision regression
        # in the firing rule or a real new violation in the fixture.
        # PSE-GH-006 is an expected co-fire on this fixture: ppe_classic
        # is the canonical pwn_request shape (pull_request_target +
        # tainted ref checkout + npm install in the same job), which is
        # exactly the 5-way join PSE-GH-006 detects.  The default token
        # for pull_request_target is write-capable when no permissions
        # block is set, completing the chain.
        ("github/vulnerable/ppe_classic.yml", ["SEC3-GH-001"], [
            "LOTP-GH-001", "LOTP-GH-003", "PSE-GH-006", "SEC10-GH-001",
            "SEC2-GH-002", "SEC3-GH-003", "SEC3-GH-004", "SEC3-GH-006",
            "SEC4-GH-001", "SEC4-GH-002", "SEC4-GH-005", "SEC4-GH-005B", "SEC4-GH-011",
        ]),
        ("github/vulnerable/write_all_permissions.yml", ["SEC2-GH-001"], ["SEC1-GH-001", "SEC10-GH-001"]),
        ("github/vulnerable/injection_run_block.yml",   ["SEC4-GH-004"], ["SEC10-GH-001", "SEC4-GH-002", "SEC4-GH-006"]),
        ("github/vulnerable/workflow_run_no_conclusion.yml", ["SEC4-GH-003"], ["SEC1-GH-001", "SEC10-GH-001", "SEC4-GH-004", "SEC4-GH-005", "SEC4-GH-005B", "TAINT-GH-008"]),
        ("github/vulnerable/secret_in_with_input.yml", ["SEC6-GH-010"], ["SEC1-GH-001", "SEC10-GH-001", "SEC3-GH-006"]),
        ("github/vulnerable/publish_job_no_environment.yml", ["SEC1-GH-001"], ["SEC10-GH-001"]),
        ("github/vulnerable/release_please_with_publish_step.yml", ["SEC1-GH-001"], ["SEC3-GH-006"]),
        ("github/vulnerable/tag_push_unquoted_ref_name.yml", ["SEC4-GH-018"], ["SEC1-GH-001", "SEC10-GH-001"]),
        # PSE-GH-006 expected co-fire: the fixture is the canonical
        # "imposter trigger" shape (pull_request_target + tainted
        # head.sha checkout + ./build.sh in the same job).
        ("github/vulnerable/pull_request_target_head_sha_checkout.yml", ["SEC4-GH-001"], ["PSE-GH-006", "SEC10-GH-001", "SEC2-GH-002", "SEC4-GH-002", "SEC4-GH-005", "SEC4-GH-005B"]),
        ("github/vulnerable/ai_trust_remote_code.yml",  ["AI-GH-001"], ["SEC10-GH-001"]),
        ("github/vulnerable/ai_hf_no_revision.yml",     ["AI-GH-002"], ["AI-GH-004", "SEC10-GH-001"]),
        ("github/vulnerable/ai_torch_load_unsafe.yml",  ["AI-GH-003"], ["SEC10-GH-001"]),
        ("github/vulnerable/ai_no_model_scanner.yml",   ["AI-GH-004"], ["SEC10-GH-001"]),
        ("github/vulnerable/ai_prompt_injection_surface.yml", ["AI-GH-005"], ["AI-GH-015", "SEC10-GH-001", "SEC4-GH-002", "TAINT-GH-012"]),
        ("github/vulnerable/ai_agent_on_pr.yml",        ["AI-GH-006"], [
            "AI-GH-015", "AI-GH-020", "PSE-GH-001", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC5-GH-001", "SEC6-GH-010",
        ]),
        ("github/vulnerable/ai_llm_output_to_shell.yml", ["AI-GH-007"], ["AI-GH-005", "AI-GH-015", "SEC10-GH-001"]),
        ("github/vulnerable/ai_agent_with_pr_checkout.yml", ["AI-GH-008"], [
            "AI-GH-006", "AI-GH-015", "AI-GH-020", "AI-GH-021", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC4-GH-001", "SEC4-GH-002", "SEC6-GH-010",
        ]),
        ("github/vulnerable/ai_agent_dangerous_flags.yml", ["AI-GH-009"], [
            "AI-GH-006", "AI-GH-015", "AI-GH-018", "AI-GH-020", "AI-GH-022",
            "SEC10-GH-001", "SEC3-GH-001", "SEC3-GH-006", "SEC6-GH-010",
        ]),
        ("github/vulnerable/ai_joblib_load.yml",         ["AI-GH-010"], ["SEC10-GH-001"]),
        ("github/vulnerable/ai_mcp_unpinned.yml",        ["AI-GH-011"], [
            "AI-GH-006", "AI-GH-012", "AI-GH-015", "AI-GH-020", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC6-GH-010",
        ]),
        ("github/vulnerable/ai_mcp_privileged.yml",      ["AI-GH-012"], [
            "AI-GH-006", "AI-GH-015", "AI-GH-020", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC4-GH-023", "SEC6-GH-010",
        ]),
        ("github/vulnerable/ai_agent_cli_on_pr.yml",     ["AI-GH-013"], ["AI-GH-015", "SEC10-GH-001"]),
        ("github/vulnerable/ai_agent_output_to_shell.yml", ["AI-GH-014"], [
            "AI-GH-006", "AI-GH-015", "AI-GH-020", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC4-GH-023", "SEC6-GH-010",
        ]),
        ("github/vulnerable/taint_agent_output.yml",    ["TAINT-GH-005"], [
            "AI-GH-006", "AI-GH-015", "AI-GH-020", "SEC10-GH-001",
            "SEC3-GH-001", "SEC3-GH-006", "SEC4-GH-023", "SEC6-GH-010",
        ]),
        # ── GitLab ──────────────────────────────────────────────────────────────
        ("gitlab/vulnerable/ai_trust_remote_code.yml",           ["AI-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_llm_output_to_shell.yml",         ["AI-GL-002"], ["AI-GL-007", "SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_joblib_load.yml",                 ["AI-GL-003"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_hf_no_revision.yml",              ["AI-GL-004"], ["AI-GL-006", "SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_torch_load_unsafe.yml",           ["AI-GL-005"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_no_model_scanner.yml",            ["AI-GL-006"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_prompt_injection_surface.yml",    ["AI-GL-007"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/ai_agent_cli_on_mr.yml",             ["AI-GL-008"], ["LOTP-GL-001", "LOTP-GL-003", "SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/debug_trace.yml",                    ["SEC7-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/prod_no_approval.yml",               ["SEC1-GL-001"], ["SEC10-GL-002", "SEC10-GL-003", "SEC5-GL-001"]),
        ("gitlab/vulnerable/security_gate_allow_failure.yml",    ["SEC1-GL-002"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/docker_auth_config.yml",             ["SEC2-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/dind_no_tls.yml",                    ["SEC2-GL-002"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/unquoted_commit_message.yml",        ["SEC4-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/trigger_with_job_token.yml",         ["SEC4-GL-002"], ["SEC10-GL-002", "SEC10-GL-003", "SEC3-GL-006"]),
        ("gitlab/vulnerable/unquoted_ref_name.yml",              ["SEC4-GL-003"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/pipeline_source_only.yml",           ["SEC4-GL-004"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/mr_pipeline_docker_push.yml",        ["SEC4-GL-005"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/deploy_no_resource_group.yml",       ["SEC5-GL-001"], ["SEC1-GL-001", "SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/wget_pipe_bash.yml",                 ["SEC6-GL-006"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/long_lived_cloud_creds.yml",         ["SEC6-GL-007"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/registry_override.yml",              ["SEC6-GL-008"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/service_latest.yml",                 ["SEC8-GL-003"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/artifacts_no_access.yml",            ["SEC9-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/download_no_checksum.yml",           ["SEC9-GL-002"], ["AI-GL-006", "SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/cache_no_key.yml",                   ["SEC9-GL-003"], ["SEC10-GL-002", "SEC10-GL-003"]),
        ("gitlab/vulnerable/print_job_token.yml",                ["SEC10-GL-001"], ["SEC10-GL-002", "SEC10-GL-003"]),
        # ── Jenkins ─────────────────────────────────────────────────────────────
        ("jenkins/vulnerable/ai_trust_remote_code.Jenkinsfile",     ["AI-JK-001"], ["SEC3-JK-005"]),
        ("jenkins/vulnerable/ai_torch_load_unsafe.Jenkinsfile",     ["AI-JK-002"], ["SEC3-JK-005"]),
        ("jenkins/vulnerable/ai_llm_output_to_shell.Jenkinsfile",   ["AI-JK-003"], ["SEC3-JK-005"]),
        ("jenkins/vulnerable/ai_joblib_load.Jenkinsfile",           ["AI-JK-004"], ["SEC3-JK-005"]),
        ("jenkins/vulnerable/unpinned_shared_library.Jenkinsfile",  ["SEC3-JK-001"], ["SEC1-JK-002", "SEC10-JK-001", "SEC3-JK-005"]),
        ("jenkins/vulnerable/hardcoded_credential.Jenkinsfile",     ["SEC6-JK-001"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/credential_echo.Jenkinsfile",          ["SEC6-JK-002"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/agent_any.Jenkinsfile",                ["SEC7-JK-001"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/docker_latest.Jenkinsfile",            ["SEC8-JK-001"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/curl_pipe_bash.Jenkinsfile",           ["SEC9-JK-001"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/params_injection.Jenkinsfile",         ["SEC4-JK-001"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001", "TAINT-JK-001"]),
        ("jenkins/vulnerable/scm_env_injection.Jenkinsfile",        ["SEC4-JK-002"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/dynamic_groovy_eval.Jenkinsfile",      ["SEC4-JK-003"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/println_credential.Jenkinsfile",       ["SEC6-JK-003"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/remote_groovy_script.Jenkinsfile",     ["SEC8-JK-002"], ["SEC1-JK-002", "SEC10-JK-001", "SEC4-JK-003"]),
        ("jenkins/vulnerable/grab_no_version.Jenkinsfile",          ["SEC3-JK-002"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/prod_deploy_no_input.Jenkinsfile",     ["SEC1-JK-001"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/archive_no_fingerprint.Jenkinsfile",   ["SEC9-JK-002"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/password_param.Jenkinsfile",           ["SEC2-JK-001"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/credentials_from_params.Jenkinsfile",  ["SEC2-JK-002"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/input_no_submitter.Jenkinsfile",       ["SEC4-JK-004"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/pr_author_injection.Jenkinsfile",      ["SEC4-JK-005"], ["SEC1-JK-002", "SEC10-JK-001", "SEC4-JK-002", "SEC4-JK-008", "TAINT-JK-001"]),
        ("jenkins/vulnerable/no_disable_concurrent.Jenkinsfile",    ["SEC5-JK-001"], ["SEC1-JK-002"]),
        ("jenkins/vulnerable/docker_image_latest_step.Jenkinsfile", ["SEC3-JK-003"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/curl_insecure.Jenkinsfile",            ["SEC6-JK-004"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/cloud_creds_env.Jenkinsfile",          ["SEC6-JK-005"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001", "SEC6-JK-001"]),
        ("jenkins/vulnerable/writefile_private_key.Jenkinsfile",    ["SEC6-JK-006"], ["SEC1-JK-002", "SEC10-JK-001", "SEC5-JK-001"]),
        ("jenkins/vulnerable/bat_interpolation.Jenkinsfile",        ["SEC6-JK-007"], ["SEC1-JK-002", "SEC10-JK-001", "TAINT-JK-001"]),
        ("jenkins/vulnerable/node_no_label.Jenkinsfile",            ["SEC7-JK-002"], []),
        ("jenkins/vulnerable/docker_registry_null_creds.Jenkinsfile", ["SEC7-JK-003"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/http_checkout.Jenkinsfile",            ["SEC8-JK-003"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/wget_no_checksum.Jenkinsfile",         ["SEC9-JK-003"], ["SEC1-JK-002", "SEC10-JK-001"]),
        ("jenkins/vulnerable/no_timeout.Jenkinsfile",               ["SEC1-JK-002"], []),
        ("jenkins/vulnerable/no_post_always.Jenkinsfile",           ["SEC10-JK-001"], []),
    ],
)
def test_vulnerable_fixture_fires_expected_rules(
    fixture_path, expected_rules, allowed_extras, all_rules
):
    """Pin both that ``expected_rules`` fire AND that nothing outside
    ``expected_rules ∪ allowed_extras`` fires.

    Why the second half matters: the ``expected ⊆ fired`` shape this
    test had previously was silently lenient — a precision regression
    in some unrelated rule (its regex broadens, suddenly fires on
    every fixture that contains the new matching surface) would not
    fail the test as long as the originally-targeted rule kept firing.
    Forcing maintainers to explicitly list co-fires turns silent
    broadening into a loud test failure.
    """
    platform_str = fixture_path.split("/")[0]
    _PLATFORM_MAP = {
        "github": Platform.GITHUB,
        "gitlab": Platform.GITLAB,
        "jenkins": Platform.JENKINS,
    }
    platform = _PLATFORM_MAP[platform_str]
    rules = [r for r in all_rules if r.platform == platform]

    fixture = FIXTURES / fixture_path
    findings = scan_file(str(fixture), rules=rules)
    fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}

    expected_set = set(expected_rules)
    allowed = expected_set | set(allowed_extras)

    missing = expected_set - fired
    assert not missing, (
        f"{fixture_path}: expected rules {sorted(missing)} to fire but didn't. "
        f"Fired rules: {sorted(fired)}"
    )

    unexpected = fired - allowed
    assert not unexpected, (
        f"{fixture_path}: unexpected co-fires {sorted(unexpected)}. "
        f"If these are intentional, add them to allowed_extras for this "
        f"fixture; if they're a regression, fix the firing rule. "
        f"Fired rules: {sorted(fired)}"
    )


# =============================================================================
# Edge cases: scanner must not crash on unusual inputs
# =============================================================================


def test_empty_file_no_crash(github_rules):
    fixture = FIXTURES / "github" / "edge_cases" / "empty.yml"
    findings = scan_file(str(fixture), rules=github_rules)
    # Empty file: no findings expected, no crash
    assert isinstance(findings, list)


def test_deeply_nested_4space_indent_fires(github_rules):
    """4-space indented unpinned action must still be detected."""
    fixture = FIXTURES / "github" / "edge_cases" / "deeply_nested.yml"
    findings = scan_file(str(fixture), rules=github_rules)
    fired = {f.rule_id for f in findings}
    assert "SEC3-GH-001" in fired, (
        "4-space indent should not prevent SEC3-GH-001 from firing on unpinned actions"
    )


# =============================================================================
# Edge-case correctness — survival is fuzz's job, CORRECTNESS is integration's
#
# Pre-audit: fuzz only asserted "doesn't crash" on adversarial inputs;
# integration only checked the two edges above. The audit (chunk 2.4)
# noted that a fixture that survives a fuzz run AND fires the rules
# it's supposed to is the actually informative test. The cases below
# take canonical fuzz edges (CRLF, BOM, tab indent, anchor merges) and
# assert that rules still fire correctly on those edges — fuzz checks
# survival, integration checks behaviour.
# =============================================================================


_EDGE_CASE_CORRECTNESS = [
    # (label, content, must_fire) — all unpinned-action shapes that
    # exercise SEC3-GH-001 across formatting variants. If the rule
    # silently breaks on any of these, the fuzz tests stay green
    # (no crash) but the rule's coverage gets a hole.
    (
        "crlf_line_endings",
        # Windows-style line endings — engines that hardcode '\n'
        # silently desync.
        "name: T\r\non: push\r\njobs:\r\n  b:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - uses: tj-actions/changed-files@v44\r\n",
        ["SEC3-GH-001"],
    ),
    (
        "bom_prefixed",
        # UTF-8 BOM at start of file. Real GitHub files do this on
        # Windows-saved workflows.
        "﻿name: T\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v44\n",
        ["SEC3-GH-001"],
    ),
    (
        "yaml_merge_key",
        # YAML 1.1 merge key. Anchor-expander preprocessor must
        # resolve the merge before pattern matching.
        ".defaults: &d\n"
        "  runs-on: ubuntu-latest\n"
        "jobs:\n"
        "  a:\n"
        "    <<: *d\n"
        "    steps:\n"
        "      - uses: tj-actions/changed-files@v44\n",
        ["SEC3-GH-001"],
    ),
]


@pytest.mark.parametrize(
    ("label", "content", "must_fire"),
    _EDGE_CASE_CORRECTNESS,
    ids=[c[0] for c in _EDGE_CASE_CORRECTNESS],
)
def test_edge_cases_still_fire_correctly(label, content, must_fire, github_rules, tmp_path):
    """Fuzz checks survival; integration checks correctness on the
    same edge-case inputs. A rule that quietly stops firing under
    BOM-prefixing or CRLF line endings has a real coverage hole that
    no fuzz test would surface.

    Failure here means: "the scanner doesn't crash on this YAML
    variant, but it also no longer detects what it should." Fix the
    rule pattern (preferred) or expand the engine's normalisation
    pre-pass (the right knob if multiple rules share the bug)."""
    f = tmp_path / "edge.yml"
    f.write_bytes(content.encode("utf-8"))
    findings = scan_file(str(f), rules=github_rules)
    fired = {ff.rule_id for ff in findings if ff.rule_id != "ENGINE-ERR"}
    missing = set(must_fire) - fired
    assert not missing, (
        f"[{label}] expected {sorted(missing)} to fire on this edge "
        f"case but they didn't. Fired: {sorted(fired)}"
    )


# =============================================================================
# Rule registry sanity checks
# =============================================================================


def test_no_duplicate_rule_ids(all_rules):
    ids = [r.id for r in all_rules]
    seen = set()
    dupes = [rid for rid in ids if rid in seen or seen.add(rid)]
    assert not dupes, f"Duplicate rule IDs found: {dupes}"


def test_all_rules_have_test_samples(all_rules):
    """Every active rule must have at least one positive and one negative sample."""
    missing = [
        r.id for r in all_rules
        if not _is_stub_rule(r) and (not r.test_positive or not r.test_negative)
    ]
    assert not missing, (
        f"Rules missing test samples (add test_positive and test_negative): {missing}"
    )


def test_all_rules_have_valid_platform(all_rules):
    from taintly.models import Platform
    for rule in all_rules:
        assert rule.platform in (Platform.GITHUB, Platform.GITLAB, Platform.JENKINS), (
            f"Rule {rule.id} has unknown platform: {rule.platform!r}"
        )


# =============================================================================
# Cross-platform sanity — every check that runs on GitHub must also run
# (or be explicitly justified as not running) on GitLab and Jenkins.
#
# Without this, registry-sanity gates can silently regress on the newer
# platforms: a contributor adds a rule to taintly/rules/github/, the
# global "no duplicate rule_ids" / "all rules have samples" gates pass,
# and the gap stays on GitLab/Jenkins until someone notices manually.
# =============================================================================


@pytest.mark.parametrize(
    "platform_value",
    ["github", "gitlab", "jenkins"],
)
def test_per_platform_no_duplicate_rule_ids(platform_value, all_rules):
    """Per-platform partition: no rule_id can appear twice within a
    single platform's rule pack. The global ``test_no_duplicate_rule_ids``
    gate is fine for catching cross-platform clashes; this gate
    surfaces *which* platform pack introduced the dupe."""
    rules = [r for r in all_rules if r.platform.value == platform_value]
    ids = [r.id for r in rules]
    seen: set[str] = set()
    dupes = [rid for rid in ids if rid in seen or seen.add(rid)]  # type: ignore[func-returns-value]
    assert not dupes, f"{platform_value}: duplicate rule IDs: {dupes}"


@pytest.mark.parametrize(
    "platform_value",
    ["github", "gitlab", "jenkins"],
)
def test_per_platform_all_rules_have_test_samples(platform_value, all_rules):
    """Per-platform: every active rule has at least one positive AND
    one negative sample. Mirrors ``test_all_rules_have_test_samples``
    but parameterised by platform so the failure message names the
    platform that's missing coverage."""
    rules = [r for r in all_rules if r.platform.value == platform_value]
    missing = [
        r.id for r in rules
        if not _is_stub_rule(r) and (not r.test_positive or not r.test_negative)
    ]
    assert not missing, (
        f"{platform_value}: rules missing test samples: {missing}"
    )


@pytest.mark.parametrize(
    "platform_value",
    ["github", "gitlab", "jenkins"],
)
def test_per_platform_minimum_rule_count(platform_value, all_rules):
    """Smoke check: each platform must have at least N rules. Catches
    the case where a registry-loading bug silently drops a whole
    platform pack — without this, downstream tests would still pass
    (no rules → no findings → everyone happy) and the regression
    would only surface when someone scanned a real workflow.

    Thresholds chosen as ~80% of the current rule counts so a small
    rule deletion doesn't trip the gate but a wholesale loss does."""
    minimums = {"github": 80, "gitlab": 50, "jenkins": 40}
    rules = [r for r in all_rules if r.platform.value == platform_value]
    assert len(rules) >= minimums[platform_value], (
        f"{platform_value}: only {len(rules)} rules loaded; expected at "
        f"least {minimums[platform_value]}. The registry may have failed "
        f"to import a module — check load_all_rules() output for "
        f"_IMPORT_FAILURES."
    )
