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
    from taintly.models import AbsencePattern, Severity
    from taintly.rules.github.sec3_sec4_supply_chain_ppe import ImposterCommitPattern
    from taintly.workflow_corpus import CorpusPattern
    if isinstance(rule.pattern, CorpusPattern):
        return True
    # SEC3-GH-009 (imposter-commit) is opt-in via --check-imposter-commits
    # and depends on a network call.  Its samples live in
    # tests/unit/test_imposter_commits.py against a stub verifier;
    # the per-file test-sample contract isn't applicable.
    if isinstance(rule.pattern, ImposterCommitPattern):
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
    "fixture_path, expected_rules",
    [
        # ── GitHub ──────────────────────────────────────────────────────────────
        ("github/vulnerable/ppe_classic.yml",           ["SEC3-GH-001"]),
        ("github/vulnerable/write_all_permissions.yml", ["SEC2-GH-001"]),
        ("github/vulnerable/injection_run_block.yml",   ["SEC4-GH-004"]),
        ("github/vulnerable/workflow_run_no_conclusion.yml", ["SEC4-GH-003"]),
        ("github/vulnerable/secret_in_with_input.yml", ["SEC6-GH-010"]),
        ("github/vulnerable/ai_trust_remote_code.yml",  ["AI-GH-001"]),
        ("github/vulnerable/ai_hf_no_revision.yml",     ["AI-GH-002"]),
        ("github/vulnerable/ai_torch_load_unsafe.yml",  ["AI-GH-003"]),
        ("github/vulnerable/ai_no_model_scanner.yml",   ["AI-GH-004"]),
        ("github/vulnerable/ai_prompt_injection_surface.yml", ["AI-GH-005"]),
        ("github/vulnerable/ai_agent_on_pr.yml",        ["AI-GH-006"]),
        ("github/vulnerable/ai_llm_output_to_shell.yml", ["AI-GH-007"]),
        ("github/vulnerable/ai_agent_with_pr_checkout.yml", ["AI-GH-008"]),
        ("github/vulnerable/ai_agent_dangerous_flags.yml", ["AI-GH-009"]),
        ("github/vulnerable/ai_joblib_load.yml",         ["AI-GH-010"]),
        ("github/vulnerable/ai_mcp_unpinned.yml",        ["AI-GH-011"]),
        ("github/vulnerable/ai_mcp_privileged.yml",      ["AI-GH-012"]),
        ("github/vulnerable/ai_agent_cli_on_pr.yml",     ["AI-GH-013"]),
        ("github/vulnerable/ai_agent_output_to_shell.yml", ["AI-GH-014"]),
        ("github/vulnerable/taint_agent_output.yml",    ["TAINT-GH-005"]),
        # ── GitLab ──────────────────────────────────────────────────────────────
        ("gitlab/vulnerable/ai_trust_remote_code.yml",           ["AI-GL-001"]),
        ("gitlab/vulnerable/ai_llm_output_to_shell.yml",         ["AI-GL-002"]),
        ("gitlab/vulnerable/ai_joblib_load.yml",                 ["AI-GL-003"]),
        ("gitlab/vulnerable/ai_hf_no_revision.yml",              ["AI-GL-004"]),
        ("gitlab/vulnerable/ai_torch_load_unsafe.yml",           ["AI-GL-005"]),
        ("gitlab/vulnerable/ai_no_model_scanner.yml",            ["AI-GL-006"]),
        ("gitlab/vulnerable/ai_prompt_injection_surface.yml",    ["AI-GL-007"]),
        ("gitlab/vulnerable/ai_agent_cli_on_mr.yml",             ["AI-GL-008"]),
        ("gitlab/vulnerable/debug_trace.yml",                    ["SEC7-GL-001"]),
        ("gitlab/vulnerable/prod_no_approval.yml",               ["SEC1-GL-001"]),
        ("gitlab/vulnerable/security_gate_allow_failure.yml",    ["SEC1-GL-002"]),
        ("gitlab/vulnerable/docker_auth_config.yml",             ["SEC2-GL-001"]),
        ("gitlab/vulnerable/dind_no_tls.yml",                    ["SEC2-GL-002"]),
        ("gitlab/vulnerable/unquoted_commit_message.yml",        ["SEC4-GL-001"]),
        ("gitlab/vulnerable/trigger_with_job_token.yml",         ["SEC4-GL-002"]),
        ("gitlab/vulnerable/unquoted_ref_name.yml",              ["SEC4-GL-003"]),
        ("gitlab/vulnerable/pipeline_source_only.yml",           ["SEC4-GL-004"]),
        ("gitlab/vulnerable/mr_pipeline_docker_push.yml",        ["SEC4-GL-005"]),
        ("gitlab/vulnerable/deploy_no_resource_group.yml",       ["SEC5-GL-001"]),
        ("gitlab/vulnerable/wget_pipe_bash.yml",                 ["SEC6-GL-006"]),
        ("gitlab/vulnerable/long_lived_cloud_creds.yml",         ["SEC6-GL-007"]),
        ("gitlab/vulnerable/registry_override.yml",              ["SEC6-GL-008"]),
        ("gitlab/vulnerable/service_latest.yml",                 ["SEC8-GL-003"]),
        ("gitlab/vulnerable/artifacts_no_access.yml",            ["SEC9-GL-001"]),
        ("gitlab/vulnerable/download_no_checksum.yml",           ["SEC9-GL-002"]),
        ("gitlab/vulnerable/cache_no_key.yml",                   ["SEC9-GL-003"]),
        ("gitlab/vulnerable/print_job_token.yml",                ["SEC10-GL-001"]),
        # ── Jenkins ─────────────────────────────────────────────────────────────
        ("jenkins/vulnerable/ai_trust_remote_code.Jenkinsfile",     ["AI-JK-001"]),
        ("jenkins/vulnerable/ai_torch_load_unsafe.Jenkinsfile",     ["AI-JK-002"]),
        ("jenkins/vulnerable/ai_llm_output_to_shell.Jenkinsfile",   ["AI-JK-003"]),
        ("jenkins/vulnerable/ai_joblib_load.Jenkinsfile",           ["AI-JK-004"]),
        ("jenkins/vulnerable/unpinned_shared_library.Jenkinsfile",  ["SEC3-JK-001"]),
        ("jenkins/vulnerable/hardcoded_credential.Jenkinsfile",     ["SEC6-JK-001"]),
        ("jenkins/vulnerable/credential_echo.Jenkinsfile",          ["SEC6-JK-002"]),
        ("jenkins/vulnerable/agent_any.Jenkinsfile",                ["SEC7-JK-001"]),
        ("jenkins/vulnerable/docker_latest.Jenkinsfile",            ["SEC8-JK-001"]),
        ("jenkins/vulnerable/curl_pipe_bash.Jenkinsfile",           ["SEC9-JK-001"]),
        ("jenkins/vulnerable/params_injection.Jenkinsfile",         ["SEC4-JK-001"]),
        ("jenkins/vulnerable/scm_env_injection.Jenkinsfile",        ["SEC4-JK-002"]),
        ("jenkins/vulnerable/dynamic_groovy_eval.Jenkinsfile",      ["SEC4-JK-003"]),
        ("jenkins/vulnerable/println_credential.Jenkinsfile",       ["SEC6-JK-003"]),
        ("jenkins/vulnerable/remote_groovy_script.Jenkinsfile",     ["SEC8-JK-002"]),
        ("jenkins/vulnerable/grab_no_version.Jenkinsfile",          ["SEC3-JK-002"]),
        ("jenkins/vulnerable/prod_deploy_no_input.Jenkinsfile",     ["SEC1-JK-001"]),
        ("jenkins/vulnerable/archive_no_fingerprint.Jenkinsfile",   ["SEC9-JK-002"]),
        ("jenkins/vulnerable/password_param.Jenkinsfile",           ["SEC2-JK-001"]),
        ("jenkins/vulnerable/credentials_from_params.Jenkinsfile",  ["SEC2-JK-002"]),
        ("jenkins/vulnerable/input_no_submitter.Jenkinsfile",       ["SEC4-JK-004"]),
        ("jenkins/vulnerable/pr_author_injection.Jenkinsfile",      ["SEC4-JK-005"]),
        ("jenkins/vulnerable/no_disable_concurrent.Jenkinsfile",    ["SEC5-JK-001"]),
        ("jenkins/vulnerable/docker_image_latest_step.Jenkinsfile", ["SEC3-JK-003"]),
        ("jenkins/vulnerable/curl_insecure.Jenkinsfile",            ["SEC6-JK-004"]),
        ("jenkins/vulnerable/cloud_creds_env.Jenkinsfile",          ["SEC6-JK-005"]),
        ("jenkins/vulnerable/writefile_private_key.Jenkinsfile",    ["SEC6-JK-006"]),
        ("jenkins/vulnerable/bat_interpolation.Jenkinsfile",        ["SEC6-JK-007"]),
        ("jenkins/vulnerable/node_no_label.Jenkinsfile",            ["SEC7-JK-002"]),
        ("jenkins/vulnerable/docker_registry_null_creds.Jenkinsfile", ["SEC7-JK-003"]),
        ("jenkins/vulnerable/http_checkout.Jenkinsfile",            ["SEC8-JK-003"]),
        ("jenkins/vulnerable/wget_no_checksum.Jenkinsfile",         ["SEC9-JK-003"]),
        ("jenkins/vulnerable/no_timeout.Jenkinsfile",               ["SEC1-JK-002"]),
        ("jenkins/vulnerable/no_post_always.Jenkinsfile",           ["SEC10-JK-001"]),
    ],
)
def test_vulnerable_fixture_fires_expected_rules(fixture_path, expected_rules, all_rules):
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
    fired = {f.rule_id for f in findings}

    missing = [r for r in expected_rules if r not in fired]
    assert not missing, (
        f"{fixture_path}: expected rules {missing} to fire but they didn't. "
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
