"""Regression coverage for individual detection-improvement defects.

Each test locks down a specific defect or capability. Test names are
the primary search surface — keep them descriptive enough to answer
"has this been tested?" without cross-referencing external roadmap
numbering.
"""

from __future__ import annotations


# =============================================================================
# PLAT-GH-001 — empty include list does not cover default branch
# Location: taintly/platform/github_checks.py:_ruleset_targets_default_branch
# =============================================================================


def test_plat_gh_001_empty_includes_does_not_cover_default_branch():
    """GitHub ruleset semantics: an empty `include` list matches zero
    refs, not all refs. A ruleset with no includes cannot be claimed
    to protect the default branch.
    """
    from taintly.platform.github_checks import _ruleset_targets_default_branch

    ruleset = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [], "exclude": []}},
    }
    assert _ruleset_targets_default_branch(ruleset) is False

    # Sanity: an explicit default-branch include must still count.
    ruleset_explicit = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    }
    assert _ruleset_targets_default_branch(ruleset_explicit) is True


# =============================================================================
# Hidden / masked GitLab variables are always kept for checks
# Location: taintly/platform/gitlab_checks.py:_non_trivial_variables
# =============================================================================


def test_hidden_gitlab_variable_survives_non_trivial_filter():
    """GitLab 17.x "Masked and hidden" variables never return a value
    via the API. A value-length heuristic would drop every hidden
    variable — exactly the highest-risk class.
    """
    from taintly.platform.gitlab_checks import _non_trivial_variables

    hidden = {"key": "X", "value": "", "hidden": True}
    assert hidden in _non_trivial_variables([hidden])

    secret_named = {"key": "DEPLOY_TOKEN", "value": "abc"}  # short value
    assert secret_named in _non_trivial_variables([secret_named])

    boring = {"key": "ENABLE_FOO", "value": "true"}
    assert boring not in _non_trivial_variables([boring])


# =============================================================================
# Self-hosted runner map form (group:) is recognised as privileged
# Location: taintly/workflow_context.py:_RE_SELF_HOSTED_GROUP
# =============================================================================


def test_workflow_context_detects_runner_group_form():
    """Enterprise runners use:

        runs-on:
          group: my-group

    which the primary regex misses (no `self-hosted` literal).
    """
    from taintly.workflow_context import analyze

    content = (
        "jobs:\n"
        "  build:\n"
        "    runs-on:\n"
        "      group: enterprise-runners\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    ctx = analyze(content)
    assert ctx.runs_self_hosted is True


# =============================================================================
# SEC9-GH-005 — cache key poisoning via attacker-controlled context
# Location: taintly/rules/github/sec1_sec5_sec6_sec7_sec9.py
# =============================================================================


def test_sec9_gh_005_fires_on_attacker_controlled_cache_key():
    """actions/cache with a key derived from github.head_ref or PR
    head SHA is cache-poisoning-prone.
    """
    from taintly.rules.registry import load_all_rules

    rule = next(r for r in load_all_rules() if r.id == "SEC9-GH-005")

    dangerous = (
        "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n"
        "        with:\n          key: deps-${{ github.head_ref }}\n"
    )
    assert rule.pattern.check(dangerous, dangerous.splitlines())

    safe = (
        "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n"
        "        with:\n          key: deps-${{ hashFiles('**/lock') }}\n"
    )
    assert rule.pattern.check(safe, safe.splitlines()) == []


# =============================================================================
# SEC3-GH-008 — pip --extra-index-url dependency confusion
# Location: taintly/rules/github/sec1_sec5_sec6_sec7_sec9.py
# =============================================================================


def test_sec3_gh_008_fires_on_extra_index_url():
    from taintly.rules.registry import load_all_rules

    rule = next(r for r in load_all_rules() if r.id == "SEC3-GH-008")

    dangerous = "      - run: pip install --extra-index-url https://pypi.internal/ mypkg"
    assert rule.pattern.check(dangerous, [dangerous])

    safe = "      - run: pip install --index-url https://pypi.internal/ mypkg"
    assert rule.pattern.check(safe, [safe]) == []


# =============================================================================
# SEC10-GH-003 — ACTIONS_STEP_DEBUG=true debug-logging exposure
# Location: taintly/rules/github/sec1_sec5_sec6_sec7_sec9.py
# =============================================================================


def test_sec10_gh_003_fires_on_actions_step_debug_true():
    from taintly.rules.registry import load_all_rules

    rule = next(r for r in load_all_rules() if r.id == "SEC10-GH-003")

    for sample in (
        "env:\n  ACTIONS_STEP_DEBUG: true",
        "env:\n  ACTIONS_RUNNER_DEBUG: 'true'",
        '    env:\n      ACTIONS_STEP_DEBUG: "true"',
        "env:\n  ACTIONS_RUNNER_DEBUG: 1",
    ):
        assert rule.pattern.check(sample, sample.splitlines()), (
            f"must fire on: {sample!r}"
        )

    for sample in (
        "env:\n  ACTIONS_STEP_DEBUG: false",
        "# env:\n#   ACTIONS_STEP_DEBUG: true",
        "env:\n  MY_VAR: true",
    ):
        assert rule.pattern.check(sample, sample.splitlines()) == [], (
            f"must not fire on: {sample!r}"
        )


# =============================================================================
# GitLab tainted-var source list — user identity and target-branch
# Location: taintly/gitlab_taint.py:_TAINTED_VARS
# =============================================================================


def test_gitlab_taint_covers_user_identity_and_target_branch_vars():
    """Triggerer identity variables accept arbitrary UTF-8 (including
    shell metachars). CI_MERGE_REQUEST_TARGET_BRANCH_NAME is attacker-
    influenceable on self-serve instances.
    """
    from taintly.gitlab_taint import _TAINTED_VARS

    for name in (
        "GITLAB_USER_NAME",
        "GITLAB_USER_LOGIN",
        "GITLAB_USER_EMAIL",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ):
        assert name in _TAINTED_VARS, f"{name} missing from tainted var list"


# =============================================================================
# SEC4-JK-001 / SEC4-JK-002 — triple-double-quoted GString interpolation
# Location: taintly/rules/jenkins/sec_jenkins.py
# =============================================================================


def test_sec4_jk_001_fires_on_triple_double_quoted_gstring():
    """Groovy triple-double-quoted strings ARE GStrings — they
    interpolate ${params.X} the same way as regular double-quoted
    strings.
    """
    from taintly.rules.registry import load_all_rules

    rule = next(r for r in load_all_rules() if r.id == "SEC4-JK-001")

    # The triple-double form — must match.
    dangerous = 'sh """docker build -t ${params.IMAGE_TAG} ."""'
    assert rule.pattern.check(dangerous, [dangerous]), (
        "triple-double-quoted GString interpolates and must fire"
    )

    # Single-quoted form — must still skip (negative from prior fix).
    safe = "sh 'docker build -t ${params.IMAGE_TAG} .'"
    assert rule.pattern.check(safe, [safe]) == []
