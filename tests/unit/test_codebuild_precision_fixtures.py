"""CodeBuild precision fixtures — full realistic buildspec.yml files exercised
through the real engine, one TP/FP set per rule.

Fixtures live in ``tests/fixtures/codebuild/{positives,negatives}/``, named
``<rule_id>_<description>.yml`` (e.g. ``sec6_cb_002_parameter_store_base64.yml``
-> ``SEC6-CB-002``). Each positive fixture must trigger its named rule; each
negative fixture must not. Mirrors the hand-written scan_file()-based pattern
in test_precision_fixtures.py (GitHub) — there is no generic fixture-discovery
harness in this repo; every fixture is wired by an explicit assertion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules

_POS = Path(__file__).parent.parent / "fixtures" / "codebuild" / "positives"
_NEG = Path(__file__).parent.parent / "fixtures" / "codebuild" / "negatives"


@pytest.fixture(scope="module")
def cb_rules():
    return [r for r in load_all_rules() if r.platform == Platform.CODEBUILD]


def _rule_id_from_filename(name: str) -> str:
    stem = name.rsplit(".", 1)[0]
    parts = stem.split("_")
    return "-".join(p.upper() for p in parts[:3])


_POSITIVE_FIXTURES = [
    "sec3_cb_001_bash_process_substitution.yml",
    "sec3_cb_001_curl_pipe_bash.yml",
    "sec6_cb_001_plaintext_secret.yml",
    "sec6_cb_002_parameter_store_base64.yml",
    "sec6_cb_002_secrets_manager_rev.yml",
    "theatre_cb_001_npm_audit_continue.yml",
    "theatre_cb_001_bandit_continue_order.yml",
    "sec3_cb_002_floating_dot_x.yml",
    "sec3_cb_002_latest.yml",
    "lotp_cb_001_npm_install.yml",
    "lotp_cb_001_pip_install.yml",
    # Regression for the yarn global-add subcommand form.
    "lotp_cb_001_yarn_global_add.yml",
    "sec4_cb_001_eval_webhook_ref.yml",
    "sec4_cb_001_shell_c_source_version.yml",
    "sec9_cb_001_maximal_glob_artifacts.yml",
    "sec9_cb_001_secondary_artifacts_glob.yml",
    "sec9_cb_002_webhook_ref_key.yml",
    "sec9_cb_002_webhook_ref_fallback.yml",
]

_NEGATIVE_FIXTURES = [
    "sec3_cb_001_checksum_verified.yml",
    "sec3_cb_001_commented_out.yml",
    "sec6_cb_001_parameter_store_alias.yml",
    "sec6_cb_002_curl_user_unmodified.yml",
    "sec6_cb_002_non_secret_base64.yml",
    "sec6_cb_002_decode_direction.yml",
    "theatre_cb_001_notify_continue.yml",
    "theatre_cb_001_default_abort.yml",
    "theatre_cb_001_explicit_abort.yml",
    "theatre_cb_001_commented_out_gate.yml",
    "sec3_cb_002_pinned_exact.yml",
    "sec3_cb_002_env_var_indirection.yml",
    "lotp_cb_001_ignore_scripts.yml",
    "lotp_cb_001_require_hashes.yml",
    "lotp_cb_001_commented_out.yml",
    # Precision regressions.
    "lotp_cb_001_yarn_cache_key.yml",
    "theatre_cb_001_report_filename.yml",
    "theatre_cb_001_trailing_comment.yml",
    "sec6_cb_002_decode_flag_not_first.yml",
    "sec4_cb_001_quoted_checkout.yml",
    "sec4_cb_001_plain_unquoted_expansion.yml",
    "sec4_cb_001_shell_c_positional_data.yml",
    "sec4_cb_001_unrelated_build_id.yml",
    "sec9_cb_001_scoped_files.yml",
    "sec9_cb_001_cache_paths_glob.yml",
    "sec9_cb_001_commented_out.yml",
    "sec9_cb_002_stable_key.yml",
    "sec9_cb_002_webhook_var_in_paths.yml",
    "sec9_cb_002_commented_out.yml",
    # Precision regression: SEC4-CB-001 must stay
    # scoped to phases.*.commands and not cross-fire on env.variables.
    "sec4_cb_001_env_variables_not_shell.yml",
]


@pytest.mark.parametrize("fixture_name", _POSITIVE_FIXTURES)
def test_codebuild_positive_fixture_fires(fixture_name, cb_rules):
    expected_rule_id = _rule_id_from_filename(fixture_name)
    findings = scan_file(str(_POS / fixture_name), cb_rules)
    fired = [f for f in findings if f.rule_id == expected_rule_id]
    assert fired, (
        f"{fixture_name}: expected {expected_rule_id} to fire, but it did not. "
        f"Findings: {[f.rule_id for f in findings]}"
    )


@pytest.mark.parametrize("fixture_name", _NEGATIVE_FIXTURES)
def test_codebuild_negative_fixture_does_not_fire(fixture_name, cb_rules):
    expected_rule_id = _rule_id_from_filename(fixture_name)
    findings = scan_file(str(_NEG / fixture_name), cb_rules)
    fired = [f for f in findings if f.rule_id == expected_rule_id]
    assert not fired, f"{fixture_name}: expected {expected_rule_id} NOT to fire, but got: {fired}"


def test_sec4_cb_001_does_not_cross_fire_on_sec9_cb_002_cache_key(cb_rules):
    """Precision regression: an unquoted webhook var in
    ``cache.key`` is SEC9-CB-002's shape (cache poisoning), not a shell
    command — SEC4-CB-001 must not also fire on the same line. Reuses the
    existing SEC9-CB-002 positive fixture directly rather than duplicating
    its content under a new filename, and asserts both rules' correct
    divergence on the identical input in one place.
    """
    findings = scan_file(str(_POS / "sec9_cb_002_webhook_ref_key.yml"), cb_rules)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC9-CB-002" in rule_ids, f"expected SEC9-CB-002 to still fire, got: {rule_ids}"
    assert "SEC4-CB-001" not in rule_ids, f"SEC4-CB-001 cross-fired on a cache.key line: {rule_ids}"


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (
            "version: 0.2\nenv:\n  variables:\n    DOC: npm install\n"
            "phases:\n  build:\n    commands:\n      - echo ok\n",
            set(),
        ),
        (
            'version: 0.2\nphases:\n  build:\n    commands:\n      - echo "npm install"\n',
            set(),
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n"
            '      - bash -lc "deploy $CODEBUILD_SOURCE_VERSION"\n',
            {"SEC4-CB-001"},
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n"
            "      - bash -c \"printf '#'; $CODEBUILD_SOURCE_VERSION\"\n",
            {"SEC4-CB-001"},
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"
            "cache:\n  action: restore\n"
            "  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  paths:\n    - node_modules/**/*\n",
            set(),
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok && npm install\n",
            {"LOTP-CB-001"},
        ),
        (
            "version: 0.2\nphases:\n  install:\n    commands:\n"
            "      - /usr/bin/pip install requests\n",
            {"LOTP-CB-001"},
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"
            "cache:\n  action: save\n"
            "  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  paths:\n    - node_modules/**/*\n",
            {"SEC9-CB-002"},
        ),
    ],
)
def test_codebuild_precision_regressions(tmp_path, cb_rules, content, expected):
    buildspec = tmp_path / "buildspec.yml"
    buildspec.write_text(content, encoding="utf-8")
    findings = scan_file(str(buildspec), cb_rules)
    relevant = {
        finding.rule_id
        for finding in findings
        if finding.rule_id in {"LOTP-CB-001", "SEC4-CB-001", "SEC9-CB-002"}
    }
    assert relevant == expected


@pytest.mark.parametrize(
    ("rule_id", "content", "should_fire"),
    [
        (
            "SEC6-CB-001",
            "version: 0.2\nenv:\n  variables:\n    TOKEN: plaintext\nphases:\n  build:\n    commands:\n      - echo ok\n",
            True,
        ),
        (
            "SEC6-CB-002",
            "version: 0.2\nenv:\n  parameter-store:\n    TOKEN: /app/token\n  variables:\n    DOC: echo $TOKEN | base64\nphases:\n  build:\n    commands:\n      - echo ok\n",
            False,
        ),
        (
            "SEC6-CB-002",
            "version: 0.2\nenv:\n  parameter-store:\n    TOKEN: /app/token\nphases:\n  build:\n    commands:\n      - echo $TOKEN | base64 > token.b64\n",
            False,
        ),
        (
            "SEC3-CB-001",
            "version: 0.2\nenv:\n  variables:\n    DOC: curl https://example.test/install | bash\nphases:\n  build:\n    commands:\n      - echo ok\n",
            False,
        ),
        (
            "LOTP-CB-001",
            "version: 0.2\nphases:\n  build:\n    commands:\n      - npm ci --ignore-scripts && pip install requests\n",
            True,
        ),
        (
            "THEATRE-CB-001",
            "version: 0.2\nphases:\n  build:\n    on-failure: CONTINUE\n    commands:\n      - npm audit\n",
            False,
        ),
    ],
)
def test_codebuild_independent_review_regressions(
    tmp_path, cb_rules, rule_id, content, should_fire
):
    buildspec = tmp_path / "buildspec.yml"
    buildspec.write_text(content, encoding="utf-8")
    fired = rule_id in {finding.rule_id for finding in scan_file(str(buildspec), cb_rules)}
    assert fired is should_fire
