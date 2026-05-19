"""GitHub cache / checkout / permissions posture negative corpus round 1."""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github" / "negative_corpus"

CACHE_WRITE_FAMILY = {"SEC4-GH-026", "SEC9-GH-005", "XF-GH-001", "XF-GH-001A"}
CREDENTIAL_FAMILY = {"SEC4-GH-005", "CHAIN-GH-101"}


def _ids(name: str, rules) -> set[str]:
    return {finding.rule_id for finding in scan_file(str(FIXTURES / name), rules)}


def test_safe_checkout_with_persist_credentials_false_does_not_fire_sec4_gh_005(
    github_rules,
):
    fired = _ids("safe_pr_cache_restore_only.yml", github_rules)

    assert "SEC4-GH-005" not in fired


def test_safe_hashfiles_cache_key_does_not_fire_sec9_gh_005(github_rules):
    fired = _ids("safe_push_hashfiles_cache.yml", github_rules)

    assert "SEC9-GH-005" not in fired


def test_cache_restore_only_under_pr_does_not_fire_cache_write_family(github_rules):
    fired = _ids("safe_pr_cache_restore_only.yml", github_rules)

    assert not (fired & CACHE_WRITE_FAMILY)


def test_pull_request_target_cache_write_still_fires_sec4_gh_026(github_rules):
    fired = _ids("positive_prt_cache_hashfiles_write.yml", github_rules)

    assert "SEC4-GH-026" in fired


def test_missing_permissions_job_level_behavior_is_pinned(github_rules):
    fired = _ids("positive_missing_permissions_job_level.yml", github_rules)

    assert "SEC2-GH-002" not in fired


def test_top_level_permissions_block_suppresses_sec2_gh_002(github_rules):
    fired = _ids("safe_top_level_permissions.yml", github_rules)

    assert "SEC2-GH-002" not in fired


def test_persist_credentials_downstream_positive_anchor_still_fires(github_rules):
    fired = _ids("positive_persist_credentials_downstream.yml", github_rules)

    assert "SEC4-GH-005" in fired


def test_existing_safe_cache_checkout_stays_quiet_for_high_blast_family(github_rules):
    fired = _ids("safe_cache_checkout.yml", github_rules)

    assert not (fired & (CACHE_WRITE_FAMILY | CREDENTIAL_FAMILY))
