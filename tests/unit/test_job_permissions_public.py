"""Effective job-permission coverage for SEC2-GH-002."""

from taintly.rules.registry import get_rule_by_id


def _matches(workflow: str) -> bool:
    rule = get_rule_by_id("SEC2-GH-002")
    assert rule is not None
    return bool(rule.pattern.check(workflow, workflow.splitlines()))


def test_mixed_job_permissions_keep_posture_finding() -> None:
    workflow = (
        "on: push\n"
        "jobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n"
        "  release:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n"
    )
    assert _matches(workflow)


def test_every_job_has_direct_permissions() -> None:
    workflow = (
        "on: push\n"
        "jobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: read\n"
        "  release:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n"
    )
    assert not _matches(workflow)
