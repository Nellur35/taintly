"""AI006 exclusions require the candidate's own effective execution guards."""

import pytest

from taintly.eventguard import event_guard_verdict
from taintly.rules.github.ai import RULES

RULE = next(rule for rule in RULES if rule.id == "AI-GH-006")
SAME = "github.event.pull_request.head.repo.full_name == github.repository"
ASSOCIATION = "github.event.comment.author_association"


def workflow(job_if="", step_if="", event="pull_request_target", tail=""):
    return (
        f"on: {event}\njobs:\n  review:\n"
        + (f"    if: {job_if}\n" if job_if else "")
        + "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        + (f"        if: {step_if}\n" if step_if else "")
        + tail
    )


def fires(source):
    return bool(RULE.pattern.check(source, source.splitlines()))


@pytest.mark.parametrize("slot", ["job_if", "step_if"])
@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        (SAME, False),
        (SAME.replace("==", "!="), True),
        (SAME + " || true", True),
        (SAME + " || inputs.force", True),
        (SAME + " && inputs.force", False),
        ("!(" + SAME + ")", True),
        ("github['repository'] == github.event.pull_request.head.repo.full_name", False),
        ("inputs.run_agent", True),
        ("false", False),
        ("github.event_name == 'push'", False),
        ("github.event_name != 'pull_request_target' || inputs.force", True),
        (SAME + " trailing", True),
    ],
)
def test_own_guard_boolean_semantics(slot, guard, expected):
    assert fires(workflow(**{slot: guard})) is expected


@pytest.mark.parametrize(
    "tail",
    [
        f"      - if: {SAME}\n        run: echo later\n",
        f"  sibling:\n    if: {SAME}\n    steps:\n      - run: echo sibling\n",
        f"      - run: echo '{SAME}'\n",
        f"# if: {SAME}\n",
        f"        env:\n          if: {SAME}\n",
    ],
)
def test_unrelated_guard_retains_candidate(tail):
    assert fires(workflow(tail=tail))


@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        (ASSOCIATION + " == 'MEMBER'", False),
        (ASSOCIATION + " != 'MEMBER'", True),
        (ASSOCIATION + " == 'member' || " + ASSOCIATION + " == 'OWNER'", False),
        (ASSOCIATION + " == 'MEMBER' || true", True),
        ('contains(fromJSON(\'["OWNER","MEMBER"]\'), ' + ASSOCIATION + ")", False),
        ('contains(fromJSON(\'["OWNER","NONE"]\'), ' + ASSOCIATION + ")", True),
        ("contains(fromJSON('[\"OWNER\"]'), inputs.association)", True),
        ("contains('OWNER,MEMBER', " + ASSOCIATION + ")", True),
        ("contains(fromJSON('[\"OWNER\",0]'), " + ASSOCIATION + ")", True),
        ("contains(fromJSON('[bad'), " + ASSOCIATION + ")", True),
        ("github.event.issue.author_association == 'OWNER'", True),
    ],
)
def test_only_event_actor_association_exclusions_are_proved(guard, expected):
    assert fires(workflow(job_if=guard, event="issue_comment")) is expected


def test_mixed_event_does_not_inherit_pr_identity_assumption():
    assert fires(workflow(job_if=SAME, event="[pull_request_target, issue_comment]"))


def test_unmodeled_event_is_not_silently_discarded():
    assert fires(
        workflow(
            job_if="github.event_name == 'discussion_comment'",
            event="[pull_request_target, discussion_comment]",
        )
    )


def test_trusted_trigger_does_not_create_an_outside_path():
    assert not fires(workflow(job_if=SAME, event="[pull_request_target, push]"))


def test_duplicate_guard_or_job_keeps_review():
    source = workflow(job_if=SAME)
    assert fires(source.replace("    runs-on:", "    if: true\n    runs-on:"))
    assert fires(source + "  review:\n    steps:\n      - run: echo duplicate\n")


def test_parse_error_and_merge_ambiguity_keep_review():
    assert fires(workflow(job_if=SAME, tail="broken: *missing\n"))
    source = "defaults: &guard\n  if: true\n" + workflow(job_if=SAME)
    assert fires(source.replace("    runs-on:", "    <<: *guard\n    runs-on:"))


def test_sibling_agent_and_own_step_guard_are_independent():
    source = workflow(step_if=SAME, tail="      - uses: anthropics/claude-code-action@v1\n")
    hits = RULE.pattern.check(source, source.splitlines())
    assert hits == [(source.count("\n"), "- uses: anthropics/claude-code-action@v1")]


def test_exclusion_facts_are_opt_in_for_existing_evaluator_callers():
    guard = ASSOCIATION + " == 'OWNER'"
    assert event_guard_verdict(guard, "issue_comment") is None
    assert event_guard_verdict("contains(fromJSON('[]'), inputs.actor)", "issue_comment") is None
    assert (
        event_guard_verdict(
            guard,
            "issue_comment",
            path_string_exclusions={ASSOCIATION: frozenset({"owner", "member", "collaborator"})},
        )
        is False
    )


@pytest.mark.parametrize("source", RULE.test_positive)
def test_registered_positive_preserved(source):
    assert fires(source)


@pytest.mark.parametrize("source", RULE.test_negative)
def test_registered_negative_preserved(source):
    assert not fires(source)
