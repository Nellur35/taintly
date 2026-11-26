"""Owning-job event guards constrain the checkout posture candidate."""

import pytest

from taintly.rules.github.sec3_sec4_supply_chain_ppe import RULES
from taintly.eventguard import event_guard_verdict


RULE = next(rule for rule in RULES if rule.id == "SEC4-GH-005B")


def workflow(guard="", events="[push, pull_request]", extra=""):
    return (
        f"on: {events}\njobs:\n  build:\n"
        + (f"    if: {guard}\n" if guard else "")
        + "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - run: echo test\n" + extra
    )


def fires(source):
    return RULE.pattern.check(source, source.splitlines())


@pytest.mark.parametrize(
    "guard,expected",
    [
        (None, True),
        ("true", True),
        ("false", False),
        ("!false", True),
        ("false && inputs.force", False),
        ("inputs.force && false", False),
        ("true || inputs.force", True),
        ("inputs.force || true", True),
        ("false || false", False),
        ("true && true", True),
        ("false || inputs.force", None),
        ("true && inputs.force", None),
        ("!inputs.force", None),
        ("", None),
        ("null", None),
        ("0", None),
        ("github.event_name == 0", None),
        ("(github.event_name == 'push') == false", None),
        ("${{ false }} trailing", None),
        ("(" * 1000 + "false" + ")" * 1000, None),
        ("x" * 8193, None),
    ],
)
def test_unknown_values_never_become_false_exclusion_proofs(guard, expected):
    assert event_guard_verdict(guard, "pull_request") is expected


@pytest.mark.parametrize(
    "guard",
    [
        "github.event_name != 'pull_request'",
        "${{ github.event_name != 'pull_request' }}",
        "${{ 'push' == github.event_name }}",
        "github['event_name'] == 'PUSH'",
        "github.event_name != 'pull_request' && success()",
        "success() && (github.event_name != 'pull_request')",
        "${{ !(github.event_name == 'pull_request') }}",
        "github.event_name == 'push' || github.event_name == 'schedule'",
        ">-\n      github.event_name != 'pull_request' &&\n      success()",
    ],
)
def test_excluded_pr_job_is_not_fork_reachable(guard):
    assert not fires(workflow(guard))


@pytest.mark.parametrize(
    "guard,events",
    [
        ("github.event_name != 'pull_request'", "[pull_request, pull_request_target]"),
        ("github.event_name != 'pull_request'", "[push, issue_comment, pull_request]"),
        ("github.event_name != 'pull_request'", "[push, workflow_run, pull_request]"),
        ("github.event_name != 'pull_request' || inputs.force", "[push, pull_request]"),
        ("${{ !(github.event_name != 'pull_request') }}", "[push, pull_request]"),
        ("contains(github.event_name, 'pull_request')", "[push, pull_request]"),
        ("github.event_name == inputs.event", "[push, pull_request]"),
        ("${{ github.event_name != 'pull_request' }} trailing", "[push, pull_request]"),
        ("github.event_name !=", "[push, pull_request]"),
    ],
)
def test_possible_or_unknown_fork_path_retains_review(guard, events):
    assert fires(workflow(guard, events))


def test_job_guard_does_not_suppress_sibling_checkout():
    source = workflow(
        "github.event_name != 'pull_request'",
        extra=(
            "  sibling:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        ),
    )
    assert fires(source) == [
        (source.count("\n", 0, source.rfind("      - uses:")) + 1, "- uses: actions/checkout@v4")
    ]


def test_step_and_env_if_do_not_become_job_guard():
    source = workflow().replace(
        "      - run: echo test",
        (
            "      - run: echo test\n        if: github.event_name != 'pull_request'\n"
            "        env:\n          if: github.event_name != 'pull_request'"
        ),
    )
    assert fires(source)


def test_trigger_name_in_script_is_not_a_trigger():
    source = workflow(events="push").replace("echo test", "echo pull_request")
    assert not fires(source)


def test_duplicate_job_guards_do_not_establish_exclusion():
    source = workflow("github.event_name != 'pull_request'").replace(
        "    runs-on:", "    if: github.event_name == 'pull_request'\n    runs-on:"
    )
    assert fires(source)


@pytest.mark.parametrize(
    "fields",
    [
        "    if: true\n    <<: *guard\n",
        "    <<: *guard\n    if: true\n",
    ],
)
def test_merge_replay_cannot_overwrite_explicit_guard(fields):
    source = "defaults: &guard\n  if: false\n" + workflow()
    source = source.replace("    runs-on:", fields + "    runs-on:")
    assert fires(source)


def test_parse_error_cannot_establish_exclusion():
    source = workflow("github.event_name != 'pull_request'") + "broken: *missing\n"
    assert fires(source)


def test_unsupported_yaml_tag_does_not_erase_candidates():
    assert fires(workflow("!(github.event_name != 'pull_request')"))


def test_only_checkout_step_guard_can_exclude_its_checkout():
    source = workflow().replace(
        "      - uses:", ("      - if: github.event_name != 'pull_request'\n        uses:")
    )
    assert not fires(source)


def test_two_event_guards_jointly_exclude_all_fork_paths():
    source = workflow(
        "github.event_name != 'pull_request'", "[push, pull_request, pull_request_target]"
    )
    source = source.replace(
        "      - uses:", ("      - if: github.event_name != 'pull_request_target'\n        uses:")
    )
    assert not fires(source)


@pytest.mark.parametrize(
    "events",
    [
        "pull_request",
        "[pull_request]",
        "{pull_request: {}}",
        "\n  pull_request: {}",
    ],
)
def test_unconditional_pr_shapes_still_fire(events):
    assert fires(workflow(events=events))


@pytest.mark.parametrize("consumer", ["echo test", "git push origin HEAD"])
@pytest.mark.parametrize(
    "first,second,expected",
    [
        ("", "", [6, 7]),
        ("        # persist-credentials: false\n", "", [6, 8]),
        ('        with: {"persist-credentials": "false"}\n', "", [8]),
        ("", "        with:\n          persist-credentials: false\n", [6]),
        ("        with:\n          persist-credentials: ${{ inputs.persist }}\n", "", [6, 9]),
        ("        with:\n          persist-credentials: false\n          persist-credentials: true\n", "", [6, 10]),
    ],
)
def test_checkout_persistence_belongs_to_the_invocation(consumer, first, second, expected):
    source = (
        "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: actions/checkout@v4\n{first}"
        f"      - uses: actions/checkout@v4\n{second}"
        f"      - run: {consumer}\n"
    )
    rule_id = "SEC4-GH-005B" if consumer == "echo test" else "SEC4-GH-005"
    rule = next(rule for rule in RULES if rule.id == rule_id)
    assert [line for line, _ in rule.pattern.check(source, source.splitlines())] == expected


@pytest.mark.parametrize(
    "settings,expected",
    [
        ("        with:\n          <<: *options\n", False),
        ("        with:\n          <<: *options\n          persist-credentials: true\n", True),
        ("        with:\n          persist-credentials: true\n          <<: *options\n", True),
        ("        with:\n          persist-credentials: false\n        with: {}\n", True),
    ],
)
def test_checkout_persistence_keeps_effective_yaml_value(settings, expected):
    source = "options: &options\n  persist-credentials: false\n" + workflow()
    source = source.replace("      - run:", settings + "      - run:")
    assert bool(fires(source)) is expected


def test_checkout_looking_text_is_not_an_invocation():
    source = workflow().replace(
        "      - uses: actions/checkout@v4",
        "      - run: |\n          uses: actions/checkout@v4\n          persist-credentials: false",
    )
    assert not fires(source)


def test_checkout_does_not_inherit_a_shadowed_with_mapping():
    source = (
        "checkout_options: &checkout_options\n"
        "  with:\n"
        "    persist-credentials: false\n"
    ) + workflow()
    source = source.replace(
        "      - run:",
        "        <<: *checkout_options\n        with: {fetch-depth: 1}\n      - run:",
    )
    assert fires(source)
