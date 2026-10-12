"""Independent authored expectations for owned guards and tool restrictions."""

import json
from pathlib import Path

import pytest

from taintly.agentguards import AgentGuardIndex
from taintly.rules.github.ai import RULES
from taintly.testing.mutations import mutate_whitespace_pad
from taintly.workflow_context import analyze, analyze_job_contexts, compute_exploitability

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/ai_agent_family_owning_guard.json").read_text(
        encoding="utf-8"
    )
)
RULE_BY_ID = {rule.id: rule for rule in RULES}
SAME = "github.event.pull_request.head.repo.full_name == github.repository"


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["name"])
def test_authored_source_expectations(case):
    rule = RULE_BY_ID[case["rule"]]
    assert (
        bool(rule.pattern.check(case["source"], case["source"].splitlines())) is case["expected"]
    ), case["reason"]


@pytest.mark.parametrize(
    "rule_id", ["AI-GH-012", "AI-GH-013", "AI-GH-015", "AI-GH-019", "AI-GH-020"]
)
def test_registered_rule_controls(rule_id):
    rule = RULE_BY_ID[rule_id]
    for source in rule.test_positive:
        assert rule.pattern.check(source, source.splitlines())
    for source in rule.test_negative:
        assert not rule.pattern.check(source, source.splitlines())
    assert rule.review_needed is True


def cli_workflow(guard="", event="pull_request_target", tail=""):
    return (
        f"on: {event}\npermissions:\n  contents: write\njobs:\n  review:\n"
        + (f"    if: {guard}\n" if guard else "")
        + "    steps:\n      - run: claude -p review\n"
        + tail
    )


@pytest.mark.parametrize(
    ("guard", "event", "expected"),
    [
        (SAME, "pull_request_target", True),
        (SAME.replace("==", "!="), "pull_request_target", False),
        (SAME + " || true", "pull_request_target", False),
        (SAME + " && inputs.enable", "pull_request_target", True),
        (SAME, "[pull_request_target, issue_comment]", False),
        (SAME, "[pull_request_target, discussion_comment]", False),
        (SAME, "[pull_request_target, push]", True),
        ("inputs.guard", "pull_request_target", False),
    ],
)
def test_only_owning_job_proof_can_temper_supported_trigger_risks(guard, event, expected):
    source = cli_workflow(guard, event)
    assert analyze(source).has_fork_identity_guard is False
    ctx = analyze_job_contexts(source)["review"]
    assert ctx.has_fork_identity_guard is expected
    assert compute_exploitability("ai_ml_model_risk", ctx, rule_id="AI-GH-013") == (
        "low" if expected else "high"
    )


def test_guard_credit_does_not_cross_jobs_steps_or_mutable_source_rules():
    source = cli_workflow(tail=f"  sibling:\n    if: {SAME}\n    steps:\n      - run: echo ok\n")
    contexts = analyze_job_contexts(source)
    assert contexts["review"].has_fork_identity_guard is False
    guarded = contexts["sibling"]
    assert guarded.has_fork_identity_guard is True
    for rule_id in ("AI-GH-019", "AI-GH-001", "AI-GH-018", ""):
        assert compute_exploitability("ai_ml_model_risk", guarded, rule_id=rule_id) == "high"
    step_guard = cli_workflow().replace("      - run:", f"      - if: {SAME}\n        run:")
    assert analyze_job_contexts(step_guard)["review"].has_fork_identity_guard is False


@pytest.mark.parametrize(
    "rule_id", ["AI-GH-012", "AI-GH-013", "AI-GH-015", "AI-GH-019", "AI-GH-020"]
)
def test_duplicate_and_merged_guard_structures_never_supply_exclusion(rule_id):
    base = next(row["source"] for row in CASES if row["name"] == rule_id.lower() + "-own-equality")
    for source in (
        base.replace("    steps:", "    if: true\n    steps:"),
        "defaults: &guard\n  if: true\n" + base.replace("    steps:", "    <<: *guard\n    steps:"),
    ):
        assert RULE_BY_ID[rule_id].pattern.check(source, source.splitlines())


@pytest.mark.parametrize(
    "policy",
    [
        "--tools Read,Grep",
        "--tools Read --disallowedTools Bash",
        "--tools Read --disallowedTools mcp__* --dangerously-skip-permissions",
        "--tools Read --disallowedTools mcp__* --settings unknown.json",
        "--tools Read --disallowedTools mcp__* --tools Bash",
        "--tools Agent --disallowedTools mcp__*",
    ],
)
def test_partial_conflicting_or_delegating_tool_policies_remain_reviewable(policy):
    source = next(row["source"] for row in CASES if row["name"] == "policy-closed-builtins")
    source = source.replace("--tools Read,Grep --disallowedTools mcp__*", policy)
    assert RULE_BY_ID["AI-GH-020"].pattern.check(source, source.splitlines())


@pytest.mark.parametrize(
    "setting",
    [
        '{"tools":{"core":["read_file"],"core":["run_shell_command"]}}',
        '{"tools":{"core":["read_file"]},"mcpServers":{"shell":{}}}',
        '{"tools":{"core":["unknown_tool"]}}',
        '{"tools":{"core":["run_shell_command(echo)"]}}',
        '{"tools":{"core":"read_file"}}',
    ],
)
def test_gemini_unresolved_policy_is_not_a_proof(setting):
    source = next(row["source"] for row in CASES if row["name"] == "policy-gemini-core")
    source = source.replace('{"tools":{"core":["read_file","grep_search"]}}', setting)
    assert RULE_BY_ID["AI-GH-020"].pattern.check(source, source.splitlines())


def test_null_permissions_do_not_prove_empty_grant():
    source = cli_workflow().replace("    steps:", "    permissions:\n    steps:")
    assert AgentGuardIndex(source).permissions_write(("jobs", "review", "steps", 0)) is None


@pytest.mark.parametrize(
    "permission",
    [
        "{contents: read, issues: {unexpected: write}}",
        "{contents: read, unknown: read}",
        "{contents: read, issues:}",
    ],
)
def test_incomplete_or_unknown_permission_map_does_not_prove_readonly(permission):
    source = cli_workflow().replace("    steps:", f"    permissions: {permission}\n    steps:")
    assert AgentGuardIndex(source).permissions_write(("jobs", "review", "steps", 0)) is None


def test_vendor_fork_or_extra_unknown_input_does_not_inherit_tool_profile():
    source = next(row["source"] for row in CASES if row["name"] == "policy-closed-builtins")
    for changed in (
        source.replace("anthropics/", "unverified-fork/"),
        source.replace("        with:", "        with:\n          settings: {}"),
        source.replace("        with:", "        with:\n          unknown_option: true"),
    ):
        assert RULE_BY_ID["AI-GH-020"].pattern.check(changed, changed.splitlines())


def test_whitespace_equivalence_excludes_loss_of_a_real_execution_guard():
    source = RULE_BY_ID["AI-GH-012"].test_negative[-1]
    mutated = source.replace(": ", ":")
    assert RULE_BY_ID["AI-GH-012"].pattern.check(mutated, mutated.splitlines())
    assert mutated not in mutate_whitespace_pad(source)
    assert source.replace(": ", ":  ") in mutate_whitespace_pad(source)


def test_whitespace_unknown_guard_is_not_an_exclusion_proof():
    source = cli_workflow("unsupported(condition)")
    # The expression parser recognizes calls structurally, even when their
    # runtime truth is unknown; losing this execution guard changes semantics.
    assert source.replace(": ", ":") not in mutate_whitespace_pad(source)
    malformed = cli_workflow("broken(")
    assert malformed.replace(": ", ":") in mutate_whitespace_pad(malformed)
    plain = "on: pull_request\njobs:\n  test:\n    steps:\n      - run: echo ok\n"
    assert plain.replace(": ", ":") in mutate_whitespace_pad(plain)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("BASE_REF=$(gh pr view 1 --json baseRefName -q .baseRefName)", False),
        ("gh pr view 1 --json state,mergeable", False),
        ("gh pr view 1 --json=number,state", False),
        ("gh pr view 1 --json title,body", True),
        ("gh pr view 1 --json state --json title", True),
        ("gh pr view 1 --json state,${{ inputs.field }}", True),
        ("gh pr view 1 --json state && gh pr view 1 --json body", True),
        ("gh pr view 1 --json state && gh api /repos/o/r/issues/1", True),
        ("gh pr view 1 --json state \\", True),
        ("gh pr view 1 --json unknownField", True),
        ("gh pr view 1 # --json state", True),
        ("gh pr view 1 --template '--json state'", True),
        ('gh pr view "--json state"', True),
        ('echo "gh pr view 1 --json state"', True),
        ("gh pr view ${{ steps.number.outputs.number }} --json state", True),
        ('gh pr view "$PR_NUMBER" --json state', True),
        ("gh pr view 1 --json body -q .state", True),
        ("gh pr view 1 --json state -q .state", False),
        ("gh pr view 1 --json state -q .body", True),
        ("gh pr view --json number,state", False),
        ("gh issue view 1 --json number,state", False),
        ("gh issue view --json state", True),
        ("gh issue view 1 --json baseRefName", True),
        ("gh pr view 1 --json state,", True),
        ("gh pr view 1 --json state --jq .state -q .state", True),
        ("gh pr view 1 --json state --unknown", True),
    ],
)
def test_fresh_read_field_selection_has_a_bounded_content_contract(command, expected):
    source = (
        "on: workflow_dispatch\njobs:\n  review:\n    steps:\n      - run: |\n          "
        + command
        + "\n      - uses: anthropics/claude-code-action@v1\n"
    )
    assert bool(RULE_BY_ID["AI-GH-019"].pattern.check(source, source.splitlines())) is expected
