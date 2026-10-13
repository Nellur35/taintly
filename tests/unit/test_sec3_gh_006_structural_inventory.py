from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.rules.registry import load_all_rules

RULES = load_all_rules()
INVENTORY = next(rule for rule in RULES if rule.id == "SEC3-GH-006")


def matches(content: str, filepath: str = "workflow.yml"):
    return INVENTORY.pattern.check(content, content.splitlines())


def scan(content: str, filepath: str = "workflow.yml"):
    return scan_file(filepath, RULES, _content=content)


def inventory_findings(content: str, filepath: str = "workflow.yml"):
    return [f for f in scan(content, filepath) if f.rule_id == "SEC3-GH-006"]


def test_inventory_walks_flow_and_quoted_use_values_and_keeps_pinned_refs():
    content = """jobs:
  flow:
    steps: [{uses: example/flow@0123456789012345678901234567890123456789}]
  quoted:
    steps:
      - "uses": example/quoted@v1
"""
    found = matches(content)
    assert [line for line, _ in found] == [3, 6]


def test_inventory_ignores_run_env_with_false_uses_and_comments():
    content = """jobs:
  demo:
    steps:
      - run: |
          uses: fake/run@v1
        env:
          uses: fake/env@v1
        with:
          uses: fake/input@v1
      # uses: fake/comment@v1
"""
    assert matches(content) == []


def test_inventory_keeps_multiple_uses_events_on_one_line():
    content = "jobs: {a: {steps: [{uses: one/action@v1}, {uses: two/action@v1}]}}\n"
    found = matches(content)
    assert len(found) == 2
    assert found[0][0] == found[1][0] == 1
    emitted = inventory_findings(content)
    assert len(emitted) == 2
    assert emitted[0].line == emitted[1].line == 1


def test_inventory_detects_external_reusable_job_call():
    content = """jobs:
  call:
    uses: example/workflows/.github/workflows/ci.yml@v1
"""
    (finding,) = inventory_findings(content)
    assert "reusable workflow" in " ".join(finding.context_notes).lower()


def test_inventory_fragment_and_composite_provenance():
    fragment = "- uses: example/action@v1\n"
    assert matches(fragment) == [(1, fragment.strip())]
    composite = """name: Composite
description: test
runs:
  using: composite
  steps:
    - uses: example/nested@v1
"""
    assert (
        len(INVENTORY.pattern.check_with_filepath(composite, composite.splitlines(), "action.yml"))
        == 1
    )
    assert inventory_findings(composite, "workflow.yml") == []


def test_inventory_preserves_namespace_exclusions():
    content = """jobs:
  demo:
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: ./local
      - uses: ../sibling
      - uses: docker://alpine:3.19
      - uses: action-foundation/tool@v1
"""
    found = matches(content)
    assert len(found) == 1
    assert "action-foundation/tool@v1" in found[0][1]


def test_inventory_context_is_owner_local_and_does_not_claim_effective_authority():
    content = """on: pull_request_target
permissions: {contents: write}
jobs:
  call:
    uses: example/workflows/.github/workflows/ci.yml@v1
    secrets: inherit
  build:
    permissions: {contents: read}
    steps:
      - uses: example/action@v1
        with:
          token: ${{ secrets.BUILD_TOKEN }}
      - run: echo sibling
        env:
          SECRET: ${{ secrets.SIBLING_ONLY }}
"""
    findings = inventory_findings(content)
    assert len(findings) == 2
    call = next(f for f in findings if "reusable workflow" in " ".join(f.context_notes).lower())
    action = next(f for f in findings if "action step" in " ".join(f.context_notes).lower())
    call_notes = " ".join(call.context_notes).lower()
    action_notes = " ".join(action.context_notes).lower()
    assert "reusable workflow" in call.title.lower() or "dependency" in call.title.lower()
    assert "inherit" in call_notes
    assert "sibling_only" not in action_notes
    assert "build_token" in action_notes
    permission_note = next(
        note.lower()
        for note in action.context_notes
        if note.startswith("Declared local permission ceiling:")
    )
    assert "contents=read" in permission_note
    assert "contents=write" not in permission_note
    assert "effective provider token permissions remain unknown" in permission_note
    assert "effective" in action_notes
    assert "unknown" in action_notes
    assert action.context_notes[0] in action.to_dict()["context_notes"]


def test_malformed_and_incomplete_uses_keep_inventory_with_unknown_context():
    mixed = """jobs:
  odd:
    uses: example/reusable@v1
    steps:
      - uses: example/action@v1
"""
    findings = inventory_findings(mixed)
    assert len(findings) == 2
    assert all("unknown" in " ".join(f.context_notes).lower() for f in findings)

    incomplete = """jobs:
  before:
    steps:
      - uses: example/before@v1
%YAML 1.2
"""
    assert inventory_findings(incomplete) == []
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "SEC3-GH-006" in f.title
        and "incomplete pattern results" in f.title
        for f in scan(incomplete)
    )


def test_duplicate_owner_keys_keep_occurrence_but_withhold_borrowed_context():
    content = """jobs:
  build:
    permissions: {contents: write}
  build:
    steps:
      - uses: example/action@v1
"""
    (finding,) = inventory_findings(content)
    notes = " ".join(finding.context_notes).lower()
    assert "ambiguous" in notes
    assert "authority and secret ownership remain unknown" in notes
    assert "contents=write" not in notes


def test_step_and_reusable_inventory_are_info_review_needed():
    content = """jobs:
  call:
    uses: example/workflows/.github/workflows/ci.yml@v1
  build:
    steps:
      - uses: example/action@v1
"""
    findings = inventory_findings(content)
    assert len(findings) == 2
    assert all(f.severity.value == "INFO" and f.review_needed for f in findings)
    assert all(f.finding_family == "dependency_inventory" for f in findings)


def test_dead_job_filter_does_not_shift_owner_or_permission_notes():
    content = """on: workflow_dispatch
jobs:
  dead:
    if: false
    permissions: write-all
    runs-on: ubuntu-latest
    steps:
      - uses: example/dead@v1
  live:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: example/live@v1
"""
    findings = inventory_findings(content)
    assert len(findings) == 1
    notes = " ".join(findings[0].context_notes).lower()
    assert "jobs.live.steps[0]" in notes
    assert "example/live@v1" in notes
    assert "contents=read" in notes
    assert "write-all" not in notes


def test_dead_step_filter_does_not_shift_sibling_environment_notes():
    content = """on: workflow_dispatch
jobs:
  live:
    runs-on: ubuntu-latest
    steps:
      - if: false
        uses: example/dead@v1
        env:
          PRIVATE: ${{ secrets.SIBLING_ONLY }}
      - uses: example/live@v1
"""
    findings = inventory_findings(content)
    assert len(findings) == 1
    notes = " ".join(findings[0].context_notes).lower()
    assert "jobs.live.steps[1]" in notes
    assert "example/live@v1" in notes
    assert "sibling_only" not in notes


def test_inline_ignored_occurrence_does_not_shift_following_owner_notes():
    content = """jobs:
  ignored:
    permissions: write-all
    steps:
      - uses: example/ignored@v1 # taintly: ignore[SEC3-GH-006]
  visible:
    permissions: {contents: read}
    steps:
      - uses: example/visible@v1
"""
    findings = inventory_findings(content)
    assert len(findings) == 1
    notes = " ".join(findings[0].context_notes).lower()
    assert "jobs.visible.steps[0]" in notes
    assert "example/visible@v1" in notes
    assert "contents=read" in notes
    assert "write-all" not in notes


def test_same_line_dead_and_live_jobs_keep_live_inventory():
    content = "on: workflow_dispatch\njobs: {dead: {if: false, runs-on: ubuntu-latest, steps: [{uses: example/dead@v1}]}, live: {runs-on: ubuntu-latest, steps: [{uses: example/live@v1}]}}\n"
    findings = inventory_findings(content)
    assert any("example/live@v1" in " ".join(f.context_notes) for f in findings)
    assert all(
        "liveness attribution is unresolved" in " ".join(f.context_notes).lower() for f in findings
    )


def test_same_line_occurrences_keep_distinct_references_after_earlier_dead_job():
    content = """jobs:
  dead:
    if: false
    steps:
      - uses: example/dead@v1
  live:
    steps: [{uses: example/one@v1}, {uses: example/two@v1}]
"""
    findings = inventory_findings(content)
    assert len(findings) == 2
    note_sets = [" ".join(f.context_notes) for f in findings]
    assert any("example/one@v1" in notes and "example/two@v1" not in notes for notes in note_sets)
    assert any("example/two@v1" in notes and "example/one@v1" not in notes for notes in note_sets)


def test_ambiguous_reusable_secret_mappings_are_not_claimed():
    content = """jobs:
  call:
    uses: example/first/.github/workflows/a.yml@v1
    secrets: {DEPLOY: ${{ secrets.OLD }} }
  call:
    uses: example/second/.github/workflows/b.yml@v1
"""
    findings = inventory_findings(content)
    assert len(findings) == 2
    assert all(
        "forwarding remains unresolved" in " ".join(f.context_notes).lower() for f in findings
    )
    assert all("deploy" not in " ".join(f.context_notes).lower() for f in findings)
    assert all("secrets.old" not in " ".join(f.context_notes).lower() for f in findings)


def test_reusable_mapping_notes_redact_values_and_reject_nested_shape():
    content = """jobs:
  literal:
    uses: example/literal/.github/workflows/a.yml@v1
    secrets:
      PASSWORD: never-print-this-value
  nested:
    uses: example/nested/.github/workflows/b.yml@v1
    secrets:
      group:
        password: ${{ secrets.PASSWORD }}
"""
    findings = inventory_findings(content)
    assert len(findings) == 2
    joined = " ".join(" ".join(f.context_notes) for f in findings).lower()
    assert "never-print-this-value" not in joined
    nested = next(f for f in findings if "jobs.nested.uses" in " ".join(f.context_notes).lower())
    assert "unresolved" in " ".join(nested.context_notes).lower()
    assert "secrets.password" not in " ".join(nested.context_notes).lower()


def test_context_references_require_expression_ast_and_opaque_maps_stay_unknown():
    content = """env:
  TOKEN: ${{ secrets.OLD }}
jobs:
  build:
    steps:
      - uses: example/action@v1
        with:
          note: documentation says secrets.DEMO
          deploy: ${{ secrets['DEPLOY_KEY'] }}
          actor: ${{ github.actor }}
        env: ${{ inputs.env }}
      - uses: example/opaque@v1
        with: ${{ inputs.options }}
"""
    findings = inventory_findings(content)
    finding = next(f for f in findings if "jobs.build.steps[0]" in " ".join(f.context_notes))
    notes = " ".join(finding.context_notes).lower()
    assert "secrets.demo" not in notes
    assert "secrets.deploy_key" in notes
    assert "github.actor" in notes
    assert "opaque" in notes or "unresolved" in notes
    assert "effective" in notes
    opaque = next(f for f in findings if "jobs.build.steps[1]" in " ".join(f.context_notes))
    assert "with map" in " ".join(opaque.context_notes).lower()


def test_duplicate_secrets_fields_withhold_inherit_and_named_mapping_claims():
    content = """jobs:
  call:
    uses: example/call/.github/workflows/ci.yml@v1
    secrets:
      TOKEN: ${{ secrets.OLD }}
    secrets: inherit
"""
    (finding,) = inventory_findings(content)
    notes = " ".join(finding.context_notes).lower()
    assert "secret forwarding remains unresolved" in notes
    assert "declares secrets: inherit" not in notes
    assert "token (line" not in notes
    assert "secrets.old" not in notes


def test_merged_reusable_secret_fields_remain_unresolved():
    content = """secret-map: &secret-map
  TOKEN: ${{ secrets.OLD }}
jobs:
  call:
    uses: example/call/.github/workflows/ci.yml@v1
    secrets:
      <<: *secret-map
"""
    (finding,) = inventory_findings(content)
    notes = " ".join(finding.context_notes).lower()
    assert "secret forwarding remains unresolved" in notes
    assert "secrets.old" not in notes
    assert "token (line" not in notes


def test_context_event_bound_is_disclosed_as_unknown(monkeypatch):
    import taintly.rules.github.sec3_sec4_supply_chain_ppe as inventory

    monkeypatch.setattr(inventory, "_MAX_SEC3_CONTEXT_EVENTS", 1)
    (finding,) = inventory_findings("jobs:\n  x:\n    steps:\n      - uses: example/action@v1\n")
    assert any("stopped at 1 structural events" in note for note in finding.context_notes)
    assert any("context are unknown" in note for note in finding.context_notes)


def test_context_note_truncation_keeps_separate_qualifiers_and_omitted_counts():
    long_keys = [f"input_{index}_" + "x" * 64 for index in range(20)]
    with_lines = "\n".join(f"          {key}: value" for key in long_keys)
    content = f"jobs:\n  build:\n    steps:\n      - uses: example/action@v1\n        with:\n{with_lines}\n"
    (finding,) = inventory_findings(content)
    assert all(len(note) <= 500 for note in finding.context_notes)
    assert any("[evidence truncated" in note for note in finding.context_notes)
    assert any("8 additional with/env field(s)" in note for note in finding.context_notes)
    assert any("do not establish value existence" in note for note in finding.context_notes)


def test_valid_reusable_secret_inherit_is_observed_without_release_claim():
    content = """on: workflow_dispatch
jobs:
  call:
    uses: example/workflows/.github/workflows/ci.yml@v1
    secrets: inherit
"""
    (finding,) = inventory_findings(content)
    notes = " ".join(finding.context_notes).lower()
    assert "declares secrets: inherit" in notes
    assert (
        "forwarding configuration does not establish secret existence, value, or release" in notes
    )


@pytest.mark.parametrize(
    ("dead_step", "expected_count"),
    [
        ("{uses: actions/checkout@v4}", 1),
        ("{run: echo dead}", 1),
    ],
)
def test_same_line_dead_noninventory_owner_does_not_hide_live_inventory(dead_step, expected_count):
    content = (
        "on: workflow_dispatch\n"
        "jobs: {dead: {if: false, runs-on: ubuntu-latest, steps: ["
        + dead_step
        + "]}, live: {runs-on: ubuntu-latest, steps: [{uses: example/live@v1}]}}\n"
    )
    findings = inventory_findings(content)
    assert len(findings) == expected_count
    if expected_count:
        notes = " ".join(" ".join(f.context_notes) for f in findings).lower()
        assert "example/live@v1" in notes
        assert "liveness attribution is unresolved" in notes


def test_single_proven_dead_inventory_remains_suppressed():
    content = (
        "on: workflow_dispatch\n"
        "jobs: {dead: {if: false, runs-on: ubuntu-latest, "
        "steps: [{uses: example/dead@v1}]}}\n"
    )
    assert inventory_findings(content) == []


def test_multiline_flow_dead_step_cannot_hide_live_sibling():
    content = """on: workflow_dispatch
jobs: {x: {runs-on: ubuntu-latest, steps: [
  {if: false, uses: actions/checkout@v4,
   with: {fetch-depth: 0}}, {uses: example/live@v1}]}}
"""
    findings = inventory_findings(content)
    assert len(findings) == 1
    notes = " ".join(findings[0].context_notes).lower()
    assert "example/live@v1" in notes
    assert "liveness attribution is unresolved" in notes


def test_all_rules_scan_does_not_treat_jenkinsfile_as_incomplete_github_yaml():
    filepath = Path("tests/fixtures/jenkins/realistic/java_library_ci.Jenkinsfile")
    findings = scan_file(str(filepath), RULES)
    assert not any(
        finding.rule_id == "ENGINE-ERR"
        and "SEC3-GH-006" in finding.title
        and "incomplete pattern results" in finding.title
        for finding in findings
    )
    fragment = "jobs:\n  check:\n    steps:\n      - uses: example/fragment@v1\n"
    assert len(INVENTORY.pattern.check(fragment, fragment.splitlines())) == 1
