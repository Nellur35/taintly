"""Synthetic regressions from independent review of the precision candidate."""

from taintly.rules.registry import get_rule_by_id


def _fires(rule_id: str, workflow: str) -> bool:
    rule = get_rule_by_id(rule_id)
    assert rule is not None
    return bool(rule.pattern.check(workflow, workflow.splitlines()))


def test_fork_repository_with_fixed_ref_is_not_trusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: main
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)


def test_action_input_text_cannot_prove_step_output_safe() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - id: producer
        uses: example/action@v1
        with:
          script: |
            echo "tag=fixed" >> $GITHUB_OUTPUT
      - run: deploy ${{ steps.producer.outputs.tag }}
"""
    assert _fires("SEC4-GH-021", workflow)


def test_inherited_artifact_settings_do_not_prove_restricted_access() -> None:
    workflow = """.defaults: &defaults
  access: all
build:
  script: make
  artifacts:
    <<: *defaults
    paths:
      - .env
"""
    assert _fires("SEC9-GL-001", workflow)


def test_write_capable_reusable_workflow_caller_is_visible() -> None:
    workflow = """on: pull_request_target
jobs:
  cache:
    cache-mode: write
    uses: ./.github/workflows/cache.yml
"""
    assert _fires("SEC4-GH-026B", workflow)


def test_reusable_cache_cue_requires_real_pull_request_target_trigger() -> None:
    workflow = """on: push
jobs:
  call:
    cache-mode: write
    uses: ./.github/workflows/cache.yml
  example:
    steps:
      - run: |
          pull_request_target:
            echo example
"""
    assert not _fires("SEC4-GH-026B", workflow)


def test_npm_build_before_pr_checkout_is_not_reported() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - run: npm ci
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert not _fires("LOTP-GH-003", workflow)


def test_fork_checkout_then_static_branch_switch_stays_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: main
      - run: git switch main
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_uncapped_reusable_workflow_call_needs_cache_review() -> None:
    workflow = """on: pull_request_target
jobs:
  call:
    uses: ./.github/workflows/cache.yml
"""
    assert _fires("SEC4-GH-026B", workflow)


def test_cache_write_rule_ignores_trigger_text_in_push_script() -> None:
    workflow = """on: push
jobs:
  build:
    cache-mode: write
    steps:
      - run: |
          pull_request_target:
            echo example
      - uses: actions/cache@v4
"""
    assert not _fires("SEC4-GH-026A", workflow)


def test_push_only_checkout_does_not_taint_pr_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - if: github.event_name == 'push'
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_push_only_branch_switch_cannot_clear_pr_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - if: github.event_name == 'push'
        run: git switch main
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)
