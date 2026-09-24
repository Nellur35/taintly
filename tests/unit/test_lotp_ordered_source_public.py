"""Synthetic execution-path contracts for LOTP-GH-001."""

from taintly.rules.registry import get_rule_by_id


def _matches(body: str) -> list[tuple[int, str]]:
    rule = get_rule_by_id("LOTP-GH-001")
    assert rule is not None
    return rule.pattern.check(body, body.splitlines())


def test_build_after_pr_head_checkout_still_fires() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""
    assert _matches(body)


def test_build_before_future_pr_checkout_does_not_fire() -> None:
    body = """jobs:
  build:
    steps:
      - run: npm ci
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert not _matches(body)


def test_fixed_branch_switch_proves_later_build_trusted() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: git switch main
      - run: cargo test
"""
    assert not _matches(body)


def test_pr_checkout_after_fixed_branch_restores_untrusted_state() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: git switch main
      - run: cargo test
      - run: git checkout ${{ github.event.pull_request.head.sha }}
      - run: cargo test
"""
    assert [line for line, _ in _matches(body)] == [10]


def test_dynamic_source_change_fails_closed() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: git switch main
      - run: git switch "$TARGET_REF"
      - run: npm ci
"""
    assert _matches(body)


def test_path_restore_does_not_change_untrusted_source_state() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: git checkout -- package-lock.json
      - run: npm ci
"""
    assert _matches(body)


def test_push_only_build_step_is_not_on_pr_path() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - if: github.event_name == 'push' && github.actor != 'dependabot[bot]'
        run: npm ci
"""
    assert not _matches(body)


def test_pull_request_guard_keeps_finding() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - if: github.event_name == 'pull_request'
        run: npm ci
"""
    assert _matches(body)


def test_disjunctive_event_guard_fails_closed() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - if: github.event_name == 'push' || github.event_name == 'pull_request'
        run: npm ci
"""
    assert _matches(body)


def test_negative_event_guard_fails_closed_for_pull_request_target() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - if: github.event_name != 'pull_request'
        run: npm ci
"""
    assert _matches(body)


def test_negated_push_guard_fails_closed() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - if: "!(github.event_name == 'push')"
        run: npm ci
"""
    assert _matches(body)


def test_bracket_encoded_pr_head_checkout_still_fires() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ GITHUB.event.pull_request['head']['sha'] }}
      - run: npm ci
"""
    assert _matches(body)


def test_later_pr_checkout_does_not_taint_an_earlier_trusted_build() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: npm ci
      - run: git checkout ${{ github.event.pull_request.head.sha }}
"""
    assert not _matches(body)


def test_unresolved_default_checkout_remains_visible() -> None:
    body = """jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: git checkout ${{ github.event.pull_request.head.sha }}
"""
    assert _matches(body)
