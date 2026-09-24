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


def test_side_by_side_checkouts_build_in_fork_path_fires() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: main
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: cd fork && npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_side_by_side_checkouts_build_in_trusted_path_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: main
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: cd base && npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_quoted_cache_mode_and_action_use_fire() -> None:
    workflow = """on: pull_request_target
cache-mode: "write"
jobs:
  build:
    steps:
      - uses: "actions/cache@v4"
"""
    assert _fires("SEC4-GH-026A", workflow)


def test_quoted_job_cache_mode_and_action_use_fire() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    cache-mode: 'write-only'
    steps:
      - uses: 'actions/cache/save@v4'
"""
    assert _fires("SEC4-GH-026A", workflow)


def test_quoted_read_cap_keeps_reusable_review_cue_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  call:
    cache-mode: 'read'
    uses: './.github/workflows/cache.yml'
"""
    assert not _fires("SEC4-GH-026B", workflow)


def test_side_by_side_checkout_step_working_directory_fires() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci
        working-directory: fork
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_side_by_side_checkout_job_default_working_directory_fires() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    defaults:
      run:
        working-directory: fork
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_second_cd_on_same_line_controls_build_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: cd base && cd ../fork && npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_unknown_shell_directory_keeps_build_visible() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: cd "$TARGET" && npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_workflow_default_working_directory_selects_fork() -> None:
    workflow = """on: pull_request_target
defaults:
  run:
    working-directory: fork
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_fork_subdirectory_inherits_checkout_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci
        working-directory: fork/package
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_trusted_subdirectory_inherits_checkout_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci
        working-directory: base/package
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_four_space_step_working_directory_selects_fork() -> None:
    workflow = """on: pull_request_target
jobs:
    build:
        steps:
            - uses: actions/checkout@v4
                with:
                    ref: ${{ github.event.pull_request.head.sha }}
                    path: fork
            - uses: actions/checkout@v4
                with:
                    ref: main
                    path: base
            - run: npm ci
                working-directory: fork
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_printed_cd_cannot_move_source_to_trusted_checkout() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          echo "starting; cd ../base"
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_printed_git_switch_cannot_clear_pr_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          echo "example; git switch main"
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_build_argument_may_select_side_by_side_fork() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci --prefix fork
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_printed_cd_cannot_taint_trusted_checkout() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd base
          echo "starting; cd ../fork"
          npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_yaml_quoted_run_still_executes_cd() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: 'cd fork && npm ci'
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_npm_prefix_before_install_verb_selects_side_fork() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm --prefix fork ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_multiline_printed_cd_cannot_clear_fork_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          echo "starting;
          cd ../base"
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_commented_cd_cannot_clear_fork_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          # ; cd ../base
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_heredoc_cd_cannot_clear_fork_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          cat <<EOF
          ; cd ../base
          EOF
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_plain_root_build_with_fork_side_checkout_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: samples
      - run: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_explicit_trusted_prefix_stays_silent_with_fork_side_checkout() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: npm ci --prefix base
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_commented_prefix_cannot_redirect_fork_build_to_trusted_path() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          npm ci # --prefix ../base
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_inline_comment_build_text_is_not_executed() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo ready # npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_action_input_build_text_is_not_a_run_command() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: example/action@v1
        with:
          note: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_shell_c_wrapper_still_executes_quoted_build_command() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash -c "npm ci"
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_quoted_hyphenated_heredoc_delimiter_keeps_later_fork_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          cat <<'END-EOF'
          this is data
          END-EOF
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pip_local_side_checkout_is_untrusted_from_trusted_cwd() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install ./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_pip_trusted_side_checkout_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: pip install ./base
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_pip_requirements_from_fork_side_checkout_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install -r fork/requirements.txt
"""
    assert _fires("LOTP-GH-001", workflow)


def test_pip_multiple_local_paths_do_not_prove_trusted_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install . ./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_indented_heredoc_data_cannot_close_delimiter_early() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          cat <<EOF
            EOF
          ; cd ../base
          EOF
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pip_editable_side_checkout_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install -e fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_pip_long_editable_trusted_side_checkout_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: pip install --editable base
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_pr_metadata_env_does_not_prove_pr_head_checkout() -> None:
    workflow = """on: pull_request
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - env:
          PR_SHA: ${{ github.event.pull_request.head.sha }}
        run: pip install -e ".[dev]"
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_checkout_ref_still_proves_pr_head_with_metadata_env() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - env:
          PR_SHA: ${{ github.event.pull_request.head.sha }}
        run: pip install -e ".[dev]"
"""
    assert _fires("LOTP-GH-001", workflow)


def test_second_heredoc_body_cannot_clear_fork_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: |
          cd fork
          cat <<A <<B
          first body
          A
          ; cd ../base
          B
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pip_editable_equals_path_from_fork_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install --editable=./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_pip_long_requirement_path_from_fork_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install --requirement ./fork/requirements.txt
"""
    assert _fires("LOTP-GH-001", workflow)


def test_executable_git_checkout_is_pr_source_without_checkout_ref() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout ${{ github.event.pull_request.head.sha }}
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_fetch_head_does_not_prove_trusted_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout FETCH_HEAD
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_head_switch_does_not_prove_trusted_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          git checkout HEAD
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pr_ref_fetch_then_fetch_head_build_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout FETCH_HEAD
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pr_ref_fetched_into_named_branch_stays_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head:refs/remotes/origin/pr-head
          git checkout origin/pr-head
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_git_checkout_target_ignores_adjacent_pr_echo() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: |
          git checkout main && echo ${{ github.event.pull_request.head.sha }}
          npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_pip_compact_short_options_resolve_fork_paths() -> None:
    for command in ("pip install -e./fork", "pip install -r./fork/requirements.txt"):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: {command}
"""
        assert _fires("LOTP-GH-001", workflow), command


def test_pr_fetch_provenance_survives_run_step_boundary() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: git fetch origin refs/pull/${{ github.event.pull_request.number }}/head:refs/remotes/origin/pr-head
      - run: git checkout origin/pr-head
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_short_pr_fetch_spelling_taints_fetch_head() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: |
          git fetch origin pull/${{ github.event.pull_request.number }}/head
          git checkout FETCH_HEAD
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pip_option_before_compact_editable_path_is_detected() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install --no-deps -e./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_later_trusted_fetch_replaces_fetch_head_provenance() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git fetch origin main
          git checkout FETCH_HEAD
          npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_echoed_git_fetch_does_not_change_provenance() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: |
          git fetch origin main
          echo git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout FETCH_HEAD
          npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_echoed_git_checkout_does_not_change_provenance() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: |
          echo git checkout ${{ github.event.pull_request.head.sha }}
          npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_named_pip_package_after_option_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pip install --no-deps requests
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_pip_output_directory_does_not_select_source_checkout() -> None:
    for command in (
        "pip install --target ./output requests",
        "pip install --prefix ./output requests",
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: {command}
"""
        assert not _fires("LOTP-GH-001", workflow), command


def test_second_pip_build_on_line_selects_untrusted_checkout() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install requests && pip install -e./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_second_npm_build_after_cd_on_line_is_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: npm ci; cd fork; npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_conditional_trusted_git_fallback_cannot_clear_pr_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout ${{ github.event.pull_request.head.sha }} || git checkout main
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_conditional_trusted_fetch_cannot_clear_pr_fetch_head() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head || git fetch origin main
          git checkout FETCH_HEAD
          npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pip_cert_path_is_not_install_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip install --cert ./fork/ca.pem requests
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_bash_c_pip_local_side_checkout_is_detected() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: bash -c "pip install ./fork"
"""
    assert _fires("LOTP-GH-001", workflow)


def test_bash_c_pip_trusted_side_checkout_stays_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - run: bash -c "pip install ./base"
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_pip_global_flag_before_install_keeps_local_source_visible() -> None:
    for command in (
        "pip --no-cache-dir install ./fork",
        "python -m pip --disable-pip-version-check install ./fork",
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: {command}
"""
        assert _fires("LOTP-GH-001", workflow), command


def test_pip_global_cert_value_is_not_install_source() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: pip --cert ./fork/ca.pem install requests
"""
    assert not _fires("LOTP-GH-001", workflow)


def test_nested_shell_directory_change_selects_untrusted_source() -> None:
    for command in (
        'bash -c "cd fork; pip install ."',
        'sh -c "cd fork; npm ci"',
        'bash -lc "cd fork; npm ci"',
        'bash -c "npm ci; cd fork; npm ci"',
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: {command}
"""
        assert _fires("LOTP-GH-001", workflow), command


def test_printed_build_text_is_not_executed() -> None:
    for command in ('echo npm ci', 'bash -c "echo npm ci"'):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: {command}
"""
        assert not _fires("LOTP-GH-001", workflow), command
        assert not _fires("LOTP-GH-003", workflow), command


def test_nested_shell_pr_fetch_reaches_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: bash -c "git fetch origin pull/${{ github.event.pull_request.number }}/head; git checkout FETCH_HEAD; npm ci"
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_python3_m_pip_global_flag_reaches_side_checkout() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: fork
      - run: python3 -m pip --no-cache-dir install ./fork
"""
    assert _fires("LOTP-GH-001", workflow)


def test_nested_shell_with_outer_commands_keeps_pr_build_visible() -> None:
    for command in (
        'bash -c "cd fork; npm ci" && echo done',
        'env CI=1 bash -c "cd fork; npm ci"',
        'echo ready && sh -c "cd fork; npm ci"',
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: {command}
"""
        assert _fires("LOTP-GH-001", workflow), command


def test_nested_shell_cd_does_not_change_parent_cwd() -> None:
    for command in (
        'bash -c "cd fork"\nnpm ci',
        'bash -c "cd fork"; npm ci',
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: |
          {command.replace(chr(10), chr(10) + '          ')}
"""
        assert not _fires("LOTP-GH-001", workflow), command
        assert not _fires("LOTP-GH-003", workflow), command


def test_pip_non_install_subcommand_is_not_local_build() -> None:
    for command in ("pip show install", "python -m pip show install"):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: {command}
"""
        assert not _fires("LOTP-GH-001", workflow), command
        assert not _fires("LOTP-GH-003", workflow), command


def test_child_shell_inherits_current_outer_directory_in_command_order() -> None:
    for command, expected in (
        ('cd fork; bash -c "npm ci"', True),
        ('cd fork; bash -c "cd ..; npm ci"', False),
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: {command}
"""
        assert _fires("LOTP-GH-001", workflow) is expected, command


def test_pip_repeated_verbosity_keeps_local_install_path() -> None:
    for path, expected in (("./base", False), ("./fork", True)):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
          path: base
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: fork
      - run: pip -vv install {path}
"""
        assert _fires("LOTP-GH-001", workflow) is expected, path


def test_pr_merge_ref_fetch_reaches_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin refs/pull/${{ github.event.pull_request.number }}/merge; git checkout FETCH_HEAD; npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pr_fetch_options_and_force_refspec_reach_build() -> None:
    for command in (
        "git fetch --depth=1 origin refs/pull/${{ github.event.pull_request.number }}/head",
        "git fetch --depth 1 origin +refs/pull/${{ github.event.pull_request.number }}/head",
        "git fetch origin +refs/pull/${{ github.event.pull_request.number }}/merge:refs/remotes/origin/pr",
    ):
        checkout = "refs/remotes/origin/pr" if ":refs/remotes/" in command else "FETCH_HEAD"
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {command}; git checkout {checkout}; npm ci
"""
        assert _fires("LOTP-GH-001", workflow), command
        assert _fires("LOTP-GH-003", workflow), command


def test_gh_pr_checkout_reaches_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: gh pr checkout ${{ github.event.pull_request.number }}
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_pr_checkout_text_is_not_executed() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: echo gh pr checkout ${{ github.event.pull_request.number }}
      - run: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_optioned_trusted_fetch_keeps_build_silent() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch --depth 1 origin refs/heads/main; git checkout FETCH_HEAD; npm ci
      - run: echo ${{ github.event.pull_request.number }}
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_git_global_options_before_pr_fetch_reach_build() -> None:
    for command in (
        "git -c protocol.version=2 fetch origin refs/pull/${{ github.event.pull_request.number }}/head",
        "git -C . fetch origin refs/pull/${{ github.event.pull_request.number }}/merge",
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {command}; git checkout FETCH_HEAD; npm ci
"""
        assert _fires("LOTP-GH-001", workflow), command
        assert _fires("LOTP-GH-003", workflow), command


def test_gh_pr_checkout_url_reaches_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: gh pr checkout https://github.com/${{ github.repository }}/pull/${{ github.event.pull_request.number }}
      - run: npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_gh_pr_checkout_worktree_taints_only_worktree_path() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: gh pr checkout ${{ github.event.pull_request.number }} --worktree fork
      - run: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)
    fork_workflow = workflow.replace("- run: npm ci", "- run: npm --prefix fork ci")
    assert _fires("LOTP-GH-001", fork_workflow)
    assert _fires("LOTP-GH-003", fork_workflow)


def test_dry_run_pr_fetch_does_not_change_fetch_head() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin main
      - run: git fetch --dry-run origin refs/pull/${{ github.event.pull_request.number }}/head
      - run: git checkout FETCH_HEAD
      - run: npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_global_git_options_before_checkout_preserve_pr_fetch_provenance() -> None:
    for checkout in (
        "git -C . checkout FETCH_HEAD",
        "git -c protocol.version=2 checkout FETCH_HEAD",
        "git -C fork checkout FETCH_HEAD; cd fork",
    ):
        fetch = "git -C fork fetch" if "fork" in checkout else "git fetch"
        setup = "mkdir fork; git clone . fork; " if "fork" in checkout else ""
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {setup}{fetch} origin refs/pull/${{{{ github.event.pull_request.number }}}}/head; {checkout}; npm ci
"""
        assert _fires("LOTP-GH-001", workflow), checkout
        assert _fires("LOTP-GH-003", workflow), checkout


def test_changed_origin_to_pr_fork_makes_static_ref_untrusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote set-url origin https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_static_origin_still_keeps_static_ref_trusted() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote set-url origin https://github.com/example/base.git; git fetch origin main; git checkout FETCH_HEAD; npm ci
      - run: echo ${{ github.event.pull_request.number }}
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)


def test_fork_remote_add_and_direct_fetch_reach_build() -> None:
    for commands in (
        "git remote add fork https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch fork main",
        "git fetch https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git main",
    ):
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {commands}; git checkout FETCH_HEAD; npm ci
"""
        assert _fires("LOTP-GH-001", workflow), commands
        assert _fires("LOTP-GH-003", workflow), commands


def test_fork_clone_url_changed_origin_reaches_build() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote set-url origin ${{ github.event.pull_request.head.repo.clone_url }}; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
    assert _fires("LOTP-GH-001", workflow)
    assert _fires("LOTP-GH-003", workflow)


def test_added_second_fetch_url_does_not_replace_trusted_first_url() -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote set-url --add origin https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
    assert not _fires("LOTP-GH-001", workflow)
    assert not _fires("LOTP-GH-003", workflow)
