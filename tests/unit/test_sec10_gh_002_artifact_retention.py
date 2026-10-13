from __future__ import annotations

from taintly.engine import scan_file
from taintly.rules.registry import load_all_rules

RULES = load_all_rules()


def findings(content: str, filepath: str = "workflow.yml"):
    return [f for f in scan_file(filepath, RULES, _content=content) if f.rule_id == "SEC10-GH-002"]


def engine_diagnostics(content: str, filepath: str = "workflow.yml"):
    return [
        f
        for f in scan_file(filepath, RULES, _content=content)
        if f.rule_id == "ENGINE-ERR" and "SEC10-GH-002" in f.title
    ]


def test_git_pushed_build_output_is_reported_as_an_alternative_candidate():
    content = """name: build-and-push-dist
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - name: Commit dist
        run: |
          git add dist/
          git commit -m "build dist"
          git push
"""
    (finding,) = findings(content)
    assert finding.severity.name == "LOW"
    assert finding.review_needed is True
    notes = " ".join(finding.context_notes).lower()
    assert "git publication command candidate" in notes
    assert "does not establish" in notes or "unknown" in notes
    assert "retains no artifacts" not in finding.title.lower()


def test_release_upload_and_s3_copy_remain_review_candidates():
    release = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
"""
    storage = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - run: aws s3 cp dist/ s3://example-bucket/dist/ --recursive
"""
    (release_finding,) = findings(release)
    (storage_finding,) = findings(storage)
    assert "release" in " ".join(release_finding.context_notes).lower()
    assert "s3" in " ".join(storage_finding.context_notes).lower()
    assert release_finding.review_needed is True
    assert storage_finding.review_needed is True


def test_release_files_configuration_is_bound_to_the_release_step():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - uses: softprops/action-gh-release@v2
      - uses: example/other-action@v1
        with:
          files: unrelated.txt
"""
    (finding,) = findings(content)
    assert (
        "release action files configuration candidate"
        not in " ".join(finding.context_notes).lower()
    )


def test_inbound_s3_copy_is_not_described_as_retention():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - run: aws s3 cp s3://example-bucket/source ./dist --recursive
"""
    (finding,) = findings(content)
    notes = " ".join(finding.context_notes).lower()
    assert "inbound copy" in notes
    assert "not evidence of build-output retention" in notes
    assert "outbound storage command candidate" not in notes


def test_same_owner_upload_declaration_suppresses_but_other_job_does_not():
    same_owner = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist/
"""
    foreign_owner = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
  screenshots:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: screenshots
          path: screenshots/
"""
    assert findings(same_owner) == []
    (finding,) = findings(foreign_owner)
    assert "another owner" in " ".join(finding.context_notes).lower()


def test_non_executable_text_comments_heredocs_and_env_values_are_not_builds():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BUILD_NOTE: npm run build
    steps:
      - run: echo "npm run build"
      - run: |
          # npm run build
          cat <<'EOF'
          npm run build
          EOF
          npm run build
      - name: Documentation
        run: printf '%s\\n' 'npm run build'
"""
    assert findings(content) == []
    assert not engine_diagnostics(content)


def test_unsupported_command_context_is_not_silently_promoted_from_a_later_step():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          npm run build
          EOF
      - run: npm run build
"""
    (finding,) = findings(content)
    assert "heredoc" in " ".join(finding.context_notes).lower()


def test_quoted_separator_text_does_not_create_a_build_command():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ';' npm run build
      - run: printf '%s' 'npm run build'
      - run: echo \\";\\" npm run build
"""
    assert findings(content) == []


def test_command_family_match_preserves_case_sensitive_shell_semantics():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: NPM run BUILD
"""
    assert findings(content) == []


def test_static_build_package_script_suffixes_are_candidates_not_echoed_data():
    accepted = ("npm run build:preview", "yarn build:preview", "pnpm build:preview")
    for command in accepted:
        content = f"""jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
"""
        (finding,) = findings(content)
        assert finding.review_needed is True
        assert "observed executable" in " ".join(finding.context_notes).lower()

    rejected = (
        "npm run build:",
        "npm run preview:build",
        "npm install build:preview",
        'echo "npm run build:preview"',
    )
    for command in rejected:
        content = f"""jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
"""
        assert findings(content) == []


def test_fragment_api_still_finds_executable_build_command():
    from taintly.rules.github.sec10_logging_visibility import RULES as MODULE_RULES

    rule = next(rule for rule in MODULE_RULES if rule.id == "SEC10-GH-002")
    fragment = "steps:\n  - run: npm run build\n"
    assert rule.pattern.check(fragment, fragment.splitlines()) == [(2, "- run: npm run build")]


def test_line_owner_count_collapses_ancestors_but_keeps_sibling_owners():
    from taintly.parsers.structural import Event, EventKind
    from taintly.rules.github.sec10_logging_visibility import _line_owner_counts

    def leaf(path: tuple[object, ...], line: int) -> Event:
        return Event(EventKind.LEAF_SCALAR, path, line, 1)

    parent_and_child = [
        leaf(("jobs", "build", "defaults", "run", "shell"), 8),
        leaf(("jobs", "build", "steps", 0, "run"), 8),
    ]
    sibling_steps = [
        leaf(("jobs", "build", "steps", 0, "run"), 9),
        leaf(("jobs", "build", "steps", 1, "run"), 9),
    ]
    separate_jobs = [
        leaf(("jobs", "build", "steps", 0, "run"), 10),
        leaf(("jobs", "test", "steps", 0, "run"), 10),
    ]
    assert _line_owner_counts(parent_and_child) == {8: 1}
    assert _line_owner_counts(sibling_steps) == {9: 2}
    assert _line_owner_counts(separate_jobs) == {10: 2}


def test_literal_body_locations_and_folded_scalar_origin_are_explicit():
    literal = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo setup
          npm run build
"""
    (literal_finding,) = findings(literal)
    assert literal_finding.line == 7
    assert literal_finding.snippet == "npm run build"
    assert not any("scalar origin" in note.lower() for note in literal_finding.context_notes)

    folded = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: >+
          echo setup

          npm run build
"""
    (folded_finding,) = findings(folded)
    assert folded_finding.line == 5
    assert folded_finding.snippet == "- run: >+"
    assert any(
        "scalar origin, not a physical command-body line" in note
        for note in folded_finding.context_notes
    )

    folded_backslash = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          echo \\
          npm run build
"""
    assert findings(folded_backslash) == []


def test_composite_action_build_step_uses_its_declared_shell():
    content = """name: build
runs:
  using: composite
  steps:
    - shell: bash
      run: npm run build
"""
    (finding,) = findings(content, "action.yml")
    assert finding.review_needed is True


def test_shared_line_dead_and_live_owners_are_retained_with_unknown_liveness():
    content = (
        "on: workflow_dispatch\n"
        "jobs: {dead: {if: false, runs-on: ubuntu-latest, steps: [{run: npm run build}]}, "
        "live: {runs-on: ubuntu-latest, steps: [{run: npm run build}]}}\n"
    )
    found = findings(content)
    assert len(found) == 2
    assert all(
        "liveness attribution is unresolved" in " ".join(f.context_notes).lower() for f in found
    )


def test_shared_line_dead_nonbuild_sibling_does_not_hide_live_build():
    content = (
        "on: workflow_dispatch\n"
        "jobs: {dead: {if: false, runs-on: ubuntu-latest, steps: [{run: echo no-build}]}, "
        "live: {runs-on: ubuntu-latest, steps: [{run: npm run build}]}}\n"
    )
    (finding,) = findings(content)
    assert "liveness attribution is unresolved" in " ".join(finding.context_notes).lower()


def test_sole_proven_dead_build_owner_stays_suppressed():
    content = """on: workflow_dispatch
jobs:
  dead:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
"""
    assert findings(content) == []


def test_duplicate_and_cutoff_owner_are_disclosed_as_incomplete():
    duplicate = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
        run: echo done
"""
    result = findings(duplicate)
    assert result == []
    assert engine_diagnostics(duplicate)
    cutoff = "node: &node\n  next: *node\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run build\n"
    assert findings(cutoff) == []
    assert engine_diagnostics(cutoff)


def test_folded_and_flow_run_values_are_read_from_decoded_scalars():
    folded = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          npm run build
    """
    flow = "jobs: {build: {runs-on: ubuntu-latest, steps: [{run: 'npm run build'}]}}\n"
    (folded_finding,) = findings(folded)
    assert folded_finding.file == "workflow.yml"
    assert folded_finding.line == 5
    assert folded_finding.snippet == "- run: >-"
    assert folded_finding.review_needed is True
    assert "observed executable npm build-command candidate in owner jobs.build." in (
        " ".join(folded_finding.context_notes).lower()
    )
    assert any(
        "scalar origin, not a physical command-body line" in note
        for note in folded_finding.context_notes
    )
    assert len(findings(flow)) == 1

    folded_echo = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          echo
          npm run build
"""
    assert findings(folded_echo) == []


def test_effective_shell_and_ambiguous_owner_are_not_guessed():
    powershell = """defaults:
  run:
    shell: pwsh
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
"""
    assert findings(powershell) == []
    assert not engine_diagnostics(powershell)
    explicit = """defaults:
  run:
    shell: pwsh
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run: npm run build
"""
    assert len(findings(explicit)) == 1
    dynamic_runner = """jobs:
  build:
    runs-on: ${{ matrix.runner }}
    steps:
      - run: npm run build
"""
    assert findings(dynamic_runner) == []
    assert not engine_diagnostics(dynamic_runner)
    null_shell = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: null
        run: npm run build
"""
    assert findings(null_shell) == []
    assert not engine_diagnostics(null_shell)
    null_job_default = """jobs:
  build:
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: null
    steps:
      - run: npm run build
"""
    assert findings(null_job_default) == []
    assert not engine_diagnostics(null_job_default)
    merged = """step: &step
  run: npm run build
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - <<: *step
"""
    assert findings(merged) == []
    assert engine_diagnostics(merged)


def test_inherited_runner_with_echo_only_does_not_create_sec10_diagnostic():
    content = """runner: &runner
  runs-on: ubuntu-latest
jobs:
  build:
    <<: *runner
    steps:
      - run: echo setup complete
"""
    assert findings(content) == []
    assert engine_diagnostics(content) == []


def test_windows_job_is_not_parsed_as_posix():
    content = """jobs:
  build:
    runs-on: windows-latest
    steps:
      - run: npm run build
"""
    assert findings(content) == []
    assert not engine_diagnostics(content)


def test_non_yaml_filepath_does_not_run_structural_rule():
    content = "pipeline {\n  sh 'npm run build'\n}\n"
    assert findings(content, "Jenkinsfile") == []
    assert not engine_diagnostics(content, "Jenkinsfile")
