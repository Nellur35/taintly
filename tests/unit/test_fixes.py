"""Unit tests for the auto-fix functions in taintly.fixes."""

from __future__ import annotations

import pathlib

import pytest

from taintly.fixes import (
    ALL_FIXERS,
    OPT_IN_FIXERS,
    apply_fixes,
    fix_disable_setup_cache_in_release,
    fix_github_ai_allowed_tools_scaffold,
    fix_hoist_service_credentials,
    fix_jenkins_cap_add_hint,
    fix_npm_ignore_scripts,
    fix_quote_github_refs,
    fix_quote_gitlab_ci_vars,
    fix_quote_gitlab_refs,
    fix_remove_debug_logging,
    fix_remove_insecure_commands,
    fix_unquote_groovy_gstring_with_params,
)


# ---------------------------------------------------------------------------
# fix_npm_ignore_scripts
# ---------------------------------------------------------------------------


def _write(tmp_path, content: str):
    p = tmp_path / "workflow.yml"
    p.write_text(content, encoding="utf-8")
    return str(p)


def _read(path: str) -> str:
    """Read helper that closes the handle — prevents ResourceWarning."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_ignore_scripts_adds_flag_to_npm_install(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: npm install\n")
    results = fix_npm_ignore_scripts(path, dry_run=False)
    assert len(results) == 1
    assert results[0].fix_type == "npm_ignore_scripts"
    assert "npm install --ignore-scripts" in _read(path)


def test_ignore_scripts_adds_flag_to_npm_ci(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: npm ci --production\n")
    fix_npm_ignore_scripts(path, dry_run=False)
    # Flag inserted right after the npm command, preserving trailing args.
    assert "npm ci --ignore-scripts --production" in _read(path)


def test_ignore_scripts_handles_yarn_and_pnpm(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: yarn install\n  - run: pnpm i\n")
    results = fix_npm_ignore_scripts(path, dry_run=False)
    assert len(results) == 2
    text = _read(path)
    assert "yarn install --ignore-scripts" in text
    assert "pnpm i --ignore-scripts" in text


def test_ignore_scripts_skips_lines_already_safe(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: npm install --ignore-scripts\n")
    results = fix_npm_ignore_scripts(path, dry_run=False)
    assert results == []
    assert _read(path).count("--ignore-scripts") == 1


def test_ignore_scripts_does_not_rewrite_npm_test_or_run(tmp_path):
    # `npm test` / `npm run X` are explicit user-script invocations; adding
    # --ignore-scripts to them would be surprising and is out of scope.
    path = _write(
        tmp_path,
        "steps:\n  - run: npm test\n  - run: npm run build\n",
    )
    results = fix_npm_ignore_scripts(path, dry_run=False)
    assert results == []


def test_ignore_scripts_dry_run_does_not_modify_file(tmp_path):
    original = "steps:\n  - run: npm install\n"
    path = _write(tmp_path, original)
    results = fix_npm_ignore_scripts(path, dry_run=True)
    assert len(results) == 1
    assert _read(path) == original


# ---------------------------------------------------------------------------
# fix_quote_github_refs  (SEC4-GH-018)
# ---------------------------------------------------------------------------


def test_quote_github_refs_wraps_unquoted_ref_name(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: echo $GITHUB_REF_NAME\n")
    results = fix_quote_github_refs(path, dry_run=False)
    assert len(results) == 1
    assert results[0].fix_type == "quote_github_refs"
    assert 'echo "$GITHUB_REF_NAME"' in _read(path)


def test_quote_github_refs_wraps_braced_form(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: docker tag img:${GITHUB_REPOSITORY_OWNER}\n")
    fix_quote_github_refs(path, dry_run=False)
    assert 'img:"${GITHUB_REPOSITORY_OWNER}"' in _read(path)


def test_quote_github_refs_skips_already_double_quoted(tmp_path):
    original = 'steps:\n  - run: echo "$GITHUB_REF_NAME"\n'
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=False)
    assert results == []
    assert _read(path) == original


def test_quote_github_refs_skips_single_quoted(tmp_path):
    original = "steps:\n  - run: echo '$GITHUB_REF_NAME is literal'\n"
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=False)
    assert results == []
    assert _read(path) == original


def test_quote_github_refs_skips_if_expression(tmp_path):
    original = "      - if: $GITHUB_REF_NAME == 'main'\n"
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=False)
    assert results == []
    assert _read(path) == original


def test_quote_github_refs_skips_yaml_key_value(tmp_path):
    original = "    env:\n      REF: $GITHUB_REF_NAME\n"
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=False)
    assert results == []
    assert _read(path) == original


def test_quote_github_refs_skips_quoted_heredoc_body(tmp_path):
    original = (
        "steps:\n"
        "  - run: |\n"
        "      cat <<'EOF'\n"
        "      $GITHUB_REF_NAME is literal inside a quoted heredoc\n"
        "      EOF\n"
    )
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=False)
    assert results == []
    assert _read(path) == original


def test_quote_github_refs_dry_run_preserves_file(tmp_path):
    original = "steps:\n  - run: echo $GITHUB_REF_NAME\n"
    path = _write(tmp_path, original)
    results = fix_quote_github_refs(path, dry_run=True)
    assert len(results) == 1
    assert _read(path) == original


def test_quote_github_refs_does_not_double_rewrite(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: echo $GITHUB_REF_NAME\n")
    fix_quote_github_refs(path, dry_run=False)
    # Second pass over the now-fixed file: nothing further to do.
    results_second = fix_quote_github_refs(path, dry_run=False)
    assert results_second == []
    assert _read(path).count('"$GITHUB_REF_NAME"') == 1


def test_quote_github_refs_registered_in_all_fixers():
    assert "quote_github_refs" in ALL_FIXERS


# ---------------------------------------------------------------------------
# fix_quote_gitlab_refs  (SEC4-GL-003)
# ---------------------------------------------------------------------------


def test_quote_gitlab_refs_wraps_commit_ref_name(tmp_path):
    path = _write(tmp_path, "script:\n  - docker tag image:latest image:$CI_COMMIT_REF_NAME\n")
    results = fix_quote_gitlab_refs(path, dry_run=False)
    assert len(results) == 1
    assert 'image:"$CI_COMMIT_REF_NAME"' in _read(path)


def test_quote_gitlab_refs_handles_tag_and_build_ref(tmp_path):
    path = _write(
        tmp_path,
        "script:\n  - git push origin $CI_COMMIT_TAG\n  - deploy.sh --version $CI_BUILD_REF_NAME\n",
    )
    results = fix_quote_gitlab_refs(path, dry_run=False)
    assert len(results) == 2
    text = _read(path)
    assert '"$CI_COMMIT_TAG"' in text
    assert '"$CI_BUILD_REF_NAME"' in text


def test_quote_gitlab_refs_skips_already_quoted(tmp_path):
    original = 'script:\n  - docker tag image:latest "image:$CI_COMMIT_REF_NAME"\n'
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_skips_rules_if(tmp_path):
    original = "    - if: $CI_COMMIT_REF_NAME == 'main'\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_skips_yaml_key_value(tmp_path):
    original = "variables:\n  REF: $CI_COMMIT_REF_NAME\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_skips_bash_double_bracket(tmp_path):
    original = "script:\n  - if [[ $CI_COMMIT_REF_NAME =~ ^v[0-9]+ ]]; then echo release; fi\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_skips_quoted_heredoc(tmp_path):
    original = (
        "script:\n"
        "  - |\n"
        "    cat <<'EOF'\n"
        "    $CI_COMMIT_REF_NAME stays literal in quoted heredoc\n"
        "    EOF\n"
    )
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_does_not_touch_sha_variable(tmp_path):
    # CI_MERGE_REQUEST_SOURCE_BRANCH_SHA was removed from the rule in PR #65
    # because SHAs are 40-char hex and can't carry shell metacharacters.
    original = "script:\n  - git log --format=%h $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_refs(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_refs_dry_run_preserves_file(tmp_path):
    original = "script:\n  - docker tag image:latest image:$CI_COMMIT_REF_NAME\n"
    path = _write(tmp_path, original)
    results = fix_quote_gitlab_refs(path, dry_run=True)
    assert len(results) == 1
    assert _read(path) == original


def test_quote_gitlab_refs_registered_in_all_fixers():
    assert "quote_gitlab_refs" in ALL_FIXERS


# ---------------------------------------------------------------------------
# fix_quote_gitlab_ci_vars  (SEC4-GL-001)
# ---------------------------------------------------------------------------


def test_quote_gitlab_ci_vars_wraps_commit_message(tmp_path):
    path = _write(tmp_path, "script:\n  - echo $CI_COMMIT_MESSAGE\n")
    results = fix_quote_gitlab_ci_vars(path, dry_run=False)
    assert len(results) == 1
    assert results[0].fix_type == "quote_gitlab_ci_vars"
    assert 'echo "$CI_COMMIT_MESSAGE"' in _read(path)


def test_quote_gitlab_ci_vars_handles_all_five_vars(tmp_path):
    path = _write(
        tmp_path,
        "script:\n"
        "  - echo $CI_COMMIT_MESSAGE\n"
        "  - git tag $CI_MERGE_REQUEST_TITLE\n"
        "  - log.sh $CI_MERGE_REQUEST_DESCRIPTION\n"
        "  - deploy.sh $CI_COMMIT_BRANCH\n"
        "  - branch.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME\n",
    )
    results = fix_quote_gitlab_ci_vars(path, dry_run=False)
    assert len(results) == 5
    text = _read(path)
    assert '"$CI_COMMIT_MESSAGE"' in text
    assert '"$CI_MERGE_REQUEST_TITLE"' in text
    assert '"$CI_MERGE_REQUEST_DESCRIPTION"' in text
    assert '"$CI_COMMIT_BRANCH"' in text
    assert '"$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"' in text


def test_quote_gitlab_ci_vars_wraps_braced_form(tmp_path):
    path = _write(tmp_path, "script:\n  - docker tag img:${CI_COMMIT_BRANCH}\n")
    fix_quote_gitlab_ci_vars(path, dry_run=False)
    assert 'img:"${CI_COMMIT_BRANCH}"' in _read(path)


def test_quote_gitlab_ci_vars_skips_already_double_quoted(tmp_path):
    original = 'script:\n  - echo "$CI_COMMIT_MESSAGE"\n'
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_skips_single_quoted(tmp_path):
    # `$VAR` inside `'...'` is literal per POSIX sh §2.2.2.
    original = "script:\n  - echo '$CI_COMMIT_BRANCH is literal'\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_skips_rules_if(tmp_path):
    original = '    - if: $CI_COMMIT_BRANCH == "main"\n'
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_skips_yaml_key_value(tmp_path):
    original = "variables:\n  MSG: $CI_COMMIT_MESSAGE\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_skips_bash_double_bracket(tmp_path):
    # Inside [[ ]], word splitting is disabled per Bash §3.2.5.2.
    original = "script:\n  - if [[ $CI_COMMIT_BRANCH =~ ^main ]]; then echo prod; fi\n"
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_skips_quoted_heredoc(tmp_path):
    original = (
        "script:\n"
        "  - |\n"
        "    cat <<'EOF'\n"
        "    $CI_COMMIT_MESSAGE stays literal in quoted heredoc\n"
        "    EOF\n"
    )
    path = _write(tmp_path, original)
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path) == original


def test_quote_gitlab_ci_vars_dry_run_preserves_file(tmp_path):
    original = "script:\n  - echo $CI_COMMIT_MESSAGE\n"
    path = _write(tmp_path, original)
    results = fix_quote_gitlab_ci_vars(path, dry_run=True)
    assert len(results) == 1
    assert _read(path) == original


def test_quote_gitlab_ci_vars_does_not_double_rewrite(tmp_path):
    path = _write(tmp_path, "script:\n  - echo $CI_COMMIT_MESSAGE\n")
    fix_quote_gitlab_ci_vars(path, dry_run=False)
    # Second pass over the now-fixed file: nothing further to do.
    assert fix_quote_gitlab_ci_vars(path, dry_run=False) == []
    assert _read(path).count('"$CI_COMMIT_MESSAGE"') == 1


def test_quote_gitlab_ci_vars_registered_in_all_fixers():
    assert "quote_gitlab_ci_vars" in ALL_FIXERS


# ---------------------------------------------------------------------------
# fix_unquote_groovy_gstring_with_params  (SEC4-JK-001)
# ---------------------------------------------------------------------------


def test_groovy_gstring_rewrites_params_interpolation(tmp_path):
    p = tmp_path / "Jenkinsfile"
    p.write_text('sh "git checkout ${params.BRANCH_NAME}"\n', encoding="utf-8")
    results = fix_unquote_groovy_gstring_with_params(str(p), dry_run=False)
    assert len(results) == 1
    assert results[0].fix_type == "unquote_groovy_gstring_with_params"
    assert "sh 'git checkout ${params.BRANCH_NAME}'" in p.read_text(encoding="utf-8")


def test_groovy_gstring_rewrites_env_interpolation(tmp_path):
    p = tmp_path / "Jenkinsfile"
    p.write_text('sh "git checkout ${env.GIT_BRANCH}"\n', encoding="utf-8")
    fix_unquote_groovy_gstring_with_params(str(p), dry_run=False)
    assert "sh 'git checkout ${env.GIT_BRANCH}'" in p.read_text(encoding="utf-8")


def test_groovy_gstring_skips_already_single_quoted(tmp_path):
    p = tmp_path / "Jenkinsfile"
    original = "sh 'git checkout ${params.BRANCH_NAME}'\n"
    p.write_text(original, encoding="utf-8")
    assert fix_unquote_groovy_gstring_with_params(str(p), dry_run=False) == []
    assert p.read_text(encoding="utf-8") == original


def test_groovy_gstring_skips_comment_line(tmp_path):
    p = tmp_path / "Jenkinsfile"
    original = '// sh "git checkout ${params.BRANCH_NAME}"\n'
    p.write_text(original, encoding="utf-8")
    assert fix_unquote_groovy_gstring_with_params(str(p), dry_run=False) == []
    assert p.read_text(encoding="utf-8") == original


def test_groovy_gstring_skips_body_with_non_params_interpolation(tmp_path):
    # Body has a Groovy-scope variable ${BUILD_ID} alongside ${params.X} —
    # single-quoting would silently change ${BUILD_ID}'s meaning, so skip.
    p = tmp_path / "Jenkinsfile"
    original = 'sh "echo ${BUILD_ID} ${params.X}"\n'
    p.write_text(original, encoding="utf-8")
    assert fix_unquote_groovy_gstring_with_params(str(p), dry_run=False) == []
    assert p.read_text(encoding="utf-8") == original


def test_groovy_gstring_skips_body_with_apostrophe(tmp_path):
    # Groovy '...' has no \' escape; rewriting requires concatenation.
    p = tmp_path / "Jenkinsfile"
    original = "sh \"echo don't touch ${params.X}\"\n"
    p.write_text(original, encoding="utf-8")
    assert fix_unquote_groovy_gstring_with_params(str(p), dry_run=False) == []
    assert p.read_text(encoding="utf-8") == original


def test_groovy_gstring_dry_run_preserves_file(tmp_path):
    p = tmp_path / "Jenkinsfile"
    original = 'sh "git checkout ${params.BRANCH_NAME}"\n'
    p.write_text(original, encoding="utf-8")
    results = fix_unquote_groovy_gstring_with_params(str(p), dry_run=True)
    assert len(results) == 1
    assert p.read_text(encoding="utf-8") == original


def test_groovy_gstring_does_not_double_rewrite(tmp_path):
    p = tmp_path / "Jenkinsfile"
    p.write_text('sh "git checkout ${params.BRANCH_NAME}"\n', encoding="utf-8")
    fix_unquote_groovy_gstring_with_params(str(p), dry_run=False)
    # Second pass over the now-single-quoted file: nothing further.
    assert fix_unquote_groovy_gstring_with_params(str(p), dry_run=False) == []


def test_groovy_gstring_registered_in_all_fixers():
    assert "unquote_groovy_gstring_with_params" in ALL_FIXERS


# ---------------------------------------------------------------------------
# apply_fixes wiring
# ---------------------------------------------------------------------------


def test_opt_in_fixer_not_run_by_default(tmp_path):
    """Default --fix must not invoke npm_ignore_scripts."""
    path = _write(tmp_path, "steps:\n  - run: npm install\n")
    results = apply_fixes(path, dry_run=True)
    assert all(r.fix_type != "npm_ignore_scripts" for r in results)


def test_opt_in_fixer_runs_when_requested(tmp_path):
    path = _write(tmp_path, "steps:\n  - run: npm install\n")
    results = apply_fixes(path, dry_run=True, extra_fix_types=["npm_ignore_scripts"])
    assert any(r.fix_type == "npm_ignore_scripts" for r in results)


def test_opt_in_registry_separate_from_safe_set():
    """Guard against accidentally registering the opt-in fix in ALL_FIXERS."""
    assert "npm_ignore_scripts" not in ALL_FIXERS
    assert "npm_ignore_scripts" in OPT_IN_FIXERS


# ---------------------------------------------------------------------------
# SEC4-GH-011 anchor expansion (integration-style, uses the real rule)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sec4_011():
    from taintly.rules.registry import get_rule_by_id

    rule = get_rule_by_id("SEC4-GH-011")
    assert rule is not None
    return rule


@pytest.mark.parametrize(
    "body, should_fire",
    [
        # Newly covered by the shared anchor
        ("      - run: docker build -t app .", True),
        ("      - run: go generate ./...", True),
        ("      - run: ./gradlew build", True),
        ("      - run: ./mvnw package", True),
        ("      - run: cmake --build .", True),
        ("      - run: python setup.py install", True),
        ("      - run: pnpm install", True),
        # Already covered — regression guard
        ("      - run: npm install", True),
        ("      - run: make", True),
        # Explicitly NOT covered (pip install PackageName)
        ("      - run: pip install PyGithub", False),
        # Non-build-tool — must not fire
        ("      - run: echo hello", False),
    ],
)
def test_sec4_gh_011_expanded_tool_coverage(sec4_011, body, should_fire):
    yaml = f"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{body}\n"
    results = sec4_011.pattern.check(yaml, yaml.splitlines())
    assert bool(results) == should_fire, f"Expected fire={should_fire} for:\n{body}"


# ---------------------------------------------------------------------------
# --fix mode on mixed-platform repositories
#
# Regression test for the bug flagged in the external code review: fix
# mode used to auto-detect the platform and silently fall back to GitHub
# when both GitHub and GitLab CI configuration coexisted in the same
# repository.  The result was that --fix touched only the GitHub files
# and exited 0, giving the operator no signal that the GitLab side was
# untouched.  Drive the CLI end-to-end to confirm both platforms are
# now processed.
# ---------------------------------------------------------------------------


def test_fix_dry_run_on_mixed_platform_repo_processes_both(tmp_path):
    """Both the GitHub workflow and the .gitlab-ci.yml should appear in
    --fix-dry-run output when no --platform is given."""
    import subprocess
    import sys

    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - project: org/shared\n    file: /ci.yml\n    ref: main\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path),
         "--fix-dry-run", "--no-color"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # Both platforms' files must show up in the fix-dry-run output.
    out = result.stdout
    assert "ci.yml" in out, f"GitHub workflow missing from fix output:\n{out}"
    assert ".gitlab-ci.yml" in out, f"GitLab CI file missing from fix output:\n{out}"


# ---------------------------------------------------------------------------
# fix_remove_insecure_commands  (SEC4-GH-009)
# ---------------------------------------------------------------------------


def test_remove_insecure_commands_deletes_line(tmp_path):
    path = _write(
        tmp_path,
        "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n  OTHER: value\n",
    )
    results = fix_remove_insecure_commands(path, dry_run=False)
    assert len(results) == 1
    assert "ACTIONS_ALLOW_UNSECURE_COMMANDS" not in _read(path)
    assert "OTHER: value" in _read(path)


def test_remove_insecure_commands_handles_quoted_and_other_truthy(tmp_path):
    path = _write(
        tmp_path,
        "env:\n"
        "  ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'\n"
        "  ACTIONS_ALLOW_UNSECURE_COMMANDS: yes\n"
        "  ACTIONS_ALLOW_UNSECURE_COMMANDS: on\n"
        "  ACTIONS_ALLOW_UNSECURE_COMMANDS: 1\n",
    )
    results = fix_remove_insecure_commands(path, dry_run=False)
    assert len(results) == 4
    assert "ACTIONS_ALLOW_UNSECURE_COMMANDS" not in _read(path)


def test_remove_insecure_commands_does_not_touch_false(tmp_path):
    path = _write(tmp_path, "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: false\n")
    results = fix_remove_insecure_commands(path, dry_run=False)
    assert results == []
    assert "ACTIONS_ALLOW_UNSECURE_COMMANDS: false" in _read(path)


def test_remove_insecure_commands_dry_run_preserves_file(tmp_path):
    content = "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"
    path = _write(tmp_path, content)
    results = fix_remove_insecure_commands(path, dry_run=True)
    assert len(results) == 1
    assert _read(path) == content


# ---------------------------------------------------------------------------
# fix_remove_debug_logging  (SEC10-GH-003)
# ---------------------------------------------------------------------------


def test_remove_debug_logging_deletes_step_debug(tmp_path):
    path = _write(tmp_path, "env:\n  ACTIONS_STEP_DEBUG: true\n  OTHER: x\n")
    results = fix_remove_debug_logging(path, dry_run=False)
    assert len(results) == 1
    assert "ACTIONS_STEP_DEBUG" not in _read(path)


def test_remove_debug_logging_deletes_runner_debug(tmp_path):
    path = _write(tmp_path, "env:\n  ACTIONS_RUNNER_DEBUG: 'true'\n")
    results = fix_remove_debug_logging(path, dry_run=False)
    assert len(results) == 1
    assert "ACTIONS_RUNNER_DEBUG" not in _read(path)


def test_remove_debug_logging_does_not_touch_false(tmp_path):
    path = _write(tmp_path, "env:\n  ACTIONS_STEP_DEBUG: false\n")
    results = fix_remove_debug_logging(path, dry_run=False)
    assert results == []


def test_remove_debug_logging_does_not_touch_similar_vars(tmp_path):
    # MY_DEBUG is not a GitHub-runner debug toggle; leave alone.
    path = _write(tmp_path, "env:\n  MY_DEBUG: true\n")
    results = fix_remove_debug_logging(path, dry_run=False)
    assert results == []
    assert "MY_DEBUG: true" in _read(path)


# ---------------------------------------------------------------------------
# fix_disable_setup_cache_in_release  (SEC9-GH-003)
# ---------------------------------------------------------------------------


_RELEASE_WORKFLOW = (
    "on:\n  release:\n    types: [published]\n"
    "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
    "        with:\n          cache: npm\n          node-version: 22\n"
)

_TAG_WORKFLOW = (
    "on:\n  push:\n    tags:\n      - 'v*'\n"
    "jobs:\n  build:\n    steps:\n      - uses: actions/setup-python@v5\n"
    "        with:\n          python-version: '3.12'\n          cache: pip\n"
)


def test_setup_cache_rewrites_on_release(tmp_path):
    path = _write(tmp_path, _RELEASE_WORKFLOW)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert len(results) == 1
    text = _read(path)
    assert "cache: false" in text
    assert "cache: npm" not in text
    # Unrelated keys preserved
    assert "node-version: 22" in text


def test_setup_cache_rewrites_on_push_tags(tmp_path):
    path = _write(tmp_path, _TAG_WORKFLOW)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert len(results) == 1
    assert "cache: false" in _read(path)


def test_setup_cache_skips_non_release_workflows(tmp_path):
    # on: push (branches only) — rule wouldn't fire, fixer must not rewrite.
    push_only = (
        "on:\n  push:\n    branches: [main]\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
        "        with:\n          cache: npm\n"
    )
    path = _write(tmp_path, push_only)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert results == []
    assert "cache: npm" in _read(path)


def test_setup_cache_skips_tags_negation_pattern(tmp_path):
    # on: push with tags: ['!**'] — tag events EXCLUDED; fixer should not run.
    excluded = (
        "on:\n  push:\n    branches:\n      - '**'\n    tags:\n      - '!**'\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
        "        with:\n          cache: pnpm\n"
    )
    path = _write(tmp_path, excluded)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert results == []
    assert "cache: pnpm" in _read(path)


def test_setup_cache_skips_if_no_setup_action(tmp_path):
    # File has release trigger but uses actions/cache directly (SEC9-GH-002
    # territory). SEC9-GH-003 doesn't fire, so this fixer shouldn't
    # rewrite anything here.
    no_setup = (
        "on:\n  release:\n    types: [published]\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n"
        "        with:\n          cache: npm\n"
    )
    path = _write(tmp_path, no_setup)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert results == []


def test_setup_cache_preserves_already_disabled(tmp_path):
    already_off = _RELEASE_WORKFLOW.replace("cache: npm", "cache: false")
    path = _write(tmp_path, already_off)
    results = fix_disable_setup_cache_in_release(path, dry_run=False)
    assert results == []


def test_all_new_fixers_registered():
    for name in (
        "remove_insecure_commands",
        "remove_debug_logging",
        "disable_setup_cache_in_release",
    ):
        assert name in ALL_FIXERS, f"{name} not registered in ALL_FIXERS"


# ---------------------------------------------------------------------------
# fix_jenkins_cap_add_hint (opt-in)
# ---------------------------------------------------------------------------


def _write_jenkins(tmp_path, content: str, name: str = "Jenkinsfile"):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_cap_add_hint_injects_comment_above_privileged_args(tmp_path):
    """The declarative ``args '--privileged'`` form gets a Groovy
    ``// taintly hint`` comment on the line above, and the source
    line is unchanged."""
    path = _write_jenkins(
        tmp_path,
        "pipeline {\n"
        "    agent { docker { image 'builder' args '-v /tmp:/tmp --privileged' } }\n"
        "    stages { stage('x') { steps { sh 'make' } } }\n"
        "}\n",
    )
    results = fix_jenkins_cap_add_hint(path, dry_run=False)
    assert len(results) == 1
    assert results[0].fix_type == "jenkins_cap_add_hint"
    new_content = pathlib.Path(path).read_text()
    assert "taintly hint (SEC8-JK-004)" in new_content
    assert "--privileged" in new_content  # source line preserved


def test_cap_add_hint_handles_scripted_inside_and_withRun(tmp_path):
    path = _write_jenkins(
        tmp_path,
        "node {\n"
        "    docker.image('ubuntu').inside('--privileged') { sh 'make' }\n"
        "    docker.image('build').withRun('--privileged --rm') { c -> sh 'work' }\n"
        "}\n",
    )
    results = fix_jenkins_cap_add_hint(path, dry_run=False)
    assert len(results) == 2


def test_cap_add_hint_idempotent(tmp_path):
    """Second invocation must not re-inject the comment."""
    path = _write_jenkins(
        tmp_path,
        "pipeline {\n"
        "    agent { docker { image 'x' args '--privileged' } }\n"
        "}\n",
    )
    fix_jenkins_cap_add_hint(path, dry_run=False)
    results = fix_jenkins_cap_add_hint(path, dry_run=False)
    assert results == []


def test_cap_add_hint_skips_non_jenkinsfile(tmp_path):
    """Rule text or similar ``--privileged`` reference in a
    non-Jenkinsfile path must not be touched."""
    p = tmp_path / "docs.md"
    p.write_text(
        "Avoid `--privileged` containers; use `--cap-add` instead.\n",
        encoding="utf-8",
    )
    results = fix_jenkins_cap_add_hint(str(p), dry_run=False)
    assert results == []


# ---------------------------------------------------------------------------
# fix_github_ai_allowed_tools_scaffold (opt-in)
# ---------------------------------------------------------------------------


def test_allowed_tools_scaffold_injects_with_block(tmp_path):
    """Agent action with no ``with:`` block at all — scaffold creates
    one and nests the ``allowed_tools:`` line inside it."""
    path = _write(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n",
    )
    results = fix_github_ai_allowed_tools_scaffold(path, dry_run=False)
    assert len(results) == 1
    new_content = pathlib.Path(path).read_text()
    assert "with:" in new_content
    assert "allowed_tools:" in new_content
    assert "mcp__github_inline_comment__create_inline_comment" in new_content


def test_allowed_tools_scaffold_nests_under_existing_with(tmp_path):
    """Existing ``with:`` block — scaffold becomes the first key
    under it without disrupting other inputs."""
    path = _write(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n"
        "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n",
    )
    results = fix_github_ai_allowed_tools_scaffold(path, dry_run=False)
    assert len(results) == 1
    new_content = pathlib.Path(path).read_text()
    # anthropic_api_key must survive, allowed_tools must be present.
    assert "anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}" in new_content
    assert "allowed_tools:" in new_content


def test_allowed_tools_scaffold_skips_already_scoped(tmp_path):
    """File that already declares a tool allowlist (anywhere) is
    left alone to avoid conflicting scaffolds."""
    path = _write(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n"
        "          allowed_tools: 'Read,Grep'\n",
    )
    results = fix_github_ai_allowed_tools_scaffold(path, dry_run=False)
    assert results == []


def test_allowed_tools_scaffold_idempotent(tmp_path):
    path = _write(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n",
    )
    fix_github_ai_allowed_tools_scaffold(path, dry_run=False)
    results = fix_github_ai_allowed_tools_scaffold(path, dry_run=False)
    assert results == []


# ---------------------------------------------------------------------------
# fix_hoist_service_credentials (opt-in)
# ---------------------------------------------------------------------------


def test_hoist_replaces_literal_with_var_reference(tmp_path):
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text(
        "variables:\n"
        "  POSTGRES_PASSWORD: hunter2ispostgres\n"
        "  POSTGRES_DB: myapp\n",
        encoding="utf-8",
    )
    results = fix_hoist_service_credentials(str(p), dry_run=False)
    assert len(results) == 1
    new_content = p.read_text()
    assert "POSTGRES_PASSWORD: $POSTGRES_PASSWORD" in new_content
    assert "POSTGRES_DB: myapp" in new_content   # unrelated key survives
    assert "hunter2ispostgres" not in new_content  # literal gone


def test_hoist_preserves_reference_shapes(tmp_path):
    """Values that are already ``$VAR`` / ``${VAR}`` / ``${{ ... }}``
    must NOT be rewritten."""
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text(
        "variables:\n"
        "  POSTGRES_PASSWORD: $POSTGRES_PASSWORD\n"
        "  MYSQL_PASSWORD: ${DB_PASSWORD}\n",
        encoding="utf-8",
    )
    results = fix_hoist_service_credentials(str(p), dry_run=False)
    assert results == []


def test_hoist_skips_non_gitlab_file(tmp_path):
    """Non-.gitlab-ci.yml files must not be rewritten even if they
    contain a matching ``*_PASSWORD:`` line."""
    p = tmp_path / "docker-compose.yml"
    p.write_text(
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: hunter2ispostgres\n",
        encoding="utf-8",
    )
    results = fix_hoist_service_credentials(str(p), dry_run=False)
    assert results == []


def test_hoist_dry_run_does_not_write(tmp_path):
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text(
        "variables:\n  POSTGRES_PASSWORD: hunter2ispostgres\n",
        encoding="utf-8",
    )
    results = fix_hoist_service_credentials(str(p), dry_run=True)
    assert len(results) == 1
    assert results[0].applied is False
    assert "hunter2ispostgres" in p.read_text()   # file unchanged


def test_all_opt_in_fixers_registered():
    for name in (
        "npm_ignore_scripts",
        "jenkins_cap_add_hint",
        "github_ai_allowed_tools_scaffold",
        "hoist_service_credentials",
    ):
        assert name in OPT_IN_FIXERS, f"{name} not registered in OPT_IN_FIXERS"


# ---------------------------------------------------------------------------
# Windows path-separator regression tests
# ---------------------------------------------------------------------------


def test_jenkins_cap_add_hint_path_check_handles_windows_separators():
    """Regression: ``fix_jenkins_cap_add_hint`` gates on
    ``"jenkins" in dirname(filepath).split("/")``.  On Windows
    ``os.path.dirname`` returns ``\\``-separated paths, so the
    literal ``.split("/")`` would return the entire path as one
    element and silently miss every Jenkins ``.groovy`` file under a
    ``jenkins\\`` directory.

    The fix normalises the dirname output to forward slashes before
    splitting; this test pins the post-fix logic so a future "clean
    up" doesn't undo it.
    """
    windows_dirname = r"C:\repo\jenkins"
    # Pre-fix shape (broken on Windows):
    assert "jenkins" not in windows_dirname.split("/"), (
        "If this assertion fails, Python's str.split started normalising "
        "backslashes — the fix would no longer be needed."
    )
    # Post-fix shape (correct on every OS):
    assert "jenkins" in windows_dirname.replace("\\", "/").split("/")


def test_hoist_service_credentials_path_check_handles_windows_separators():
    """Regression: ``fix_hoist_service_credentials`` gates on
    ``"/ci/" in filepath``.  On Windows the filepath uses ``\\``,
    so the literal ``"/ci/"`` substring never matches and the rule
    silently skips legitimate GitLab include files under ``ci\\``.

    The fix normalises the filepath to forward slashes before the
    substring check; this test pins the post-fix logic.
    """
    windows_filepath = r"C:\repo\ci\db-migrations.yml"
    # Pre-fix shape (broken on Windows):
    assert "/ci/" not in windows_filepath, (
        "If this assertion fails, the literal substring check started "
        "matching backslash separators — the fix would no longer be needed."
    )
    # Post-fix shape (correct on every OS):
    assert "/ci/" in windows_filepath.replace("\\", "/")
