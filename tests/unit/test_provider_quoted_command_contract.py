"""Contract for quoted YAML command scalars reaching provider shell checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.models import IncompletePatternMatches
from taintly.rules.codebuild.sec_codebuild import _SecondEvaluationWebhookRefPattern
from taintly.rules.gitlab.sec1_sec4_sec6_sec7_sec9 import _ReevaluatedCiVariablePattern


def _gitlab(style: str, command: str) -> str:
    scalar = {
        "plain": command,
        "single": "'" + command.replace("'", "''") + "'",
        "double": '"' + command.replace("\\", "\\\\").replace('"', '\\"') + '"',
    }[style]
    return f"deploy_job:\n  script:\n    - {scalar}\n"


def _codebuild(style: str, command: str) -> str:
    scalar = {
        "plain": command,
        "single": "'" + command.replace("'", "''") + "'",
        "double": '"' + command.replace("\\", "\\\\").replace('"', '\\"') + '"',
    }[style]
    return f"phases:\n  build:\n    commands:\n      - {scalar}\n"


@pytest.mark.parametrize("style", ["plain", "single", "double"])
def test_gitlab_detects_reevaluation_across_yaml_scalar_styles(style: str) -> None:
    command = 'eval "$CI_MERGE_REQUEST_TITLE"'
    source = _gitlab(style, command)

    result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())

    assert result == [(3, source.splitlines()[2].strip())]


@pytest.mark.parametrize("style", ["plain", "single", "double"])
def test_codebuild_detects_reevaluation_across_yaml_scalar_styles(style: str) -> None:
    command = 'eval "deploy --ref $CODEBUILD_WEBHOOK_HEAD_REF"'
    source = _codebuild(style, command)

    result = _SecondEvaluationWebhookRefPattern().check(source, source.splitlines())

    expected_snippet = source.splitlines()[3].strip()
    assert result == [(4, expected_snippet)]


@pytest.mark.parametrize("style", ["single", "double"])
def test_quoted_shell_data_stays_data_after_yaml_decode(style: str) -> None:
    gitlab = _gitlab(style, 'deploy "$CI_MERGE_REQUEST_TITLE"')
    codebuild = _codebuild(style, 'deploy --ref "$CODEBUILD_WEBHOOK_HEAD_REF"')

    assert _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines()) == []
    assert _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines()) == []


def test_double_quoted_yaml_escapes_reach_shell_as_decoded_data() -> None:
    gitlab = 'deploy_job:\n  script:\n    - "deploy \\"$CI_MERGE_REQUEST_TITLE\\""\n'
    codebuild = (
        "phases:\n  build:\n    commands:\n"
        '      - "deploy --ref \\"$CODEBUILD_WEBHOOK_HEAD_REF\\""\n'
    )

    assert _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines()) == []
    assert _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines()) == []

    gitlab_backslash = _gitlab("double", r"deploy \$CI_MERGE_REQUEST_TITLE")
    codebuild_backslash = _codebuild("double", r"deploy --ref \$CODEBUILD_WEBHOOK_HEAD_REF")
    assert (
        _ReevaluatedCiVariablePattern().check(gitlab_backslash, gitlab_backslash.splitlines()) == []
    )
    assert (
        _SecondEvaluationWebhookRefPattern().check(
            codebuild_backslash, codebuild_backslash.splitlines()
        )
        == []
    )


def test_non_command_fields_and_alias_only_lines_are_not_promoted_to_commands() -> None:
    gitlab = (
        "saved_command: &saved_command 'eval \"$CI_MERGE_REQUEST_TITLE\"'\n"
        "workflow:\n  script:\n    - 'eval \"$CI_MERGE_REQUEST_TITLE\"'\n"
        "job:\n  script:\n    - *saved_command\n"
    )
    codebuild = (
        "saved_command: &saved_command 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n"
        "env:\n  variables:\n    COMMAND: 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n"
        "phases:\n  build:\n    commands:\n      - *saved_command\n"
    )

    gitlab_result = _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines())
    codebuild_result = _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines())
    assert isinstance(gitlab_result, IncompletePatternMatches)
    assert isinstance(codebuild_result, IncompletePatternMatches)
    assert len(gitlab_result) == 0
    assert len(codebuild_result) == 0


def test_duplicate_command_owner_is_not_used_for_scalar_normalization() -> None:
    gitlab = (
        "job:\n  script:\n    - 'eval \"$CI_MERGE_REQUEST_TITLE\"'\n"
        "  script:\n    - 'eval \"$CI_MERGE_REQUEST_DESCRIPTION\"'\n"
    )
    codebuild = (
        "phases:\n  build:\n    commands:\n"
        "      - 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n"
        "    commands:\n      - 'eval \"$CODEBUILD_SOURCE_VERSION\"'\n"
    )

    gitlab_result = _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines())
    codebuild_result = _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines())
    assert isinstance(gitlab_result, IncompletePatternMatches)
    assert isinstance(codebuild_result, IncompletePatternMatches)
    assert len(gitlab_result) == 0
    assert len(codebuild_result) == 0


def test_gitlab_bare_shell_self_test_and_quoted_heredoc_behavior_remain_unchanged() -> None:
    bare = 'eval "$CI_COMMIT_MESSAGE"'
    assert _ReevaluatedCiVariablePattern().check(bare, [bare]) == [(1, bare)]

    heredoc = (
        "job:\n  script:\n    - |\n"
        "      cat <<'EOF'\n"
        '      eval "$CI_COMMIT_MESSAGE"\n'
        "      EOF\n"
    )
    assert _ReevaluatedCiVariablePattern().check(heredoc, heredoc.splitlines()) == []


def test_unsupported_yaml_escape_is_reported_as_incomplete() -> None:
    gitlab = 'job:\n  script:\n    - "eval $CI_MERGE_REQUEST_TITLE\\q"\n'
    codebuild = 'phases:\n  build:\n    commands:\n      - "eval $CODEBUILD_WEBHOOK_HEAD_REF\\q"\n'

    gitlab_result = _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines())
    codebuild_result = _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines())
    assert isinstance(gitlab_result, IncompletePatternMatches)
    assert isinstance(codebuild_result, IncompletePatternMatches)
    assert "unsupported" in gitlab_result.reason
    assert "unsupported" in codebuild_result.reason


@pytest.mark.parametrize(
    "source",
    [
        "job:\n  script:\n    - 'eval \"$CI_MERGE_REQUEST_TITLE\"'\n  script: []\n",
        "job:\n  script:\n    - 'eval \"$CI_MERGE_REQUEST_TITLE\"'\njob: {}\n",
    ],
)
def test_duplicate_empty_gitlab_owner_reports_incomplete(source: str) -> None:
    result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())

    assert isinstance(result, IncompletePatternMatches)
    assert len(result) == 0
    assert "ambiguous" in result.reason


@pytest.mark.parametrize(
    "source",
    [
        "phases:\n  build:\n    commands:\n"
        "      - 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n    commands: []\n",
        "phases:\n  build:\n    commands:\n"
        "      - 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n  build: {}\n",
        "phases:\n  build:\n    commands:\n"
        "      - 'eval \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\nphases: {}\n",
    ],
)
def test_duplicate_empty_codebuild_owner_reports_incomplete(source: str) -> None:
    result = _SecondEvaluationWebhookRefPattern().check(source, source.splitlines())

    assert isinstance(result, IncompletePatternMatches)
    assert len(result) == 0
    assert "ambiguous" in result.reason


@pytest.mark.parametrize("escape", [r"\u00a0", r"\v", r"\f", r"\N", r"\_", r"\L", r"\P", r"\x85"])
def test_non_shell_unicode_whitespace_is_incomplete_not_a_token_boundary(escape: str) -> None:
    gitlab = 'job:\n  script:\n    - "eval' + escape + '\\"$CI_MERGE_REQUEST_TITLE\\""\n'
    codebuild = (
        'phases:\n  build:\n    commands:\n      - "eval'
        + escape
        + '\\"deploy --ref $CODEBUILD_WEBHOOK_HEAD_REF\\""\n'
    )

    gitlab_result = _ReevaluatedCiVariablePattern().check(gitlab, gitlab.splitlines())
    codebuild_result = _SecondEvaluationWebhookRefPattern().check(codebuild, codebuild.splitlines())
    assert isinstance(gitlab_result, IncompletePatternMatches)
    assert isinstance(codebuild_result, IncompletePatternMatches)
    assert len(gitlab_result) == 0
    assert len(codebuild_result) == 0
    assert "unsupported" in gitlab_result.reason
    assert "unsupported" in codebuild_result.reason


def test_gitlab_inline_script_scalar_remains_a_script_command() -> None:
    source = "job:\n  script: 'eval \"$CI_MERGE_REQUEST_TITLE\"'\n"

    result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())

    assert result == [(2, source.splitlines()[1].strip())]


def test_gitlab_safe_single_item_flow_sequence_is_not_incomplete() -> None:
    source = 'job:\n  script: ["make build"]\n'

    result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())

    assert not isinstance(result, IncompletePatternMatches)
    assert result == []


def test_gitlab_existing_safe_inline_script_sequence_is_not_incomplete() -> None:
    fixture = (
        Path(__file__).parents[1]
        / "fixtures"
        / "gitlab"
        / "safe"
        / "negative_corpus"
        / "sec9_gl_001_artifacts_access_none_and_maintainer.yml"
    )
    source = fixture.read_text(encoding="utf-8")

    result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())

    assert not isinstance(result, IncompletePatternMatches)
    assert result == []


@pytest.mark.parametrize(
    "relative_path",
    [
        "negative_corpus/safe_lotp/jenkinsio_doc_comments.Jenkinsfile",
        "realistic/java_library_ci.Jenkinsfile",
        "realistic/plugin_ci_build.Jenkinsfile",
        "realistic/web_app_deploy.Jenkinsfile",
    ],
)
def test_non_provider_groovy_fixtures_do_not_get_yaml_coverage_errors(
    relative_path: str,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "jenkins" / relative_path
    source = fixture.read_text(encoding="utf-8")

    gitlab_result = _ReevaluatedCiVariablePattern().check(source, source.splitlines())
    codebuild_result = _SecondEvaluationWebhookRefPattern().check(source, source.splitlines())

    assert not isinstance(gitlab_result, IncompletePatternMatches)
    assert not isinstance(codebuild_result, IncompletePatternMatches)
    assert gitlab_result == []
    assert codebuild_result == []
