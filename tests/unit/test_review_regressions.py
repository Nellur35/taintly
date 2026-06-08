"""Regression tests for second-pass review findings."""

from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.models import Platform
from taintly.parsers.structural.tokenizer import TokenizerError, tokenize
from taintly.platform import github_archived_check, gitlab_archived_check
from taintly.rules.registry import load_all_rules


@pytest.fixture(scope="module")
def all_rules():
    return load_all_rules()


@pytest.fixture(scope="module")
def github_rules(all_rules):
    return [r for r in all_rules if r.platform == Platform.GITHUB]


@pytest.fixture(scope="module")
def gitlab_rules(all_rules):
    return [r for r in all_rules if r.platform == Platform.GITLAB]


@pytest.fixture(scope="module")
def jenkins_rules(all_rules):
    return [r for r in all_rules if r.platform == Platform.JENKINS]


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_sec2_gh_002_accepts_quoted_workflow_call_only_trigger(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "reusable.yml",
        '"on": workflow_call\n'
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC2-GH-002" not in _rule_ids(findings)


def test_sec2_gh_002_accepts_on_line_comment_before_workflow_call(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "reusable.yml",
        "on: # reusable entry point\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      name:\n"
        "        required: false\n"
        "        type: string\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC2-GH-002" not in _rule_ids(findings)


def test_sec2_gh_005_counts_quoted_job_keys(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: push\n"
        "permissions:\n"
        "  contents: write\n"
        "jobs:\n"
        '  "job-name":\n'
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo one\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo two\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC2-GH-005" in _rule_ids(findings)


def test_sec2_gh_005_skips_quoted_workflow_call_only_reusable(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "reusable.yml",
        '"on": workflow_call\n'
        "permissions:\n"
        "  contents: write\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo b\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC2-GH-005" not in _rule_ids(findings)


def test_unclosed_gitlab_reference_tag_is_rejected():
    with pytest.raises(TokenizerError):
        list(tokenize("extends:\n  - !reference [.foo\nnext: value\n"))


def test_sec4_gh_005_does_not_treat_git_config_only_as_credential_use(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: push\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: git config user.email bot@example.com\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC4-GH-005" not in _rule_ids(findings)


def test_sec4_gh_005_detects_git_fetch_https_consumer(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: push\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: git fetch https://github.com/example/repo refs/heads/main\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC4-GH-005" in _rule_ids(findings)


def test_sec4_gh_005_ignores_comments_and_heredoc_literals(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: push\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo ok # git push origin main\n"
        "      - run: |\n"
        "          cat <<'EOF' > script.sh\n"
        "          git push origin main\n"
        "          EOF\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC4-GH-005" not in _rule_ids(findings)


def test_dependabot_scan_does_not_run_workflow_permissions_rules(tmp_path, all_rules):
    _write(
        tmp_path / ".github" / "dependabot.yml",
        "version: 2\n"
        "updates:\n"
        "  - package-ecosystem: npm\n"
        "    directory: /\n"
        "    schedule:\n"
        "      interval: weekly\n",
    )
    reports = scan_repo(str(tmp_path), all_rules)
    findings = [f for report in reports for f in report.findings]
    assert "SEC8-GH-005" in _rule_ids(findings)
    assert "SEC2-GH-002" not in _rule_ids(findings)


def test_explicit_dependabot_file_scan_keeps_dependabot_rules(tmp_path, all_rules):
    dep = _write(
        tmp_path / ".github" / "dependabot.yml",
        "version: 2\n"
        "updates:\n"
        "  - package-ecosystem: npm\n"
        "    directory: /\n"
        "    schedule:\n"
        "      interval: weekly\n",
    )
    reports = scan_repo(str(dep), all_rules)
    findings = [f for report in reports for f in report.findings]
    assert "SEC8-GH-005" in _rule_ids(findings)
    assert "SEC2-GH-002" not in _rule_ids(findings)


def test_sec8_gh_005_is_per_dependabot_update_spec(tmp_path, all_rules):
    _write(
        tmp_path / ".github" / "dependabot.yml",
        "version: 2\n"
        "updates:\n"
        "  - package-ecosystem: npm\n"
        "    directory: /\n"
        "    schedule:\n"
        "      interval: weekly\n"
        "    cooldown:\n"
        "      default-days: 5\n"
        "  - package-ecosystem: pip\n"
        "    directory: /py\n"
        "    schedule:\n"
        "      interval: weekly\n",
    )
    reports = scan_repo(str(tmp_path), all_rules)
    fired = [f for report in reports for f in report.findings if f.rule_id == "SEC8-GH-005"]
    assert len(fired) == 1
    assert fired[0].snippet == "- package-ecosystem: pip"


# SEC4-GH-023 was an exact duplicate of SEC4-GH-021 (same pattern, identical
# firing) and was removed; these regressions now assert the surviving rule.
def test_sec4_gh_021_detects_bracketed_step_output_in_run(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: meta\n"
        "        run: echo 'title=x' >> \"$GITHUB_OUTPUT\"\n"
        "      - run: echo ${{ steps.meta.outputs['title-with-dash'] }}\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC4-GH-021" in _rule_ids(findings)


def test_sec4_gh_021_does_not_fire_on_non_shell_action_metadata_inputs(tmp_path, github_rules):
    wf = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: meta\n"
        "        run: echo 'path=dist' >> \"$GITHUB_OUTPUT\"\n"
        "      - uses: actions/upload-artifact@v4\n"
        "        with:\n"
        "          path: dist/${{ steps.meta.outputs.path }}\n"
        "      - uses: softprops/action-gh-release@v2\n"
        "        with:\n"
        "          description: release ${{ steps.meta.outputs.path }}\n",
    )
    findings = scan_file(str(wf), github_rules)
    assert "SEC4-GH-021" not in _rule_ids(findings)


def test_github_archived_check_404_is_indeterminate(monkeypatch):
    from taintly.platform.github_client import GitHubClient

    def return_not_found(*args, **kwargs):
        return None

    github_archived_check.reset_cache()
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(GitHubClient, "_request", return_not_found)
    assert github_archived_check.is_archived("missing", "repo") is None


def test_gitlab_archived_check_404_is_indeterminate(monkeypatch):
    gitlab_archived_check.reset_cache()
    monkeypatch.setenv("GITLAB_TOKEN", "token")

    def raise_404(*args, **kwargs):
        raise urllib.error.HTTPError(
            url="https://gitlab.com/api/v4/projects/missing",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_404)
    assert gitlab_archived_check.is_archived("missing/repo") is None


# SEC4-GL-009 was an exact duplicate of SEC4-GL-008 (same DotenvReportPattern,
# identical firing) and was removed; this regression now asserts the survivor.
def test_sec4_gl_008_anchors_on_dotenv_report_only(tmp_path, gitlab_rules):
    ci = _write(
        tmp_path / ".gitlab-ci.yml",
        "test:\n"
        "  script: pytest\n"
        "  artifacts:\n"
        "    reports:\n"
        "      junit: junit.xml\n"
        "build:\n"
        "  script: echo X=value > out.env\n"
        "  artifacts:\n"
        "    reports:\n"
        "      dotenv: out.env\n",
    )
    findings = scan_file(str(ci), gitlab_rules)
    fired = [f for f in findings if f.rule_id == "SEC4-GL-008"]
    assert len(fired) == 1
    assert fired[0].snippet == "dotenv: out.env"


def test_sec4_jk_008_allows_common_jenkins_builtin_env_vars(tmp_path, jenkins_rules):
    jf = _write(
        tmp_path / "Jenkinsfile",
        'pipeline { stages { stage("x") { steps {\n'
        '  sh "echo ${env.STAGE_NAME}"\n'
        '  sh "echo ${env.RUN_DISPLAY_URL}"\n'
        '  sh "echo ${env.BUILD_DISPLAY_NAME}"\n'
        "} } } }\n",
    )
    findings = scan_file(str(jf), jenkins_rules)
    assert "SEC4-JK-008" not in _rule_ids(findings)


@pytest.mark.parametrize("step", ["bat", "powershell"])
def test_sec4_jk_008_detects_windows_shell_steps(tmp_path, jenkins_rules, step):
    jf = _write(
        tmp_path / "Jenkinsfile",
        f'pipeline {{ stages {{ stage("x") {{ steps {{ {step} "echo ${{env.USER_INPUT}}" }} }} }} }}\n',
    )
    findings = scan_file(str(jf), jenkins_rules)
    assert "SEC4-JK-008" in _rule_ids(findings)
