import pytest

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.gitlab.curl_tls import GitLabCurlShortTLSPattern


def check(source):
    return GitLabCurlShortTLSPattern().check(source, source.splitlines())


@pytest.mark.parametrize(
    "command",
    [
        "curl -k https://example.invalid/status",
        "curl -skS https://example.invalid/status",
        "curl '-k' https://example.invalid/status",
        "curl -k -- https://example.invalid/status",
    ],
)
def test_first_direct_command_owns_the_option(command):
    matches = check(f"deploy:\n  script:\n    - {command}\n")
    assert matches == [(3, f"- {command}")]
    assert not isinstance(matches, IncompletePatternMatches)


@pytest.mark.parametrize(
    "command",
    [
        "echo 'curl -k https://example.invalid/status'",
        "echo '$(curl -k https://example.invalid/status)'",
        "curl -H '-k' https://example.invalid/status",
        "curl -k --no-insecure https://example.invalid/status",
        "curl -k --help https://example.invalid/status",
        "curl -k http://example.invalid/status",
        "curl https://example.invalid/status -o file-keyring",
    ],
)
def test_text_data_and_disabled_options_have_no_bypass_claim(command):
    matches = check(f"deploy:\n  script:\n    - {command}\n")
    assert matches == []
    assert not isinstance(matches, IncompletePatternMatches)


@pytest.mark.parametrize(
    "command",
    [
        "curl $FLAGS -k https://example.invalid/status",
        "curl -u $CREDENTIALS -H '-k' https://example.invalid/status",
        "curl -k $FLAGS --no-insecure https://example.invalid/status",
        "curl -k https://example.invalid/status --next",
        "curl -k https://example.invalid/status >output",
        "test -n \"$HOST\" && curl -k https://example.invalid/status",
    ],
)
def test_uncertain_argv_or_shell_boundary_does_not_prove_the_short_option(command):
    matches = check(f"deploy:\n  script:\n    - {command}\n")
    assert isinstance(matches, IncompletePatternMatches)
    assert matches == []


def test_script_does_not_borrow_native_dispatch_across_a_prior_setup():
    source = (
        "deploy:\n  before_script:\n    - alias curl=custom\n"
        "  script:\n    - curl -k https://example.invalid/status\n"
        "  after_script:\n    - curl -k https://example.invalid/status\n"
    )
    matches = check(source)
    assert isinstance(matches, IncompletePatternMatches)
    assert [line for line, _ in matches] == [7]
    assert "script, line 5: effective owner" in matches.reason


def test_folded_after_script_reports_the_owner_and_unresolved_final_arguments(
    tmp_path, gitlab_rules
):
    source = (
        "deploy:\n  script: echo done\n  after_script:\n    - >-\n"
        "      curl -sk\n"
        "      https://$HOST/status -u\n"
        "      $CREDENTIALS\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text(source, encoding="utf-8")
    report = scan_repo(str(tmp_path), gitlab_rules, platform=Platform.GITLAB)[0]
    [finding] = [f for f in report.findings if f.rule_id == "SEC6-GL-012"]
    assert finding.line == 5 and finding.review_needed and finding.severity.value == "MEDIUM"
    assert any("job 'deploy', after_script, command at line 5" in n for n in finding.context_notes)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "SEC6-GL-012" in f.title
        and "final curl arguments are unresolved" in f.description
        for f in report.findings
    )
