import pytest

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.codebuild.kubectl_tls import KubectlTLSConfigurationPattern
from taintly.rules.registry import load_rules_for_platform


def _buildspec(command: str, *, setup: str = "") -> str:
    return f"version: 0.2\nphases:\n  post_build:\n    commands:\n      - {command}\n{setup}"


def _check(text: str):
    return KubectlTLSConfigurationPattern().check(text, text.splitlines())


@pytest.mark.parametrize("value", ["", "=true", "=True", "=1"])
def test_literal_tls_request_belongs_to_the_phase_command(value):
    text = _buildspec(
        f'kubectl config set-cluster prod --server="$KUBE_URL" --insecure-skip-tls-verify{value}'
    )
    assert _check(text) == [(5, text.splitlines()[4].strip())]


@pytest.mark.parametrize(
    "command",
    [
        "kubectl config set-cluster prod --insecure-skip-tls-verify=false",
        "kubectl config set-cluster prod --server=--insecure-skip-tls-verify=true",
        "kubectl config set-cluster prod --insecure-skip-tls-verify=true --help",
        "printf '%s' 'kubectl config set-cluster prod --insecure-skip-tls-verify=true'",
    ],
)
def test_no_true_request_for_false_help_or_data(command):
    result = _check(_buildspec(command))
    assert not result and not isinstance(result, IncompletePatternMatches)


@pytest.mark.parametrize(
    "argument",
    [
        '--insecure-skip-tls-verify="$BYPASS"',
        "--insecure-skip-tls-verify=TrUe",
        "--insecure-skip-tls-verify false",
        "--insecure-skip-tls-verify=true --insecure-skip-tls-verify=false",
        "--insecure-skip-tls-verify=true --certificate-authority=ca.pem",
        "--insecure-skip-tls-verify=true --server=$URL",
        '--insecure-skip-tls-verify=true --server="$URL"*',
        "--insecure-skip-tls-verify=true && echo done",
    ],
)
def test_dynamic_argv_or_native_option_conflict_is_unresolved(argument):
    result = _check(_buildspec(f"kubectl config set-cluster prod {argument}"))
    assert not result and isinstance(result, IncompletePatternMatches)


@pytest.mark.parametrize("setup", ["alias kubectl=echo", 'kube"ctl"() { echo data; }'])
def test_earlier_phase_rebinding_is_not_attributed_to_native_kubectl(setup):
    text = _buildspec(
        "kubectl config set-cluster prod --insecure-skip-tls-verify=true",
        setup=f"  install:\n    commands:\n      - {setup}\n",
    )
    result = _check(text)
    assert not result and isinstance(result, IncompletePatternMatches)


def test_a_nested_sequence_is_not_a_direct_phase_command():
    result = _check(_buildspec("- kubectl config set-cluster prod --insecure-skip-tls-verify=true"))
    assert not result and isinstance(result, IncompletePatternMatches)


def test_a_plain_scalar_continuation_has_unresolved_physical_ownership():
    text = _buildspec("kubectl config set-cluster prod")
    text += "        --insecure-skip-tls-verify=true\n"
    result = _check(text)
    assert not result and isinstance(result, IncompletePatternMatches)


def test_actual_report_keeps_the_review_and_earlier_context_gap(tmp_path):
    text = _buildspec(
        'kubectl config set-cluster prod --server="$KUBE_URL" --insecure-skip-tls-verify=true',
        setup="  pre_build:\n    commands:\n      - $(aws ecr get-login)\n",
    )
    (tmp_path / "buildspec.yml").write_text(text, encoding="utf8")
    rules = load_rules_for_platform(Platform.CODEBUILD)
    report = scan_repo(str(tmp_path), rules, platform=Platform.CODEBUILD)[0]
    (review,) = [finding for finding in report.findings if finding.rule_id == "SEC6-CB-005"]
    assert review.line == 5 and review.review_needed and review.severity.value == "MEDIUM"
    assert any("phases.post_build.commands[0]" in note for note in review.context_notes)
    assert any("kubeconfig write" in note for note in review.context_notes)
    assert any(f.rule_id == "ENGINE-ERR" and "SEC6-CB-005" in f.title for f in report.findings)
