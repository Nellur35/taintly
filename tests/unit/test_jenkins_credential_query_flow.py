"""Authored semantic contrasts for a bound credential in a curl URL query."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.reporters.json_report import format_json
from taintly.rules._secret_network_shell import _physical_source
from taintly.rules.jenkins.credential_query_flow import JenkinsCredentialQueryPattern
from taintly.rules.registry import load_rules_for_platform


def _source(shell: str, *, variable: str = "TOKEN", prefix: str = "") -> str:
    return (
        "node {\n"
        + prefix
        + f"  withCredentials([string(credentialsId: 'id', variable: '{variable}')]) {{\n"
        + f"    sh {shell}\n"
        + "  }\n}\n"
    )


def _scan(tmp_path: Path, source: str, *, mixed_endings: bool = False):
    path = tmp_path / "Jenkinsfile"
    data = source.encode()
    if mixed_endings:
        data = data.replace(b"\n", b"\r\n", 2)
    path.write_bytes(data)
    return scan_file(str(path), load_rules_for_platform(Platform.JENKINS))


def _selected(findings):
    return [finding for finding in findings if finding.rule_id == "SEC6-JK-013"]


def test_direct_bound_query_through_product_boundary(tmp_path: Path) -> None:
    source = _source("'''curl https://example.test/status?access_token=$TOKEN'''")
    selected = _selected(_scan(tmp_path, source))
    assert len(selected) == 1
    assert selected[0].review_needed
    assert "withCredentials binding TOKEN" in " ".join(selected[0].context_notes)
    assert "delivery" in " ".join(selected[0].context_notes)


def test_json_report_preserves_path(tmp_path: Path) -> None:
    source = _source("'''curl https://example.test/status?access_token=$TOKEN'''")
    (tmp_path / "Jenkinsfile").write_text(source, encoding="utf8")
    report = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.JENKINS), platform=Platform.JENKINS
    )[0]
    output = json.loads(format_json(report))
    selected = [finding for finding in output["findings"] if finding["rule_id"] == "SEC6-JK-013"]
    assert len(selected) == 1
    assert selected[0]["review_needed"]
    assert "binding TOKEN" in " ".join(selected[0]["context_notes"])


def test_mixed_line_endings_retain_exact_source_identity(tmp_path: Path) -> None:
    source = _source('"curl https://example.test/status?access_token=$TOKEN"')
    selected = _selected(_scan(tmp_path, source, mixed_endings=True))
    assert len(selected) == 1
    assert "Source SHA256" in " ".join(selected[0].context_notes)


def test_exact_raw_source_form_remains_accepted(tmp_path: Path) -> None:
    path = tmp_path / "Jenkinsfile"
    raw = b"sh 'echo ready'\r\n"
    path.write_bytes(raw)
    assert _physical_source(str(path), raw.decode()) == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "shell",
    [
        "'''curl https://example.test/status -H \"Authorization: Bearer $TOKEN\"'''",
        "'''curl https://example.test/status?access_token=$OTHER'''",
        "'''curl 'https://example.test/status?access_token=$TOKEN' '''",
    ],
)
def test_unrelated_header_and_literal_query_do_not_claim_path(tmp_path: Path, shell: str) -> None:
    assert not _selected(_scan(tmp_path, _source(shell)))


def test_unrelated_binding_owner_does_not_join(tmp_path: Path) -> None:
    source = (
        "node {\n"
        "  withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) { sh 'echo ready' }\n"
        "  sh '''curl https://example.test/status?access_token=$TOKEN'''\n"
        "}\n"
    )
    assert not _selected(_scan(tmp_path, source))


def test_sibling_invocations_at_same_owner_do_not_join(tmp_path: Path) -> None:
    source = (
        "node {\n"
        "  withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) { sh 'echo ready' }\n"
        "  withCredentials([file(credentialsId: 'other', variable: 'FILE')]) {\n"
        "    sh '''curl https://example.test/status?access_token=$TOKEN'''\n"
        "  }\n"
        "}\n"
    )
    path = tmp_path / "Jenkinsfile"
    path.write_text(source, encoding="utf8")
    result = JenkinsCredentialQueryPattern().check_with_filepath(
        source, source.splitlines(), str(path)
    )
    assert isinstance(result, IncompletePatternMatches)
    assert not result


@pytest.mark.parametrize(
    "shell",
    [
        "'''TOKEN=public\ncurl https://example.test/status?access_token=$TOKEN'''",
        "'''source ./unknown.sh\ncurl https://example.test/status?access_token=$TOKEN'''",
        "'''curl \\\"https://example.test/status?access_token=$TOKEN\\\"'''",
        "'''curl https://example.test/status?public=yes&access_token=$TOKEN'''",
        "'''curl https://example.test/status?public=yes#access_token=$TOKEN'''",
    ],
)
def test_unsupported_transform_or_literal_quote_stays_unresolved(
    tmp_path: Path, shell: str
) -> None:
    source = _source(shell)
    path = tmp_path / "Jenkinsfile"
    path.write_text(source, encoding="utf8")
    result = JenkinsCredentialQueryPattern().check_with_filepath(
        source, source.splitlines(), str(path)
    )
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_script_text_outside_shell_is_not_a_query(tmp_path: Path) -> None:
    source = _source("'''cat > example.txt <<'EOF'\ncurl https://example.test/?key=$TOKEN\nEOF'''")
    assert not _selected(_scan(tmp_path, source))


def test_groovy_shadow_keeps_gstring_dependency_unresolved(tmp_path: Path) -> None:
    source = _source(
        '"curl https://example.test/status?access_token=$TOKEN"',
        prefix="  def TOKEN = 'public'\n",
    )
    path = tmp_path / "Jenkinsfile"
    path.write_text(source, encoding="utf8")
    result = JenkinsCredentialQueryPattern().check_with_filepath(
        source, source.splitlines(), str(path)
    )
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_header_credential_and_nonsecret_query_do_not_create_query_warning(
    tmp_path: Path,
) -> None:
    source = _source(
        "'''curl -H \"Authorization: Bearer $TOKEN\" "
        "https://example.test/status?name=$BUILD_NUMBER'''"
    )
    path = tmp_path / "Jenkinsfile"
    path.write_text(source, encoding="utf8")
    result = JenkinsCredentialQueryPattern().check_with_filepath(
        source, source.splitlines(), str(path)
    )
    assert result == []


def test_legacy_map_named_sh_and_curl_data_option_reach_query(tmp_path: Path) -> None:
    source = (
        "node { withCredentials([[$class: 'UsernamePasswordMultiBinding', "
        "credentialsId: 'id', usernameVariable: 'USER', "
        "passwordVariable: 'TOKEN']]) {\n"
        "  def response = sh script: \"curl --data 'public' "
        "https://example.test/releases?access_token=$TOKEN\", returnStdout: true\n"
        "} }\n"
    )
    selected = _selected(_scan(tmp_path, source))
    assert len(selected) == 1
    assert selected[0].line == 2
    assert "binding TOKEN" in " ".join(selected[0].context_notes)


def test_curl_option_before_direct_query_reaches_query(tmp_path: Path) -> None:
    source = _source('"curl -XPOST \\"https://example.test/send?access_token=$TOKEN\\""')
    assert len(_selected(_scan(tmp_path, source))) == 1


def test_url_in_data_operand_is_not_the_request_destination(tmp_path: Path) -> None:
    source = _source(
        "'''curl --data 'https://example.test/?access_token=$TOKEN' "
        "https://example.test/public'''"
    )
    assert not _selected(_scan(tmp_path, source))


def test_unrecognized_legacy_map_class_does_not_bind_password(tmp_path: Path) -> None:
    source = (
        "node { withCredentials([[$class: 'OtherBinding', "
        "credentialsId: 'id', passwordVariable: 'TOKEN']]) {\n"
        "  sh script: 'curl https://example.test/?access_token=$TOKEN'\n"
        "} }\n"
    )
    assert not _selected(_scan(tmp_path, source))
