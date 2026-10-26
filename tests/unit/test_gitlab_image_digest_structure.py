"""Configured GitLab job-image references and structural ownership."""

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.gitlab.sec3_sec6_supply_chain_creds import GitlabUnpinnedImagePattern
from taintly.rules.registry import load_rules_for_platform


def _matches(source: str):
    return GitlabUnpinnedImagePattern().check(source, source.splitlines())


def test_equivalent_owned_image_syntax_and_variable_tag():
    for declaration in (
        "image: alpine:3.24",
        "'image': 'alpine:3.24'",
        "image: {name: alpine:3.24}",
        "image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/library/alpine:$ALPINE_VERSION",
    ):
        source = f"build:\n  {declaration}\n  script: echo ok\n"
        assert _matches(source), declaration


def test_global_and_default_image_forms_keep_pinning_check():
    assert _matches("image: alpine:3.24\nbuild:\n  script: echo ok\n")
    assert _matches("default:\n  image: alpine:3.24\nbuild:\n  script: echo ok\n")


def test_pinned_image_and_inert_script_text_are_not_image_findings():
    source = (
        "build:\n"
        "  image: alpine@sha256:" + "a" * 64 + "\n"
        "  script: |\n"
        "    cat > example.yml <<'EOF'\n"
        "    image: alpine:3.24\n"
        "    EOF\n"
    )
    assert _matches(source) == []


def test_whole_variable_image_is_unresolved_not_unpinned():
    source = "build:\n  image: $JOB_IMAGE\n  script: echo ok\n"
    result = _matches(source)
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_scan_repo_reports_owned_variable_tag_without_script_decoy(tmp_path):
    source = (
        "build:\n"
        "  image: registry.example.org/app:$IMAGE_TAG\n"
        "  script: |\n"
        "    cat > example.yml <<'EOF'\n"
        "    image: alpine:3.24\n"
        "    EOF\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text(source, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB))
    findings = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "SEC3-GL-005"
    ]
    assert [(finding.line, finding.review_needed) for finding in findings] == [(2, False)]


def test_scan_repo_does_not_call_whole_variable_image_safe(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "build:\n  image: $JOB_IMAGE\n  script: echo ok\n", encoding="utf-8"
    )
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB))
    relevant = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id in {"SEC3-GL-005", "ENGINE-ERR"}
    ]
    assert not any(finding.rule_id == "SEC3-GL-005" for finding in relevant)
    assert any("SEC3-GL-005" in finding.description for finding in relevant)


def test_scan_repo_pinned_image_has_no_unpinned_finding(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "build:\n  image: alpine@sha256:" + "a" * 64 + "\n  script: echo ok\n",
        encoding="utf-8",
    )
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB))
    assert not any(
        finding.rule_id == "SEC3-GL-005" for report in reports for finding in report.findings
    )


def test_service_scalar_map_and_default_are_owned_image_references():
    for source in (
        "build:\n  services:\n    - postgres:17\n  script: echo ok\n",
        "build:\n  services: [{name: postgres:17}]\n  script: echo ok\n",
        "default:\n  services:\n    - name: postgres:17\nbuild:\n  script: echo ok\n",
        "services:\n  - postgres:17\nbuild:\n  script: echo ok\n",
    ):
        assert _matches(source), source


def test_service_digest_unknown_and_script_decoy_remain_distinct():
    source = (
        "build:\n  services:\n    - name: postgres@sha256:"
        + "a" * 64
        + "\n  script: |\n    cat > example.yml <<'EOF'\n"
        "    services:\n    - name: redis:latest\n    EOF\n"
    )
    assert _matches(source) == []
    unknown = "build:\n  services:\n    - name: $SERVICE_IMAGE\n  script: echo ok\n"
    assert isinstance(_matches(unknown), IncompletePatternMatches)


def test_scan_repo_service_finding_supersedes_same_line_latest_rule(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "build:\n  services:\n    - postgres:latest\n  script: echo ok\n",
        encoding="utf-8",
    )
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB))
    relevant = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id in {"SEC3-GL-005", "SEC8-GL-003"}
    ]
    assert [(finding.rule_id, finding.line) for finding in relevant] == [("SEC3-GL-005", 3)]
