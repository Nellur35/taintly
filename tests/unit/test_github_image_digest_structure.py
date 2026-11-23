"""GitHub image findings require an owned job or service consumer."""

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.github.image_refs import GithubImageReferencePattern
from taintly.rules.registry import load_rules_for_platform


def _matches(source: str, kind: str = "tagged"):
    return GithubImageReferencePattern(kind).check(source, source.splitlines())


def test_direct_job_and_service_forms_are_distinct_consumers():
    source = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    container: node:20\n"
        "    services:\n"
        "      db:\n"
        "        image: postgres:17\n"
    )
    assert [line for line, _ in _matches(source)] == [5, 8]


def test_matrix_image_values_and_script_text_are_not_direct_consumers():
    source = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - image: ubuntu:rolling\n"
        "    services: {}\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo 'image: postgres:17'\n"
        "          echo 'services: ${{ vars.SERVICE_MAP }}'\n"
    )
    result = _matches(source)
    assert result == []
    assert not isinstance(result, IncompletePatternMatches)


def test_digest_pinned_and_dynamic_consumers_are_not_called_unpinned():
    pinned = "jobs:\n  build:\n    container: node@sha256:" + "a" * 64 + "\n"
    assert _matches(pinned) == []
    dynamic = "jobs:\n  build:\n    container:\n      image: ${{ matrix.image }}\n"
    result = _matches(dynamic)
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_dynamic_consumer_remains_unresolved_in_product_report(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - image: ubuntu:rolling\n"
        "    container: ${{ matrix.image }}\n",
        encoding="utf-8",
    )
    findings = [
        finding
        for report in scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
        for finding in report.findings
    ]
    assert not any(f.rule_id in {"SEC3-GH-007", "SEC8-GH-001", "SEC8-GH-002"} for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "image reference" in f.description.lower() for f in findings
    )


def test_latest_untagged_and_version_tags_keep_separate_rules(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    container: node:20\n"
        "    services:\n"
        "      db:\n"
        "        image: postgres:latest\n"
        "      cache:\n"
        "        image: redis\n",
        encoding="utf-8",
    )
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
    relevant = [
        (finding.rule_id, finding.line)
        for report in reports
        for finding in report.findings
        if finding.rule_id in {"SEC3-GH-007", "SEC8-GH-001", "SEC8-GH-002"}
    ]
    assert relevant == [
        ("SEC3-GH-007", 5),
        ("SEC8-GH-001", 8),
        ("SEC8-GH-002", 10),
    ]


def test_unresolved_services_map_retains_other_job_image_findings(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\n"
        "jobs:\n"
        "  expression:\n"
        "    runs-on: ubuntu-latest\n"
        "    services: ${{ fromJSON(vars.SERVICE_MAP) }}\n"
        "  literal:\n"
        "    runs-on: ubuntu-latest\n"
        "    services:\n"
        "      db:\n"
        "        image: postgres:17\n",
        encoding="utf-8",
    )
    (report,) = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
    assert [(f.rule_id, f.line) for f in report.findings if f.rule_id == "SEC3-GH-007"] == [
        ("SEC3-GH-007", 10),
    ]
    assert (
        sum(
            f.rule_id == "ENGINE-ERR" and "image reference" in f.description.lower()
            for f in report.findings
        )
        == 1
    )
