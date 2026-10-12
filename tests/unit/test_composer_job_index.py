"""Composition must reuse job ranges without changing source attribution."""

from types import SimpleNamespace

import pytest

from taintly.composer import FindingFact, run_composer
from taintly.models import Finding, Severity
from taintly.parsers import segmentation
from taintly.workflow_corpus import WorkflowCorpus, WorkflowSummary

WORKFLOW = (
    "on: pull_request_target\npermissions: read-all\njobs:\n"
    "  first:\n    steps:\n      - run: echo first\n"
    "  second:\n    steps:\n      - run: echo second\n"
)


def _corpus(contents):
    return WorkflowCorpus(
        repo_path="/repo",
        workflows={
            path: WorkflowSummary(path, content, content.splitlines())
            for path, content in contents.items()
        },
    )


def _finding(path, line):
    return Finding("TEST", Severity.HIGH, "test", "test", path, line)


def _capture(corpus, findings):
    captured = []

    def observe(db):
        captured[:] = db.all("finding")
        return []

    assert run_composer(corpus, findings, [observe]) == []
    return captured


def test_composer_segments_each_file_once_independent_of_finding_count(monkeypatch):
    original = segmentation.for_each_job
    calls = []

    def count(content):
        calls.append(content)
        return original(content)

    monkeypatch.setattr(segmentation, "for_each_job", count)
    corpus = _corpus({"a.yml": WORKFLOW, "b.yml": WORKFLOW.replace("first", "alpha")})
    findings = [_finding(path, 6) for path in corpus.workflows for _ in range(30)]
    rows = _capture(corpus, findings)
    assert len(rows) == 2
    assert len(calls) == 2


@pytest.mark.parametrize("content", [WORKFLOW, "", "on: push\n", "build:\n  script: test\n"])
def test_composer_attribution_matches_existing_segmentation_at_every_boundary(content):
    findings = [_finding("ci.yml", line) for line in range(-1, len(content.splitlines()) + 3)]
    rows = _capture(_corpus({"ci.yml": content}), findings)
    assert {(row.line, row.job) for row in rows if isinstance(row, FindingFact)} == {
        (finding.line, segmentation.job_at_line(content, finding.line)) for finding in findings
    }


def test_explicit_job_unknown_file_and_engine_error_keep_existing_semantics():
    explicit = SimpleNamespace(
        rule_id="TEST", file="ci.yml", line=0, job="explicit", severity=Severity.LOW, snippet=""
    )
    missing = _finding("missing.yml", 6)
    error = _finding("ci.yml", 6)
    error.rule_id = "ENGINE-ERR"
    rows = _capture(_corpus({"ci.yml": WORKFLOW}), [explicit, missing, error])
    assert {(row.file, row.job, row.line) for row in rows} == {
        ("ci.yml", "explicit", 0),
        ("missing.yml", None, 6),
    }


def test_job_ranges_do_not_survive_a_composer_invocation():
    corpus = _corpus({"ci.yml": WORKFLOW})
    finding = _finding("ci.yml", 6)
    assert _capture(corpus, [finding])[0].job == "first"
    corpus.workflows["ci.yml"].content = WORKFLOW.replace("first", "changed")
    assert _capture(corpus, [finding])[0].job == "changed"


def test_composer_databases_remain_isolated():
    corpus = _corpus({"ci.yml": WORKFLOW})
    assert len(_capture(corpus, [_finding("ci.yml", 6)])) == 1
    assert _capture(corpus, []) == []
