"""Contracts for invocation-local GitHub workflow summary reuse."""

from __future__ import annotations

import builtins
from pathlib import Path

import taintly.engine as engine
from taintly.models import Platform, RegexPattern, Rule, Severity
import taintly.workflow_corpus as workflow_corpus
from taintly.workflow_corpus import CorpusPattern


def _rule(rule_id: str, pattern, *, composition_tags: list[str] | None = None) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description="corpus reuse test",
        pattern=pattern,
        remediation="review",
        reference="",
        composition_tags=composition_tags or [],
    )


def _workflow(tmp_path: Path) -> Path:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: demo\non: push\njobs: {}\n", encoding="utf-8")
    return workflow


def test_scan_repo_rebuilds_corpus_but_reuses_unchanged_summaries(monkeypatch, tmp_path: Path):
    workflow = _workflow(tmp_path)
    builds = []
    summaries = []
    composer_inputs = []

    real_build_corpus = engine.build_corpus
    real_summarize = workflow_corpus._summarize_workflow

    def counted_build(repo_path: str, **kwargs):
        corpus = real_build_corpus(repo_path, **kwargs)
        builds.append(corpus)
        return corpus

    def counted_summarize(filepath: str, content: str):
        summaries.append((filepath, content))
        return real_summarize(filepath, content)

    monkeypatch.setattr(engine, "build_corpus", counted_build)
    monkeypatch.setattr(workflow_corpus, "_summarize_workflow", counted_summarize)

    def ordinary_callback(corpus):
        assert len(corpus.all()) == 1
        # CorpusPattern callbacks receive a mutable corpus. Mutations in this
        # pass must not leak into the separately routed composer pass.
        corpus.all()[0].workflow_name = "callback mutation"
        corpus.workflows.clear()
        return [(str(workflow), 1, "ordinary corpus finding")]

    def composer_callback(corpus):
        prior = getattr(corpus, "_prior_findings", [])
        composer_inputs.append(
            (
                len(corpus.all()),
                corpus.all()[0].workflow_name if corpus.all() else "",
                {finding.rule_id for finding in prior},
            )
        )
        return [(str(workflow), 1, "composer finding")]

    rules = [
        _rule("BASE", RegexPattern(match=r"name: demo")),
        _rule("ORDINARY", CorpusPattern(callback=ordinary_callback)),
        _rule(
            "COMPOSER",
            CorpusPattern(callback=composer_callback),
            composition_tags=["chain-composition"],
        ),
    ]

    reports = engine.scan_repo(str(tmp_path), rules, Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]

    assert len(builds) == 2
    assert len(summaries) == 1
    assert {finding.rule_id for finding in findings} >= {"BASE", "ORDINARY", "COMPOSER"}
    assert composer_inputs == [(1, "demo", {"BASE", "ORDINARY"})]


def test_corpus_state_and_prior_findings_are_fresh_for_each_scan(monkeypatch, tmp_path: Path):
    workflow = _workflow(tmp_path)
    builds = []
    summaries = []
    composer_inputs = []
    real_build_corpus = engine.build_corpus
    real_summarize = workflow_corpus._summarize_workflow

    def counted_build(repo_path: str, **kwargs):
        corpus = real_build_corpus(repo_path, **kwargs)
        builds.append(corpus)
        return corpus

    def counted_summarize(filepath: str, content: str):
        summaries.append((filepath, content))
        return real_summarize(filepath, content)

    monkeypatch.setattr(engine, "build_corpus", counted_build)
    monkeypatch.setattr(workflow_corpus, "_summarize_workflow", counted_summarize)

    def composer_callback(corpus):
        prior = getattr(corpus, "_prior_findings", [])
        composer_inputs.append((id(corpus), {finding.rule_id for finding in prior}))
        return [(str(workflow), 1, "composer finding")]

    rules = [
        _rule("BASE", RegexPattern(match=r"name: demo")),
        _rule(
            "COMPOSER",
            CorpusPattern(callback=composer_callback),
            composition_tags=["chain-composition"],
        ),
    ]

    first = engine.scan_repo(str(tmp_path), rules, Platform.GITHUB)
    second = engine.scan_repo(str(tmp_path), rules, Platform.GITHUB)

    assert len(builds) == 2
    assert len(summaries) == 2
    assert builds[0] is not builds[1]
    assert composer_inputs[0][0] != composer_inputs[1][0]
    assert composer_inputs[0][1] == composer_inputs[1][1] == {"BASE"}
    for reports in (first, second):
        assert {finding.rule_id for report in reports for finding in report.findings} >= {
            "BASE",
            "COMPOSER",
        }


def test_corpus_reuse_does_not_hide_per_file_read_errors(monkeypatch, tmp_path: Path):
    workflow = _workflow(tmp_path)
    real_open = builtins.open

    def unreadable_workflow(file, *args, **kwargs):
        try:
            resolved = Path(file).resolve()
        except (TypeError, OSError):
            resolved = None
        if resolved == workflow.resolve():
            raise PermissionError("synthetic read denial")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", unreadable_workflow)
    rules = [_rule("CORPUS", CorpusPattern(callback=lambda _corpus: []))]

    reports = engine.scan_repo(str(tmp_path), rules, Platform.GITHUB)

    assert reports[0].files_scanned == 1
    assert any(finding.rule_id == "ENGINE-ERR" for finding in reports[0].findings)


def test_composer_build_observes_workflow_changes_between_passes(monkeypatch, tmp_path: Path):
    workflow = _workflow(tmp_path)
    removed = workflow.parent / "remove.yml"
    removed.write_text("name: removed\non: push\njobs: {}\n", encoding="utf-8")
    unreadable = workflow.parent / "blocked.yml"
    unreadable.write_text("name: blocked\non: push\njobs: {}\n", encoding="utf-8")
    reject_blocked = [False]
    real_open = builtins.open
    builds = []
    real_build_corpus = engine.build_corpus

    def conditional_open(file, *args, **kwargs):
        try:
            resolved = Path(file).resolve()
        except (TypeError, OSError):
            resolved = None
        if reject_blocked[0] and resolved == unreadable.resolve():
            raise PermissionError("synthetic second-pass read denial")
        return real_open(file, *args, **kwargs)

    def counted_build(repo_path: str, **kwargs):
        corpus = real_build_corpus(repo_path, **kwargs)
        builds.append(corpus)
        return corpus

    monkeypatch.setattr(builtins, "open", conditional_open)
    monkeypatch.setattr(engine, "build_corpus", counted_build)
    composer_observations = []

    def ordinary_callback(corpus):
        workflow.write_text("name: updated\non: push\njobs: {}\n", encoding="utf-8")
        (workflow.parent / "new.yml").write_text(
            "name: new\non: push\njobs: {}\n", encoding="utf-8"
        )
        removed.unlink()
        reject_blocked[0] = True
        return [(str(workflow), 1, "ordinary corpus finding")]

    def composer_callback(corpus):
        composer_observations.append(
            {summary.workflow_name for summary in corpus.all()}
        )
        return [(str(workflow), 1, "composer finding")]

    rules = [
        _rule("ORDINARY", CorpusPattern(callback=ordinary_callback)),
        _rule(
            "COMPOSER",
            CorpusPattern(callback=composer_callback),
            composition_tags=["chain-composition"],
        ),
    ]

    engine.scan_repo(str(tmp_path), rules, Platform.GITHUB)

    assert composer_observations == [{"updated", "new"}]
    assert len(builds) == 2
