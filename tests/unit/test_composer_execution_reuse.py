"""The dedicated composer pass reuses only immutable content structure."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.composer import (
    _EXECUTION_STRUCTURE_CACHE,
    Database,
    _seed_execution_contexts,
    composer_execution_structure_cache,
    run_composer,
)
from taintly.engine import _run_corpus_rules
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import CorpusPattern, WorkflowCorpus, WorkflowSummary

WORKFLOW = "on: pull_request_target\njobs:\n  build:\n    steps:\n      - run: echo hi\n"


def _corpus(contents: dict[str, str]) -> WorkflowCorpus:
    return WorkflowCorpus(
        repo_path="/repo",
        workflows={
            path: WorkflowSummary(path, content, content.splitlines())
            for path, content in contents.items()
        },
    )


def _rule(rule_id: str, callback) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="",
        description="test",
        pattern=CorpusPattern(callback),
        remediation="",
        reference="",
        composition_tags=frozenset({"chain-composition"}),
    )


def test_engine_composer_pass_reuses_same_content_across_five_callbacks(
    tmp_path: Path, monkeypatch
):
    from taintly import composer

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(WORKFLOW, encoding="utf-8")

    original = composer._build_execution_structure
    calls = []

    def count(content):
        calls.append(content)
        return original(content)

    monkeypatch.setattr(composer, "_build_execution_structure", count)
    visited = []

    def callback(index, *, fail=False):
        def run(corpus):
            visited.append(index)
            run_composer(corpus, [], [])
            if fail:
                raise RuntimeError("bounded callback failure")
            return []

        return run

    rules = [_rule(f"CHAIN-{index}", callback(index, fail=index == 1)) for index in range(5)]
    result = _run_corpus_rules(str(tmp_path), rules, prior_findings=[], composer_only=True)

    assert visited == list(range(5))
    assert len(calls) == 1
    assert len(result) == 1
    assert result[0].rule_id == "ENGINE-ERR"
    assert "bounded callback failure" in result[0].description
    assert _EXECUTION_STRUCTURE_CACHE.get() is None


def test_same_content_shares_structure_but_file_facts_and_prior_findings_are_fresh(
    monkeypatch,
):
    from taintly import composer
    from taintly.models import Finding

    corpus = _corpus({"one.yml": WORKFLOW, "two.yml": WORKFLOW})
    original = composer._build_execution_structure
    calls = []

    def count(content):
        calls.append(content)
        return original(content)

    monkeypatch.setattr(composer, "_build_execution_structure", count)
    observed = []

    def inspect(db):
        observed.append(
            {
                "files": {fact.file for fact in db.all("execution_context")},
                "rules": {fact.rule_id for fact in db.all("finding")},
            }
        )
        return []

    with composer_execution_structure_cache():
        run_composer(
            corpus,
            [Finding("FIRST", Severity.LOW, "first", "", "one.yml", 1)],
            [inspect],
        )
        run_composer(
            corpus,
            [Finding("SECOND", Severity.HIGH, "second", "", "two.yml", 1)],
            [inspect],
        )

    assert calls == [WORKFLOW]
    assert observed == [
        {"files": {"one.yml", "two.yml"}, "rules": {"FIRST"}},
        {"files": {"one.yml", "two.yml"}, "rules": {"SECOND"}},
    ]


def test_changed_content_at_same_path_rebuilds_structure(monkeypatch):
    from taintly import composer

    original = composer._build_execution_structure
    calls = []

    def count(content):
        calls.append(content)
        return original(content)

    monkeypatch.setattr(composer, "_build_execution_structure", count)
    corpus = _corpus({"same.yml": WORKFLOW})
    captured = []

    def inspect(db):
        fact = db.get("execution_context", ("same.yml",))
        captured.append(fact.keys)
        return []

    with composer_execution_structure_cache():
        run_composer(corpus, [], [inspect])
        changed = WORKFLOW.replace("build", "renamed")
        corpus.workflows["same.yml"].content = changed
        run_composer(corpus, [], [inspect])

    assert calls == [WORKFLOW, changed]
    assert ("jobs", "build") in captured[0]
    assert ("jobs", "renamed") in captured[1]


def test_parent_reachability_is_queried_fresh_for_cached_child_content():
    child_content = "on: workflow_run\njobs:\n  child:\n    steps:\n      - run: echo child\n"
    parent = WorkflowSummary(
        "parent.yml",
        "on: pull_request\n",
        ["on: pull_request"],
        raw_event_names=frozenset({"pull_request"}),
        workflow_name="Parent",
    )
    child = WorkflowSummary(
        "child.yml",
        child_content,
        child_content.splitlines(),
        raw_event_names=frozenset({"workflow_run"}),
        workflow_run_parents=("Parent",),
    )
    corpus = _corpus({"parent.yml": parent.content, "child.yml": child.content})
    corpus.workflows["parent.yml"] = parent
    corpus.workflows["child.yml"] = child
    observed = []

    with composer_execution_structure_cache():
        db = Database()
        _seed_execution_contexts(db, corpus)
        observed.append(db.get("execution_context", ("child.yml",)).events)

        parent.raw_event_names = frozenset()
        db = Database()
        _seed_execution_contexts(db, corpus)
        observed.append(db.get("execution_context", ("child.yml",)).events)

    assert observed[0] is not None
    assert "workflow_run" in observed[0]
    assert observed[1] == frozenset()


def test_calls_outside_scope_are_uncached_and_nested_failed_or_thread_scopes_isolate():
    from threading import Thread

    from taintly import composer

    original = composer._build_execution_structure
    calls = []

    def count(content):
        calls.append(content)
        return original(content)

    composer._build_execution_structure = count
    try:
        composer._execution_structure(WORKFLOW)
        composer._execution_structure(WORKFLOW)
        assert len(calls) == 2

        def fail_nested_scope():
            with composer_execution_structure_cache():
                composer._execution_structure(WORKFLOW)
                raise RuntimeError("scope failure")

        with composer_execution_structure_cache():
            composer._execution_structure(WORKFLOW)
            worker = Thread(target=lambda: composer._execution_structure(WORKFLOW))
            worker.start()
            worker.join()
            composer._execution_structure(WORKFLOW)
            assert len(calls) == 4
            with pytest.raises(RuntimeError, match="scope failure"):
                fail_nested_scope()
            composer._execution_structure(WORKFLOW)
            assert len(calls) == 5
        assert _EXECUTION_STRUCTURE_CACHE.get() is None
    finally:
        composer._build_execution_structure = original


def test_extraction_failure_is_not_cached_and_retention_is_bounded(monkeypatch):
    from taintly import composer

    original = composer._build_execution_structure
    calls = []

    def fail_once(content):
        calls.append(content)
        if len(calls) == 1:
            raise ValueError("temporary extraction failure")
        return original(content)

    monkeypatch.setattr(composer, "_build_execution_structure", fail_once)
    with composer_execution_structure_cache():
        with pytest.raises(ValueError, match="temporary extraction failure"):
            composer._execution_structure(WORKFLOW)
        assert composer._execution_structure(WORKFLOW).events is not None
        composer._execution_structure(WORKFLOW)
        for index in range(12):
            composer._execution_structure(WORKFLOW + f"# {index}\n")
        cache = _EXECUTION_STRUCTURE_CACHE.get()
        assert cache is not None
        assert len(cache.entries) == composer._EXECUTION_STRUCTURE_CACHE_LIMIT
    assert len(calls) == 14


def test_changed_helper_implementation_bypasses_active_cache(monkeypatch):
    from taintly import composer

    original_build = composer._build_execution_structure
    original_guard_extractor = composer._certified_guards
    calls = []

    def count(content):
        calls.append(content)
        return original_build(content)

    monkeypatch.setattr(composer, "_build_execution_structure", count)
    guarded = WORKFLOW.replace("    steps:", "    if: github.event_name == 'push'\n    steps:")
    with composer_execution_structure_cache():
        first = composer._execution_structure(guarded)
        monkeypatch.setattr(composer, "_certified_guards", lambda _content, _index: ())
        second = composer._execution_structure(guarded)
        third = composer._execution_structure(guarded)
    monkeypatch.setattr(composer, "_certified_guards", original_guard_extractor)

    assert first.guards
    assert second.guards == ()
    assert second == third
    assert calls == [guarded, guarded, guarded]


def test_oversize_content_is_correctly_extracted_without_retention(monkeypatch):
    from taintly import composer

    original = composer._build_execution_structure
    calls = []
    content = "on: push\n#" + ("bounded comment\\n" * 5_000)

    def count(source):
        calls.append(source)
        return original(source)

    monkeypatch.setattr(composer, "_build_execution_structure", count)
    assert len(content) > composer._EXECUTION_STRUCTURE_MAX_CONTENT_CHARS
    with composer_execution_structure_cache():
        first = composer._execution_structure(content)
        second = composer._execution_structure(content)
        cache = _EXECUTION_STRUCTURE_CACHE.get()
        assert cache is not None
        assert not cache.entries
    assert first.events == second.events == frozenset({"push"})
    assert calls == [content, content]
