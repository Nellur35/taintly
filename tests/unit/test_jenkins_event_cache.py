"""Bounded reuse preserves events, diagnostics and scanner source ownership."""

from dataclasses import FrozenInstanceError

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.parsers.jenkinsfile import api
from taintly.parsers.jenkinsfile.events import EventKind
from taintly.parsers.jenkinsfile.island_walker import iter_island_leaves
from taintly.rules.registry import load_rules_for_platform


SOURCES = [
    "pipeline { stages { stage('Build') { steps { sh 'echo ok' } } } }",
    'node { withCredentials([string(credentialsId: "id", variable: "TOKEN")]) '
    '{ stage("test") { sh "echo ${params.INPUT}" } } }',
    "@Library('custom') _\nnode { customStep([a: 1]); sh 'echo ok' }",
    "node { sh 'echo before'; sh '''unterminated",
]


@pytest.fixture(autouse=True)
def clear_cache():
    api._cached_island_events.cache_clear()
    yield
    api._cached_island_events.cache_clear()


@pytest.mark.parametrize('source', SOURCES)
@pytest.mark.parametrize('recover', [True, False])
def test_exact_event_stream_and_immutable_records(source, recover):
    expected = tuple(iter_island_leaves(source))
    first = tuple(api.walk_jenkinsfile(source, recover=recover))
    assert first == tuple(api.walk_jenkinsfile(source, recover=recover)) == expected
    assert api._cached_island_events.cache_info().hits == 1
    if first:
        with pytest.raises(FrozenInstanceError):
            first[0].line = 99
    if 'unterminated' in source:
        assert any(event.kind is EventKind.CUTOFF for event in first)


def test_content_options_and_capacity():
    for i in range(12):
        list(api.walk_jenkinsfile(f"node {{ sh 'echo {i}' }}"))
    assert api._cached_island_events.cache_info().currsize == 8
    api._cached_island_events.cache_clear()
    list(api.walk_jenkinsfile(SOURCES[0], recover=True))
    list(api.walk_jenkinsfile(SOURCES[0], recover=False))
    assert api._cached_island_events.cache_info().misses == 2


def test_scanner_ownership_matches_uncached(tmp_path, monkeypatch):
    for name in ('Jenkinsfile', 'Jenkinsfile.test'):
        (tmp_path / name).write_text(SOURCES[1], encoding='utf-8')
    rules = load_rules_for_platform(Platform.JENKINS)
    cached = scan_repo(str(tmp_path), rules, Platform.JENKINS)
    with monkeypatch.context() as patch:
        patch.setattr(api, '_cached_island_events', api._cached_island_events.__wrapped__)
        uncached = scan_repo(str(tmp_path), rules, Platform.JENKINS)
    assert cached == uncached
    assert {finding.file for report in cached for finding in report.findings} == {
        str(tmp_path / 'Jenkinsfile'), str(tmp_path / 'Jenkinsfile.test')
    }
