"""A formatting probe must not silently replace a condition with plain text."""

from __future__ import annotations

import pytest

from taintly.parsers.structural import EventKind, walk_workflow
from taintly.testing.mutations import mutate_whitespace_pad


def condition_paths(source):
    return {
        event.path for event in walk_workflow(".gitlab-ci.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR and event.path[-1:] == ("if",)
    }


@pytest.mark.parametrize("source", [
    '    - if: $CI_COMMIT_BRANCH == "main"',
    '    - if: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^feature/',
    "    - if: $CI_COMMIT_REF_NAME == 'main'",
    'job:\n  rules:\n    - if: $CI_COMMIT_BRANCH == "main"\n  script: echo ready\n',
    'workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == "main"\n',
])
def test_condition_mapping_loss_is_not_a_whitespace_equivalence(source):
    collapsed = source.replace(": ", ":")
    assert condition_paths(source)
    assert not condition_paths(collapsed)
    assert collapsed not in mutate_whitespace_pad(source)
    assert source.replace(": ", ":  ") in mutate_whitespace_pad(source)


def test_quoted_flow_condition_is_retained_when_its_key_survives():
    source = '{"workflow": {"rules": [{"if": "$CI_COMMIT_BRANCH == null"}]}}\n'
    collapsed = source.replace(": ", ":")
    assert condition_paths(source) == condition_paths(collapsed)
    assert collapsed in mutate_whitespace_pad(source)


@pytest.mark.parametrize("source", [
    'job:\n  script: |\n    if: $CI_COMMIT_BRANCH == null\n',
    'if: $CI_COMMIT_BRANCH == null\n',
    'job:\n  rules:\n    - if: $CI_COMMIT_BRANCH == null\n      if: $CI_COMMIT_TAG == null\n',
    'job:\n  rules:\n    - if: $CI_COMMIT_BRANCH == null\n%YAML 1.2\n',
    'job:\n  rules:\n    - if: *unresolved\n',
    'sh "echo kind: value"',
    'echo kind: value',
])
def test_uncertain_or_non_profile_input_does_not_authorize_probe_removal(source):
    assert source.replace(": ", ":") in mutate_whitespace_pad(source)
