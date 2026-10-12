from __future__ import annotations

import pytest

import taintly.rules.github.ai as ai_rules
from taintly.agentguards import AgentGuardIndex
from taintly.models import ContextPattern


def _workflow(*commands: str, suffix: str = "") -> str:
    steps = "".join(f"      - run: {command}\n" for command in commands)
    return (
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    steps:\n"
        f"{steps}"
        "      - uses: anthropics/claude-code-action@v1\n"
        f"{suffix}"
    )


def _mutable_pattern():
    return next(rule.pattern for rule in ai_rules.RULES if rule.id == "AI-GH-019")


def _old_mutable_read_check(pattern, content: str) -> list[tuple[int, str]]:
    """Explicit pre-refactor oracle: owner filter, then a fresh metadata index."""
    lines = content.splitlines()
    candidates = ContextPattern.check(pattern, content, lines)
    if not candidates:
        return candidates

    owner_index = AgentGuardIndex(content)
    survivors = []
    for candidate in candidates:
        owner = owner_index.owner(candidate[0])
        if owner is None or not pattern._excluded(owner_index, owner):
            survivors.append(candidate)
    if not survivors:
        return survivors

    metadata_index = AgentGuardIndex(content)
    return [
        candidate
        for candidate in survivors
        if not metadata_index.read_selects_only_metadata(candidate[0])
    ]


class _CountingIndex(AgentGuardIndex):
    def __init__(self, content: str, trace: list[tuple]):
        trace.append(("construct", content))
        self._trace = trace
        super().__init__(content)

    def owner(self, line: int):
        self._trace.append(("owner", line))
        return super().owner(line)

    def excludes(self, owner, *, outside_actor: bool = True):
        self._trace.append(("exclude", owner))
        return super().excludes(owner, outside_actor=outside_actor)

    def read_selects_only_metadata(self, line: int) -> bool:
        self._trace.append(("metadata", line))
        return super().read_selects_only_metadata(line)


def _install_counting_index(monkeypatch, trace: list[tuple]) -> None:
    monkeypatch.setattr(
        ai_rules,
        "AgentGuardIndex",
        lambda content: _CountingIndex(content, trace),
    )


def test_reuses_owner_index_after_all_exclusion_checks(monkeypatch):
    content = _workflow(
        "gh pr view 1 --json state",
        "gh pr view 2 --json title,body",
    )
    expected = _old_mutable_read_check(_mutable_pattern(), content)
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)

    actual = _mutable_pattern().check(content, content.splitlines())

    assert actual == expected
    assert [event for event in trace if event[0] == "construct"] == [("construct", content)]
    exclusion_positions = [i for i, event in enumerate(trace) if event[0] == "exclude"]
    metadata_positions = [i for i, event in enumerate(trace) if event[0] == "metadata"]
    assert exclusion_positions
    assert metadata_positions
    assert max(exclusion_positions) < min(metadata_positions)


def test_no_candidates_and_fully_excluded_candidates_keep_construction_behavior(monkeypatch):
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)
    pattern = _mutable_pattern()
    no_read = _workflow("echo no read")

    assert pattern.check(no_read, no_read.splitlines()) == []
    assert trace == []

    content = _workflow("gh pr view 1 --json title", "gh pr view 2 --json body")
    excluded: list[tuple] = []

    def exclude_every_owned_candidate(index, owner) -> bool:
        excluded.append(owner)
        return True

    monkeypatch.setattr(pattern, "_excluded", exclude_every_owned_candidate)
    assert pattern.check(content, content.splitlines()) == []
    assert len(excluded) == 2
    assert [event[0] for event in trace].count("construct") == 1
    assert not any(event[0] == "metadata" for event in trace)


@pytest.mark.parametrize(
    "suffix",
    [
        # Duplicate job path makes AgentGuardIndex invalid and every owner unknown.
        "jobs:\n  review:\n    steps:\n      - run: echo duplicate\n",
        # Merge origins also make owner proofs unknown.
        "defaults: &defaults\n  run: echo merged\njobs:\n  sibling:\n    <<: *defaults\n",
        # Structural parse failure must retain conservative unknown-owner behavior.
        "broken: [\n",
    ],
    ids=["duplicate-owner", "merged-owner", "malformed-owner"],
)
def test_unknown_owners_match_old_behavior_and_still_reach_metadata_check(monkeypatch, suffix):
    content = _workflow("gh pr view 1 --json state", suffix=suffix)
    expected = _old_mutable_read_check(_mutable_pattern(), content)
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)

    actual = _mutable_pattern().check(content, content.splitlines())

    assert actual == expected
    assert [event[0] for event in trace].count("construct") == 1
    assert any(event[0] == "metadata" for event in trace)


def test_changed_content_gets_fresh_index_per_check(monkeypatch):
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)
    pattern = _mutable_pattern()
    metadata = _workflow("gh pr view 1 --json state")
    body = _workflow("gh pr view 1 --json body")

    assert pattern.check(metadata, metadata.splitlines()) == []
    assert pattern.check(body, body.splitlines())

    constructions = [event[1] for event in trace if event[0] == "construct"]
    assert constructions == [metadata, body]


def test_same_repository_guard_does_not_exclude_mutable_content(monkeypatch):
    content = _workflow("gh pr view 1 --json title,body").replace(
        "    steps:\n",
        "    if: github.event.pull_request.head.repo.full_name == github.repository\n    steps:\n",
    )
    pattern = _mutable_pattern()
    expected = _old_mutable_read_check(pattern, content)
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)
    actual = _mutable_pattern().check(content, content.splitlines())

    assert actual == expected
    assert actual
    assert [event for event in trace if event[0] == "construct"] == [("construct", content)]


def test_exclusion_failure_propagates_before_any_metadata_reads(monkeypatch):
    content = _workflow(
        "gh pr view 1 --json state",
        "gh pr view 2 --json title",
    )
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)
    pattern = _mutable_pattern()
    exclusions: list[tuple] = []

    def fail_on_second_candidate(index, owner) -> bool:
        exclusions.append(owner)
        if len(exclusions) == 2:
            raise RuntimeError("owner exclusion failed")
        return False

    monkeypatch.setattr(pattern, "_excluded", fail_on_second_candidate)
    with pytest.raises(RuntimeError, match="owner exclusion failed"):
        pattern.check(content, content.splitlines())

    assert len(exclusions) == 2
    assert not any(event[0] == "metadata" for event in trace)


def test_metadata_read_error_propagates_after_all_owner_exclusions(monkeypatch):
    content = _workflow(
        "gh pr view 1 --json state",
        "gh pr view 2 --json body",
    )
    trace: list[tuple] = []
    _install_counting_index(monkeypatch, trace)
    pattern = _mutable_pattern()

    def fail_metadata(self, line: int) -> bool:
        raise RuntimeError("metadata read failed")

    monkeypatch.setattr(AgentGuardIndex, "read_selects_only_metadata", fail_metadata)
    with pytest.raises(RuntimeError, match="metadata read failed"):
        pattern.check(content, content.splitlines())

    first_metadata = next(i for i, event in enumerate(trace) if event[0] == "metadata")
    assert sum(event[0] == "exclude" for event in trace[:first_metadata]) == 2
