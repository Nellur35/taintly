"""SEC4-GH-001 mutation probes must preserve workflow structure."""

from __future__ import annotations

import pytest

from taintly.parsers.structural import EventKind, triggers, walk_workflow
from taintly.testing.mutations import mutate_whitespace_pad


@pytest.mark.parametrize(
    "checkout_with",
    [
        """with:
          ref: ${{ github.event.pull_request.head.sha }}""",
        'with: { ref: "${{ github.event.pull_request.head.sha }}" }',
    ],
    ids=["block", "flow"],
)
def test_sec4_whitespace_variants_only_expect_detection_when_structure_survives(
    all_rules, checkout_with: str
) -> None:
    rule = next(rule for rule in all_rules if rule.id == "SEC4-GH-001")
    content = (
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"        {checkout_with.replace(chr(10), chr(10) + '        ')}\n"
        "      - run: echo X= 1\n"
    )
    variants = mutate_whitespace_pad(content)

    # Extra spacing around mapping separators and equals signs preserves the
    # trigger/checkout structure and should remain detectable directly. The
    # zero-space colon collapse is excluded by the mutation generator because
    # the structural reader proves it destroys the original uses mapping.
    assert len(variants) == 2
    assert rule.pattern.check(variants[0], variants[0].splitlines())
    assert rule.pattern.check(variants[1], variants[1].splitlines())

    # The zero-space colon collapse turns the uses mapping into plain scalar
    # text. This block-form trigger survives but no checkout action remains.
    collapsed = content.replace(": ", ":")
    assert "pull_request_target" in triggers(collapsed)
    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=collapsed)
        if event.kind is EventKind.LEAF_SCALAR
    ]
    assert not any(
        len(event.path) >= 2 and event.path[-1] == "uses" and event.value == "actions/checkout@v4"
        for event in leaves
    )
    assert rule.pattern.check(collapsed, collapsed.splitlines()) == []
