"""Unit tests for SEC4-GH-004's dangerous-context regex.

Locks in the attacker-controllable GitHub-context shapes the rule
recognises.  Kept in sync with ``_TAINTED_CONTEXTS`` in
``taintly.taint`` — any shape catchable by the cross-step taint
analyzer must also be catchable directly by SEC4-GH-004, otherwise
the same byte appearing inline (without an intermediate ``env:``
hop) goes unflagged.
"""

from __future__ import annotations

import pytest

from taintly.rules.github.sec3_sec4_supply_chain_ppe import (
    _has_dangerous_github_context,
)


@pytest.mark.parametrize(
    "value",
    [
        "echo \"${{ github.event.pull_request.title }}\"",
        "echo \"${{ github.event.pull_request.body }}\"",
        "echo \"${{ github.event.pull_request.head.ref }}\"",
        "echo \"${{ github.event.pull_request.head.label }}\"",
        "echo \"${{ github.event.pull_request.user.login }}\"",
        "echo \"${{ github.event.issue.title }}\"",
        "echo \"${{ github.event.issue.body }}\"",
        "echo \"${{ github.event.comment.body }}\"",
        "echo \"${{ github.event.review.body }}\"",
        "echo \"${{ github.event.head_commit.message }}\"",
        "echo \"${{ github.event.head_commit.author.email }}\"",
        "echo \"${{ github.event.head_commit.author.name }}\"",
        "echo \"${{ github.event.review_comment.body }}\"",
        "echo \"${{ github.event.discussion.title }}\"",
        "echo \"${{ github.event.discussion.body }}\"",
        "echo \"${{ github.event.head_commit.committer.email }}\"",
        "echo \"${{ github.event.head_commit.committer.name }}\"",
        "echo \"${{ github.event.pull_request.head.repo.default_branch }}\"",
        "git checkout ${{ github.head_ref }}",
    ],
)
def test_dangerous_context_shapes_match(value: str) -> None:
    assert _has_dangerous_github_context(value, "scalar", ("jobs", "j", "steps", 0, "run"))


@pytest.mark.parametrize(
    "value",
    [
        # Non-attacker-controlled GitHub context
        "echo \"${{ github.repository }}\"",
        "echo \"${{ github.run_id }}\"",
        "echo \"${{ github.sha }}\"",
        # Other contexts
        "echo \"${{ env.SAFE }}\"",
        "echo \"${{ secrets.TOKEN }}\"",
        # Bare shell with no expression
        "echo hi",
        # Near-misses of the new additions: sibling fields that are NOT
        # attacker-controlled free text and must stay unflagged.
        # ``repo.full_name`` is the same-repo guard the calibration pass
        # relies on — flagging it as a source would be actively wrong.
        "echo \"${{ github.event.pull_request.head.repo.full_name }}\"",
        "echo \"${{ github.event.discussion.html_url }}\"",
        "echo \"${{ github.event.review_comment.html_url }}\"",
        "echo \"${{ github.event.head_commit.committer.date }}\"",
    ],
)
def test_safe_shapes_do_not_match(value: str) -> None:
    assert not _has_dangerous_github_context(value, "scalar", ("jobs", "j", "steps", 0, "run"))
