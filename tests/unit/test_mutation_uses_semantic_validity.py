"""Whitespace mutations exclude only proved loss of a supported uses map."""

from __future__ import annotations

import pytest

from taintly.testing.mutations import mutate_whitespace_pad


@pytest.mark.parametrize(
    "source",
    [
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
        "jobs:\n  call:\n    uses: owner/repo/.github/workflows/ci.yml@v1\n",
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
        "- uses: owner/repo@v1\n",
    ],
    ids=["job-step", "reusable-call", "composite-step", "standalone-sequence"],
)
def test_supported_uses_mapping_loss_excludes_only_zero_space_variant(source: str) -> None:
    variants = mutate_whitespace_pad(source)
    collapsed = source.replace(": ", ":")
    assert collapsed not in variants
    assert source.replace(": ", ":  ") in variants


@pytest.mark.parametrize(
    "source",
    [
        "uses: owner/repo@v1\n",
        "jobs:\n  x:\n    steps:\n      - uses: owner/repo@v1\n%YAML 1.2\n",
        "jobs:\n  x:\n    steps:\n      - uses: owner/first@v1\n        uses: owner/second@v1\n",
    ],
    ids=["unsupported-root-map", "malformed-yaml", "ambiguous-duplicate-key"],
)
def test_unsupported_or_ambiguous_sources_do_not_prove_mutation_loss(source: str) -> None:
    collapsed = source.replace(": ", ":")
    assert collapsed in mutate_whitespace_pad(source)
