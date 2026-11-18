"""Saved Pages publications must prove the selected nested Git member."""

import pytest

from taintly.ingestion.github_pages_publication import (
    _git_digest,
    _git_members,
    _graph_revision,
    _member_path,
)
from taintly.ingestion.github_preview import PreviewEvidenceError


@pytest.mark.parametrize("selected", ["index.html", "graphs/summary.json", "graphs/../index.html"])
def test_nested_archive_selection_matches_its_own_git_path(selected):
    blob = _git_digest("blob", b"public report")
    file_oid = bytes.fromhex(blob)
    graphs = b"100644 summary.json\0" + file_oid
    graphs_id = _git_digest("tree", graphs)
    page = b"40000 graphs\0" + bytes.fromhex(graphs_id) + b"100644 index.html\0" + file_oid
    page_id = _git_digest("tree", page)
    pull = b"40000 17\0" + bytes.fromhex(page_id)
    pull_id = _git_digest("tree", pull)
    root = b"40000 pull\0" + bytes.fromhex(pull_id)
    root_id = _git_digest("tree", root)
    commit = f"tree {root_id}\n\nreceipt fixture\n"
    witness = {
        "commit": _git_digest("commit", commit.encode()),
        "commit_bytes": commit,
        "tree_objects": {
            oid: raw.hex()
            for oid, raw in zip(
                (root_id, pull_id, page_id, graphs_id), (root, pull, page, graphs), strict=True
            )
        },
    }
    if not _member_path(selected):
        with pytest.raises(PreviewEvidenceError, match="bounded named publication files"):
            _git_members(witness, "pull/17", [selected])
    else:
        assert _git_members(witness, "pull/17", [selected]) == {selected: blob}
        witness["tree_objects"][page_id] = (page + b"changed").hex()
        with pytest.raises(PreviewEvidenceError, match="different object ID"):
            _git_members(witness, "pull/17", [selected])


@pytest.mark.parametrize(
    ("revisions", "points"),
    [
        ({"22": "head", "23": "base"}, [[23, 1.25]]),
        ({"22": "head", "23": "head"}, [[22, 1.25]]),
        ({"22": "head"}, [[22, 1.25], [22, 2.5]]),
        ({"22": "head"}, [[22, True]]),
    ],
)
def test_sample_needs_a_unique_head_ordinal_and_exact_value(revisions, points):
    assert _graph_revision({"revision_to_hash": {"22": "head"}}, [[22, 1.25]], "head", 1.25) == 22
    with pytest.raises(PreviewEvidenceError):
        _graph_revision({"revision_to_hash": revisions}, points, "head", 1.25)
