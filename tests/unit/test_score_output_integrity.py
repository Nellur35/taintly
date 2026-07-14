"""Regression: ``--score`` must not corrupt machine-readable output.

The human-readable score block is printed by ``__main__`` *after* the
report body.  It was emitted for every format except ``html``, so
``--format json --score`` (and ``sarif`` / ``csv``) dumped prose after
the machine document — unparseable JSON, and a SARIF file that
``codeql-action/upload-sarif`` would reject.  The score is already
embedded in the JSON ``score`` block, so the human block belongs only in
the ``text`` format.

These run the real CLI via subprocess so the assertion is about actual
stdout, not a Python-level intermediate.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

_VULN_WORKFLOW = """\
name: bad
on: [pull_request_target]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: actions/checkout@v4
"""


def _repo_with_findings(tmp_path: Path) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "bad.yml").write_text(_VULN_WORKFLOW, encoding="utf-8")
    return tmp_path


def _stdout(args: list[str]) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "taintly", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_score_keeps_machine_output_parseable(tmp_path: Path, fmt: str):
    """``--format {json,sarif} --score`` must stay valid JSON — no human
    score text appended after the document."""
    repo = _repo_with_findings(tmp_path)
    out = _stdout([str(repo), "--format", fmt, "--score"])
    # Raises JSONDecodeError (with "Extra data") if prose was appended.
    json.loads(out)


def test_json_score_block_is_embedded_not_appended(tmp_path: Path):
    """The score still reaches JSON consumers — via the in-band ``score``
    block, not trailing prose."""
    repo = _repo_with_findings(tmp_path)
    doc = json.loads(_stdout([str(repo), "--format", "json", "--score"]))
    assert "score" in doc
    assert doc["score"]["applicable"] is True
    assert isinstance(doc["score"]["total"], int)


def test_text_format_still_shows_score_block(tmp_path: Path):
    """The human ``text`` format must keep the score block — the fix
    narrows *where* it prints, it doesn't remove it."""
    repo = _repo_with_findings(tmp_path)
    out = _stdout([str(repo), "--format", "text", "--score"])
    assert "CI/CD SECURITY SCORE" in out
