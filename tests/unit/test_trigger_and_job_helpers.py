"""Unit tests for the shared helpers backing guard calibration:

- ``workflow_corpus.is_fork_reachable`` — must recognise fork-reachable
  triggers in ALL four ``on:`` YAML shapes (the Finding-A bug class was a
  block-style-only regex missing flow/list forms).
- ``parsers.segmentation.job_at_line`` — point lookup of the job owning a
  line, used to job-scope guard calibration (Finding B).
"""

from __future__ import annotations

import pytest

from taintly.parsers.segmentation import job_at_line
from taintly.workflow_corpus import is_fork_reachable

# --- is_fork_reachable: all four on: shapes ------------------------------


@pytest.mark.parametrize(
    "content",
    [
        # 1. bare string
        "on: pull_request_target\njobs:\n  a:\n    steps: []\n",
        # 2. flow list
        "on: [push, pull_request]\njobs:\n  a:\n    steps: []\n",
        # 3. flow mapping
        "on: { pull_request_target: { types: [opened] } }\njobs:\n  a: {}\n",
        # 4. block mapping
        "on:\n  pull_request:\n    branches: [main]\njobs:\n  a: {}\n",
    ],
)
def test_is_fork_reachable_all_shapes(content: str) -> None:
    assert is_fork_reachable(content)


@pytest.mark.parametrize(
    "content",
    [
        "on: push\njobs:\n  a: {}\n",
        "on: [push, workflow_dispatch]\njobs:\n  a: {}\n",
        "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  a: {}\n",
        # a run: step that merely contains the text 'on:' must not match
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo 'on: pull_request'\n",
    ],
)
def test_is_fork_reachable_negatives(content: str) -> None:
    assert not is_fork_reachable(content)


# --- job_at_line ----------------------------------------------------------

_TWO_JOBS = (
    "on: pull_request_target\n"  # line 1
    "jobs:\n"  # line 2
    "  build:\n"  # line 3
    "    steps:\n"  # line 4
    "      - run: echo build\n"  # line 5
    "  deploy:\n"  # line 6
    "    steps:\n"  # line 7
    "      - run: echo deploy\n"  # line 8
)


def test_job_at_line_resolves_each_job() -> None:
    assert job_at_line(_TWO_JOBS, 5) == "build"
    assert job_at_line(_TWO_JOBS, 8) == "deploy"


def test_job_at_line_boundaries() -> None:
    # The job-key line itself belongs to that job's range.
    assert job_at_line(_TWO_JOBS, 3) == "build"
    assert job_at_line(_TWO_JOBS, 6) == "deploy"


def test_job_at_line_preamble_and_oob_return_none() -> None:
    assert job_at_line(_TWO_JOBS, 1) is None  # preamble (on:/jobs:)
    assert job_at_line(_TWO_JOBS, 0) is None  # non-positive
    assert job_at_line(_TWO_JOBS, 999) is None  # past EOF
