"""Contract tests for the public segmentation primitives.

These lock the (name, start_line, end_line) shape of ``for_each_job``
and ``for_each_step`` so future refactors of the underlying segmenter
don't silently change the API every consumer (cross-tool harness,
labelled-corpus runner, eventual rule migrations) depends on.

NB: line numbers are 1-based and inclusive on both ends.
"""

from __future__ import annotations

from taintly.parsers.segmentation import (
    JobSegment,
    StepSegment,
    for_each_job,
    for_each_step,
)


# =============================================================================
# for_each_job — GitHub Actions
# =============================================================================


def test_for_each_job_github_two_jobs():
    """Classic two-job workflow.  Job names extracted; preamble carries the
    on:/name:/permissions: lines and is returned with name=''.

    Layout (1-based):
        1: on: push
        2: jobs:
        3:   build:
        4:     runs-on: ubuntu-latest
        5:     steps: []
        6:   test:
        7:     runs-on: ubuntu-latest
        8:     steps: []
    """
    src = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
    )
    jobs = for_each_job(src)
    names = [j.name for j in jobs]
    assert "build" in names, names
    assert "test" in names, names
    # End-line is inclusive; the 'test' job runs from line 6 to line 8.
    test_job = next(j for j in jobs if j.name == "test")
    assert test_job.start_line == 6, test_job
    assert test_job.end_line == 8, test_job


def test_for_each_job_github_single_job_returns_at_least_one_named():
    """A workflow with a single job must produce a JobSegment whose name
    matches the job key (otherwise per-job rules can't anchor at all)."""
    src = (
        "on: push\n"
        "jobs:\n"
        "  only_one:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    jobs = for_each_job(src)
    assert any(j.name == "only_one" for j in jobs), [j.name for j in jobs]


def test_for_each_job_gitlab_jobs():
    """GitLab CI: 0-indent non-keyword keys are jobs.  ``stages`` and
    hidden ``.template`` keys are NOT jobs and must not appear as named
    segments."""
    src = (
        "stages:\n"
        "  - build\n"
        "  - test\n"
        ".hidden_template:\n"
        "  script: echo template\n"
        "build_job:\n"
        "  stage: build\n"
        "  script: echo build\n"
        "test_job:\n"
        "  stage: test\n"
        "  script: echo test\n"
    )
    jobs = for_each_job(src)
    names = {j.name for j in jobs if j.name}
    assert "build_job" in names, names
    assert "test_job" in names, names
    assert ".hidden_template" not in names
    assert "stages" not in names


def test_for_each_job_line_ranges_are_disjoint_and_cover_input():
    """Job segments must tile the input: contiguous, non-overlapping,
    spanning every line.  Regression guard for any future segmentation
    refactor that loses lines."""
    src = (
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
    )
    total_lines = len(src.splitlines())
    jobs = for_each_job(src)
    # Sort by start.
    jobs_sorted = sorted(jobs, key=lambda j: j.start_line)
    # Coverage: every line 1..total_lines is in exactly one segment.
    covered: set[int] = set()
    for j in jobs_sorted:
        seg_range = set(range(j.start_line, j.end_line + 1))
        assert covered.isdisjoint(seg_range), (
            f"segment for {j.name!r} overlaps a previous segment: "
            f"{j.start_line}..{j.end_line} vs already-covered {covered}"
        )
        covered |= seg_range
    assert covered == set(range(1, total_lines + 1)), (
        f"segments don't cover all lines.  Missing: "
        f"{set(range(1, total_lines + 1)) - covered}; extra: {covered - set(range(1, total_lines + 1))}"
    )


# =============================================================================
# for_each_step — GitHub Actions only
# =============================================================================


def test_for_each_step_basic_two_steps():
    src = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: npm test\n"
    )
    steps = for_each_step(src)
    assert len(steps) == 2, [(s.index, s.start_line, s.end_line) for s in steps]
    assert steps[0].index == 0
    assert steps[1].index == 1
    assert steps[0].job_name == "build"
    assert steps[1].job_name == "build"
    # Step 0 is on line 6; step 1 is on line 7 (1-based).
    assert steps[0].start_line == 6, steps[0]
    assert steps[1].start_line == 7, steps[1]


def test_for_each_step_extracts_id_and_name():
    """Steps that carry ``id:`` and ``name:`` must surface them on the
    record so downstream rules don't need to re-parse the body."""
    src = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: checkout\n"
        "        name: Check out code\n"
        "        uses: actions/checkout@v4\n"
        "      - name: 'Build'\n"
        "        run: make\n"
    )
    steps = for_each_step(src)
    assert len(steps) == 2
    assert steps[0].id == "checkout"
    assert steps[0].display_name == "Check out code"
    assert steps[1].id == ""
    # Quoted form must be unquoted.
    assert steps[1].display_name == "Build"


def test_for_each_step_returns_empty_for_gitlab():
    """GitLab CI files have no GH-shaped ``steps:`` block — must return
    an empty list rather than mis-parsing ``script:`` entries."""
    src = (
        "stages:\n"
        "  - build\n"
        "build_job:\n"
        "  stage: build\n"
        "  script:\n"
        "    - echo a\n"
        "    - echo b\n"
    )
    assert for_each_step(src) == []


def test_for_each_step_step_body_includes_with_block():
    """A step's body must include any ``with:`` / ``env:`` sub-block —
    the structural-rule consumer needs to see the whole step in one
    body, not just the opener."""
    src = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "          fetch-depth: 0\n"
        "      - run: npm test\n"
    )
    steps = for_each_step(src)
    assert len(steps) == 2
    # First step's body must contain the with: block.
    body0 = "\n".join(steps[0].body_lines)
    assert "persist-credentials: false" in body0, body0
    assert "fetch-depth: 0" in body0, body0
    # And the with: block must NOT leak into the second step.
    body1 = "\n".join(steps[1].body_lines)
    assert "persist-credentials" not in body1, body1


def test_for_each_step_blank_input_is_empty():
    assert for_each_step("") == []
    assert for_each_step("name: x\non: push\n") == []


# =============================================================================
# Type-shape contract
# =============================================================================


def test_records_are_frozen_dataclasses():
    """JobSegment / StepSegment must be hashable + immutable so they
    can be cached and compared by-value in the cross-tool harness."""
    job = JobSegment(name="x", start_line=1, end_line=2, body_lines=("a", "b"))
    step = StepSegment(
        job_name="x",
        index=0,
        id="",
        display_name="",
        start_line=1,
        end_line=2,
        body_lines=("a", "b"),
    )
    # Hash must work — frozen dataclasses are hashable iff all fields are.
    hash(job)
    hash(step)
