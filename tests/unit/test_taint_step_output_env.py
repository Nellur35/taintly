"""Same-job, step-ordered step-output propagation into env assignments."""

from __future__ import annotations

from textwrap import dedent

from taintly.taint import TaintPath, analyze


def _analyze(source: str) -> list[TaintPath]:
    source = dedent(source).lstrip("\n")
    return analyze(source, source.splitlines())


def test_step_output_bridges_into_later_step_env_with_provenance() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            steps:
              - id: write
                run: echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
              - name: consume
                env:
                  VALUE: ${{ steps.write.outputs.name }}
                run: echo "$VALUE"
        """
    )

    assert len(paths) == 1, paths
    path = paths[0]
    assert path.kind == "step_output"
    assert path.source_expr == "github.event.pull_request.title"
    assert path.env_var == "VALUE"
    assert [hop.kind for hop in path.hops] == ["step_output", "env_indirect", "sink"]


def test_step_output_is_not_visible_to_env_in_writer_step() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            steps:
              - id: write
                env:
                  VALUE: ${{ steps.write.outputs.name }}
                run: |
                  echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
                  echo "$VALUE"
        """
    )

    assert paths == []


def test_step_output_is_not_visible_to_env_before_writer() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            steps:
              - env:
                  VALUE: ${{ steps.write.outputs.name }}
                run: echo "$VALUE"
              - id: write
                run: echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
        """
    )

    assert paths == []


def test_step_outputs_do_not_cross_jobs_even_when_step_ids_match() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          producer:
            steps:
              - id: write
                run: echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
          consumer:
            steps:
              - id: write
                run: echo "name=trusted" >> $GITHUB_OUTPUT
              - run: echo "${{ steps.write.outputs.name }}"
        """
    )

    assert paths == []


def test_step_output_from_foreign_job_does_not_taint_consumer_env() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          producer:
            steps:
              - id: write
                run: echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
          consumer:
            steps:
              - env:
                  VALUE: ${{ steps.write.outputs.name }}
                run: echo "$VALUE"
        """
    )

    assert paths == []


def test_step_output_boolean_result_does_not_taint_env_value() -> None:
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            steps:
              - id: write
                run: echo "name=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
              - env:
                  VALUE: ${{ steps.write.outputs.name == 'trusted' }}
                run: echo "$VALUE"
        """
    )

    assert paths == []
