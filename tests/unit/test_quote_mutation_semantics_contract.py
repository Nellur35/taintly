"""Portable tests for the generic quote-mutation source premise and hook."""

from __future__ import annotations

import pytest
from taintly.models import Platform
from taintly.rules.github.secret_artifact_flow import SecretArtifactFlowPattern
from taintly.rules.registry import load_rules_for_platform
from taintly.testing._quote_semantics import (
    invalidates_owned_printf_expansion as premise,
)
from taintly.testing.mutations import mutate_quote_swap

SOURCE = """on: workflow_dispatch
jobs:
  ordinary:
    runs-on: ubuntu-latest
    steps:
      - env:
          MESSAGE: ordinary-local-data
        run: |
          mkdir -p reports
          printf 'value=%s\\n' "$MESSAGE" > reports/status.txt
"""


def swap(source: str) -> str:
    return source.replace('"', "'")


def _unsupported_contexts() -> list[tuple[str, str]]:
    cases = {
        "fragment": "printf '%s\\n' \"$MESSAGE\"",
        "powershell": SOURCE.replace(
            "        run: |", "        shell: pwsh\n        run: |"
        ),
        "custom_shell": SOURCE.replace(
            "        run: |", "        shell: bash -e {0}\n        run: |"
        ),
        "shell_sequence": SOURCE.replace(
            "        run: |", "        shell: [bash]\n        run: |"
        ),
        "missing_runner": SOURCE.replace("    runs-on: ubuntu-latest\n", ""),
        "unknown_runner": SOURCE.replace("ubuntu-latest", "self-hosted"),
        "runner_sequence": SOURCE.replace("ubuntu-latest", "[self-hosted, linux]"),
        "defaults": SOURCE.replace("jobs:", "defaults: {}\njobs:"),
        "container": SOURCE.replace("    steps:", "    container: ubuntu\n    steps:"),
        "duplicate_root": SOURCE + "jobs: {}\n",
        "duplicate_shell": SOURCE.replace(
            "        run: |", "        shell: bash\n        shell: bash\n        run: |"
        ),
        "anchor": SOURCE.replace("ordinary-local-data", "&label ordinary-local-data"),
        "alias": SOURCE.replace("ordinary-local-data", "*missing"),
        "tag_cutoff": SOURCE.replace(
            "ordinary-local-data", "!!str ordinary-local-data"
        ),
        "folded": SOURCE.replace("run: |", "run: >"),
        "uses_and_run": SOURCE.replace(
            "        run: |", "        uses: local/action@v1\n        run: |"
        ),
        "escaped_dollar": SOURCE.replace("$MESSAGE", "\\$MESSAGE"),
        "extra_command": SOURCE.replace(
            "          mkdir", "          echo harmless\n          mkdir"
        ),
        "compound": SOURCE.replace(" > reports/status.txt", "; echo harmless"),
        "function": SOURCE.replace(
            "          mkdir", "          printf() { :; }\n          mkdir"
        ),
        "option_format": SOURCE.replace("value=%s", "-v %s"),
        "other_conversion": SOURCE.replace("%s", "%b"),
        "yaml_escape_change": SOURCE.replace("ordinary-local-data", '"a\\nb"'),
    }
    assert len(cases) == 23
    return list(cases.items())


def test_nonsecret_variable_argument_is_a_proved_expansion_change() -> None:
    assert premise(SOURCE, swap(SOURCE))
    for name in ("UNRELATED", "BUILD_LABEL", "MESSAGE_2"):
        source = SOURCE.replace("MESSAGE", name)
        assert premise(source, swap(source))


def test_braced_variable_and_explicit_sh() -> None:
    source = SOURCE.replace("$MESSAGE", "${MESSAGE}").replace(
        "        run: |", "        shell: sh\n        run: |"
    )
    assert premise(source, swap(source))


def test_nonrun_quoted_flow_values_keep_same_meaning() -> None:
    source = SOURCE.replace(
        "env:\n          MESSAGE: ordinary-local-data",
        'env: {"MESSAGE": "ordinary-local-data"}',
    )
    assert premise(source, swap(source))


def test_static_format_mutation_must_remain_emitted_by_premise() -> None:
    assert not premise(SOURCE, SOURCE.replace("'", '"'))
    assert not premise(SOURCE, SOURCE)


def test_other_value_changes_cannot_be_hidden() -> None:
    assert not premise(SOURCE, swap(SOURCE).replace("ordinary-local-data", "different"))
    assert not premise(
        SOURCE, swap(SOURCE).replace("reports/status.txt", "reports/other.txt")
    )


@pytest.mark.parametrize(("label", "source"), _unsupported_contexts())
def test_unsupported_contexts_keep_mutants(label: str, source: str) -> None:
    assert not premise(source, swap(source)), label


def test_two_changed_scripts_are_outside_initial_scope() -> None:
    source = SOURCE + "      - run: |\n          printf '%s\\n' \"$MESSAGE\"\n"
    assert not premise(source, swap(source))


def test_ordinary_mutator_retains_static_format_variant() -> None:
    emitted = mutate_quote_swap(SOURCE)
    static_format_variant = SOURCE.replace("'", '"')
    expansion_lost_variant = swap(SOURCE)
    assert static_format_variant in emitted
    assert expansion_lost_variant not in emitted


def test_real_secret_artifact_positive_remains_a_hit() -> None:
    rules = [
        rule
        for rule in load_rules_for_platform(Platform.GITHUB)
        if rule.id == "SEC6-GH-016"
    ]
    assert len(rules) == 1
    assert isinstance(rules[0].pattern, SecretArtifactFlowPattern)
    sample = rules[0].test_positive[0]
    assert rules[0].pattern.check(sample, sample.splitlines())
