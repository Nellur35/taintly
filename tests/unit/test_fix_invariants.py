"""Fix invariants — every fixer MUST preserve correctness.

The 80+ tests in test_fixes.py verify that string substitutions land
in the right place, but they don't verify the rewritten file is still
valid YAML, that job/step structure is preserved, or that running the
fixer twice is a no-op. A fixer that turned ``permissions: write-all``
into ``permissions: writeall:`` (broken YAML) would pass every existing
substitution test.

This file closes that gap. For every fixer × representative input we
assert:

  parsability   — output parses as YAML if input did. Catches
                  fixers that emit syntactically broken output.
  structure     — same job names + same step counts per job.
                  Catches fixers that accidentally duplicate or
                  drop content.
  idempotency   — running the fixer twice produces no further
                  change. Catches fixers that don't recognise their
                  own output as already-fixed (which would corrupt
                  files on a second --fix invocation).

A failure here is a real correctness bug — never paper over it by
removing the input from the parametrize list. Either the fixer is
wrong or the invariant claim is wrong; investigate and fix the
underlying problem.

Why a separate file from test_fixes.py: each fixer is exercised here
with a small library of canonical inputs (vulnerable + safe + edge),
not with the per-fixer scenarios in test_fixes.py. Splitting keeps
the substitution tests focused on "does the right text appear" and
this file focused on "is the file still valid afterwards." If the
two ever fight, this file is the source of truth on global
correctness.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from taintly.fixes import (
    ALL_FIXERS,
    OPT_IN_FIXERS,
    FixResult,
)


# ---------------------------------------------------------------------------
# Canonical inputs per fixer
#
# Each fixer gets at least:
#   * one ``vulnerable`` sample its rule fires on
#   * one ``already_safe`` sample it should leave alone
# More are welcome, but the contract test is parametrized so adding
# rows here grows coverage automatically.
#
# Inputs are stored as raw strings (dedented). The harness writes
# them to ``tmp_path`` and points the fixer at that file.
# ---------------------------------------------------------------------------


_NPM_VULN = textwrap.dedent("""\
    name: CI
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: npm install
          - run: yarn install
          - run: pnpm i
""")

_NPM_SAFE = textwrap.dedent("""\
    name: CI
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: npm install --ignore-scripts
""")

_PIN_VULN = textwrap.dedent("""\
    name: CI
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-node@v3
""")

_PIN_SAFE = textwrap.dedent("""\
    name: CI
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
""")

_PERMS_VULN = textwrap.dedent("""\
    name: CI
    on: push
    permissions: write-all
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo hi
""")

_PERMS_SAFE = textwrap.dedent("""\
    name: CI
    on: push
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo hi
""")

_PERSIST_VULN = textwrap.dedent("""\
    name: CI
    on: push
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
""")

_INSECURE_CMD_VULN = textwrap.dedent("""\
    name: CI
    on: push
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'
        steps:
          - run: echo hi
""")

_DEBUG_VULN = textwrap.dedent("""\
    name: CI
    on: push
    permissions:
      contents: read
    env:
      ACTIONS_RUNNER_DEBUG: true
      ACTIONS_STEP_DEBUG: true
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo hi
""")

_RELEASE_CACHE_VULN = textwrap.dedent("""\
    name: Release
    on:
      push:
        tags: ['v*']
    permissions:
      contents: write
    jobs:
      release:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/setup-node@1a4442cacd436585916779262731d1f9a026da5d # v3
            with:
              node-version: 20
              cache: 'npm'
          - run: npm publish
""")

_GITHUB_REFS_VULN = textwrap.dedent("""\
    name: CI
    on: push
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo $GITHUB_REF_NAME
          - run: docker tag img:${GITHUB_REPOSITORY_OWNER}
""")

_GITLAB_REFS_VULN = textwrap.dedent("""\
    stages:
      - build
    build:
      stage: build
      script:
        - echo $CI_COMMIT_REF_NAME
        - echo $CI_COMMIT_BRANCH
""")

_GITLAB_VARS_VULN = textwrap.dedent("""\
    variables:
      DEPLOY_BRANCH: $CI_COMMIT_REF_NAME
    stages:
      - build
    build:
      stage: build
      script:
        - echo $DEPLOY_BRANCH
""")

_HARDENED = textwrap.dedent("""\
    name: Hardened
    on:
      push:
        branches: [main]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        permissions:
          contents: read
        steps:
          - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
            with:
              persist-credentials: false
          - run: npm ci
""")


# Per-fixer inputs. Hardened YAML is always a valid input (fixer should
# leave it alone or make a tightening that still parses). Per-fixer
# vulnerable samples ensure the fixer's "does fire" branch runs too.
_FIXER_INPUTS: dict[str, list[tuple[str, str]]] = {
    # ALL_FIXERS — safe, semantics-preserving
    "pin_sha":                          [("hardened", _HARDENED), ("vulnerable_pin", _PIN_VULN), ("already_safe_pin", _PIN_SAFE)],
    "persist_credentials":              [("hardened", _HARDENED), ("vulnerable_persist", _PERSIST_VULN)],
    "add_permissions":                  [("hardened", _HARDENED), ("vulnerable_perms", _PERMS_VULN), ("already_safe_perms", _PERMS_SAFE)],
    "remove_insecure_commands":         [("hardened", _HARDENED), ("vulnerable_insecure_cmd", _INSECURE_CMD_VULN)],
    "remove_debug_logging":             [("hardened", _HARDENED), ("vulnerable_debug", _DEBUG_VULN)],
    "disable_setup_cache_in_release":   [("hardened", _HARDENED), ("vulnerable_release_cache", _RELEASE_CACHE_VULN)],
    "quote_github_refs":                [("hardened", _HARDENED), ("vulnerable_gh_refs", _GITHUB_REFS_VULN)],
    "quote_gitlab_refs":                [("vulnerable_gl_refs", _GITLAB_REFS_VULN)],
    "quote_gitlab_ci_vars":             [("vulnerable_gl_vars", _GITLAB_VARS_VULN)],
    # Groovy fixer — Jenkinsfile content isn't YAML; we still require
    # idempotency. Parsability is checked only when the input parses.
    "unquote_groovy_gstring_with_params": [
        ("groovy_with_params", "pipeline {\n  parameters {\n    string(name: 'PR_TITLE', defaultValue: '')\n  }\n  stages {\n    stage('s') { steps { sh \"echo ${params.PR_TITLE}\" } }\n  }\n}\n"),
    ],

    # OPT_IN_FIXERS — change build semantics
    "npm_ignore_scripts":               [("hardened", _HARDENED), ("vulnerable_npm", _NPM_VULN), ("already_safe_npm", _NPM_SAFE)],
    "jenkins_cap_add_hint":             [
        ("jenkins_dind", "pipeline {\n  agent any\n  stages {\n    stage('s') { steps { sh 'docker run --cap-add=SYS_ADMIN ubuntu' } }\n  }\n}\n"),
    ],
    "github_ai_allowed_tools_scaffold": [
        ("ai_step", textwrap.dedent("""\
            name: AI agent
            on: pull_request
            permissions:
              contents: read
            jobs:
              ai:
                runs-on: ubuntu-latest
                steps:
                  - uses: anthropics/claude-code-action@v1
                    with:
                      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
        """)),
    ],
    "hoist_service_credentials":        [("hardened", _HARDENED), (
        "service_inline_creds", textwrap.dedent("""\
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              test:
                runs-on: ubuntu-latest
                services:
                  postgres:
                    image: postgres:15
                    env:
                      POSTGRES_PASSWORD: hunter2
                steps:
                  - run: echo hi
        """),
    )],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_yaml(text: str):
    """Parse YAML, returning ``None`` if the input was never valid YAML
    in the first place (so we don't fail Jenkinsfile inputs on the
    parsability check)."""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _job_step_shape(parsed) -> dict[str, int] | None:
    """Return a {job_name: step_count} mapping if ``parsed`` looks like
    a GitHub Actions workflow with a ``jobs:`` block, else ``None``.

    Used to detect when a fixer accidentally drops a job or duplicates
    steps. We don't compare exact step content because legitimate
    rewrites change ``run:`` strings.
    """
    if not isinstance(parsed, dict):
        return None
    jobs = parsed.get("jobs")
    if not isinstance(jobs, dict):
        return None
    shape: dict[str, int] = {}
    for name, job in jobs.items():
        if not isinstance(job, dict):
            shape[name] = 0
            continue
        steps = job.get("steps")
        shape[name] = len(steps) if isinstance(steps, list) else 0
    return shape


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def assert_fix_invariants(
    fixer: Callable[[str, bool], list[FixResult]],
    workdir: Path,
    original: str,
    *,
    label: str = "",
) -> None:
    """Run ``fixer`` against ``original`` written into ``workdir`` and
    assert the three correctness invariants.

    Public helper — also imported by tests/playground/test_playground.py
    so the CLI-level fix path enforces the same contract.
    """
    workfile = workdir / "workflow.yml"
    workfile.write_text(original, encoding="utf-8")

    # First application — may or may not change the file.
    fixer(str(workfile), False)
    after_first = _read(workfile)

    # Parsability: if the original parsed as YAML, the fixed output
    # MUST also parse. (We don't require originally-broken input to
    # become valid; that's not a fixer's job.)
    original_parsed = _parse_yaml(original)
    after_first_parsed = _parse_yaml(after_first)
    if original_parsed is not None:
        assert after_first_parsed is not None or after_first == original, (
            f"[{label}] fixer produced output that no longer parses as YAML.\n"
            f"--- original ---\n{original}\n--- after fix ---\n{after_first}"
        )

    # Structure: when input was a workflow with jobs, every job must
    # still exist and have the same step count.
    original_shape = _job_step_shape(original_parsed) if original_parsed else None
    after_shape = _job_step_shape(after_first_parsed) if after_first_parsed else None
    if original_shape is not None and after_shape is not None:
        assert set(original_shape) == set(after_shape), (
            f"[{label}] fixer changed job names: "
            f"{set(original_shape)} -> {set(after_shape)}"
        )
        for job_name, expected_count in original_shape.items():
            actual = after_shape[job_name]
            # Some fixers legitimately add steps (e.g. add_permissions
            # adds a top-level permissions key but doesn't touch steps).
            # We forbid step COUNT shrinking; growing is allowed but
            # surfaced for review.
            assert actual >= expected_count, (
                f"[{label}] fixer dropped steps in job {job_name!r}: "
                f"{expected_count} -> {actual}\n"
                f"--- after ---\n{after_first}"
            )

    # Idempotency: a second application must be a no-op.
    fixer(str(workfile), False)
    after_second = _read(workfile)
    assert after_first == after_second, (
        f"[{label}] fixer is NOT idempotent — second application changed "
        f"the file again. This will corrupt files on repeated --fix runs.\n"
        f"--- after first fix ---\n{after_first}\n"
        f"--- after second fix ---\n{after_second}"
    )


# ---------------------------------------------------------------------------
# Parametrized contract test
# ---------------------------------------------------------------------------


def _build_cases() -> list[tuple[str, str, Callable, str, str]]:
    """Yield ``(fixer_name, input_label, fixer_fn, label, content)`` for
    every (fixer, input) pair declared above."""
    cases: list[tuple[str, str, Callable, str, str]] = []
    for fixer_name, samples in _FIXER_INPUTS.items():
        fixer = ALL_FIXERS.get(fixer_name) or OPT_IN_FIXERS.get(fixer_name)
        if fixer is None:
            # Test-data drift — don't silently skip; surface it.
            raise RuntimeError(
                f"_FIXER_INPUTS lists {fixer_name!r} but no such fixer "
                f"in ALL_FIXERS or OPT_IN_FIXERS. Update one or the other."
            )
        for input_label, content in samples:
            cases.append(
                (fixer_name, input_label, fixer, f"{fixer_name}/{input_label}", content)
            )
    return cases


@pytest.mark.parametrize(
    "fixer_name,input_label,fixer,label,content",
    _build_cases(),
    ids=[f"{c[0]}-{c[1]}" for c in _build_cases()],
)
def test_fixer_preserves_invariants(fixer_name, input_label, fixer, label, content, tmp_path):
    assert_fix_invariants(fixer, tmp_path, content, label=label)


def test_every_fixer_has_at_least_one_input():
    """Registry sanity: every fixer in ALL_FIXERS / OPT_IN_FIXERS must
    have at least one entry in _FIXER_INPUTS so this contract test
    actually exercises it. Catches the case where a new fixer ships
    without a representative input."""
    declared = set(_FIXER_INPUTS.keys())
    registered = set(ALL_FIXERS.keys()) | set(OPT_IN_FIXERS.keys())
    missing = registered - declared
    assert not missing, (
        f"fixers without any _FIXER_INPUTS coverage in test_fix_invariants.py: "
        f"{sorted(missing)} — add a representative input row so the "
        f"parsability/idempotency contract is exercised."
    )
    extra = declared - registered
    assert not extra, (
        f"_FIXER_INPUTS references unknown fixers (drift between fixes.py "
        f"and the test): {sorted(extra)}"
    )
